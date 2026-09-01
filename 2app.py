#!/usr/bin/env python3
"""Flask application for Infrastructure Intelligence.

Run ingest.py only when parsed JSON changes. app.py reads the existing SQLite DB.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Iterable

from flask import Flask, jsonify, render_template, request

from database import (
    DEFAULT_DB_PATH,
    classify_ip_search,
    extract_direct_attached_sg_ids,
    fetch_records_by_ids,
    find_network_record_ids,
    get_db,
    get_file_modified_time,
    get_latest_dir_mtime,
    network_bounds,
    value_matches_network_or_range,
)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = DEFAULT_DB_PATH
FW_DATA_ROOT = BASE_DIR / "parsed"
AWS_DATA_ROOT = BASE_DIR / "aws_parsed"
ORG_FILE_PATH = BASE_DIR / "org_topology.json"
PAN_TOPOLOGY_PATH = BASE_DIR / "panorama_topology.json"

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))


def _safe_json(raw: str) -> Any:
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _record(row: Any, *, reason: str | None = None, matched_value: str | None = None) -> dict[str, Any]:
    item = _safe_json(row["data"])
    rec = {
        "record_id": int(row["id"]),
        "device": row["device"],
        "platform": row["platform"],
        "type": row["category"],
        "category": row["category"],
        "file": row["filename"],
        "name": row["name"] or "",
        "data": item,
    }
    if reason:
        rec["match_reason"] = reason
    if matched_value:
        rec["matched_value"] = matched_value
    return rec


def _dedupe_records(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[int] = set()
    for rec in records:
        rid = int(rec.get("record_id", -1))
        if rid in seen:
            continue
        seen.add(rid)
        out.append(rec)
    return out


def _flatten_values(obj: Any) -> list[str]:
    if obj is None:
        return []
    if isinstance(obj, (str, int, float, bool)):
        return [str(obj)]
    if isinstance(obj, list):
        out: list[str] = []
        for item in obj:
            out.extend(_flatten_values(item))
        return out
    if isinstance(obj, dict):
        out: list[str] = []
        if "member" in obj:
            out.extend(_flatten_values(obj["member"]))
        else:
            for value in obj.values():
                out.extend(_flatten_values(value))
        return out
    return []


def _find_first(obj: Any, keys: set[str]) -> Any:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key.lower() in keys:
                return value
        for value in obj.values():
            found = _find_first(value, keys)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for value in obj:
            found = _find_first(value, keys)
            if found is not None:
                return found
    return None


def _clean_fts_query(query: str) -> str:
    tokens = re.findall(r"[A-Za-z0-9_./:@-]+", query)
    tokens = [t.replace('"', '') for t in tokens if t]
    return " AND ".join(f'"{t}"*' for t in tokens)


def _category_norm(category: str) -> str:
    return str(category or "").replace("-", "_").lower()


def _is_raw_collection(row_or_rec: Any) -> bool:
    category = _category_norm(row_or_rec["category"] if "category" in row_or_rec.keys() else row_or_rec.get("category", ""))
    filename = str(row_or_rec["filename"] if "filename" in row_or_rec.keys() else row_or_rec.get("file", "")).lower()
    return "all_entries" in category or "all_entries" in filename


def _pan_role(category: str, data: Any) -> str:
    cat = _category_norm(category)
    if "all_entries" in cat:
        return "raw"
    if "rule" in cat or "policy" in cat or "nat" in cat:
        return "rule"
    if "service_group" in cat:
        return "service_group"
    if "service" in cat and "group" not in cat:
        return "service"
    if "group" in cat:
        return "group"
    if "address" in cat or "object" in cat or "fqdn" in cat:
        return "object"
    # Some parsed categories are generic; infer from payload.
    payload = data.get("entry", data) if isinstance(data, dict) else data
    if isinstance(payload, dict):
        keys = {str(k).lower() for k in payload.keys()}
        if {"source", "destination"}.issubset(keys) or "action" in keys:
            return "rule"
        if "static" in keys and "member" in json.dumps(payload).lower():
            return "group"
        if any(k in keys for k in ("ip-netmask", "ip_range", "ip-range", "fqdn")):
            return "object"
    return "other"


def _pan_payload(data: Any) -> dict[str, Any]:
    if isinstance(data, dict) and isinstance(data.get("entry"), dict):
        return data["entry"]
    return data if isinstance(data, dict) else {}


def _pan_name(rec: dict[str, Any]) -> str:
    data = _pan_payload(rec.get("data", {}))
    return str(rec.get("name") or data.get("@name") or data.get("name") or "")


def _pan_group_members(rec: dict[str, Any]) -> list[str]:
    data = _pan_payload(rec.get("data", {}))
    for key in ("static", "members", "member"):
        if key in data:
            return [x for x in _flatten_values(data[key]) if x]
    value = _find_first(data, {"member"})
    return [x for x in _flatten_values(value) if x] if value is not None else []


def _rule_field(rec: dict[str, Any], field_names: set[str]) -> list[str]:
    data = _pan_payload(rec.get("data", {}))
    value = _find_first(data, {x.lower() for x in field_names})
    return [str(x) for x in _flatten_values(value) if str(x)]


def _rule_action(rec: dict[str, Any]) -> str:
    value = _find_first(_pan_payload(rec.get("data", {})), {"action"})
    vals = _flatten_values(value)
    return vals[0] if vals else "unknown"


def _record_network_values(conn, record_ids: Iterable[int]) -> list[str]:
    ids = list(dict.fromkeys(int(x) for x in record_ids))
    if not ids:
        return []
    placeholders = ",".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT DISTINCT value FROM record_networks WHERE record_id IN ({placeholders})",
        ids,
    ).fetchall()
    return [str(r[0]) for r in rows]


def _network_context_add(target: list[dict[str, Any]], seen: set[str], value: str, source: str, name: str = "") -> None:
    if not network_bounds(value):
        return
    key = value.strip().lower()
    if key in seen:
        return
    seen.add(key)
    target.append({"value": value, "source": source, "name": name})


def _looks_like_ref(query: str) -> bool:
    return bool(re.match(r"^(?:i|eni|sg|subnet|vpc)-[0-9a-z]+$", query, re.I))


def _base_search_rows(conn, query: str, *, platform: str | None = None, limit: int = 600) -> list[Any]:
    info = classify_ip_search(query)
    ids: list[int] = []

    if info["family"] in (4, 6):
        ids.extend(find_network_record_ids(conn, query, platform=platform, limit=limit * 3))
    else:
        ql = query.lower()
        sql = """
            SELECT DISTINCT r.id
            FROM records r
            LEFT JOIN record_refs rr ON rr.record_id = r.id
            LEFT JOIN record_terms rt ON rt.record_id = r.id
            WHERE (LOWER(r.name)=? OR rr.ref_value_lower=? OR rt.term_lower=?)
        """
        params: list[Any] = [ql, ql, ql]
        if platform:
            sql += " AND r.platform=?"
            params.append(platform)
        sql += " LIMIT ?"
        params.append(limit)
        ids.extend(int(r[0]) for r in conn.execute(sql, params).fetchall())

        fts = _clean_fts_query(query)
        if fts:
            sql = """
                SELECT r.id
                FROM records_fts fts
                JOIN records r ON r.id=fts.rowid
                WHERE records_fts MATCH ?
            """
            params = [fts]
            if platform:
                sql += " AND r.platform=?"
                params.append(platform)
            sql += " LIMIT ?"
            params.append(limit)
            try:
                ids.extend(int(r[0]) for r in conn.execute(sql, params).fetchall())
            except Exception:
                # FTS syntax should not make the whole search fail.
                pass

    return fetch_records_by_ids(conn, list(dict.fromkeys(ids))[:limit])


def _aws_ids_from_item(item: dict[str, Any]) -> dict[str, set[str]]:
    refs = {"instance": set(), "eni": set(), "subnet": set(), "vpc": set(), "sg": set()}

    def walk(obj: Any, parent_key: str = "") -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                kl = key.lower().replace("_", "")
                if isinstance(value, str):
                    if kl == "instanceid" and value.startswith("i-"):
                        refs["instance"].add(value)
                    elif kl == "networkinterfaceid" and value.startswith("eni-"):
                        refs["eni"].add(value)
                    elif kl == "subnetid" and value.startswith("subnet-"):
                        refs["subnet"].add(value)
                    elif kl == "vpcid" and value.startswith("vpc-"):
                        refs["vpc"].add(value)
                if isinstance(value, (dict, list)):
                    walk(value, key)
        elif isinstance(obj, list):
            for value in obj:
                walk(value, parent_key)

    walk(item)
    refs["sg"].update(extract_direct_attached_sg_ids(item))
    return refs


def _fetch_ref_rows(conn, device: str, ref_type: str, value: str, *, limit: int = 200) -> list[Any]:
    return conn.execute(
        """
        SELECT DISTINCT r.id, d.name AS device, r.platform, r.category, r.filename, r.name, r.data
        FROM record_refs rr
        JOIN records r ON r.id=rr.record_id
        JOIN devices d ON d.id=r.device_id
        WHERE r.platform='aws' AND d.name=? AND rr.ref_type=? AND rr.ref_value_lower=?
        LIMIT ?
        """,
        (device, ref_type, value.lower(), limit),
    ).fetchall()


def _is_compute_like(category: str) -> bool:
    cat = _category_norm(category)
    return any(x in cat for x in ("instance", "ec2", "network_interface", "eni", "load_balancer", "rds", "db_instance", "lambda"))


def _is_sg_definition(category: str, item: dict[str, Any]) -> bool:
    cat = _category_norm(category)
    return "security_group" in cat and bool(item.get("GroupId") or item.get("IpPermissions") is not None)


def _service_port_values(data: Any) -> list[str]:
    payload = _pan_payload(data)
    values: list[str] = []

    def walk(obj: Any, key: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                kl = k.lower().replace("_", "-")
                if kl in {"port", "destination-port", "source-port"} and not isinstance(v, (dict, list)):
                    values.append(str(v))
                else:
                    walk(v, k)
        elif isinstance(obj, list):
            for v in obj:
                walk(v, key)
        elif key.lower().replace("_", "-") in {"port", "destination-port", "source-port"}:
            values.append(str(obj))

    walk(payload)
    return values


def _parse_port_query(port: str) -> tuple[str | None, int | None, str]:
    raw = port.strip().lower()
    if not raw:
        return None, None, ""
    proto = None
    if raw.startswith("tcp"):
        proto = "tcp"
    elif raw.startswith("udp"):
        proto = "udp"
    m = re.search(r"(?<!\d)(\d{1,5})(?!\d)", raw)
    return proto, int(m.group(1)) if m else None, raw


def _port_in_spec(port: int, spec: str) -> bool:
    for part in re.split(r"[,\s]+", spec.strip()):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            if a.isdigit() and b.isdigit() and int(a) <= port <= int(b):
                return True
        elif part.isdigit() and int(part) == port:
            return True
    return False


class InfrastructureDataSource:
    def __init__(self, db_file: Path | None = None):
        self._db_file = db_file

    @property
    def db_file(self) -> Path:
        return self._db_file if self._db_file is not None else DB_PATH

    def files_count(self) -> int:
        conn = get_db(self.db_file)
        try:
            return int(conn.execute("SELECT COUNT(*) FROM records").fetchone()[0])
        finally:
            conn.close()

    def devices_count(self) -> int:
        conn = get_db(self.db_file)
        try:
            return int(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0])
        finally:
            conn.close()

    def get_stats(self) -> dict[str, Any]:
        conn = get_db(self.db_file)
        try:
            panos = {r["category"]: r["cnt"] for r in conn.execute("SELECT category,COUNT(*) cnt FROM records WHERE platform='panos' GROUP BY category")}
            aws = {r["category"]: r["cnt"] for r in conn.execute("SELECT category,COUNT(*) cnt FROM records WHERE platform='aws' GROUP BY category")}
            return {
                "panos": panos,
                "aws_resources": aws,
                "aws_accounts_scanned": int(conn.execute("SELECT COUNT(*) FROM devices WHERE name LIKE 'AWS:%'").fetchone()[0]),
                "total_files": int(conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]),
                "indexed_terms": int(conn.execute("SELECT COUNT(*) FROM record_terms").fetchone()[0]),
                "indexed_networks": int(conn.execute("SELECT COUNT(*) FROM record_networks").fetchone()[0]),
            }
        finally:
            conn.close()

    def _expand_aws(self, conn, query: str, base_rows: list[Any], limit: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        aws_base = [r for r in base_rows if r["platform"] == "aws"]
        # An IP appearing inside an SG rule does not mean that SG is attached to the IP's resource.
        # Exclude SG definitions from network-based base matches; directly attached SGs are added separately.
        if network_bounds(query):
            aws_base = [r for r in aws_base if not _is_sg_definition(r["category"], _safe_json(r["data"]))]
        related_rows: list[Any] = list(aws_base)
        related_ids = {int(r["id"]) for r in related_rows}
        direct_sg_pairs: set[tuple[str, str]] = set()

        # Controlled relationship expansion. Subnet/VPC refs fetch only their definition,
        # while instance/ENI refs may connect the compute record to its interface.
        for row in list(aws_base):
            item = _safe_json(row["data"])
            if _is_sg_definition(row["category"], item):
                continue
            refs = _aws_ids_from_item(item)
            for sg in refs["sg"]:
                direct_sg_pairs.add((row["device"], sg))

            for ref_type in ("instance", "eni", "subnet", "vpc"):
                for value in refs[ref_type]:
                    for rr in _fetch_ref_rows(conn, row["device"], ref_type, value, limit=100):
                        cat = _category_norm(rr["category"])
                        keep = False
                        if ref_type == "instance":
                            keep = _is_compute_like(cat)
                        elif ref_type == "eni":
                            keep = "network_interface" in cat or "eni" in cat or "instance" in cat or "ec2" in cat
                        elif ref_type == "subnet":
                            keep = "subnet" in cat
                        elif ref_type == "vpc":
                            keep = cat == "vpcs" or "vpc" in cat
                        if keep and int(rr["id"]) not in related_ids:
                            related_ids.add(int(rr["id"]))
                            related_rows.append(rr)

        # SG reverse lookup: if SG itself is searched, show resources where it is actually attached.
        ql = query.lower()
        if ql.startswith("sg-"):
            devices = {r["device"] for r in aws_base}
            if not devices:
                devices = {r[0] for r in conn.execute("SELECT name FROM devices WHERE name LIKE 'AWS:%'").fetchall()}
            for device in devices:
                for rr in _fetch_ref_rows(conn, device, "sg", query, limit=limit):
                    item = _safe_json(rr["data"])
                    if query in extract_direct_attached_sg_ids(item) and int(rr["id"]) not in related_ids:
                        related_ids.add(int(rr["id"]))
                        related_rows.append(rr)
                        direct_sg_pairs.add((device, query))

        # Reverse-added compute resources (for example an SG-id lookup) need their own
        # ENI/subnet/VPC definitions pulled in without expanding to every resource in the VPC.
        for row in list(related_rows):
            if not _is_compute_like(row["category"]):
                continue
            item = _safe_json(row["data"])
            refs = _aws_ids_from_item(item)
            for ref_type in ("instance", "eni", "subnet", "vpc"):
                for value in refs[ref_type]:
                    for rr in _fetch_ref_rows(conn, row["device"], ref_type, value, limit=100):
                        cat = _category_norm(rr["category"])
                        keep = (
                            (ref_type == "instance" and _is_compute_like(cat)) or
                            (ref_type == "eni" and ("network_interface" in cat or "eni" in cat or "instance" in cat or "ec2" in cat)) or
                            (ref_type == "subnet" and "subnet" in cat) or
                            (ref_type == "vpc" and (cat == "vpcs" or "vpc" in cat))
                        )
                        if keep and int(rr["id"]) not in related_ids:
                            related_ids.add(int(rr["id"]))
                            related_rows.append(rr)

        # Any newly-related compute resources may reveal directly attached SGs.
        for row in related_rows:
            if row["platform"] != "aws":
                continue
            item = _safe_json(row["data"])
            if _is_compute_like(row["category"]):
                for sg in extract_direct_attached_sg_ids(item):
                    direct_sg_pairs.add((row["device"], sg))

        sg_records: list[dict[str, Any]] = []
        for device, sg_id in sorted(direct_sg_pairs):
            rows = _fetch_ref_rows(conn, device, "sg", sg_id, limit=100)
            for rr in rows:
                item = _safe_json(rr["data"])
                if _is_sg_definition(rr["category"], item):
                    rec = _record(rr, reason="directly_attached_security_group", matched_value=sg_id)
                    rec["attachment_scope"] = "direct"
                    sg_records.append(rec)

        # Network context contains searched IP/CIDR plus compute IPs and subnet/VPC networks.
        network_context: list[dict[str, Any]] = []
        seen_networks: set[str] = set()
        if network_bounds(query):
            _network_context_add(network_context, seen_networks, query, "query")
        for row in related_rows:
            item = _safe_json(row["data"])
            if _is_sg_definition(row["category"], item):
                continue
            values = _record_network_values(conn, [int(row["id"])])
            source = "aws_resource"
            cat = _category_norm(row["category"])
            if "subnet" in cat:
                source = "aws_subnet"
            elif "vpc" in cat:
                source = "aws_vpc"
            for value in values:
                _network_context_add(network_context, seen_networks, value, source, row["name"] or "")

        aws_records = [_record(r, reason="direct_or_related_aws") for r in related_rows]
        return _dedupe_records(aws_records), _dedupe_records(sg_records), network_context

    def _pan_inventory(self, conn, query: str, base_rows: list[Any], network_context: list[dict[str, Any]], limit: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        pan_rows = conn.execute(
            """SELECT r.id,d.name AS device,r.platform,r.category,r.filename,r.name,r.data
               FROM records r JOIN devices d ON d.id=r.device_id WHERE r.platform='panos'"""
        ).fetchall()
        pan_records = [_record(r) for r in pan_rows if not _is_raw_collection(r)]
        raw_rows = [r for r in base_rows if r["platform"] == "panos" and _is_raw_collection(r)]

        by_name: dict[str, list[dict[str, Any]]] = {}
        groups: list[dict[str, Any]] = []
        rules: list[dict[str, Any]] = []
        objects: list[dict[str, Any]] = []
        services: list[dict[str, Any]] = []
        for rec in pan_records:
            name = _pan_name(rec)
            if name:
                by_name.setdefault(name.lower(), []).append(rec)
            role = _pan_role(rec["category"], rec["data"])
            if role in {"group", "service_group"}:
                groups.append(rec)
            elif role == "rule":
                rules.append(rec)
            elif role in {"object", "other"}:
                objects.append(rec)
            elif role == "service":
                services.append(rec)

        initial_ids = {int(r["id"]) for r in base_rows if r["platform"] == "panos" and not _is_raw_collection(r)}
        initial: list[dict[str, Any]] = [rec for rec in pan_records if int(rec["record_id"]) in initial_ids]

        # Network context can match larger/smaller Palo objects regardless of exact query.
        network_values = [x["value"] for x in network_context]
        for value in network_values:
            for rid in find_network_record_ids(conn, value, platform="panos", limit=limit * 4):
                if rid in initial_ids:
                    continue
                rows = fetch_records_by_ids(conn, [rid])
                if not rows or _is_raw_collection(rows[0]):
                    continue
                rec = _record(rows[0], reason="network_overlap", matched_value=value)
                initial.append(rec)
                initial_ids.add(rid)

        matched_names: set[str] = set()
        selected_objects: list[dict[str, Any]] = []
        selected_groups: list[dict[str, Any]] = []
        selected_rules: list[dict[str, Any]] = []

        for rec in initial:
            role = _pan_role(rec["category"], rec["data"])
            name = _pan_name(rec)
            if name:
                matched_names.add(name.lower())
            if role in {"group", "service_group"}:
                selected_groups.append(rec)
            elif role == "rule":
                selected_rules.append(rec)
                # Rule-name lookup should also resolve referenced address entities.
                for field in ("source", "destination"):
                    matched_names.update(x.lower() for x in _rule_field(rec, {field}) if x.lower() != "any")
            else:
                selected_objects.append(rec)

        # Downward expansion: if a group itself matched, include its members and nested groups.
        changed = True
        depth = 0
        while changed and depth < 12:
            changed = False
            depth += 1
            for group in groups:
                gname = _pan_name(group).lower()
                members = [m.lower() for m in _pan_group_members(group)]
                if gname in matched_names:
                    for member in members:
                        if member not in matched_names:
                            matched_names.add(member)
                            changed = True
                if any(member in matched_names for member in members) and gname not in matched_names:
                    # Upward expansion: member -> containing group -> parent group.
                    matched_names.add(gname)
                    changed = True

        for name in list(matched_names):
            for rec in by_name.get(name, []):
                role = _pan_role(rec["category"], rec["data"])
                if role in {"group", "service_group"}:
                    selected_groups.append(rec)
                elif role == "rule":
                    selected_rules.append(rec)
                elif role != "service":
                    selected_objects.append(rec)

        def side_matches(rule_rec: dict[str, Any], field: str) -> bool:
            refs = _rule_field(rule_rec, {field})
            if any(r.lower() == "any" for r in refs):
                return True
            if any(r.lower() in matched_names for r in refs):
                return True
            for ref in refs:
                if network_bounds(ref) and any(value_matches_network_or_range(ref, n) for n in network_values):
                    return True
            return False

        for rule in rules:
            if int(rule["record_id"]) in {int(x["record_id"]) for x in selected_rules}:
                continue
            if side_matches(rule, "source") or side_matches(rule, "destination"):
                selected_rules.append(rule)

        for rec in selected_objects + selected_groups + selected_rules:
            if "match_reason" not in rec:
                rec["match_reason"] = "palo_relationship"

        raw_matches = [_record(r, reason="raw_collection_match") for r in raw_rows]
        return (
            _dedupe_records(selected_objects),
            _dedupe_records(selected_groups),
            _dedupe_records(selected_rules),
            _dedupe_records(raw_matches),
        )

    def investigate(self, query: str, limit: int = 600) -> dict[str, Any]:
        query = query.strip()
        search_info = classify_ip_search(query)
        output: dict[str, Any] = {
            "query": query,
            "query_type": search_info["type"],
            "query_family": search_info["family"],
            "aws_matches": [],
            "attached_security_groups": [],
            "matched_objects": [],
            "matched_groups": [],
            "matched_rules": [],
            "all_entries_matches": [],
            "network_context": [],
            "summary": {},
        }

        conn = get_db(self.db_file)
        try:
            base_rows = _base_search_rows(conn, query, limit=limit)
            aws_matches, direct_sgs, network_context = self._expand_aws(conn, query, base_rows, limit)

            # Reverse direction: a Palo address object can lead back to AWS resources.
            pan_base_ids = [int(r["id"]) for r in base_rows if r["platform"] == "panos"]
            for value in _record_network_values(conn, pan_base_ids):
                _network_context_add(network_context, {x["value"].lower() for x in network_context}, value, "palo_object")

            existing_aws_ids = {int(x["record_id"]) for x in aws_matches}
            for ctx in list(network_context):
                for rid in find_network_record_ids(conn, ctx["value"], platform="aws", limit=limit * 2):
                    if rid in existing_aws_ids:
                        continue
                    rows = fetch_records_by_ids(conn, [rid])
                    if not rows:
                        continue
                    rr = rows[0]
                    cat = _category_norm(rr["category"])
                    item = _safe_json(rr["data"])
                    # Avoid treating an SG rule CIDR as an AWS resource owning that IP.
                    if "security_group" in cat and _is_sg_definition(cat, item):
                        continue
                    if any(x in cat for x in ("instance", "network_interface", "eni", "subnet", "vpc", "load_balancer", "rds", "db", "route53", "hosted")):
                        aws_matches.append(_record(rr, reason="reverse_network_relationship", matched_value=ctx["value"]))
                        existing_aws_ids.add(rid)

            # Re-expand AWS after reverse matches so ENI/subnet/VPC/direct-SG relationships are included.
            reverse_rows = fetch_records_by_ids(conn, [int(x["record_id"]) for x in aws_matches])
            aws_matches, direct_sgs2, network_context2 = self._expand_aws(conn, query, reverse_rows, limit)
            direct_sgs.extend(direct_sgs2)
            for ctx in network_context2:
                if ctx["value"].lower() not in {x["value"].lower() for x in network_context}:
                    network_context.append(ctx)

            objects, groups, rules, raw = self._pan_inventory(conn, query, base_rows, network_context, limit)

            output["aws_matches"] = _dedupe_records(aws_matches)
            output["attached_security_groups"] = _dedupe_records(direct_sgs)
            output["matched_objects"] = objects
            output["matched_groups"] = groups
            output["matched_rules"] = rules
            output["all_entries_matches"] = raw
            output["network_context"] = network_context
            output["summary"] = {
                "aws_resources": len(output["aws_matches"]),
                "attached_sgs": len(output["attached_security_groups"]),
                "palo_objects": len(output["matched_objects"]),
                "palo_groups": len(output["matched_groups"]),
                "palo_rules": len(output["matched_rules"]),
                "all_entries": len(output["all_entries_matches"]),
            }
            return output
        finally:
            conn.close()

    def _service_matches(self, service_refs: list[str], port_query: str, pan_by_name: dict[str, list[dict[str, Any]]]) -> bool:
        if not port_query:
            return True
        proto, port_num, raw = _parse_port_query(port_query)
        if any(s.lower() == "any" for s in service_refs):
            return True

        visited: set[str] = set()

        def one(ref: str) -> bool:
            rl = ref.lower()
            if rl in visited:
                return False
            visited.add(rl)
            if raw == rl or raw in rl:
                return True
            if port_num is not None and re.search(rf"(?<!\d){port_num}(?!\d)", rl):
                return True
            for rec in pan_by_name.get(rl, []):
                role = _pan_role(rec["category"], rec["data"])
                if role == "service_group":
                    if any(one(member) for member in _pan_group_members(rec)):
                        return True
                if role == "service":
                    blob = json.dumps(rec["data"]).lower()
                    if proto and proto not in blob:
                        continue
                    if port_num is None:
                        if raw in blob:
                            return True
                    else:
                        for spec in _service_port_values(rec["data"]):
                            if _port_in_spec(port_num, spec):
                                return True
            return False

        return any(one(ref) for ref in service_refs)

    def policy_lookup(self, source: str = "", destination: str = "", port: str = "") -> dict[str, Any]:
        source = source.strip()
        destination = destination.strip()
        port = port.strip()
        if not source and not destination:
            return {
                "query": {"source": source, "destination": destination, "port": port},
                "source_context": None,
                "destination_context": None,
                "matched_objects": [], "matched_groups": [], "matched_rules": [],
                "summary": {"objects": 0, "groups": 0, "rules": 0, "allow": 0, "deny": 0},
            }

        source_inv = self.investigate(source, limit=350) if source else None
        dest_inv = self.investigate(destination, limit=350) if destination else None

        def endpoint(inv: dict[str, Any] | None, raw_query: str) -> dict[str, Any] | None:
            if inv is None:
                return None
            names = {raw_query.lower()}
            for rec in inv.get("matched_objects", []) + inv.get("matched_groups", []):
                name = _pan_name(rec)
                if name:
                    names.add(name.lower())
            networks = [x["value"] for x in inv.get("network_context", [])]
            if network_bounds(raw_query) and raw_query not in networks:
                networks.append(raw_query)
            return {
                "query": raw_query,
                "query_type": inv.get("query_type"),
                "names": sorted(names),
                "networks": networks,
                "aws_matches": inv.get("aws_matches", []),
                "attached_security_groups": inv.get("attached_security_groups", []),
                "objects": inv.get("matched_objects", []),
                "groups": inv.get("matched_groups", []),
            }

        src_ctx = endpoint(source_inv, source)
        dst_ctx = endpoint(dest_inv, destination)

        conn = get_db(self.db_file)
        try:
            rows = conn.execute(
                """SELECT r.id,d.name AS device,r.platform,r.category,r.filename,r.name,r.data
                   FROM records r JOIN devices d ON d.id=r.device_id
                   WHERE r.platform='panos'"""
            ).fetchall()
            all_pan = [_record(r) for r in rows if not _is_raw_collection(r)]
        finally:
            conn.close()

        pan_by_name: dict[str, list[dict[str, Any]]] = {}
        rules: list[dict[str, Any]] = []
        for rec in all_pan:
            name = _pan_name(rec)
            if name:
                pan_by_name.setdefault(name.lower(), []).append(rec)
            if _pan_role(rec["category"], rec["data"]) == "rule":
                rules.append(rec)

        def side_hit(rule: dict[str, Any], field: str, ctx: dict[str, Any] | None) -> tuple[bool, list[str]]:
            if ctx is None:
                return True, ["not_specified"]
            refs = _rule_field(rule, {field})
            reasons: list[str] = []
            if any(x.lower() == "any" for x in refs):
                reasons.append("any")
            for ref in refs:
                if ref.lower() in set(ctx["names"]):
                    reasons.append(f"entity:{ref}")
                if network_bounds(ref):
                    for net in ctx["networks"]:
                        if value_matches_network_or_range(ref, net):
                            reasons.append(f"network:{ref}~{net}")
                            break
            return bool(reasons), reasons

        matched_rules: list[dict[str, Any]] = []
        for rule in rules:
            src_hit, src_reasons = side_hit(rule, "source", src_ctx)
            dst_hit, dst_reasons = side_hit(rule, "destination", dst_ctx)
            service_refs = _rule_field(rule, {"service"})
            port_hit = self._service_matches(service_refs, port, pan_by_name)
            if src_hit and dst_hit and port_hit:
                rule["action"] = _rule_action(rule)
                rule["match_details"] = {
                    "source": src_reasons,
                    "destination": dst_reasons,
                    "services": service_refs,
                    "port_query": port,
                }
                matched_rules.append(rule)

        matched_objects = _dedupe_records(
            (source_inv.get("matched_objects", []) if source_inv else []) +
            (dest_inv.get("matched_objects", []) if dest_inv else [])
        )
        matched_groups = _dedupe_records(
            (source_inv.get("matched_groups", []) if source_inv else []) +
            (dest_inv.get("matched_groups", []) if dest_inv else [])
        )

        allow = sum(1 for r in matched_rules if str(r.get("action", "")).lower() == "allow")
        deny = sum(1 for r in matched_rules if str(r.get("action", "")).lower() in {"deny", "drop", "reject", "reset-client", "reset-server", "reset-both"})

        return {
            "query": {"source": source, "destination": destination, "port": port},
            "source_context": src_ctx,
            "destination_context": dst_ctx,
            "matched_objects": matched_objects,
            "matched_groups": matched_groups,
            "matched_rules": _dedupe_records(matched_rules),
            "summary": {
                "objects": len(matched_objects),
                "groups": len(matched_groups),
                "rules": len(matched_rules),
                "allow": allow,
                "deny": deny,
            },
        }


DATA = InfrastructureDataSource()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/info")
def api_info():
    return jsonify({"files": DATA.files_count(), "devices": DATA.devices_count()})


@app.route("/api/stats")
def api_stats():
    return jsonify(DATA.get_stats())


@app.route("/api/automation/status")
def api_automation_status():
    return jsonify({
        "aws_org_mtime": get_file_modified_time(ORG_FILE_PATH),
        "aws_data_mtime": get_latest_dir_mtime(AWS_DATA_ROOT),
        "pan_org_mtime": get_file_modified_time(PAN_TOPOLOGY_PATH),
        "pan_data_mtime": get_latest_dir_mtime(FW_DATA_ROOT),
    })


@app.route("/api/topology/aws")
def api_topology_aws():
    if not ORG_FILE_PATH.exists():
        return jsonify({"error": "AWS Organization Topology file not found."}), 404
    try:
        return jsonify(json.loads(ORG_FILE_PATH.read_text(encoding="utf-8")))
    except Exception as exc:
        return jsonify({"error": f"Failed to read AWS Org topology file: {exc}"}), 500


@app.route("/api/topology/pan")
def api_topology_pan():
    if not PAN_TOPOLOGY_PATH.exists():
        return jsonify({"error": "Panorama Topology file not found."}), 404
    try:
        return jsonify(json.loads(PAN_TOPOLOGY_PATH.read_text(encoding="utf-8")))
    except Exception as exc:
        return jsonify({"error": f"Failed to read Panorama topology file: {exc}"}), 500


@app.route("/api/investigate")
def api_investigate():
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify({"error": "A search query is required."}), 400
    try:
        return jsonify(DATA.investigate(query))
    except Exception as exc:
        app.logger.exception("Investigation failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/policy-lookup")
def api_policy_lookup():
    try:
        return jsonify(DATA.policy_lookup(
            request.args.get("src", ""),
            request.args.get("dst", ""),
            request.args.get("port", ""),
        ))
    except Exception as exc:
        app.logger.exception("Policy lookup failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/debug-records")
def api_debug_records():
    conn = get_db(DATA.db_file)
    try:
        categories = [dict(r) for r in conn.execute("SELECT platform,category,COUNT(*) count FROM records GROUP BY platform,category ORDER BY platform,category")]
        return jsonify({"categories": categories})
    finally:
        conn.close()


def main() -> None:
    global DB_PATH, FW_DATA_ROOT, AWS_DATA_ROOT, ORG_FILE_PATH, PAN_TOPOLOGY_PATH, DATA
    parser = argparse.ArgumentParser(description="Infrastructure Intelligence Dashboard")
    parser.add_argument("--db", default=str(DB_PATH))
    parser.add_argument("--firewall-data", default=str(FW_DATA_ROOT))
    parser.add_argument("--aws-data", default=str(AWS_DATA_ROOT))
    parser.add_argument("--org-file", default=str(ORG_FILE_PATH))
    parser.add_argument("--pan-file", default=str(PAN_TOPOLOGY_PATH))
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    DB_PATH = Path(args.db).resolve()
    FW_DATA_ROOT = Path(args.firewall_data).resolve()
    AWS_DATA_ROOT = Path(args.aws_data).resolve()
    ORG_FILE_PATH = Path(args.org_file).resolve()
    PAN_TOPOLOGY_PATH = Path(args.pan_file).resolve()
    DATA = InfrastructureDataSource(DB_PATH)

    print(f"[*] Starting web server on http://localhost:{args.port}/")
    print(f"[*] Database: {DB_PATH}")
    print("[*] app.py does not ingest. Run ingest.py when parsed JSON changes.")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
