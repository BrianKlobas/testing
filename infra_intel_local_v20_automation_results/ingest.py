#!/usr/bin/env python3
"""Ingest Palo Alto, AWS, and Wiz JSON into the indexed SQLite database."""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterator

from database import (
    DEFAULT_DB_PATH, get_db, init_db, ip_hex, network_bounds, is_noisy_category
)

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_FW_DATA_ROOT = BASE_DIR / "parsed"
DEFAULT_AWS_DATA_ROOT = BASE_DIR / "aws_parsed"
DEFAULT_WIZ_DATA_ROOT = BASE_DIR / "wiz_data"
DEFAULT_ORG_FILE = BASE_DIR / "org_topology.json"

AWS_REF_PATTERNS = {
    "instance": re.compile(r"^i-[0-9a-z]+$", re.I),
    "eni": re.compile(r"^eni-[0-9a-z]+$", re.I),
    "sg": re.compile(r"^sg-[0-9a-z]+$", re.I),
    "subnet": re.compile(r"^subnet-[0-9a-z]+$", re.I),
    "vpc": re.compile(r"^vpc-[0-9a-z]+$", re.I),
}
KEY_REF_TYPES = {
    "instanceid": "instance", "networkinterfaceid": "eni", "groupid": "sg",
    "vpcsecuritygroupid": "sg", "subnetid": "subnet", "vpcid": "vpc",
}
DNS_KEYS = {"name", "dnsname", "privatednsname", "publicdnsname", "fqdn", "recordname", "hostedzonename", "canonicalhostedzonename"}


def json_candidates(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    return []


def panos_record_name(item: dict[str, Any]) -> str:
    for value in (item.get("name"), item.get("@name")):
        if value:
            return str(value)
    for key in ("object", "rule", "profile", "entry"):
        value = item.get(key)
        if isinstance(value, dict):
            name = value.get("name") or value.get("@name")
            if name:
                return str(name)
    return ""


def _pan_path_value(item: Any) -> str:
    """Return a parser-supplied PAN config path when present."""
    if isinstance(item, dict):
        for key in ("path", "xpath", "config_path", "config-path"):
            value = item.get(key)
            if value:
                return str(value)
        for key in ("object", "rule", "profile", "entry"):
            value = item.get(key)
            if isinstance(value, dict):
                found = _pan_path_value(value)
                if found:
                    return found
    return ""


def panos_category(base_category: str, rel_path: Path, item: Any) -> str:
    """Normalize authoritative shared PAN config paths to searchable categories.

    This lets object search work even when the source JSON filename is generic
    (for example all_entries.json). The per-entry config path is authoritative.
    """
    path_text = str(rel_path).replace("\\", "/").lower()
    item_path = _pan_path_value(item).replace("\\", "/").lower()
    combined = f"{path_text} {item_path}"
    if "/config/shared/application/entry" in combined:
        return "application"
    if "/config/shared/profiles/custom-url-category/entry" in combined:
        return "custom_url_category"
    return base_category


def aws_record_name(item: dict[str, Any]) -> str:
    for key in ("InstanceId", "NetworkInterfaceId", "GroupId", "SubnetId", "VpcId", "DBInstanceIdentifier", "DBInstanceId", "LoadBalancerName", "LoadBalancerArn", "HostedZoneId", "Id", "Name"):
        if item.get(key):
            value = str(item[key])
            return value.split("/")[-1] if value.startswith("arn:") else value
    records = item.get("ResourceRecordSets")
    if isinstance(records, list) and records and isinstance(records[0], dict) and records[0].get("Name"):
        return str(records[0]["Name"])
    return str(item.get("GroupName") or "AWS-Resource")


def walk_scalars(obj: Any, path: str = "$") -> Iterator[tuple[str, str, str]]:
    if isinstance(obj, dict):
        for key, value in obj.items():
            child = f"{path}.{key}"
            if isinstance(value, (dict, list)):
                yield from walk_scalars(value, child)
            elif value is not None:
                yield child, str(key), str(value)
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            child = f"{path}[{i}]"
            if isinstance(value, (dict, list)):
                yield from walk_scalars(value, child)
            elif value is not None:
                yield child, "", str(value)


def classify_ref(key: str, value: str) -> str | None:
    compact = key.replace("-", "_").lower().replace("_", "")
    if compact in KEY_REF_TYPES:
        return KEY_REF_TYPES[compact]
    for ref_type, pattern in AWS_REF_PATTERNS.items():
        if pattern.match(value):
            return ref_type
    if value.lower().startswith("arn:aws:"):
        return "arn"
    if compact in {x.replace("_", "") for x in DNS_KEYS}:
        return "dns"
    return None


def _network_type(value: str) -> str:
    if "/" not in value and "-" in value:
        try:
            a, b = value.split("-", 1)
            if ipaddress.ip_address(a.strip()).version == ipaddress.ip_address(b.strip()).version:
                return "range"
        except ValueError:
            pass
    return "network"


def _pan_payload(item: dict[str, Any]) -> dict[str, Any]:
    for key in ("object", "rule", "profile"):
        if isinstance(item.get(key), dict):
            return item[key]
    return item


def _flatten(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (str, int, float, bool)):
        return [str(value)]
    if isinstance(value, list):
        out: list[str] = []
        for x in value:
            out.extend(_flatten(x))
        return out
    if isinstance(value, dict):
        if "member" in value:
            return _flatten(value["member"])
        out: list[str] = []
        for x in value.values():
            out.extend(_flatten(x))
        return out
    return []


def _find_key(obj: Any, names: set[str]) -> Any:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in names:
                return v
        for v in obj.values():
            hit = _find_key(v, names)
            if hit is not None:
                return hit
    elif isinstance(obj, list):
        for v in obj:
            hit = _find_key(v, names)
            if hit is not None:
                return hit
    return None


def _pan_role(category: str, item: dict[str, Any]) -> str:
    cat = category.replace("-", "_").lower()
    if "all_entries" in cat:
        return "raw"
    if "rule" in cat or "policy" in cat or "nat" in cat or "pbf" in cat or "qos" in cat or "decryption" in cat or "override" in cat or "authentication" in cat:
        return "rule"
    if "service_group" in cat:
        return "service_group"
    if "service" in cat and "group" not in cat:
        return "service"
    if "address_group" in cat:
        return "group"
    if "address" in cat:
        return "object"
    payload = _pan_payload(item)
    keys = {str(k).lower() for k in payload}
    if "action" in keys and ("source" in keys or "destination" in keys):
        return "rule"
    if "static" in keys or "member" in keys:
        return "group"
    return "other"


def _index_pan_relationships(cur: sqlite3.Cursor, rid: int, category: str, item: dict[str, Any]) -> None:
    role = _pan_role(category, item)
    payload = _pan_payload(item)
    if role in {"group", "service_group"}:
        members = _find_key(payload, {"static", "member", "members"})
        values = sorted(set(x for x in _flatten(members) if x))
        cur.executemany("INSERT INTO pan_group_members(group_record_id,member_name,member_name_lower) VALUES(?,?,?)",
                        [(rid, x, x.lower()) for x in values])
    if role == "rule":
        for field in ("source", "destination", "service"):
            value = _find_key(payload, {field})
            refs = sorted(set(x for x in _flatten(value) if x))
            cur.executemany("INSERT INTO pan_rule_refs(rule_record_id,field,ref_name,ref_name_lower) VALUES(?,?,?,?)",
                            [(rid, field, x, x.lower()) for x in refs])
            # Literal CIDRs/IPs/ranges inside rules get their own fast index.
            netrows = []
            for x in refs:
                bounds = network_bounds(x)
                if bounds:
                    version, start, end = bounds
                    netrows.append((rid, field, version, ip_hex(start), ip_hex(end), x))
            if netrows:
                cur.executemany("INSERT INTO pan_rule_networks(rule_record_id,field,version,start_hex,end_hex,value) VALUES(?,?,?,?,?,?)", netrows)


def index_record(cur: sqlite3.Cursor, rid: int, item: dict[str, Any], record_name: str, platform: str, category: str) -> tuple[int, int, int]:
    """Index one record.

    Aggregate/safety-net PAN JSON (all_entries/all_objects/etc.) is retained in
    records so it can be shown in the expandable noise tray, but it is deliberately
    excluded from network/ref/relationship indexes. Otherwise ancestor entries can
    recursively contain thousands of IPs and swamp a normal /32 lookup.
    """
    terms: set[tuple[str, str, str, str]] = set()
    refs: set[tuple[str, str, str]] = set()
    networks: set[tuple[int, str, str, str, str, str]] = set()
    noisy = platform == "panos" and is_noisy_category(category)

    if record_name:
        terms.add((record_name, record_name.lower(), "name", "$.name"))

    if noisy:
        # Keep only the record name/path searchable. Do not recursively index the
        # nested aggregate payload; it remains available as raw JSON in records.data.
        path_value = item.get("path") if isinstance(item, dict) else None
        if path_value:
            terms.add((str(path_value), str(path_value).lower(), "path", "$.path"))
    else:
        for json_path, key, raw in walk_scalars(item):
            value = raw.strip()
            if not value or len(value) > 4096:
                continue
            terms.add((value, value.lower(), "value", json_path))
            ref_type = classify_ref(key, value)
            if ref_type:
                refs.add((ref_type, value, json_path))
            bounds = network_bounds(value)
            if bounds:
                version, start, end = bounds
                networks.add((version, ip_hex(start), ip_hex(end), value, _network_type(value), json_path))

    cur.executemany("INSERT INTO record_terms(record_id,term,term_lower,term_type,json_path) VALUES(?,?,?,?,?)",
                    [(rid, *x) for x in terms])
    cur.executemany("INSERT INTO record_refs(record_id,ref_type,ref_value,ref_value_lower,json_path) VALUES(?,?,?,?,?)",
                    [(rid, a, b, b.lower(), c) for a, b, c in refs])
    cur.executemany("INSERT INTO record_networks(record_id,version,start_hex,end_hex,value,network_type,json_path) VALUES(?,?,?,?,?,?,?)",
                    [(rid, *x) for x in networks])
    if platform == "panos" and not noisy:
        _index_pan_relationships(cur, rid, category, item)
    return len(terms), len(networks), len(refs)


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _wiz_issue_nodes(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    data = payload.get("data", payload)
    if not isinstance(data, dict):
        return []
    issues = data.get("issuesV2")
    if isinstance(issues, dict) and isinstance(issues.get("nodes"), list):
        return [x for x in issues["nodes"] if isinstance(x, dict)]
    if isinstance(data.get("nodes"), list):
        return [x for x in data["nodes"] if isinstance(x, dict)]
    return []


def _wiz_account_id(issue: dict[str, Any]) -> str:
    snap = issue.get("entitySnapshot") if isinstance(issue.get("entitySnapshot"), dict) else {}
    for key in ("accountId", "account_id", "subscriptionId"):
        if snap.get(key):
            return str(snap[key])
    arn = str(snap.get("providerId") or "")
    m = re.search(r"arn:aws:[^:]+:[^:]*:(\d{12}):", arn)
    return m.group(1) if m else ""


def _load_org_accounts(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    roots = data.get("Hierarchy", data) if isinstance(data, dict) else data
    out: dict[str, dict[str, Any]] = {}

    def walk(node: Any, ou_path: list[str]) -> None:
        if not isinstance(node, dict):
            return
        name = str(node.get("Name") or node.get("name") or node.get("Id") or "")
        current_path = ou_path + ([name] if name else [])
        for acc in node.get("Accounts") or node.get("AccountList") or []:
            if not isinstance(acc, dict):
                continue
            aid = str(acc.get("Id") or acc.get("AccountId") or "").strip()
            if not aid:
                continue
            tags = acc.get("Tags") if isinstance(acc.get("Tags"), dict) else {}
            out[aid] = {
                "ou": name or (ou_path[-1] if ou_path else ""),
                "ou_path": current_path,
                "account_name": acc.get("Name") or acc.get("name") or aid,
                "primary_owner": acc.get("PrimaryOwner") or tags.get("PrimaryOwner", ""),
                "secondary_owner": acc.get("SecondaryOwner") or tags.get("SecondaryOwner", ""),
            }
        for child_key in ("Children", "OUs", "OrganizationalUnits", "Units"):
            children = node.get(child_key)
            if isinstance(children, list):
                for child in children:
                    walk(child, current_path)
        for child in node.get("Children") or [] if isinstance(node.get("Children"), list) else []:
            if isinstance(child, dict):
                walk(child, current_path)

    if isinstance(roots, list):
        for root in roots:
            walk(root, [])
    else:
        walk(roots, [])
    return out


def ingest_wiz_data(cur: sqlite3.Cursor, wiz_root: Path, org_file: Path, counts: dict[str, int]) -> None:
    if not wiz_root.exists():
        return
    accounts = _load_org_accounts(org_file)
    issues_by_id: dict[str, dict[str, Any]] = {}
    source_files: list[str] = []
    issue_source: dict[str, str] = {}
    for path in sorted(wiz_root.glob("*.json"), key=lambda x: x.name.lower()):
        try:
            payload = _load_json(path)
        except Exception as exc:
            counts["bad_files"] += 1
            print(f"[!] Wiz JSON skipped: {path} ({exc})")
            continue
        nodes = _wiz_issue_nodes(payload)
        if not nodes:
            continue
        source_files.append(path.name)
        for issue in nodes:
            issue_id = str(issue.get("id") or "").strip()
            if issue_id:
                issues_by_id[issue_id] = issue
                issue_source[issue_id] = path.name
    counts["wiz_files"] = len(source_files)
    counts["wiz_issues"] = len(issues_by_id)

    cur.execute("DELETE FROM wiz_issues")
    cur.execute("DELETE FROM wiz_policies")
    cur.execute("DELETE FROM wiz_security_groups")
    policies: dict[str, dict[str, Any]] = {}
    groups: dict[str, dict[str, Any]] = {}

    for issue_id, issue in issues_by_id.items():
        snap = issue.get("entitySnapshot") if isinstance(issue.get("entitySnapshot"), dict) else {}
        control = issue.get("control") if isinstance(issue.get("control"), dict) else {}
        rule = issue.get("sourceRule") if isinstance(issue.get("sourceRule"), dict) else {}
        native = str(snap.get("nativeType") or "")
        external = str(snap.get("externalId") or "")
        provider = str(snap.get("providerId") or "")
        aid = _wiz_account_id(issue)
        raw = json.dumps(issue, separators=(",", ":"), default=str)
        cur.execute("""INSERT INTO wiz_issues(
            issue_id,status,severity,issue_type,created_at,updated_at,policy_id,policy_name,
            source_rule_id,source_rule_name,entity_id,resource_type,native_type,external_id,
            provider_id,resource_name,region,cloud_platform,cloud_provider_url,account_id,source_file,raw_json
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            issue_id, str(issue.get("status") or ""), str(issue.get("severity") or ""), str(issue.get("type") or ""),
            str(issue.get("createdAt") or ""), str(issue.get("updatedAt") or ""), str(control.get("id") or ""),
            str(control.get("name") or ""), str(rule.get("id") or ""), str(rule.get("name") or ""),
            str(snap.get("id") or ""), str(snap.get("type") or ""), native, external, provider,
            str(snap.get("name") or ""), str(snap.get("region") or ""), str(snap.get("cloudPlatform") or ""),
            str(snap.get("cloudProviderURL") or ""), aid, issue_source.get(issue_id, ""), raw
        ))
        pid = str(control.get("id") or control.get("name") or "").strip()
        if pid:
            policies.setdefault(pid, {"name": str(control.get("name") or pid), "count": 0})["count"] += 1
        if native.lower() == "securitygroup" and external:
            g = groups.setdefault(external, {"arn": provider, "name": str(snap.get("name") or ""), "region": str(snap.get("region") or ""), "account_id": aid, "entity_id": str(snap.get("id") or ""), "count": 0})
            g["count"] += 1
            if provider: g["arn"] = provider
            if snap.get("name"): g["name"] = str(snap["name"])
            if aid: g["account_id"] = aid

    for pid, value in policies.items():
        cur.execute("INSERT INTO wiz_policies(policy_id,policy_name,issue_count) VALUES(?,?,?)", (pid, value["name"], value["count"]))
    for gid, value in groups.items():
        cur.execute("INSERT INTO wiz_security_groups(security_group_id,security_group_arn,resource_name,region,account_id,wiz_entity_id,issue_count) VALUES(?,?,?,?,?,?,?)",
                    (gid, value["arn"], value["name"], value["region"], value["account_id"], value["entity_id"], value["count"]))
    counts["wiz_policies"] = len(policies)
    counts["wiz_security_groups"] = len(groups)


def ingest_data(fw_root: Path = DEFAULT_FW_DATA_ROOT, aws_root: Path = DEFAULT_AWS_DATA_ROOT,
                db_file: Path = DEFAULT_DB_PATH, *, reset: bool = True,
                wiz_root: Path = DEFAULT_WIZ_DATA_ROOT, org_file: Path = DEFAULT_ORG_FILE) -> dict[str, int]:
    fw_root, aws_root, db_file = Path(fw_root).resolve(), Path(aws_root).resolve(), Path(db_file).resolve()
    wiz_root, org_file = Path(wiz_root).resolve(), Path(org_file).resolve()
    init_db(db_file, reset=reset)
    conn = get_db(db_file)
    cur = conn.cursor()
    counts = {"panos_files": 0, "panos_records": 0, "aws_files": 0, "aws_records": 0,
              "wiz_files": 0, "wiz_issues": 0, "wiz_policies": 0, "wiz_security_groups": 0,
              "terms": 0, "networks": 0, "refs": 0, "bad_files": 0}
    device_cache: dict[str, int] = {}

    def device_id(name: str) -> int:
        if name in device_cache:
            return device_cache[name]
        cur.execute("INSERT OR IGNORE INTO devices(name) VALUES(?)", (name,))
        rid = cur.execute("SELECT id FROM devices WHERE name=?", (name,)).fetchone()[0]
        device_cache[name] = int(rid)
        return int(rid)

    def insert(dev: int, platform: str, category: str, path: Path, name: str, item: dict[str, Any]) -> None:
        cur.execute("INSERT INTO records(device_id,platform,category,filename,name,name_lower,data) VALUES(?,?,?,?,?,?,?)",
                    (dev, platform, category, path.name, name, name.lower() if name else "", json.dumps(item, separators=(",", ":"))))
        rid = int(cur.lastrowid)
        t, n, r = index_record(cur, rid, item, name, platform, category)
        counts["terms"] += t; counts["networks"] += n; counts["refs"] += r

    try:
        cur.execute("BEGIN")
        if fw_root.exists():
            for path in sorted(fw_root.rglob("*.json")):
                try:
                    data = _load_json(path)
                except Exception as exc:
                    counts["bad_files"] += 1; print(f"[!] PAN JSON skipped: {path} ({exc})"); continue
                candidates = json_candidates(data)
                counts["panos_files"] += 1
                rel = path.relative_to(fw_root)
                device = rel.parts[0] if len(rel.parts) > 1 else "(root)"
                dev = device_id(device)
                category = path.stem.replace("-", "_").lower()
                for item in candidates:
                    item_category = panos_category(category, rel, item)
                    insert(dev, "panos", item_category, path, panos_record_name(item), item)
                    counts["panos_records"] += 1
                if not candidates:
                    print(f"[!] PAN JSON contains no object records: {path}")

        if aws_root.exists():
            for path in sorted(aws_root.rglob("*.json")):
                try:
                    data = _load_json(path)
                except Exception as exc:
                    counts["bad_files"] += 1; print(f"[!] AWS JSON skipped: {path} ({exc})"); continue
                candidates = json_candidates(data)
                counts["aws_files"] += 1
                rel = path.relative_to(aws_root)
                account = rel.parts[0] if rel.parts else "(root)"
                dev = device_id(f"AWS: {account}")
                category = path.stem.replace("-", "_").lower()
                for item in candidates:
                    insert(dev, "aws", category, path, aws_record_name(item), item)
                    counts["aws_records"] += 1
                if not candidates:
                    print(f"[!] AWS JSON contains no records: {path}")
        if wiz_root.exists():
            ingest_wiz_data(cur, wiz_root, org_file, counts)
        conn.commit()
        # Query planner statistics dramatically help this many-row database.
        conn.execute("ANALYZE")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Infrastructure Intelligence JSON -> SQLite ingest")
    parser.add_argument("--firewall-data", default=str(DEFAULT_FW_DATA_ROOT))
    parser.add_argument("--aws-data", default=str(DEFAULT_AWS_DATA_ROOT))
    parser.add_argument("--wiz-data", default=str(DEFAULT_WIZ_DATA_ROOT))
    parser.add_argument("--org-file", default=str(DEFAULT_ORG_FILE))
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH))
    parser.add_argument("--no-reset", action="store_true", help="Append instead of rebuilding (normally not recommended)")
    args = parser.parse_args()
    fw, aws, wiz, org, db = Path(args.firewall_data), Path(args.aws_data), Path(args.wiz_data), Path(args.org_file), Path(args.db)
    print("=" * 72)
    print("INFRASTRUCTURE INTELLIGENCE - JSON -> SQLITE INGEST")
    print("=" * 72)
    print(f"PAN JSON : {fw.resolve()} {'[FOUND]' if fw.exists() else '[NOT FOUND]'}")
    print(f"AWS JSON : {aws.resolve()} {'[FOUND]' if aws.exists() else '[NOT FOUND]'}")
    print(f"Wiz JSON : {wiz.resolve()} {'[FOUND]' if wiz.exists() else '[NOT FOUND]'}")
    print(f"Org JSON : {org.resolve()} {'[FOUND]' if org.exists() else '[NOT FOUND]'}")
    print(f"Database : {db.resolve()}")
    print(f"Mode     : {'append' if args.no_reset else 'FULL REBUILD'}")
    counts = ingest_data(fw, aws, db, reset=not args.no_reset, wiz_root=wiz, org_file=org)
    print("\n" + "-" * 72)
    print(f"PAN files/records : {counts['panos_files']:,} / {counts['panos_records']:,}")
    print(f"AWS files/records : {counts['aws_files']:,} / {counts['aws_records']:,}")
    print(f"Wiz files/issues  : {counts['wiz_files']:,} / {counts['wiz_issues']:,}")
    print(f"Wiz policies/SGs  : {counts['wiz_policies']:,} / {counts['wiz_security_groups']:,}")
    print(f"Indexed terms     : {counts['terms']:,}")
    print(f"Indexed networks  : {counts['networks']:,}")
    print(f"Indexed refs      : {counts['refs']:,}")
    print(f"Bad JSON files    : {counts['bad_files']:,}")
    print(f"Database          : {db.resolve()}")
    print("-" * 72)

if __name__ == "__main__":
    main()
