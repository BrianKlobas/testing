#!/usr/bin/env python3
"""Infrastructure Intelligence Flask application.

The app never ingests JSON. Run ingest.py when source JSON changes.
This version is optimized for millions of indexed terms/references and hundreds
of thousands of networks by resolving Palo relationships with SQL indexes.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable

from flask import Flask, jsonify, render_template, request
from markupsafe import Markup, escape
from urllib.parse import quote

from database import (
    DEFAULT_DB_PATH, classify_ip_search, extract_direct_attached_sg_ids,
    fetch_records_by_ids, find_network_record_ids, get_db,
    get_file_modified_time, get_latest_dir_mtime, network_bounds,
    value_matches_network_or_range, is_noisy_category,
)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = DEFAULT_DB_PATH
FW_DATA_ROOT = BASE_DIR / "parsed"
AWS_DATA_ROOT = BASE_DIR / "aws_parsed"
ORG_FILE_PATH = BASE_DIR / "org_topology.json"
PAN_TOPOLOGY_PATH = BASE_DIR / "panorama_topology.json"
AUTOMATION_RESULTS_ROOT = BASE_DIR / "automation_results"
app = Flask(__name__, static_folder=str(BASE_DIR / "static"), static_url_path="/static", template_folder=str(BASE_DIR / "templates"))


def _safe_json(raw: str) -> Any:
    try: return json.loads(raw)
    except Exception: return {}


def _record(row: Any, *, reason: str | None = None, matched_value: str | None = None) -> dict[str, Any]:
    """Normalize a DB row and tolerate helper queries that omit display columns."""
    keys = set(row.keys()) if hasattr(row, "keys") else set()
    def rv(key: str, default: Any = "") -> Any:
        try:
            return row[key] if not keys or key in keys else default
        except (KeyError, IndexError, TypeError):
            return default
    rec = {
        "record_id": int(rv("id", -1)),
        "device": rv("device", f"device_id:{rv('device_id','?')}"),
        "platform": rv("platform", ""),
        "type": rv("category", ""),
        "category": rv("category", ""),
        "file": rv("filename", ""),
        "name": rv("name", "") or "",
        "data": _safe_json(rv("data", "{}")),
    }
    if reason:
        rec["match_reason"] = reason
    if matched_value:
        rec["matched_value"] = matched_value
    return rec


def _dedupe(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate semantically identical display records, not just DB row IDs."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for x in records:
        data = x.get("data") if isinstance(x.get("data"), dict) else {}
        path = str(data.get("path") or "").lower()
        key = (
            str(x.get("platform") or "").lower(),
            str(x.get("device") or "").lower(),
            str(x.get("category") or x.get("type") or "").lower(),
            str(x.get("name") or "").lower(),
            path,
        )
        # unnamed records need record_id so unrelated AWS blobs are not collapsed
        if not key[3] and not path:
            key = (*key, int(x.get("record_id", -1)))
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out


def _cat(category: str) -> str: return str(category or "").replace("-", "_").lower()


def _pan_payload(data: Any) -> dict[str, Any]:
    if isinstance(data, dict):
        for k in ("object", "rule", "profile"):
            if isinstance(data.get(k), dict): return data[k]
        if isinstance(data.get("entry"), dict): return data["entry"]
        return data
    return {}


def _flatten(v: Any) -> list[str]:
    if v is None: return []
    if isinstance(v, (str, int, float, bool)): return [str(v)]
    if isinstance(v, list):
        o=[]
        for x in v: o.extend(_flatten(x))
        return o
    if isinstance(v, dict):
        if "member" in v: return _flatten(v["member"])
        o=[]
        for x in v.values(): o.extend(_flatten(x))
        return o
    return []


def _find_key(obj: Any, names: set[str]) -> Any:
    if isinstance(obj, dict):
        for k,v in obj.items():
            if str(k).lower() in names: return v
        for v in obj.values():
            x=_find_key(v,names)
            if x is not None: return x
    elif isinstance(obj,list):
        for v in obj:
            x=_find_key(v,names)
            if x is not None: return x
    return None


def _pan_role(category: str, data: Any) -> str:
    c = _cat(category)
    if is_noisy_category(c):
        return "raw"
    if any(x in c for x in ("rule","policy","nat","pbf","qos","decryption","override","authentication")):
        return "rule"
    if "service_group" in c:
        return "service_group"
    if "service" in c and "group" not in c:
        return "service"
    if "address_group" in c:
        return "group"
    if "address" in c:
        return "object"
    p = _pan_payload(data)
    keys = {str(k).lower() for k in p}
    if "action" in keys and ("source" in keys or "destination" in keys):
        return "rule"
    if "static" in keys or "member" in keys:
        return "group"
    return "other"


def _is_raw(row: Any) -> bool:
    return is_noisy_category(row["category"])


def _is_sg(category: str, item: dict[str,Any]) -> bool:
    c=_cat(category)
    return "security_group" in c and ("GroupId" in item or "IpPermissions" in item or "IpPermissionsEgress" in item)


def _rule_action(rec: dict[str,Any]) -> str:
    vals=_flatten(_find_key(_pan_payload(rec.get("data",{})),{"action"}))
    return vals[0] if vals else "unknown"


def _rule_field(rec: dict[str,Any], field: str) -> list[str]:
    return [x for x in _flatten(_find_key(_pan_payload(rec.get("data",{})),{field})) if x]


def _group_members(rec: dict[str,Any]) -> list[str]:
    return _rule_field(rec,"static") or _rule_field(rec,"member") or _rule_field(rec,"members")


def _is_compute(category: str) -> bool:
    c=_cat(category)
    return any(x in c for x in ("instance","ec2","network_interface","eni","load_balancer","rds","db_instance","lambda"))


def _network_values(conn: sqlite3.Connection, ids: Iterable[int]) -> list[str]:
    ids=list(dict.fromkeys(int(x) for x in ids))
    if not ids:return []
    ph=",".join("?"*len(ids))
    return [str(r[0]) for r in conn.execute(f"SELECT DISTINCT value FROM record_networks WHERE record_id IN ({ph})",ids)]


def _add_ctx(ctx:list[dict[str,Any]], seen:set[str], value:str, source:str, name:str=""):
    if not network_bounds(value): return
    k=value.lower()
    if k not in seen:
        seen.add(k); ctx.append({"value":value,"source":source,"name":name})


def _normal_record_predicate(alias: str = "r") -> str:
    c = f"lower(replace({alias}.category,'-','_'))"
    return (f"{c} NOT LIKE '%all_entries%' AND {c} NOT LIKE '%all_objects%' "
            f"AND {c} NOT LIKE '%all_object_entries%' AND {c} NOT IN ('metadata','summary')")


def _find_pan_network_entity_ids(conn: sqlite3.Connection, value: str, limit: int = 500) -> list[int]:
    """Find real PAN address objects/groups whose network fully contains value."""
    b = network_bounds(value)
    if not b:
        return []
    ver, start, end = b
    pred = _normal_record_predicate("r")
    sql = f"""
        SELECT DISTINCT rn.record_id
        FROM record_networks rn
        JOIN records r ON r.id=rn.record_id
        WHERE r.platform='panos'
          AND rn.version=? AND rn.start_hex<=? AND rn.end_hex>=?
          AND {pred}
          AND lower(replace(r.category,'-','_')) LIKE '%address%'
        LIMIT ?
    """
    return [int(r[0]) for r in conn.execute(sql, (ver, f"{int(start):032x}", f"{int(end):032x}", limit))]


def _noisy_search(
    conn: sqlite3.Connection,
    query: str,
    related_names: Iterable[str] = (),
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Small tray for aggregate PAN JSON; never drives relationships.

    Aggregate records are selected only by exact query/name matches or by names of
    authoritative objects/groups/rules already found. This preserves the duplicate
    raw evidence without recursively indexing or expanding giant all_entries trees.
    """
    q = query.strip().lower()
    names = {str(x).strip().lower() for x in related_names if str(x).strip()}
    if q:
        names.add(q)
    if not names:
        return []
    pred = f"NOT ({_normal_record_predicate('r')})"
    ids: list[int] = []
    for batch_start in range(0, len(names), 100):
        batch = list(names)[batch_start:batch_start + 100]
        ph = ','.join('?' * len(batch))
        ids.extend(int(r[0]) for r in conn.execute(
            f"SELECT id FROM records r WHERE r.platform='panos' AND {pred} AND r.name_lower IN ({ph}) LIMIT ?",
            [*batch, max(0, limit-len(ids))],
        ))
        if len(ids) >= limit:
            break
    # Old databases may still have scalar terms for all_entries. Exact-term only is
    # safe; never use network containment or FTS for noisy records.
    if q and len(ids) < limit:
        ids.extend(int(r[0]) for r in conn.execute(
            f"""SELECT DISTINCT rt.record_id FROM record_terms rt
                JOIN records r ON r.id=rt.record_id
                WHERE r.platform='panos' AND {pred} AND rt.term_lower=? LIMIT ?""",
            (q, limit-len(ids)),
        ))
    return _dedupe([_record(r, reason="noisy_aggregate_duplicate") for r in fetch_records_by_ids(conn, ids)])[:limit]


def _pan_seed_networks(query: str, ctx: list[dict[str, Any]]) -> list[str]:
    """Networks that are allowed to drive PAN roll-up.

    If the user typed an IP/CIDR, that exact query is the only roll-up seed. AWS
    subnet/VPC context is display context, not a new search target. For non-IP
    searches (instance/ENI/DNS/object name), endpoint/resource IPs become seeds.
    """
    if network_bounds(query):
        return [query]
    out: list[str] = []
    seen: set[str] = set()
    for c in ctx:
        if c.get("source") not in {"aws_resource", "palo_object"}:
            continue
        v = str(c.get("value") or "")
        if network_bounds(v) and v.lower() not in seen:
            seen.add(v.lower())
            out.append(v)
    return out[:100]


def _base_search(conn: sqlite3.Connection, query: str, platform: str | None = None, limit: int = 300) -> list[sqlite3.Row]:
    info = classify_ip_search(query)
    ids: list[int] = []
    pred = _normal_record_predicate("r")
    if info["family"] in (4, 6):
        ids = find_network_record_ids(conn, query, platform=platform, limit=max(limit * 4, 1000), include_noisy=False)
    else:
        q = query.strip().lower()
        sql = f"SELECT DISTINCT r.id FROM records r WHERE {pred} AND r.name_lower=?"
        p: list[Any] = [q]
        if platform:
            sql += " AND r.platform=?"; p.append(platform)
        sql += " LIMIT ?"; p.append(limit)
        ids += [int(r[0]) for r in conn.execute(sql, p)]

        sql = f"""SELECT DISTINCT rr.record_id FROM record_refs rr
                  JOIN records r ON r.id=rr.record_id
                  WHERE {pred} AND rr.ref_value_lower=?"""
        p = [q]
        if platform:
            sql += " AND r.platform=?"; p.append(platform)
        sql += " LIMIT ?"; p.append(limit)
        ids += [int(r[0]) for r in conn.execute(sql, p)]

        if len(set(ids)) < limit:
            sql = f"""SELECT DISTINCT rt.record_id FROM record_terms rt
                      JOIN records r ON r.id=rt.record_id
                      WHERE {pred} AND rt.term_lower=?"""
            p = [q]
            if platform:
                sql += " AND r.platform=?"; p.append(platform)
            sql += " LIMIT ?"; p.append(limit)
            ids += [int(r[0]) for r in conn.execute(sql, p)]

        # Partial-name only fallback. Full JSON is intentionally not in FTS anymore.
        if len(set(ids)) < limit and len(q) >= 3:
            toks = re.findall(r"[A-Za-z0-9_./:@-]+", query)
            fts = " AND ".join('"' + t.replace('"','') + '"*' for t in toks if t)
            if fts:
                sql = f"""SELECT f.rowid FROM records_fts f
                          JOIN records r ON r.id=f.rowid
                          WHERE {pred} AND records_fts MATCH ?"""
                p = [fts]
                if platform:
                    sql += " AND r.platform=?"; p.append(platform)
                sql += " LIMIT ?"; p.append(limit)
                try:
                    ids += [int(r[0]) for r in conn.execute(sql, p)]
                except sqlite3.Error:
                    pass
    return fetch_records_by_ids(conn, list(dict.fromkeys(ids))[:limit])


def _fetch_ref(conn, device:str, ref_type:str, value:str, limit:int=200) -> list[sqlite3.Row]:
    return conn.execute("""SELECT DISTINCT r.id,d.name AS device,r.platform,r.category,r.filename,r.name,r.data
        FROM record_refs rr JOIN records r ON r.id=rr.record_id JOIN devices d ON d.id=r.device_id
        WHERE r.platform='aws' AND d.name=? AND rr.ref_type=? AND rr.ref_value_lower=? LIMIT ?""",
        (device,ref_type,value.lower(),limit)).fetchall()


def _aws_ids(item:dict[str,Any]) -> dict[str,set[str]]:
    out={x:set() for x in ("instance","eni","subnet","vpc")}
    def walk(o:Any):
        if isinstance(o,dict):
            for k,v in o.items():
                kl=str(k).lower().replace("_","")
                if isinstance(v,str):
                    if kl=="instanceid" and v.startswith("i-"):out["instance"].add(v)
                    elif kl=="networkinterfaceid" and v.startswith("eni-"):out["eni"].add(v)
                    elif kl=="subnetid" and v.startswith("subnet-"):out["subnet"].add(v)
                    elif kl=="vpcid" and v.startswith("vpc-"):out["vpc"].add(v)
                elif isinstance(v,(dict,list)):walk(v)
        elif isinstance(o,list):
            for x in o:walk(x)
    walk(item); return out


def _aws_expand(conn:sqlite3.Connection, query:str, base:list[sqlite3.Row], limit:int):
    aws=[r for r in base if r["platform"]=="aws"]
    if network_bounds(query): aws=[r for r in aws if not _is_sg(r["category"],_safe_json(r["data"]))]
    related=list(aws); ids={int(r["id"]) for r in related}; sg_pairs=set()
    def add_related(rr):
        if int(rr["id"]) not in ids: ids.add(int(rr["id"])); related.append(rr)
    # Relationship expansion is deliberately shallow and indexed.
    for r in list(related):
        item=_safe_json(r["data"])
        if _is_sg(r["category"],item): continue
        for sg in extract_direct_attached_sg_ids(item): sg_pairs.add((r["device"],sg))
        refs=_aws_ids(item)
        for typ,keep in (("instance",lambda c:_is_compute(c)),("eni",lambda c:"network_interface" in c or "eni" in c or "instance" in c),
                         ("subnet",lambda c:"subnet" in c),("vpc",lambda c:"vpc" in c)):
            for val in refs[typ]:
                for rr in _fetch_ref(conn,r["device"],typ,val,100):
                    if keep(_cat(rr["category"])): add_related(rr)
    # SG reverse lookup: only resources that have the SG in their direct attachment list.
    if query.lower().startswith("sg-"):
        devices={r["device"] for r in aws}
        if not devices: devices=[r[0] for r in conn.execute("SELECT name FROM devices WHERE name LIKE 'AWS:%'")]
        for dev in devices:
            for rr in _fetch_ref(conn,dev,"sg",query,limit):
                if query in extract_direct_attached_sg_ids(_safe_json(rr["data"])): add_related(rr); sg_pairs.add((dev,query))
    # Pull direct SG definitions and compute context.
    for r in list(related):
        item=_safe_json(r["data"])
        if _is_compute(r["category"]):
            for sg in extract_direct_attached_sg_ids(item): sg_pairs.add((r["device"],sg))
    sg_records=[]
    for dev,sg in sorted(sg_pairs):
        for rr in _fetch_ref(conn,dev,"sg",sg,20):
            if _is_sg(rr["category"],_safe_json(rr["data"])):
                x=_record(rr,reason="directly_attached_security_group",matched_value=sg); x["attachment_scope"]="direct"; sg_records.append(x)
    ctx=[]; seen=set()
    if network_bounds(query): _add_ctx(ctx,seen,query,"query")
    for r in related:
        if _is_sg(r["category"],_safe_json(r["data"])): continue
        source="aws_resource"; c=_cat(r["category"])
        if "subnet" in c: source="aws_subnet"
        elif "vpc" in c: source="aws_vpc"
        for v in _network_values(conn,[r["id"]]): _add_ctx(ctx,seen,v,source,r["name"] or "")
    return _dedupe([_record(r,reason="direct_or_related_aws") for r in related]),_dedupe(sg_records),ctx


def _dedupe_rows(rows: list[sqlite3.Row]) -> list[sqlite3.Row]:
    seen = set(); out = []
    for row in rows:
        rid = int(row["id"])
        if rid not in seen: seen.add(rid); out.append(row)
    return out


def _pan_record_rows(conn, ids:list[int]) -> list[sqlite3.Row]:
    return fetch_records_by_ids(conn,ids)


def _pan_entity_candidates(conn, names:set[str], limit:int) -> list[sqlite3.Row]:
    if not names:return []
    ids=[]
    for name in list(names)[:1000]:
        rows=conn.execute("SELECT id FROM records WHERE platform='panos' AND name_lower=? LIMIT ?",(name.lower(),limit)).fetchall()
        ids.extend(int(r[0]) for r in rows)
    return _pan_record_rows(conn,list(dict.fromkeys(ids))[:limit])


def _expand_groups_sql(conn: sqlite3.Connection, names: set[str], limit: int = 1000) -> tuple[set[str], list[sqlite3.Row]]:
    all_names = {x.lower() for x in names if x}
    group_ids: set[int] = set()
    rows: list[sqlite3.Row] = []
    # Upward expansion only: object -> containing group -> containing parent group.
    for _ in range(20):
        if not all_names:
            break
        ph = ','.join('?' * len(all_names))
        found = conn.execute(f"""SELECT DISTINCT
                g.id, g.device_id, d.name AS device, g.platform, g.category,
                g.filename, g.name, g.data
            FROM pan_group_members gm
            JOIN records g ON g.id=gm.group_record_id
            JOIN devices d ON d.id=g.device_id
            WHERE g.platform='panos'
              AND gm.member_name_lower IN ({ph})
            LIMIT ?""", [*all_names, limit]).fetchall()
        new: set[str] = set()
        for r in found:
            if is_noisy_category(r["category"]):
                continue
            rid = int(r["id"])
            n = (r["name"] or "").lower()
            if rid not in group_ids:
                group_ids.add(rid)
                rows.append(r)
                if n and n not in all_names:
                    new.add(n)
        if not new:
            break
        all_names.update(new)
    return all_names, rows


def _pan_inventory(conn: sqlite3.Connection, query: str, base: list[sqlite3.Row], ctx: list[dict[str, Any]], limit: int):
    # Only authoritative PAN records may seed normal object/group/rule expansion.
    ids = {int(r["id"]) for r in base if r["platform"] == "panos" and not _is_raw(r)}
    seed_nets = _pan_seed_networks(query, ctx)

    # For a /32 or CIDR, retrieve only address-object records that CONTAIN the seed.
    # Do not use subnet/VPC roll-up context as fresh search targets.
    for n in seed_nets:
        ids.update(_find_pan_network_entity_ids(conn, n, limit=min(max(limit * 2, 200), 1000)))

    base_pan = _pan_record_rows(conn, list(ids)[:max(limit * 3, 1000)])
    objects: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    entity_names: set[str] = set()

    for r in base_pan:
        if _is_raw(r):
            continue
        role = _pan_role(r["category"], _safe_json(r["data"]))
        rec = _record(r)
        if role == "object":
            objects.append(rec)
            if r["name"]:
                entity_names.add(str(r["name"]).lower())
        elif role in ("group", "service_group"):
            groups.append(rec)
            if r["name"]:
                entity_names.add(str(r["name"]).lower())

    # Object/group membership is expanded upward only; this avoids pulling every
    # child of a large unrelated group into an endpoint lookup.
    expanded_names, group_rows = _expand_groups_sql(conn, entity_names, limit=1000)
    group_seen = {x["record_id"] for x in groups}
    for r in group_rows:
        rec = _record(r, reason="contains_matched_object_or_group")
        if rec["record_id"] not in group_seen:
            groups.append(rec)
            group_seen.add(rec["record_id"])
        if r["name"]:
            expanded_names.add(str(r["name"]).lower())

    # If the original text query was itself a group/object name, keep exact base
    # entities. Do not surface every entity referenced by a matched rule; that was
    # another source of result amplification in the previous version.
    names_for_rules = {x for x in expanded_names if x}
    candidate_rule_ids: set[int] = {
        int(r["id"]) for r in base_pan
        if _pan_role(r["category"], _safe_json(r["data"])) == "rule"
    }

    if names_for_rules:
        ph = ','.join('?' * len(names_for_rules))
        candidate_rule_ids.update(int(r[0]) for r in conn.execute(
            f"SELECT DISTINCT rule_record_id FROM pan_rule_refs WHERE ref_name_lower IN ({ph}) LIMIT 3000",
            [*names_for_rules],
        ))

    # Literal source/destination CIDRs in a rule are matched by containment against
    # the original endpoint seed, not against every larger AWS subnet/VPC context.
    for n in seed_nets:
        bounds = network_bounds(n)
        if not bounds:
            continue
        ver, start, end = bounds
        candidate_rule_ids.update(int(r[0]) for r in conn.execute(
            """SELECT DISTINCT rule_record_id FROM pan_rule_networks
               WHERE version=? AND start_hex<=? AND end_hex>=? LIMIT 3000""",
            (ver, f"{int(start):032x}", f"{int(end):032x}"),
        ))

    rule_rows = _pan_record_rows(conn, list(candidate_rule_ids)[:5000]) if candidate_rule_ids else []
    matched_rules: list[dict[str, Any]] = []
    names = {x.lower() for x in expanded_names if x}
    for r in rule_rows:
        if _pan_role(r["category"], _safe_json(r["data"])) != "rule":
            continue
        rec = _record(r)
        reasons: list[str] = []
        fields: list[str] = []
        for field in ("source", "destination"):
            hit = False
            for ref in _rule_field(rec, field):
                rl = ref.lower()
                if rl in names:
                    hit = True; reasons.append(f"{field}:object:{ref}")
                elif network_bounds(ref) and any(value_matches_network_or_range(ref, n) for n in seed_nets):
                    hit = True; reasons.append(f"{field}:network:{ref}")
                elif rl == "any" and candidate_rule_ids:
                    # 'any' is relevant only after some other aspect selected this rule.
                    reasons.append(f"{field}:any")
            if hit:
                fields.append(field)
        # A direct rule-name search is allowed through even without endpoint fields.
        direct_rule = int(r["id"]) in {int(x["id"]) for x in base_pan if _pan_role(x["category"], _safe_json(x["data"])) == "rule"}
        if not fields and not direct_rule:
            continue
        rec["match_fields"] = fields
        rec["action"] = _rule_action(rec)
        rec["decision"] = _decision(rec["action"])
        rec["match_details"] = {"fields": reasons, "rollup_seeds": seed_nets}
        matched_rules.append(rec)

    # Soft display caps are intentionally much smaller than DB candidate caps.
    return _dedupe(objects)[:250], _dedupe(groups)[:250], _dedupe(matched_rules)[:500], []


def _decision(action:str)->str:
    a=str(action or "").lower()
    if a=="allow":return "ALLOWED"
    if a in {"deny","drop","reject","reset-client","reset-server","reset-both"}:return "DENIED"
    if a in {"disabled","disable"}:return "DISABLED"
    return "OTHER"


def _parse_port(port:str):
    raw=port.strip().lower(); proto=None
    if raw.startswith("tcp"):proto="tcp"
    elif raw.startswith("udp"):proto="udp"
    m=re.search(r"(?<!\d)(\d{1,5})(?!\d)",raw)
    return proto,int(m.group(1)) if m else None,raw


def _service_specs(data:Any)->list[str]:
    vals=[]
    def walk(o:Any,key=""):
        if isinstance(o,dict):
            for k,v in o.items():
                kl=str(k).lower().replace("_","-")
                if kl in {"port","destination-port","source-port"} and not isinstance(v,(dict,list)):vals.append(str(v))
                else:walk(v,k)
        elif isinstance(o,list):
            for x in o:walk(x,key)
    walk(_pan_payload(data)); return vals


def _port_spec_hit(port:int,spec:str)->bool:
    for p in re.split(r"[,\s]+",spec):
        if "-" in p:
            a,b=p.split("-",1)
            if a.isdigit() and b.isdigit() and int(a)<=port<=int(b):return True
        elif p.isdigit() and int(p)==port:return True
    return False


def _service_hit(conn: sqlite3.Connection, refs: list[str], port: str, cache: dict[str, list[sqlite3.Row]], visited=None) -> bool:
    if not port:
        return True
    proto, num, raw = _parse_port(port)
    if any(x.lower() == "any" for x in refs):
        return True
    if num is None:
        return False
    if visited is None:
        visited = set()

    def one(ref: str) -> bool:
        key = ref.lower()
        if key in visited:
            return False
        visited.add(key)
        if re.search(rf"(?<!\d){num}(?!\d)", key):
            return True
        if key not in cache:
            cache[key] = conn.execute("""SELECT r.id,r.device_id,d.name AS device,r.platform,
                    r.category,r.filename,r.name,r.data
                FROM records r JOIN devices d ON d.id=r.device_id
                WHERE r.platform='panos' AND r.name_lower=? LIMIT 50""", (key,)).fetchall()
        for r in cache[key]:
            if is_noisy_category(r["category"]):
                continue
            role = _pan_role(r["category"], _safe_json(r["data"]))
            if role == "service_group":
                rec = _record(r)
                if any(one(x) for x in _group_members(rec)):
                    return True
            elif role == "service":
                blob = str(r["data"]).lower()
                if proto and proto not in blob:
                    continue
                if any(_port_spec_hit(num, s) for s in _service_specs(_safe_json(r["data"]))):
                    return True
        return False
    return any(one(x) for x in refs)


def _route53_query_matches(record: dict[str, Any], query: str) -> bool:
    """Return True only when this individual Route53 record matches the query."""
    q = str(query or "").strip()
    if not q:
        return False
    qlow = q.lower()
    values: list[str] = []
    name = record.get("Name") or record.get("name")
    if name:
        values.append(str(name))
    rtype = record.get("Type") or record.get("type")
    if rtype:
        values.append(str(rtype))
    for rr in record.get("ResourceRecords") or []:
        if isinstance(rr, dict) and rr.get("Value") is not None:
            values.append(str(rr["Value"]))
        elif rr is not None:
            values.append(str(rr))
    alias = record.get("AliasTarget") or record.get("alias_target")
    if isinstance(alias, dict):
        for k in ("DNSName", "HostedZoneId", "EvaluateTargetHealth"):
            if alias.get(k) is not None:
                values.append(str(alias[k]))
    elif alias:
        values.append(str(alias))
    if record.get("Value") is not None:
        values.append(str(record["Value"]))

    info = classify_ip_search(q)
    if info.get("family") in (4, 6):
        qb = network_bounds(q)
        if not qb:
            return False
        for value in values:
            vb = network_bounds(value)
            if vb and vb[0] == qb[0] and vb[1] <= qb[1] and vb[2] >= qb[2]:
                return True
        return False
    return any(qlow in value.lower() for value in values)


def _route53_child_records(row: sqlite3.Row, query: str) -> list[dict[str, Any]]:
    """Convert a collector's hosted-zone blob into only the matching RRsets."""
    data = _safe_json(row["data"])
    record_sets = data.get("ResourceRecordSets") if isinstance(data, dict) else None
    if not isinstance(record_sets, list):
        return []
    zone_name = data.get("Name") or data.get("name") or ""
    zone_id = data.get("Id") or data.get("HostedZoneId") or ""
    out = []
    for rr in record_sets:
        if not isinstance(rr, dict) or not _route53_query_matches(rr, query):
            continue
        child = dict(rr)
        child["HostedZoneName"] = zone_name
        child["HostedZoneId"] = zone_id
        out.append({
            "record_id": f'{int(row["id"])}:{str(rr.get("Name") or "")}:{str(rr.get("Type") or "")}',
            "device": row["device"],
            "platform": "aws",
            "type": "route53_record",
            "category": "route53_record",
            "file": row["filename"],
            "name": str(rr.get("Name") or zone_name or "Route53 Record"),
            "data": child,
            "match_reason": "matched_route53_record",
            "matched_value": query,
        })
    return out


def _expand_route53_matches(conn: sqlite3.Connection, records: list[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for rec in records:
        if rec.get("platform") != "aws":
            out.append(rec)
            continue
        cat = _cat(rec.get("category", ""))
        data = rec.get("data") if isinstance(rec.get("data"), dict) else {}
        if "route53" not in cat and "hostedzone" not in cat and "resource_record_sets" not in data:
            out.append(rec)
            continue
        # Find the original zone row and emit only matching RRsets.
        rid = str(rec.get("record_id", ""))
        try:
            base_id = int(rid.split(":", 1)[0])
        except (TypeError, ValueError):
            base_id = None
        if base_id is None:
            continue
        rows = conn.execute("""SELECT r.id,r.device_id,d.name AS device,r.platform,r.category,r.filename,r.name,r.data
                              FROM records r JOIN devices d ON d.id=r.device_id WHERE r.id=?""", (base_id,)).fetchall()
        if rows:
            out.extend(_route53_child_records(rows[0], query))
    return out


class InfrastructureDataSource:
    def __init__(self, db_file: Path | None = None):
        self._db_file = db_file

    @property
    def db_file(self):
        return self._db_file or DB_PATH

    def files_count(self):
        c = get_db(self.db_file)
        try:
            return int(c.execute("SELECT COUNT(*) FROM records").fetchone()[0])
        finally:
            c.close()

    def devices_count(self):
        c = get_db(self.db_file)
        try:
            return int(c.execute("SELECT COUNT(*) FROM devices").fetchone()[0])
        finally:
            c.close()

    def get_stats(self):
        c = get_db(self.db_file)
        try:
            return {
                "panos": {r["category"]: r["cnt"] for r in c.execute("SELECT category,COUNT(*) cnt FROM records WHERE platform='panos' GROUP BY category")},
                "aws_resources": {r["category"]: r["cnt"] for r in c.execute("SELECT category,COUNT(*) cnt FROM records WHERE platform='aws' GROUP BY category")},
                "aws_accounts_scanned": int(c.execute("SELECT COUNT(*) FROM devices WHERE name LIKE 'AWS:%'").fetchone()[0]),
                "total_files": int(c.execute("SELECT COUNT(*) FROM records").fetchone()[0]),
                "indexed_terms": int(c.execute("SELECT COUNT(*) FROM record_terms").fetchone()[0]),
                "indexed_networks": int(c.execute("SELECT COUNT(*) FROM record_networks").fetchone()[0]),
                "indexed_refs": int(c.execute("SELECT COUNT(*) FROM record_refs").fetchone()[0]),
            }
        finally:
            c.close()

    def investigate(self, query: str, limit: int = 300):
        timings = {}
        started = time.perf_counter()
        info = classify_ip_search(query)
        conn = get_db(self.db_file)
        try:
            t0 = time.perf_counter()
            if info["family"] in (4, 6):
                # Search PAN and AWS independently.  Do not let a large PAN network
                # result set consume the shared search limit and hide an EC2/ENI.
                pan_base = _base_search(conn, query, platform="panos", limit=limit)
                aws_base = _base_search(conn, query, platform="aws", limit=limit)

                # Always augment the network-index result with exact endpoint matches.
                # A /32 can legitimately hit a VPC/subnet network first; that must
                # never prevent us from also returning the EC2/ENI/RDS/Route53
                # record that actually owns or contains the IP.
                bounds = network_bounds(query)
                target_ip = str(bounds[1]) if bounds and bounds[0] in (4, 6) else query.split("/", 1)[0].strip()
                exact_ids: list[int] = []

                rows = conn.execute("""
                    SELECT DISTINCT rt.record_id
                    FROM record_terms rt JOIN records r ON r.id=rt.record_id
                    WHERE r.platform='aws' AND rt.term_lower=?
                    LIMIT ?
                """, (target_ip.lower(), limit)).fetchall()
                exact_ids.extend(int(x[0]) for x in rows)

                # Older databases may have the endpoint only in raw JSON. SQLite
                # JSON1 gives us an exact recursive scalar lookup regardless of
                # whether the collector stored EC2/ENI/RDS/R53 data as nested blobs.
                try:
                    rows = conn.execute("""
                        SELECT DISTINCT r.id
                        FROM records r, json_tree(r.data) jt
                        WHERE r.platform='aws'
                          AND jt.type IN ('text','integer','real')
                          AND lower(CAST(jt.value AS TEXT))=?
                        LIMIT ?
                    """, (target_ip.lower(), limit)).fetchall()
                    exact_ids.extend(int(x[0]) for x in rows)
                except sqlite3.OperationalError:
                    pass

                # Final compatibility fallback for databases without JSON1.
                if not exact_ids:
                    rows = conn.execute("""
                        SELECT r.id
                        FROM records r
                        WHERE r.platform='aws'
                          AND (r.category LIKE '%instance%' OR r.category LIKE '%network_interface%'
                               OR r.category LIKE '%eni%' OR r.category LIKE '%rds%'
                               OR r.category LIKE '%load_balancer%' OR r.category LIKE '%route53%'
                               OR r.category LIKE '%hosted%')
                          AND lower(r.data) LIKE ?
                        LIMIT ?
                    """, (f'%{target_ip.lower()}%', limit)).fetchall()
                    exact_ids.extend(int(x[0]) for x in rows)

                if exact_ids:
                    aws_base = _dedupe_rows(aws_base + fetch_records_by_ids(conn, exact_ids))
                base = _dedupe_rows(pan_base + aws_base)
            else:
                base = _base_search(conn, query, limit=limit)
            timings["indexed_search_ms"] = round((time.perf_counter() - t0) * 1000, 2)

            t0 = time.perf_counter()
            aws, sgs, ctx = _aws_expand(conn, query, base, limit)
            timings["aws_relationships_ms"] = round((time.perf_counter() - t0) * 1000, 2)

            # Only authoritative PAN objects/groups can contribute endpoint networks.
            pan_base = [r for r in base if r["platform"] == "panos" and not _is_raw(r)]
            seen = {x["value"].lower() for x in ctx}
            for r in pan_base:
                role = _pan_role(r["category"], _safe_json(r["data"]))
                if role not in {"object", "group"}:
                    continue
                for v in _network_values(conn, [r["id"]]):
                    _add_ctx(ctx, seen, v, "palo_object", r["name"] or "")

            # Reverse PAN -> AWS mapping uses only endpoint seeds, never a recursively
            # enlarged set of VPC/subnet networks.
            existing = {x["record_id"] for x in aws}
            for n in _pan_seed_networks(query, ctx):
                for rid in find_network_record_ids(conn, n, platform="aws", limit=limit * 2, include_noisy=False):
                    if rid in existing:
                        continue
                    rr = fetch_records_by_ids(conn, [rid])
                    if not rr:
                        continue
                    r = rr[0]
                    item = _safe_json(r["data"])
                    cat = _cat(r["category"])
                    if _is_sg(r["category"], item):
                        continue
                    if any(x in cat for x in ("instance","network_interface","eni","subnet","vpc","load_balancer","rds","db","route53","hosted")):
                        aws.append(_record(r, reason="reverse_network_relationship", matched_value=n))
                        existing.add(rid)

            t0 = time.perf_counter()
            objects, groups, rules, _ = _pan_inventory(conn, query, base, ctx, limit)
            timings["palo_relationships_ms"] = round((time.perf_counter() - t0) * 1000, 2)

            # Noisy aggregate JSON is queried separately and cannot affect any of the
            # authoritative result sections above.
            t0 = time.perf_counter()
            noisy_names = [x.get("name", "") for x in (objects + groups + rules)]
            noisy = _noisy_search(conn, query, noisy_names, limit=50)
            timings["noisy_exact_lookup_ms"] = round((time.perf_counter() - t0) * 1000, 2)

            aws = _expand_route53_matches(conn, aws, query)
            aws = _dedupe(aws)
            sgs = _dedupe(sgs)
            # A direct SG definition belongs in the SG section, not duplicated in AWS.
            sg_keys = {(x.get("device"), x.get("name")) for x in sgs}
            aws = [x for x in aws if not (_is_sg(x.get("category", ""), x.get("data", {})) and (x.get("device"), x.get("name")) in sg_keys)]

            timings["total_ms"] = round((time.perf_counter() - started) * 1000, 2)
            return {
                "query": query,
                "query_type": info["type"],
                "query_family": info["family"],
                "aws_matches": aws,
                "attached_security_groups": sgs,
                "matched_objects": objects,
                "matched_groups": groups,
                "matched_rules": rules,
                "all_entries_matches": noisy,
                "noisy_matches": noisy,
                "network_context": ctx,
                "rollup_seeds": _pan_seed_networks(query, ctx),
                "timing": timings,
                "summary": {
                    "aws_resources": len(aws),
                    "attached_sgs": len(sgs),
                    "palo_objects": len(objects),
                    "palo_groups": len(groups),
                    "palo_rules": len(rules),
                    "all_entries": len(noisy),
                },
            }
        finally:
            conn.close()

    def policy_lookup(self, source: str = "", destination: str = "", port: str = ""):
        source, destination, port = source.strip(), destination.strip(), port.strip()
        total = time.perf_counter()
        if not source and not destination:
            return {"query": {"source": source, "destination": destination, "port": port}, "source_context": None,
                    "destination_context": None, "matched_objects": [], "matched_groups": [], "matched_rules": [],
                    "rules": [], "all_entries_matches": [], "summary": {"objects": 0, "groups": 0, "rules": 0, "allow": 0, "deny": 0}}

        t = time.perf_counter()
        src = self.investigate(source, 250) if source else None
        dst = self.investigate(destination, 250) if destination else None
        timing = {"endpoint_resolution_ms": round((time.perf_counter() - t) * 1000, 2)}

        def endpoint(inv, q):
            if not inv:
                return None
            names = {q.lower()}
            for r in inv.get("matched_objects", []) + inv.get("matched_groups", []):
                if r.get("name"):
                    names.add(r["name"].lower())
            nets = list(inv.get("rollup_seeds", []))
            if network_bounds(q) and q not in nets:
                nets.insert(0, q)
            return {
                "query": q,
                "query_type": inv.get("query_type"),
                "names": sorted(names),
                "networks": nets,
                "aws_matches": inv.get("aws_matches", []),
                "attached_security_groups": inv.get("attached_security_groups", []),
                "objects": inv.get("matched_objects", []),
                "groups": inv.get("matched_groups", []),
            }

        srcctx, dstctx = endpoint(src, source), endpoint(dst, destination)
        conn = get_db(self.db_file)
        matched: list[dict[str, Any]] = []
        try:
            t = time.perf_counter()
            ids: set[int] = set()
            for ctx, field in ((srcctx, "source"), (dstctx, "destination")):
                if not ctx:
                    continue
                names = set(ctx["names"])
                if names:
                    ph = ','.join('?' * len(names))
                    ids.update(int(r[0]) for r in conn.execute(
                        f"SELECT DISTINCT rule_record_id FROM pan_rule_refs WHERE field=? AND ref_name_lower IN ({ph})",
                        [field, *names],
                    ))
                for n in ctx["networks"]:
                    b = network_bounds(n)
                    if b:
                        v, s, e = b
                        ids.update(int(r[0]) for r in conn.execute(
                            "SELECT DISTINCT rule_record_id FROM pan_rule_networks WHERE field=? AND version=? AND start_hex<=? AND end_hex>=?",
                            (field, v, f"{int(s):032x}", f"{int(e):032x}"),
                        ))

            # 'any' must be considered on the specified sides, but it does not by
            # itself make a rule a match; final side() evaluation still requires both.
            for field, ctx in (("source", srcctx), ("destination", dstctx)):
                if ctx:
                    ids.update(int(r[0]) for r in conn.execute(
                        "SELECT DISTINCT rule_record_id FROM pan_rule_refs WHERE field=? AND ref_name_lower='any'", (field,)
                    ))

            rows = fetch_records_by_ids(conn, list(ids)[:10000])
            timing["rule_candidate_sql_ms"] = round((time.perf_counter() - t) * 1000, 2)
            t = time.perf_counter()
            service_cache: dict[str, list[sqlite3.Row]] = {}

            def side(rec, field, ctx):
                if not ctx:
                    return True, ["not_specified"]
                refs = _rule_field(rec, field)
                reasons = []
                names = set(ctx["names"])
                nets = ctx["networks"]
                for x in refs:
                    xl = x.lower()
                    if xl == "any":
                        reasons.append("any")
                    elif xl in names:
                        reasons.append(f"entity:{x}")
                    elif network_bounds(x) and any(value_matches_network_or_range(x, n) for n in nets):
                        reasons.append(f"network:{x}")
                return bool(reasons), reasons

            for r in rows:
                if is_noisy_category(r["category"]) or _pan_role(r["category"], _safe_json(r["data"])) != "rule":
                    continue
                rec = _record(r)
                sh, sr = side(rec, "source", srcctx)
                dh, dr = side(rec, "destination", dstctx)
                if sh and dh and _service_hit(conn, _rule_field(rec, "service"), port, service_cache):
                    rec["action"] = _rule_action(rec)
                    rec["decision"] = _decision(rec["action"])
                    rec["match_details"] = {"source": sr, "destination": dr, "services": _rule_field(rec, "service"), "port_query": port}
                    matched.append(rec)
            timing["rule_evaluation_ms"] = round((time.perf_counter() - t) * 1000, 2)
        finally:
            conn.close()

        objs = _dedupe((src or {}).get("matched_objects", []) + (dst or {}).get("matched_objects", []))
        groups = _dedupe((src or {}).get("matched_groups", []) + (dst or {}).get("matched_groups", []))
        matched = _dedupe(matched)
        noisy = _dedupe((src or {}).get("all_entries_matches", []) + (dst or {}).get("all_entries_matches", []))[:50]
        allow = sum(1 for r in matched if r.get("decision") == "ALLOWED")
        deny = sum(1 for r in matched if r.get("decision") == "DENIED")
        timing["total_ms"] = round((time.perf_counter() - total) * 1000, 2)
        return {
            "query": {"source": source, "destination": destination, "port": port},
            "source_context": srcctx,
            "destination_context": dstctx,
            "matched_objects": objs,
            "matched_groups": groups,
            "matched_rules": matched,
            "rules": matched,  # UI/backward compatibility
            "all_entries_matches": noisy,
            "timing": timing,
            "summary": {"objects": len(objs), "groups": len(groups), "rules": len(matched), "allow": allow, "deny": deny},
        }

DATA=InfrastructureDataSource()

# ---------------------------------------------------------------------------
# Server-rendered UI helpers
#
# The application UI intentionally uses only Python/Flask + HTML/CSS.
# There is no browser-side JavaScript dependency.  The existing JSON API
# routes below are retained for compatibility/future integrations.
# ---------------------------------------------------------------------------

def _e(value: Any) -> str:
    return str(escape("" if value is None else value))


def _json_pre(value: Any) -> str:
    return _e(json.dumps(value, indent=2, sort_keys=False, default=str))


def _extract_values(obj: Any) -> list[str]:
    if obj is None:
        return []
    if isinstance(obj, (str, int, float, bool)):
        return [str(obj)]
    if isinstance(obj, list):
        out = []
        for item in obj:
            out.extend(_extract_values(item))
        return out
    if isinstance(obj, dict):
        out = []
        for key in ("member", "entry", "#text"):
            if key in obj:
                out.extend(_extract_values(obj[key]))
        if isinstance(obj.get("name"), str):
            out.append(obj["name"])
        if "@name" in obj:
            out.append(str(obj["@name"]))
        if out:
            return out
        for key, value in obj.items():
            if not str(key).startswith("@"):
                out.extend(_extract_values(value))
        return out
    return []


def _find_key_recursive(obj: Any, keys: Iterable[str]) -> Any:
    if not isinstance(obj, dict):
        if isinstance(obj, list):
            for item in obj:
                found = _find_key_recursive(item, keys)
                if found is not None:
                    return found
        return None
    for key in keys:
        if key in obj:
            return obj[key]
    for value in obj.values():
        if isinstance(value, (dict, list)):
            found = _find_key_recursive(value, keys)
            if found is not None:
                return found
    return None


def _pill_list(value: Any, default_label: str = "any") -> str:
    items = _extract_values(value)
    if not items:
        return f'<span class="rule-tag">{_e(default_label)}</span>'
    return " ".join(f'<span class="rule-tag highlight">{_e(x)}</span>' for x in items)


def _properties_table(obj: Any) -> str:
    if not isinstance(obj, dict):
        return ""
    rows = []
    for key, value in obj.items():
        if value not in (None, "") and not isinstance(value, (dict, list)):
            rows.append(f"<tr><th>{_e(key)}</th><td>{_e(value)}</td></tr>")
    return '<table class="prop-table">' + "".join(rows) + "</table>"


def _route53_details(data: Any, query: str = "") -> str:
    raw = data if isinstance(data, dict) else {}
    if isinstance(raw.get("ResourceRecordSets"), list):
        record_sets = raw["ResourceRecordSets"]
    elif any(k in raw for k in ("Name", "Type", "TTL")):
        record_sets = [raw]
    else:
        record_sets = raw.get("ResourceRecords", []) if isinstance(raw.get("ResourceRecords"), list) else []

    q = (query or "").lower()
    matched = []
    for rec in record_sets:
        if isinstance(rec, dict) and (not q or q in json.dumps(rec, default=str).lower()):
            matched.append(rec)
    if not matched:
        matched = record_sets[:10]

    rows = []
    for rec in matched:
        if not isinstance(rec, dict):
            continue
        name = rec.get("Name", rec.get("name", "-"))
        typ = rec.get("Type", rec.get("type", "-"))
        ttl = rec.get("TTL", rec.get("ttl", "-"))
        values = []
        if isinstance(rec.get("ResourceRecords"), list):
            for v in rec["ResourceRecords"]:
                values.append(v.get("Value", json.dumps(v, default=str)) if isinstance(v, dict) else str(v))
        elif isinstance(rec.get("AliasTarget"), dict):
            values.append("Alias: " + str(rec["AliasTarget"].get("DNSName", json.dumps(rec["AliasTarget"], default=str))))
        elif rec.get("Value") is not None:
            values.append(str(rec["Value"]))
        vals = " ".join(f'<span class="rule-tag highlight">{_e(v)}</span>' for v in values) or '<i style="color:var(--text-secondary)">None</i>'
        rows.append(f"<tr><td><b>{_e(name)}</b></td><td><span class=\"badge blue\">{_e(typ)}</span></td><td>{_e(ttl)}</td><td>{vals}</td></tr>")
    return ('<div style="margin-top:10px;"><b style="font-size:13px;color:var(--accent);">Matched Route53 Resource Record(s):</b>'
            '<table class="prop-table" style="margin-top:6px;"><tr><th>Record Name / FQDN</th><th>Type</th><th>TTL</th><th>Values / Targets</th></tr>'
            + "".join(rows) + "</table></div>")


def _security_group_details(data: Any) -> str:
    raw = data if isinstance(data, dict) else {}
    desc = raw.get("Description", "No description provided.")
    def rules_table(title, rules):
        rows = []
        for rule in rules or []:
            if not isinstance(rule, dict):
                continue
            proto_raw = rule.get("IpProtocol")
            proto = "All Protocols" if proto_raw == "-1" else (str(proto_raw).upper() if proto_raw else "Any")
            fp, tp = rule.get("FromPort"), rule.get("ToPort")
            port_display = proto
            if proto_raw != "-1" and fp is not None and tp is not None:
                port_display += f" : {fp}" if fp == tp else f" : {fp} - {tp}"
            targets = []
            for key, valkey in (("IpRanges","CidrIp"),("Ipv6Ranges","CidrIpv6"),("UserIdGroupPairs","GroupId"),("PrefixListIds","PrefixListId")):
                for item in rule.get(key, []) or []:
                    if not isinstance(item, dict):
                        continue
                    value = item.get(valkey) or item.get("GroupName")
                    if value:
                        if item.get("Description"):
                            value += f" ({item['Description']})"
                        targets.append(str(value))
            if not targets and proto_raw == "-1":
                targets.append("0.0.0.0/0 (Any)")
            target_html = " ".join(f'<span class="rule-tag highlight">{_e(v)}</span>' for v in targets) or '<i style="color:var(--text-secondary)">None</i>'
            rows.append(f'<tr><td><span class="badge blue">{_e(port_display)}</span></td><td>{target_html}</td></tr>')
        if not rows:
            rows.append('<tr><td colspan="2"><i style="color:var(--text-secondary)">No rules defined</i></td></tr>')
        return f'<div style="margin-top:8px;font-weight:bold;font-size:12px;color:var(--text-primary);">{title}</div><table class="prop-table" style="margin-top:4px;"><tr><th>Protocol / Ports</th><th>Source / Destination Targets</th></tr>{"".join(rows)}</table>'
    return (f'<div style="margin-top:10px;"><b style="font-size:13px;color:var(--accent);">Security Group Details:</b>'
            f'<div class="meta" style="margin-bottom:8px;"><b>Description:</b> {_e(desc)}</div>'
            + rules_table("📥 Inbound Rules (IpPermissions)", raw.get("IpPermissions", []))
            + rules_table("📤 Outbound Rules (IpPermissionsEgress)", raw.get("IpPermissionsEgress", [])) + "</div>")


def _palo_details(x: dict[str, Any]) -> str:
    raw = x.get("data") if isinstance(x.get("data"), dict) else {}
    d = raw.get("entry") if isinstance(raw.get("entry"), dict) else raw
    cat = str(x.get("type") or "").lower()
    if ("rule" in cat or "policy" in cat or "nat" in cat or
            _find_key_recursive(d, ["action", "from", "to"]) is not None):
        action = _find_key_recursive(d, ["action"]) or "allow"
        action_html = '<span class="rule-tag allow">ALLOW</span>' if str(action).lower() == "allow" else f'<span class="rule-tag deny">{_e(str(action).upper())}</span>'
        rows = [
            ("Rule Action", action_html),
            ("From Zone(s)", _pill_list(_find_key_recursive(d, ["from", "from-zone"]))),
            ("To Zone(s)", _pill_list(_find_key_recursive(d, ["to", "to-zone"]))),
            ("Source Address", _pill_list(_find_key_recursive(d, ["source"]))),
            ("Destination Address", _pill_list(_find_key_recursive(d, ["destination", "dest"]))),
            ("Application", _pill_list(_find_key_recursive(d, ["application", "app"]))),
            ("Service / Port", _pill_list(_find_key_recursive(d, ["service", "port"]))),
        ]
        for label, keys in (("URL Category", ["url-category", "category"]), ("Description", ["description"])):
            val = _find_key_recursive(d, keys)
            if val is not None:
                rows.append((label, _pill_list(val) if label == "URL Category" else _e(" ".join(_extract_values(val)))))
        return '<table class="prop-table">' + "".join(f"<tr><th>{a}</th><td>{b}</td></tr>" for a,b in rows) + "</table>"
    name = x.get("name") or _find_key_recursive(d, ["name", "@name"]) or "Unnamed Object"
    desc = _find_key_recursive(d, ["description"])
    vals = [
        ("Object Name", f"<b>{_e(name)}</b>"),
        ("Description", _e(" ".join(_extract_values(desc))) if desc is not None else '<i style="color:var(--text-secondary)">None</i>'),
    ]
    for label, keys in (("Group Members", ["static","members","member","group"]),("IP / Subnet",["ip-netmask","ip_netmask"]),("IP Range",["ip-range","ip_range"]),("FQDN",["fqdn"])):
        val = _find_key_recursive(d, keys)
        if val is not None:
            vals.append((label, _pill_list(val, "None")))
    if len(vals) == 2:
        generic = [v for v in _extract_values(d) if v != name]
        if generic:
            vals.append(("Value(s)", " ".join(f'<span class="rule-tag highlight">{_e(v)}</span>' for v in generic)))
    return '<table class="prop-table">' + "".join(f"<tr><th>{a}</th><td>{b}</td></tr>" for a,b in vals) + "</table>"


def _item_html(x: dict[str, Any], badge_class: str, query: str = "") -> str:
    raw = x.get("data") if isinstance(x.get("data"), dict) else {}
    eval_data = raw.get("entry") if isinstance(raw.get("entry"), dict) else raw
    category = str(x.get("type") or "").lower()
    is_sg = "security_group" in category or "security-group" in category or "IpPermissions" in raw
    name = x.get("name") or (eval_data.get("name") if isinstance(eval_data, dict) else None) or (eval_data.get("@name") if isinstance(eval_data, dict) else None) or "Unnamed Record"
    if is_sg:
        group_name = raw.get("GroupName") or (eval_data.get("GroupName") if isinstance(eval_data, dict) else None) or x.get("group_name") or "Unnamed Security Group"
        group_id = raw.get("GroupId") or (eval_data.get("GroupId") if isinstance(eval_data, dict) else None) or x.get("name") or ""
        display = f'<div><b>{_e(group_name)}</b></div>' + (f'<div class="meta" style="margin-top:2px;">Group ID: <b>{_e(group_id)}</b></div>' if group_id else "")
    else:
        display = _e(name)
    if badge_class == "palo":
        details = _palo_details(x)
    elif is_sg:
        details = _security_group_details(raw)
    elif "route53" in category or "r53" in category or "hostedzone" in category or "ResourceRecordSets" in raw:
        details = _route53_details(raw, query)
    else:
        details = _properties_table(x.get("data"))
    return (f'<div class="item"><div class="item-head"><div class="item-name">{display}</div><div>'
            f'<span class="badge blue">{_e(x.get("device",""))}</span> <span class="badge {badge_class}">{_e(x.get("type",""))}</span></div></div>'
            f'<div class="meta">Source File: {_e(x.get("file",""))}</div>{details}'
            f'<details style="margin-top:12px;"><summary>View Full Raw JSON Payload</summary><pre>{_json_pre(x.get("data",{}))}</pre></details></div>')


def _palo_rule_bucket(x):
    c = str(x.get("type") or x.get("category") or "").lower().replace("-", " ").replace("_", " ")
    if "nat" in c: return "NAT Rules"
    if "pbf" in c or "policy based forwarding" in c: return "PBF Rules"
    if "security" in c or "policy" in c: return "Security Rules"
    if "qos" in c: return "QoS Rules"
    if "decryption" in c: return "Decryption Rules"
    if "authentication" in c: return "Authentication Rules"
    if "application override" in c or "override" in c: return "Application Override Rules"
    return "Other Rules"


def _aws_bucket(x):
    c = str(x.get("type") or x.get("category") or "").lower().replace("-", " ").replace("_", " ")
    if "security group" in c or c == "sg" or x.get("attachment_scope") == "direct": return "Security Groups"
    if "route53" in c or "hostedzone" in c or "route 53" in c or "route53 record" in c: return "Route53 Records"
    if "network interface" in c or " eni" in c: return "Network Interfaces"
    if "instance" in c or "ec2" in c: return "EC2 Instances"
    if "rds" in c or "db instance" in c: return "RDS Databases"
    if "load balancer" in c or "elb" in c: return "Load Balancers"
    if "subnet" in c: return "Subnets"
    if "vpc" in c: return "VPCs"
    if "lambda" in c: return "Lambda"
    if "nat" in c: return "NAT Gateways"
    if "elastic ip" in c or "eip" in c: return "Elastic IPs"
    return str(x.get("type") or x.get("category") or "AWS Resources")


def _expandable(title, items, badge="palo", open_=False, query=""):
    if not items:
        return ""
    content = "".join(_item_html(x, badge, query) for x in items)
    return f'<details class="palo-type-block" {"open" if open_ else ""}><summary>{_e(title)} <span class="count" style="float:right;">{len(items)}</span></summary><div class="palo-type-body">{content}</div></details>'


def _aws_buckets(items, query=""):
    buckets = {}
    for x in items:
        buckets.setdefault(_aws_bucket(x), []).append(x)
    preferred = ["EC2 Instances","Network Interfaces","Security Groups","RDS Databases","Load Balancers","Route53 Records","Subnets","VPCs","Lambda","NAT Gateways","Elastic IPs"]
    parts = ['<div class="palo-type-grid">']
    for key in preferred:
        if key in buckets:
            parts.append(_expandable(key, buckets[key], "aws", False, query))
    for key in sorted(k for k in buckets if k not in preferred):
        parts.append(_expandable(key, buckets[key], "aws", False, query))
    return "".join(parts) + "</div>"


def _palo_buckets(objects, groups, rules, query=""):
    parts = ['<div class="palo-type-grid">', _expandable("Address Objects / CIDR Roll-up", objects, "palo", True, query),
             _expandable("Address Groups", groups, "palo", False, query)]
    buckets = {}
    for r in rules:
        buckets.setdefault(_palo_rule_bucket(r), []).append(r)
    order = ["Security Rules","NAT Rules","PBF Rules","QoS Rules","Decryption Rules","Authentication Rules","Application Override Rules","Other Rules"]
    for key in order:
        if key in buckets:
            parts.append(_expandable(key, buckets[key], "palo", False, query))
    for key in sorted(k for k in buckets if k not in order):
        parts.append(_expandable(key, buckets[key], "palo", False, query))
    return "".join(parts) + "</div>"


def _investigation_html(data, query):
    if data.get("error"):
        return f'<div class="empty" style="color:#f87171;">{_e(data["error"])}</div>'
    summary = data.get("summary") or {}
    aws = list(data.get("aws_matches") or []) + list(data.get("attached_security_groups") or [])
    objects, groups, rules = data.get("matched_objects") or [], data.get("matched_groups") or [], data.get("matched_rules") or []
    noisy = data.get("noisy_matches") or data.get("all_entries_matches") or []
    parts = [f'<div class="summary"><div class="card"><b>{summary.get("aws_resources",len(data.get("aws_matches") or []))}</b><span>AWS Resources</span></div>'
             f'<div class="card"><b>{summary.get("attached_sgs",len(data.get("attached_security_groups") or []))}</b><span>Attached Security Groups</span></div>'
             f'<div class="card palo-card"><b>{summary.get("palo_objects",len(objects))}</b><span>Palo Address Objects</span></div>'
             f'<div class="card palo-card"><b>{summary.get("palo_groups",len(groups))}</b><span>Palo Address Groups</span></div>'
             f'<div class="card palo-card"><b>{summary.get("palo_rules",len(rules))}</b><span>Palo Security / NAT Rules</span></div></div>']
    if aws:
        parts.append(f'<div class="section"><div class="section-title"><h2>Matching AWS Resources</h2><span class="count">{len(aws)}</span></div>{_aws_buckets(aws,query)}</div>')
    if objects or groups or rules:
        parts.append(f'<div class="section"><div class="section-title"><h2>Palo Alto Results</h2><span class="count">{len(objects)+len(groups)+len(rules)}</span></div>{_palo_buckets(objects,groups,rules,query)}</div>')
    if noisy:
        body = "".join(_item_html(x,"palo",query) for x in noisy)
        parts.append(f'<div class="section" style="border-style:dashed;opacity:.92;"><details><summary style="padding:16px;font-size:14px;background:#2f3036;cursor:pointer;">🗃️ Noisy / Aggregate JSON — <b>{len(noisy)} exact matches hidden</b></summary><div style="padding-top:8px;">{body}</div></details></div>')
    if not aws and not objects and not groups and not rules and not noisy:
        parts.append('<div class="empty">No matching records found.</div>')
    return "".join(parts)


def _policy_html(data, source, destination, port):
    if data.get("error"):
        return f'<div class="empty" style="color:#f87171;">{_e(data["error"])}</div>'
    rules = data.get("matched_rules") or data.get("rules") or []
    src = data.get("source_context") or {}
    dst = data.get("destination_context") or {}
    noisy = data.get("all_entries_matches") or []
    scope = data.get("search_scope")
    scope_text = {
        "source_only": f"Source-only lookup{f' on {_e(port)}' if port else ''} — destination is unrestricted",
        "destination_only": f"Destination-only lookup{f' on {_e(port)}' if port else ''} — source is unrestricted",
    }.get(scope, f"Source + destination lookup{f' on {_e(port)}' if port else ''}")
    parts = [f'<div class="hint" style="margin-bottom:14px;"><b>Lookup scope:</b> {scope_text}</div>']
    def endpoint(title, query, ctx, unrestricted):
        objects = ctx.get("objects") or []
        groups = ctx.get("groups") or []
        body = f'<div class="section-title"><h2>{_e(title)}</h2><span class="count">{len(objects)+len(groups)}</span></div>'
        body += f'<div class="meta" style="margin-bottom:10px;"><b>{"Query" if query else "Scope"}:</b> {_e(query) if query else _e(unrestricted)}</div>'
        if objects: body += _expandable("Address Objects",objects,"palo",True,query)
        if groups: body += _expandable("Address Groups",groups,"palo",False,query)
        if not objects and not groups and query: body += '<div class="empty">No Palo address objects or groups resolved.</div>'
        return f'<div class="section policy-endpoint">{body}</div>'
    parts.append(f'<div class="policy-endpoint-grid">{endpoint("SOURCE Objects & Groups",source,src,"Any source")}{endpoint("DESTINATION Objects & Groups",destination,dst,"Any destination")}</div>')
    if rules:
        parts.append(f'<div class="section"><div class="section-title"><h2>Matching Firewall Rules</h2><span class="count">{len(rules)}</span></div>{_palo_buckets([],[],rules,"")}</div>')
    if noisy:
        body="".join(_item_html(x,"palo","") for x in noisy)
        parts.append(f'<div class="section" style="border-style:dashed;opacity:.92;"><details><summary style="padding:16px;background:#2f3036;cursor:pointer;">🗃️ Noisy / Aggregate JSON — <b>{len(noisy)} exact matches hidden</b></summary><div>{body}</div></details></div>')
    return "".join(parts) if rules or src or dst or noisy else '<div class="empty">No firewall rules found matching the given criteria.</div>'


def _org_tree(node, role_name=""):
    if not isinstance(node, dict):
        return ""
    name = node.get("Name") or node.get("Id") or node.get("name") or "Unit"
    accounts = node.get("Accounts") or node.get("AccountList") or []
    children = node.get("OUs") or node.get("Children") or node.get("SubOUs") or []
    parts=[f'<div class="tree-node"><span class="tree-folder">📁 {_e(name)}</span>']
    if accounts:
        leaves=[]
        for acc in accounts:
            if not isinstance(acc,dict): continue
            acc_name=acc.get("Name") or acc.get("Id") or "Account"
            acc_id=acc.get("Id") or acc.get("AccountId") or ""
            tags=acc.get("Tags") or acc.get("tags") or {}
            primary=acc.get("PrimaryOwner") or acc.get("primaryOwner") or tags.get("PrimaryOwner") or tags.get("primaryOwner") or tags.get("Primary Owner") or ""
            secondary=acc.get("SecondaryOwner") or acc.get("secondaryOwner") or tags.get("SecondaryOwner") or tags.get("secondaryOwner") or tags.get("Secondary Owner") or ""
            if role_name and acc_id:
                href=f"https://signin.aws.amazon.com/switchrole?account={quote(str(acc_id))}&roleName={quote(str(role_name))}"
                label=f'<a class="switch-link" href="{href}" target="_blank" rel="noopener">📄 {_e(acc_name)} <span style="color:var(--text-secondary);">({_e(acc_id)})</span> 🔗 Switch Role</a>'
            else:
                label=f'📄 <b>{_e(acc_name)}</b> <span style="color:var(--text-secondary);">({_e(acc_id)})</span>'
            owner=f'<div style="margin-top:7px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;"><span class="owner-chip"><b>Primary Owner</b> {_e(primary or "—")}</span><span class="owner-chip secondary"><b>Secondary Owner</b> {_e(secondary or "—")}</span></div>'
            if isinstance(tags,dict) and tags:
                tag_html=" ".join(f'<span class="rule-tag highlight"><b>{_e(k)}:</b> {_e(v)}</span>' for k,v in tags.items())
                tags_block=f'<details style="margin-top:7px;"><summary>View {len(tags)} Account Tag{"s" if len(tags)!=1 else ""}</summary><div style="margin-top:7px;display:flex;gap:6px;flex-wrap:wrap;">{tag_html}</div></details>'
            else:
                tags_block='<div class="meta" style="margin-top:6px;">No account tags returned.</div>'
            leaves.append(f'<div class="tree-leaf">{label}{owner}{tags_block}</div>')
        parts.append('<div style="margin-left:20px;">'+"".join(leaves)+"</div>")
    if children:
        parts.append('<div style="margin-left:10px;">'+"".join(_org_tree(c,role_name) for c in children)+"</div>")
    return "".join(parts)+"</div>"


def _automation_results():
    results=[]
    root=AUTOMATION_RESULTS_ROOT
    if not root.exists(): return results
    for path in sorted(root.glob("*.json"), key=lambda x:x.name.lower()):
        try:
            payload=json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload,dict): continue
            def get_key(name,default=""):
                if name in payload: return payload.get(name,default)
                wanted=name.lower()
                for k,v in payload.items():
                    if str(k).lower()==wanted: return v
                return default
            reserved={"name","status","lastrun"}
            results.append({"file":path.name,"name":get_key("Name",path.stem),"status":get_key("Status","Unknown"),
                            "lastrun":get_key("Lastrun",""),"extra":{str(k):v for k,v in payload.items() if str(k).lower() not in reserved}})
        except Exception as exc:
            results.append({"file":path.name,"name":path.stem,"status":"ERROR","lastrun":"","extra":{"Error":str(exc)}})
    return results


def _load_json_file(path: Path):
    if not path.exists():
        return None, f"{path.name} not found."
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except Exception as exc:
        return None, str(exc)


@app.context_processor
def ui_context():
    try:
        files_count = DATA.files_count()
        devices_count = DATA.devices_count()
    except Exception:
        files_count = devices_count = 0
    return {"db_files": files_count, "db_devices": devices_count}


@app.route("/")
def index():
    q=request.args.get("q","").strip()
    data=None
    error=None
    if q:
        try: data=DATA.investigate(q)
        except Exception as exc: app.logger.exception("Investigation failed"); error=str(exc)
    return render_template("search.html", active_page="search", query=q, result_html=Markup(_investigation_html(data,q)) if data else None, error=error)


@app.route("/search")
def search_page():
    return index()


@app.route("/policy-lookup")
def policy_lookup_page():
    source=request.args.get("src","").strip()
    destination=request.args.get("dst","").strip()
    port=request.args.get("port","").strip()
    data=None
    error=None
    if source or destination:
        try: data=DATA.policy_lookup(source,destination,port)
        except Exception as exc: app.logger.exception("Policy lookup failed"); error=str(exc)
    return render_template("firewall_policy_lookup.html", active_page="policy", source=source, destination=destination, port=port,
                           result_html=Markup(_policy_html(data,source,destination,port)) if data else None, error=error)


@app.route("/aws-org")
def aws_org_page():
    data, error=_load_json_file(ORG_FILE_PATH)
    role=request.args.get("role","").strip()
    tree=""
    if data is not None:
        root_nodes=data.get("Hierarchy",data) if isinstance(data,dict) else data
        if isinstance(root_nodes,list):
            tree="".join(_org_tree(x,role) for x in root_nodes)
        else:
            tree=_org_tree(root_nodes,role)
    return render_template("aws_org_topology.html",active_page="org",org_tree=Markup(tree),org_error=error,role=role,
                           org_meta="Loaded" if data is not None else "Unavailable")


@app.route("/wiz-policy-check")
def wiz_policy_check_page():
    return render_template("wiz_policy_check.html",active_page="wiz")


@app.route("/automation")
def automation_page():
    results=_automation_results()
    return render_template("automation_results.html",active_page="automation",automation_results=results)


@app.route("/information")
def information_page():
    return render_template("information_links.html",active_page="info")


@app.route("/about")
def about_page():
    return render_template("about.html",active_page="about")



# ---------------------------------------------------------------------------
# Palo Alto Object Search
# ---------------------------------------------------------------------------

_PAN_OBJECT_KINDS = {
    "addresses": ("address", "address_group"),
    "services": ("service", "service_group"),
    "applications": ("application",),
    "custom_urls": ("custom_url", "customurl", "url_category", "custom_url_category"),
}


def _pan_kind_matches(category: str, kind: str) -> bool:
    c = _cat(category)
    needles = _PAN_OBJECT_KINDS.get(kind, ())
    if kind == "addresses":
        return "address" in c and "rule" not in c
    if kind == "services":
        return ("service" in c) and not any(x in c for x in ("rule", "service_profile"))
    if kind == "applications":
        return "application" in c and "rule" not in c
    if kind == "custom_urls":
        return any(x in c for x in needles) and "rule" not in c
    return False


def _scalar_items(value: Any, key_path: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for k, v in value.items():
            path = f"{key_path}.{k}" if key_path else str(k)
            yield from _scalar_items(v, path)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _scalar_items(v, f"{key_path}[{i}]")
    elif value is not None:
        yield key_path, str(value)


def _looks_like_partial_ipv4(q: str) -> bool:
    return bool(re.fullmatch(r"(?:\d{1,3}\.){0,3}\d{0,3}", q.strip())) if q.strip() else False


def _address_value_match(conn: sqlite3.Connection, record_id: int, query: str) -> bool:
    q = query.strip().lower()
    if not q:
        return False
    # The network index contains the authoritative IP/CIDR values extracted from
    # PAN objects. Prefix matching is intentional here: typing 10.5.2 should find
    # 10.5.2.x as well as values beginning with that prefix.
    rows = conn.execute(
        "SELECT value FROM record_networks WHERE record_id=?",
        (record_id,),
    ).fetchall()
    if _looks_like_partial_ipv4(q):
        return any(str(r[0]).lower().startswith(q) for r in rows)
    return any(q in str(r[0]).lower() for r in rows)


def _port_match(data: Any, query: str) -> bool:
    q = query.strip()
    if not re.fullmatch(r"\d+", q):
        return False
    wanted = int(q)
    for path, value in _scalar_items(data):
        key = path.lower()
        if "port" not in key:
            continue
        # Handle PAN forms such as 80, 443, 8000, 8000-8010, and comma/space lists.
        for token in re.findall(r"\d+(?:\s*-\s*\d+)?", value):
            if "-" in token:
                a, b = [int(x.strip()) for x in token.split("-", 1)]
                if a <= wanted <= b:
                    return True
            elif int(token) == wanted:
                return True
    return False


def _fqdn_match(data: Any, query: str) -> bool:
    q = query.strip().lower()
    if not q:
        return False
    for path, value in _scalar_items(data):
        key = path.lower()
        if any(x in key for x in ("fqdn", "domain", "url", "host")):
            if q in value.lower():
                return True
    return False


def _pan_object_search(kind: str, query: str, limit: int = 500) -> dict[str, Any]:
    kind = kind if kind in _PAN_OBJECT_KINDS else "addresses"
    q = query.strip().lower()
    if not q:
        return {"kind": kind, "query": query, "results": [], "searched": False}

    conn = get_db(DATA.db_file)
    try:
        # Name searches are handled directly by SQLite so a common search such as
        # "prod" does not require loading the entire PAN dataset into Python.
        category_like = {
            "addresses": "%address%",
            "services": "%service%",
            "applications": "%application%",
            "custom_urls": "%custom%url%",
        }[kind]
        rows = conn.execute(
            """SELECT r.id, d.name AS device, r.platform, r.category, r.filename,
                      r.name, r.data
               FROM records r JOIN devices d ON d.id=r.device_id
               WHERE r.platform='panos'
                 AND r.name IS NOT NULL AND r.name <> ''
                 AND lower(replace(r.category,'-','_')) LIKE ?
                 AND lower(r.name) LIKE ?
                 AND NOT (lower(replace(r.category,'-','_')) LIKE '%all_entries%'
                          OR lower(replace(r.category,'-','_')) LIKE '%all_objects%'
                          OR lower(replace(r.category,'-','_')) LIKE '%all_object_entries%'
                          OR lower(replace(r.category,'-','_')) IN ('metadata','summary'))
               ORDER BY lower(r.name), lower(d.name)
               LIMIT ?""",
            (category_like, f"%{q}%", limit),
        ).fetchall()

        # Value searches are only needed when the query was not already a name hit.
        # Candidate rows are limited to the requested object family before JSON is
        # inspected, keeping the operation bounded even with a large database.
        if len(rows) < limit:
            candidate_rows = conn.execute(
                """SELECT r.id, d.name AS device, r.platform, r.category, r.filename,
                          r.name, r.data
                   FROM records r JOIN devices d ON d.id=r.device_id
                   WHERE r.platform='panos' AND r.name IS NOT NULL AND r.name <> ''
                     AND lower(replace(r.category,'-','_')) LIKE ?
                     AND NOT (lower(replace(r.category,'-','_')) LIKE '%all_entries%'
                              OR lower(replace(r.category,'-','_')) LIKE '%all_objects%'
                              OR lower(replace(r.category,'-','_')) LIKE '%all_object_entries%'
                              OR lower(replace(r.category,'-','_')) IN ('metadata','summary'))
                   ORDER BY lower(r.name), lower(d.name)""",
                (category_like,),
            ).fetchall()
        else:
            candidate_rows = rows

        existing = {int(r["id"]) for r in rows}
        matched_rows = list(rows)
        matched_names: set[str] = {str(r["name"]).lower() for r in rows if r["name"]}

        # Address IP/CIDR matching uses the indexed network table. A partial IPv4
        # prefix intentionally uses textual prefix matching; a complete IP/CIDR
        # uses containment semantics so 10.5.2.25 finds an object containing it.
        if kind == "addresses":
            if network_bounds(query):
                b = network_bounds(query)
                ver, start_ip, end_ip = b
                net_rows = conn.execute(
                    """SELECT DISTINCT r.id, d.name AS device, r.platform, r.category,
                                      r.filename, r.name, r.data
                       FROM record_networks rn
                       JOIN records r ON r.id=rn.record_id
                       JOIN devices d ON d.id=r.device_id
                       WHERE r.platform='panos' AND rn.version=?
                         AND rn.start_hex<=? AND rn.end_hex>=?
                         AND lower(replace(r.category,'-','_')) LIKE '%address%'
                         AND lower(replace(r.category,'-','_')) NOT LIKE '%rule%'
                         AND NOT (lower(replace(r.category,'-','_')) LIKE '%all_entries%'
                                  OR lower(replace(r.category,'-','_')) LIKE '%all_objects%'
                                  OR lower(replace(r.category,'-','_')) LIKE '%all_object_entries%')
                       LIMIT ?""",
                    (ver, f"{int(start_ip):032x}", f"{int(end_ip):032x}", limit),
                ).fetchall()
            elif _looks_like_partial_ipv4(query):
                net_rows = conn.execute(
                    """SELECT DISTINCT r.id, d.name AS device, r.platform, r.category,
                                      r.filename, r.name, r.data
                       FROM record_networks rn
                       JOIN records r ON r.id=rn.record_id
                       JOIN devices d ON d.id=r.device_id
                       WHERE r.platform='panos'
                         AND lower(rn.value) LIKE ?
                         AND lower(replace(r.category,'-','_')) LIKE '%address%'
                         AND lower(replace(r.category,'-','_')) NOT LIKE '%rule%'
                       LIMIT ?""",
                    (f"{q}%", limit),
                ).fetchall()
            else:
                net_rows = []
            for r in net_rows:
                if int(r["id"]) not in existing:
                    matched_rows.append(r); existing.add(int(r["id"]))

        # Port/FQDN value searches inspect only the relevant PAN object family.
        if kind in ("services", "applications") and re.fullmatch(r"\d+", query.strip()):
            for r in candidate_rows:
                if int(r["id"]) in existing:
                    continue
                if _port_match(_safe_json(r["data"]), query):
                    matched_rows.append(r); existing.add(int(r["id"]))
                    if len(matched_rows) >= limit: break
        elif kind == "custom_urls":
            for r in candidate_rows:
                if int(r["id"]) in existing:
                    continue
                if _fqdn_match(_safe_json(r["data"]), query):
                    matched_rows.append(r); existing.add(int(r["id"]))
                    if len(matched_rows) >= limit: break

        # A value match on a member object should also expose containing groups.
        # This is especially useful for "10.5.2", port 443, or an FQDN where the
        # object is nested inside one or more Panorama groups.
        member_names = {str(r["name"]).lower() for r in matched_rows if r["name"]}
        if member_names and kind in ("addresses", "services") and len(matched_rows) < limit:
            _, group_rows = _expand_groups_sql(conn, member_names, limit=max(limit * 2, 500))
            for r in group_rows:
                c = _cat(r["category"])
                if not _pan_kind_matches(c, kind):
                    continue
                if int(r["id"]) in existing:
                    continue
                matched_rows.append(r); existing.add(int(r["id"]))
                if len(matched_rows) >= limit: break

        out = []
        for r in matched_rows[:limit]:
            data = _safe_json(r["data"])
            name = str(r["name"] or "")
            if q in name.lower():
                match_type = "Name"
            elif kind == "addresses":
                match_type = "IP/CIDR"
            elif kind in ("services", "applications") and re.fullmatch(r"\d+", query.strip()):
                match_type = "Port"
            elif kind == "custom_urls":
                match_type = "FQDN"
            else:
                match_type = "Value"

            networks = []
            if kind == "addresses":
                networks = [str(x[0]) for x in conn.execute(
                    "SELECT DISTINCT value FROM record_networks WHERE record_id=? ORDER BY value",
                    (int(r["id"]),),
                ).fetchall()]

            out.append({
                "record_id": int(r["id"]),
                "device": r["device"] or "",
                "category": r["category"] or "",
                "filename": r["filename"] or "",
                "name": name,
                "match_type": match_type,
                "networks": networks,
                "data": data,
            })

        return {"kind": kind, "query": query, "results": out, "searched": True}
    finally:
        conn.close()


def _pan_object_search_html(data: dict[str, Any]) -> str:
    kind = data.get("kind", "addresses")
    labels = {
        "addresses": "Addresses / Address Groups",
        "services": "Services / Service Groups",
        "applications": "Applications",
        "custom_urls": "Custom URLs",
    }
    results = data.get("results", [])
    parts = [f'<div class="object-search-summary"><b>{len(results)}</b> matching {escape(labels.get(kind, kind))}</div>']
    if not results:
        parts.append('<div class="empty">No matching Palo Alto objects found.</div>')
        return "".join(parts)

    for x in results:
        raw = json.dumps(x.get("data", {}), indent=2, ensure_ascii=False, sort_keys=True)
        parts.append('<div class="object-result">')
        parts.append('<div class="object-result-head">')
        parts.append(f'<div><span class="item-name">{escape(x["name"])}</span> '
                     f'<span class="badge palo">{escape(x["category"])}</span> '
                     f'<span class="badge">{escape(x["match_type"])}</span></div>')
        parts.append(f'<div class="meta">Device: <b>{escape(x["device"])}</b></div>')
        parts.append('</div>')
        if x.get("networks"):
            parts.append('<div class="object-values"><b>Networks:</b> ' +
                         " ".join(f'<span class="rule-tag highlight">{escape(v)}</span>' for v in x["networks"]) + '</div>')
        parts.append('<details><summary>View full object JSON</summary>')
        parts.append(f'<pre>{escape(raw)}</pre></details>')
        parts.append('</div>')
    return "".join(parts)


@app.route("/palo-object-search")
def palo_object_search_page():
    kind = request.args.get("kind", "addresses").strip().lower()
    if kind not in _PAN_OBJECT_KINDS:
        kind = "addresses"
    query = request.args.get("q", "").strip()
    data = _pan_object_search(kind, query) if query else {"kind": kind, "query": "", "results": [], "searched": False}
    return render_template(
        "palo_object_search.html",
        active_page="palo_objects",
        kind=kind,
        query=query,
        result_html=Markup(_pan_object_search_html(data)) if data.get("searched") else None,
    )


@app.route("/api/info")
def api_info():return jsonify({"files":DATA.files_count(),"devices":DATA.devices_count()})
@app.route("/api/stats")
def api_stats():return jsonify(DATA.get_stats())
@app.route("/api/automation/status")
def api_status():return jsonify({"aws_org_mtime":get_file_modified_time(ORG_FILE_PATH),"aws_data_mtime":get_latest_dir_mtime(AWS_DATA_ROOT),"pan_org_mtime":get_file_modified_time(PAN_TOPOLOGY_PATH),"pan_data_mtime":get_latest_dir_mtime(FW_DATA_ROOT)})
@app.route("/api/automation/results")
def api_automation_results():
    results = []
    root = AUTOMATION_RESULTS_ROOT
    if not root.exists():
        return jsonify({"results": [], "directory": str(root), "exists": False})
    for path in sorted(root.glob("*.json"), key=lambda x: x.name.lower()):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                continue
            def get_key(name, default=""):
                if name in payload: return payload.get(name, default)
                wanted = name.lower()
                for k, v in payload.items():
                    if str(k).lower() == wanted: return v
                return default
            reserved = {"name", "status", "lastrun"}
            extras = {str(k): v for k, v in payload.items() if str(k).lower() not in reserved}
            results.append({
                "file": path.name,
                "name": get_key("Name", path.stem),
                "status": get_key("Status", "Unknown"),
                "lastrun": get_key("Lastrun", ""),
                "extra": extras,
            })
        except Exception as exc:
            results.append({"file": path.name, "name": path.stem, "status": "ERROR", "lastrun": "", "extra": {"Error": str(exc)}})
    return jsonify({"results": results, "directory": str(root), "exists": True})

@app.route("/api/topology/aws")
def api_top_aws():
    if not ORG_FILE_PATH.exists():return jsonify({"error":"AWS Organization Topology file not found."}),404
    try:return jsonify(json.loads(ORG_FILE_PATH.read_text(encoding="utf-8")))
    except Exception as e:return jsonify({"error":str(e)}),500
@app.route("/api/topology/pan")
def api_top_pan():
    if not PAN_TOPOLOGY_PATH.exists():return jsonify({"error":"Panorama Topology file not found."}),404
    try:return jsonify(json.loads(PAN_TOPOLOGY_PATH.read_text(encoding="utf-8")))
    except Exception as e:return jsonify({"error":str(e)}),500
@app.route("/api/investigate")
def api_investigate():
    q=request.args.get("q","").strip()
    if not q:return jsonify({"error":"A search query is required."}),400
    try:return jsonify(DATA.investigate(q))
    except Exception as e:app.logger.exception("Investigation failed");return jsonify({"error":str(e)}),500
@app.route("/api/policy-lookup")
def api_policy():
    try:return jsonify(DATA.policy_lookup(request.args.get("src",""),request.args.get("dst",""),request.args.get("port","")))
    except Exception as e:app.logger.exception("Policy lookup failed");return jsonify({"error":str(e)}),500
@app.route("/api/debug-records")
def api_debug():
    c=get_db(DATA.db_file)
    try:return jsonify({"categories":[dict(r) for r in c.execute("SELECT platform,category,COUNT(*) count FROM records GROUP BY platform,category ORDER BY platform,category")]})
    finally:c.close()


def main():
    global DB_PATH,FW_DATA_ROOT,AWS_DATA_ROOT,ORG_FILE_PATH,PAN_TOPOLOGY_PATH,DATA
    p=argparse.ArgumentParser(description="Infrastructure Intelligence Dashboard")
    p.add_argument("--db",default=str(DB_PATH));p.add_argument("--firewall-data",default=str(FW_DATA_ROOT));p.add_argument("--aws-data",default=str(AWS_DATA_ROOT));p.add_argument("--org-file",default=str(ORG_FILE_PATH));p.add_argument("--pan-file",default=str(PAN_TOPOLOGY_PATH));p.add_argument("--port",type=int,default=8080);p.add_argument("--host",default="0.0.0.0");p.add_argument("--debug",action="store_true")
    a=p.parse_args();DB_PATH=Path(a.db).resolve();FW_DATA_ROOT=Path(a.firewall_data).resolve();AWS_DATA_ROOT=Path(a.aws_data).resolve();ORG_FILE_PATH=Path(a.org_file).resolve();PAN_TOPOLOGY_PATH=Path(a.pan_file).resolve();DATA=InfrastructureDataSource(DB_PATH)
    print(f"[*] Starting web server on http://localhost:{a.port}/");print(f"[*] Database: {DB_PATH}");print("[*] app.py does not ingest. Run ingest.py when parsed JSON changes.")
    app.run(host=a.host,port=a.port,debug=a.debug)
if __name__=="__main__":main()
