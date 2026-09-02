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
app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))


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

@app.route("/")
def index():return render_template("index.html")
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
