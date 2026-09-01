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
    try: return json.loads(raw)
    except Exception: return {}


def _record(row: Any, *, reason: str | None = None, matched_value: str | None = None) -> dict[str, Any]:
    rec = {"record_id": int(row["id"]), "device": row["device"], "platform": row["platform"],
           "type": row["category"], "category": row["category"], "file": row["filename"],
           "name": row["name"] or "", "data": _safe_json(row["data"])}
    if reason: rec["match_reason"] = reason
    if matched_value: rec["matched_value"] = matched_value
    return rec


def _dedupe(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    out, seen = [], set()
    for x in records:
        rid = int(x.get("record_id", -1))
        if rid not in seen: seen.add(rid); out.append(x)
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
    c=_cat(category)
    if "all_entries" in c: return "raw"
    if any(x in c for x in ("rule","policy","nat","pbf","qos","decryption","override","authentication")): return "rule"
    if "service_group" in c: return "service_group"
    if "service" in c and "group" not in c: return "service"
    if "address_group" in c: return "group"
    if "address" in c: return "object"
    p=_pan_payload(data); keys={str(k).lower() for k in p}
    if "action" in keys and ("source" in keys or "destination" in keys): return "rule"
    if "static" in keys or "member" in keys: return "group"
    return "other"


def _is_raw(row: Any) -> bool: return "all_entries" in _cat(row["category"])

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


def _base_search(conn:sqlite3.Connection, query:str, platform:str|None=None, limit:int=800) -> list[sqlite3.Row]:
    info=classify_ip_search(query); ids=[]
    if info["family"] in (4,6):
        ids=find_network_record_ids(conn,query,platform=platform,limit=max(limit*4,2000))
    else:
        q=query.strip().lower()
        # Exact indexed lookups first. These are the common path for IDs/names.
        sql="SELECT DISTINCT r.id FROM records r WHERE r.name_lower=?"
        p=[q]
        if platform: sql+=" AND r.platform=?"; p.append(platform)
        sql+=" LIMIT ?"; p.append(limit)
        ids += [int(r[0]) for r in conn.execute(sql,p)]
        sql="SELECT DISTINCT rr.record_id FROM record_refs rr JOIN records r ON r.id=rr.record_id WHERE rr.ref_value_lower=?"
        p=[q]
        if platform: sql+=" AND r.platform=?"; p.append(platform)
        sql+=" LIMIT ?"; p.append(limit)
        ids += [int(r[0]) for r in conn.execute(sql,p)]
        # Terms are still indexed, but only consulted if exact refs/names weren't enough.
        if len(ids)<limit:
            sql="SELECT DISTINCT rt.record_id FROM record_terms rt JOIN records r ON r.id=rt.record_id WHERE rt.term_lower=?"
            p=[q]
            if platform: sql+=" AND r.platform=?"; p.append(platform)
            sql+=" LIMIT ?"; p.append(limit-len(ids))
            ids += [int(r[0]) for r in conn.execute(sql,p)]
        # FTS is a fallback for partial text queries, not the normal identifier path.
        if len(ids)<limit and len(q)>=3:
            toks=re.findall(r"[A-Za-z0-9_./:@-]+",query)
            fts=" AND ".join('"'+t.replace('"','')+'"*' for t in toks if t)
            if fts:
                sql="SELECT f.rowid FROM records_fts f JOIN records r ON r.id=f.rowid WHERE records_fts MATCH ?"
                p=[fts]
                if platform: sql+=" AND r.platform=?"; p.append(platform)
                sql+=" LIMIT ?"; p.append(limit-len(ids))
                try: ids += [int(r[0]) for r in conn.execute(sql,p)]
                except sqlite3.Error: pass
    return fetch_records_by_ids(conn,dict.fromkeys(ids))[:limit]


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


def _pan_record_rows(conn, ids:list[int]) -> list[sqlite3.Row]:
    return fetch_records_by_ids(conn,ids)


def _pan_entity_candidates(conn, names:set[str], limit:int) -> list[sqlite3.Row]:
    if not names:return []
    ids=[]
    for name in list(names)[:1000]:
        rows=conn.execute("SELECT id FROM records WHERE platform='panos' AND name_lower=? LIMIT ?",(name.lower(),limit)).fetchall()
        ids.extend(int(r[0]) for r in rows)
    return _pan_record_rows(conn,list(dict.fromkeys(ids))[:limit])


def _expand_groups_sql(conn:sqlite3.Connection, names:set[str], limit:int=3000) -> tuple[set[str],list[sqlite3.Row]]:
    all_names={x.lower() for x in names if x}; groups={}; group_ids=set(); rows=[]
    # Upward expansion: find groups containing any known member; repeat for nested groups.
    for _ in range(20):
        if not all_names: break
        ph=','.join('?'*len(all_names))
        found=conn.execute(f"""SELECT DISTINCT g.id,g.device_id,g.platform,g.category,g.filename,g.name,g.data
            FROM pan_group_members gm JOIN records g ON g.id=gm.group_record_id
            WHERE g.platform='panos' AND gm.member_name_lower IN ({ph}) LIMIT ?""",[*all_names,limit]).fetchall()
        new=set()
        for r in found:
            rid=int(r["id"]); n=(r["name"] or "").lower()
            if rid not in group_ids:
                group_ids.add(rid); rows.append(r); 
                if n and n not in all_names:new.add(n)
        if not new: break
        all_names.update(new)
    return all_names,rows


def _pan_inventory(conn:sqlite3.Connection, query:str, base:list[sqlite3.Row], ctx:list[dict[str,Any]], limit:int):
    # Start from exact/network candidates. For each network context, use the network index.
    ids={int(r["id"]) for r in base if r["platform"]=="panos" and not _is_raw(r)}
    for c in ctx:
        for rid in find_network_record_ids(conn,c["value"],platform="panos",limit=min(limit*4,5000)): ids.add(rid)
    base_pan=_pan_record_rows(conn,list(ids)[:max(limit*4,5000)])
    object_ids=[]; group_ids=[]; rule_ids=[]; raw=[]; entity_names=set()
    for r in base_pan:
        rec=_record(r)
        role=_pan_role(r["category"],r["data"])
        if role=="object": object_ids.append(rec); entity_names.add((r["name"] or "").lower())
        elif role in ("group","service_group"): group_ids.append(rec); entity_names.add((r["name"] or "").lower())
        elif role=="rule": rule_ids.append(rec)
        elif role=="raw": raw.append(rec)
    # Pull groups that contain a matching object, then recursively nested parents.
    expanded_names, group_rows=_expand_groups_sql(conn,entity_names,limit=3000)
    for r in group_rows:
        rec=_record(r,reason="contains_matched_object_or_group")
        if int(r["id"]) not in {x["record_id"] for x in group_ids}: group_ids.append(rec)
        expanded_names.add((r["name"] or "").lower())
    # If a matched rule references an object/group, surface those entities without scanning all rules.
    rule_ref_ids=set()
    for r in base_pan:
        if _pan_role(r["category"],r["data"])=="rule":
            for f in ("source","destination","service"):
                for n in _rule_field(_record(r),f):
                    entity_names.add(n.lower()); expanded_names.add(n.lower())
                    rule_ref_ids.add(n.lower())
    ent_rows=_pan_entity_candidates(conn,entity_names|expanded_names,limit=4000)
    for r in ent_rows:
        role=_pan_role(r["category"],r["data"]); rec=_record(r,reason="rule_or_group_reference")
        if role=="object" and rec["record_id"] not in {x["record_id"] for x in object_ids}: object_ids.append(rec)
        elif role in ("group","service_group") and rec["record_id"] not in {x["record_id"] for x in group_ids}: group_ids.append(rec)
    # Rule lookup is index-driven: names on source/destination/service or literal CIDRs in either side.
    candidate_rule_ids={int(r["id"]) for r in base_pan if _pan_role(r["category"],r["data"])=="rule"}
    names_for_rules={x for x in expanded_names if x}
    if names_for_rules:
        ph=','.join('?'*len(names_for_rules))
        for r in conn.execute(f"SELECT DISTINCT rule_record_id FROM pan_rule_refs WHERE ref_name_lower IN ({ph}) LIMIT ?",[*names_for_rules,5000]): candidate_rule_ids.add(int(r[0]))
    for c in ctx:
        bounds=network_bounds(c["value"])
        if not bounds: continue
        ver,start,end=bounds
        for r in conn.execute("""SELECT DISTINCT rule_record_id FROM pan_rule_networks
             WHERE version=? AND start_hex<=? AND end_hex>=? LIMIT ?""",(ver,f"{int(end):032x}",f"{int(start):032x}",5000)): candidate_rule_ids.add(int(r[0]))
    if not candidate_rule_ids:
        # No network/name candidate: don't scan every rule.
        rule_rows=[]
    else:
        rule_rows=_pan_record_rows(conn,list(candidate_rule_ids)[:10000])
    matched_rules=[]
    ctxnets=[c["value"] for c in ctx]
    names={x.lower() for x in expanded_names if x}
    for r in rule_rows:
        if _pan_role(r["category"],r["data"])!="rule": continue
        rec=_record(r); reasons=[]
        for field in ("source","destination"):
            refs=_rule_field(rec,field)
            hit=False
            for ref in refs:
                if ref.lower()=="any": hit=True; reasons.append(f"{field}:any"); continue
                if ref.lower() in names: hit=True; reasons.append(f"{field}:object:{ref}")
                if network_bounds(ref) and any(value_matches_network_or_range(ref,n) for n in ctxnets): hit=True; reasons.append(f"{field}:network:{ref}")
            if hit: rec.setdefault("match_fields",[]).append(field)
        # Inventory search is directional-agnostic: either source or destination hit is useful.
        if not rec.get("match_fields") and not (not ctxnets and not names): continue
        rec["action"]=_rule_action(rec); rec["decision"]=_decision(rec["action"]); rec["match_details"]={"fields":reasons}
        matched_rules.append(rec)
    return _dedupe(object_ids)[:limit],_dedupe(group_ids)[:limit],_dedupe(matched_rules)[:limit],_dedupe(raw)[:100]


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


def _service_hit(conn:sqlite3.Connection, refs:list[str], port:str, cache:dict[str,list[sqlite3.Row]], visited=None)->bool:
    if not port:return True
    proto,num,raw=_parse_port(port)
    if any(x.lower()=="any" for x in refs):return True
    if num is None:return False
    if visited is None:visited=set()
    def one(ref:str):
        key=ref.lower()
        if key in visited:return False
        visited.add(key)
        if re.search(rf"(?<!\d){num}(?!\d)",key):return True
        if key not in cache:
            cache[key]=conn.execute("SELECT id,device_id,platform,category,filename,name,data FROM records WHERE platform='panos' AND name_lower=? LIMIT 50",(key,)).fetchall()
        for r in cache[key]:
            role=_pan_role(r["category"],r["data"])
            if role=="service_group":
                rec=_record(r)
                if any(one(x) for x in _group_members(rec)):return True
            elif role=="service":
                blob=json.dumps(r["data"]).lower()
                if proto and proto not in blob:continue
                if any(_port_spec_hit(num,s) for s in _service_specs(r["data"])):return True
        return False
    return any(one(x) for x in refs)


class InfrastructureDataSource:
    def __init__(self,db_file:Path|None=None): self._db_file=db_file
    @property
    def db_file(self):return self._db_file or DB_PATH
    def files_count(self):
        c=get_db(self.db_file)
        try:return int(c.execute("SELECT COUNT(*) FROM records").fetchone()[0])
        finally:c.close()
    def devices_count(self):
        c=get_db(self.db_file)
        try:return int(c.execute("SELECT COUNT(*) FROM devices").fetchone()[0])
        finally:c.close()
    def get_stats(self):
        c=get_db(self.db_file)
        try:
            return {"panos":{r["category"]:r["cnt"] for r in c.execute("SELECT category,COUNT(*) cnt FROM records WHERE platform='panos' GROUP BY category")},
                    "aws_resources":{r["category"]:r["cnt"] for r in c.execute("SELECT category,COUNT(*) cnt FROM records WHERE platform='aws' GROUP BY category")},
                    "aws_accounts_scanned":int(c.execute("SELECT COUNT(*) FROM devices WHERE name LIKE 'AWS:%'").fetchone()[0]),
                    "total_files":int(c.execute("SELECT COUNT(*) FROM records").fetchone()[0]),
                    "indexed_terms":int(c.execute("SELECT COUNT(*) FROM record_terms").fetchone()[0]),
                    "indexed_networks":int(c.execute("SELECT COUNT(*) FROM record_networks").fetchone()[0]),
                    "indexed_refs":int(c.execute("SELECT COUNT(*) FROM record_refs").fetchone()[0])}
        finally:c.close()
    def investigate(self,query:str,limit:int=800):
        timings={}; t=time.perf_counter(); info=classify_ip_search(query)
        conn=get_db(self.db_file)
        try:
            t0=time.perf_counter(); base=_base_search(conn,query,limit=limit); timings["indexed_search_ms"]=round((time.perf_counter()-t0)*1000,2)
            t0=time.perf_counter(); aws,sgs,ctx=_aws_expand(conn,query,base,limit); timings["aws_relationships_ms"]=round((time.perf_counter()-t0)*1000,2)
            # A Palo object may itself contain the network that maps back into AWS.
            pan_base=[r for r in base if r["platform"]=="panos"]
            seen={x["value"].lower() for x in ctx}
            for v in _network_values(conn,[r["id"] for r in pan_base]): _add_ctx(ctx,seen,v,"palo_object","")
            # Reverse Palo -> AWS network mapping.
            existing={x["record_id"] for x in aws}
            for c in list(ctx):
                for rid in find_network_record_ids(conn,c["value"],platform="aws",limit=limit*2):
                    if rid in existing:continue
                    rr=fetch_records_by_ids(conn,[rid])
                    if not rr:continue
                    r=rr[0]; item=_safe_json(r["data"]); cat=_cat(r["category"])
                    if _is_sg(r["category"],item):continue
                    if any(x in cat for x in ("instance","network_interface","eni","subnet","vpc","load_balancer","rds","db","route53","hosted")):
                        aws.append(_record(r,reason="reverse_network_relationship",matched_value=c["value"])); existing.add(rid)
            t0=time.perf_counter(); objects,groups,rules,raw=_pan_inventory(conn,query,base,ctx,limit); timings["palo_relationships_ms"]=round((time.perf_counter()-t0)*1000,2)
            # Add useful direct network names from AWS subnet/VPC relationships into Palo matching.
            timings["total_ms"]=round((time.perf_counter()-t)*1000,2)
            return {"query":query,"query_type":info["type"],"query_family":info["family"],"aws_matches":_dedupe(aws),"attached_security_groups":_dedupe(sgs),
                    "matched_objects":objects,"matched_groups":groups,"matched_rules":rules,"all_entries_matches":raw,"network_context":ctx,
                    "timing":timings,"summary":{"aws_resources":len(_dedupe(aws)),"attached_sgs":len(_dedupe(sgs)),"palo_objects":len(objects),"palo_groups":len(groups),"palo_rules":len(rules),"all_entries":len(raw)}}
        finally:conn.close()
    def policy_lookup(self,source:str="",destination:str="",port:str=""):
        source,destination,port=source.strip(),destination.strip(),port.strip()
        total=time.perf_counter()
        if not source and not destination:return {"query":{"source":source,"destination":destination,"port":port},"source_context":None,"destination_context":None,"matched_objects":[],"matched_groups":[],"matched_rules":[],"summary":{"objects":0,"groups":0,"rules":0,"allow":0,"deny":0}}
        t=time.perf_counter(); src=self.investigate(source,500) if source else None; dst=self.investigate(destination,500) if destination else None
        timing={"endpoint_resolution_ms":round((time.perf_counter()-t)*1000,2)}
        def endpoint(inv,q):
            if not inv:return None
            names={q.lower()}
            for r in inv.get("matched_objects",[])+inv.get("matched_groups",[]):
                if r.get("name"):names.add(r["name"].lower())
            nets=[x["value"] for x in inv.get("network_context",[])]
            if network_bounds(q) and q not in nets:nets.append(q)
            return {"query":q,"query_type":inv.get("query_type"),"names":sorted(names),"networks":nets,"aws_matches":inv.get("aws_matches",[]),"attached_security_groups":inv.get("attached_security_groups",[]),"objects":inv.get("matched_objects",[]),"groups":inv.get("matched_groups",[])}
        srcctx,dstctx=endpoint(src,source),endpoint(dst,destination)
        conn=get_db(self.db_file)
        try:
            t=time.perf_counter(); ids=set()
            for ctx,field in ((srcctx,"source"),(dstctx,"destination")):
                if not ctx:continue
                names=set(ctx["names"])
                if names:
                    ph=','.join('?'*len(names)); ids.update(int(r[0]) for r in conn.execute(f"SELECT DISTINCT rule_record_id FROM pan_rule_refs WHERE field=? AND ref_name_lower IN ({ph})",[field,*names]))
                for n in ctx["networks"]:
                    b=network_bounds(n)
                    if b:
                        v,s,e=b; ids.update(int(r[0]) for r in conn.execute("SELECT DISTINCT rule_record_id FROM pan_rule_networks WHERE field=? AND version=? AND start_hex<=? AND end_hex>=?",(field,v,f"{int(e):032x}",f"{int(s):032x}")))
            # Rules using 'any' on either endpoint are possible candidates. This is a much smaller
            # scan than all Palo records and is bounded by the number of rule records.
            for field in ("source","destination"):
                ids.update(int(r[0]) for r in conn.execute("SELECT DISTINCT rule_record_id FROM pan_rule_refs WHERE field=? AND ref_name_lower='any'",(field,)))
            rows=fetch_records_by_ids(conn,list(ids)[:15000]); timing["rule_candidate_sql_ms"]=round((time.perf_counter()-t)*1000,2)
            t=time.perf_counter(); service_cache={}; matched=[]
            def side(rec,field,ctx):
                if not ctx:return True,["not_specified"]
                refs=_rule_field(rec,field); reasons=[]
                names=set(ctx["names"]); nets=ctx["networks"]
                for x in refs:
                    if x.lower()=="any":reasons.append("any")
                    elif x.lower() in names:reasons.append(f"entity:{x}")
                    elif network_bounds(x) and any(value_matches_network_or_range(x,n) for n in nets):reasons.append(f"network:{x}")
                return bool(reasons),reasons
            for r in rows:
                if _pan_role(r["category"],r["data"])!="rule":continue
                rec=_record(r); sh,sr=side(rec,"source",srcctx); dh,dr=side(rec,"destination",dstctx)
                if sh and dh and _service_hit(conn,_rule_field(rec,"service"),port,service_cache):
                    rec["action"]=_rule_action(rec); rec["decision"]=_decision(rec["action"]); rec["match_details"]={"source":sr,"destination":dr,"services":_rule_field(rec,"service"),"port_query":port}
                    matched.append(rec)
            timing["rule_evaluation_ms"]=round((time.perf_counter()-t)*1000,2)
        finally:conn.close()
        objs=_dedupe((src or {}).get("matched_objects",[])+(dst or {}).get("matched_objects",[])); groups=_dedupe((src or {}).get("matched_groups",[])+(dst or {}).get("matched_groups",[])); matched=_dedupe(matched)
        allow=sum(1 for r in matched if r.get("decision")=="ALLOWED"); deny=sum(1 for r in matched if r.get("decision")=="DENIED")
        timing["total_ms"]=round((time.perf_counter()-total)*1000,2)
        return {"query":{"source":source,"destination":destination,"port":port},"source_context":srcctx,"destination_context":dstctx,"matched_objects":objs,"matched_groups":groups,"matched_rules":matched,"timing":timing,"summary":{"objects":len(objs),"groups":len(groups),"rules":len(matched),"allow":allow,"deny":deny}}

DATA=InfrastructureDataSource()

@app.route("/")
def index():return render_template("index.html")
@app.route("/api/info")
def api_info():return jsonify({"files":DATA.files_count(),"devices":DATA.devices_count()})
@app.route("/api/stats")
def api_stats():return jsonify(DATA.get_stats())
@app.route("/api/automation/status")
def api_status():return jsonify({"aws_org_mtime":get_file_modified_time(ORG_FILE_PATH),"aws_data_mtime":get_latest_dir_mtime(AWS_DATA_ROOT),"pan_org_mtime":get_file_modified_time(PAN_TOPOLOGY_PATH),"pan_data_mtime":get_latest_dir_mtime(FW_DATA_ROOT)})
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
