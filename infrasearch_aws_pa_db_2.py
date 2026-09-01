#!/usr/bin/env python3
"""
PerDef Security Orchestrator GUI (Left-Sidebar Unified Dashboard)
------------------------------------------------------------
Tabs:
  1. Search & Investigation
  2. Firewall Policy Lookup
  3. AWS Organization Topology Explorer
  4. PAN-OS Panorama Topology & Mapping
  5. Automation Results & Collection Status
  6. Information & Useful Links
  7. Data Collection Metrics & Analytics
  8. About / Site Info

Run:
    python infra_intel.py --firewall-data ./parsed --aws-data ./aws_parsed --org-file org_topology.json --pan-file panorama_topology.json --db infra_intel.db
Then open:
    http://localhost:8080
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sqlite3
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

DB_PATH = Path("infra_intel.db")
FW_DATA_ROOT = Path("parsed").resolve()
AWS_DATA_ROOT = Path("aws_parsed").resolve()
ORG_FILE_PATH = Path("org_topology.json").resolve()
PAN_TOPOLOGY_PATH = Path("panorama_topology.json").resolve()


# ----------------------------------------------------------------------
# IP and Subnet Matching Helpers
# ----------------------------------------------------------------------

def extract_ip_or_cidr(val: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if not val:
        return None
    val = str(val).strip()
    try:
        if "/" in val:
            return ipaddress.ip_network(val, strict=False)
        return ipaddress.ip_network(val + "/32", strict=False)
    except ValueError:
        return None


def sqlite_ip_contains(target_str: str, cidr_or_range_str: str) -> int:
    if not target_str or not cidr_or_range_str:
        return 0
    
    target_net = extract_ip_or_cidr(target_str)
    if not target_net:
        return 0

    val = str(cidr_or_range_str).strip()
    
    if "-" in val and "/" not in val:
        parts = val.split("-")
        if len(parts) == 2:
            try:
                start = ipaddress.ip_address(parts[0].strip())
                end = ipaddress.ip_address(parts[1].strip())
                return 1 if start <= target_net.network_address <= end or start <= target_net.broadcast_address <= end else 0
            except ValueError:
                pass

    fw_net = extract_ip_or_cidr(val)
    if fw_net:
        # Adjusted to catch both overlaps and when a target /32 falls inside a larger /16 or /20
        try:
            return 1 if target_net.overlaps(fw_net) or target_net.subnet_of(fw_net) or fw_net.subnet_of(target_net) else 0
        except ValueError:
            return 1 if target_net.overlaps(fw_net) else 0
        
    return 0


def extract_direct_attached_sg_ids(item: dict[str, Any]) -> set[str]:
    sg_ids = set()
    groups = item.get("Groups") or item.get("SecurityGroups")
    if isinstance(groups, list):
        for g in groups:
            if isinstance(g, str) and g.startswith("sg-"):
                sg_ids.add(g)
            elif isinstance(g, dict):
                gid = g.get("GroupId") or g.get("VpcSecurityGroupId")
                if gid and str(gid).startswith("sg-"):
                    sg_ids.add(str(gid))

    nis = item.get("NetworkInterfaces")
    if isinstance(nis, list):
        for ni in nis:
            if isinstance(ni, dict):
                ni_groups = ni.get("Groups") or ni.get("SecurityGroups")
                if isinstance(ni_groups, list):
                    for g in ni_groups:
                        if isinstance(g, str) and g.startswith("sg-"):
                            sg_ids.add(g)
                        elif isinstance(g, dict):
                            gid = g.get("GroupId") or g.get("VpcSecurityGroupId")
                            if gid and str(gid).startswith("sg-"):
                                sg_ids.add(str(gid))
                                
    return sg_ids


def get_file_modified_time(filepath: Path) -> str:
    if filepath.exists():
        mtime = os.path.getmtime(filepath)
        return datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
    return "N/A"


def get_latest_dir_mtime(dirpath: Path) -> str:
    if not dirpath.exists():
        return "N/A"
    latest = 0.0
    for p in dirpath.rglob("*.json"):
        if p.is_file():
            mtime = os.path.getmtime(p)
            if mtime > latest:
                latest = mtime
    if latest > 0:
        return datetime.fromtimestamp(latest).strftime('%Y-%m-%d %H:%M:%S')
    return "N/A"


def get_db(db_file: Path | None = None):
    if db_file is None:
        db_file = DB_PATH
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    conn.create_function("IP_CONTAINS", 2, sqlite_ip_contains)
    return conn


def init_db(db_file: Path | None = None):
    if db_file is None:
        db_file = DB_PATH
    if db_file.exists():
        db_file.unlink()
        
    conn = get_db(db_file)
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        );

        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            platform TEXT,
            category TEXT,
            filename TEXT,
            name TEXT,           
            data TEXT,           
            FOREIGN KEY(device_id) REFERENCES devices(id)
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS records_fts USING fts5(
            name, data, content='records', content_rowid='id'
        );

        CREATE TRIGGER records_ai AFTER INSERT ON records BEGIN
            INSERT INTO records_fts(rowid, name, data) VALUES (new.id, new.name, new.data);
        END;
    """)
    conn.commit()
    conn.close()


def ingest_data(fw_root: Path, aws_root: Path, db_file: Path | None = None):
    if db_file is None:
        db_file = DB_PATH
    init_db(db_file)
    conn = get_db(db_file)
    cursor = conn.cursor()

    device_cache = {}

    def get_device_id(dev_name: str) -> int:
        if dev_name in device_cache:
            return device_cache[dev_name]
        cursor.execute("INSERT OR IGNORE INTO devices (name) VALUES (?)", (dev_name,))
        cursor.execute("SELECT id FROM devices WHERE name = ?", (dev_name,))
        row = cursor.fetchone()
        device_cache[dev_name] = row["id"]
        return row["id"]

    if fw_root.exists():
        for path in sorted(fw_root.rglob("*.json")):
            if not path.is_file():
                continue
            rel = path.relative_to(fw_root)
            device = rel.parts[0] if len(rel.parts) > 1 else "(root)"
            file_type = path.stem

            try:
                with path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue

            candidates = data if isinstance(data, list) else [data]
            dev_id = get_device_id(device)

            for item in candidates:
                if not isinstance(item, dict):
                    continue
                name = item.get("name", item.get("@name", ""))
                if not name:
                    for key in ("object", "rule", "profile", "entry"):
                        val = item.get(key)
                        if isinstance(val, dict) and (val.get("name") or val.get("@name")):
                            name = str(val.get("name") or val.get("@name"))
                            break

                cursor.execute(
                    "INSERT INTO records (device_id, platform, category, filename, name, data) VALUES (?, ?, ?, ?, ?, ?)",
                    (dev_id, "panos", file_type, path.name, str(name), json.dumps(item))
                )

    if aws_root.exists():
        for path in sorted(aws_root.rglob("*.json")):
            if not path.is_file():
                continue
            rel = path.relative_to(aws_root)
            if len(rel.parts) < 3:
                continue
            
            account_name = rel.parts[0]
            service_type = path.stem

            try:
                with path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue

            candidates = data if isinstance(data, list) else [data]
            dev_id = get_device_id(f"AWS: {account_name}")

            for item in candidates:
                if not isinstance(item, dict):
                    continue
                
                name = ""
                for name_key in ("VpcId", "SubnetId", "NetworkInterfaceId", "LoadBalancerArn", "LoadBalancerName", "InstanceId", "DBInstanceId", "GroupId", "Id", "Name", "Id"):
                    if item.get(name_key):
                        name = str(item[name_key])
                        if "arn:aws:" in name:
                            name = name.split("/")[-1]
                        break
                if not name:
                    name = item.get("GroupName", item.get("HostedZone", {}).get("Name", "AWS-Resource"))

                cursor.execute(
                    "INSERT INTO records (device_id, platform, category, filename, name, data) VALUES (?, ?, ?, ?, ?, ?)",
                    (dev_id, "aws", service_type, path.name, str(name), json.dumps(item))
                )

    conn.commit()
    conn.close()


class InfrastructureDataSource:
    def __init__(self, db_file: Path | None = None):
        self._db_file = db_file

    @property
    def db_file(self) -> Path:
        return self._db_file if self._db_file is not None else DB_PATH

    def get_stats(self) -> dict[str, Any]:
        conn = get_db(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("SELECT category, COUNT(*) as cnt FROM records WHERE platform='panos' GROUP BY category")
        panos_counts = {row["category"]: row["cnt"] for row in cursor.fetchall()}
        
        cursor.execute("SELECT category, COUNT(*) as cnt FROM records WHERE platform='aws' GROUP BY category")
        aws_summary = {row["category"]: row["cnt"] for row in cursor.fetchall()}

        cursor.execute("SELECT COUNT(DISTINCT name) FROM devices WHERE name LIKE 'AWS:%'")
        aws_accounts_count = cursor.fetchone()[0]

        conn.close()
        return {
            "panos": panos_counts,
            "aws_resources": aws_summary,
            "aws_accounts_scanned": aws_accounts_count,
            "total_files": self.files_count()
        }

    def files_count(self) -> int:
        conn = get_db(self.db_file)
        count = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        conn.close()
        return count

    def devices_count(self) -> int:
        conn = get_db(self.db_file)
        count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        conn.close()
        return count

    def investigate(self, query: str, limit: int = 500) -> dict[str, Any]:
        query = query.strip()
        query_network = extract_ip_or_cidr(query)
        
        output = {
            "query": query,
            "query_type": "ip_or_cidr" if query_network else "text",
            "matched_objects": [],
            "matched_rules": [],
            "all_entries_matches": [],
            "aws_matches": [],
            "attached_security_groups": [],
            "summary": {}
        }

        conn = get_db(self.db_file)
        cursor = conn.cursor()

        matched_aws_record_ids = set()
        attached_sg_ids = set()
        related_cidrs_to_match = set()

        if query_network:
            related_cidrs_to_match.add(query_network.compressed)

        pending_aws_lookups = []
        if query_network:
            target_ip = str(query_network.network_address)
            target_cidr = query_network.compressed
            
            cursor.execute("""
                SELECT r.id, d.name as device, r.platform, r.category, r.filename, r.name, r.data
                FROM records r
                JOIN devices d ON r.device_id = d.id
                WHERE r.platform = 'aws' AND (r.data LIKE ? OR r.data LIKE ?)
                LIMIT ?
            """, (f"%{target_ip}%", f"%{target_cidr}%", limit))
            
            for row in cursor.fetchall():
                if row["id"] not in matched_aws_record_ids:
                    matched_aws_record_ids.add(row["id"])
                    pending_aws_lookups.append(row)
        else:
            clean_q = re.sub(r'[^a-zA-Z0-9_\-\.]', ' ', query).strip()
            if clean_q:
                fts_query = f'"{clean_q}"*'
                cursor.execute("""
                    SELECT r.id, d.name as device, r.platform, r.category, r.filename, r.name, r.data
                    FROM records r
                    JOIN devices d ON r.device_id = d.id
                    JOIN records_fts fts ON fts.rowid = r.id
                    WHERE r.platform = 'aws' AND records_fts MATCH ?
                    LIMIT ?
                """, (fts_query, limit))
                
                for row in cursor.fetchall():
                    if row["id"] not in matched_aws_record_ids:
                        matched_aws_record_ids.add(row["id"])
                        pending_aws_lookups.append(row)

        for row in pending_aws_lookups:
            item = json.loads(row["data"])

            output["aws_matches"].append({
                "device": row["device"],
                "type": row["category"],
                "file": row["filename"],
                "name": row["name"],
                "data": item
            })

            dev_name = row["device"]
            
            direct_sgs = extract_direct_attached_sg_ids(item)
            for sg_id in direct_sgs:
                attached_sg_ids.add((dev_name, sg_id))

            subnet_id = item.get("SubnetId")
            vpc_id = item.get("VpcId")

            # 1. Directly check if matched item has a CidrBlock (Subnet/VPC)
            item_cidr = item.get("CidrBlock")
            if item_cidr:
                related_cidrs_to_match.add(item_cidr)

            # 2. Check all account subnets to see if our query IP falls inside them
            cursor.execute("""
                SELECT data FROM records r JOIN devices d ON r.device_id = d.id
                WHERE (r.category LIKE '%subnet%') AND d.name = ?
            """, (dev_name,))
            for s_row in cursor.fetchall():
                s_data = json.loads(s_row["data"])
                s_cidr = s_data.get("CidrBlock")
                if s_cidr and query_network:
                    s_net = extract_ip_or_cidr(s_cidr)
                    if s_net and query_network.subnet_of(s_net):
                        related_cidrs_to_match.add(s_cidr)

            # 3. Check all account VPCs to see if our query IP falls inside them
            cursor.execute("""
                SELECT data FROM records r JOIN devices d ON r.device_id = d.id
                WHERE (r.category LIKE '%vpc%') AND d.name = ?
            """, (dev_name,))
            for v_row in cursor.fetchall():
                v_data = json.loads(v_row["data"])
                v_cidr = v_data.get("CidrBlock")
                if v_cidr and query_network:
                    v_net = extract_ip_or_cidr(v_cidr)
                    if v_net and query_network.subnet_of(v_net):
                        related_cidrs_to_match.add(v_cidr)
                for block in v_data.get("CidrBlockAssociationSet", []):
                    if isinstance(block, dict) and block.get("CidrBlock") and query_network:
                        b_net = extract_ip_or_cidr(block["CidrBlock"])
                        if b_net and query_network.subnet_of(b_net):
                            related_cidrs_to_match.add(block["CidrBlock"])

            if subnet_id:
                cursor.execute("""
                    SELECT data FROM records r JOIN devices d ON r.device_id = d.id
                    WHERE (r.category LIKE '%subnet%') AND (r.name = ? OR json_extract(r.data, '$.SubnetId') = ?) AND d.name = ?
                """, (subnet_id, subnet_id, dev_name))
                for s_row in cursor.fetchall():
                    s_data = json.loads(s_row["data"])
                    cidr = s_data.get("CidrBlock")
                    if cidr:
                        related_cidrs_to_match.add(cidr)

            if vpc_id:
                cursor.execute("""
                    SELECT data FROM records r JOIN devices d ON r.device_id = d.id
                    WHERE (r.category LIKE '%vpc%') AND (r.name = ? OR json_extract(r.data, '$.VpcId') = ?) AND d.name = ?
                """, (vpc_id, vpc_id, dev_name))
                for v_row in cursor.fetchall():
                    v_data = json.loads(v_row["data"])
                    cidr = v_data.get("CidrBlock")
                    if cidr:
                        related_cidrs_to_match.add(cidr)
                    for block in v_data.get("CidrBlockAssociationSet", []):
                        if isinstance(block, dict) and block.get("CidrBlock"):
                            related_cidrs_to_match.add(block["CidrBlock"])

      # 2. Immediately following the AWS loop, place the new Palo Alto lookup block 
        # so it utilizes the newly discovered subnets/VPCs from related_cidrs_to_match:
        palo_matched_objects = set()
        
        all_target_nets = [query_network] if query_network else []
        for c_str in related_cidrs_to_match:
            net_obj = extract_ip_or_cidr(c_str)
            if net_obj:
                all_target_nets.append(net_obj)

        cursor.execute("""
            SELECT r.id, r.name, r.category, r.data, d.name as device_name 
            FROM records r JOIN devices d ON r.device_id = d.id 
            WHERE r.category LIKE '%object%' OR r.category LIKE '%address%' OR r.category LIKE '%group%'
        """)
        
        for row in cursor.fetchall():
            try:
                p_data = json.loads(row["data"])
                p_val = p_data.get("ip_net") or p_data.get("address") or p_data.get("value") or row["name"]
                p_net = extract_ip_or_cidr(str(p_val))
                
                if p_net:
                    for t_net in all_target_nets:
                        if t_net.subnet_of(p_net) or p_net.subnet_of(t_net) or t_net == t_net:
                            output["palo_matches"].append({
                                "device": row["device_name"],
                                "type": row["category"],
                                "file": "",
                                "name": row["name"],
                                "data": p_data
                            })
                            break
            except Exception:
                continue
                          
        for dev_name, sg_id in attached_sg_ids:
            cursor.execute("""
                SELECT r.id, d.name as device, r.category, r.filename, r.name, r.data
                FROM records r
                JOIN devices d ON r.device_id = d.id
                WHERE (r.category = 'security_groups' OR r.category = 'security_group' OR r.category LIKE '%security-group%')
                  AND (r.name = ? OR json_extract(r.data, '$.GroupId') = ?) AND d.name = ?
            """, (sg_id, sg_id, dev_name))
            
            for sg_row in cursor.fetchall():
                sg_item = json.loads(sg_row["data"])
                exists = any(s.get("record_id") == sg_row["id"] for s in output["attached_security_groups"])
                if not exists:
                    output["attached_security_groups"].append({
                        "record_id": sg_row["id"],
                        "device": sg_row["device"],
                        "type": sg_row["category"],
                        "file": sg_row["filename"],
                        "name": sg_row["name"],
                        "data": sg_item
                    })

        matched_panos_ids = set()
        matched_object_names = set()

        cursor.execute("""
            SELECT r.id, d.name as device, r.platform, r.category, r.filename, r.name, r.data
            FROM records r
            JOIN devices d ON r.device_id = d.id
            WHERE r.platform = 'panos'
        """)
        
        all_panos_records = cursor.fetchall()

        def classify_and_append_panos(row_dict, item_payload):
            filename = str(row_dict["filename"]).lower()
            cat = str(row_dict["category"]).lower()
            rec = {
                "device": row_dict["device"],
                "type": row_dict["category"],
                "file": row_dict["filename"],
                "name": row_dict["name"],
                "data": item_payload
            }

            if "all_entries" in filename or "all_entries" in cat:
                output["all_entries_matches"].append(rec)
            elif "rule" in cat or "policy" in cat or "nat" in cat:
                output["matched_rules"].append(rec)
            else:
                output["matched_objects"].append(rec)

        if related_cidrs_to_match:
            def extract_all_json_ips(obj: Any) -> list[str]:
                results = []
                if isinstance(obj, str):
                    val = obj.strip()
                    if "/" in val or "-" in val or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', val):
                        results.append(val)
                elif isinstance(obj, list):
                    for item in obj:
                        results.extend(extract_all_json_ips(item))
                elif isinstance(obj, dict):
                    for k, v in obj.items():
                        results.extend(extract_all_json_ips(v))
                return results

            for row in all_panos_records:
                item_data = json.loads(row["data"])
                is_match = False
                
                # Recursively extract all potential IP/CIDR/range strings from anywhere in the record
                targets = extract_all_json_ips(item_data)

                for cidr in related_cidrs_to_match:
                    cidr_net = extract_ip_or_cidr(cidr)
                    for target in targets:
                        target_net = extract_ip_or_cidr(target)
                        if cidr_net and target_net:
                            # Ensure both are the same IP version (v4 vs v6) to prevent TypeErrors
                            if cidr_net.version == target_net.version:
                                if cidr_net.overlaps(target_net) or cidr_net.subnet_of(target_net) or target_net.subnet_of(cidr_net):
                                    is_match = True
                                    break
                        elif target and sqlite_ip_contains(cidr, target):
                            is_match = True
                            break
                    if is_match:
                        break

                if is_match:
                    matched_panos_ids.add(row["id"])
                    eval_obj = item_data.get("entry", item_data) if isinstance(item_data, dict) else item_data
                    obj_name = row["name"] or item_data.get("name") or (eval_obj.get("@name") if isinstance(eval_obj, dict) else "")
                    if obj_name:
                        matched_object_names.add(str(obj_name))
                    classify_and_append_panos(row, item_data)

            expanded_new_names = True
            while expanded_new_names:
                expanded_new_names = False
                for row in all_panos_records:
                    if row["id"] in matched_panos_ids:
                        continue

                    item_data = json.loads(row["data"])
                    data_str = json.dumps(item_data)

                    for name in list(matched_object_names):
                        if re.search(r'\b' + re.escape(name) + r'\b', data_str):
                            matched_panos_ids.add(row["id"])
                            eval_obj = item_data.get("entry", item_data) if isinstance(item_data, dict) else item_data
                            obj_name = row["name"] or (eval_obj.get("@name") if isinstance(eval_obj, dict) else "")
                            if obj_name and str(obj_name) not in matched_object_names:
                                matched_object_names.add(str(obj_name))
                                expanded_new_names = True
                            classify_and_append_panos(row, item_data)
                            break

        else:
            clean_q = re.sub(r'[^a-zA-Z0-9_\-\.]', ' ', query).strip()
            if clean_q:
                fts_query = f'"{clean_q}"*'
                cursor.execute("""
                    SELECT r.id, d.name as device, r.platform, r.category, r.filename, r.name, r.data
                    FROM records r
                    JOIN devices d ON r.device_id = d.id
                    JOIN records_fts fts ON fts.rowid = r.id
                    WHERE r.platform = 'panos' AND records_fts MATCH ?
                    LIMIT ?
                """, (fts_query, limit))
                for row in cursor.fetchall():
                    if row["id"] not in matched_panos_ids:
                        matched_panos_ids.add(row["id"])
                        classify_and_append_panos(row, json.loads(row["data"]))

        output["summary"] = {
            "aws_resources": len(output["aws_matches"]),
            "attached_sgs": len(output["attached_security_groups"]),
            "palo_objects": len(output["matched_objects"]),
            "palo_rules": len(output["matched_rules"]),
            "all_entries": len(output["all_entries_matches"])
        }

        conn.close()
        return output


PANOS = InfrastructureDataSource()

# ----------------------------------------------------------------------
# GUI Frontend Template
# ----------------------------------------------------------------------

HTML = r"""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PerDef Security Orchestrator — Dashboard</title>
<style>
:root {
    --dark-gray: #3b3c43;
    --gold: #fbc600;
    --medium-gray: #94969a;
    --light-gray: #e0eae8;
    
    --bg-main: #2b2c32;
    --bg-surface: var(--dark-gray);
    --bg-card: #45464f;
    --border-color: var(--gold);
    --text-primary: var(--light-gray);
    --text-secondary: var(--medium-gray);
    --accent: var(--gold);
    --accent-hover: #d4a700;
    --palo-orange: var(--gold);
    --code-bg: #2d2e34;
    --sidebar-width: 260px;
}

* { box-sizing: border-box; }

body {
    margin: 0;
    background: var(--bg-main);
    color: var(--text-primary);
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    display: flex;
    min-height: 100vh;
}

.sidebar {
    width: var(--sidebar-width);
    background: var(--bg-surface);
    border-right: 1px solid var(--border-color);
    display: flex;
    flex-direction: column;
    position: fixed;
    top: 0; bottom: 0; left: 0;
    z-index: 100;
}

.brand {
    padding: 20px;
    display: flex;
    gap: 12px;
    align-items: center;
    border-bottom: 1px solid var(--border-color);
}
.logo {
    width: 36px; height: 36px; border-radius: 8px; background: var(--gold);
    display: grid; place-items: center; font-weight: bold; font-size: 18px; color: var(--dark-gray);
}
.brand h1 { margin: 0; font-size: 15px; font-weight: 700; letter-spacing: 0.5px; color: var(--light-gray); }
.brand small { color: var(--medium-gray); font-size: 11px; }

.nav-menu {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 16px 12px;
    flex: 1;
}

.tab-btn {
    background: transparent;
    color: var(--text-secondary);
    border: none;
    padding: 12px 14px;
    font-size: 13.5px;
    font-weight: 600;
    cursor: pointer;
    border-radius: 8px;
    text-align: left;
    transition: all 0.2s;
    display: flex;
    align-items: center;
    gap: 10px;
}

.tab-btn:hover { color: var(--text-primary); background: rgba(251, 198, 0, 0.1); }
.tab-btn.active { color: var(--dark-gray); background: var(--gold); }

.sidebar-footer {
    padding: 16px;
    border-top: 1px solid var(--border-color);
    font-size: 11px;
    color: var(--text-secondary);
}

.main-wrapper {
    margin-left: var(--sidebar-width);
    flex: 1;
    padding: 28px;
    max-width: 1400px;
}

.tab-content { display: none; }
.tab-content.active { display: block; }

.beta-banner {
    background: rgba(251, 198, 0, 0.15);
    border: 1px solid var(--gold);
    color: var(--gold);
    padding: 10px 16px;
    border-radius: 8px;
    font-size: 13px;
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
}

.search-panel {
    background: var(--bg-surface);
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    border: 1px solid var(--border-color);
}

.search-row { display: flex; gap: 10px; flex-wrap: wrap; }
.search-row input { flex: 1; min-width: 320px; }

input, button {
    height: 44px;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 0 14px;
    font-size: 14px;
    outline: none;
    background: var(--bg-main);
    color: var(--text-primary);
}
input:focus { border-color: var(--gold); box-shadow: 0 0 0 3px rgba(251, 198, 0, 0.25); }
button { background: var(--gold); color: var(--dark-gray); border: 0; font-weight: 600; cursor: pointer; transition: background 0.2s; }
button:hover { background: var(--accent-hover); }
button.secondary { background: var(--bg-card); color: var(--text-primary); border: 1px solid var(--border-color); }

.hint { color: var(--text-secondary); font-size: 13px; margin-top: 10px; }

.summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 14px;
    margin: 18px 0;
}

.card {
    background: var(--bg-surface);
    padding: 16px;
    border-radius: 10px;
    border: 1px solid var(--border-color);
}
.card b { display: block; font-size: 24px; color: var(--gold); font-weight: 700; }
.card.palo-card b { color: var(--gold); }
.card span { color: var(--text-secondary); font-size: 11px; margin-top: 4px; display: block; text-transform: uppercase; letter-spacing: 0.5px; }

.status-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: 16px;
    margin-top: 16px;
}

.status-card {
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    padding: 18px;
}

.status-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
}

.status-title { font-weight: 700; font-size: 15px; }
.status-pill {
    padding: 3px 8px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
}
.status-pill.success { background: rgba(251, 198, 0, 0.2); color: var(--gold); border: 1px solid var(--gold); }

.section {
    background: var(--bg-surface);
    border-radius: 10px;
    margin-bottom: 20px;
    border: 1px solid var(--border-color);
    overflow: hidden;
}

.section-title {
    padding: 14px 18px;
    border-bottom: 1px solid var(--border-color);
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #2f3036;
}
.section-title h2 { font-size: 14px; margin: 0; font-weight: 600; color: var(--text-primary); }
.count { background: var(--bg-card); border-radius: 20px; padding: 2px 10px; font-size: 11px; font-weight: 600; color: var(--gold); border: 1px solid var(--border-color); }

.item { border-bottom: 1px solid var(--border-color); padding: 18px; }
.item:last-child { border-bottom: 0; }

.item-head {
    display: flex;
    justify-content: space-between;
    gap: 10px;
    flex-wrap: wrap;
    align-items: center;
}
.item-name { font-weight: 700; font-size: 15px; color: var(--light-gray); }

.badge {
    display: inline-block;
    background: var(--bg-card);
    color: var(--light-gray);
    border-radius: 6px;
    padding: 3px 8px;
    margin-left: 6px;
    font-size: 11px;
    font-weight: 600;
    border: 1px solid var(--medium-gray);
}
.badge.blue { background: #2f3036; color: var(--gold); border: 1px solid var(--gold); }
.badge.aws { background: #4a3e1c; color: var(--gold); border: 1px solid var(--gold); }
.badge.sg { background: #3b3a43; color: var(--light-gray); border: 1px solid var(--medium-gray); }
.badge.palo { background: rgba(251, 198, 0, 0.15); color: var(--gold); border: 1px solid var(--gold); }

.meta { color: var(--text-secondary); font-size: 12px; margin-top: 4px; }
pre { background: var(--code-bg); color: var(--light-gray); border-radius: 8px; padding: 14px; overflow: auto; max-height: 350px; font-size: 12px; font-family: monospace; border: 1px solid var(--border-color); }
details { margin-top: 10px; }
summary { color: var(--gold); cursor: pointer; font-size: 12px; font-weight: 600; }

.prop-table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; background: var(--bg-card); border-radius: 6px; overflow: hidden; border: 1px solid var(--border-color); }
.prop-table th { background: #2f3036; color: var(--gold); text-align: left; padding: 8px 12px; font-weight: 600; border-bottom: 1px solid var(--border-color); width: 25%; }
.prop-table td { padding: 8px 12px; border-bottom: 1px solid #4f5058; color: var(--text-primary); font-family: monospace; word-break: break-all; }
.prop-table tr:last-child td { border-bottom: none; }

.rule-tag { display: inline-block; background: var(--bg-main); padding: 2px 8px; border-radius: 4px; font-size: 12px; margin: 2px; border: 1px solid var(--medium-gray); color: var(--text-secondary); }
.rule-tag.allow { background: rgba(251, 198, 0, 0.2); color: var(--gold); border-color: var(--gold); font-weight: bold; }
.rule-tag.deny { background: #5a2d2d; color: #fecaca; border-color: #991b1b; font-weight: bold; }
.rule-tag.highlight { background: var(--bg-card); color: var(--gold); border-color: var(--gold); }

/* 2-Column Info Page Layout */
.info-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-top: 14px;
}
@media (max-width: 900px) {
    .info-grid { grid-template-columns: 1fr; }
}

.link-column-title {
    font-size: 15px;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 14px;
    border-bottom: 2px solid var(--border-color);
    padding-bottom: 8px;
}

.link-card {
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 14px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
}
.link-card h4 { margin: 0 0 6px 0; color: var(--text-primary); font-size: 14px; }
.link-card p { margin: 0 0 10px 0; font-size: 12.5px; color: var(--text-secondary); line-height: 1.4; }
.link-card a {
    color: var(--gold);
    text-decoration: none;
    font-size: 12.5px;
    font-weight: 600;
}
.link-card a:hover { text-decoration: underline; }

.sub-links {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin-top: 6px;
    padding-top: 8px;
    border-top: 1px dashed var(--border-color);
}

.org-tree { font-family: monospace; font-size: 13px; line-height: 1.6; }
.tree-node { margin: 8px 0; }
.tree-folder { font-weight: bold; color: var(--text-primary); padding: 6px 0; display: inline-block; }
.tree-leaf {
    background: var(--bg-card);
    padding: 8px 12px;
    border-radius: 6px;
    margin: 6px 0;
    border: 1px solid var(--border-color);
}
.switch-link { color: var(--gold); text-decoration: none; font-weight: 600; }
.switch-link:hover { text-decoration: underline; color: #ffe680; }

.empty { padding: 30px; text-align: center; color: var(--text-secondary); font-size: 14px; }

.about-card {
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    padding: 16px;
    margin-top: 10px;
}
.about-card h3 { margin: 0 0 8px 0; color: var(--gold); font-size: 16px; }
.about-card p { margin: 4px 0; font-size: 13px; color: var(--text-primary); }
</style>
</head>

<body>

<div class="sidebar">
    <div class="brand">
        <div class="logo">🔒</div>
        <div>
            <h1>PerDef Security Orchestrator</h1>
            <small>Unified Security Dashboard</small>
        </div>
    </div>
    
    <div class="nav-menu">
        <button class="tab-btn active" onclick="switchTab('search', this)">🔍 Search & Investigate</button>
        <button class="tab-btn" onclick="switchTab('policyLookup', this)">🛡️ Firewall Policy Lookup</button>
        <button class="tab-btn" onclick="switchTab('org', this)">🏢 AWS Org Topology</button>
        <button class="tab-btn" onclick="switchTab('pan', this)">🔥 PAN Panorama Topology</button>
        <button class="tab-btn" onclick="switchTab('automation', this)">⚙️ Automation Results</button>
        <button class="tab-btn" onclick="switchTab('info', this)">ℹ️ Information & Links</button>
        <button class="tab-btn" onclick="switchTab('stats', this)">📊 Collection Analytics</button>
        
        <button class="tab-btn" onclick="switchTab('about', this)" style="margin-top: auto;">ℹ️ About / Site Info</button>
    </div>

    <div class="sidebar-footer">
        <div id="dataInfo">Loading database status...</div>
    </div>
</div>

<div class="main-wrapper">

    <div id="tab-search" class="tab-content active">
        <div class="beta-banner">
            ⚠️ <b>Early Beta Warning:</b> This search tool is currently in early preview. Always manually double-check and verify findings against your source system before performing administrative changes.
        </div>

        <div class="search-panel">
            <div class="search-row">
                <input id="query" placeholder="Search IP, CIDR, Instance ID (i-xxxx), ENI ID, Route53 Domain/Record, Palo Rule..." autocomplete="off">
                <button onclick="investigate()">Investigate</button>
                <button class="secondary" onclick="clearAll()">Clear</button>
            </div>
            <div class="hint">
                💡 High-noise 'all_entries' objects are cleanly tucked away in an expandable tray at the bottom.
            </div>
        </div>

        <div id="summary"></div>
        <div id="output">
            <div class="empty">Enter a query above to start exploring your infrastructure.</div>
        </div>
    </div>

    <div id="tab-policyLookup" class="tab-content">
        <div class="beta-banner">
            🛡️ <b>Firewall Policy Intersection Lookup:</b> Enter a source, destination, and optional port/service to find existing firewall rules where both entities match together.
        </div>

        <div class="search-panel">
            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr auto; gap: 10px; flex-wrap: wrap;">
                <input id="lookupSource" placeholder="Source IP, Subnet, or Object..." autocomplete="off">
                <input id="lookupDest" placeholder="Destination IP, Subnet, or Object..." autocomplete="off">
                <input id="lookupPort" placeholder="Port / Service (Optional)..." autocomplete="off">
                <button onclick="executePolicyLookup()">Check Rules</button>
            </div>
            <div class="hint">
                💡 Useful for firewall change requests to quickly verify if an access path is already permitted by existing rules.
            </div>
        </div>

        <div id="policyLookupOutput" style="margin-top: 20px;">
            <div class="empty">Enter source, destination, and optional port above to query rules.</div>
        </div>
    </div>

    <div id="tab-org" class="tab-content">
        <div class="section">
            <div class="section-title">
                <h2>AWS Organization Hierarchy</h2>
                <span id="orgMeta" class="count">Ready</span>
            </div>
            <!-- Added clean top link bar -->
            <div style="padding: 12px 20px; border-bottom: 1px solid var(--border-color); background: #2f3036; display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 13px; color: var(--text-secondary);">Quick Access:</span>
                <a href="https://aws.amazon.com/console/" target="_blank" class="switch-link" style="font-size: 13px;">🔗 Open Main AWS Console Login &rarr;</a>
            </div>
            <div style="padding: 16px 20px; border-bottom: 1px solid var(--border-color); background: var(--bg-surface); display: flex; align-items: center; gap: 12px;">
                <label for="crossRoleInput" style="font-size: 13px; font-weight: 600; color: var(--text-secondary);">Cross-Account Role Name:</label>
                <input id="crossRoleInput" type="text" placeholder="e.g. OrganizationAccountAccessRole or SecurityAdmin" style="height: 36px; width: 320px;" oninput="renderOrgTreeWithRole()">
                <small style="color: var(--text-secondary);">Populating this makes AWS account IDs clickable direct Switch-Role links.</small>
            </div>
            <div style="padding: 20px;" id="orgTreeView" class="org-tree">
                <div class="empty">Loading organization topology...</div>
            </div>
        </div>
    </div>

    <div id="tab-pan" class="tab-content">
        <div class="section">
            <div class="section-title">
                <h2>Panorama Templates & Device Groups Hierarchy</h2>
                <span id="panMeta" class="count">Ready</span>
            </div>
            <!-- Added clean top link bar -->
            <div style="padding: 12px 20px; border-bottom: 1px solid var(--border-color); background: #2f3036; display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 13px; color: var(--text-secondary);">Quick Access:</span>
                <a href="#" onclick="alert('Configure Panorama URL in script or replace this href with your direct Panorama URL.'); return false;" class="switch-link" style="font-size: 13px;">🔗 Open Panorama Login &rarr;</a>
            </div>
            <div style="padding: 20px;" id="panTreeView" class="org-tree">
                <div class="empty">Loading panorama topology...</div>
            </div>
        </div>
    </div>

    <div id="tab-automation" class="tab-content">
        <div class="section">
            <div class="section-title">
                <h2>Automation Job & Collection Results</h2>
                <span class="count">Live Status</span>
            </div>
            <div style="padding: 20px;">
                <h3 style="margin-top: 0; font-size: 15px;">AWS Automated Collections</h3>
                <div class="status-grid">
                    <div class="status-card">
                        <div class="status-card-header">
                            <span class="status-title">AWS Org Collection</span>
                            <span class="status-pill success">Successful</span>
                        </div>
                        <div class="meta"><b>Source File:</b> org_topology.json</div>
                        <div class="meta" id="awsOrgDate"><b>File Date:</b> Loading...</div>
                    </div>

                    <div class="status-card">
                        <div class="status-card-header">
                            <span class="status-title">AWS Resource Data Collection</span>
                            <span class="status-pill success">Successful</span>
                        </div>
                        <div class="meta"><b>Source Directory:</b> ./aws_parsed</div>
                        <div class="meta" id="awsDataDate"><b>File Date:</b> Loading...</div>
                    </div>
                </div>

                <h3 style="margin-top: 24px; font-size: 15px;">Palo Alto Automated Collections</h3>
                <div class="status-grid">
                    <div class="status-card">
                        <div class="status-card-header">
                            <span class="status-title">Panorama Topology Collection</span>
                            <span class="status-pill success">Successful</span>
                        </div>
                        <div class="meta"><b>Source File:</b> panorama_topology.json</div>
                        <div class="meta" id="panOrgDate"><b>File Date:</b> Loading...</div>
                    </div>

                    <div class="status-card">
                        <div class="status-card-header">
                            <span class="status-title">Palo Alto Data Collection</span>
                            <span class="status-pill success">Successful</span>
                        </div>
                        <div class="meta"><b>Source Directory:</b> ./parsed</div>
                        <div class="meta" id="panDataDate"><b>File Date:</b> Loading...</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div id="tab-info" class="tab-content">
        <div class="section">
            <div class="section-title">
                <h2>Useful Links & Infrastructure Portals</h2>
            </div>
            <div style="padding: 20px;">
                <div class="info-grid">
                    <!-- Column 1: Systems & Tools -->
                    <div>
                        <div class="link-column-title">🛠️ System & Tool Portals</div>

                        <div class="link-card">
                            <h4>Splunk Enterprise Log Management</h4>
                            <p>Centralized SIEM log search, firewall traffic analysis, and SOC alerts.</p>
                            <a href="#" onclick="alert('Configure internal Splunk URL in script.'); return false;">Open Splunk &rarr;</a>
                        </div>

                        <div class="link-card">
                            <h4>AWS Management Console</h4>
                            <p>Direct SSO portal access for cloud tenant administration and EC2 management.</p>
                            <a href="https://aws.amazon.com/console/" target="_blank">Open AWS Console &rarr;</a>
                        </div>

                        <div class="link-card">
                            <h4>Palo Alto Panorama Portal</h4>
                            <p>Centralized firewall policy manager, security profile configuration, and rule inspection.</p>
                            <a href="#" onclick="alert('Configure Panorama URL in script.'); return false;">Open Panorama &rarr;</a>
                        </div>

                        <div class="link-card">
                            <h4>Microsoft Azure Portal</h4>
                            <p>Cloud tenant administration, VNets, and Enterprise application management.</p>
                            <a href="https://portal.azure.com" target="_blank">Open Azure Portal &rarr;</a>
                        </div>

                        <div class="link-card">
                            <h4>Infoblox IPAM & Grid Manager</h4>
                            <p>Enterprise IP Address Management, DNS zone administrative panel, and DHCP scopes.</p>
                            <a href="#" onclick="alert('Configure Infoblox URL in script.'); return false;">Open Infoblox &rarr;</a>
                        </div>

                        <div class="link-card">
                            <h4>Wiz Cloud Security Platform</h4>
                            <p>Cloud Security Posture Management (CSPM), vulnerability management, and risk graphs.</p>
                            <a href="#" onclick="alert('Configure Wiz URL in script.'); return false;">Open Wiz &rarr;</a>
                        </div>

                        <div class="link-card">
                            <h4>AlgoSec Firewall Analyzer</h4>
                            <p>Automated security policy analysis, change management, and firewall rule cleanup.</p>
                            <a href="#" onclick="alert('Configure AlgoSec URL in script.'); return false;">Open AlgoSec &rarr;</a>
                        </div>

                        <div class="link-card">
                            <h4>Akamai Control Center</h4>
                            <p>Edge Security, Web Application Firewall (WAF) rule tuning, and CDN management.</p>
                            <a href="https://control.akamai.com" target="_blank">Open Akamai Portal &rarr;</a>
                        </div>
                    </div>

                    <!-- Column 2: General & Information -->
                    <div>
                        <div class="link-column-title">📚 General & Information Links</div>

                        <div class="link-card">
                            <h4>ServiceNow Portal</h4>
                            <p>Enterprise IT Service Management for submitting security requests and incidents.</p>
                            <div class="sub-links">
                                <a href="#" onclick="alert('Configure FW Request URL'); return false;">🔥 Firewall Request</a>
                                <a href="#" onclick="alert('Configure Proxy Request URL'); return false;">🌐 Proxy Request</a>
                                <a href="#" onclick="alert('Configure Security Tab URL'); return false;">🛡️ Security Tab</a>
                            </div>
                        </div>

                        <div class="link-card">
                            <h4>Security Standards & Compliance</h4>
                            <p>Corporate baseline security policies, hardening standards, and governance rules.</p>
                            <a href="#" onclick="alert('Configure documentation link in script.'); return false;">View Security Standards &rarr;</a>
                        </div>

                        <div class="link-card">
                            <h4>Network Documentation</h4>
                            <p>High-level architectural diagrams, VLAN mapping tables, and routing policies.</p>
                            <a href="#" onclick="alert('Configure documentation link in script.'); return false;">View Network Docs &rarr;</a>
                        </div>

                        <div class="link-card">
                            <h4>On-Premise Network Diagrams</h4>
                            <p>Data center topologies, core distribution layer Visio maps, and edge WAN layouts.</p>
                            <a href="#" onclick="alert('Configure diagram link in script.'); return false;">View On-Prem Diagrams &rarr;</a>
                        </div>

                        <div class="link-card">
                            <h4>AWS Architecture Diagrams</h4>
                            <p>Transit Gateway layouts, VPC peering maps, and cross-account network designs.</p>
                            <a href="#" onclick="alert('Configure AWS diagram link in script.'); return false;">View AWS Diagrams &rarr;</a>
                        </div>

                        <div class="link-card">
                            <h4>Azure Architecture Diagrams</h4>
                            <p>Hub-and-Spoke topology diagrams, Azure ExpressRoute connections, and Virtual WAN maps.</p>
                            <a href="#" onclick="alert('Configure Azure diagram link in script.'); return false;">View Azure Diagrams &rarr;</a>
                        </div>

                        <div class="link-card">
                            <h4>Run Books & Operational Procedures</h4>
                            <p>Step-by-step procedures for standard infrastructure operations, failovers, and emergency changes.</p>
                            <a href="#" onclick="alert('Configure Runbooks link in script.'); return false;">View Run Books &rarr;</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div id="tab-stats" class="tab-content">
        <div class="stats-grid" style="display:grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 16px;">
            <div class="card">
                <h3 style="margin-top:0;">☁️ AWS Cloud Inventory</h3>
                <div id="awsStats"><div class="empty">Loading stats...</div></div>
            </div>
            <div class="card">
                <h3 style="margin-top:0; color:var(--palo-orange);">🛡️ PAN-OS Firewall Inventory</h3>
                <div id="panosStats"><div class="empty">Loading stats...</div></div>
            </div>
        </div>
    </div>

    <div id="tab-about" class="tab-content">
        <div class="section">
            <div class="section-title">
                <h2>About / Site Information</h2>
            </div>
            <div style="padding: 20px;">
                <div class="beta-banner">
                    ⚠️ <b>Early Beta Warning:</b> This search tool is currently in early preview. Always manually double-check and verify findings against your source system before performing administrative changes.
                </div>
                
                <div class="about-card">
                    <h3>PerDef Security Orchestrator</h3>
                    <p><b>Version:</b> v.01 (beta)</p>
                    <p><b>Owner:</b> PerDef Team</p>
                </div>
            </div>
        </div>
    </div>

</div>

<script>
let currentOrgData = null;
let currentSearchQuery = "";

function switchTab(tabId, btn) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    document.getElementById('tab-' + tabId).classList.add('active');
    btn.classList.add('active');

    if (tabId === 'org') loadOrgTopology();
    if (tabId === 'pan') loadPanTopology();
    if (tabId === 'automation') loadAutomationResults();
    if (tabId === 'stats') loadStats();
}

function esc(value) {
    return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}
function jsonStr(value) { return esc(JSON.stringify(value, null, 2)); }

function setSummary(s) {
    document.getElementById("summary").innerHTML = `
        <div class="summary">
            <div class="card"><b>${s.aws_resources}</b><span>AWS Resources</span></div>
            <div class="card"><b>${s.attached_sgs}</b><span>Attached Security Groups</span></div>
            <div class="card palo-card"><b>${s.palo_objects}</b><span>Palo Alto Objects & Groups</span></div>
            <div class="card palo-card"><b>${s.palo_rules}</b><span>Palo Alto Security & NAT Rules</span></div>
            <div class="card" style="border-color:var(--border-color);"><b>${s.all_entries || 0}</b><span>Raw All-Entries Items</span></div>
        </div>
    `;
}

function section(title, count, body) {
    return `<div class="section"><div class="section-title"><h2>${title}</h2><span class="count">${count}</span></div>${body}</div>`;
}

function extractValues(obj) {
    if (obj === null || obj === undefined) return [];
    if (typeof obj === 'string' || typeof obj === 'number' || typeof obj === 'boolean') {
        return [String(obj)];
    }
    if (Array.isArray(obj)) {
        return obj.flatMap(item => extractValues(item));
    }
    if (typeof obj === 'object') {
        let results = [];
        if (obj.member !== undefined) results.push(...extractValues(obj.member));
        if (obj.entry !== undefined) results.push(...extractValues(obj.entry));
        if (obj['#text'] !== undefined) results.push(String(obj['#text']));
        if (obj.name !== undefined && typeof obj.name === 'string') results.push(obj.name);
        if (obj['@name'] !== undefined) results.push(String(obj['@name']));
        
        if (results.length > 0) return results;

        for (const [k, v] of Object.entries(obj)) {
            if (!k.startsWith('@')) {
                results.push(...extractValues(v));
            }
        }
        return results;
    }
    return [];
}

function renderPillList(val, defaultLabel = 'any') {
    const items = extractValues(val);
    if (!items || items.length === 0) {
        return `<span class="rule-tag">${esc(defaultLabel)}</span>`;
    }
    return items.map(i => `<span class="rule-tag highlight">${esc(i)}</span>`).join(' ');
}

function findKeyRecursively(obj, keys) {
    if (!obj || typeof obj !== 'object') return undefined;
    for (const k of keys) {
        if (obj[k] !== undefined) return obj[k];
    }
    for (const key in obj) {
        if (typeof obj[key] === 'object') {
            const found = findKeyRecursively(obj[key], keys);
            if (found !== undefined) return found;
        }
    }
    return undefined;
}

function renderRoute53Details(data, query) {
    const raw = data || {};
    const recordSets = raw.ResourceRecordSets || raw.ResourceRecords || [];
    const qLower = (query || "").toLowerCase();

    let matchedRecords = [];

    if (Array.isArray(recordSets)) {
        for (const r of recordSets) {
            const strRepresentation = JSON.stringify(r).toLowerCase();
            if (!qLower || strRepresentation.includes(qLower)) {
                matchedRecords.push(r);
            }
        }
    }

    if (matchedRecords.length === 0 && Array.isArray(recordSets)) {
        matchedRecords = recordSets.slice(0, 10);
    }

    let html = `<div style="margin-top: 10px;">`;
    html += `<b style="font-size:13px; color: var(--accent);">Matched Route53 Resource Record(s):</b>`;
    html += `<table class="prop-table" style="margin-top:6px;">`;
    html += `<tr><th>Record Name / FQDN</th><th>Type</th><th>TTL</th><th>Values / Targets</th></tr>`;

    for (const rec of matchedRecords) {
        const rName = rec.Name || rec.name || "-";
        const rType = rec.Type || rec.type || "-";
        const rTTL = rec.TTL ?? rec.ttl ?? "-";
        
        let values = [];
        if (Array.isArray(rec.ResourceRecords)) {
            values = rec.ResourceRecords.map(v => typeof v === 'object' ? (v.Value || JSON.stringify(v)) : v);
        } else if (rec.AliasTarget) {
            values.push("Alias: " + (rec.AliasTarget.DNSName || JSON.stringify(rec.AliasTarget)));
        } else if (rec.Value) {
            values.push(rec.Value);
        }

        const formattedValues = values.length > 0 
            ? values.map(v => `<span class="rule-tag highlight">${esc(v)}</span>`).join(" ")
            : `<i style="color:var(--text-secondary)">None</i>`;

        html += `<tr>`;
        html += `<td><b>${esc(rName)}</b></td>`;
        html += `<td><span class="badge blue">${esc(rType)}</span></td>`;
        html += `<td>${esc(rTTL)}</td>`;
        html += `<td>${formattedValues}</td>`;
        html += `</tr>`;
    }

    html += `</table></div>`;
    return html;
}

function renderSecurityGroupDetails(data) {
    const raw = data || {};
    const ipPermissions = raw.IpPermissions || [];
    const ipPermissionsEgress = raw.IpPermissionsEgress || [];
    const sgName = raw.GroupName || raw.GroupId || "Security Group";
    const description = raw.Description || "No description provided.";

    let html = `<div style="margin-top: 10px;">`;
    html += `<b style="font-size:13px; color: var(--accent);">Security Group Details:</b>`;
    html += `<div class="meta" style="margin-bottom: 8px;"><b>Description:</b> ${esc(description)}</div>`;

    // Helper to render rule blocks
    function renderRulesTable(title, rules, isEgress) {
        let tHtml = `<div style="margin-top: 8px; font-weight: bold; font-size: 12px; color: var(--text-primary);">${title}</div>`;
        tHtml += `<table class="prop-table" style="margin-top:4px;">`;
        tHtml += `<tr><th>Protocol / Ports</th><th>Source / Destination Targets</th></tr>`;

        if (!rules || rules.length === 0) {
            tHtml += `<tr><td colspan="2"><i style="color:var(--text-secondary)">No rules defined</i></td></tr>`;
        } else {
            for (const rule of rules) {
                let proto = rule.IpProtocol === "-1" ? "All Protocols" : (rule.IpProtocol ? rule.IpProtocol.toUpperCase() : "Any");
                let fromPort = rule.FromPort;
                let toPort = rule.ToPort;
                
                let portDisplay = proto;
                if (rule.IpProtocol !== "-1" && fromPort !== undefined && toPort !== undefined) {
                    if (fromPort === toPort) {
                        portDisplay = `${proto} : ${fromPort}`;
                    } else {
                        portDisplay = `${proto} : ${fromPort} - ${toPort}`;
                    }
                }

                let targetEntries = [];
                const targetKey = isEgress ? (rule.IpRanges || rule.Ipv6Ranges || rule.UserIdGroupPairs || rule.PrefixListIds) : (rule.IpRanges || rule.Ipv6Ranges || rule.UserIdGroupPairs || rule.PrefixListIds);
                
                // Collect IP ranges
                if (Array.isArray(rule.IpRanges)) {
                    rule.IpRanges.forEach(r => targetEntries.push(r.CidrIp + (r.Description ? ` (${r.Description})` : '')));
                }
                if (Array.isArray(rule.Ipv6Ranges)) {
                    rule.Ipv6Ranges.forEach(r => targetEntries.push(r.CidrIpv6 + (r.Description ? ` (${r.Description})` : '')));
                }
                // Collect Security Group references / targets
                if (Array.isArray(rule.UserIdGroupPairs)) {
                    rule.UserIdGroupPairs.forEach(g => targetEntries.push((g.GroupId || g.GroupName) + (g.Description ? ` (${g.Description})` : '')));
                }
                // Collect Prefix list IDs
                if (Array.isArray(rule.PrefixListIds)) {
                    rule.PrefixListIds.forEach(p => targetEntries.push(p.PrefixListId));
                }

                if (targetEntries.length === 0 && rule.IpProtocol === "-1") {
                    targetEntries.push("0.0.0.0/0 (Any)");
                }

                const formattedTargets = targetEntries.length > 0
                    ? targetEntries.map(v => `<span class="rule-tag highlight">${esc(v)}</span>`).join(" ")
                    : `<i style="color:var(--text-secondary)">None</i>`;

                tHtml += `<tr>`;
                tHtml += `<td><span class="badge blue">${esc(portDisplay)}</span></td>`;
                tHtml += `<td>${formattedTargets}</td>`;
                tHtml += `</tr>`;
            }
        }
        tHtml += `</table>`;
        return tHtml;
    }

    html += renderRulesTable("📥 Inbound Rules (IpPermissions)", ipPermissions, false);
    html += renderRulesTable("📤 Outbound Rules (IpPermissionsEgress)", ipPermissionsEgress, true);
    html += `</div>`;
    return html;
}

function renderPaloAltoDetails(x) {
    const raw = x.data || {};
    const d = raw.entry || raw;
    const cat = (x.type || "").toLowerCase();

    if (cat.includes("rule") || cat.includes("policy") || cat.includes("nat") || d.action || d.from || d.to) {
        const action = findKeyRecursively(d, ['action']) || 'allow';
        const actionBadge = (String(action).toLowerCase() === "allow") 
            ? `<span class="rule-tag allow">ALLOW</span>` 
            : `<span class="rule-tag deny">${esc(String(action).toUpperCase())}</span>`;

        const fromVal = findKeyRecursively(d, ['from', 'from-zone']);
        const toVal = findKeyRecursively(d, ['to', 'to-zone']);
        const srcVal = findKeyRecursively(d, ['source']);
        const dstVal = findKeyRecursively(d, ['destination', 'dest']);
        const appVal = findKeyRecursively(d, ['application', 'app']);
        const svcVal = findKeyRecursively(d, ['service', 'port']);
        const urlVal = findKeyRecursively(d, ['url-category', 'category']);
        const descVal = findKeyRecursively(d, ['description']);

        let html = `<table class="prop-table">`;
        html += `<tr><th>Rule Action</th><td>${actionBadge}</td></tr>`;
        html += `<tr><th>From Zone(s)</th><td>${renderPillList(fromVal, 'any')}</td></tr>`;
        html += `<tr><th>To Zone(s)</th><td>${renderPillList(toVal, 'any')}</td></tr>`;
        html += `<tr><th>Source Address</th><td>${renderPillList(srcVal, 'any')}</td></tr>`;
        html += `<tr><th>Destination Address</th><td>${renderPillList(dstVal, 'any')}</td></tr>`;
        html += `<tr><th>Application</th><td>${renderPillList(appVal, 'any')}</td></tr>`;
        html += `<tr><th>Service / Port</th><td>${renderPillList(svcVal, 'any')}</td></tr>`;
        if (urlVal) html += `<tr><th>URL Category</th><td>${renderPillList(urlVal, 'any')}</td></tr>`;
        if (descVal) html += `<tr><th>Description</th><td>${esc(extractValues(descVal).join(" "))}</td></tr>`;
        html += `</table>`;
        return html;
    }

    const nameVal = x.name || findKeyRecursively(d, ['name', '@name']) || 'Unnamed Object';
    const descVal = findKeyRecursively(d, ['description']);
    
    const ipNetmask = findKeyRecursively(d, ['ip-netmask', 'ip_netmask']);
    const ipRange = findKeyRecursively(d, ['ip-range', 'ip_range']);
    const fqdn = findKeyRecursively(d, ['fqdn']);
    const members = findKeyRecursively(d, ['static', 'members', 'member', 'group']);

    let html = `<table class="prop-table">`;
    html += `<tr><th>Object Name</th><td><b>${esc(nameVal)}</b></td></tr>`;
    
    if (descVal) {
        html += `<tr><th>Description</th><td>${esc(extractValues(descVal).join(" "))}</td></tr>`;
    } else {
        html += `<tr><th>Description</th><td><i style="color:var(--text-secondary)">None</i></td></tr>`;
    }

    if (members) html += `<tr><th>Group Members</th><td>${renderPillList(members, 'None')}</td></tr>`;
    if (ipNetmask) html += `<tr><th>IP / Subnet</th><td>${renderPillList(ipNetmask)}</td></tr>`;
    if (ipRange) html += `<tr><th>IP Range</th><td>${renderPillList(ipRange)}</td></tr>`;
    if (fqdn) html += `<tr><th>FQDN</th><td>${renderPillList(fqdn)}</td></tr>`;

    if (!members && !ipNetmask && !ipRange && !fqdn) {
        const genericVals = extractValues(d).filter(v => v !== nameVal);
        if (genericVals.length > 0) {
            html += `<tr><th>Value(s)</th><td>${genericVals.map(v => `<span class="rule-tag highlight">${esc(v)}</span>`).join(' ')}</td></tr>`;
        }
    }
    
    html += `</table>`;
    return html;
}

function renderProperties(obj) {
    if (!obj || typeof obj !== 'object') return '';
    let html = `<table class="prop-table">`;
    for (const [k, v] of Object.entries(obj)) {
        if (v !== null && v !== undefined && v !== "" && typeof v !== 'object') {
            html += `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`;
        }
    }
    html += `</table>`;
    return html;
}

function itemHTML(x, badgeClass) {
    const rawData = x.data || {};
    const evalData = rawData.entry || rawData;
    const displayName = x.name || evalData.name || evalData['@name'] || "Unnamed Record";
    const categoryLower = (x.type || "").toLowerCase();
    
    let extraDetails = "";
    if (badgeClass === "palo") {
        extraDetails = renderPaloAltoDetails(x);
    } else if (categoryLower.includes("security_group") || categoryLower.includes("security-group") || rawData.IpPermissions !== undefined) {
        extraDetails = renderSecurityGroupDetails(rawData);
    } else if (categoryLower.includes("route53") || categoryLower.includes("r53") || categoryLower.includes("hostedzone") || rawData.ResourceRecordSets) {
        extraDetails = renderRoute53Details(rawData, currentSearchQuery);
    } else {
        extraDetails = renderProperties(x.data);
    }

    return `
        <div class="item">
            <div class="item-head">
                <div class="item-name">${esc(displayName)}</div>
                <div>
                    <span class="badge blue">${esc(x.device)}</span>
                    <span class="badge ${badgeClass}">${esc(x.type)}</span>
                </div>
            </div>
            <div class="meta">Source File: ${esc(x.file)}</div>
            ${extraDetails}
            <details style="margin-top: 12px;">
                <summary>View Full Raw JSON Payload</summary>
                <pre>${jsonStr(x.data)}</pre>
            </details>
        </div>
    `;
}

function render(data) {
    setSummary(data.summary);
    let html = "";
    if (data.aws_matches.length) html += section("Matching AWS Resources", data.aws_matches.length, data.aws_matches.map(x => itemHTML(x, "aws")).join(""));
    if (data.attached_security_groups.length) html += section("Attached Security Groups", data.attached_security_groups.length, data.attached_security_groups.map(x => itemHTML(x, "sg")).join(""));
    if (data.matched_objects.length) html += section("Palo Alto Objects & Groups", data.matched_objects.length, data.matched_objects.map(x => itemHTML(x, "palo")).join(""));
    if (data.matched_rules.length) html += section("Palo Alto Security Rules & NATs", data.matched_rules.length, data.matched_rules.map(x => itemHTML(x, "palo")).join(""));
    
    if (data.all_entries_matches && data.all_entries_matches.length > 0) {
        const allEntriesContent = data.all_entries_matches.map(x => itemHTML(x, "palo")).join("");
        html += `
            <div class="section" style="border-style: dashed;">
                <details>
                    <summary style="padding: 16px; font-size: 14px; background: #2f3036;">
                        📄 Parsed Full Collections (all_entries.json Files) — <b>${data.all_entries_matches.length} items hidden</b>
                    </summary>
                    <div>
                        ${allEntriesContent}
                    </div>
                </details>
            </div>
        `;
    }

    if (!html) html = `<div class="empty">No matching records found.</div>`;
    document.getElementById("output").innerHTML = html;
}

async function investigate() {
    const q = document.getElementById("query").value.trim();
    if (!q) return;
    currentSearchQuery = q;
    document.getElementById("output").innerHTML = `<div class="empty">Searching indexed database for <b>${esc(q)}</b>...</div>`;
    try {
        const res = await fetch("/api/investigate?q=" + encodeURIComponent(q));
        const data = await res.json();
        render(data);
    } catch (err) {
        document.getElementById("output").innerHTML = `<div class="empty" style="color:#f87171;">Error executing search query.</div>`;
    }
}

async function executePolicyLookup() {
    const src = document.getElementById("lookupSource").value.trim();
    const dst = document.getElementById("lookupDest").value.trim();
    const port = document.getElementById("lookupPort").value.trim();

    if (!src && !dst) {
        alert("Please enter at least a Source or Destination to search.");
        return;
    }

    document.getElementById("policyLookupOutput").innerHTML = `<div class="empty">Querying firewall policies for matching intersections...</div>`;
    
    try {
        const params = new URLSearchParams();
        if (src) params.append("src", src);
        if (dst) params.append("dst", dst);
        if (port) params.append("port", port);

        const res = await fetch("/api/policy-lookup?" + params.toString());
        const data = await res.json();

        if (data.rules && data.rules.length > 0) {
            let html = `<div class="section"><div class="section-title"><h2>Matching Rules & Intersections</h2><span class="count">${data.rules.length} Rules Found</span></div>`;
            html += data.rules.map(x => itemHTML(x, "palo")).join("");
            html += `</div>`;
            document.getElementById("policyLookupOutput").innerHTML = html;
        } else {
            document.getElementById("policyLookupOutput").innerHTML = `<div class="empty">No intersecting firewall rules found matching the given criteria.</div>`;
        }
    } catch (err) {
        document.getElementById("policyLookupOutput").innerHTML = `<div class="empty" style="color:#f87171;">Error executing policy lookup query.</div>`;
    }
}

function buildTreeHTML(node, roleName) {
    if (!node) return '';
    let html = '';
    const name = node.Name || node.Id || node.name || 'Unit';
    const accounts = node.Accounts || node.AccountList || [];
    const children = node.OUs || node.Children || node.SubOUs || [];

    html += `<div class="tree-node">`;
    html += `<span class="tree-folder">📁 ${esc(name)}</span>`;
    
    if (accounts.length > 0) {
        html += `<div style="margin-left: 20px;">`;
        accounts.forEach(acc => {
            const accName = acc.Name || acc.Id;
            const accId = acc.Id || acc.AccountId || '';
            
            let accountLabelHTML = `<b>${esc(accName)}</b> <span style="color:var(--text-secondary);">(${esc(accId)})</span>`;
            if (roleName && accId) {
                const switchUrl = `https://signin.aws.amazon.com/switchrole?account=${encodeURIComponent(accId)}&roleName=${encodeURIComponent(roleName)}`;
                accountLabelHTML = `<a class="switch-link" href="${switchUrl}" target="_blank" title="Click to Switch Role in AWS Console">📄 ${esc(accName)} <span style="color:var(--text-secondary);">(${esc(accId)})</span> 🔗 Switch Role</a>`;
            } else {
                accountLabelHTML = `📄 ${accountLabelHTML}`;
            }

            html += `<div class="tree-leaf">${accountLabelHTML}</div>`;
        });
        html += `</div>`;
    }

    if (children.length > 0) {
        html += `<div style="margin-left: 10px;">`;
        children.forEach(child => html += buildTreeHTML(child, roleName));
        html += `</div>`;
    }

    html += `</div>`;
    return html;
}

function renderOrgTreeWithRole() {
    if (!currentOrgData) return;
    const roleName = document.getElementById("crossRoleInput").value.trim();
    document.getElementById("orgTreeView").innerHTML = buildTreeHTML(currentOrgData.Hierarchy || currentOrgData, roleName);
}

async function loadOrgTopology() {
    try {
        const r = await fetch("/api/topology/aws");
        const data = await r.json();
        if (data.error) {
            document.getElementById("orgTreeView").innerHTML = `<div class="empty">${esc(data.error)}</div>`;
            return;
        }
        currentOrgData = data;
        renderOrgTreeWithRole();
        document.getElementById("orgMeta").textContent = "Loaded";
    } catch(e) {
        document.getElementById("orgTreeView").innerHTML = `<div class="empty">Unable to render topology tree.</div>`;
    }
}

function buildPanTreeHTML(node) {
    if (!node) return '';
    let html = '';
    
    const groupName = node.Name || node.DeviceGroupName || node.TemplateGroupName || node.name || 'Group';
    const groupType = node.Type || node.GroupType || (node.TemplateGroups ? 'Device Group' : 'Group');
    const templateGroups = node.TemplateGroups || node.template_groups || [];
    const firewalls = node.Firewalls || node.Devices || node.firewalls || [];

    html += `<div class="tree-node">`;
    html += `<span class="tree-folder">📁 ${esc(groupName)} <span class="badge blue">${esc(groupType)}</span></span>`;

    if (templateGroups.length > 0) {
        html += `<div style="margin-left: 20px;">`;
        templateGroups.forEach(tg => {
            const tgName = tg.Name || tg.TemplateGroupName || tg.name || 'Template Group';
            const tgFirewalls = tg.Firewalls || tg.Devices || tg.firewalls || [];
            
            html += `<div class="tree-node">`;
            html += `<span class="tree-folder" style="color: var(--gold);">📂 Template Group: ${esc(tgName)}</span>`;
            
            if (tgFirewalls.length > 0) {
                html += `<div style="margin-left: 20px;">`;
                tgFirewalls.forEach(fw => html += renderFirewallLeaf(fw));
                html += `</div>`;
            }
            html += `</div>`;
        });
        html += `</div>`;
    }

    if (firewalls.length > 0) {
        html += `<div style="margin-left: 20px;">`;
        firewalls.forEach(fw => {
            html += renderFirewallLeaf(fw);
        });
        html += `</div>`;
    }

    const subGroups = node.Groups || node.DeviceGroups || [];
    if (subGroups.length > 0) {
        html += `<div style="margin-left: 10px;">`;
        subGroups.forEach(sub => html += buildPanTreeHTML(sub));
        html += `</div>`;
    }

    html += `</div>`;
    return html;
}

function renderFirewallLeaf(fw) {
    const hostname = fw.Hostname || fw.hostname || fw.Name || fw.name || 'Unknown Firewall';
    const serial = fw.Serial || fw.serial || 'N/A';
    const description = fw.Description || fw.description || '';
    const ip = fw.ManagementIP || fw.ip || fw.ManagementIp || fw.MGMT_IP || 'IP not specified';

    return `
        <div class="tree-leaf">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                <div>
                    🔥 <b>${esc(hostname)}</b> 
                    <span style="color: var(--text-secondary); font-size: 11px; margin-left: 6px;">Serial: <b>${esc(serial)}</b></span>
                </div>
                <div>
                    <span class="badge" style="background: #2f3036; color: var(--gold);">IP: ${esc(ip)}</span>
                </div>
            </div>
            ${description ? `<div style="font-size: 11.5px; color: var(--text-secondary); margin-top: 4px;">Description: ${esc(description)}</div>` : ''}
        </div>
    `;
}

async function loadPanTopology() {
    try {
        const r = await fetch("/api/topology/pan");
        const data = await r.json();
        if (data.error) {
            document.getElementById("panTreeView").innerHTML = `<div class="empty">${esc(data.error)}</div>`;
            document.getElementById("panMeta").textContent = "Error";
            return;
        }
        
        let treeHtml = "";
        const rootNodes = data.DeviceGroups || data.Groups || (Array.isArray(data) ? data : [data]);
        rootNodes.forEach(group => {
            treeHtml += buildPanTreeHTML(group);
        });

        document.getElementById("panTreeView").innerHTML = treeHtml || `<div class="empty">No Panorama topology hierarchy nodes found.</div>`;
        document.getElementById("panMeta").textContent = "Loaded";
    } catch(e) {
        document.getElementById("panTreeView").innerHTML = `<div class="empty">Unable to render Panorama topology.</div>`;
        document.getElementById("panMeta").textContent = "Failed";
    }
}

async function loadAutomationResults() {
    try {
        const r = await fetch("/api/automation/status");
        const data = await r.json();
        document.getElementById("awsOrgDate").innerHTML = `<b>File Date:</b> ${esc(data.aws_org_mtime)}`;
        document.getElementById("awsDataDate").innerHTML = `<b>File Date:</b> ${esc(data.aws_data_mtime)}`;
        document.getElementById("panOrgDate").innerHTML = `<b>File Date:</b> ${esc(data.pan_org_mtime)}`;
        document.getElementById("panDataDate").innerHTML = `<b>File Date:</b> ${esc(data.pan_data_mtime)}`;
    } catch(e) {}
}

async function loadStats() {
    try {
        const r = await fetch("/api/stats");
        const data = await r.json();
        
        let awsHTML = `<table class="prop-table">`;
        for (const [k, v] of Object.entries(data.aws_resources || {})) {
            awsHTML += `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`;
        }
        awsHTML += `</table>`;
        document.getElementById("awsStats").innerHTML = awsHTML;

        let panosHTML = `<table class="prop-table">`;
        for (const [k, v] of Object.entries(data.panos || {})) {
            panosHTML += `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`;
        }
        panosHTML += `</table>`;
        document.getElementById("panosStats").innerHTML = panosHTML;
    } catch(e) {}
}

function clearAll() {
    document.getElementById("query").value = "";
    document.getElementById("summary").innerHTML = "";
    document.getElementById("output").innerHTML = `<div class="empty">Enter a query above to start exploring your infrastructure.</div>`;
}

document.getElementById("query").addEventListener("keydown", e => { if (e.key === "Enter") investigate(); });

async function loadInfo() {
    try {
        const r = await fetch("/api/info");
        const x = await r.json();
        document.getElementById("dataInfo").innerHTML = `<b>Database:</b> ${x.files} items | ${x.devices} devices`;
    } catch(e) {}
}

loadInfo();
</script>
</body>
</html>
"""

# ----------------------------------------------------------------------
# Flask API Routes
# ----------------------------------------------------------------------

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/api/info")
def api_info():
    return jsonify({"files": PANOS.files_count(), "devices": PANOS.devices_count()})

@app.route("/api/stats")
def api_stats():
    return jsonify(PANOS.get_stats())

@app.route("/api/automation/status")
def api_automation_status():
    return jsonify({
        "aws_org_mtime": get_file_modified_time(ORG_FILE_PATH),
        "aws_data_mtime": get_latest_dir_mtime(AWS_DATA_ROOT),
        "pan_org_mtime": get_file_modified_time(PAN_TOPOLOGY_PATH),
        "pan_data_mtime": get_latest_dir_mtime(FW_DATA_ROOT)
    })

@app.route("/api/topology/aws")
def api_topology_aws():
    if ORG_FILE_PATH.exists():
        try:
            with ORG_FILE_PATH.open("r", encoding="utf-8") as f:
                return jsonify(json.load(f))
        except Exception as e:
            return jsonify({"error": f"Failed to read AWS Org topology file: {str(e)}"}), 500
    return jsonify({"error": "AWS Organization Topology file not found."}), 404

@app.route("/api/topology/pan")
def api_topology_pan():
    if PAN_TOPOLOGY_PATH.exists():
        try:
            with PAN_TOPOLOGY_PATH.open("r", encoding="utf-8") as f:
                return jsonify(json.load(f))
        except Exception as e:
            return jsonify({"error": f"Failed to read Panorama topology file: {str(e)}"}), 500
    return jsonify({"error": "Panorama Topology file not found."}), 404

@app.route("/api/investigate")
def api_investigate():
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify({"error": "A search query is required."}), 400
    try:
        return jsonify(PANOS.investigate(query))
    except Exception as exc:
        app.logger.exception("Investigation failed")
        return jsonify({"error": str(exc)}), 500

@app.route("/api/policy-lookup")
def api_policy_lookup():
    src_query = request.args.get("src", "").strip().lower()
    dst_query = request.args.get("dst", "").strip().lower()
    port_query = request.args.get("port", "").strip().lower()

    conn = get_db(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT r.id, d.name as device, r.platform, r.category, r.filename, r.name, r.data
        FROM records r
        JOIN devices d ON r.device_id = d.id
        WHERE r.platform = 'panos' AND (r.category LIKE '%rule%' OR r.category LIKE '%policy%' OR r.category LIKE '%nat%')
    """)
    
    matched_rules = []
    rows = cursor.fetchall()
    conn.close()

    for row in rows:
        try:
            item_data = json.loads(row["data"])
        except json.JSONDecodeError:
            continue

        d = item_data.get("entry", item_data) if isinstance(item_data, dict) else item_data
        if not isinstance(d, dict):
            continue

        sources = [str(x).lower() for x in extractValues(findKeyRecursively(d, ['source']))]
        destinations = [str(x).lower() for x in extractValues(findKeyRecursively(d, ['destination', 'dest']))]
        services = [str(x).lower() for x in extractValues(findKeyRecursively(d, ['service', 'port']))]

        def matches_any(query_str, value_list):
            if not query_str:
                return True
            if "any" in value_list:
                return True
            for val in value_list:
                if query_str in val or val in query_str:
                    return True
                if sqlite_ip_contains(query_str, val) or sqlite_ip_contains(val, query_str):
                    return True
            return False

        src_match = matches_any(src_query, sources) if src_query else True
        dst_match = matches_any(dst_query, destinations) if dst_query else True
        port_match = matches_any(port_query, services) if port_query else True

        if src_query and not src_match:
            continue
        if dst_query and not dst_match:
            continue
        if port_query and not port_match:
            continue

        matched_rules.append({
            "device": row["device"],
            "type": row["category"],
            "file": row["filename"],
            "name": row["name"],
            "data": item_data
        })

    return jsonify({"rules": matched_rules})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Left-Sidebar Infrastructure Intelligence Dashboard")
    parser.add_argument("--firewall-data", default="./parsed", help="Path to parsed Firewall JSON folder")
    parser.add_argument("--aws-data", default="./aws_parsed", help="Path to parsed AWS JSON folder")
    parser.add_argument("--org-file", default="org_topology.json", help="Path to AWS Org topology JSON file")
    parser.add_argument("--pan-file", default="panorama_topology.json", help="Path to Panorama topology JSON file")
    parser.add_argument("--db", default="infra_intel.db", help="Path to SQLite database file")
    parser.add_argument("--port", type=int, default=8080, help="Web server port")
    args = parser.parse_args()

    FW_DATA_ROOT = Path(args.firewall_data).resolve()
    AWS_DATA_ROOT = Path(args.aws_data).resolve()
    ORG_FILE_PATH = Path(args.org_file).resolve()
    PAN_TOPOLOGY_PATH = Path(args.pan_file).resolve()
    DB_PATH = Path(args.db).resolve()

    print(f"[*] Ingesting data into SQLite database...")
    ingest_data(FW_DATA_ROOT, AWS_DATA_ROOT, DB_PATH)
    print(f"[*] Starting web server on http://localhost:{args.port}...")

    app.run(host="0.0.0.0", port=args.port, debug=False)
