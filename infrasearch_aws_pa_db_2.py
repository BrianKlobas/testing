#!/usr/bin/env python3
"""
Infrastructure Intelligence GUI (Left-Sidebar Unified Dashboard)
------------------------------------------------------------
Tabs:
  1. Search & Investigation
  2. AWS Organization Topology Explorer
  3. PAN-OS Panorama Topology & Mapping
  4. Automation Results & Collection Status
  5. Information & Useful Links
  6. Data Collection Metrics & Analytics

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
                return 1 if start <= target_net.network_address <= end else 0
            except ValueError:
                pass

    fw_net = extract_ip_or_cidr(val)
    if fw_net:
        return 1 if target_net.overlaps(fw_net) else 0
        
    return 0


def extract_direct_attached_sg_ids(item: dict[str, Any]) -> set[str]:
    sg_ids = set()
    groups = item.get("Groups") or item.get("SecurityGroups") or item.get("groups")
    if isinstance(groups, list):
        for g in groups:
            if isinstance(g, str) and g.startswith("sg-"):
                sg_ids.add(g)
            elif isinstance(g, dict):
                gid = g.get("GroupId") or g.get("VpcSecurityGroupId")
                if gid:
                    sg_ids.add(gid)

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
                            if gid:
                                sg_ids.add(gid)
                                
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
                name = item.get("name", "")
                if not name:
                    for key in ("object", "rule", "profile"):
                        val = item.get(key)
                        if isinstance(val, dict) and val.get("name"):
                            name = str(val["name"])
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
                for name_key in ("VpcId", "SubnetId", "NetworkInterfaceId", "LoadBalancerArn", "LoadBalancerName", "InstanceId", "DBInstanceId", "GroupId", "Id", "Name"):
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


# ----------------------------------------------------------------------
# Search Engine
# ----------------------------------------------------------------------

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

        # 1. AWS Initial Lookup
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

        # 2. Extract Attached Security Groups strictly & Harvest Subnet/VPC CIDRs
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

            if subnet_id:
                cursor.execute("""
                    SELECT data FROM records r JOIN devices d ON r.device_id = d.id
                    WHERE r.category LIKE '%subnet%' AND (r.name = ? OR r.data LIKE ?) AND d.name = ?
                """, (subnet_id, f'%"SubnetId": "{subnet_id}"%', dev_name))
                for s_row in cursor.fetchall():
                    s_data = json.loads(s_row["data"])
                    cidr = s_data.get("CidrBlock")
                    if cidr:
                        related_cidrs_to_match.add(cidr)

            if vpc_id:
                cursor.execute("""
                    SELECT data FROM records r JOIN devices d ON r.device_id = d.id
                    WHERE r.category LIKE '%vpc%' AND (r.name = ? OR r.data LIKE ?) AND d.name = ?
                """, (vpc_id, f'%"VpcId": "{vpc_id}"%', dev_name))
                for v_row in cursor.fetchall():
                    v_data = json.loads(v_row["data"])
                    cidr = v_data.get("CidrBlock")
                    if cidr:
                        related_cidrs_to_match.add(cidr)
                    for block in v_data.get("CidrBlockAssociationSet", []):
                        if isinstance(block, dict) and block.get("CidrBlock"):
                            related_cidrs_to_match.add(block["CidrBlock"])

        # 3. Resolve Payload for Attached SGs
        for dev_name, sg_id in attached_sg_ids:
            cursor.execute("""
                SELECT r.id, d.name as device, r.category, r.filename, r.name, r.data
                FROM records r
                JOIN devices d ON r.device_id = d.id
                WHERE (r.category LIKE '%security_group%' OR r.category LIKE '%sg%')
                  AND (r.name = ? OR r.data LIKE ?) AND d.name = ?
            """, (sg_id, f'%"GroupId": "{sg_id}"%', dev_name))
            
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

        # 4. PAN-OS Engine (Splitting Objects vs Rules)
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
            cat = str(row_dict["category"]).lower()
            rec = {
                "device": row_dict["device"],
                "type": row_dict["category"],
                "file": row_dict["filename"],
                "name": row_dict["name"],
                "data": item_payload
            }
            if "rule" in cat or "policy" in cat or "nat" in cat:
                output["matched_rules"].append(rec)
            else:
                output["matched_objects"].append(rec)

        if related_cidrs_to_match:
            for row in all_panos_records:
                item_data = json.loads(row["data"])
                is_match = False
                
                ip_netmask = item_data.get("ip-netmask") or item_data.get("ip_netmask") or item_data.get("ip")
                ip_range = item_data.get("ip-range") or item_data.get("ip_range")
                check_targets = [ip_netmask, ip_range]
                
                for cidr in related_cidrs_to_match:
                    for target in check_targets:
                        if target and sqlite_ip_contains(cidr, target):
                            is_match = True
                            break
                    if is_match:
                        break

                if is_match:
                    matched_panos_ids.add(row["id"])
                    obj_name = row["name"] or item_data.get("name")
                    if obj_name:
                        matched_object_names.add(str(obj_name))
                    classify_and_append_panos(row, item_data)

            if matched_object_names:
                for row in all_panos_records:
                    if row["id"] in matched_panos_ids:
                        continue
                    item_data = json.loads(row["data"])
                    data_str = json.dumps(item_data)
                    
                    for name in list(matched_object_names):
                        if f'"{name}"' in data_str:
                            matched_panos_ids.add(row["id"])
                            obj_name = row["name"] or item_data.get("name")
                            if obj_name:
                                matched_object_names.add(str(obj_name))
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
            "palo_rules": len(output["matched_rules"])
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
<title>Infrastructure Intelligence — Dashboard</title>
<style>
:root {
    --bg-main: #090d16;
    --bg-surface: #0f172a;
    --bg-card: #1e293b;
    --border-color: #334155;
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --accent: #3b82f6;
    --accent-hover: #2563eb;
    --palo-orange: #ff6b00;
    --code-bg: #090d16;
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

/* Sidebar Layout */
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
    width: 36px; height: 36px; border-radius: 8px; background: linear-gradient(135deg, var(--accent), #1d4ed8);
    display: grid; place-items: center; font-weight: bold; font-size: 15px; color: white;
}
.brand h1 { margin: 0; font-size: 15px; font-weight: 700; letter-spacing: 0.5px; }
.brand small { color: var(--text-secondary); font-size: 11px; }

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

.tab-btn:hover { color: var(--text-primary); background: rgba(255,255,255,0.04); }
.tab-btn.active { color: #ffffff; background: var(--accent); }

.sidebar-footer {
    padding: 16px;
    border-top: 1px solid var(--border-color);
    font-size: 11px;
    color: var(--text-secondary);
}

/* Main Content Wrapper */
.main-wrapper {
    margin-left: var(--sidebar-width);
    flex: 1;
    padding: 28px;
    max-width: 1400px;
}

.tab-content { display: none; }
.tab-content.active { display: block; }

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
input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.25); }
button { background: var(--accent); color: white; border: 0; font-weight: 600; cursor: pointer; transition: background 0.2s; }
button:hover { background: var(--accent-hover); }
button.secondary { background: #334155; color: var(--text-primary); }

.hint { color: var(--text-secondary); font-size: 13px; margin-top: 10px; }

.summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 14px;
    margin: 18px 0;
}

.card {
    background: var(--bg-surface);
    padding: 16px;
    border-radius: 10px;
    border: 1px solid var(--border-color);
}
.card b { display: block; font-size: 24px; color: var(--accent); font-weight: 700; }
.card.palo-card b { color: var(--palo-orange); }
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
.status-pill.success { background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid #059669; }

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
    background: #141e33;
}
.section-title h2 { font-size: 14px; margin: 0; font-weight: 600; color: var(--text-primary); }
.count { background: #1e293b; border-radius: 20px; padding: 2px 10px; font-size: 11px; font-weight: 600; color: var(--text-secondary); border: 1px solid var(--border-color); }

.item { border-bottom: 1px solid var(--border-color); padding: 18px; }
.item:last-child { border-bottom: 0; }

.item-head {
    display: flex;
    justify-content: space-between;
    gap: 10px;
    flex-wrap: wrap;
    align-items: center;
}
.item-name { font-weight: 700; font-size: 15px; color: #ffffff; }

.badge {
    display: inline-block;
    background: #334155;
    color: #cbd5e1;
    border-radius: 6px;
    padding: 3px 8px;
    margin-left: 6px;
    font-size: 11px;
    font-weight: 600;
}
.badge.blue { background: #1e3a8a; color: #93c5fd; border: 1px solid #1d4ed8; }
.badge.green { background: #064e3b; color: #6ee7b7; border: 1px solid #047857; }
.badge.aws { background: #451a03; color: #fdba74; border: 1px solid #c2410c; }
.badge.sg { background: #3b0764; color: #d8b4fe; border: 1px solid #7e22ce; }
.badge.palo { background: rgba(255, 107, 0, 0.15); color: #ff9d5c; border: 1px solid var(--palo-orange); }

.meta { color: var(--text-secondary); font-size: 12px; margin-top: 4px; }
pre { background: var(--code-bg); color: #e2e8f0; border-radius: 8px; padding: 14px; overflow: auto; max-height: 350px; font-size: 12px; font-family: monospace; border: 1px solid var(--border-color); }
details { margin-top: 10px; }
summary { color: var(--accent); cursor: pointer; font-size: 12px; font-weight: 600; }

.prop-table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; background: var(--bg-card); border-radius: 6px; overflow: hidden; border: 1px solid var(--border-color); }
.prop-table th { background: #182238; color: var(--text-secondary); text-align: left; padding: 8px 12px; font-weight: 600; border-bottom: 1px solid var(--border-color); width: 28%; }
.prop-table td { padding: 8px 12px; border-bottom: 1px solid #26334d; color: var(--text-primary); font-family: monospace; word-break: break-all; }
.prop-table tr:last-child td { border-bottom: none; }
.rule-tag { display: inline-block; background: #0f172a; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin: 2px; border: 1px solid var(--border-color); color: #94a3b8; }
.rule-tag.allow { background: #064e3b; color: #a7f3d0; border-color: #047857; }
.rule-tag.deny { background: #7f1d1d; color: #fecaca; border-color: #991b1b; }

.link-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
    margin-top: 14px;
}
.link-card {
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    padding: 16px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
}
.link-card h4 { margin: 0 0 8px 0; color: var(--text-primary); }
.link-card p { margin: 0 0 14px 0; font-size: 13px; color: var(--text-secondary); }
.link-card a {
    color: var(--accent);
    text-decoration: none;
    font-size: 13px;
    font-weight: 600;
}
.link-card a:hover { text-decoration: underline; }

.org-tree { font-family: monospace; font-size: 13px; line-height: 1.6; }
.tree-node { margin-left: 20px; padding: 4px 0; }
.tree-folder { color: #60a5fa; font-weight: bold; cursor: pointer; }
.tree-leaf { color: #cbd5e1; }

.empty { padding: 30px; text-align: center; color: var(--text-secondary); font-size: 14px; }
</style>
</head>

<body>

<!-- Left Sidebar Navigation -->
<div class="sidebar">
    <div class="brand">
        <div class="logo">II</div>
        <div>
            <h1>Infra Intel</h1>
            <small>Unified Security Dashboard</small>
        </div>
    </div>
    
    <div class="nav-menu">
        <button class="tab-btn active" onclick="switchTab('search', this)">🔍 Search & Investigate</button>
        <button class="tab-btn" onclick="switchTab('org', this)">🏢 AWS Org Topology</button>
        <button class="tab-btn" onclick="switchTab('pan', this)">🔥 PAN Panorama Topology</button>
        <button class="tab-btn" onclick="switchTab('automation', this)">⚙️ Automation Results</button>
        <button class="tab-btn" onclick="switchTab('info', this)">ℹ️ Information & Links</button>
        <button class="tab-btn" onclick="switchTab('stats', this)">📊 Collection Analytics</button>
    </div>

    <div class="sidebar-footer">
        <div id="dataInfo">Loading database status...</div>
    </div>
</div>

<!-- Main Area -->
<div class="main-wrapper">

    <!-- TAB 1: Search -->
    <div id="tab-search" class="tab-content active">
        <div class="search-panel">
            <div class="search-row">
                <input id="query" placeholder="Search IP, CIDR, Instance ID (i-xxxx), ENI ID, Security Group, Palo Rule..." autocomplete="off">
                <button onclick="investigate()">Investigate</button>
                <button class="secondary" onclick="clearAll()">Clear</button>
            </div>
            <div class="hint">
                💡 Strict attached Security Group scoping and host/subnet/VPC network matching enabled.
            </div>
        </div>

        <div id="summary"></div>
        <div id="output">
            <div class="empty">Enter a query above to start exploring your infrastructure.</div>
        </div>
    </div>

    <!-- TAB 2: AWS Org Topology -->
    <div id="tab-org" class="tab-content">
        <div class="section">
            <div class="section-title">
                <h2>AWS Organization Hierarchy</h2>
                <span id="orgMeta" class="count">Ready</span>
            </div>
            <div style="padding: 20px;" id="orgTreeView" class="org-tree">
                <div class="empty">Loading organization topology...</div>
            </div>
        </div>
    </div>

    <!-- TAB 3: Panorama Topology -->
    <div id="tab-pan" class="tab-content">
        <div class="section">
            <div class="section-title">
                <h2>Panorama Templates & Device Groups Hierarchy</h2>
                <span id="panMeta" class="count">Ready</span>
            </div>
            <div style="padding: 20px;" id="panTreeView" class="org-tree">
                <div class="empty">Loading panorama topology...</div>
            </div>
        </div>
    </div>

    <!-- TAB 4: Automation Results -->
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

    <!-- TAB 5: Useful Links & Info -->
    <div id="tab-info" class="tab-content">
        <div class="section">
            <div class="section-title">
                <h2>Useful Links & Infrastructure Documentation</h2>
            </div>
            <div style="padding: 20px;">
                <p style="margin-top:0; color: var(--text-secondary); font-size: 14px;">Quick access to internal documentation, dashboards, and security portals.</p>
                <div class="link-grid">
                    <div class="link-card">
                        <div>
                            <h4>AWS Management Console</h4>
                            <p>Direct SSO portal access for cloud tenant administration and EC2 instance management.</p>
                        </div>
                        <a href="https://aws.amazon.com/console/" target="_blank">Open Console &rarr;</a>
                    </div>
                    <div class="link-card">
                        <div>
                            <h4>Palo Alto Panorama Portal</h4>
                            <p>Centralized firewall policy manager, security profile configuration, and network rule inspection.</p>
                        </div>
                        <a href="#" onclick="alert('Configure internal Panorama URL in script.'); return false;">Open Panorama &rarr;</a>
                    </div>
                    <div class="link-card">
                        <div>
                            <h4>Internal IPAM Portal</h4>
                            <p>Centralized IP Address Management database and subnet allocation records.</p>
                        </div>
                        <a href="#" onclick="alert('Configure internal IPAM URL in script.'); return false;">Open IPAM &rarr;</a>
                    </div>
                    <div class="link-card">
                        <div>
                            <h4>Security Runbooks & Docs</h4>
                            <p>Guides for security group management, firewall rule requests, and Incident Response procedures.</p>
                        </div>
                        <a href="#" onclick="alert('Configure documentation link in script.'); return false;">View Documentation &rarr;</a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- TAB 6: Stats -->
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

</div>

<script>
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
        </div>
    `;
}

function section(title, count, body) {
    return `<div class="section"><div class="section-title"><h2>${title}</h2><span class="count">${count}</span></div>${body}</div>`;
}

function renderPillList(arr, defaultLabel = 'any') {
    if (!arr || (Array.isArray(arr) && arr.length === 0)) return `<span class="rule-tag">${defaultLabel}</span>`;
    const items = Array.isArray(arr) ? arr : [arr];
    return items.map(i => `<span class="rule-tag">${esc(typeof i === 'object' ? (i.name || JSON.stringify(i)) : i)}</span>`).join(' ');
}

function renderPaloAltoDetails(x) {
    const d = x.data || {};
    const cat = (x.type || "").toLowerCase();
    let html = "";

    if (cat.includes("security_rules") || cat.includes("security") || cat.includes("nat")) {
        const action = d.action || "allow";
        const actionBadge = action === "allow" 
            ? `<span class="rule-tag allow">ALLOW</span>` 
            : `<span class="rule-tag deny">${esc(action.toUpperCase())}</span>`;

        html += `<table class="prop-table">`;
        html += `<tr><th>Action</th><td>${actionBadge}</td></tr>`;
        html += `<tr><th>From Zone(s)</th><td>${renderPillList(d.from || d.from_zone, 'any')}</td></tr>`;
        html += `<tr><th>To Zone(s)</th><td>${renderPillList(d.to || d.to_zone, 'any')}</td></tr>`;
        html += `<tr><th>Source Address</th><td>${renderPillList(d.source, 'any')}</td></tr>`;
        html += `<tr><th>Destination Address</th><td>${renderPillList(d.destination, 'any')}</td></tr>`;
        html += `<tr><th>Application</th><td>${renderPillList(d.application, 'any')}</td></tr>`;
        html += `<tr><th>Service / Port</th><td>${renderPillList(d.service, 'any')}</td></tr>`;
        if (d.description) html += `<tr><th>Description</th><td>${esc(d.description)}</td></tr>`;
        html += `</table>`;
        return html;
    }

    if (cat.includes("address")) {
        html += `<table class="prop-table">`;
        if (d["ip-netmask"]) html += `<tr><th>IP / Subnet</th><td><code>${esc(d["ip-netmask"])}</code></td></tr>`;
        if (d["ip-range"]) html += `<tr><th>IP Range</th><td><code>${esc(d["ip-range"])}</code></td></tr>`;
        if (d.fqdn) html += `<tr><th>FQDN</th><td><code>${esc(d.fqdn)}</code></td></tr>`;
        if (d.members || d.static) html += `<tr><th>Group Members</th><td>${renderPillList(d.members || d.static)}</td></tr>`;
        if (d.description) html += `<tr><th>Description</th><td>${esc(d.description)}</td></tr>`;
        html += `</table>`;
        return html;
    }

    return renderProperties(d);
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
    let extraDetails = (badgeClass === "palo" || badgeClass === "green") 
        ? renderPaloAltoDetails(x) 
        : renderProperties(x.data);

    return `
        <div class="item">
            <div class="item-head">
                <div class="item-name">${esc(x.name)}</div>
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
    if (!html) html = `<div class="empty">No matching records found.</div>`;
    document.getElementById("output").innerHTML = html;
}

async function investigate() {
    const q = document.getElementById("query").value.trim();
    if (!q) return;
    document.getElementById("output").innerHTML = `<div class="empty">Searching indexed database for <b>${esc(q)}</b>...</div>`;
    try {
        const res = await fetch("/api/investigate?q=" + encodeURIComponent(q));
        const data = await res.json();
        render(data);
    } catch (err) {
        document.getElementById("output").innerHTML = `<div class="empty" style="color:#f87171;">Error executing search query.</div>`;
    }
}

function buildTreeHTML(node) {
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
            html += `<div class="tree-leaf">📄 ${esc(accName)} <span style="color:var(--text-secondary);">(${esc(accId)})</span></div>`;
        });
        html += `</div>`;
    }

    if (children.length > 0) {
        html += `<div style="margin-left: 10px;">`;
        children.forEach(child => html += buildTreeHTML(child));
        html += `</div>`;
    }

    html += `</div>`;
    return html;
}

async function loadOrgTopology() {
    try {
        const r = await fetch("/api/topology/aws");
        const data = await r.json();
        if (data.error) {
            document.getElementById("orgTreeView").innerHTML = `<div class="empty">${esc(data.error)}</div>`;
            return;
        }
        document.getElementById("orgTreeView").innerHTML = buildTreeHTML(data.Hierarchy || data);
        document.getElementById("orgMeta").textContent = "Loaded";
    } catch(e) {
        document.getElementById("orgTreeView").innerHTML = `<div class="empty">Unable to render topology tree.</div>`;
    }
}

async function loadPanTopology() {
    try {
        const r = await fetch("/api/topology/pan");
        const data = await r.json();
        if (data.error) {
            document.getElementById("panTreeView").innerHTML = `<div class="empty">${esc(data.error)}</div>`;
            return;
        }
        document.getElementById("panTreeView").innerHTML = `<pre>${jsonStr(data)}</pre>`;
        document.getElementById("panMeta").textContent = "Loaded";
    } catch(e) {
        document.getElementById("panTreeView").innerHTML = `<div class="empty">Unable to render Panorama topology.</div>`;
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
