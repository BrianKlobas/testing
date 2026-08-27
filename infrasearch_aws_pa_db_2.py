#!/usr/bin/env python3
"""
Infrastructure Intelligence GUI (Multi-Tab Unified Dashboard)
------------------------------------------------------------
Tabs:
  1. Search & Investigation (Full Cascading Resource & Security Group Correlation)
  2. AWS Organization Topology Explorer
  3. PAN-OS Panorama Topology & Mapping
  4. Data Collection Metrics & Analytics

Run:
    python infra_intel.py --firewall-data ./parsed --aws-data ./aws_parsed --org-file org_topology.json --pan-file panorama_topology.json --db infra_intel.db
Then open:
    http://localhost:8080
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sqlite3
import re
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
# Helper Functions for SG Extraction and IP Matching
# ----------------------------------------------------------------------

def extract_sg_ids(data: Any) -> set[str]:
    """Recursively extracts all Security Group IDs from any nested dictionary/list structure."""
    sg_ids = set()
    if isinstance(data, dict):
        for k, v in data.items():
            if k in ("GroupId", "VpcSecurityGroupId") and isinstance(v, str) and v.startswith("sg-"):
                sg_ids.add(v)
            elif k in ("SecurityGroups", "Groups", "VpcSecurityGroups") and isinstance(v, list):
                for item in v:
                    if isinstance(item, str) and item.startswith("sg-"):
                        sg_ids.add(item)
                    elif isinstance(item, dict):
                        gid = item.get("GroupId") or item.get("VpcSecurityGroupId")
                        if gid and isinstance(gid, str) and gid.startswith("sg-"):
                            sg_ids.add(gid)
            else:
                sg_ids.update(extract_sg_ids(v))
    elif isinstance(data, list):
        for item in data:
            sg_ids.update(extract_sg_ids(item))
    return sg_ids


def sqlite_ip_contains(ip_str: str, cidr_or_ip_str: str) -> int:
    """Checks if a target IP falls inside a CIDR block, IP range, or string definition."""
    if not ip_str or not cidr_or_ip_str:
        return 0
    try:
        target_ip = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return 0

    val = str(cidr_or_ip_str).strip()
    
    # Handle Range: 10.0.0.1-10.0.0.250
    if "-" in val and "/" not in val:
        parts = val.split("-")
        if len(parts) == 2:
            try:
                start = ipaddress.ip_address(parts[0].strip())
                end = ipaddress.ip_address(parts[1].strip())
                return 1 if start <= target_ip <= end else 0
            except ValueError:
                pass

    # Handle CIDR / Single IP: 10.0.0.0/24 or 10.0.0.1
    try:
        net = ipaddress.ip_network(val, strict=False)
        return 1 if target_ip in net else 0
    except ValueError:
        return 0


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

        aws_accounts_count = 0
        if ORG_FILE_PATH.exists():
            try:
                with ORG_FILE_PATH.open("r", encoding="utf-8") as f:
                    org_data = json.load(f)
                    def count_accounts(node):
                        cnt = len(node.get("Accounts", []) or node.get("AccountList", []))
                        for ou in (node.get("OUs", []) or node.get("Children", []) or node.get("OrganizationalUnits", []) or node.get("SubOUs", [])):
                            cnt += count_accounts(ou)
                        return cnt
                    aws_accounts_count = count_accounts(org_data.get("Hierarchy", {}) or org_data)
            except Exception:
                aws_accounts_count = 0

        if aws_accounts_count == 0:
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

    def parse_network(self, value):
        value = str(value).strip()
        try:
            if "/" in value:
                return ipaddress.ip_network(value, strict=False)
            return ipaddress.ip_network(value + "/32", strict=False)
        except ValueError:
            return None

    def investigate(self, query: str, limit: int = 500) -> dict[str, Any]:
        query = query.strip()
        query_network = self.parse_network(query)
        
        output = {
            "query": query,
            "query_type": "ip_or_cidr" if query_network else "text",
            "matched_addresses": [],
            "aws_matches": [],
            "attached_security_groups": [],
            "raw_matches": [],
            "summary": {}
        }

        conn = get_db(self.db_file)
        cursor = conn.cursor()

        matched_aws_record_ids = set()
        matched_sg_ids = set()  # Set of (device_name, sg_id)
        pending_aws_lookups = []

        # 1. Primary AWS Lookup
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
                    pending_aws_lookups.append((row, []))
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
                        pending_aws_lookups.append((row, []))

        # 2. Extract Security Groups using Recursive AST Inspection
        processed_count = 0
        while processed_count < len(pending_aws_lookups):
            row, hits = pending_aws_lookups[processed_count]
            processed_count += 1
            item = json.loads(row["data"])

            output["aws_matches"].append({
                "device": row["device"],
                "type": row["category"],
                "file": row["filename"],
                "name": row["name"],
                "data": item,
                "matches": hits
            })

            dev_name = row["device"]
            found_sgs = extract_sg_ids(item)
            for sg in found_sgs:
                matched_sg_ids.add((dev_name, sg))

            # Cascade: EC2 Instance -> Network Interfaces
            if row["category"] == "ec2_instances":
                inst_id = item.get("InstanceId")
                if inst_id:
                    cursor.execute("""
                        SELECT r.id, d.name as device, r.category, r.filename, r.name, r.data
                        FROM records r JOIN devices d ON r.device_id = d.id
                        WHERE r.category LIKE '%eni%' AND r.data LIKE ? AND d.name = ?
                    """, (f"%{inst_id}%", dev_name))
                    for eni_row in cursor.fetchall():
                        if eni_row["id"] not in matched_aws_record_ids:
                            matched_aws_record_ids.add(eni_row["id"])
                            pending_aws_lookups.append((eni_row, []))

        # 3. Pull Full Record Payloads for Discovered Security Groups
        for dev_name, sg_id in matched_sg_ids:
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

        # 4. Palo Alto Correlation Engine (Addresses, Address Groups & Security Rules)
        matched_panos_ids = set()
        matched_object_names = set()

        cursor.execute("""
            SELECT r.id, d.name as device, r.platform, r.category, r.filename, r.name, r.data
            FROM records r
            JOIN devices d ON r.device_id = d.id
            WHERE r.platform = 'panos'
        """)
        
        all_panos_records = cursor.fetchall()

        if query_network:
            target_ip_str = str(query_network.network_address)

            # Phase A: Match direct IP / CIDR / Subnets inside Address objects
            for row in all_panos_records:
                item_data = json.loads(row["data"])
                is_match = False

                # Convert data to string for broad text checking if needed
                data_str = json.dumps(item_data)

                # Check explicit PAN-OS object structures
                ip_netmask = item_data.get("ip-netmask") or item_data.get("ip_netmask") or item_data.get("ip")
                ip_range = item_data.get("ip-range") or item_data.get("ip_range")
                
                if ip_netmask and sqlite_ip_contains(target_ip_str, ip_netmask):
                    is_match = True
                elif ip_range and sqlite_ip_contains(target_ip_str, ip_range):
                    is_match = True
                elif target_ip_str in data_str:
                    is_match = True

                if is_match:
                    matched_panos_ids.add(row["id"])
                    obj_name = row["name"] or item_data.get("name")
                    if obj_name:
                        matched_object_names.add(str(obj_name))
                    output["matched_addresses"].append({
                        "device": row["device"],
                        "type": row["category"],
                        "file": row["filename"],
                        "name": row["name"],
                        "data": item_data
                    })

            # Phase B: Cascading correlation for Address Groups and Rules referencing matched object names
            if matched_object_names:
                for row in all_panos_records:
                    if row["id"] in matched_panos_ids:
                        continue
                    item_data = json.loads(row["data"])
                    data_str = json.dumps(item_data)
                    
                    for name in list(matched_object_names):
                        if f'"{name}"' in data_str or name in item_data.get("static", []) or name in item_data.get("members", []):
                            matched_panos_ids.add(row["id"])
                            obj_name = row["name"] or item_data.get("name")
                            if obj_name:
                                matched_object_names.add(str(obj_name))
                            output["matched_addresses"].append({
                                "device": row["device"],
                                "type": row["category"],
                                "file": row["filename"],
                                "name": row["name"],
                                "data": item_data
                            })
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
                        output["matched_addresses"].append({
                            "device": row["device"],
                            "type": row["category"],
                            "file": row["filename"],
                            "name": row["name"],
                            "data": json.loads(row["data"])
                        })

        output["summary"] = {
            "aws_resources": len(output["aws_matches"]),
            "attached_sgs": len(output["attached_security_groups"]),
            "firewall_objects": len(output["matched_addresses"]),
            "raw": len(output["raw_matches"])
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
}

* { box-sizing: border-box; }

body {
    margin: 0;
    background: var(--bg-main);
    color: var(--text-primary);
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}

.topbar {
    background: var(--bg-surface);
    color: white;
    padding: 14px 28px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid var(--border-color);
}

.brand { display: flex; gap: 12px; align-items: center; }
.logo {
    width: 36px; height: 36px; border-radius: 8px; background: linear-gradient(135deg, var(--accent), #1d4ed8);
    display: grid; place-items: center; font-weight: bold; font-size: 15px; color: white;
}
.brand h1 { margin: 0; font-size: 17px; font-weight: 600; letter-spacing: 0.5px; }
.brand small { color: var(--text-secondary); font-size: 11px; }

.tabs-bar {
    background: #0c1322;
    padding: 0 28px;
    display: flex;
    gap: 6px;
    overflow-x: auto;
    border-bottom: 1px solid var(--border-color);
}

.tab-btn {
    background: transparent;
    color: var(--text-secondary);
    border: none;
    padding: 12px 20px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    border-bottom: 3px solid transparent;
    transition: all 0.2s;
    white-space: nowrap;
}

.tab-btn:hover { color: var(--text-primary); background: rgba(255,255,255,0.02); }
.tab-btn.active { color: #ffffff; border-bottom-color: var(--accent); background: var(--bg-surface); }

.container { max-width: 1600px; margin: 24px auto; padding: 0 24px; }
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
.card span { color: var(--text-secondary); font-size: 12px; margin-top: 4px; display: block; text-transform: uppercase; }

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

.org-tree { font-family: monospace; font-size: 13px; line-height: 1.6; }
.tree-node { margin-left: 20px; padding: 4px 0; }
.tree-folder { color: #60a5fa; font-weight: bold; cursor: pointer; }
.tree-leaf { color: #cbd5e1; }

.empty { padding: 30px; text-align: center; color: var(--text-secondary); font-size: 14px; }
</style>
</head>

<body>
<div class="topbar">
    <div class="brand">
        <div class="logo">II</div>
        <div>
            <h1>Infrastructure Intelligence</h1>
            <small>Unified Security & Topology Dashboard</small>
        </div>
    </div>
    <div id="dataInfo" style="font-size:12px;color:var(--text-secondary);"></div>
</div>

<div class="tabs-bar">
    <button class="tab-btn active" onclick="switchTab('search', this)">🔍 Search & Investigation</button>
    <button class="tab-btn" onclick="switchTab('org', this)">🏢 AWS Organization Topology</button>
    <button class="tab-btn" onclick="switchTab('pan', this)">🔥 PAN-OS Panorama Topology</button>
    <button class="tab-btn" onclick="switchTab('stats', this)">📊 Collection Analytics</button>
</div>

<div class="container">
    <div id="tab-search" class="tab-content active">
        <div class="search-panel">
            <div class="search-row">
                <input id="query" placeholder="Search IP, CIDR, Instance ID (i-xxxx), ENI ID, Security Group, Palo Rule..." autocomplete="off">
                <button onclick="investigate()">Investigate</button>
                <button class="secondary" onclick="clearAll()">Clear</button>
            </div>
            <div class="hint">
                💡 Recursive security group extraction and Palo Alto subnet math enabled.
            </div>
        </div>

        <div id="summary"></div>
        <div id="output">
            <div class="empty">Enter a query above to start exploring your infrastructure.</div>
        </div>
    </div>

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
            <div class="card palo-card"><b>${s.firewall_objects}</b><span>Palo Alto Objects / Rules</span></div>
            <div class="card"><b>SQLite</b><span>Engine: Recursive AST Search</span></div>
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

    if (cat.includes("security_rules") || cat.includes("security")) {
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
    if (data.matched_addresses.length) html += section("Palo Alto Objects & Rules", data.matched_addresses.length, data.matched_addresses.map(x => itemHTML(x, "palo")).join(""));
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
        document.getElementById("dataInfo").textContent = x.files + " indexed items | " + x.devices + " devices";
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
    parser = argparse.ArgumentParser(description="Multi-Tab Unified Infrastructure Intelligence Dashboard")
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
