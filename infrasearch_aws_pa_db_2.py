#!/usr/bin/env python3
"""
Infrastructure Intelligence GUI (Multi-Tab Unified Dashboard)
------------------------------------------------------------
Tabs:
  1. Search & Investigation (Full Cascading Resource & Security Group Correlation)
  2. AWS Organization Topology Explorer (Expandable Tree with Account IDs & Names)
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
# Database Initialization & Indexing Engine
# ----------------------------------------------------------------------

def get_db(db_file: Path | None = None):
    if db_file is None:
        db_file = DB_PATH
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
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
            platform TEXT,       -- 'panos' or 'aws'
            category TEXT,       -- 'addresses', 'vpcs', 'ec2_instances', 'security_groups', 'enis', etc.
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

    # 1. Ingest PAN-OS Data
    if fw_root.exists():
        rule_types = {
            "security_rules", "nat_rules", "pbf_rules", "qos_rules",
            "decryption_rules", "application_override_rules", "authentication_rules"
        }
        object_types = {
            "addresses", "address_groups", "services", "service_groups",
            "tags", "zones", "interfaces", "virtual_routers", "ipsec_tunnels"
        }

        for path in sorted(fw_root.rglob("*.json")):
            if not path.is_file():
                continue
            rel = path.relative_to(fw_root)
            device = rel.parts[0] if len(rel.parts) > 1 else "(root)"
            file_type = path.stem

            if file_type not in rule_types and file_type not in object_types:
                continue

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
                name = ""
                if item.get("name"):
                    name = str(item["name"])
                else:
                    for key in ("object", "rule", "profile"):
                        val = item.get(key)
                        if isinstance(val, dict) and val.get("name"):
                            name = str(val["name"])
                            break

                cursor.execute(
                    "INSERT INTO records (device_id, platform, category, filename, name, data) VALUES (?, ?, ?, ?, ?, ?)",
                    (dev_id, "panos", file_type, path.name, name, json.dumps(item))
                )

    # 2. Ingest AWS Data
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
# Precision Search & Analytics Engine
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

    def extract_networks_from_text(self, text):
        pattern = r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])"
        for match in re.findall(pattern, str(text)):
            net = self.parse_network(match)
            if net:
                yield match, net

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
        matched_sg_ids = set()
        discovered_ips = set()
        if query_network:
            discovered_ips.add(query_network.compressed)
        else:
            potential_ip = self.parse_network(query)
            if potential_ip:
                discovered_ips.add(potential_ip.compressed)

        pending_aws_lookups = []

        # 1. Initial Match Search (by Network overlap or Text/ID search)
        if query_network:
            cursor.execute("""
                SELECT r.id, d.name as device, r.platform, r.category, r.filename, r.name, r.data
                FROM records r
                JOIN devices d ON r.device_id = d.id
                WHERE r.platform = 'aws'
            """)
            for row in cursor.fetchall():
                item = json.loads(row["data"])
                hits = []
                def scan_dict(d, path=""):
                    for k, v in d.items():
                        p = f"{path}.{k}" if path else str(k)
                        if isinstance(v, dict):
                            scan_dict(v, p)
                        elif isinstance(v, list):
                            for idx, elem in enumerate(v):
                                if isinstance(elem, dict):
                                    scan_dict(elem, f"{p}[{idx}]")
                                else:
                                    for orig, net in self.extract_networks_from_text(elem):
                                        if query_network.overlaps(net):
                                            hits.append({"path": f"{p}[{idx}]", "value": orig})
                        else:
                            for orig, net in self.extract_networks_from_text(v):
                                if query_network.overlaps(net):
                                    hits.append({"path": p, "value": orig})
                scan_dict(item)

                if hits:
                    if row["id"] not in matched_aws_record_ids:
                        matched_aws_record_ids.add(row["id"])
                        pending_aws_lookups.append((row, hits))
        else:
            cursor.execute("""
                SELECT r.id, d.name as device, r.platform, r.category, r.filename, r.name, r.data
                FROM records r
                JOIN devices d ON r.device_id = d.id
                WHERE r.platform = 'aws' AND (r.name LIKE ? OR r.data LIKE ?)
            """, (f"%{query}%", f"%{query}%"))
            for row in cursor.fetchall():
                if row["id"] not in matched_aws_record_ids:
                    matched_aws_record_ids.add(row["id"])
                    pending_aws_lookups.append((row, []))

        # 2. Cascading Relationship Discovery & IP Extraction
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

            cat = row["category"]
            dev_name = row["device"]

            # Dynamically extract IPs from discovered AWS records
            for _, net in self.extract_networks_from_text(row["data"]):
                discovered_ips.add(net.compressed)

            if cat == "ec2_instances":
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

                for group in item.get("SecurityGroups", []):
                    sg_id = group.get("GroupId")
                    if sg_id:
                        matched_sg_ids.add((dev_name, sg_id))

            elif "eni" in cat.lower():
                for group in item.get("Groups", []):
                    sg_id = group.get("GroupId")
                    if sg_id:
                        matched_sg_ids.add((dev_name, sg_id))
                
                attachment = item.get("Attachment", {})
                att_inst_id = attachment.get("InstanceId")
                if att_inst_id:
                    cursor.execute("""
                        SELECT r.id, d.name as device, r.category, r.filename, r.name, r.data
                        FROM records r JOIN devices d ON r.device_id = d.id
                        WHERE r.category = 'ec2_instances' AND r.name = ? AND d.name = ?
                    """, (att_inst_id, dev_name))
                    for inst_row in cursor.fetchall():
                        if inst_row["id"] not in matched_aws_record_ids:
                            matched_aws_record_ids.add(inst_row["id"])
                            pending_aws_lookups.append((inst_row, []))

            elif cat == "rds_instances":
                for group in item.get("VpcSecurityGroups", []):
                    sg_id = group.get("VpcSecurityGroupId")
                    if sg_id:
                        matched_sg_ids.add((dev_name, sg_id))

        # 3. Fetch All Associated Security Groups strictly by GroupId and Account scope
        for dev_name, sg_id in matched_sg_ids:
            cursor.execute("""
                SELECT r.id, d.name as device, r.category, r.filename, r.name, r.data
                FROM records r
                JOIN devices d ON r.device_id = d.id
                WHERE (r.category LIKE '%security_group%' OR r.category LIKE '%sg%')
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

        # 4. Search PAN-OS Firewall Objects & Rules using Query + Discovered IPs
        pan_queries = set(discovered_ips)
        if query:
            pan_queries.add(query)

        matched_panos_ids = set()
        for pan_q in pan_queries:
            p_net = self.parse_network(pan_q)
            p_term = p_net.compressed if p_net else pan_q

            cursor.execute("""
                SELECT r.id, d.name as device, r.platform, r.category, r.filename, r.name, r.data
                FROM records r
                JOIN devices d ON r.device_id = d.id
                WHERE r.platform = 'panos' AND (r.name LIKE ? OR r.data LIKE ?)
            """, (f"%{p_term}%", f"%{p_term}%"))
            
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
# Modern Multi-Tab HTML / CSS Template
# ----------------------------------------------------------------------

HTML = r"""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Infrastructure Intelligence — Unified Dashboard</title>
<style>
:root {
    --bg-main: #0f172a;
    --bg-surface: #1e293b;
    --bg-card: #ffffff;
    --border-color: #e2e8f0;
    --text-primary: #0f172a;
    --text-secondary: #64748b;
    --accent: #3b82f6;
    --accent-hover: #2563eb;
}

* { box-sizing: border-box; }

body {
    margin: 0;
    background: #f8fafc;
    color: var(--text-primary);
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}

.topbar {
    background: var(--bg-main);
    color: white;
    padding: 14px 28px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
}

.brand { display: flex; gap: 12px; align-items: center; }
.logo {
    width: 36px; height: 36px; border-radius: 8px; background: var(--accent);
    display: grid; place-items: center; font-weight: bold; font-size: 15px;
}
.brand h1 { margin: 0; font-size: 17px; font-weight: 600; }
.brand small { color: #94a3b8; font-size: 11px; }

.tabs-bar {
    background: #1e293b;
    padding: 0 28px;
    display: flex;
    gap: 6px;
    overflow-x: auto;
}

.tab-btn {
    background: transparent;
    color: #94a3b8;
    border: none;
    padding: 12px 20px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    border-bottom: 3px solid transparent;
    transition: all 0.2s;
    white-space: nowrap;
}

.tab-btn:hover { color: #f8fafc; }
.tab-btn.active { color: #ffffff; border-bottom-color: var(--accent); background: rgba(255,255,255,0.03); }

.container { max-width: 1600px; margin: 24px auto; padding: 0 24px; }
.tab-content { display: none; }
.tab-content.active { display: block; }

.search-panel {
    background: var(--bg-card);
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    border: 1px solid var(--border-color);
}

.search-row { display: flex; gap: 10px; flex-wrap: wrap; }
.search-row input { flex: 1; min-width: 320px; }

input, button {
    height: 44px;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    padding: 0 14px;
    font-size: 14px;
    outline: none;
}
input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15); }
button { background: var(--accent); color: white; border: 0; font-weight: 600; cursor: pointer; }
button:hover { background: var(--accent-hover); }
button.secondary { background: #64748b; }

.hint { color: var(--text-secondary); font-size: 13px; margin-top: 8px; }

.summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 14px;
    margin: 18px 0;
}

.card {
    background: var(--bg-card);
    padding: 16px;
    border-radius: 10px;
    border: 1px solid var(--border-color);
}
.card b { display: block; font-size: 22px; color: var(--accent); }
.card span { color: var(--text-secondary); font-size: 12px; margin-top: 4px; display: block; }

.section {
    background: var(--bg-card);
    border-radius: 10px;
    margin-bottom: 16px;
    border: 1px solid var(--border-color);
    overflow: hidden;
}

.section-title {
    padding: 14px 18px;
    border-bottom: 1px solid var(--border-color);
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #f8fafc;
}
.section-title h2 { font-size: 14px; margin: 0; font-weight: 600; }
.count { background: #e2e8f0; border-radius: 20px; padding: 2px 8px; font-size: 11px; font-weight: 600; color: #334155; }

.item { border-bottom: 1px solid #f1f5f9; padding: 16px 18px; }
.item:last-child { border-bottom: 0; }

.item-head {
    display: flex;
    justify-content: space-between;
    gap: 10px;
    flex-wrap: wrap;
    align-items: center;
}
.item-name { font-weight: 700; font-size: 14px; }

.badge {
    display: inline-block;
    background: #f1f5f9;
    color: #475569;
    border-radius: 6px;
    padding: 3px 8px;
    margin-left: 6px;
    font-size: 11px;
    font-weight: 500;
}
.badge.blue { background: #eff6ff; color: #1d4ed8; }
.badge.green { background: #f0fdf4; color: #15803d; }
.badge.aws { background: #fff7ed; color: #c2410c; border: 1px solid #ff9900; }
.badge.sg { background: #faf5ff; color: #7e22ce; border: 1px solid #d8b4fe; }

.meta { color: var(--text-secondary); font-size: 12px; margin-top: 4px; }
pre { background: #0f172a; color: #e2e8f0; border-radius: 6px; padding: 14px; overflow: auto; max-height: 350px; font-size: 12px; font-family: monospace; }
details { margin-top: 10px; }
summary { color: var(--accent); cursor: pointer; font-size: 12px; font-weight: 600; }

/* Tree & Properties Views */
.org-tree details { margin: 6px 0; background: #ffffff; border: 1px solid var(--border-color); border-radius: 6px; padding: 8px 12px; }
.org-tree summary { font-weight: 600; color: #1e293b; font-size: 14px; outline: none; }
.org-accounts { margin-top: 8px; padding-left: 14px; display: flex; flex-wrap: wrap; gap: 8px; }
.account-badge { background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 6px; padding: 4px 10px; font-size: 12px; color: #334155; }

.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 16px; }
.stat-card { background: white; border: 1px solid var(--border-color); border-radius: 10px; padding: 20px; }
.stat-card h3 { margin-top: 0; font-size: 16px; border-bottom: 1px solid #f1f5f9; padding-bottom: 10px; }
.stat-row { display: flex; justify-content: space-between; padding: 6px 0; font-size: 13px; border-bottom: 1px dashed #f8fafc; }

/* Clean Property Tables */
.prop-table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; background: #ffffff; border-radius: 6px; overflow: hidden; border: 1px solid #e2e8f0; }
.prop-table th { background: #f8fafc; color: #475569; text-align: left; padding: 8px 12px; font-weight: 600; border-bottom: 1px solid #e2e8f0; width: 30%; }
.prop-table td { padding: 8px 12px; border-bottom: 1px solid #f1f5f9; color: #1e293b; font-family: monospace; word-break: break-all; }
.prop-table tr:last-child td { border-bottom: none; }
.sub-table-header { font-weight: 600; font-size: 12px; color: #64748b; margin: 12px 0 4px 0; text-transform: uppercase; letter-spacing: 0.5px; }
.rule-tag { display: inline-block; background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 12px; margin: 2px; border: 1px solid #cbd5e1; }
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
    <div id="dataInfo" style="font-size:12px;color:#94a3b8;"></div>
</div>

<div class="tabs-bar">
    <button class="tab-btn active" onclick="switchTab('search', this)">🔍 Search & Investigation</button>
    <button class="tab-btn" onclick="switchTab('org', this)">🏢 AWS Organization Topology</button>
    <button class="tab-btn" onclick="switchTab('pan', this)">🔥 PAN-OS Panorama Topology</button>
    <button class="tab-btn" onclick="switchTab('stats', this)">📊 Collection Analytics</button>
</div>

<div class="container">
    <!-- TAB 1: SEARCH -->
    <div id="tab-search" class="tab-content active">
        <div class="search-panel">
            <div class="search-row">
                <input id="query" placeholder="Search IP, CIDR, Instance ID (i-xxxx), ENI ID, Security Group..." autocomplete="off">
                <button onclick="investigate()">Investigate</button>
                <button class="secondary" onclick="clearAll()">Clear</button>
            </div>
            <div class="hint">
                💡 <b>Deep Cascade:</b> Searching an Instance ID automatically surfaces its EC2 details, attached ENIs, bound Security Groups, and correlates its IPs to Palo Alto rules.
            </div>
        </div>

        <div id="summary"></div>
        <div id="output">
            <div class="empty">Enter a query above to start exploring your infrastructure.</div>
        </div>
    </div>

    <!-- TAB 2: AWS ORG TOPOLOGY -->
    <div id="tab-org" class="tab-content">
        <div class="section">
            <div class="section-title">
                <h2>AWS Organization Expandable Hierarchy</h2>
                <span id="orgMeta" class="count">Loading...</span>
            </div>
            <div style="padding: 20px;" id="orgTreeView" class="org-tree">
                <div class="empty">Loading organization topology...</div>
            </div>
        </div>
    </div>

    <!-- TAB 3: PANORAMA TOPOLOGY -->
    <div id="tab-pan" class="tab-content">
        <div class="section">
            <div class="section-title">
                <h2>Panorama Templates & Device Groups Hierarchy</h2>
                <span id="panMeta" class="count">Loading...</span>
            </div>
            <div style="padding: 20px;" id="panTreeView" class="org-tree">
                <div class="empty">Loading Panorama topology...</div>
            </div>
        </div>
    </div>

    <!-- TAB 4: ANALYTICS -->
    <div id="tab-stats" class="tab-content">
        <div class="stats-grid">
            <div class="stat-card">
                <h3>☁️ AWS Cloud Inventory</h3>
                <div id="awsStats"><div class="empty">Loading stats...</div></div>
            </div>
            <div class="stat-card">
                <h3>🛡️ PAN-OS Firewall Inventory</h3>
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
            <div class="card"><b>${s.firewall_objects}</b><span>Firewall Objects</span></div>
            <div class="card"><b>SQLite</b><span>Engine: FTS5</span></div>
        </div>
    `;
}

function section(title, count, body) {
    return `<div class="section"><div class="section-title"><h2>${title}</h2><span class="count">${count}</span></div>${body}</div>`;
}

function renderProperties(obj) {
    if (!obj || typeof obj !== 'object') return '';
    let html = `<table class="prop-table">`;
    
    if (obj.GroupId || obj.GroupName) {
        html += `<tr><th>Security Group ID</th><td>${esc(obj.GroupId || 'N/A')}</td></tr>`;
        html += `<tr><th>Security Group Name</th><td>${esc(obj.GroupName || 'N/A')}</td></tr>`;
    }

    const priorityKeys = ['InstanceId', 'NetworkInterfaceId', 'VpcId', 'SubnetId', 'PrivateIpAddress', 'State', 'InstanceType', 'Platform', 'Description'];
    const renderedKeys = new Set(['GroupId', 'GroupName']);

    for (const k of priorityKeys) {
        if (obj[k] !== undefined && obj[k] !== null && obj[k] !== "") {
            let val = obj[k];
            if (typeof val === 'object') val = JSON.stringify(val);
            html += `<tr><th>${esc(k)}</th><td>${esc(val)}</td></tr>`;
            renderedKeys.add(k);
        }
    }

    for (const [k, v] of Object.entries(obj)) {
        if (renderedKeys.has(k)) continue;
        if (v !== null && v !== undefined && v !== "" && typeof v !== 'object') {
            html += `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`;
        } else if (Array.isArray(v) && v.length > 0 && typeof v[0] === 'object') {
            html += `<tr><th>${esc(k)}</th><td><div style="font-family:sans-serif; font-size:12px; color:#475569;"><em>Contains ${v.length} sub-item(s)</em></div></td></tr>`;
        }
    }
    html += `</table>`;
    return html;
}

function itemHTML(x, badgeClass) {
    let extraDetails = "";
    
    if (x.type && x.type.includes('security_group') && x.data.IpPermissions) {
        extraDetails += `<div class="sub-table-header">Inbound Rules (IpPermissions)</div>`;
        extraDetails += `<table class="prop-table"><tr><th>Protocol</th><th>Port Range</th><th>Source (CIDRs / Groups)</th></tr>`;
        for (const perm of (x.data.IpPermissions || [])) {
            const proto = perm.IpProtocol === '-1' ? 'All' : (perm.IpProtocol || 'Any');
            let portStr = 'All';
            if (perm.FromPort !== undefined && perm.ToPort !== undefined) {
                portStr = perm.FromPort === perm.ToPort ? `${perm.FromPort}` : `${perm.FromPort} - ${perm.ToPort}`;
            }
            
            const sources = [];
            for (const ipR of (perm.IpRanges || [])) {
                sources.push(`<code class="rule-tag">${esc(ipR.CidrIp)}${ipR.Description ? ' (' + esc(ipR.Description) + ')' : ''}</code>`);
            }
            for (const pvR of (perm.UserIdGroupPairs || [])) {
                sources.push(`<code class="rule-tag">SG: ${esc(pvR.GroupId || pvR.GroupName)}</code>`);
            }
            
            extraDetails += `<tr><td>${esc(proto)}</td><td>${esc(portStr)}</td><td>${sources.join(' ') || 'Any'}</td></tr>`;
        }
        extraDetails += `</table>`;
    }

    if (x.type && x.type.includes('eni') && x.data.PrivateIpAddresses) {
        extraDetails += `<div class="sub-table-header">Assigned IP Addresses</div>`;
        extraDetails += `<table class="prop-table"><tr><th>Private IP</th><th>Primary</th><th>Association (Public IP)</th></tr>`;
        for (const ipcfg of (x.data.PrivateIpAddresses || [])) {
            const pubIp = ipcfg.Association ? ipcfg.Association.PublicIp : 'None';
            extraDetails += `<tr><td><code>${esc(ipcfg.PrivateIpAddress)}</code></td><td>${esc(ipcfg.Primary)}</td><td><code>${esc(pubIp)}</code></td></tr>`;
        }
        extraDetails += `</table>`;
    }

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
            ${renderProperties(x.data)}
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
    if (data.aws_matches.length) html += section("Matching AWS Resources (EC2, ENIs, RDS, etc.)", data.aws_matches.length, data.aws_matches.map(x => itemHTML(x, "aws")).join(""));
    if (data.attached_security_groups.length) html += section("Directly Attached Security Groups & Rules", data.attached_security_groups.length, data.attached_security_groups.map(x => itemHTML(x, "sg")).join(""));
    if (data.matched_addresses.length) html += section("Firewall Address Objects & Rules", data.matched_addresses.length, data.matched_addresses.map(x => itemHTML(x, "green")).join(""));
    if (data.raw_matches.length) html += section("Raw Text Matches", data.raw_matches.length, data.raw_matches.map(x => itemHTML(x, "")).join(""));
    if (!html) html = `<div class="empty">No matching records found.</div>`;
    document.getElementById("output").innerHTML = html;
}

async function investigate() {
    const q = document.getElementById("query").value.trim();
    if (!q) return;
    document.getElementById("output").innerHTML = `<div class="empty">Searching database for <b>${esc(q)}</b>...</div>`;
    const res = await fetch("/api/investigate?q=" + encodeURIComponent(q));
    const data = await res.json();
    render(data);
}

function clearAll() {
    document.getElementById("query").value = "";
    document.getElementById("summary").innerHTML = "";
    document.getElementById("output").innerHTML = `<div class="empty">Enter a query above to start exploring your infrastructure.</div>`;
}

document.getElementById("query").addEventListener("keydown", e => { if (e.key === "Enter") investigate(); });

async function loadInfo() {
    const r = await fetch("/api/info");
    const x = await r.json();
    document.getElementById("dataInfo").textContent = `${x.files} indexed items &bull; ${x.devices} devices/accounts`;
}

async function loadOrgTopology() {
    const container = document.getElementById("orgTreeView");
    const res = await fetch("/api/org");
    const org = await res.json();
    if (org.error) {
        container.innerHTML = `<div class="empty">${esc(org.error)}</div>`;
        return;
    }
    document.getElementById("orgMeta").textContent = `Org ID: ${org.OrganizationId || 'N/A'} | Root: ${org.RootName || org.Name || 'Root'}`;

    function renderNode(node, openDefault = true) {
        if (!node || typeof node !== 'object') return '';
        const nodeName = node.Name || node.Path || node.OrganizationalUnitName || node.Id || "Organizational Unit";
        const accounts = node.Accounts || node.AccountList || [];
        const subOus = node.OUs || node.Children || node.OrganizationalUnits || node.SubOUs || [];
        
        let html = `<details ${openDefault ? 'open' : ''}><summary>📁 <b>${esc(nodeName)}</b> <span style="font-weight:400; color:#64748b; font-size:12px;">(${accounts.length} accounts, ${subOus.length} sub-OUs)</span></summary>`;
        
        if (accounts.length > 0) {
            html += `<div class="org-accounts">`;
            for (const acc of accounts) {
                const accName = acc.Name || acc.AccountName || acc.Account?.Name || "Unnamed Account";
                const accId = acc.Id || acc.AccountId || acc.Account?.Id || "";
                const status = acc.Status || acc.AccountStatus || "ACTIVE";
                html += `<div class="account-badge">🖥️ <b>${esc(accName)}</b> &bull; <code>${esc(accId)}</code> <span style="color:#64748b;">[${esc(status)}]</span></div>`;
            }
            html += `</div>`;
        }

        if (subOus.length > 0) {
            html += `<div style="margin-top: 8px; padding-left: 14px; border-left: 2px solid #e2e8f0;">`;
            for (const ou of subOus) {
                html += renderNode(ou, false);
            }
            html += `</div>`;
        }

        if (accounts.length === 0 && subOus.length === 0) {
            html += `<div style="padding: 6px 14px; font-size:12px; color:#94a3b8; font-style:italic;">No direct accounts or sub-OUs in this level.</div>`;
        }
        
        html += `</details>`;
        return html;
    }

    const hierarchyRoot = org.Hierarchy || org;
    container.innerHTML = renderNode(hierarchyRoot, true);
}

async function loadPanTopology() {
    const container = document.getElementById("panTreeView");
    const res = await fetch("/api/pan-topology");
    const data = await res.json();
    if (data.error) {
        container.innerHTML = `<div class="empty">${esc(data.error)}</div>`;
        return;
    }
    document.getElementById("panMeta").textContent = `Panorama: ${data.PanoramaName || 'Panorama'}`;

    let html = "";
    html += `<details open><summary>📁 <b>Templates & Template Stacks</b> <span style="font-weight:400; color:#64748b; font-size:12px;">(${data.Templates ? data.Templates.length : 0} templates)</span></summary>`;
    if (data.Templates && data.Templates.length > 0) {
        html += `<div style="margin-top: 8px; padding-left: 14px; border-left: 2px solid #e2e8f0;">`;
        for (const tpl of data.Templates) {
            html += `<details open><summary>🛠️ <b>${esc(tpl.Name)}</b> <span class="badge blue">${esc(tpl.Type)}</span> <span style="font-size:11px; color:#64748b;">— ${esc(tpl.Description || '')}</span></summary>`;
            if (tpl.Firewalls && tpl.Firewalls.length > 0) {
                html += `<div class="org-accounts">`;
                for (const fw of tpl.Firewalls) {
                    html += `<div class="account-badge">🔥 <b>${esc(fw.Hostname)}</b> &bull; Model: <code>${esc(fw.Model)}</code> &bull; SN: <code>${esc(fw.Serial)}</code></div>`;
                }
                html += `</div>`;
            } else {
                html += `<div style="padding: 6px 14px; font-size:12px; color:#94a3b8; font-style:italic;">No firewalls bound directly to this template.</div>`;
            }
            html += `</details>`;
        }
        html += `</div>`;
    }
    html += `</details>`;

    html += `<details open style="margin-top: 16px;"><summary>📁 <b>Device Groups (Policy Hierarchies)</b> <span style="font-weight:400; color:#64748b; font-size:12px;">(${data.DeviceGroups ? data.DeviceGroups.length : 0} device groups)</span></summary>`;
    if (data.DeviceGroups && data.DeviceGroups.length > 0) {
        html += `<div style="margin-top: 8px; padding-left: 14px; border-left: 2px solid #e2e8f0;">`;
        for (const dg of data.DeviceGroups) {
            html += `<details open><summary>🛡️ <b>${esc(dg.Name)}</b> <span class="badge" style="background:#faf5ff; color:#7e22ce;">Parent: ${esc(dg.Parent || 'shared')}</span> <span style="font-size:11px; color:#64748b;">— ${esc(dg.Description || '')}</span></summary>`;
            if (dg.Firewalls && dg.Firewalls.length > 0) {
                html += `<div class="org-accounts">`;
                for (const fw of dg.Firewalls) {
                    html += `<div class="account-badge">🔥 <b>${esc(fw.Hostname)}</b> &bull; Model: <code>${esc(fw.Model)}</code> &bull; SN: <code>${esc(fw.Serial)}</code></div>`;
                }
                html += `</div>`;
            } else {
                html += `<div style="padding: 6px 14px; font-size:12px; color:#94a3b8; font-style:italic;">No firewalls assigned to this device group.</div>`;
            }
            html += `</details>`;
        }
        html += `</div>`;
    }
    html += `</details>`;

    container.innerHTML = html;
}

async function loadStats() {
    const res = await fetch("/api/stats");
    const st = await res.json();
    
    let awsHtml = `<div class="stat-row"><b>Active AWS Accounts Scanned</b><span><b>${st.aws_accounts_scanned}</b></span></div>`;
    for (const [k, v] of Object.entries(st.aws_resources)) {
        awsHtml += `<div class="stat-row"><span>${esc(k)}</span><b>${v}</b></div>`;
    }
    document.getElementById("awsStats").innerHTML = awsHtml;

    let panosHtml = "";
    for (const [k, v] of Object.entries(st.panos)) {
        panosHtml += `<div class="stat-row"><span>${esc(k)}</span><b>${v}</b></div>`;
    }
    document.getElementById("panosStats").innerHTML = panosHtml || `<div class="empty">No PAN-OS records found.</div>`;
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

@app.route("/api/org")
def api_org():
    if not ORG_FILE_PATH.exists():
        return jsonify({"error": f"Organization topology file '{ORG_FILE_PATH.name}' not found."}), 404
    try:
        with ORG_FILE_PATH.open("r", encoding="utf-8") as f:
            return jsonify(json.load(f))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/pan-topology")
def api_pan_topology():
    if not PAN_TOPOLOGY_PATH.exists():
        return jsonify({"error": f"Panorama topology file '{PAN_TOPOLOGY_PATH.name}' not found."}), 404
    try:
        with PAN_TOPOLOGY_PATH.open("r", encoding="utf-8") as f:
            return jsonify(json.load(f))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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


# ----------------------------------------------------------------------
# CLI Entry Point
# ----------------------------------------------------------------------

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
