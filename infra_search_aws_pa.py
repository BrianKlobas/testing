#!/usr/bin/env python3
"""
Infrastructure Intelligence GUI (Unified PAN-OS & AWS SQLite-Backed Engine)
-------------------------------------------------------------------------
Unified search GUI for PAN-OS firewall JSON and multi-account AWS JSON records,
using SQLite + FTS5 for sub-millisecond full-text and relationship queries.

Run:
    python infra_intel.py --firewall-data ./parsed --aws-data ./aws_parsed --db infra_intel.db

Then:
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

# ----------------------------------------------------------------------
# Database Initialization & Indexing Engine
# ----------------------------------------------------------------------

def get_db(db_file: Path = DB_PATH):
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_file: Path = DB_PATH):
    if db_file.exists():
        db_file.unlink()  # Rebuild clean index on startup
        
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
            category TEXT,       -- 'addresses', 'vpcs', 'ec2_instances', 'security_groups', etc.
            filename TEXT,
            name TEXT,           -- Object or resource name / ID
            data TEXT,           -- Full JSON payload string
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

def ingest_data(fw_root: Path, aws_root: Path, db_file: Path = DB_PATH):
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

    # 2. Ingest AWS Data (Layout: aws_parsed/<account_id_name>/<region_or_global>/<service>.json)
    if aws_root.exists():
        for path in sorted(aws_root.rglob("*.json")):
            if not path.is_file():
                continue
            rel = path.relative_to(aws_root)
            if len(rel.parts) < 3:
                continue
            
            account_name = rel.parts[0]
            region_or_global = rel.parts[1]
            service_type = path.stem

            try:
                with path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue

            candidates = data if isinstance(data, list) else [data]
            dev_id = get_device_id(f"AWS: {account_name} ({region_or_global})")

            for item in candidates:
                if not isinstance(item, dict):
                    continue
                
                # Extract appropriate identifier name based on AWS resource type
                name = ""
                for name_key in ("VpcId", "SubnetId", "NetworkInterfaceId", "LoadBalancerArn", "LoadBalancerName", "InstanceId", "DBInstanceId", "Id", "Name"):
                    if item.get(name_key):
                        name = str(item[name_key])
                        # Clean up ARN if needed for cleaner title
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
# Database-Backed Search & Investigation Engine
# ----------------------------------------------------------------------

class InfrastructureDataSource:
    def __init__(self, db_file: Path = DB_PATH):
        self.db_file = db_file

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
            "matched_groups": [],
            "related_rules": [],
            "aws_matches": [],
            "raw_matches": [],
            "summary": {}
        }

        conn = get_db(self.db_file)
        cursor = conn.cursor()

        if query_network:
            # IP/CIDR Workflow: Search both PAN-OS and AWS for network overlap
            cursor.execute("""
                SELECT r.id, d.name as device, r.platform, r.category, r.filename, r.name, r.data
                FROM records r
                JOIN devices d ON r.device_id = d.id
            """)
            
            address_hits = []
            aws_matches = []
            raw_matches = []

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
                    record_entry = {
                        "device": row["device"],
                        "platform": row["platform"],
                        "type": row["category"],
                        "file": row["filename"],
                        "name": row["name"],
                        "data": item,
                        "matches": hits
                    }
                    if row["platform"] == "aws":
                        aws_matches.append(record_entry)
                    elif row["category"] == "addresses":
                        address_hits.append(record_entry)
                    else:
                        raw_matches.append(record_entry)

            output["matched_addresses"] = address_hits
            output["aws_matches"] = aws_matches
            output["raw_matches"] = raw_matches

        else:
            # Standard Text Search using FTS5
            cursor.execute("""
                SELECT r.id, d.name as device, r.platform, r.category, r.filename, r.name, r.data
                FROM records_fts f
                JOIN records r ON f.rowid = r.id
                JOIN devices d ON r.device_id = d.id
                WHERE records_fts MATCH ? LIMIT ?
            """, (query, limit))

            raw_matches = []
            aws_matches = []
            for row in cursor.fetchall():
                item = json.loads(row["data"])
                entry = {
                    "device": row["device"],
                    "platform": row["platform"],
                    "type": row["category"],
                    "file": row["filename"],
                    "name": row["name"],
                    "match_path": "FTS Match",
                    "match_value": query,
                    "data": item
                }
                if row["platform"] == "aws":
                    aws_matches.append(entry)
                else:
                    raw_matches.append(entry)

            output["aws_matches"] = aws_matches
            output["raw_matches"] = raw_matches

        output["summary"] = {
            "addresses": len(output["matched_addresses"]),
            "groups": len(output["matched_groups"]),
            "rules": len(output["related_rules"]),
            "aws": len(output["aws_matches"]),
            "raw": len(output["raw_matches"])
        }

        conn.close()
        return output


PANOS = InfrastructureDataSource(DB_PATH)


# ----------------------------------------------------------------------
# Modernized GUI Template
# ----------------------------------------------------------------------

HTML = r"""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Infrastructure Intelligence — Unified Cloud & Firewall Explorer</title>
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
    --aws-orange: #ff9900;
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
    padding: 16px 32px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
}

.brand {
    display: flex;
    gap: 14px;
    align-items: center;
}

.logo {
    width: 38px;
    height: 38px;
    border-radius: 10px;
    background: var(--accent);
    display: grid;
    place-items: center;
    font-weight: bold;
    font-size: 16px;
}

.brand h1 { margin: 0; font-size: 18px; font-weight: 600; }
.brand small { color: #94a3b8; font-size: 12px; }

.container { max-width: 1600px; margin: 28px auto; padding: 0 24px; }

.search-panel {
    background: var(--bg-card);
    border-radius: 14px;
    padding: 22px;
    box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.05);
    border: 1px solid var(--border-color);
}

.search-row { display: flex; gap: 12px; }
.search-row input { flex: 1; min-width: 350px; }

input, select, button {
    height: 48px;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    padding: 0 16px;
    font-size: 15px;
    outline: none;
    transition: all 0.2s ease;
}

input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15);
}

button {
    background: var(--accent);
    color: white;
    border: 0;
    font-weight: 600;
    padding: 0 26px;
    cursor: pointer;
}
button:hover { background: var(--accent-hover); }
button.secondary { background: #64748b; }
button.secondary:hover { background: #475569; }

.hint { color: var(--text-secondary); font-size: 13px; margin-top: 10px; }

.summary {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 14px;
    margin: 20px 0;
}

.card {
    background: var(--bg-card);
    padding: 18px;
    border-radius: 12px;
    box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.05);
    border: 1px solid var(--border-color);
}
.card b { display: block; font-size: 24px; color: var(--accent); }
.card span { color: var(--text-secondary); font-size: 13px; margin-top: 4px; display: block; }

.section {
    background: var(--bg-card);
    border-radius: 12px;
    margin-bottom: 18px;
    box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.05);
    border: 1px solid var(--border-color);
    overflow: hidden;
}

.section-title {
    padding: 16px 20px;
    border-bottom: 1px solid var(--border-color);
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #f8fafc;
}
.section-title h2 { font-size: 15px; margin: 0; font-weight: 600; }
.count { background: #e2e8f0; border-radius: 20px; padding: 4px 10px; font-size: 12px; font-weight: 600; color: #334155; }

.item { border-bottom: 1px solid #f1f5f9; padding: 18px 20px; }
.item:last-child { border-bottom: 0; }

.item-head {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
    align-items: center;
}
.item-name { font-weight: 700; font-size: 15px; }

.badge {
    display: inline-block;
    background: #f1f5f9;
    color: #475569;
    border-radius: 6px;
    padding: 4px 8px;
    margin-left: 6px;
    font-size: 11px;
    font-weight: 500;
}
.badge.blue { background: #eff6ff; color: #1d4ed8; }
.badge.green { background: #f0fdf4; color: #15803d; }
.badge.aws { background: #fff7ed; color: #c2410c; border: 1px solid #ff9900; }

.meta { color: var(--text-secondary); font-size: 13px; margin-top: 6px; }

pre {
    background: #0f172a;
    color: #e2e8f0;
    border-radius: 8px;
    padding: 16px;
    overflow: auto;
    max-height: 400px;
    font-size: 13px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

details { margin-top: 12px; }
summary { color: var(--accent); cursor: pointer; font-size: 13px; font-weight: 600; }
.empty { padding: 48px; background: var(--bg-card); border-radius: 12px; text-align: center; color: var(--text-secondary); border: 1px solid var(--border-color); }

@media (max-width: 900px) {
    .search-row { flex-direction: column; }
    .summary { grid-template-columns: repeat(2, 1fr); }
}
</style>
</head>

<body>
<div class="topbar">
    <div class="brand">
        <div class="logo">UI</div>
        <div>
            <h1>Infrastructure Intelligence</h1>
            <small>Unified Firewall & Multi-Account AWS DB Engine</small>
        </div>
    </div>
    <div id="dataInfo" style="font-size:13px;color:#94a3b8;"></div>
</div>

<div class="container">
    <div class="search-panel">
        <div class="search-row">
            <input id="query" placeholder="Search VPC ID, Subnet, EC2 Instance ID, Security Group, IP, or Firewall Rule..." autocomplete="off">
            <button onclick="investigate()">Investigate</button>
            <button class="secondary" onclick="clearAll()">Clear</button>
        </div>
        <div class="hint">
            💡 <b>Unified Search:</b> Instantly query across multi-account AWS infrastructure (VPCs, EC2, RDS, ENIs, Security Groups) and PAN-OS firewall definitions.
        </div>
    </div>

    <div id="summary"></div>
    <div id="output">
        <div class="empty">Enter a query above to start exploring your infrastructure.</div>
    </div>
</div>

<script>
function esc(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;");
}

function jsonStr(value) {
    return esc(JSON.stringify(value, null, 2));
}

function setSummary(s) {
    document.getElementById("summary").innerHTML = `
        <div class="summary">
            <div class="card"><b>${s.addresses}</b><span>Firewall Addresses</span></div>
            <div class="card"><b>${s.aws}</b><span>AWS Resources</span></div>
            <div class="card"><b>${s.rules}</b><span>Related Rules</span></div>
            <div class="card"><b>${s.raw}</b><span>Raw JSON Matches</span></div>
            <div class="card"><b>SQLite</b><span>Accelerated Index</span></div>
        </div>
    `;
}

function section(title, count, body) {
    return `
        <div class="section">
            <div class="section-title">
                <h2>${title}</h2>
                <span class="count">${count}</span>
            </div>
            ${body}
        </div>
    `;
}

function awsItemHTML(x) {
    return `
        <div class="item">
            <div class="item-head">
                <div class="item-name">${esc(x.name)}</div>
                <div>
                    <span class="badge blue">${esc(x.device)}</span>
                    <span class="badge aws">${esc(x.type)}</span>
                </div>
            </div>
            <div class="meta">${esc(x.file)}</div>
            <details>
                <summary>View Resource JSON & Tags</summary>
                <pre>${jsonStr(x.data)}</pre>
            </details>
        </div>
    `;
}

function rawHTML(x) {
    return `
        <div class="item">
            <div class="item-head">
                <div class="item-name">${esc(x.name || "(unnamed)")}</div>
                <div>
                    <span class="badge blue">${esc(x.device)}</span>
                    <span class="badge">${esc(x.type)}</span>
                </div>
            </div>
            <div class="meta">${esc(x.file)}</div>
            <details>
                <summary>View Full JSON Match</summary>
                <pre>${jsonStr(x.data)}</pre>
            </details>
        </div>
    `;
}

function render(data) {
    setSummary(data.summary);
    let html = "";
    if (data.aws_matches.length) html += section("AWS Infrastructure Resources", data.aws_matches.length, data.aws_matches.map(awsItemHTML).join(""));
    if (data.matched_addresses.length) html += section("Firewall Address Objects", data.matched_addresses.length, data.matched_addresses.map(rawHTML).join(""));
    if (data.raw_matches.length) html += section("Raw JSON Matches", data.raw_matches.length, data.raw_matches.map(rawHTML).join(""));
    if (!html) html = `<div class="empty">No matching records found.</div>`;
    document.getElementById("output").innerHTML = html;
}

async function investigate() {
    const q = document.getElementById("query").value.trim();
    if (!q) return;
    document.getElementById("output").innerHTML = `<div class="empty">Searching database for <b>${esc(q)}</b>...</div>`;
    const response = await fetch("/api/investigate?q=" + encodeURIComponent(q));
    const data = await response.json();
    if (data.error) {
        document.getElementById("output").innerHTML = `<div class="empty">${esc(data.error)}</div>`;
        return;
    }
    render(data);
}

function clearAll() {
    document.getElementById("query").value = "";
    document.getElementById("summary").innerHTML = "";
    document.getElementById("output").innerHTML = `<div class="empty">Enter a query above to start exploring your infrastructure.</div>`;
}

document.getElementById("query").addEventListener("keydown", e => {
    if (e.key === "Enter") investigate();
});

async function loadInfo() {
    const r = await fetch("/api/info");
    const x = await r.json();
    document.getElementById("dataInfo").textContent = `${x.files} indexed items &bull; ${x.devices} devices/accounts`;
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
    return jsonify({
        "fw_root": str(FW_DATA_ROOT),
        "aws_root": str(AWS_DATA_ROOT),
        "files": PANOS.files_count(),
        "devices": PANOS.devices_count(),
    })

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
    parser = argparse.ArgumentParser(description="Unified Infrastructure Intelligence Engine")
    parser.add_argument("--firewall-data", default="./parsed", help="Path to parsed Firewall JSON folder")
    parser.add_argument("--aws-data", default="./aws_parsed", help="Path to parsed AWS JSON folder")
    parser.add_argument("--db", default="infra_intel.db", help="Path to SQLite database file")
    parser.add_argument("--port", type=int, default=8080, help="Web server port")
    args = parser.parse_args()

    FW_DATA_ROOT = Path(args.firewall_data).resolve()
    AWS_DATA_ROOT = Path(args.aws_data).resolve()
    DB_PATH = Path(args.db).resolve()

    print(f"[*] Ingesting Firewall data from {FW_DATA_ROOT} and AWS data from {AWS_DATA_ROOT} into SQLite...")
    ingest_data(FW_DATA_ROOT, AWS_DATA_ROOT, DB_PATH)
    print(f"[*] Database index ready. Starting unified web server on http://localhost:{args.port}...")

    app.run(host="0.0.0.0", port=args.port, debug=False)
