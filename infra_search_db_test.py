#!/usr/bin/env python3
"""
Infrastructure Intelligence GUI (SQLite-Backed & Accelerated)
-----------------------------------------------------------
Extensible search GUI for PAN-OS / Panorama JSON data, using SQLite + FTS5
for instant sub-millisecond relationship and text queries.

Run:
    pip install flask
    python infra_intel.py --data ./parsed --db infra_intel.db

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
DATA_ROOT = Path("parsed").resolve()

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
            category TEXT,       -- 'addresses', 'address_groups', 'security_rules', etc.
            filename TEXT,
            name TEXT,           -- Object or rule name
            data TEXT,           -- Full JSON payload string
            FOREIGN KEY(device_id) REFERENCES devices(id)
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS records_fts USING fts5(
            name, data, content='records', content_rowid='id'
        );

        -- Triggers to keep FTS table in sync
        CREATE TRIGGER records_ai AFTER INSERT ON records BEGIN
            INSERT INTO records_fts(rowid, name, data) VALUES (new.id, new.name, new.data);
        END;
    """)
    conn.commit()
    conn.close()

def ingest_data(root: Path, db_file: Path = DB_PATH):
    if not root.exists():
        return

    init_db(db_file)
    conn = get_db(db_file)
    cursor = conn.cursor()

    rule_types = {
        "security_rules", "nat_rules", "pbf_rules", "qos_rules",
        "decryption_rules", "application_override_rules", "authentication_rules"
    }
    object_types = {
        "addresses", "address_groups", "services", "service_groups",
        "tags", "zones", "interfaces", "virtual_routers", "ipsec_tunnels"
    }

    device_cache = {}

    def get_device_id(dev_name: str) -> int:
        if dev_name in device_cache:
            return device_cache[dev_name]
        cursor.execute("INSERT OR IGNORE INTO devices (name) VALUES (?)", (dev_name,))
        cursor.execute("SELECT id FROM devices WHERE name = ?", (dev_name,))
        row = cursor.fetchone()
        device_cache[dev_name] = row["id"]
        return row["id"]

    for path in sorted(root.rglob("*.json")):
        if not path.is_file():
            continue

        rel = path.relative_to(root)
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

            # Extract identifier name
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
                "INSERT INTO records (device_id, category, filename, name, data) VALUES (?, ?, ?, ?, ?)",
                (dev_id, file_type, path.name, name, json.dumps(item))
            )

    conn.commit()
    conn.close()


# ----------------------------------------------------------------------
# PanOS Database-Backed Data Source
# ----------------------------------------------------------------------

class PanOSDataSource:
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
            "raw_matches": [],
            "summary": {}
        }

        conn = get_db(self.db_file)
        cursor = conn.cursor()

        if query_network:
            # IP/CIDR Workflow: Fetch all address records and match via Python network overlap
            cursor.execute("""
                r.id, d.name as device, r.category, r.filename, r.name, r.data
                FROM records r
                JOIN devices d ON r.device_id = d.id
                WHERE r.category = 'addresses'
            """)
            
            address_hits = []
            discovered_names = set()
            devices_involved = set()

            for row in cursor.fetchall():
                item = json.loads(row["data"])
                body = item.get("object", item)
                
                # Check for IP matches recursively in the address object
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
                scan_dict(body)

                if hits:
                    address_hits.append({
                        "device": row["device"],
                        "type": row["category"],
                        "file": row["filename"],
                        "name": row["name"],
                        "data": item,
                        "matches": hits
                    })
                    discovered_names.add(row["name"])
                    devices_involved.add(row["device"])

            output["matched_addresses"] = address_hits

            # Recursively find group memberships containing discovered objects/groups
            cursor.execute("""
                SELECT r.id, d.name as device, r.category, r.filename, r.name, r.data
                FROM records r
                JOIN devices d ON r.device_id = d.id
                WHERE r.category = 'address_groups'
            """)
            all_groups = cursor.fetchall()
            group_map = {}
            for g in all_groups:
                g_data = json.loads(g["data"])
                # Extract members list
                members = []
                def extract_members(node):
                    if isinstance(node, dict):
                        for mk, mv in node.items():
                            if mk == "member":
                                if isinstance(mv, list):
                                    members.extend([str(m) for m in mv])
                                else:
                                    members.append(str(mv))
                            extract_members(mv)
                    elif isinstance(node, list):
                        for item in node:
                            extract_members(item)
                extract_members(g_data)
                group_map[(g["device"], g["name"])] = {
                    "record": dict(g),
                    "members": list(dict.fromkeys(members)),
                    "data": g_data
                }

            # BFS/DFS discovery for nested groups
            matched_groups = []
            queue = list(discovered_names)
            discovered_groups = set()

            changed = True
            while changed:
                changed = False
                for (dev, g_name), info in group_map.items():
                    if dev not in devices_involved and devices_involved:
                        continue
                    if (dev, g_name) in discovered_groups:
                        continue
                    if any(m in queue or m in discovered_names for m in info["members"]):
                        discovered_groups.add((dev, g_name))
                        discovered_names.add(g_name)
                        queue.append(g_name)
                        changed = True

            for dev, g_name in discovered_groups:
                info = group_map[(dev, g_name)]
                rec = info["record"]
                matched_groups.append({
                    "device": rec["device"],
                    "type": rec["category"],
                    "file": rec["filename"],
                    "name": rec["name"],
                    "data": info["data"],
                    "members": info["members"],
                    "relationship": "contains discovered object/group"
                })

            output["matched_groups"] = matched_groups

            # Fetch rules referencing any discovered names
            all_names_to_check = list(discovered_names)
            rule_categories = [
                "security_rules", "nat_rules", "pbf_rules", "qos_rules",
                "decryption_rules", "application_override_rules", "authentication_rules"
            ]
            placeholders = ','.join(['?'] * len(rule_categories))
            cursor.execute(f"""
                r.id, d.name as device, r.category, r.filename, r.name, r.data
                FROM records r
                JOIN devices d ON r.device_id = d.id
                WHERE r.category IN ({placeholders})
            """, rule_categories)

            related_rules = []
            for row in cursor.fetchall():
                rule_item = json.loads(row["data"])
                # Extract all scalar values in rule to check references
                rule_scalars = set()
                def extract_scalars(node):
                    if isinstance(node, dict):
                        for kv in node.values():
                            extract_scalars(kv)
                    elif isinstance(node, list):
                        for lv in node:
                            extract_scalars(lv)
                    else:
                        rule_scalars.add(str(node).strip())
                extract_scalars(rule_item)

                matched_objs = sorted([n for n in all_names_to_check if n in rule_scalars])
                if matched_objs:
                    related_rules.append({
                        "device": row["device"],
                        "type": row["category"],
                        "file": row["filename"],
                        "name": row["name"],
                        "data": rule_item,
                        "matched_objects": matched_objs
                    })

            output["related_rules"] = related_rules

            # Raw FTS search for general text matches
            cursor.execute("""
                SELECT r.id, d.name as device, r.category, r.filename, r.name, r.data
                FROM records_fts f
                JOIN records r ON f.rowid = r.id
                JOIN devices d ON r.device_id = d.id
                WHERE records_fts MATCH ? LIMIT ?
            """, (query, limit))

            raw_matches = []
            for row in cursor.fetchall():
                raw_matches.append({
                    "device": row["device"],
                    "type": row["category"],
                    "file": row["filename"],
                    "name": row["name"],
                    "match_path": "FTS Match",
                    "match_value": query,
                    "data": json.loads(row["data"])
                })
            output["raw_matches"] = raw_matches

        else:
            # Standard Text Search using FTS5
            cursor.execute("""
                SELECT r.id, d.name as device, r.category, r.filename, r.name, r.data
                FROM records_fts f
                JOIN records r ON f.rowid = r.id
                JOIN devices d ON r.device_id = d.id
                WHERE records_fts MATCH ? LIMIT ?
            """, (query, limit))

            raw_matches = []
            object_names = set()
            devices_involved = set()

            for row in cursor.fetchall():
                item = json.loads(row["data"])
                raw_matches.append({
                    "device": row["device"],
                    "type": row["category"],
                    "file": row["filename"],
                    "name": row["name"],
                    "match_path": "FTS Match",
                    "match_value": query,
                    "data": item
                })
                if row["category"] in {"addresses", "address_groups"} and row["name"]:
                    object_names.add(row["name"])
                    devices_involved.add(row["device"])

            output["raw_matches"] = raw_matches

            if object_names:
                rule_categories = [
                    "security_rules", "nat_rules", "pbf_rules", "qos_rules",
                    "decryption_rules", "application_override_rules", "authentication_rules"
                ]
                placeholders = ','.join(['?'] * len(rule_categories))
                cursor.execute(f"""
                    SELECT r.id, d.name as device, r.category, r.filename, r.name, r.data
                    FROM records r
                    JOIN devices d ON r.device_id = d.id
                    WHERE r.category IN ({placeholders})
                """, rule_categories)

                related_rules = []
                for row in cursor.fetchall():
                    rule_item = json.loads(row["data"])
                    rule_scalars = set()
                    def extract_scalars(node):
                        if isinstance(node, dict):
                            for kv in node.values():
                                extract_scalars(kv)
                        elif isinstance(node, list):
                            for lv in node:
                                extract_scalars(lv)
                        else:
                            rule_scalars.add(str(node).strip())
                    extract_scalars(rule_item)

                    matched_objs = sorted([n for n in object_names if n in rule_scalars])
                    if matched_objs:
                        related_rules.append({
                            "device": row["device"],
                            "type": row["category"],
                            "file": row["filename"],
                            "name": row["name"],
                            "data": rule_item,
                            "matched_objects": matched_objs
                        })
                output["related_rules"] = related_rules

        output["summary"] = {
            "addresses": len(output["matched_addresses"]),
            "groups": len(output["matched_groups"]),
            "rules": len(output["related_rules"]),
            "raw": len(output["raw_matches"])
        }

        conn.close()
        return output


PANOS = PanOSDataSource(DB_PATH)


# ----------------------------------------------------------------------
# Modernized GUI Template
# ----------------------------------------------------------------------

HTML = r"""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Infrastructure Intelligence — PAN-OS Explorer</title>
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
    letter-spacing: 0.5px;
}

.brand h1 {
    margin: 0;
    font-size: 18px;
    font-weight: 600;
}

.brand small {
    color: #94a3b8;
    font-size: 12px;
}

.container {
    max-width: 1600px;
    margin: 28px auto;
    padding: 0 24px;
}

.search-panel {
    background: var(--bg-card);
    border-radius: 14px;
    padding: 22px;
    box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.05), 0 2px 4px -2px rgb(0 0 0 / 0.05);
    border: 1px solid var(--border-color);
}

.search-row {
    display: flex;
    gap: 12px;
}

.search-row input {
    flex: 1;
    min-width: 350px;
}

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

.hint {
    color: var(--text-secondary);
    font-size: 13px;
    margin-top: 10px;
}

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

.card b {
    display: block;
    font-size: 24px;
    color: var(--accent);
}

.card span {
    color: var(--text-secondary);
    font-size: 13px;
    margin-top: 4px;
    display: block;
}

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

.section-title h2 {
    font-size: 15px;
    margin: 0;
    font-weight: 600;
}

.count {
    background: #e2e8f0;
    border-radius: 20px;
    padding: 4px 10px;
    font-size: 12px;
    font-weight: 600;
    color: #334155;
}

.item {
    border-bottom: 1px solid #f1f5f9;
    padding: 18px 20px;
}

.item:last-child { border-bottom: 0; }

.item-head {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
    align-items: center;
}

.item-name {
    font-weight: 700;
    font-size: 15px;
}

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
.badge.orange { background: #fff7ed; color: #c2410c; }

.meta {
    color: var(--text-secondary);
    font-size: 13px;
    margin-top: 6px;
}

.relationship {
    margin-top: 10px;
    background: #f8fafc;
    border-left: 3px solid var(--accent);
    padding: 10px 14px;
    font-size: 13px;
    border-radius: 0 6px 6px 0;
}

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

details {
    margin-top: 12px;
}

summary {
    color: var(--accent);
    cursor: pointer;
    font-size: 13px;
    font-weight: 600;
}

.empty {
    padding: 48px;
    background: var(--bg-card);
    border-radius: 12px;
    text-align: center;
    color: var(--text-secondary);
    border: 1px solid var(--border-color);
}

.member-list {
    margin-top: 10px;
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
}

.member {
    background: #f1f5f9;
    border-radius: 6px;
    padding: 6px 10px;
    font-family: monospace;
    font-size: 12px;
    color: #334155;
    border: 1px solid #e2e8f0;
}

.rule-summary {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 10px;
    margin-top: 12px;
}

.rule-field {
    background: #f8fafc;
    padding: 10px;
    border-radius: 6px;
    border: 1px solid #e2e8f0;
}

.rule-field label {
    display: block;
    font-size: 11px;
    color: var(--text-secondary);
    text-transform: uppercase;
    font-weight: 600;
}

.rule-field div {
    font-size: 13px;
    margin-top: 4px;
    word-break: break-word;
    font-weight: 500;
}

@media (max-width: 900px) {
    .search-row { flex-direction: column; }
    .search-row input { min-width: 0; }
    .summary { grid-template-columns: repeat(2, 1fr); }
    .rule-summary { grid-template-columns: 1fr 1fr; }
}
</style>
</head>

<body>
<div class="topbar">
    <div class="brand">
        <div class="logo">II</div>
        <div>
            <h1>Infrastructure Intelligence</h1>
            <small>SQLite Accelerated Engine</small>
        </div>
    </div>
    <div id="dataInfo" style="font-size:13px;color:#94a3b8;"></div>
</div>

<div class="container">
    <div class="search-panel">
        <div class="search-row">
            <input id="query" placeholder="Search IP, CIDR, FQDN, object, group, rule..." autocomplete="off">
            <button onclick="investigate()">Investigate</button>
            <button class="secondary" onclick="clearAll()">Clear</button>
        </div>
        <div class="hint">
            💡 <b>Fast Local Database:</b> IP/CIDR queries execute instant relationship mapping over address objects, nested groups, and security rules.
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
            <div class="card"><b>${s.addresses}</b><span>Address Objects</span></div>
            <div class="card"><b>${s.groups}</b><span>Address Groups</span></div>
            <div class="card"><b>${s.rules}</b><span>Related Rules</span></div>
            <div class="card"><b>${s.raw}</b><span>Raw JSON Matches</span></div>
            <div class="card"><b>Indexed</b><span>Engine: SQLite</span></div>
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

function addressHTML(x) {
    const hits = (x.matches || []).map(m =>
        `<div class="relationship"><b>${esc(m.path)}</b> = ${esc(m.value)}</div>`
    ).join("");

    return `
        <div class="item">
            <div class="item-head">
                <div class="item-name">${esc(x.name)}</div>
                <div>
                    <span class="badge blue">${esc(x.device)}</span>
                    <span class="badge green">address</span>
                </div>
            </div>
            <div class="meta">${esc(x.file)}</div>
            ${hits}
            <details>
                <summary>View Full JSON</summary>
                <pre>${jsonStr(x.data)}</pre>
            </details>
        </div>
    `;
}

function groupHTML(x) {
    const members = (x.members || []).map(m => `<span class="member">${esc(m)}</span>`).join("");
    return `
        <div class="item">
            <div class="item-head">
                <div class="item-name">${esc(x.name)}</div>
                <div>
                    <span class="badge blue">${esc(x.device)}</span>
                    <span class="badge green">address-group</span>
                </div>
            </div>
            <div class="meta">${esc(x.file)} &bull; ${esc(x.relationship)}</div>
            <div class="member-list">${members || "<span class='meta'>No members found</span>"}</div>
            <details>
                <summary>View Full JSON</summary>
                <pre>${jsonStr(x.data)}</pre>
            </details>
        </div>
    `;
}

function getRuleField(data, names) {
    let rule = data?.rule || data?.object || data || {};
    for (const n of names) {
        if (rule[n] !== undefined) {
            const v = rule[n];
            if (Array.isArray(v)) return v.join(", ");
            if (typeof v === "object") return JSON.stringify(v);
            return String(v);
        }
    }
    return "";
}

function ruleHTML(x) {
    const source = getRuleField(x.data, ["source"]);
    const destination = getRuleField(x.data, ["destination"]);
    const application = getRuleField(x.data, ["application"]);
    const service = getRuleField(x.data, ["service"]);
    const matched = (x.matched_objects || []).map(m => `<span class="badge orange">${esc(m)}</span>`).join("");

    return `
        <div class="item">
            <div class="item-head">
                <div class="item-name">${esc(x.name || "(unnamed rule)")}</div>
                <div>
                    <span class="badge blue">${esc(x.device)}</span>
                    <span class="badge green">${esc(x.type)}</span>
                    ${matched}
                </div>
            </div>
            <div class="meta">${esc(x.file)}</div>
            <div class="rule-summary">
                <div class="rule-field"><label>Source</label><div>${esc(source || "—")}</div></div>
                <div class="rule-field"><label>Destination</label><div>${esc(destination || "—")}</div></div>
                <div class="rule-field"><label>Application</label><div>${esc(application || "—")}</div></div>
                <div class="rule-field"><label>Service</label><div>${esc(service || "—")}</div></div>
            </div>
            <details>
                <summary>View Full Rule JSON</summary>
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
    if (data.matched_addresses.length) html += section("Address Objects", data.matched_addresses.length, data.matched_addresses.map(addressHTML).join(""));
    if (data.matched_groups.length) html += section("Address Groups", data.matched_groups.length, data.matched_groups.map(groupHTML).join(""));
    if (data.related_rules.length) html += section("Related Rules", data.related_rules.length, data.related_rules.map(ruleHTML).join(""));
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
    document.getElementById("dataInfo").textContent = `${x.files} indexed items &bull; ${x.devices} devices`;
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
        "data_root": str(DATA_ROOT),
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
    parser = argparse.ArgumentParser(description="Infrastructure Intelligence Engine")
    parser.add_argument("--data", default="./parsed", help="Path to parsed JSON folder")
    parser.add_argument("--db", default="infra_intel.db", help="Path to SQLite database file")
    parser.add_argument("--port", type=int, default=8080, help="Web server port")
    args = parser.parse_args()

    DATA_ROOT = Path(args.data).resolve()
    DB_PATH = Path(args.db).resolve()

    print(f"[*] Ingesting data from {DATA_ROOT} into SQLite database ({DB_PATH})...")
    ingest_data(DATA_ROOT, DB_PATH)
    print(f"[*] Database index ready. Starting web server on http://localhost:{args.port}...")

    app.run(host="0.0.0.0", port=args.port, debug=False)
