#!/usr/bin/env python3
"""
Infrastructure Intelligence GUI
-------------------------------
Extensible search GUI for PAN-OS / Panorama JSON data, with the design
intended to later support AWS, Azure, etc.

Current PAN-OS workflow:

    Search IP / CIDR / FQDN / object name
        |
        +--> Address objects matching the IP/CIDR
        |
        +--> Address groups containing those objects
        |       +--> nested groups
        |
        +--> Rules referencing any discovered object/group
        |       +--> security
        |       +--> NAT
        |       +--> PBF
        |       +--> QoS
        |       +--> decryption
        |       +--> authentication
        |       +--> application override
        |
        +--> Raw JSON matches
        |
        +--> Full JSON for every rule/object

Run:
    pip install flask
    python infra_intel.py --data ./parsed

Then:
    http://localhost:8080
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

DATA_ROOT = Path("parsed").resolve()

# ----------------------------------------------------------------------
# Extensible data-source architecture
#
# Future:
#   class AWSDataSource(...)
#   class AzureDataSource(...)
#   class GCPDataSource(...)
#
# The GUI/API can remain the same while additional data sources are added.
# ----------------------------------------------------------------------

class DataSource:
    name = "base"

    def search(self, query: str) -> dict[str, Any]:
        raise NotImplementedError


class PanOSDataSource(DataSource):
    name = "panos"

    RULE_TYPES = {
        "security_rules",
        "nat_rules",
        "pbf_rules",
        "qos_rules",
        "decryption_rules",
        "application_override_rules",
        "authentication_rules",
    }

    OBJECT_TYPES = {
        "addresses",
        "address_groups",
        "services",
        "service_groups",
        "tags",
        "zones",
        "interfaces",
        "virtual_routers",
        "ipsec_tunnels",
    }

    def __init__(self, root: Path):
        self.root = root

    # --------------------------
    # Basic JSON loading
    # --------------------------

    def files(self):
        if not self.root.exists():
            return []
        return sorted(
            p for p in self.root.rglob("*.json")
            if p.is_file()
        )

    def classify(self, path: Path):
        rel = path.relative_to(self.root)
        device = rel.parts[0] if len(rel.parts) > 1 else "(root)"
        file_type = path.stem
        return device, file_type, path.name

    def load(self, path: Path):
        try:
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

    # --------------------------
    # Generic JSON traversal
    # --------------------------

    def flatten(self, value, path=""):
        if isinstance(value, dict):
            for key, child in value.items():
                p = f"{path}.{key}" if path else str(key)
                yield from self.flatten(child, p)

        elif isinstance(value, list):
            for i, child in enumerate(value):
                yield from self.flatten(child, f"{path}[{i}]")

        else:
            yield path, value

    def stringify(self, value):
        if value is None:
            return ""
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)

    def recursive_values(self, value):
        for path, scalar in self.flatten(value):
            yield path, self.stringify(scalar)

    # --------------------------
    # IP/CIDR parsing
    # --------------------------

    def parse_network(self, value):
        """
        Parse:
          10.1.2.3
          10.1.2.3/32
          10.1.0.0/24

        Returns ipaddress object or None.
        """
        value = str(value).strip()

        try:
            if "/" in value:
                return ipaddress.ip_network(value, strict=False)
            return ipaddress.ip_network(value + "/32", strict=False)
        except ValueError:
            return None

    def extract_networks(self, value):
        """
        Extract IP/CIDR values from arbitrary PAN-OS strings.
        """
        text = self.stringify(value)

        # Avoid trying to interpret every number in a port/rule name as IP.
        pattern = r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])"

        for match in re.findall(pattern, text):
            network = self.parse_network(match)
            if network:
                yield match, network

    def networks_related(self, a, b):
        """
        True when the query network and object network overlap.

        For an IP query this effectively means:
            IP is inside object CIDR.

        For CIDR queries this means:
            CIDRs overlap.

        This is useful for finding both exact objects and broader objects
        such as 10.10.0.0/16 when searching 10.10.20.15.
        """
        try:
            return a.overlaps(b)
        except AttributeError:
            return False

    # --------------------------
    # PAN-OS object extraction
    # --------------------------

    def entry_name(self, entry):
        if not isinstance(entry, dict):
            return ""

        if entry.get("name"):
            return str(entry["name"])

        for key in ("object", "rule", "profile"):
            value = entry.get(key)
            if isinstance(value, dict) and value.get("name"):
                return str(value["name"])

        return ""

    def candidates_from_file(self, path):
        data = self.load(path)
        if data is None:
            return

        if isinstance(data, list):
            for item in data:
                yield item
        else:
            yield data

    def object_records(self):
        """
        Build an index of every address and address-group entry.
        """
        addresses = {}
        groups = {}

        for path in self.files():
            device, file_type, filename = self.classify(path)

            if file_type not in {"addresses", "address_groups"}:
                continue

            for item in self.candidates_from_file(path):
                if not isinstance(item, dict):
                    continue

                name = self.entry_name(item)
                if not name:
                    continue

                record = {
                    "device": device,
                    "type": file_type,
                    "file": filename,
                    "name": name,
                    "data": item,
                    "path": str(path),
                }

                if file_type == "addresses":
                    addresses[(device, name)] = record
                elif file_type == "address_groups":
                    groups[(device, name)] = record

        return addresses, groups

    def get_object_body(self, record):
        data = record.get("data", {})
        if not isinstance(data, dict):
            return {}

        # Parser output wraps normal objects under "object".
        body = data.get("object")
        if isinstance(body, dict):
            return body

        return data

    def address_values(self, record):
        body = self.get_object_body(record)

        for path, value in self.recursive_values(body):
            # Only attempt network matching on plausible values.
            if not value:
                continue

            for original, network in self.extract_networks(value):
                yield path, original, network

    def address_matches_query(self, record, query_network):
        hits = []

        for path, original, network in self.address_values(record):
            if self.networks_related(query_network, network):
                hits.append({
                    "path": path,
                    "value": original,
                })

        return hits

    # --------------------------
    # Address group membership
    # --------------------------

    def group_members(self, record):
        body = self.get_object_body(record)

        members = []

        def walk(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    # PAN-OS static address groups normally use:
                    # static -> member -> [names]
                    if key == "member":
                        if isinstance(child, list):
                            for x in child:
                                if not isinstance(x, (dict, list)):
                                    members.append(str(x))
                        elif not isinstance(child, (dict, list)):
                            members.append(str(child))

                    walk(child)

            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(body)

        # Preserve order, remove duplicates.
        return list(dict.fromkeys(members))

    def build_group_index(self, groups):
        index = {}

        for key, record in groups.items():
            index[key] = self.group_members(record)

        return index

    def groups_containing_objects(self, devices, object_names, groups):
        """
        Find every group that contains a discovered address/object.

        Recursively walks nested address groups.
        """
        group_index = self.build_group_index(groups)

        discovered = {}
        queue = []

        for device in devices:
            for name in object_names:
                queue.append((device, name))

        # We repeatedly discover parent groups until no new parents exist.
        changed = True
        while changed:
            changed = False

            for (device, group_name), members in group_index.items():
                if device not in devices:
                    continue

                if (device, group_name) in discovered:
                    continue

                if any(
                    member in object_names
                    or (device, member) in discovered
                    for member in members
                ):
                    discovered[(device, group_name)] = True
                    object_names.add(group_name)
                    changed = True

        results = []

        for key in discovered:
            record = groups.get(key)
            if not record:
                continue

            results.append({
                **record,
                "members": group_index.get(key, []),
                "relationship": "contains discovered object/group",
            })

        return results

    # --------------------------
    # Rule relationship analysis
    # --------------------------

    def rule_records(self):
        rules = []

        for path in self.files():
            device, file_type, filename = self.classify(path)

            if file_type not in self.RULE_TYPES:
                continue

            for item in self.candidates_from_file(path):
                if not isinstance(item, dict):
                    continue

                name = self.entry_name(item)

                rules.append({
                    "device": device,
                    "type": file_type,
                    "file": filename,
                    "name": name,
                    "data": item,
                    "path": str(path),
                })

        return rules

    def rule_reference_names(self, rule):
        """
        Extract scalar names from the complete rule JSON.

        We intentionally don't limit this to source/destination because
        an address/group can appear in other rule fields depending on
        PAN-OS rule type/version.
        """
        names = set()

        for path, value in self.recursive_values(rule):
            value = value.strip()
            if value:
                names.add(value)

        return names

    def rules_referencing(self, names, devices=None):
        results = []

        for rule in self.rule_records():
            if devices and rule["device"] not in devices:
                continue

            refs = self.rule_reference_names(rule["data"])

            matched = sorted(
                name for name in names
                if name in refs
            )

            if matched:
                results.append({
                    **rule,
                    "matched_objects": matched,
                })

        return results

    # --------------------------
    # Generic raw JSON search
    # --------------------------

    def raw_search(self, query, excluded_files=None, limit=500):
        excluded_files = excluded_files or set()
        results = []

        for path in self.files():
            if str(path) in excluded_files:
                continue

            device, file_type, filename = self.classify(path)

            for item_index, item in enumerate(self.candidates_from_file(path)):
                if not isinstance(item, (dict, list)):
                    continue

                for match_path, value in self.recursive_values(item):
                    if query.lower() not in value.lower():
                        continue

                    results.append({
                        "device": device,
                        "type": file_type,
                        "file": filename,
                        "name": self.entry_name(item),
                        "match_path": match_path,
                        "match_value": value,
                        "data": item,
                        "path": f"{filename}[{item_index}]",
                    })

                    if len(results) >= limit:
                        return results

        return results

    # --------------------------
    # Main investigation
    # --------------------------

    def investigate(self, query, limit=500):
        query = query.strip()

        output = {
            "query": query,
            "query_type": "text",
            "matched_addresses": [],
            "matched_groups": [],
            "related_rules": [],
            "raw_matches": [],
            "summary": {},
        }

        query_network = self.parse_network(query)

        addresses, groups = self.object_records()

        if query_network:
            output["query_type"] = "ip_or_cidr"

            address_hits = []

            for key, record in addresses.items():
                hits = self.address_matches_query(
                    record,
                    query_network,
                )

                if hits:
                    address_hits.append({
                        **record,
                        "matches": hits,
                    })

            output["matched_addresses"] = address_hits

            discovered_names = {
                x["name"]
                for x in address_hits
            }

            devices = {
                x["device"]
                for x in address_hits
            }

            # Recursively discover groups containing the matched addresses.
            group_hits = self.groups_containing_objects(
                devices=devices,
                object_names=discovered_names,
                groups=groups,
            )

            output["matched_groups"] = group_hits

            all_names = set(discovered_names)

            # Add every discovered group, including nested parent groups.
            all_names.update(
                x["name"]
                for x in group_hits
            )

            output["related_rules"] = self.rules_referencing(
                all_names,
                devices=devices,
            )

            # Raw search remains useful for fields that are not part of
            # address object definitions.
            output["raw_matches"] = self.raw_search(
                query,
                limit=min(limit, 250),
            )

        else:
            # Text search: object names, FQDNs, rule names, tags, etc.
            raw = self.raw_search(query, limit=limit)

            output["raw_matches"] = raw

            # Also identify exact object/group names from the raw results
            # and show rules that reference those names.
            object_names = set()
            devices = set()

            for x in raw:
                if x["type"] in {"addresses", "address_groups"} and x["name"]:
                    object_names.add(x["name"])
                    devices.add(x["device"])

            if object_names:
                output["related_rules"] = self.rules_referencing(
                    object_names,
                    devices=devices,
                )

        output["summary"] = {
            "addresses": len(output["matched_addresses"]),
            "groups": len(output["matched_groups"]),
            "rules": len(output["related_rules"]),
            "raw": len(output["raw_matches"]),
        }

        return output


PANOS = PanOSDataSource(DATA_ROOT)

# ----------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------

HTML = r"""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Infrastructure Intelligence</title>
<style>
* { box-sizing: border-box; }

body {
    margin: 0;
    background: #f3f5f7;
    color: #18212b;
    font-family: Inter, Arial, Helvetica, sans-serif;
}

.topbar {
    background: #111827;
    color: white;
    padding: 16px 26px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.brand {
    display: flex;
    gap: 12px;
    align-items: center;
}

.logo {
    width: 34px;
    height: 34px;
    border-radius: 8px;
    background: #2563eb;
    display: grid;
    place-items: center;
    font-weight: bold;
}

.brand h1 {
    margin: 0;
    font-size: 18px;
}

.brand small {
    color: #9ca3af;
}

.container {
    max-width: 1550px;
    margin: 22px auto;
    padding: 0 18px;
}

.search-panel {
    background: white;
    border-radius: 12px;
    padding: 18px;
    box-shadow: 0 2px 9px rgba(0,0,0,.07);
}

.search-row {
    display: flex;
    gap: 10px;
}

.search-row input {
    flex: 1;
    min-width: 350px;
}

input, select, button {
    height: 44px;
    border: 1px solid #cfd6dd;
    border-radius: 7px;
    padding: 0 13px;
    font-size: 14px;
}

button {
    background: #2563eb;
    color: white;
    border: 0;
    font-weight: 600;
    padding: 0 22px;
    cursor: pointer;
}

button.secondary {
    background: #6b7280;
}

.hint {
    color: #68737d;
    font-size: 12px;
    margin-top: 9px;
}

.tabs {
    display: flex;
    gap: 4px;
    margin-top: 18px;
}

.tab {
    border: 0;
    background: #e9edf2;
    color: #394552;
    border-radius: 7px 7px 0 0;
    padding: 10px 15px;
    height: auto;
}

.tab.active {
    background: white;
    color: #2563eb;
}

.summary {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 10px;
    margin: 15px 0;
}

.card {
    background: white;
    padding: 14px;
    border-radius: 9px;
    box-shadow: 0 1px 5px rgba(0,0,0,.06);
}

.card b {
    display: block;
    font-size: 21px;
}

.card span {
    color: #6b7280;
    font-size: 12px;
}

.section {
    background: white;
    border-radius: 10px;
    margin-bottom: 13px;
    box-shadow: 0 1px 5px rgba(0,0,0,.06);
    overflow: hidden;
}

.section-title {
    padding: 13px 16px;
    border-bottom: 1px solid #e7eaee;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.section-title h2 {
    font-size: 14px;
    margin: 0;
}

.count {
    background: #eef2f7;
    border-radius: 14px;
    padding: 4px 9px;
    font-size: 11px;
}

.item {
    border-bottom: 1px solid #edf0f2;
    padding: 14px 16px;
}

.item:last-child {
    border-bottom: 0;
}

.item-head {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
}

.item-name {
    font-weight: 700;
}

.badge {
    display: inline-block;
    background: #eef2f7;
    color: #46515d;
    border-radius: 12px;
    padding: 4px 8px;
    margin-left: 4px;
    font-size: 10px;
}

.badge.blue { background: #e8f1ff; color: #1d4ed8; }
.badge.green { background: #eaf8ef; color: #18743a; }
.badge.orange { background: #fff3df; color: #9a5b00; }

.meta {
    color: #697681;
    font-size: 12px;
    margin-top: 6px;
}

.relationship {
    margin-top: 9px;
    background: #f7f9fb;
    border-left: 3px solid #2563eb;
    padding: 9px 11px;
    font-size: 12px;
}

pre {
    background: #111827;
    color: #e5e7eb;
    border-radius: 7px;
    padding: 14px;
    overflow: auto;
    max-height: 550px;
    font-size: 12px;
}

details {
    margin-top: 11px;
}

summary {
    color: #2563eb;
    cursor: pointer;
    font-size: 12px;
    font-weight: 600;
}

.empty {
    padding: 35px;
    background: white;
    border-radius: 10px;
    text-align: center;
    color: #68737d;
}

.member-list {
    margin-top: 8px;
    display: flex;
    gap: 5px;
    flex-wrap: wrap;
}

.member {
    background: #f0f3f6;
    border-radius: 5px;
    padding: 5px 7px;
    font-family: Consolas, monospace;
    font-size: 11px;
}

.rule-summary {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 8px;
    margin-top: 10px;
}

.rule-field {
    background: #f7f8fa;
    padding: 8px;
    border-radius: 5px;
}

.rule-field label {
    display: block;
    font-size: 10px;
    color: #737e88;
    text-transform: uppercase;
}

.rule-field div {
    font-size: 12px;
    margin-top: 3px;
    word-break: break-word;
}

@media (max-width: 850px) {
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
            <small>PAN-OS / Panorama</small>
        </div>
    </div>
    <div id="dataRoot" style="font-size:12px;color:#9ca3af;"></div>
</div>

<div class="container">

    <div class="search-panel">
        <div class="search-row">
            <input id="query"
                   placeholder="Search IP, CIDR, FQDN, object, group, rule, tag..."
                   autocomplete="off">
            <button onclick="investigate()">Investigate</button>
            <button class="secondary" onclick="clearAll()">Clear</button>
        </div>

        <div class="hint">
            IP/CIDR searches perform relationship analysis:
            address objects → nested address groups → security/NAT/PBF/QoS/decryption/
            authentication/application-override rules.
            Text searches perform broad JSON searches.
        </div>
    </div>

    <div id="summary"></div>
    <div id="output">
        <div class="empty">
            Enter an IP, CIDR, FQDN, object name, or rule name to begin.
        </div>
    </div>
</div>

<script>
let lastData = null;

function esc(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;");
}

function json(value) {
    return esc(JSON.stringify(value, null, 2));
}

function setSummary(s) {
    document.getElementById("summary").innerHTML = `
        <div class="summary">
            <div class="card"><b>${s.addresses}</b><span>Address Objects</span></div>
            <div class="card"><b>${s.groups}</b><span>Address Groups</span></div>
            <div class="card"><b>${s.rules}</b><span>Related Rules</span></div>
            <div class="card"><b>${s.raw}</b><span>Raw JSON Matches</span></div>
            <div class="card"><b>${lastData.query_type}</b><span>Search Type</span></div>
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
        `<div class="relationship">
            <b>${esc(m.path)}</b> = ${esc(m.value)}
        </div>`
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
                <summary>Full address object JSON</summary>
                <pre>${json(x.data)}</pre>
            </details>
        </div>
    `;
}

function groupHTML(x) {
    const members = (x.members || []).map(m =>
        `<span class="member">${esc(m)}</span>`
    ).join("");

    return `
        <div class="item">
            <div class="item-head">
                <div class="item-name">${esc(x.name)}</div>
                <div>
                    <span class="badge blue">${esc(x.device)}</span>
                    <span class="badge green">address-group</span>
                </div>
            </div>
            <div class="meta">${esc(x.file)} · ${esc(x.relationship)}</div>
            <div class="member-list">${members || "<span class='meta'>No members found</span>"}</div>
            <details>
                <summary>Full address group JSON</summary>
                <pre>${json(x.data)}</pre>
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

    const matched = (x.matched_objects || []).map(m =>
        `<span class="badge orange">${esc(m)}</span>`
    ).join("");

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
                <div class="rule-field">
                    <label>Source</label>
                    <div>${esc(source || "—")}</div>
                </div>
                <div class="rule-field">
                    <label>Destination</label>
                    <div>${esc(destination || "—")}</div>
                </div>
                <div class="rule-field">
                    <label>Application</label>
                    <div>${esc(application || "—")}</div>
                </div>
                <div class="rule-field">
                    <label>Service</label>
                    <div>${esc(service || "—")}</div>
                </div>
            </div>

            <details open>
                <summary>Full rule information / JSON</summary>
                <pre>${json(x.data)}</pre>
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
            <div class="meta">${esc(x.file)} · ${esc(x.match_path)}</div>
            <div class="relationship">${esc(x.match_value)}</div>
            <details>
                <summary>Full JSON</summary>
                <pre>${json(x.data)}</pre>
            </details>
        </div>
    `;
}

function render(data) {
    lastData = data;
    setSummary(data.summary);

    let html = "";

    if (data.matched_addresses.length) {
        html += section(
            "Address Objects",
            data.matched_addresses.length,
            data.matched_addresses.map(addressHTML).join("")
        );
    }

    if (data.matched_groups.length) {
        html += section(
            "Address Groups / Nested Groups",
            data.matched_groups.length,
            data.matched_groups.map(groupHTML).join("")
        );
    }

    if (data.related_rules.length) {
        html += section(
            "Related Rules",
            data.related_rules.length,
            data.related_rules.map(ruleHTML).join("")
        );
    }

    if (data.raw_matches.length) {
        html += section(
            "Other JSON Matches",
            data.raw_matches.length,
            data.raw_matches.map(rawHTML).join("")
        );
    }

    if (!html) {
        html = `<div class="empty">No related objects or rules were found.</div>`;
    }

    document.getElementById("output").innerHTML = html;
}

async function investigate() {
    const q = document.getElementById("query").value.trim();

    if (!q) return;

    document.getElementById("output").innerHTML =
        `<div class="empty">Investigating <b>${esc(q)}</b>...</div>`;

    const response = await fetch(
        "/api/investigate?q=" + encodeURIComponent(q)
    );

    const data = await response.json();

    if (data.error) {
        document.getElementById("output").innerHTML =
            `<div class="empty">${esc(data.error)}</div>`;
        return;
    }

    render(data);
}

function clearAll() {
    document.getElementById("query").value = "";
    document.getElementById("summary").innerHTML = "";
    document.getElementById("output").innerHTML =
        `<div class="empty">Enter an IP, CIDR, FQDN, object, or rule name.</div>`;
}

document.getElementById("query").addEventListener("keydown", e => {
    if (e.key === "Enter") investigate();
});

async function loadInfo() {
    const r = await fetch("/api/info");
    const x = await r.json();

    document.getElementById("dataRoot").textContent =
        `${x.files} JSON files · ${x.devices} devices`;
}

loadInfo();
</script>
</body>
</html>
"""

# ----------------------------------------------------------------------
# API
# ----------------------------------------------------------------------

@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/info")
def api_info():
    files = PANOS.files()
    devices = {
        PANOS.classify(p)[0]
        for p in files
    }

    return jsonify({
        "data_root": str(DATA_ROOT),
        "files": len(files),
        "devices": len(devices),
    })


@app.route("/api/investigate")
def api_investigate():
    query = request.args.get("q", "").strip()

    if not query:
        return jsonify({"error": "A search value is required."}), 400

    try:
        return jsonify(PANOS.investigate(query))
    except Exception as exc:
        app.logger.exception("Investigation failed")
        return jsonify({
            "error": f"Investigation failed: {exc}"
        }), 500


def main():
    global DATA_ROOT, PANOS

    parser = argparse.ArgumentParser(
        description="Infrastructure Intelligence GUI for PAN-OS JSON."
    )

    parser.add_argument(
        "--data",
        default="parsed",
        help="Directory containing Panorama/firewall JSON output.",
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address. Use 0.0.0.0 for remote access.",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="HTTP port.",
    )

    args = parser.parse_args()

    DATA_ROOT = Path(args.data).resolve()
    PANOS = PanOSDataSource(DATA_ROOT)

    print("=" * 70)
    print("INFRASTRUCTURE INTELLIGENCE")
    print("=" * 70)
    print(f"Data : {DATA_ROOT}")
    print(f"URL  : http://{args.host}:{args.port}")
    print()

    app.run(
        host=args.host,
        port=args.port,
        debug=False,
        threaded=True,
    )


if __name__ == "__main__":
    main()
