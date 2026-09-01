#!/usr/bin/env python3
"""
PerDef Security Orchestrator GUI (Left-Sidebar Unified Dashboard)
------------------------------------------------------------
Run:
    python -m infra_intel.app --firewall-data ./parsed --aws-data ./aws_parsed --org-file org_topology.json --pan-file panorama_topology.json --db infra_intel.db
Then open:
    http://localhost:8080
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from infra_intel.database import (
    InfrastructureDataSource,
    get_db,
    get_file_modified_time,
    get_latest_dir_mtime,
    DB_PATH,
    sqlite_ip_contains,
    extractValues,
    findKeyRecursively
)
from infra_intel.ingest import ingest_data

app = Flask(__name__)

FW_DATA_ROOT = Path("parsed").resolve()
AWS_DATA_ROOT = Path("aws_parsed").resolve()
ORG_FILE_PATH = Path("org_topology.json").resolve()
PAN_TOPOLOGY_PATH = Path("panorama_topology.json").resolve()

PANOS = InfrastructureDataSource()


@app.route("/")
def index():
    return render_template("index.html")

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
