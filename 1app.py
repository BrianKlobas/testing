#!/usr/bin/env python3
"""
app.py
------------------------------------------------------------
Flask web layer for the Infra Intel dashboard. Thin by design:
routes call into database.InfrastructureDataSource for all data
access, so this file is safe to edit/reload rapidly while testing.

This file does NOT ingest data. It only reads whatever database
already exists at --db (default infra_intel.db). Run ingest.py
separately whenever the source JSON changes:

    python ingest.py --firewall-data ./parsed --aws-data ./aws_parsed --db infra_intel.db

Then run this file directly for local dev:

    python app.py --db infra_intel.db --port 8080
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from flask import Flask, jsonify, render_template, request

import database
from database import (
    InfrastructureDataSource,
    get_file_modified_time,
    get_latest_dir_mtime,
)

app = Flask(__name__)

# These are only used for the automation/status freshness display and
# don't affect ingestion (that lives entirely in ingest.py).
FW_DATA_ROOT = Path("parsed").resolve()
AWS_DATA_ROOT = Path("aws_parsed").resolve()
ORG_FILE_PATH = Path("org_topology.json").resolve()
PAN_TOPOLOGY_PATH = Path("panorama_topology.json").resolve()

# No db_file passed in -> InfrastructureDataSource always reads
# database.DB_PATH at call time, so updating database.DB_PATH below
# (from --db) is picked up automatically.
PANOS = InfrastructureDataSource()

# ----------------------------------------------------------------------
# Flask API Routes
# ----------------------------------------------------------------------

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
    src_query = request.args.get("src", "")
    dst_query = request.args.get("dst", "")
    port_query = request.args.get("port", "")
    return jsonify({"rules": PANOS.policy_lookup(src_query, dst_query, port_query)})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Infra Intel Dashboard web server")
    parser.add_argument("--firewall-data", default="./parsed", help="Path to parsed Firewall JSON folder (used for freshness display only)")
    parser.add_argument("--aws-data", default="./aws_parsed", help="Path to parsed AWS JSON folder (used for freshness display only)")
    parser.add_argument("--org-file", default="org_topology.json", help="Path to AWS Org topology JSON file")
    parser.add_argument("--pan-file", default="panorama_topology.json", help="Path to Panorama topology JSON file")
    parser.add_argument("--db", default="infra_intel.db", help="Path to SQLite database file")
    parser.add_argument("--port", type=int, default=8080, help="Web server port")
    args = parser.parse_args()

    FW_DATA_ROOT = Path(args.firewall_data).resolve()
    AWS_DATA_ROOT = Path(args.aws_data).resolve()
    ORG_FILE_PATH = Path(args.org_file).resolve()
    PAN_TOPOLOGY_PATH = Path(args.pan_file).resolve()

    # Update the shared DB_PATH global in database.py so PANOS (and any
    # get_db() call with no explicit path) reads/writes the right file.
    database.DB_PATH = Path(args.db).resolve()

    if not database.DB_PATH.exists():
        print(f"[!] Warning: database not found at {database.DB_PATH}")
        print(f"[!] Run ingest.py first, e.g.:")
        print(f"      python ingest.py --firewall-data {args.firewall_data} --aws-data {args.aws_data} --db {args.db}")

    print(f"[*] Starting web server on http://localhost:{args.port} (db: {database.DB_PATH})")
    app.run(host="0.0.0.0", port=args.port, debug=False)
