#!/usr/bin/env python3
from pathlib import Path
import json
import os
from flask import Flask, jsonify, render_template, request
from database import PANOS, DB_PATH, get_db

app = Flask(__name__)

ORG_FILE_PATH = Path("org_topology.json").resolve()
PAN_TOPOLOGY_PATH = Path("panorama_topology.json").resolve()
AWS_DATA_ROOT = Path("aws_parsed").resolve()
FW_DATA_ROOT = Path("parsed").resolve()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/info")
def api_info():
    return jsonify({
        "files": PANOS.files_count(), 
        "devices": PANOS.devices_count()
    })

@app.route("/api/stats")
def api_stats():
    return jsonify(PANOS.get_stats())

@app.route("/api/metadata")
def api_metadata():
    """Provides last run timestamps and file metadata for the frontend."""
    db_mtime = "N/A"
    if DB_PATH.exists():
        mtime_epoch = DB_PATH.stat().st_mtime
        db_mtime = os.path.fromtimestamp(mtime_epoch).strftime("%Y-%m-%d %H:%M:%S") if hasattr(os, 'path') else str(mtime_epoch)
        
    return jsonify({
        "last_run": db_mtime,
        "database_size_kb": round(DB_PATH.stat().st_size / 1024, 2) if DB_PATH.exists() else 0,
        "panos_source_exists": FW_DATA_ROOT.exists(),
        "aws_source_exists": AWS_DATA_ROOT.exists()
    })

@app.route("/api/investigate")
def api_investigate():
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify({"error": "A search query is required."}), 400
    return jsonify(PANOS.investigate(query))

@app.route("/api/topology/aws")
def api_topology_aws():
    if ORG_FILE_PATH.exists():
        with ORG_FILE_PATH.open("r", encoding="utf-8") as f:
            return jsonify(json.load(f))
    return jsonify({"error": "File not found."}), 404

@app.route("/api/topology/pan")
def api_topology_pan():
    if PAN_TOPOLOGY_PATH.exists():
        with PAN_TOPOLOGY_PATH.open("r", encoding="utf-8") as f:
            return jsonify(json.load(f))
    return jsonify({"error": "File not found."}), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
