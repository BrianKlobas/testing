#!/usr/bin/env python3
"""
ingest.py
------------------------------------------------------------
Standalone data ingestion script. Walks the parsed PAN-OS and AWS
JSON export directories and (re)builds the SQLite database that
app.py serves from.

Run this on its own whenever the source JSON changes:

    python ingest.py --firewall-data ./parsed --aws-data ./aws_parsed --db infra_intel.db

app.py never triggers ingestion itself, so the two can be run and
iterated on independently.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from database import get_db, init_db, DB_PATH as DEFAULT_DB_PATH


def ingest_data(fw_root: Path, aws_root: Path, db_file: Path | None = None):
    if db_file is None:
        db_file = DEFAULT_DB_PATH
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest parsed PAN-OS and AWS JSON exports into the Infra Intel SQLite database")
    parser.add_argument("--firewall-data", default="./parsed", help="Path to parsed Firewall JSON folder")
    parser.add_argument("--aws-data", default="./aws_parsed", help="Path to parsed AWS JSON folder")
    parser.add_argument("--db", default="infra_intel.db", help="Path to SQLite database file")
    args = parser.parse_args()

    fw_root = Path(args.firewall_data).resolve()
    aws_root = Path(args.aws_data).resolve()
    db_path = Path(args.db).resolve()

    print(f"[*] Ingesting firewall data from {fw_root}")
    print(f"[*] Ingesting AWS data from {aws_root}")
    print(f"[*] Writing to database {db_path}")

    ingest_data(fw_root, aws_root, db_path)

    print("[*] Ingest complete.")
