#!/usr/bin/env python3
#python3 -c "path = 'ingest.py'; content = path.read_text('utf-8').replace('\xa0', ' '); path.write_text(content, 'utf-8')"
"""Standalone JSON -> SQLite ingestion process.

Run this independently whenever the parsed AWS/PAN-OS JSON changes:
    python ingest.py
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from database import DEFAULT_DB_PATH, get_db, init_db

DEFAULT_FW_DATA_ROOT = Path(__file__).resolve().parent / "parsed"
DEFAULT_AWS_DATA_ROOT = Path(__file__).resolve().parent / "aws_parsed"


def _json_candidates(data: Any) -> list[dict[str, Any]]:
    candidates = data if isinstance(data, list) else [data]
    return [item for item in candidates if isinstance(item, dict)]


def _panos_record_name(item: dict[str, Any]) -> str:
    name = item.get("name", item.get("@name", ""))
    if name:
        return str(name)

    for key in ("object", "rule", "profile", "entry"):
        value = item.get(key)
        if isinstance(value, dict) and (value.get("name") or value.get("@name")):
            return str(value.get("name") or value.get("@name"))
    return ""


def _aws_record_name(item: dict[str, Any]) -> str:
    for key in (
        "VpcId", "SubnetId", "NetworkInterfaceId", "LoadBalancerArn",
        "LoadBalancerName", "InstanceId", "DBInstanceId", "GroupId",
        "Id", "Name",
    ):
        if item.get(key):
            name = str(item[key])
            if "arn:aws:" in name:
                name = name.split("/")[-1]
            return name

    hosted_zone = item.get("HostedZone")
    hosted_zone_name = hosted_zone.get("Name") if isinstance(hosted_zone, dict) else None
    return str(item.get("GroupName", hosted_zone_name or "AWS-Resource"))


def ingest_data(
    fw_root: Path = DEFAULT_FW_DATA_ROOT,
    aws_root: Path = DEFAULT_AWS_DATA_ROOT,
    db_file: Path = DEFAULT_DB_PATH,
    *,
    reset: bool = True,
) -> dict[str, int]:
    """Load parsed firewall/AWS JSON into SQLite.

    By default this performs the same clean rebuild behavior as the original
    monolith, which prevents stale records after source JSON is removed/changed.
    """
    fw_root = Path(fw_root).resolve()
    aws_root = Path(aws_root).resolve()
    db_file = Path(db_file).resolve()

    init_db(db_file, reset=reset)
    conn = get_db(db_file)
    cursor = conn.cursor()
    device_cache: dict[str, int] = {}
    counts = {"panos_files": 0, "panos_records": 0, "aws_files": 0, "aws_records": 0}

    def get_device_id(device_name: str) -> int:
        if device_name in device_cache:
            return device_cache[device_name]
        cursor.execute("INSERT OR IGNORE INTO devices (name) VALUES (?)", (device_name,))
        row = cursor.execute("SELECT id FROM devices WHERE name = ?", (device_name,)).fetchone()
        if row is None:
            raise RuntimeError(f"Unable to create/find device: {device_name}")
        device_cache[device_name] = int(row["id"])
        return device_cache[device_name]

    if fw_root.exists():
        for path in sorted(fw_root.rglob("*.json")):
            if not path.is_file():
                continue

            rel = path.relative_to(fw_root)
            device = rel.parts[0] if len(rel.parts) > 1 else "(root)"
            file_type = path.stem

            try:
                with path.open("r", encoding="utf-8") as handle:
                    data = json.load(handle)
            except (OSError, json.JSONDecodeError):
                continue

            candidates = _json_candidates(data)
            dev_id = get_device_id(device)
            counts["panos_files"] += 1

            for item in candidates:
                cursor.execute(
                    """
                    INSERT INTO records
                        (device_id, platform, category, filename, name, data)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        dev_id,
                        "panos",
                        file_type,
                        path.name,
                        _panos_record_name(item),
                        json.dumps(item),
                    ),
                )
                counts["panos_records"] += 1

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
                with path.open("r", encoding="utf-8") as handle:
                    data = json.load(handle)
            except (OSError, json.JSONDecodeError):
                continue

            candidates = _json_candidates(data)
            dev_id = get_device_id(f"AWS: {account_name}")
            counts["aws_files"] += 1

            for item in candidates:
                cursor.execute(
                    """
                    INSERT INTO records
                        (device_id, platform, category, filename, name, data)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        dev_id,
                        "aws",
                        service_type,
                        path.name,
                        _aws_record_name(item),
                        json.dumps(item),
                    ),
                )
                counts["aws_records"] += 1

    conn.commit()
    conn.close()
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Infrastructure Intelligence JSON -> SQLite ingest")
    parser.add_argument("--firewall-data", default=str(DEFAULT_FW_DATA_ROOT), help="Path to parsed Firewall JSON folder")
    parser.add_argument("--aws-data", default=str(DEFAULT_AWS_DATA_ROOT), help="Path to parsed AWS JSON folder")
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="Path to SQLite database")
    parser.add_argument(
        "--no-reset",
        action="store_true",
        help="Do not delete/rebuild the existing database first (normally not recommended for full source refreshes).",
    )
    args = parser.parse_args()

    print("[*] Ingesting parsed JSON into SQLite...")
    counts = ingest_data(
        Path(args.firewall_data),
        Path(args.aws_data),
        Path(args.db),
        reset=not args.no_reset,
    )
    print(
        "[*] Ingest complete: "
        f"PAN-OS {counts['panos_files']} files / {counts['panos_records']} records, "
        f"AWS {counts['aws_files']} files / {counts['aws_records']} records"
    )
    print(f"[*] Database: {Path(args.db).resolve()}")


if __name__ == "__main__":
    main()
