#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from database import get_db, DB_PATH

def init_db(db_file: Path):
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

def ingest_data(fw_root: Path, aws_root: Path, db_file: Path):
    print(f"[*] Initializing database at {db_file}...")
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
            if not path.is_file(): continue
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
                if not isinstance(item, dict): continue
                name = item.get("name", item.get("@name", ""))
                cursor.execute(
                    "INSERT INTO records (device_id, platform, category, filename, name, data) VALUES (?, ?, ?, ?, ?, ?)",
                    (dev_id, "panos", file_type, path.name, str(name), json.dumps(item))
                )

    if aws_root.exists():
        for path in sorted(aws_root.rglob("*.json")):
            if not path.is_file(): continue
            rel = path.relative_to(aws_root)
            if len(rel.parts) < 3: continue
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
                if not isinstance(item, dict): continue
                name = item.get("VpcId") or item.get("InstanceId") or item.get("GroupId") or "AWS-Resource"
                cursor.execute(
                    "INSERT INTO records (device_id, platform, category, filename, name, data) VALUES (?, ?, ?, ?, ?, ?)",
                    (dev_id, "aws", service_type, path.name, str(name), json.dumps(item))
                )

    conn.commit()
    conn.close()
    print("[*] Ingestion complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Standalone DB Ingester")
    parser.add_argument("--firewall-data", default="./parsed")
    parser.add_argument("--aws-data", default="./aws_parsed")
    parser.add_argument("--db", default="infra_intel.db")
    args = parser.parse_args()
    ingest_data(Path(args.firewall_data).resolve(), Path(args.aws_data).resolve(), Path(args.db).resolve())
