import json
import os
from database import get_db, init_db

# Designated source directories matching the original monolith setup
SOURCE_DIRS = ["./parsed", "./aws_parsed"]

def ingest_legacy_files():
    init_db()
    conn = get_db()
    cursor = conn.cursor()
    total_ingested = 0

    for directory in SOURCE_DIRS:
        if os.path.exists(directory) and os.path.isdir(directory):
            print(f"Scanning directory: {directory}")
            for filename in os.listdir(directory):
                if filename.endswith(".json"):
                    file_path = os.path.join(directory, filename)
                    print(f"Ingesting: {file_path}")
                    try:
                        with open(file_path, "r") as f:
                            data = json.load(f)

                        records = data.get("records", data) if isinstance(data, dict) else data
                        records = records if isinstance(records, list) else [records]

                        for item in records:
                            cursor.execute("""
                                INSERT INTO records (device_id, platform, category, source_ip, dest_ip, port, raw_data)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                            """, (
                                item.get("device_id") or item.get("device") or item.get("id"),
                                item.get("platform") or item.get("source_platform"),
                                item.get("category") or item.get("type"),
                                item.get("source_ip") or item.get("src_ip"),
                                item.get("dest_ip") or item.get("dst_ip"),
                                item.get("port") or item.get("dst_port"),
                                json.dumps(item)
                            ))
                        total_ingested += len(records)
                    except Exception as e:
                        print(f"Failed to process {file_path}: {e}")
        else:
            print(f"Source directory not found: {directory}")

    conn.commit()
    conn.close()
    print(f"Ingestion complete. Total records processed: {total_ingested}")

if __name__ == "__main__":
    ingest_legacy_files()
