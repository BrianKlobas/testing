import json
import os
from database import get_db, init_db

def ingest_data(file_path="data.json"):
    init_db()
    if not os.path.exists(file_path):
        print(f"Error: Target data file '{file_path}' not found.")
        return

    with open(file_path, "r") as f:
        data = json.load(f)

    conn = get_db()
    cursor = conn.cursor()

    # Handle structured dictionary wrappers or raw lists
    records = data.get("records", data) if isinstance(data, dict) else data
    records = records if isinstance(records, list) else [records]

    for item in records:
        cursor.execute("""
            INSERT INTO records (device_id, platform, category, source_ip, dest_ip, port, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            item.get("device_id"),
            item.get("platform"),
            item.get("category"),
            item.get("source_ip"),
            item.get("dest_ip"),
            item.get("port"),
            json.dumps(item)
        ))

    conn.commit()
    conn.close()
    print(f"Successfully ingested {len(records)} records into the PerDef SQLite database.")

if __name__ == "__main__":
    ingest_data()
