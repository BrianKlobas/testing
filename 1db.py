import sqlite3
import os

DB_NAME = "perdef.db"

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            platform TEXT,
            category TEXT,
            source_ip TEXT,
            dest_ip TEXT,
            port INTEGER,
            raw_data TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS topology (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT,
            connected_to TEXT,
            link_type TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS automation_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_name TEXT,
            status TEXT,
            output TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_records_plat_cat ON records(platform, category)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_records_device ON records(device_id)")
    conn.commit()
    conn.close()

def investigate(device_id=None, platform=None, category=None, src=None, dst=None, port=None):
    output = {
        "palo_matches": [],
        "device_id": device_id,
        "platform": platform,
        "category": category,
        "status": "success"
    }

    conn = get_db()
    cursor = conn.cursor()

    query = "SELECT * FROM records WHERE 1=1"
    params = []

    if device_id:
        query += " AND device_id = ?"
        params.append(device_id)
    if platform:
        query += " AND platform = ?"
        params.append(platform)
    if category:
        query += " AND category = ?"
        params.append(category)
    if src:
        query += " AND source_ip = ?"
        params.append(src)
    if dst:
        query += " AND dest_ip = ?"
        params.append(dst)
    if port:
        query += " AND port = ?"
        params.append(port)

    cursor.execute(query, params)
    rows = [dict(row) for row in cursor.fetchall()]
    output["palo_matches"] = rows
    output["count"] = len(rows)

    conn.close()
    return output
