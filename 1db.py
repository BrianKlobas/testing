from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from functools import lru_cache

DB_PATH = Path("infra_intel.db")

def extract_ip_or_cidr(val: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if not val:
        return None
    val = str(val).strip()
    try:
        if "/" in val:
            return ipaddress.ip_network(val, strict=False)
        return ipaddress.ip_network(val + "/32", strict=False)
    except ValueError:
        return None

def sqlite_ip_contains(target_str: str, cidr_or_range_str: str) -> int:
    if not target_str or not cidr_or_range_str:
        return 0
    target_net = extract_ip_or_cidr(target_str)
    if not target_net:
        return 0
    val = str(cidr_or_range_str).strip()
    if "-" in val and "/" not in val:
        parts = val.split("-")
        if len(parts) == 2:
            try:
                start = ipaddress.ip_address(parts[0].strip())
                end = ipaddress.ip_address(parts[1].strip())
                return 1 if start <= target_net.network_address <= end or start <= target_net.broadcast_address <= end else 0
            except ValueError:
                pass
    fw_net = extract_ip_or_cidr(val)
    if fw_net:
        try:
            return 1 if target_net.overlaps(fw_net) or target_net.subnet_of(fw_net) or fw_net.subnet_of(target_net) else 0
        except ValueError:
            return 1 if target_net.overlaps(fw_net) else 0
    return 0

def get_db(db_file: Path | None = None):
    db_file = db_file or DB_PATH
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    conn.create_function("IP_CONTAINS", 2, sqlite_ip_contains)
    # Enable SQLite WAL mode for faster concurrent reads/writes and better caching performance
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

class InfrastructureDataSource:
    def __init__(self, db_file: Path | None = None):
        self._db_file = db_file

    @property
    def db_file(self) -> Path:
        return self._db_file if self._db_file is not None else DB_PATH

    def get_stats(self) -> dict[str, Any]:
        return self._cached_get_stats(str(self.db_file))

    @staticmethod
    @lru_cache(maxsize=32)
    def _cached_get_stats(db_path_str: str) -> dict[str, Any]:
        conn = get_db(Path(db_path_str))
        cursor = conn.cursor()
        cursor.execute("SELECT category, COUNT(*) as cnt FROM records WHERE platform='panos' GROUP BY category")
        panos_counts = {row["category"]: row["cnt"] for row in cursor.fetchall()}
        cursor.execute("SELECT category, COUNT(*) as cnt FROM records WHERE platform='aws' GROUP BY category")
        aws_summary = {row["category"]: row["cnt"] for row in cursor.fetchall()}
        cursor.execute("SELECT COUNT(DISTINCT name) FROM devices WHERE name LIKE 'AWS:%'")
        aws_accounts_count = cursor.fetchone()[0]
        files_cnt = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        conn.close()
        return {
            "panos": panos_counts,
            "aws_resources": aws_summary,
            "aws_accounts_scanned": aws_accounts_count,
            "total_files": files_cnt
        }

    def files_count(self) -> int:
        conn = get_db(self.db_file)
        count = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        conn.close()
        return count

    def devices_count(self) -> int:
        conn = get_db(self.db_file)
        count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        conn.close()
        return count

def investigate(self, query: str, limit: int = 500) -> dict[str, Any]:
        try:
            conn = get_db(self.db_file)
            cursor = conn.cursor()
            results = []
            seen_ids = set()
            
            search_term = f"%{query.strip()}%"
            
            # 1. Try standard text/IP substring match first to guarantee results show up
            cursor.execute(
                """
                SELECT r.id, r.platform, r.category, r.filename, r.name, r.data, d.name as device_name
                FROM records r
                JOIN devices d ON r.device_id = d.id
                WHERE r.name LIKE ? OR r.data LIKE ?
                LIMIT ?
                """,
                (search_term, search_term, limit)
            )
            
            for row in cursor.fetchall():
                if row["id"] not in seen_ids:
                    seen_ids.add(row["id"])
                    results.append({
                        "id": row["id"],
                        "platform": row["platform"],
                        "category": row["category"],
                        "filename": row["filename"],
                        "name": row["name"],
                        "device": row["device_name"],
                        "data": json.loads(row["data"]) if row["data"] else {}
                    })

            # 2. If it's a valid IP/CIDR, also pull via IP_CONTAINS to catch overlapping ranges
            ip_net = extract_ip_or_cidr(query)
            if ip_net and len(results) < limit:
                cursor.execute(
                    """
                    SELECT r.id, r.platform, r.category, r.filename, r.name, r.data, d.name as device_name
                    FROM records r
                    JOIN devices d ON r.device_id = d.id
                    WHERE IP_CONTAINS(?, r.data) = 1
                    LIMIT ?
                    """,
                    (query.strip(), limit)
                )
                for row in cursor.fetchall():
                    if row["id"] not in seen_ids:
                        seen_ids.add(row["id"])
                        results.append({
                            "id": row["id"],
                            "platform": row["platform"],
                            "category": row["category"],
                            "filename": row["filename"],
                            "name": row["name"],
                            "device": row["device_name"],
                            "data": json.loads(row["data"]) if row["data"] else {}
                        })

            conn.close()
            return {"query": query, "count": len(results), "results": results}
            
        except Exception as e:
            return {"error": str(e), "query": query, "count": 0, "results": []}

PANOS = InfrastructureDataSource()
