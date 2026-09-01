from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import re
from datetime import datetime
from pathlib import Path
from typing import Any

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

def extract_direct_attached_sg_ids(item: dict[str, Any]) -> set[str]:
    sg_ids = set()
    groups = item.get("Groups") or item.get("SecurityGroups")
    if isinstance(groups, list):
        for g in groups:
            if isinstance(g, str) and g.startswith("sg-"):
                sg_ids.add(g)
            elif isinstance(g, dict):
                gid = g.get("GroupId") or g.get("VpcSecurityGroupId")
                if gid and str(gid).startswith("sg-"):
                    sg_ids.add(str(gid))
    nis = item.get("NetworkInterfaces")
    if isinstance(nis, list):
        for ni in nis:
            if isinstance(ni, dict):
                ni_groups = ni.get("Groups") or ni.get("SecurityGroups")
                if isinstance(ni_groups, list):
                    for g in ni_groups:
                        if isinstance(g, str) and g.startswith("sg-"):
                            sg_ids.add(g)
                        elif isinstance(g, dict):
                            gid = g.get("GroupId") or g.get("VpcSecurityGroupId")
                            if gid and str(gid).startswith("sg-"):
                                sg_ids.add(str(gid))
    return sg_ids

def get_db(db_file: Path | None = None):
    db_file = db_file or DB_PATH
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    conn.create_function("IP_CONTAINS", 2, sqlite_ip_contains)
    return conn

class InfrastructureDataSource:
    def __init__(self, db_file: Path | None = None):
        self._db_file = db_file

    @property
    def db_file(self) -> Path:
        return self._db_file if self._db_file is not None else DB_PATH

    def get_stats(self) -> dict[str, Any]:
        conn = get_db(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT category, COUNT(*) as cnt FROM records WHERE platform='panos' GROUP BY category")
        panos_counts = {row["category"]: row["cnt"] for row in cursor.fetchall()}
        cursor.execute("SELECT category, COUNT(*) as cnt FROM records WHERE platform='aws' GROUP BY category")
        aws_summary = {row["category"]: row["cnt"] for row in cursor.fetchall()}
        cursor.execute("SELECT COUNT(DISTINCT name) FROM devices WHERE name LIKE 'AWS:%'")
        aws_accounts_count = cursor.fetchone()[0]
        conn.close()
        return {
            "panos": panos_counts,
            "aws_resources": aws_summary,
            "aws_accounts_scanned": aws_accounts_count,
            "total_files": self.files_count()
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
        # (Include the full investigate method logic from the original monolith here)
        pass

PANOS = InfrastructureDataSource()
