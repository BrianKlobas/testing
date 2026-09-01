#!/usr/bin/env python3
"""SQLite database helpers and shared infrastructure matching utilities."""
from __future__ import annotations

import ipaddress
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "infra_intel.db"


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
    """SQLite UDF: return 1 when target IP/network intersects the supplied network/range."""
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
                return int(
                    start <= target_net.network_address <= end
                    or start <= target_net.broadcast_address <= end
                )
            except ValueError:
                pass

    fw_net = extract_ip_or_cidr(val)
    if fw_net:
        try:
            return int(
                target_net.overlaps(fw_net)
                or target_net.subnet_of(fw_net)
                or fw_net.subnet_of(target_net)
            )
        except ValueError:
            return int(target_net.overlaps(fw_net))

    return 0


def extract_direct_attached_sg_ids(item: dict[str, Any]) -> set[str]:
    sg_ids: set[str] = set()

    groups = item.get("Groups") or item.get("SecurityGroups")
    if isinstance(groups, list):
        for group in groups:
            if isinstance(group, str) and group.startswith("sg-"):
                sg_ids.add(group)
            elif isinstance(group, dict):
                gid = group.get("GroupId") or group.get("VpcSecurityGroupId")
                if gid and str(gid).startswith("sg-"):
                    sg_ids.add(str(gid))

    network_interfaces = item.get("NetworkInterfaces")
    if isinstance(network_interfaces, list):
        for ni in network_interfaces:
            if not isinstance(ni, dict):
                continue
            ni_groups = ni.get("Groups") or ni.get("SecurityGroups")
            if not isinstance(ni_groups, list):
                continue
            for group in ni_groups:
                if isinstance(group, str) and group.startswith("sg-"):
                    sg_ids.add(group)
                elif isinstance(group, dict):
                    gid = group.get("GroupId") or group.get("VpcSecurityGroupId")
                    if gid and str(gid).startswith("sg-"):
                        sg_ids.add(str(gid))

    return sg_ids


def get_file_modified_time(filepath: Path) -> str:
    if filepath.exists():
        mtime = os.path.getmtime(filepath)
        return datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
    return "N/A"


def get_latest_dir_mtime(dirpath: Path) -> str:
    if not dirpath.exists():
        return "N/A"

    latest = 0.0
    for path in dirpath.rglob("*.json"):
        if path.is_file():
            mtime = os.path.getmtime(path)
            if mtime > latest:
                latest = mtime

    if latest > 0:
        return datetime.fromtimestamp(latest).strftime("%Y-%m-%d %H:%M:%S")
    return "N/A"


def get_db(db_file: Path | str | None = None) -> sqlite3.Connection:
    db_path = Path(db_file) if db_file is not None else DEFAULT_DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.create_function("IP_CONTAINS", 2, sqlite_ip_contains)
    return conn


def init_db(db_file: Path | str | None = None, reset: bool = False) -> None:
    """Create the database schema. Set reset=True for a clean full rebuild."""
    db_path = Path(db_file) if db_file is not None else DEFAULT_DB_PATH

    if reset and db_path.exists():
        db_path.unlink()

    conn = get_db(db_path)
    conn.executescript(
        """
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

        CREATE TRIGGER IF NOT EXISTS records_ai AFTER INSERT ON records BEGIN
            INSERT INTO records_fts(rowid, name, data)
            VALUES (new.id, new.name, new.data);
        END;
        """
    )
    conn.commit()
    conn.close()
