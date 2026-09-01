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
DB_PATH = DEFAULT_DB_PATH

def parse_ip_network(value: str | None):
    """Parse an IP or CIDR into an IPv4Network/IPv6Network."""
    if not value:
        return None
    value = str(value).strip()
    try:
        if "/" in value:
            return ipaddress.ip_network(value, strict=False)
        ip = ipaddress.ip_address(value)
        return ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False)
    except (ValueError, TypeError):
        return None


def parse_ip_range(value: str | None):
    """Parse an inclusive start-end IP range, or return None."""
    if not value or "/" in str(value):
        return None
    parts = str(value).strip().split("-", 1)
    if len(parts) != 2:
        return None
    try:
        start = ipaddress.ip_address(parts[0].strip())
        end = ipaddress.ip_address(parts[1].strip())
    except (ValueError, TypeError):
        return None
    if start.version != end.version or int(start) > int(end):
        return None
    return start, end


def classify_ip_search(value: str | None) -> dict[str, Any]:
    """Classify a search as IPv4/IPv6 address, CIDR, range, or text."""
    raw = str(value or "").strip()
    if not raw:
        return {"type": "empty", "family": None, "value": raw}

    ip_range = parse_ip_range(raw)
    if ip_range:
        start, end = ip_range
        return {
            "type": "ipv4_range" if start.version == 4 else "ipv6_range",
            "family": start.version, "value": raw,
            "start": str(start), "end": str(end),
        }

    net = parse_ip_network(raw)
    if net:
        if net.prefixlen == net.max_prefixlen:
            kind = "ipv4" if net.version == 4 else "ipv6"
        else:
            kind = "ipv4_cidr" if net.version == 4 else "ipv6_cidr"
        return {
            "type": kind, "family": net.version, "value": raw,
            "network": net.compressed,
        }

    return {"type": "text", "family": None, "value": raw}


def networks_match(left: str | None, right: str | None) -> bool:
    """Overlap two IP/CIDR values, strictly ensuring same IP version."""
    left_net = parse_ip_network(left)
    right_net = parse_ip_network(right)
    if not left_net or not right_net:
        return False
    # Prevent IPv4 and IPv6 cross-family matching completely
    if left_net.version != right_net.version:
        return False
    return left_net.overlaps(right_net)


def value_matches_network_or_range(target: str | None, candidate: str | None) -> bool:
    """Safely match IP, CIDR, and IP-range values with strict IPv4/IPv6 isolation."""
    if not target or not candidate:
        return False

    target_range = parse_ip_range(target)
    candidate_range = parse_ip_range(candidate)

    # Enforce family matching for ranges
    if target_range and candidate_range:
        ts, te = target_range
        cs, ce = candidate_range
        if ts.version != cs.version:
            return False
        return not (int(te) < int(cs) or int(ts) > int(ce))

    if target_range:
        candidate_net = parse_ip_network(candidate)
        if not candidate_net or target_range[0].version != candidate_net.version:
            return False
        start, end = target_range
        return not (int(end) < int(candidate_net.network_address) or int(start) > int(candidate_net.broadcast_address))

    if candidate_range:
        target_net = parse_ip_network(target)
        if not target_net or target_net.version != candidate_range[0].version:
            return False
        start, end = candidate_range
        return not (int(target_net.broadcast_address) < int(start) or int(target_net.network_address) > int(end))

    return networks_match(target, candidate)


def sqlite_ip_contains(target_str: str, cidr_or_range_str: str) -> int:
    try:
        return int(value_matches_network_or_range(target_str, cidr_or_range_str))
    except (ValueError, TypeError):
        return 0


def extract_ip_or_cidr(value: str | None):
    """Backward-compatible name used by app.py."""
    return parse_ip_network(value)

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


def get_db(db_file: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    
    # Performance pragmas to eliminate locking and speed up reads/writes
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA cache_size = -64000;")  # Use ~64MB of memory for cache
    conn.execute("PRAGMA temp_store = MEMORY;")
    
    return conn


def init_db(db_file: Path = DEFAULT_DB_PATH, reset: bool = False) -> None:
    if reset and db_file.exists():
        db_file.unlink()

    conn = get_db(db_file)
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        );

        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            platform TEXT NOT NULL,
            category TEXT NOT NULL,
            filename TEXT NOT NULL,
            name TEXT,
            data TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        );

        CREATE INDEX IF NOT EXISTS idx_records_platform ON records(platform);
        CREATE INDEX IF NOT EXISTS idx_records_category ON records(category);
        CREATE INDEX IF NOT EXISTS idx_records_device ON records(device_id);

        -- Use external content FTS5 to keep search blazing fast and lightweight
        CREATE VIRTUAL TABLE IF NOT EXISTS records_fts USING fts5(
            name, 
            data, 
            content='records', 
            content_rowid='id'
        );

        -- Triggers to automatically keep FTS index updated during ingest
        CREATE TRIGGER IF NOT EXISTS records_ai AFTER INSERT ON records BEGIN
            INSERT INTO records_fts(rowid, name, data) VALUES (new.id, new.name, new.data);
        END;

        CREATE TRIGGER IF NOT EXISTS records_ad AFTER DELETE ON records BEGIN
            INSERT INTO records_fts(records_fts, rowid, name, data) VALUES('delete', old.id, old.name, old.data);
        END;
    """)
    conn.commit()
    conn.close()
