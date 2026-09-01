#!/usr/bin/env python3
"""SQLite schema and shared matching helpers for Infrastructure Intelligence."""
from __future__ import annotations

import ipaddress
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = BASE_DIR / "infra_intel.db"


def parse_ip_network(value: str | None):
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
    raw = str(value or "").strip()
    if not raw:
        return {"type": "empty", "family": None, "value": raw}

    ip_range = parse_ip_range(raw)
    if ip_range:
        start, end = ip_range
        return {
            "type": "ipv4_range" if start.version == 4 else "ipv6_range",
            "family": start.version,
            "value": raw,
            "start": str(start),
            "end": str(end),
        }

    net = parse_ip_network(raw)
    if net:
        if net.prefixlen == net.max_prefixlen:
            kind = "ipv4" if net.version == 4 else "ipv6"
        else:
            kind = "ipv4_cidr" if net.version == 4 else "ipv6_cidr"
        return {
            "type": kind,
            "family": net.version,
            "value": raw,
            "network": net.compressed,
        }

    return {"type": "text", "family": None, "value": raw}


def network_bounds(value: str | None):
    """Return (version, first_ip, last_ip) for an IP, CIDR, or inclusive range."""
    ip_range = parse_ip_range(value)
    if ip_range:
        return ip_range[0].version, ip_range[0], ip_range[1]
    net = parse_ip_network(value)
    if net:
        return net.version, net.network_address, net.broadcast_address
    return None


def ip_hex(address: Any) -> str:
    """Fixed-width hex permits safe lexicographic IPv4/IPv6 range comparisons."""
    return f"{int(address):032x}"


def value_matches_network_or_range(left: str | None, right: str | None) -> bool:
    lb = network_bounds(left)
    rb = network_bounds(right)
    if not lb or not rb or lb[0] != rb[0]:
        return False
    return not (int(lb[2]) < int(rb[1]) or int(lb[1]) > int(rb[2]))


def sqlite_ip_contains(left: str, right: str) -> int:
    """SQLite-safe IP/CIDR overlap test; IPv4 and IPv6 never cross-compare."""
    try:
        return int(value_matches_network_or_range(left, right))
    except (ValueError, TypeError):
        return 0


def extract_ip_or_cidr(value: str | None):
    return parse_ip_network(value)


def extract_direct_attached_sg_ids(item: dict[str, Any]) -> set[str]:
    """Return SGs directly attached to a resource/ENI, not SG rule references."""
    sg_ids: set[str] = set()

    def consume(groups: Any) -> None:
        if not isinstance(groups, list):
            return
        for group in groups:
            if isinstance(group, str) and group.startswith("sg-"):
                sg_ids.add(group)
            elif isinstance(group, dict):
                gid = group.get("GroupId") or group.get("VpcSecurityGroupId")
                if gid and str(gid).startswith("sg-"):
                    sg_ids.add(str(gid))

    consume(item.get("Groups"))
    consume(item.get("SecurityGroups"))

    # EC2 responses can also contain network interfaces with their own Groups.
    nis = item.get("NetworkInterfaces")
    if isinstance(nis, list):
        for ni in nis:
            if isinstance(ni, dict):
                consume(ni.get("Groups"))
                consume(ni.get("SecurityGroups"))

    return sg_ids


def get_file_modified_time(filepath: Path) -> str:
    if filepath.exists():
        return datetime.fromtimestamp(os.path.getmtime(filepath)).strftime("%Y-%m-%d %H:%M:%S")
    return "N/A"


def get_latest_dir_mtime(dirpath: Path) -> str:
    if not dirpath.exists():
        return "N/A"
    latest = max((os.path.getmtime(p) for p in dirpath.rglob("*.json") if p.is_file()), default=0.0)
    return datetime.fromtimestamp(latest).strftime("%Y-%m-%d %H:%M:%S") if latest else "N/A"


def get_db(db_file: Path | str | None = None) -> sqlite3.Connection:
    db_path = Path(db_file) if db_file is not None else DEFAULT_DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=60)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA cache_size=-64000")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.create_function("IP_CONTAINS", 2, sqlite_ip_contains)
    return conn


def init_db(db_file: Path | str | None = None, reset: bool = False) -> None:
    db_path = Path(db_file) if db_file is not None else DEFAULT_DB_PATH
    if reset and db_path.exists():
        # WAL mode can leave sidecar files behind. SQLite recreates the DB cleanly.
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(db_path) + suffix)
            try:
                if p.exists():
                    p.unlink()
            except OSError:
                pass

    conn = get_db(db_path)
    try:
        conn.executescript(
            """
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
                FOREIGN KEY(device_id) REFERENCES devices(id)
            );

            CREATE INDEX IF NOT EXISTS idx_records_platform ON records(platform);
            CREATE INDEX IF NOT EXISTS idx_records_category ON records(category);
            CREATE INDEX IF NOT EXISTS idx_records_device ON records(device_id);
            CREATE INDEX IF NOT EXISTS idx_records_name ON records(name);

            CREATE VIRTUAL TABLE IF NOT EXISTS records_fts USING fts5(
                name, data, content='records', content_rowid='id'
            );

            CREATE TRIGGER IF NOT EXISTS records_ai AFTER INSERT ON records BEGIN
                INSERT INTO records_fts(rowid, name, data) VALUES(new.id, new.name, new.data);
            END;
            CREATE TRIGGER IF NOT EXISTS records_ad AFTER DELETE ON records BEGIN
                INSERT INTO records_fts(records_fts, rowid, name, data)
                VALUES('delete', old.id, old.name, old.data);
            END;
            CREATE TRIGGER IF NOT EXISTS records_au AFTER UPDATE ON records BEGIN
                INSERT INTO records_fts(records_fts, rowid, name, data)
                VALUES('delete', old.id, old.name, old.data);
                INSERT INTO records_fts(rowid, name, data) VALUES(new.id, new.name, new.data);
            END;

            CREATE TABLE IF NOT EXISTS record_terms (
                record_id INTEGER NOT NULL,
                term TEXT NOT NULL,
                term_lower TEXT NOT NULL,
                term_type TEXT NOT NULL DEFAULT 'value',
                json_path TEXT,
                FOREIGN KEY(record_id) REFERENCES records(id)
            );
            CREATE INDEX IF NOT EXISTS idx_terms_lower ON record_terms(term_lower);
            CREATE INDEX IF NOT EXISTS idx_terms_type_value ON record_terms(term_type, term_lower);
            CREATE INDEX IF NOT EXISTS idx_terms_record ON record_terms(record_id);

            CREATE TABLE IF NOT EXISTS record_networks (
                record_id INTEGER NOT NULL,
                version INTEGER NOT NULL,
                start_hex TEXT NOT NULL,
                end_hex TEXT NOT NULL,
                value TEXT NOT NULL,
                network_type TEXT NOT NULL DEFAULT 'network',
                json_path TEXT,
                FOREIGN KEY(record_id) REFERENCES records(id)
            );
            CREATE INDEX IF NOT EXISTS idx_network_version_bounds
                ON record_networks(version, start_hex, end_hex);
            CREATE INDEX IF NOT EXISTS idx_network_record ON record_networks(record_id);

            CREATE TABLE IF NOT EXISTS record_refs (
                record_id INTEGER NOT NULL,
                ref_type TEXT NOT NULL,
                ref_value TEXT NOT NULL,
                ref_value_lower TEXT NOT NULL,
                json_path TEXT,
                FOREIGN KEY(record_id) REFERENCES records(id)
            );
            CREATE INDEX IF NOT EXISTS idx_refs_type_value ON record_refs(ref_type, ref_value_lower);
            CREATE INDEX IF NOT EXISTS idx_refs_value ON record_refs(ref_value_lower);
            CREATE INDEX IF NOT EXISTS idx_refs_record ON record_refs(record_id);
            """
        )
        conn.commit()
    finally:
        conn.close()


def find_network_record_ids(
    conn: sqlite3.Connection,
    value: str,
    *,
    platform: str | None = None,
    limit: int = 2000,
) -> list[int]:
    bounds = network_bounds(value)
    if not bounds:
        return []
    version, start, end = bounds
    sql = """
        SELECT DISTINCT rn.record_id
        FROM record_networks rn
        JOIN records r ON r.id = rn.record_id
        WHERE rn.version = ?
          AND rn.start_hex <= ?
          AND rn.end_hex >= ?
    """
    params: list[Any] = [version, ip_hex(end), ip_hex(start)]
    if platform:
        sql += " AND r.platform = ?"
        params.append(platform)
    sql += " LIMIT ?"
    params.append(limit)
    return [int(row[0]) for row in conn.execute(sql, params).fetchall()]


def fetch_records_by_ids(conn: sqlite3.Connection, record_ids: Iterable[int]) -> list[sqlite3.Row]:
    ids = list(dict.fromkeys(int(x) for x in record_ids))
    if not ids:
        return []
    placeholders = ",".join("?" for _ in ids)
    return conn.execute(
        f"""
        SELECT r.id, d.name AS device, r.platform, r.category, r.filename, r.name, r.data
        FROM records r
        JOIN devices d ON d.id = r.device_id
        WHERE r.id IN ({placeholders})
        """,
        ids,
    ).fetchall()
