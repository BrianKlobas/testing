```python
#!/usr/bin/env python3

"""
infra_intel/database.py

SQLite database layer and network matching utilities.

This file contains:
    - SQLite connection/schema creation
    - IPv4 / IPv6 parsing
    - CIDR containment
    - IP-range matching
    - database helper functions

It intentionally contains no Flask code.
"""

from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "infra_intel.db"


# ============================================================
# IP / NETWORK HELPERS
# ============================================================

def parse_ip(value: Any):
    """
    Parse a single IP address.

    Returns:
        IPv4Address / IPv6Address
        None if invalid
    """
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def parse_network(value: Any):
    """
    Parse:
        10.1.2.3
        10.1.2.0/24
        2001:db8::1
        2001:db8::/64

    A single IP becomes a /32 or /128 network.

    Returns:
        IPv4Network / IPv6Network
        None if invalid
    """
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    try:
        if "/" in value:
            return ipaddress.ip_network(value, strict=False)

        ip = ipaddress.ip_address(value)

        if ip.version == 4:
            return ipaddress.ip_network(f"{ip}/32", strict=False)

        return ipaddress.ip_network(f"{ip}/128", strict=False)

    except ValueError:
        return None


def parse_range(value: Any):
    """
    Parse:
        10.1.1.1-10.1.1.20
        2001:db8::1-2001:db8::20

    Returns:
        (start, end)

    IPv4/IPv6 mismatches return None.
    """
    if value is None:
        return None

    value = str(value).strip()

    if "/" in value or "-" not in value:
        return None

    left, right = value.split("-", 1)

    try:
        start = ipaddress.ip_address(left.strip())
        end = ipaddress.ip_address(right.strip())

        if start.version != end.version:
            return None

        if int(start) > int(end):
            return None

        return start, end

    except ValueError:
        return None


def classify_network(value: Any) -> dict:
    """
    Classify an input.

    Returns something like:

        {
            "type": "ipv4",
            "family": 4,
            "network": "10.1.2.3/32"
        }

    or:

        {
            "type": "ipv4_cidr",
            "family": 4,
            "network": "10.1.2.0/24"
        }
    """

    raw = str(value or "").strip()

    if not raw:
        return {
            "type": "empty",
            "family": None,
            "network": None,
        }

    ip_range = parse_range(raw)

    if ip_range:
        start, end = ip_range

        return {
            "type": "ipv4_range" if start.version == 4 else "ipv6_range",
            "family": start.version,
            "network": None,
            "start": str(start),
            "end": str(end),
        }

    network = parse_network(raw)

    if network:
        if network.prefixlen == network.max_prefixlen:
            kind = "ipv4" if network.version == 4 else "ipv6"
        else:
            kind = "ipv4_cidr" if network.version == 4 else "ipv6_cidr"

        return {
            "type": kind,
            "family": network.version,
            "network": str(network),
        }

    return {
        "type": "text",
        "family": None,
        "network": None,
    }


def networks_overlap(left: Any, right: Any) -> bool:
    """
    Safely determine whether two IP/CIDR values overlap.

    IMPORTANT:
        IPv4 is never compared with IPv6.
    """

    a = parse_network(left)
    b = parse_network(right)

    if not a or not b:
        return False

    if a.version != b.version:
        return False

    return a.overlaps(b)


def network_contains(container: Any, target: Any) -> bool:
    """
    True when container includes target.

    Examples:

        10.0.0.0/16 contains 10.0.1.5
        10.0.0.0/16 contains 10.0.1.0/24

    IPv4/IPv6 mismatches safely return False.
    """

    a = parse_network(container)
    b = parse_network(target)

    if not a or not b:
        return False

    if a.version != b.version:
        return False

    return b.subnet_of(a)


def network_is_within(target: Any, container: Any) -> bool:
    """Alias for network_contains(container, target)."""
    return network_contains(container, target)


def range_overlaps_network(range_value: Any, network_value: Any) -> bool:
    """
    Determine whether an IP range overlaps an IP/CIDR.
    """

    parsed_range = parse_range(range_value)
    network = parse_network(network_value)

    if not parsed_range or not network:
        return False

    start, end = parsed_range

    if start.version != network.version:
        return False

    network_start = int(network.network_address)
    network_end = int(network.broadcast_address)

    return not (
        int(end) < network_start
        or int(start) > network_end
    )


def values_match(left: Any, right: Any) -> bool:
    """
    General IP/CIDR/range matching function.

    Handles:
        IP ↔ IP
        IP ↔ CIDR
        CIDR ↔ CIDR
        IP ↔ range
        CIDR ↔ range
        range ↔ range
    """

    if not left or not right:
        return False

    left_range = parse_range(left)
    right_range = parse_range(right)

    # range ↔ range
    if left_range and right_range:
        a1, a2 = left_range
        b1, b2 = right_range

        if a1.version != b1.version:
            return False

        return not (
            int(a2) < int(b1)
            or int(a1) > int(b2)
        )

    # range ↔ network
    if left_range:
        return range_overlaps_network(left, right)

    if right_range:
        return range_overlaps_network(right, left)

    # network ↔ network
    return networks_overlap(left, right)


def sqlite_ip_match(search_value: str, candidate_value: str) -> int:
    """
    SQLite UDF.

    Example:

        SELECT *
        FROM network_index
        WHERE IP_MATCH(?, value) = 1
    """

    try:
        return 1 if values_match(search_value, candidate_value) else 0
    except Exception:
        return 0


# ============================================================
# DATABASE
# ============================================================

def connect(db_path: Path | str = DEFAULT_DB) -> sqlite3.Connection:
    db_path = Path(db_path)

    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))

    conn.row_factory = sqlite3.Row

    conn.create_function(
        "IP_MATCH",
        2,
        sqlite_ip_match,
    )

    return conn


def initialize_database(
    db_path: Path | str = DEFAULT_DB,
    reset: bool = False,
):
    """
    Create all database tables.

    reset=True completely rebuilds the database.
    """

    db_path = Path(db_path)

    if reset and db_path.exists():
        db_path.unlink()

    conn = connect(db_path)

    conn.executescript(
        """
        PRAGMA journal_mode=WAL;

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

            FOREIGN KEY(device_id)
                REFERENCES devices(id)
        );

        CREATE INDEX IF NOT EXISTS idx_records_name
            ON records(name);

        CREATE INDEX IF NOT EXISTS idx_records_category
            ON records(category);

        CREATE INDEX IF NOT EXISTS idx_records_platform
            ON records(platform);


        /*
         * Generic searchable terms.
         *
         * This allows reverse lookup without having to search
         * every JSON blob every time.
         */
        CREATE TABLE IF NOT EXISTS search_index (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            record_id INTEGER NOT NULL,

            term TEXT NOT NULL,

            term_type TEXT,

            normalized TEXT,

            FOREIGN KEY(record_id)
                REFERENCES records(id)
        );

        CREATE INDEX IF NOT EXISTS idx_search_term
            ON search_index(term);

        CREATE INDEX IF NOT EXISTS idx_search_normalized
            ON search_index(normalized);

        CREATE INDEX IF NOT EXISTS idx_search_type
            ON search_index(term_type);


        /*
         * IP/CIDR/range values extracted during ingest.
         */
        CREATE TABLE IF NOT EXISTS network_index (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            record_id INTEGER NOT NULL,

            value TEXT NOT NULL,

            family INTEGER NOT NULL,

            value_type TEXT,

            context TEXT,

            source_field TEXT,

            FOREIGN KEY(record_id)
                REFERENCES records(id)
        );

        CREATE INDEX IF NOT EXISTS idx_network_family
            ON network_index(family);

        CREATE INDEX IF NOT EXISTS idx_network_value
            ON network_index(value);

        CREATE INDEX IF NOT EXISTS idx_network_record
            ON network_index(record_id);


        /*
         * AWS relationships.
         *
         * This is intentionally explicit rather than hidden
         * inside JSON.
         */
        CREATE TABLE IF NOT EXISTS aws_resources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            record_id INTEGER,

            account_id TEXT,
            account_name TEXT,

            region TEXT,

            resource_type TEXT,
            resource_id TEXT,

            instance_id TEXT,
            eni_id TEXT,

            private_ip TEXT,
            public_ip TEXT,

            subnet_id TEXT,
            vpc_id TEXT,

            subnet_cidr TEXT,
            vpc_cidr TEXT,

            FOREIGN KEY(record_id)
                REFERENCES records(id)
        );

        CREATE INDEX IF NOT EXISTS idx_aws_resource_id
            ON aws_resources(resource_id);

        CREATE INDEX IF NOT EXISTS idx_aws_instance
            ON aws_resources(instance_id);

        CREATE INDEX IF NOT EXISTS idx_aws_eni
            ON aws_resources(eni_id);

        CREATE INDEX IF NOT EXISTS idx_aws_ip
            ON aws_resources(private_ip);

        CREATE INDEX IF NOT EXISTS idx_aws_subnet
            ON aws_resources(subnet_id);

        CREATE INDEX IF NOT EXISTS idx_aws_vpc
            ON aws_resources(vpc_id);


        /*
         * Direct SG attachments only.
         */
        CREATE TABLE IF NOT EXISTS aws_security_group_attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            aws_resource_id INTEGER NOT NULL,

            sg_id TEXT NOT NULL,

            attachment_type TEXT,

            FOREIGN KEY(aws_resource_id)
                REFERENCES aws_resources(id)
        );

        CREATE INDEX IF NOT EXISTS idx_aws_sg
            ON aws_security_group_attachments(sg_id);

        CREATE INDEX IF NOT EXISTS idx_aws_sg_resource
            ON aws_security_group_attachments(aws_resource_id);


        /*
         * Security group data/rules.
         */
        CREATE TABLE IF NOT EXISTS security_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            record_id INTEGER,

            sg_id TEXT,

            name TEXT,

            vpc_id TEXT,

            description TEXT,

            FOREIGN KEY(record_id)
                REFERENCES records(id)
        );

        CREATE INDEX IF NOT EXISTS idx_security_groups_id
            ON security_groups(sg_id);


        CREATE TABLE IF NOT EXISTS security_group_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            security_group_id INTEGER,

            direction TEXT,

            protocol TEXT,

            from_port INTEGER,
            to_port INTEGER,

            cidr TEXT,

            referenced_sg TEXT,

            description TEXT,

            FOREIGN KEY(security_group_id)
                REFERENCES security_groups(id)
        );

        CREATE INDEX IF NOT EXISTS idx_sg_rules_cidr
            ON security_group_rules(cidr);


        /*
         * PAN-OS objects.
         */
        CREATE TABLE IF NOT EXISTS palo_objects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            record_id INTEGER,

            device_id INTEGER,

            object_type TEXT,

            name TEXT,

            value TEXT,

            description TEXT,

            FOREIGN KEY(record_id)
                REFERENCES records(id),

            FOREIGN KEY(device_id)
                REFERENCES devices(id)
        );

        CREATE INDEX IF NOT EXISTS idx_palo_objects_name
            ON palo_objects(name);

        CREATE INDEX IF NOT EXISTS idx_palo_objects_value
            ON palo_objects(value);


        /*
         * PAN-OS object group membership.
         */
        CREATE TABLE IF NOT EXISTS palo_group_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            group_record_id INTEGER,

            group_name TEXT,

            member_name TEXT,

            member_type TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_palo_group_name
            ON palo_group_members(group_name);

        CREATE INDEX IF NOT EXISTS idx_palo_group_member
            ON palo_group_members(member_name);


        /*
         * PAN-OS rules.
         */
        CREATE TABLE IF NOT EXISTS palo_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            record_id INTEGER,

            device_id INTEGER,

            rule_name TEXT,

            rule_type TEXT,

            source TEXT,

            destination TEXT,

            service TEXT,

            application TEXT,

            action TEXT,

            disabled INTEGER DEFAULT 0,

            description TEXT,

            FOREIGN KEY(record_id)
                REFERENCES records(id),

            FOREIGN KEY(device_id)
                REFERENCES devices(id)
        );

        CREATE INDEX IF NOT EXISTS idx_palo_rule_name
            ON palo_rules(rule_name);

        CREATE INDEX IF NOT EXISTS idx_palo_rule_action
            ON palo_rules(action);


        /*
         * Panorama/device relationship.
         */
        CREATE TABLE IF NOT EXISTS palo_device_relationships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            device_id INTEGER,

            panorama_group TEXT,

            template_group TEXT,

            firewall_name TEXT,

            firewall_serial TEXT
        );
        """
    )

    conn.commit()
    conn.close()


# ============================================================
# FILE MTIME HELPERS
# ============================================================

def file_mtime(path: Path | str) -> str:
    path = Path(path)

    if not path.exists():
        return "N/A"

    return datetime.fromtimestamp(
        os.path.getmtime(path)
    ).strftime("%Y-%m-%d %H:%M:%S")


def latest_json_mtime(directory: Path | str) -> str:
    directory = Path(directory)

    if not directory.exists():
        return "N/A"

    latest = 0

    for path in directory.rglob("*.json"):
        if path.is_file():
            latest = max(
                latest,
                os.path.getmtime(path),
            )

    if not latest:
        return "N/A"

    return datetime.fromtimestamp(
        latest
    ).strftime("%Y-%m-%d %H:%M:%S")
```
