#!/usr/bin/env python3
"""Ingest the JSON produced by pa_parse.py and aws_resource_collect.py into SQLite."""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Iterator

from database import DEFAULT_DB_PATH, get_db, init_db, ip_hex, network_bounds

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_FW_DATA_ROOT = BASE_DIR / "parsed"
DEFAULT_AWS_DATA_ROOT = BASE_DIR / "aws_parsed"

AWS_REF_PATTERNS = {
    "instance": re.compile(r"^i-[0-9a-z]+$", re.I),
    "eni": re.compile(r"^eni-[0-9a-z]+$", re.I),
    "sg": re.compile(r"^sg-[0-9a-z]+$", re.I),
    "subnet": re.compile(r"^subnet-[0-9a-z]+$", re.I),
    "vpc": re.compile(r"^vpc-[0-9a-z]+$", re.I),
}

KEY_REF_TYPES = {
    "instanceid": "instance",
    "networkinterfaceid": "eni",
    "groupid": "sg",
    "vpcsecuritygroupid": "sg",
    "subnetid": "subnet",
    "vpcid": "vpc",
}

DNS_KEYS = {
    "name", "dnsname", "privatednsname", "publicdnsname", "fqdn",
    "recordname", "hostedzonename", "canonicalhostedzonename",
}


def json_candidates(data: Any) -> list[dict[str, Any]]:
    """The collectors write arrays of objects; also accept a single object."""
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    return []


def panos_record_name(item: dict[str, Any]) -> str:
    # pa_parse.py emits {name, path, object/rule/profile}.
    for value in (item.get("name"), item.get("@name")):
        if value:
            return str(value)
    for key in ("object", "rule", "profile", "entry"):
        value = item.get(key)
        if isinstance(value, dict):
            name = value.get("name") or value.get("@name")
            if name:
                return str(name)
    return ""


def aws_record_name(item: dict[str, Any]) -> str:
    # Match the actual describe/list output produced by aws_resource_collect.py.
    for key in (
        "InstanceId", "NetworkInterfaceId", "GroupId", "SubnetId", "VpcId",
        "DBInstanceIdentifier", "DBInstanceId", "LoadBalancerName",
        "LoadBalancerArn", "HostedZoneId", "Id", "Name",
    ):
        if item.get(key):
            value = str(item[key])
            return value.split("/")[-1] if value.startswith("arn:") else value

    # Route53 zone objects have Name and a nested ResourceRecordSets list.
    if item.get("Name"):
        return str(item["Name"])
    records = item.get("ResourceRecordSets")
    if isinstance(records, list) and records:
        first = records[0]
        if isinstance(first, dict) and first.get("Name"):
            return str(first["Name"])

    return str(item.get("GroupName") or "AWS-Resource")


def walk_scalars(obj: Any, path: str = "$") -> Iterator[tuple[str, str, str]]:
    """Yield (JSON path, key name, scalar value) for every scalar."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            child_path = f"{path}.{key}"
            if isinstance(value, (dict, list)):
                yield from walk_scalars(value, child_path)
            elif value is not None:
                yield child_path, str(key), str(value)
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            child_path = f"{path}[{i}]"
            if isinstance(value, (dict, list)):
                yield from walk_scalars(value, child_path)
            elif value is not None:
                yield child_path, "", str(value)


def classify_ref(key: str, value: str) -> str | None:
    key_norm = key.replace("-", "_").lower()
    compact = key_norm.replace("_", "")
    if key_norm in KEY_REF_TYPES:
        return KEY_REF_TYPES[key_norm]
    if compact in KEY_REF_TYPES:
        return KEY_REF_TYPES[compact]

    for ref_type, pattern in AWS_REF_PATTERNS.items():
        if pattern.match(value):
            return ref_type

    if value.startswith("arn:aws:"):
        return "arn"
    if key_norm in DNS_KEYS or compact in DNS_KEYS:
        return "dns"
    return None


def _network_type(value: str) -> str:
    if "-" in value and "/" not in value:
        try:
            a, b = value.split("-", 1)
            if ipaddress.ip_address(a.strip()).version == ipaddress.ip_address(b.strip()).version:
                return "range"
        except ValueError:
            pass
    return "network"


def index_record(cursor, record_id: int, item: dict[str, Any], record_name: str) -> tuple[int, int, int]:
    terms: set[tuple[str, str, str, str]] = set()
    refs: set[tuple[str, str, str]] = set()
    networks: set[tuple[int, str, str, str, str, str]] = set()

    if record_name:
        terms.add((record_name, record_name.lower(), "name", "$.name"))

    for json_path, key, raw_value in walk_scalars(item):
        value = raw_value.strip()
        if not value or len(value) > 4096:
            continue

        terms.add((value, value.lower(), "value", json_path))

        ref_type = classify_ref(key, value)
        if ref_type:
            refs.add((ref_type, value, json_path))

        bounds = network_bounds(value)
        if bounds:
            version, start, end = bounds
            networks.add((
                version,
                ip_hex(start),
                ip_hex(end),
                value,
                _network_type(value),
                json_path,
            ))

    cursor.executemany(
        "INSERT INTO record_terms(record_id,term,term_lower,term_type,json_path) VALUES(?,?,?,?,?)",
        [(record_id, *x) for x in terms],
    )
    cursor.executemany(
        "INSERT INTO record_refs(record_id,ref_type,ref_value,ref_value_lower,json_path) VALUES(?,?,?,?,?)",
        [(record_id, ref_type, value, value.lower(), path) for ref_type, value, path in refs],
    )
    cursor.executemany(
        """INSERT INTO record_networks(record_id,version,start_hex,end_hex,value,network_type,json_path)
           VALUES(?,?,?,?,?,?,?)""",
        [(record_id, *x) for x in networks],
    )
    return len(terms), len(networks), len(refs)


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _relative_device_for_pan(path: Path, root: Path) -> str:
    rel = path.relative_to(root)
    return rel.parts[0] if len(rel.parts) > 1 else "(root)"


def _relative_account_for_aws(path: Path, root: Path) -> str:
    rel = path.relative_to(root)
    return rel.parts[0] if rel.parts else "(root)"


def ingest_data(
    fw_root: Path = DEFAULT_FW_DATA_ROOT,
    aws_root: Path = DEFAULT_AWS_DATA_ROOT,
    db_file: Path = DEFAULT_DB_PATH,
    *,
    reset: bool = True,
) -> dict[str, int]:
    fw_root = Path(fw_root).resolve()
    aws_root = Path(aws_root).resolve()
    db_file = Path(db_file).resolve()

    init_db(db_file, reset=reset)
    conn = get_db(db_file)
    cursor = conn.cursor()

    counts = {
        "panos_files": 0,
        "panos_records": 0,
        "aws_files": 0,
        "aws_records": 0,
        "terms": 0,
        "networks": 0,
        "refs": 0,
        "bad_files": 0,
    }
    device_cache: dict[str, int] = {}

    def get_device_id(name: str) -> int:
        if name in device_cache:
            return device_cache[name]
        cursor.execute("INSERT OR IGNORE INTO devices(name) VALUES(?)", (name,))
        row = cursor.execute("SELECT id FROM devices WHERE name=?", (name,)).fetchone()
        if row is None:
            raise RuntimeError(f"Unable to create device '{name}'")
        device_cache[name] = int(row[0])
        return device_cache[name]

    def insert_record(device_id: int, platform: str, category: str, path: Path, name: str, item: dict[str, Any]) -> None:
        cursor.execute(
            "INSERT INTO records(device_id,platform,category,filename,name,data) VALUES(?,?,?,?,?,?)",
            (device_id, platform, category, path.name, name, json.dumps(item, separators=(",", ":"))),
        )
        rid = int(cursor.lastrowid)
        t, n, r = index_record(cursor, rid, item, name)
        counts["terms"] += t
        counts["networks"] += n
        counts["refs"] += r

    try:
        cursor.execute("BEGIN")

        # ------------------------------------------------------------
        # PAN-OS JSON generated by pa_parse.py
        # parsed/<device>/<object_type>.json
        # ------------------------------------------------------------
        if fw_root.exists():
            for path in sorted(fw_root.rglob("*.json")):
                if not path.is_file():
                    continue
                try:
                    data = _load_json(path)
                except Exception as exc:
                    counts["bad_files"] += 1
                    print(f"[!] PAN JSON skipped: {path} ({exc})")
                    continue

                candidates = json_candidates(data)
                counts["panos_files"] += 1
                rel = path.relative_to(fw_root)
                device = _relative_device_for_pan(path, fw_root)
                dev_id = get_device_id(device)
                category = path.stem.replace("-", "_").lower()

                for item in candidates:
                    insert_record(dev_id, "panos", category, path, panos_record_name(item), item)
                    counts["panos_records"] += 1

                if not candidates:
                    print(f"[!] PAN JSON contains no object records: {path} (relative: {rel})")

        # ------------------------------------------------------------
        # AWS JSON generated by aws_resource_collect.py
        # aws_parsed/<account>/<region-or-global>/<type>.json
        # ------------------------------------------------------------
        if aws_root.exists():
            for path in sorted(aws_root.rglob("*.json")):
                if not path.is_file():
                    continue
                try:
                    data = _load_json(path)
                except Exception as exc:
                    counts["bad_files"] += 1
                    print(f"[!] AWS JSON skipped: {path} ({exc})")
                    continue

                candidates = json_candidates(data)
                counts["aws_files"] += 1
                account = _relative_account_for_aws(path, aws_root)
                dev_id = get_device_id(f"AWS: {account}")
                category = path.stem.replace("-", "_").lower()

                for item in candidates:
                    insert_record(dev_id, "aws", category, path, aws_record_name(item), item)
                    counts["aws_records"] += 1

                if not candidates:
                    print(f"[!] AWS JSON contains no object records: {path}")

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Infrastructure Intelligence JSON -> SQLite ingest")
    parser.add_argument("--firewall-data", default=str(DEFAULT_FW_DATA_ROOT), help="Root produced by pa_parse.py")
    parser.add_argument("--aws-data", default=str(DEFAULT_AWS_DATA_ROOT), help="Root produced by aws_resource_collect.py")
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH))
    parser.add_argument("--no-reset", action="store_true", help="Append to the DB (normally use a full rebuild)")
    args = parser.parse_args()

    fw = Path(args.firewall_data)
    aws = Path(args.aws_data)
    db = Path(args.db)

    print("=" * 72)
    print("INFRASTRUCTURE INTELLIGENCE - JSON -> SQLITE INGEST")
    print("=" * 72)
    print(f"PAN JSON : {fw.resolve()} {'[FOUND]' if fw.exists() else '[NOT FOUND]'}")
    print(f"AWS JSON : {aws.resolve()} {'[FOUND]' if aws.exists() else '[NOT FOUND]'}")
    print(f"Database : {db.resolve()}")
    print(f"Mode     : {'append' if args.no_reset else 'FULL REBUILD'}")
    print()

    counts = ingest_data(fw, aws, db, reset=not args.no_reset)

    print("\n" + "-" * 72)
    print(f"PAN files/records : {counts['panos_files']:,} / {counts['panos_records']:,}")
    print(f"AWS files/records : {counts['aws_files']:,} / {counts['aws_records']:,}")
    print(f"Indexed terms     : {counts['terms']:,}")
    print(f"Indexed networks  : {counts['networks']:,}")
    print(f"Indexed refs      : {counts['refs']:,}")
    print(f"Bad JSON files    : {counts['bad_files']:,}")
    print(f"Database          : {db.resolve()}")
    print("-" * 72)


if __name__ == "__main__":
    main()
