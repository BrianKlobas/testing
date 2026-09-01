```python
#!/usr/bin/env python3

"""
infra_intel/ingest.py

Standalone JSON -> SQLite ingestion.

Run independently whenever the source JSON changes:

    python ingest.py

Optional:

    python ingest.py --reset
    python ingest.py --firewall-data ./parsed
    python ingest.py --aws-data ./aws_parsed
    python ingest.py --db ./infra_intel.db
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from database import (
    DEFAULT_DB,
    classify_network,
    connect,
    initialize_database,
)


BASE_DIR = Path(__file__).resolve().parent

DEFAULT_FIREWALL_DIR = BASE_DIR / "parsed"
DEFAULT_AWS_DIR = BASE_DIR / "aws_parsed"


# ============================================================
# GENERAL HELPERS
# ============================================================

def json_text(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def normalize_term(value: Any) -> str:
    return str(value).strip().lower()


def insert_record(
    conn,
    *,
    device_id=None,
    platform="",
    category="",
    filename="",
    name="",
    data=None,
) -> int:

    cur = conn.execute(
        """
        INSERT INTO records
        (
            device_id,
            platform,
            category,
            filename,
            name,
            data
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            device_id,
            platform,
            category,
            filename,
            name,
            json_text(data if data is not None else {}),
        ),
    )

    return cur.lastrowid


def add_term(
    conn,
    record_id: int,
    value: Any,
    term_type: str,
):
    if value is None:
        return

    if isinstance(value, (dict, list)):
        return

    value = str(value).strip()

    if not value:
        return

    conn.execute(
        """
        INSERT INTO search_index
        (
            record_id,
            term,
            term_type,
            normalized
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            record_id,
            value,
            term_type,
            normalize_term(value),
        ),
    )


def add_network(
    conn,
    record_id: int,
    value: Any,
    context: str,
    source_field: str,
):
    if value is None:
        return

    value = str(value).strip()

    if not value:
        return

    info = classify_network(value)

    if info["family"] not in (4, 6):
        return

    if info["type"].endswith("_range"):
        network_value = f"{info['start']}-{info['end']}"
    else:
        network_value = info["network"]

    conn.execute(
        """
        INSERT INTO network_index
        (
            record_id,
            value,
            family,
            value_type,
            context,
            source_field
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            record_id,
            network_value,
            info["family"],
            info["type"],
            context,
            source_field,
        ),
    )


def walk_scalars(value: Any, path=""):
    """
    Recursively extract scalar JSON values.

    Used as a generic safety net so arbitrary fields are searchable.
    """

    if isinstance(value, dict):

        for key, child in value.items():

            child_path = (
                f"{path}.{key}"
                if path
                else key
            )

            yield from walk_scalars(
                child,
                child_path,
            )

    elif isinstance(value, list):

        for index, child in enumerate(value):

            child_path = (
                f"{path}[{index}]"
            )

            yield from walk_scalars(
                child,
                child_path,
            )

    else:
        yield path, value


# ============================================================
# AWS
# ============================================================

def find_first(obj: dict, *keys):
    for key in keys:
        if key in obj and obj[key] not in (None, ""):
            return obj[key]

    return None


def extract_sg_ids(obj: dict) -> list[str]:
    """
    Extract ONLY directly attached SGs.

    No inferred SG relationships are added here.
    """

    found = []

    groups = find_first(
        obj,
        "Groups",
        "SecurityGroups",
        "security_groups",
    )

    if isinstance(groups, list):

        for group in groups:

            if isinstance(group, str):
                if group.startswith("sg-"):
                    found.append(group)

            elif isinstance(group, dict):

                gid = find_first(
                    group,
                    "GroupId",
                    "groupId",
                    "VpcSecurityGroupId",
                )

                if gid:
                    found.append(str(gid))

    return sorted(set(found))


def ingest_aws_file(conn, path: Path):
    print(f"[AWS] {path}")

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as fh:
            payload = json.load(fh)

    except Exception as exc:
        print(f"  ERROR: {exc}")
        return 0

    count = 0

    if isinstance(payload, list):
        records = payload

    elif isinstance(payload, dict):

        # Most AWS exports are either a list or a wrapper.
        for key in (
            "Resources",
            "resources",
            "Instances",
            "instances",
            "NetworkInterfaces",
            "network_interfaces",
            "Data",
            "data",
        ):
            if isinstance(payload.get(key), list):
                records = payload[key]
                break
        else:
            records = [payload]

    else:
        records = []

    for item in records:

        if not isinstance(item, dict):
            continue

        resource_type = str(
            find_first(
                item,
                "ResourceType",
                "resource_type",
                "Type",
                "type",
            )
            or ""
        )

        resource_id = find_first(
            item,
            "ResourceId",
            "resource_id",
            "Id",
            "id",
        )

        instance_id = find_first(
            item,
            "InstanceId",
            "instance_id",
        )

        eni_id = find_first(
            item,
            "NetworkInterfaceId",
            "NetworkInterface",
            "eni_id",
            "EniId",
        )

        private_ip = find_first(
            item,
            "PrivateIpAddress",
            "PrivateIP",
            "private_ip",
            "privateIp",
        )

        public_ip = find_first(
            item,
            "PublicIpAddress",
            "PublicIP",
            "public_ip",
            "publicIp",
        )

        subnet_id = find_first(
            item,
            "SubnetId",
            "subnet_id",
        )

        vpc_id = find_first(
            item,
            "VpcId",
            "VPCId",
            "vpc_id",
        )

        subnet_cidr = find_first(
            item,
            "SubnetCidr",
            "SubnetCIDR",
            "SubnetCidrBlock",
            "subnet_cidr",
            "subnetCidr",
        )

        vpc_cidr = find_first(
            item,
            "VpcCidr",
            "VpcCIDR",
            "VpcCidrBlock",
            "vpc_cidr",
            "vpcCidr",
        )

        account_id = find_first(
            item,
            "AccountId",
            "account_id",
        )

        account_name = find_first(
            item,
            "AccountName",
            "account_name",
        )

        region = find_first(
            item,
            "Region",
            "region",
        )

        display_name = (
            instance_id
            or eni_id
            or resource_id
            or private_ip
            or "AWS resource"
        )

        record_id = insert_record(
            conn,
            platform="AWS",
            category=resource_type or "resource",
            filename=str(path),
            name=str(display_name),
            data=item,
        )

        # Generic search index
        for field, value in walk_scalars(item):

            field_lower = field.lower()

            if any(
                x in field_lower
                for x in (
                    "id",
                    "name",
                    "dns",
                    "hostname",
                    "address",
                    "arn",
                    "cidr",
                    "ip",
                    "resource",
                )
            ):
                add_term(
                    conn,
                    record_id,
                    value,
                    field,
                )

        # Explicit important identifiers
        for value, kind in (
            (resource_id, "resource_id"),
            (instance_id, "instance_id"),
            (eni_id, "eni_id"),
            (subnet_id, "subnet_id"),
            (vpc_id, "vpc_id"),
            (account_id, "account_id"),
            (account_name, "account_name"),
            (region, "region"),
        ):
            add_term(
                conn,
                record_id,
                value,
                kind,
            )

        for value, field in (
            (private_ip, "private_ip"),
            (public_ip, "public_ip"),
            (subnet_cidr, "subnet_cidr"),
            (vpc_cidr, "vpc_cidr"),
        ):
            add_network(
                conn,
                record_id,
                value,
                "AWS",
                field,
            )

        cur = conn.execute(
            """
            INSERT INTO aws_resources
            (
                record_id,
                account_id,
                account_name,
                region,
                resource_type,
                resource_id,
                instance_id,
                eni_id,
                private_ip,
                public_ip,
                subnet_id,
                vpc_id,
                subnet_cidr,
                vpc_cidr
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record_id,
                account_id,
                account_name,
                region,
                resource_type,
                resource_id,
                instance_id,
                eni_id,
                private_ip,
                public_ip,
                subnet_id,
                vpc_id,
                subnet_cidr,
                vpc_cidr,
            ),
        )

        aws_resource_id = cur.lastrowid

        # DIRECT SG ATTACHMENTS ONLY
        for sg_id in extract_sg_ids(item):

            conn.execute(
                """
                INSERT INTO aws_security_group_attachments
                (
                    aws_resource_id,
                    sg_id,
                    attachment_type
                )
                VALUES (?, ?, ?)
                """,
                (
                    aws_resource_id,
                    sg_id,
                    "direct",
                ),
            )

            add_term(
                conn,
                record_id,
                sg_id,
                "direct_security_group",
            )

        count += 1

    return count


def ingest_aws_directory(conn, directory: Path):

    if not directory.exists():
        print(f"[AWS] Directory does not exist: {directory}")
        return

    total = 0

    for path in sorted(
        directory.rglob("*.json")
    ):
        total += ingest_aws_file(
            conn,
            path,
        )

    print(f"[AWS] Indexed {total} resources")


# ============================================================
# PAN-OS
# ============================================================

def find_pan_device(conn, name: str):

    if not name:
        return None

    cur = conn.execute(
        """
        SELECT id
        FROM devices
        WHERE name = ?
        """,
        (name,),
    )

    row = cur.fetchone()

    if row:
        return row["id"]

    cur = conn.execute(
        """
        INSERT INTO devices(name)
        VALUES (?)
        """,
        (name,),
    )

    return cur.lastrowid


def pan_object_values(obj: dict) -> list[str]:
    """
    Extract likely PAN-OS address object values.
    """

    values = []

    for key in (
        "value",
        "Value",
        "ip",
        "IP",
        "address",
        "Address",
        "fqdn",
        "FQDN",
        "fqdn_value",
        "ip-netmask",
        "ip-range",
    ):

        value = obj.get(key)

        if isinstance(value, str):
            values.append(value)

        elif isinstance(value, list):
            values.extend(
                str(x)
                for x in value
            )

    return values


def ingest_pan_file(conn, path: Path):

    print(f"[PAN] {path}")

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as fh:
            payload = json.load(fh)

    except Exception as exc:
        print(f"  ERROR: {exc}")
        return 0

    device_name = (
        payload.get("device")
        if isinstance(payload, dict)
        else None
    )

    device_name = (
        device_name
        or payload.get("hostname")
        if isinstance(payload, dict)
        else path.stem
    )

    device_id = find_pan_device(
        conn,
        str(device_name),
    )

    count = 0

    # --------------------------------------------------------
    # Address objects
    # --------------------------------------------------------

    objects = []

    if isinstance(payload, dict):

        for key in (
            "objects",
            "address_objects",
            "addressObjects",
            "addresses",
        ):

            candidate = payload.get(key)

            if isinstance(candidate, list):
                objects.extend(candidate)

            elif isinstance(candidate, dict):
                for name, value in candidate.items():

                    if isinstance(value, dict):
                        obj = dict(value)
                        obj.setdefault(
                            "name",
                            name,
                        )
                    else:
                        obj = {
                            "name": name,
                            "value": value,
                        }

                    objects.append(obj)

    for obj in objects:

        if not isinstance(obj, dict):
            continue

        name = (
            obj.get("name")
            or obj.get("Name")
            or obj.get("object_name")
        )

        if not name:
            continue

        values = pan_object_values(obj)

        record_id = insert_record(
            conn,
            device_id=device_id,
            platform="PAN-OS",
            category="address_object",
            filename=str(path),
            name=str(name),
            data=obj,
        )

        add_term(
            conn,
            record_id,
            name,
            "palo_object",
        )

        for value in values:

            add_term(
                conn,
                record_id,
                value,
                "palo_object_value",
            )

            add_network(
                conn,
                record_id,
                value,
                "PAN-OS object",
                "object_value",
            )

            conn.execute(
                """
                INSERT INTO palo_objects
                (
                    record_id,
                    device_id,
                    object_type,
                    name,
                    value,
                    description
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record_id,
                    device_id,
                    "address",
                    str(name),
                    str(value),
                    obj.get("description")
                    or obj.get("Description"),
                ),
            )

        count += 1

    # --------------------------------------------------------
    # Object groups
    # --------------------------------------------------------

    groups = []

    if isinstance(payload, dict):

        for key in (
            "groups",
            "address_groups",
            "addressGroups",
            "object_groups",
        ):

            candidate = payload.get(key)

            if isinstance(candidate, list):
                groups.extend(candidate)

            elif isinstance(candidate, dict):

                for name, value in candidate.items():

                    if isinstance(value, dict):
                        group = dict(value)
                        group.setdefault(
                            "name",
                            name,
                        )
                    else:
                        group = {
                            "name": name,
                            "members": value,
                        }

                    groups.append(group)

    for group in groups:

        if not isinstance(group, dict):
            continue

        name = (
            group.get("name")
            or group.get("Name")
        )

        if not name:
            continue

        members = (
            group.get("members")
            or group.get("Members")
            or group.get("static")
            or group.get("Static")
            or []
        )

        if isinstance(members, str):
            members = [members]

        record_id = insert_record(
            conn,
            device_id=device_id,
            platform="PAN-OS",
            category="address_group",
            filename=str(path),
            name=str(name),
            data=group,
        )

        add_term(
            conn,
            record_id,
            name,
            "palo_group",
        )

        for member in members:

            member = str(member)

            add_term(
                conn,
                record_id,
                member,
                "palo_group_member",
            )

            conn.execute(
                """
                INSERT INTO palo_group_members
                (
                    group_record_id,
                    group_name,
                    member_name,
                    member_type
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    record_id,
                    str(name),
                    member,
                    "static",
                ),
            )

        count += 1

    # --------------------------------------------------------
    # Security policies
    # --------------------------------------------------------

    rules = []

    if isinstance(payload, dict):

        for key in (
            "rules",
            "security_rules",
            "securityRules",
            "policies",
        ):

            candidate = payload.get(key)

            if isinstance(candidate, list):
                rules.extend(candidate)

    for rule in rules:

        if not isinstance(rule, dict):
            continue

        name = (
            rule.get("name")
            or rule.get("Name")
            or rule.get("rule_name")
            or "Unnamed Rule"
        )

        source = (
            rule.get("source")
            or rule.get("Source")
            or rule.get("src")
            or []
        )

        destination = (
            rule.get("destination")
            or rule.get("Destination")
            or rule.get("dst")
            or []
        )

        service = (
            rule.get("service")
            or rule.get("Service")
            or []
        )

        application = (
            rule.get("application")
            or rule.get("Application")
            or []
        )

        action = (
            rule.get("action")
            or rule.get("Action")
            or ""
        )

        if isinstance(source, str):
            source = [source]

        if isinstance(destination, str):
            destination = [destination]

        if isinstance(service, str):
            service = [service]

        if isinstance(application, str):
            application = [application]

        record_id = insert_record(
            conn,
            device_id=device_id,
            platform="PAN-OS",
            category="security_rule",
            filename=str(path),
            name=str(name),
            data=rule,
        )

        add_term(
            conn,
            record_id,
            name,
            "palo_rule",
        )

        for value in source:
            add_term(
                conn,
                record_id,
                value,
                "rule_source",
            )

            add_network(
                conn,
                record_id,
                value,
                "PAN-OS rule source",
                "source",
            )

        for value in destination:
            add_term(
                conn,
                record_id,
                value,
                "rule_destination",
            )

            add_network(
                conn,
                record_id,
                value,
                "PAN-OS rule destination",
                "destination",
            )

        for value in service:
            add_term(
                conn,
                record_id,
                value,
                "rule_service",
            )

        for value in application:
            add_term(
                conn,
                record_id,
                value,
                "rule_application",
            )

        conn.execute(
            """
            INSERT INTO palo_rules
            (
                record_id,
                device_id,
                rule_name,
                rule_type,
                source,
                destination,
                service,
                application,
                action,
                disabled,
                description
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record_id,
                device_id,
                str(name),
                "security",
                json_text(source),
                json_text(destination),
                json_text(service),
                json_text(application),
                str(action),
                int(
                    bool(
                        rule.get("disabled")
                        or rule.get("Disabled")
                    )
                ),
                rule.get("description")
                or rule.get("Description"),
            ),
        )

        count += 1

    return count


def ingest_pan_directory(conn, directory: Path):

    if not directory.exists():
        print(f"[PAN] Directory does not exist: {directory}")
        return

    total = 0

    for path in sorted(
        directory.rglob("*.json")
    ):
        total += ingest_pan_file(
            conn,
            path,
        )

    print(f"[PAN] Indexed {total} records")


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description="Build infra_intel SQLite database."
    )

    parser.add_argument(
        "--db",
        default=str(DEFAULT_DB),
    )

    parser.add_argument(
        "--firewall-data",
        default=str(DEFAULT_FIREWALL_DIR),
    )

    parser.add_argument(
        "--aws-data",
        default=str(DEFAULT_AWS_DIR),
    )

    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete and completely rebuild the database.",
    )

    args = parser.parse_args()

    db_path = Path(args.db)

    initialize_database(
        db_path,
        reset=args.reset,
    )

    conn = connect(db_path)

    try:

        ingest_pan_directory(
            conn,
            Path(args.firewall_data),
        )

        ingest_aws_directory(
            conn,
            Path(args.aws_data),
        )

        conn.commit()

    finally:
        conn.close()

    print()
    print("=" * 60)
    print("INGEST COMPLETE")
    print(f"Database: {db_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
```
