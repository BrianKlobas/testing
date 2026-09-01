```python
#!/usr/bin/env python3

"""
infra_intel/app.py

Flask application.

IMPORTANT:
    This file NEVER ingests JSON.

Run:

    python app.py

Update the database separately:

    python ingest.py --reset
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request

from database import (
    DEFAULT_DB,
    classify_network,
    connect,
    latest_json_mtime,
    networks_overlap,
    parse_network,
    parse_range,
    values_match,
)


BASE_DIR = Path(__file__).resolve().parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
)


# ============================================================
# GENERAL HELPERS
# ============================================================

def row_dict(row):
    if row is None:
        return None

    return dict(row)


def rows_dict(rows):
    return [dict(row) for row in rows]


def json_load(value, default=None):

    if default is None:
        default = []

    if value is None:
        return default

    try:
        return json.loads(value)
    except Exception:
        return default


def clean_list(value):

    if value is None:
        return []

    if isinstance(value, list):
        return [
            str(x)
            for x in value
            if x is not None
        ]

    if isinstance(value, str):
        return [value]

    return [str(value)]


def normalize(value):
    return str(value or "").strip().lower()


def contains_text(haystack, needle):

    if haystack is None:
        return False

    return normalize(needle) in normalize(haystack)


# ============================================================
# SEARCH CLASSIFICATION
# ============================================================

def classify_query(query):

    info = classify_network(query)

    if info["family"] in (4, 6):
        return info

    return {
        "type": "text",
        "family": None,
        "network": None,
    }


# ============================================================
# AWS INVENTORY
# ============================================================

def aws_resources_by_network(conn, query):

    """
    Find AWS resources whose IP/CIDR/range matches query.
    """

    info = classify_query(query)

    if info["family"] not in (4, 6):
        return []

    rows = conn.execute(
        """
        SELECT
            ar.*,
            r.name AS record_name,
            r.filename
        FROM aws_resources ar
        LEFT JOIN records r
            ON r.id = ar.record_id
        WHERE
            (
                ar.private_ip IS NOT NULL
                AND IP_MATCH(?, ar.private_ip) = 1
            )
            OR
            (
                ar.public_ip IS NOT NULL
                AND IP_MATCH(?, ar.public_ip) = 1
            )
            OR
            (
                ar.subnet_cidr IS NOT NULL
                AND IP_MATCH(?, ar.subnet_cidr) = 1
            )
            OR
            (
                ar.vpc_cidr IS NOT NULL
                AND IP_MATCH(?, ar.vpc_cidr) = 1
            )
        ORDER BY
            ar.account_id,
            ar.region,
            ar.resource_type,
            ar.resource_id
        """,
        (
            query,
            query,
            query,
            query,
        ),
    ).fetchall()

    return rows_dict(rows)


def aws_resources_by_term(conn, query):

    """
    Search IDs/names/DNS/ARNs/etc.
    """

    needle = normalize(query)

    rows = conn.execute(
        """
        SELECT DISTINCT
            ar.*,
            r.name AS record_name,
            r.filename
        FROM search_index si

        JOIN records r
            ON r.id = si.record_id

        JOIN aws_resources ar
            ON ar.record_id = r.id

        WHERE
            si.normalized = ?
            OR si.normalized LIKE ?
            OR si.term LIKE ?

        ORDER BY
            ar.account_id,
            ar.region,
            ar.resource_type,
            ar.resource_id
        """,
        (
            needle,
            f"%{needle}%",
            f"%{query}%",
        ),
    ).fetchall()

    return rows_dict(rows)


def direct_sgs_for_aws_resource(conn, aws_resource_id):

    rows = conn.execute(
        """
        SELECT
            sg_id,
            attachment_type
        FROM aws_security_group_attachments
        WHERE aws_resource_id = ?
        ORDER BY sg_id
        """,
        (aws_resource_id,),
    ).fetchall()

    return rows_dict(rows)


def get_aws_sgs(conn, resource):

    resource_id = resource.get("id")

    if not resource_id:
        return []

    return direct_sgs_for_aws_resource(
        conn,
        resource_id,
    )


def aws_network_context(resource):

    context = []

    private_ip = resource.get("private_ip")
    subnet_cidr = resource.get("subnet_cidr")
    vpc_cidr = resource.get("vpc_cidr")

    if private_ip:
        net = parse_network(private_ip)

        if net:
            context.append(
                {
                    "value": str(net),
                    "type": "instance_ip",
                    "source": "EC2/ENI",
                    "family": net.version,
                }
            )

    if subnet_cidr:
        net = parse_network(subnet_cidr)

        if net:
            context.append(
                {
                    "value": str(net),
                    "type": "subnet_cidr",
                    "source": "AWS Subnet",
                    "family": net.version,
                }
            )

    if vpc_cidr:
        net = parse_network(vpc_cidr)

        if net:
            context.append(
                {
                    "value": str(net),
                    "type": "vpc_cidr",
                    "source": "AWS VPC",
                    "family": net.version,
                }
            )

    return context


# ============================================================
# PALO OBJECT / GROUP EXPANSION
# ============================================================

def palo_objects_matching_network(conn, target):

    info = classify_query(target)

    if info["family"] not in (4, 6):
        return []

    rows = conn.execute(
        """
        SELECT DISTINCT
            po.*,
            r.filename,
            d.name AS device_name
        FROM palo_objects po

        LEFT JOIN records r
            ON r.id = po.record_id

        LEFT JOIN devices d
            ON d.id = po.device_id

        WHERE
            po.value IS NOT NULL
            AND IP_MATCH(?, po.value) = 1

        ORDER BY
            po.name
        """,
        (target,),
    ).fetchall()

    return rows_dict(rows)


def palo_objects_matching_term(conn, query):

    needle = normalize(query)

    rows = conn.execute(
        """
        SELECT DISTINCT
            po.*,
            r.filename,
            d.name AS device_name
        FROM palo_objects po

        LEFT JOIN records r
            ON r.id = po.record_id

        LEFT JOIN devices d
            ON d.id = po.device_id

        WHERE
            normalize_name IS NULL
        """
    ).fetchall() if False else []

    # SQLite does not have normalize_name. Use indexed search table.
    rows = conn.execute(
        """
        SELECT DISTINCT
            po.*,
            r.filename,
            d.name AS device_name
        FROM palo_objects po

        LEFT JOIN records r
            ON r.id = po.record_id

        LEFT JOIN devices d
            ON d.id = po.device_id

        WHERE
            lower(po.name) = ?
            OR lower(po.name) LIKE ?
            OR lower(po.value) = ?
            OR lower(po.value) LIKE ?

        ORDER BY
            po.name
        """,
        (
            needle,
            f"%{needle}%",
            needle,
            f"%{needle}%",
        ),
    ).fetchall()

    return rows_dict(rows)


def group_members_recursive(
    conn,
    member_name,
    visited=None,
):

    """
    Recursively find all groups containing member_name.

    Handles:

        object
          -> group
             -> group
                -> rule
    """

    if visited is None:
        visited = set()

    key = normalize(member_name)

    if key in visited:
        return []

    visited.add(key)

    rows = conn.execute(
        """
        SELECT
            group_name,
            member_name,
            member_type,
            group_record_id
        FROM palo_group_members
        WHERE lower(member_name) = ?
        ORDER BY group_name
        """,
        (key,),
    ).fetchall()

    results = []

    for row in rows:

        item = dict(row)

        results.append(item)

        nested = group_members_recursive(
            conn,
            item["group_name"],
            visited,
        )

        results.extend(nested)

    return results


def palo_groups_for_object(
    conn,
    object_name,
):

    return group_members_recursive(
        conn,
        object_name,
    )


def palo_rules_for_terms(
    conn,
    terms,
):

    """
    Find rules referencing any supplied object/group/member.

    Exact references are preferred.
    """

    if not terms:
        return []

    unique_terms = sorted(
        {
            normalize(x)
            for x in terms
            if x
        }
    )

    rows = []

    for term in unique_terms:

        wildcard = f"%{term}%"

        result = conn.execute(
            """
            SELECT
                pr.*,
                d.name AS device_name,
                r.filename
            FROM palo_rules pr

            LEFT JOIN devices d
                ON d.id = pr.device_id

            LEFT JOIN records r
                ON r.id = pr.record_id

            WHERE
                lower(pr.source) LIKE ?
                OR lower(pr.destination) LIKE ?

            ORDER BY
                pr.rule_name
            """,
            (
                wildcard,
                wildcard,
            ),
        ).fetchall()

        rows.extend(
            dict(x)
            for x in result
        )

    # Deduplicate
    seen = set()
    output = []

    for row in rows:

        key = (
            row.get("id"),
            row.get("rule_name"),
            row.get("device_name"),
        )

        if key in seen:
            continue

        seen.add(key)
        output.append(row)

    return output


# ============================================================
# NETWORK CONTEXT
# ============================================================

def build_network_context(
    query,
    aws_resources,
):

    """
    For an AWS resource:

        /32
          -> subnet CIDR
          -> VPC CIDR

    This is intentionally explicit so Palo matching covers
    larger address objects/rules.
    """

    context = []

    seen = set()

    def add(value, source, context_type):

        if not value:
            return

        net = parse_network(value)

        if not net:
            return

        key = (
            str(net),
            net.version,
        )

        if key in seen:
            return

        seen.add(key)

        context.append(
            {
                "value": str(net),
                "family": net.version,
                "source": source,
                "type": context_type,
            }
        )

    parsed_query = parse_network(query)

    if parsed_query:
        add(
            str(parsed_query),
            "Search query",
            "query",
        )

    for resource in aws_resources:

        private_ip = resource.get("private_ip")

        if private_ip:
            add(
                private_ip,
                "EC2/ENI",
                "instance_ip",
            )

        add(
            resource.get("subnet_cidr"),
            "AWS Subnet",
            "subnet_cidr",
        )

        add(
            resource.get("vpc_cidr"),
            "AWS VPC",
            "vpc_cidr",
        )

    return context


# ============================================================
# PALO RULE NETWORK MATCHING
# ============================================================

def rule_addresses(rule, field):

    return clean_list(
        json_load(
            rule.get(field),
            [],
        )
    )


def rule_matches_network(
    addresses,
    target,
    conn,
):

    """
    Match a target IP/CIDR against rule addresses.

    Handles:

        IP
        CIDR
        ranges
        any
        object names are handled separately
    """

    if not addresses:
        return False, None

    for address in addresses:

        if normalize(address) == "any":
            return True, "any"

        if values_match(
            target,
            address,
        ):
            return True, address

    return False, None


def resolve_rule_address_tokens(
    conn,
    tokens,
):

    """
    Resolve:

        object
        group
        nested group
        CIDR

    into concrete address values.

    Returns a list of:

        {
            value,
            source,
            name
        }
    """

    results = []

    visited_objects = set()
    visited_groups = set()

    def resolve_token(token):

        token = str(token).strip()

        if not token:
            return

        if normalize(token) == "any":
            results.append(
                {
                    "value": "any",
                    "source": "rule",
                    "name": "any",
                }
            )
            return

        # Direct network
        net = parse_network(token)

        if net:

            results.append(
                {
                    "value": str(net),
                    "source": "literal",
                    "name": token,
                }
            )

            return

        # IP range
        if parse_range(token):

            results.append(
                {
                    "value": token,
                    "source": "literal",
                    "name": token,
                }
            )

            return

        # Object
        object_rows = conn.execute(
            """
            SELECT
                name,
                value
            FROM palo_objects
            WHERE lower(name) = ?
            """,
            (normalize(token),),
        ).fetchall()

        for row in object_rows:

            object_key = normalize(
                row["name"]
            )

            if object_key in visited_objects:
                continue

            visited_objects.add(
                object_key
            )

            if row["value"]:

                results.append(
                    {
                        "value": row["value"],
                        "source": "object",
                        "name": row["name"],
                    }
                )

        # Group
        group_rows = conn.execute(
            """
            SELECT
                group_name,
                member_name
            FROM palo_group_members
            WHERE lower(group_name) = ?
            """,
            (normalize(token),),
        ).fetchall()

        if group_rows:

            group_key = normalize(token)

            if group_key in visited_groups:
                return

            visited_groups.add(
                group_key
            )

            for row in group_rows:
                resolve_token(
                    row["member_name"]
                )

    for token in tokens:
        resolve_token(token)

    return results


def rule_matches_target(
    conn,
    rule,
    target,
):

    resolved = resolve_rule_address_tokens(
        conn,
        rule_addresses(
            rule,
            "source",
        ),
    )

    # If target is intended for destination,
    # caller will resolve destination separately.
    return resolved


# ============================================================
# POLICY LOOKUP
# ============================================================

def normalize_port(port):

    if not port:
        return None

    port = str(port).strip().lower()

    if port in (
        "",
        "any",
        "*",
    ):
        return None

    # Common forms:
    # 443
    # tcp/443
    # 443-445
    # tcp-443
    match = re.match(
        r"^(?:tcp/|udp/|tcp-|udp-)?(\d+)(?:-(\d+))?$",
        port,
    )

    if not match:
        return port

    start = int(match.group(1))
    end = int(
        match.group(2)
        or start
    )

    return {
        "start": start,
        "end": end,
    }


def service_matches_port(
    service_tokens,
    requested_port,
):

    if requested_port is None:
        return True, "not specified"

    port_info = normalize_port(
        requested_port
    )

    if not isinstance(
        port_info,
        dict,
    ):
        requested_text = normalize(
            requested_port
        )

        for service in service_tokens:

            if requested_text in normalize(service):
                return True, service

        return False, None

    requested_start = port_info["start"]
    requested_end = port_info["end"]

    for service in service_tokens:

        value = normalize(service)

        if value == "any":
            return True, "any"

        # service may be:
        # tcp/443
        # udp/53
        # 443
        # 443-445

        numbers = re.findall(
            r"\d+",
            value,
        )

        if not numbers:
            continue

        try:

            start = int(numbers[0])

            end = int(
                numbers[1]
                if len(numbers) > 1
                else numbers[0]
            )

            if not (
                requested_end < start
                or requested_start > end
            ):
                return True, service

        except ValueError:
            continue

    return False, None


def policy_lookup(
    conn,
    source=None,
    destination=None,
    port=None,
):

    source = (
        source.strip()
        if source
        else None
    )

    destination = (
        destination.strip()
        if destination
        else None
    )

    # --------------------------------------------------------
    # Build network contexts.
    # --------------------------------------------------------

    source_aws = (
        aws_resources_by_network(
            conn,
            source,
        )
        if source and classify_query(source)["family"]
        else []
    )

    destination_aws = (
        aws_resources_by_network(
            conn,
            destination,
        )
        if destination and classify_query(destination)["family"]
        else []
    )

    source_context = (
        build_network_context(
            source,
            source_aws,
        )
        if source
        else []
    )

    destination_context = (
        build_network_context(
            destination,
            destination_aws,
        )
        if destination
        else []
    )

    # --------------------------------------------------------
    # Candidate rules.
    #
    # We inspect all rules, but only return rules that match
    # the requested source/destination/port.
    # --------------------------------------------------------

    rule_rows = conn.execute(
        """
        SELECT
            pr.*,
            d.name AS device_name,
            r.filename
        FROM palo_rules pr

        LEFT JOIN devices d
            ON d.id = pr.device_id

        LEFT JOIN records r
            ON r.id = pr.record_id

        ORDER BY
            d.name,
            pr.rule_name
        """
    ).fetchall()

    matching_rules = []

    for row in rule_rows:

        rule = dict(row)

        if int(
            rule.get("disabled") or 0
        ):
            continue

        source_tokens = rule_addresses(
            rule,
            "source",
        )

        destination_tokens = rule_addresses(
            rule,
            "destination",
        )

        service_tokens = rule_addresses(
            rule,
            "service",
        )

        # ----------------------------------------------------
        # Source matching
        # ----------------------------------------------------

        source_match = True
        source_reason = None

        if source:

            source_match = False

            # First check direct query.
            targets = [
                {
                    "value": source,
                    "source": "query",
                }
            ]

            # Then AWS context.
            targets.extend(
                source_context
            )

            for target in targets:

                target_value = target["value"]

                if target_value is None:
                    continue

                for token in source_tokens:

                    if normalize(token) == "any":

                        source_match = True
                        source_reason = {
                            "type": "any",
                            "matched": "any",
                        }
                        break

                    # Literal CIDR/IP/range
                    if values_match(
                        target_value,
                        token,
                    ):

                        source_match = True
                        source_reason = {
                            "type": target.get(
                                "type",
                                "network",
                            ),
                            "matched": token,
                            "target": target_value,
                        }

                        break

                    # Resolve object/group.
                    resolved = resolve_rule_address_tokens(
                        conn,
                        [token],
                    )

                    for resolved_item in resolved:

                        if normalize(
                            resolved_item["value"]
                        ) == "any":

                            source_match = True
                            source_reason = {
                                "type": "object_any",
                                "matched": token,
                            }
                            break

                        if values_match(
                            target_value,
                            resolved_item["value"],
                        ):

                            source_match = True
                            source_reason = {
                                "type": "object_or_group",
                                "matched": token,
                                "member": resolved_item["name"],
                                "value": resolved_item["value"],
                                "target": target_value,
                            }

                            break

                    if source_match:
                        break

                if source_match:
                    break

        if not source_match:
            continue

        # ----------------------------------------------------
        # Destination
        # ----------------------------------------------------

        destination_match = True
        destination_reason = None

        if destination:

            destination_match = False

            targets = [
                {
                    "value": destination,
                    "source": "query",
                }
            ]

            targets.extend(
                destination_context
            )

            for target in targets:

                target_value = target["value"]

                for token in destination_tokens:

                    if normalize(token) == "any":

                        destination_match = True

                        destination_reason = {
                            "type": "any",
                            "matched": "any",
                        }

                        break

                    if values_match(
                        target_value,
                        token,
                    ):

                        destination_match = True

                        destination_reason = {
                            "type": target.get(
                                "type",
                                "network",
                            ),
                            "matched": token,
                            "target": target_value,
                        }

                        break

                    resolved = resolve_rule_address_tokens(
                        conn,
                        [token],
                    )

                    for resolved_item in resolved:

                        if normalize(
                            resolved_item["value"]
                        ) == "any":

                            destination_match = True

                            destination_reason = {
                                "type": "object_any",
                                "matched": token,
                            }

                            break

                        if values_match(
                            target_value,
                            resolved_item["value"],
                        ):

                            destination_match = True

                            destination_reason = {
                                "type": "object_or_group",
                                "matched": token,
                                "member": resolved_item["name"],
                                "value": resolved_item["value"],
                                "target": target_value,
                            }

                            break

                    if destination_match:
                        break

                if destination_match:
                    break

        if not destination_match:
            continue

        # ----------------------------------------------------
        # Port/service
        # ----------------------------------------------------

        port_match, port_reason = (
            service_matches_port(
                service_tokens,
                port,
            )
        )

        if not port_match:
            continue

        rule["source_match"] = source_reason
        rule["destination_match"] = destination_reason
        rule["port_match"] = port_reason

        matching_rules.append(
            rule
        )

    # --------------------------------------------------------
    # Associated objects/groups/members
    # --------------------------------------------------------

    associated_terms = set()

    for rule in matching_rules:

        for field in (
            "source",
            "destination",
        ):

            for token in rule_addresses(
                rule,
                field,
            ):

                associated_terms.add(
                    token
                )

    objects = []
    groups = []
    members = []

    for term in sorted(
        associated_terms
    ):

        object_rows = conn.execute(
            """
            SELECT DISTINCT
                po.*,
                d.name AS device_name
            FROM palo_objects po
            LEFT JOIN devices d
                ON d.id = po.device_id
            WHERE lower(po.name) = ?
            """,
            (normalize(term),),
        ).fetchall()

        for row in object_rows:
            objects.append(
                dict(row)
            )

        group_rows = conn.execute(
            """
            SELECT
                group_name,
                member_name,
                member_type
            FROM palo_group_members
            WHERE lower(group_name) = ?
            """,
            (normalize(term),),
        ).fetchall()

        for row in group_rows:

            groups.append(
                {
                    "group_name": row["group_name"],
                    "member_count": 0,
                }
            )

            members.append(
                dict(row)
            )

    # Deduplicate groups
    group_map = {}

    for group in groups:
        group_map[
            group["group_name"]
        ] = group

    groups = list(
        group_map.values()
    )

    return {
        "query": {
            "source": source,
            "destination": destination,
            "port": port,
        },

        "source_context": source_context,
        "destination_context": destination_context,

        "aws_source_resources": source_aws,
        "aws_destination_resources": destination_aws,

        "objects": objects,
        "groups": groups,
        "members": members,
        "rules": matching_rules,

        "counts": {
            "objects": len(objects),
            "groups": len(groups),
            "members": len(members),
            "rules": len(matching_rules),
        },
    }


# ============================================================
# INVENTORY INVESTIGATION
# ============================================================

def inventory_lookup(
    conn,
    query,
):

    query = query.strip()

    if not query:
        return {
            "query": query,
            "query_type": "empty",
            "aws": [],
            "palo": {
                "objects": [],
                "groups": [],
                "members": [],
                "rules": [],
            },
            "network_context": [],
        }

    classification = classify_query(
        query
    )

    # --------------------------------------------------------
    # AWS
    # --------------------------------------------------------

    if classification["family"] in (
        4,
        6,
    ):

        aws = aws_resources_by_network(
            conn,
            query,
        )

    else:

        aws = aws_resources_by_term(
            conn,
            query,
        )

    # --------------------------------------------------------
    # AWS context
    # --------------------------------------------------------

    network_context = build_network_context(
        query,
        aws,
    )

    # --------------------------------------------------------
    # Palo direct lookup
    # --------------------------------------------------------

    palo_objects = []

    if classification["family"] in (
        4,
        6,
    ):

        for context in network_context:

            matches = palo_objects_matching_network(
                conn,
                context["value"],
            )

            for item in matches:

                item["match_context"] = (
                    context["type"]
                )

                item["matched_network"] = (
                    context["value"]
                )

                palo_objects.append(
                    item
                )

    else:

        palo_objects.extend(
            palo_objects_matching_term(
                conn,
                query,
            )
        )

    # Deduplicate objects
    object_map = {}

    for item in palo_objects:

        key = (
            item.get("id"),
            item.get("name"),
            item.get("value"),
        )

        if key not in object_map:
            object_map[key] = item

    palo_objects = list(
        object_map.values()
    )

    # --------------------------------------------------------
    # Groups
    # --------------------------------------------------------

    groups = []
    members = []

    for obj in palo_objects:

        name = obj.get("name")

        if not name:
            continue

        relations = palo_groups_for_object(
            conn,
            name,
        )

        for relation in relations:

            groups.append(
                {
                    "group_name": relation[
                        "group_name"
                    ],
                    "matched_member": name,
                }
            )

            members.append(
                relation
            )

    # If query itself is a group
    direct_groups = conn.execute(
        """
        SELECT
            group_name,
            member_name,
            member_type
        FROM palo_group_members
        WHERE lower(group_name) = ?
        """,
        (normalize(query),),
    ).fetchall()

    for row in direct_groups:

        groups.append(
            {
                "group_name": row["group_name"],
                "matched_member": row["member_name"],
            }
        )

        members.append(
            dict(row)
        )

    # Deduplicate
    group_map = {}

    for group in groups:

        key = (
            group["group_name"],
            group.get("matched_member"),
        )

        group_map[key] = group

    groups = list(
        group_map.values()
    )

    member_map = {}

    for member in members:

        key = (
            member.get("group_name"),
            member.get("member_name"),
        )

        member_map[key] = member

    members = list(
        member_map.values()
    )

    # --------------------------------------------------------
    # Rules
    # --------------------------------------------------------

    rule_terms = {
        query
    }

    for obj in palo_objects:
        rule_terms.add(
            obj.get("name")
        )

    for group in groups:
        rule_terms.add(
            group.get("group_name")
        )

    rules = palo_rules_for_terms(
        conn,
        rule_terms,
    )

    # For network searches also directly search
    # Palo rule source/destination networks.
    if classification["family"] in (
        4,
        6,
    ):

        for context in network_context:

            context_value = context[
                "value"
            ]

            candidates = conn.execute(
                """
                SELECT
                    pr.*,
                    d.name AS device_name,
                    r.filename
                FROM palo_rules pr

                LEFT JOIN devices d
                    ON d.id = pr.device_id

                LEFT JOIN records r
                    ON r.id = pr.record_id

                WHERE
                    lower(pr.source) LIKE ?
                    OR lower(pr.destination) LIKE ?
                """,
                (
                    f"%{normalize(context_value)}%",
                    f"%{normalize(context_value)}%",
                ),
            ).fetchall()

            # Also resolve object/group references.
            for rule_row in candidates:
                rules.append(
                    dict(rule_row)
                )

    rule_map = {}

    for rule in rules:

        key = (
            rule.get("id"),
            rule.get("rule_name"),
            rule.get("device_name"),
        )

        rule_map[key] = rule

    rules = list(
        rule_map.values()
    )

    return {
        "query": query,

        "query_type": classification["type"],
        "query_family": classification["family"],

        "aws": [
            {
                **resource,
                "direct_security_groups":
                    get_aws_sgs(
                        conn,
                        resource,
                    ),
                "network_context":
                    aws_network_context(
                        resource
                    ),
            }
            for resource in aws
        ],

        "network_context":
            network_context,

        "palo": {
            "objects":
                palo_objects,

            "groups":
                groups,

            "members":
                members,

            "rules":
                rules,
        },

        "counts": {
            "aws":
                len(aws),

            "palo_objects":
                len(palo_objects),

            "palo_groups":
                len(groups),

            "palo_members":
                len(members),

            "palo_rules":
                len(rules),
        },
    }


# ============================================================
# ROUTES
# ============================================================

@app.route("/")
def index():
    return render_template(
        "index.html"
    )


@app.route("/api/investigate")
def api_investigate():

    query = request.args.get(
        "q",
        "",
    ).strip()

    if not query:
        return jsonify(
            {
                "error":
                    "Missing query."
            }
        ), 400

    conn = connect(
        DEFAULT_DB
    )

    try:

        result = inventory_lookup(
            conn,
            query,
        )

        return jsonify(result)

    except Exception as exc:

        app.logger.exception(
            "Inventory lookup failed"
        )

        return jsonify(
            {
                "error":
                    str(exc),
                "query":
                    query,
            }
        ), 500

    finally:
        conn.close()


@app.route("/api/policy-lookup")
def api_policy_lookup():

    source = request.args.get(
        "src",
        "",
    ).strip()

    destination = request.args.get(
        "dst",
        "",
    ).strip()

    port = request.args.get(
        "port",
        "",
    ).strip()

    if not source and not destination:
        return jsonify(
            {
                "error":
                    "Provide a source or destination."
            }
        ), 400

    conn = connect(
        DEFAULT_DB
    )

    try:

        result = policy_lookup(
            conn,
            source=source or None,
            destination=destination or None,
            port=port or None,
        )

        return jsonify(result)

    except Exception as exc:

        app.logger.exception(
            "Policy lookup failed"
        )

        return jsonify(
            {
                "error":
                    str(exc)
            }
        ), 500

    finally:
        conn.close()


@app.route("/api/search/classify")
def api_search_classify():

    query = request.args.get(
        "q",
        "",
    ).strip()

    return jsonify(
        classify_query(query)
    )


# ============================================================
# STATS
# ============================================================

@app.route("/api/stats")
def api_stats():

    conn = connect(
        DEFAULT_DB
    )

    try:

        def count(table):

            row = conn.execute(
                f"SELECT COUNT(*) AS n FROM {table}"
            ).fetchone()

            return row["n"]

        return jsonify(
            {
                "aws_resources": {
                    "resources":
                        count(
                            "aws_resources"
                        ),

                    "security_groups":
                        count(
                            "security_groups"
                        ),

                    "search_index":
                        count(
                            "search_index"
                        ),

                    "network_index":
                        count(
                            "network_index"
                        ),
                },

                "panos": {
                    "objects":
                        count(
                            "palo_objects"
                        ),

                    "groups":
                        count(
                            "palo_group_members"
                        ),

                    "rules":
                        count(
                            "palo_rules"
                        ),

                    "devices":
                        count(
                            "devices"
                        ),
                },
            }
        )

    finally:
        conn.close()


# ============================================================
# AUTOMATION / DATA STATUS
# ============================================================

@app.route("/api/automation/status")
def automation_status():

    return jsonify(
        {
            "aws_org_mtime":
                latest_json_mtime(
                    BASE_DIR / "aws_parsed"
                ),

            "aws_data_mtime":
                latest_json_mtime(
                    BASE_DIR / "aws_parsed"
                ),

            "pan_org_mtime":
                latest_json_mtime(
                    BASE_DIR / "parsed"
                ),

            "pan_data_mtime":
                latest_json_mtime(
                    BASE_DIR / "parsed"
                ),
        }
    )


@app.route("/api/info")
def api_info():

    conn = connect(
        DEFAULT_DB
    )

    try:

        records = conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM records
            """
        ).fetchone()["n"]

        devices = conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM devices
            """
        ).fetchone()["n"]

        return jsonify(
            {
                "files":
                    records,

                "devices":
                    devices,

                "database":
                    str(DEFAULT_DB),
            }
        )

    finally:
        conn.close()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("INFRA INTEL")
    print("=" * 60)
    print(f"Database: {DEFAULT_DB}")
    print()
    print("IMPORTANT:")
    print("This application does NOT ingest data.")
    print("Run ingest.py separately when JSON changes.")
    print("=" * 60)
    print()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
    )
```
