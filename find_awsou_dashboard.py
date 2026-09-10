#!/usr/bin/env python3
"""Collect AWS Organizations topology, account tags, and normalized owner fields.

The output intentionally keeps the existing topology shape (Hierarchy/OUs/Accounts)
while adding Tags, PrimaryOwner, and SecondaryOwner to every account.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError


def paginate(client, operation: str, result_key: str, **kwargs):
    paginator = client.get_paginator(operation)
    for page in paginator.paginate(**kwargs):
        yield from page.get(result_key, [])


def get_tags(client, resource_id: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    try:
        token = None
        while True:
            params = {"ResourceId": resource_id}
            if token:
                params["NextToken"] = token
            response = client.list_tags_for_resource(**params)
            for tag in response.get("Tags", []):
                key = str(tag.get("Key", "")).strip()
                if key:
                    tags[key] = str(tag.get("Value", ""))
            token = response.get("NextToken")
            if not token:
                break
    except ClientError as exc:
        print(f"[!] Could not read tags for account {resource_id}: {exc}")
    return tags


def tag_value(tags: dict[str, str], preferred: str, aliases: list[str]) -> str:
    wanted = [preferred, *aliases]
    lowered = {k.lower(): v for k, v in tags.items()}
    for key in wanted:
        value = lowered.get(key.lower())
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def account_record(account: dict[str, Any], org_client, primary_key: str, secondary_key: str) -> dict[str, Any]:
    record = dict(account)
    account_id = str(record.get("Id", ""))
    tags = get_tags(org_client, account_id) if account_id else {}

    # Keep all raw account tags and also expose normalized owner fields for the UI.
    record["Tags"] = tags
    record["PrimaryOwner"] = tag_value(
        tags,
        primary_key,
        ["PrimaryOwner", "Primary-Owner", "OwnerPrimary", "Owner-Primary", "primary_owner"],
    )
    record["SecondaryOwner"] = tag_value(
        tags,
        secondary_key,
        ["SecondaryOwner", "Secondary-Owner", "OwnerSecondary", "Owner-Secondary", "secondary_owner"],
    )
    return record


def build_ou(org_client, parent_id: str, primary_key: str, secondary_key: str) -> list[dict[str, Any]]:
    output = []
    for ou in paginate(org_client, "list_organizational_units_for_parent", "OrganizationalUnits", ParentId=parent_id):
        node = {
            "Name": ou.get("Name", ""),
            "Id": ou.get("Id", ""),
            "Arn": ou.get("Arn", ""),
            "Type": "OU",
            "Accounts": [],
            "OUs": [],
        }
        for account in paginate(org_client, "list_accounts_for_parent", "Accounts", ParentId=ou["Id"]):
            node["Accounts"].append(account_record(account, org_client, primary_key, secondary_key))
        node["OUs"] = build_ou(org_client, ou["Id"], primary_key, secondary_key)
        output.append(node)
    return output


def collect(primary_key: str, secondary_key: str) -> dict[str, Any]:
    org = boto3.client("organizations")
    roots = list(paginate(org, "list_roots", "Roots"))
    hierarchy = []

    for root in roots:
        node = {
            "Name": root.get("Name", "Root"),
            "Id": root.get("Id", ""),
            "Arn": root.get("Arn", ""),
            "Type": "ROOT",
            "Accounts": [],
            "OUs": [],
        }
        for account in paginate(org, "list_accounts_for_parent", "Accounts", ParentId=root["Id"]):
            node["Accounts"].append(account_record(account, org, primary_key, secondary_key))
        node["OUs"] = build_ou(org, root["Id"], primary_key, secondary_key)
        hierarchy.append(node)

    return {
        "Hierarchy": hierarchy,
        "Metadata": {
            "PrimaryOwnerTag": primary_key,
            "SecondaryOwnerTag": secondary_key,
            "AccountTagsCollected": True,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect AWS Organization topology and account tags")
    parser.add_argument("--output", default="org_topology.json", help="Output JSON path")
    parser.add_argument("--primary-owner-tag", default="PrimaryOwner", help="Primary owner tag key")
    parser.add_argument("--secondary-owner-tag", default="SecondaryOwner", help="Secondary owner tag key")
    args = parser.parse_args()

    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    data = collect(args.primary_owner_tag, args.secondary_owner_tag)
    output.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    accounts = []
    def walk(node: dict[str, Any]):
        accounts.extend(node.get("Accounts", []))
        for child in node.get("OUs", []):
            walk(child)
    for root in data["Hierarchy"]:
        walk(root)

    print(f"[+] Wrote {output}")
    print(f"[+] Accounts: {len(accounts)}")
    print(f"[+] Accounts with primary owner: {sum(bool(a.get('PrimaryOwner')) for a in accounts)}")
    print(f"[+] Accounts with secondary owner: {sum(bool(a.get('SecondaryOwner')) for a in accounts)}")


if __name__ == "__main__":
    main()
