#!/usr/bin/env python3
"""
AWS Organization Discovery Script
--------------------------------
Iterates through the AWS Organization structure, finding all OUs,
parents, and active member accounts, saving output as a structured JSON.

Run:
    python find_awsou_dashboard.py --output org_topology.json
"""

from __future__ import annotations
import argparse
import json
from datetime import datetime
from pathlib import Path
import boto3
from botocore.exceptions import ClientError

def get_ou_hierarchy(client, parent_id, parent_path="Root"):
    """Recursively fetch OUs and accounts under a parent ID (Root or OU)."""
    node = {
        "OUs": [],
        "Accounts": []
    }

    # 1. Fetch Accounts directly under this parent
    try:
        paginator = client.get_paginator("list_accounts_for_parent")
        for page in paginator.paginate(ParentId=parent_id):
            for acc in page.get("Accounts", []):
                node["Accounts"].append({
                    "Id": acc["Id"],
                    "Arn": acc["Arn"],
                    "Name": acc["Name"],
                    "Email": acc["Email"],
                    "Status": acc.get("Status"),
                    "JoinedMethod": acc.get("JoinedMethod"),
                    "ParentPath": parent_path
                })
    except ClientError as e:
        print(f"[!] Error listing accounts for parent {parent_id}: {e}")

    # 2. Fetch Child OUs and recursively process them
    try:
        paginator = client.get_paginator("list_organizational_units_for_parent")
        for page in paginator.paginate(ParentId=parent_id):
            for ou in page.get("OrganizationalUnits", []):
                ou_id = ou["Id"]
                ou_name = ou["Name"]
                current_path = f"{parent_path} / {ou_name}"
                
                # Retrieve full nested dictionary for child OU
                child_ou = get_ou_hierarchy(client, ou_id, current_path)
                child_ou["Id"] = ou_id
                child_ou["Name"] = ou_name
                child_ou["Path"] = current_path
                
                node["OUs"].append(child_ou)
    except ClientError as e:
        print(f"[!] Error listing OUs for parent {parent_id}: {e}")

    return node

def count_all_accounts(node):
    """Recursively count all active/total accounts found in the hierarchy tree."""
    count = len(node.get("Accounts", []))
    for ou in node.get("OUs", []):
        count += count_all_accounts(ou)
    return count

def main():
    parser = argparse.ArgumentParser(description="Export AWS Org Structure to JSON")
    parser.add_argument("--output", default="org_topology.json", help="Output JSON filename")
    args = parser.parse_args()

    success = True
    accounts_found_count = 0
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    client = boto3.client("organizations")

    print("[*] Verifying AWS Organization access...")
    try:
        org_desc = client.describe_organization()["Organization"]
    except ClientError as e:
        print(f"[X] Failed to access AWS Organizations. Ensure you are running from the Management Account. Error: {e}")
        success = False
        org_desc = {}

    if success:
        try:
            # Find Root ID
            roots = client.list_roots()["Roots"]
            root_id = roots[0]["Id"]
            root_name = roots[0]["Name"]

            print(f"[*] Building Organization Tree from Root: {root_name} ({root_id})...")
            
            # Process Root node hierarchy
            root_hierarchy = get_ou_hierarchy(client, root_id, parent_path=root_name)
            root_hierarchy["Id"] = root_id
            root_hierarchy["Name"] = root_name
            root_hierarchy["Path"] = root_name

            accounts_found_count = count_all_accounts(root_hierarchy)

            org_tree = {
                "OrganizationId": org_desc.get("Id"),
                "MasterAccountArn": org_desc.get("MasterAccountArn"),
                "MasterAccountId": org_desc.get("MasterAccountId"),
                "RootId": root_id,
                "RootName": root_name,
                "Hierarchy": root_hierarchy
            }

            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(org_tree, f, indent=2, default=str)

            print(f"[+] Organization topology successfully written to {args.output}")
        except Exception as e:
            print(f"[X] Error occurred during organization discovery: {e}")
            success = False

    # Write automation results status file
    automation_dir = Path("automation_results")
    automation_dir.mkdir(parents=True, exist_ok=True)
    
    result_payload = {
        "Name": "AWS Organization Discovery",
        "Status": "Successful" if success else "Failed",
        "Lastrun": timestamp,
        "AccountsFound": accounts_found_count
    }

    result_file = automation_dir / "find_awsou_dashboard_status.json"
    with open(result_file, "w", encoding="utf-8") as rf:
        json.dump(result_payload, rf, indent=2)
    print(f"[+] Automation run status saved to {result_file}")

if __name__ == "__main__":
    main()
