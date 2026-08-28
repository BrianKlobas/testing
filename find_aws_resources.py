#!/usr/bin/env python3
"""
AWS Multi-Account / Multi-Region Infrastructure Ingester (Fine-Grained Concurrency)
----------------------------------------------------------------------------------
Reads organization json mapping, assumes cross-account roles, and exports
comprehensive resource snapshots concurrently by parallelizing at the region-account level.

Run:
    python aws_infra_ingest.py --org-file org_topology.json --role-name OrganizationAccountAccessRole --output-dir ./aws_parsed
"""

from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import boto3
from botocore.exceptions import ClientError

TARGET_REGIONS = [
    "us-east-1",      # use1
    "us-east-2",      # use2
    "us-west-2",      # usw2
    "ap-southeast-1", # apse1
    "ap-south-1"      # aps1
]

def flatten_accounts(node, account_list=None):
    """Recursively extract all account records from the nested OU hierarchy."""[cite: 4]
    if account_list is None:
        account_list = []
    
    for acc in node.get("Accounts", []):
        if acc.get("Status") == "ACTIVE" or acc.get("State") == "ACTIVE":
            account_list.append(acc)
            
    for ou in node.get("OUs", []):
        flatten_accounts(ou["Children"], account_list)
        
    return account_list

def assume_spoke_role(account_id: str, role_name: str) -> boto3.Session | None:
    """Assume execution role in target spoke account via STS."""[cite: 4]
    sts_client = boto3.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="InfraIngestSession",
            DurationSeconds=3600
        )
        creds = response["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
    except ClientError as e:
        print(f"    [!] Could not assume role {role_arn}: {e}")
        return None

def serialize_datetime(obj):
    """Helper to convert datetime fields for JSON serialization."""[cite: 4]
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def harvest_region_data(session: boto3.Session, region: str) -> dict:
    """Collects target infrastructure assets and tagging metadata within a specific region."""[cite: 4]
    data = {
        "vpcs": [],
        "subnets": [],
        "enis": [],
        "load_balancers": [],
        "ec2_instances": [],
        "rds_instances": [],
        "security_groups": []
    }

    try:
        ec2 = session.client("ec2", region_name=region)
        elbv2 = session.client("elbv2", region_name=region)
        elb = session.client("elb", region_name=region)
        rds = session.client("rds", region_name=region)
    except Exception as e:
        print(f"    [!] Failed to initialize regional clients for {region}: {e}")
        return data

    # 1. VPCs
    try:
        paginator = ec2.get_paginator("describe_vpcs")
        for page in paginator.paginate():
            data["vpcs"].extend(page.get("Vpcs", []))
    except ClientError as e:
        print(f"    [x] Error fetching VPCs in {region}: {e}")

    # 2. Subnets
    try:
        paginator = ec2.get_paginator("describe_subnets")
        for page in paginator.paginate():
            data["subnets"].extend(page.get("Subnets", []))
    except ClientError as e:
        print(f"    [x] Error fetching Subnets in {region}: {e}")

    # 3. ENIs
    try:
        paginator = ec2.get_paginator("describe_network_interfaces")
        for page in paginator.paginate():
            data["enis"].extend(page.get("NetworkInterfaces", []))
    except ClientError as e:
        print(f"    [x] Error fetching ENIs in {region}: {e}")

    # 4. ALBs, NLBs & Classic Load Balancers
    try:
        paginator = elbv2.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for alb in page.get("LoadBalancers", []):
                lb_arn = alb["LoadBalancerArn"]
                tag_resp = elbv2.describe_tags(ResourceArns=[lb_arn])
                alb["Tags"] = tag_resp.get("TagDescriptions", [{}])[0].get("Tags", [])
                data["load_balancers"].append(alb)
    except ClientError as e:
        print(f"    [x] Error fetching ELBv2 in {region}: {e}")

    try:
        clb_resp = elb.describe_load_balancers()
        for clb in clb_resp.get("LoadBalancerDescriptions", []):
            clb_name = clb["LoadBalancerName"]
            tag_resp = elb.describe_tags(LoadBalancerNames=[clb_name])
            clb["Tags"] = tag_resp.get("TagDescriptions", [{}])[0].get("Tags", [])
            data["load_balancers"].append(clb)
    except ClientError as e:
        print(f"    [x] Error fetching Classic LBs in {region}: {e}")

    # 5. EC2 Instances
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                data["ec2_instances"].extend(reservation.get("Instances", []))
    except ClientError as e:
        print(f"    [x] Error fetching EC2 instances in {region}: {e}")

    # 6. RDS Databases
    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                try:
                    tag_resp = rds.list_tags_for_resource(ResourceName=db["DBInstanceArn"])
                    db["Tags"] = tag_resp.get("TagList", [])
                except Exception:
                    db["Tags"] = []
                data["rds_instances"].append(db)
    except ClientError as e:
        print(f"    [x] Error fetching RDS instances in {region}: {e}")

    # 7. Security Groups & Rules
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            data["security_groups"].extend(page.get("SecurityGroups", []))
    except ClientError as e:
        print(f"    [x] Error fetching Security Groups in {region}: {e}")

    return data

def harvest_global_route53(session: boto3.Session) -> list:
    """Route53 is a global service; capture hosted zones and record sets."""[cite: 4]
    zones_data = []
    try:
        r53 = session.client("route53")
        paginator = r53.get_paginator("list_hosted_zones")
        for page in paginator.paginate():
            for zone in page.get("HostedZones", []):
                zone_id = zone["Id"].split("/")[-1]
                records = []
                rec_paginator = r53.get_paginator("list_resource_record_sets")
                for rec_page in rec_paginator.paginate(HostedZoneId=zone_id):
                    records.extend(rec_page.get("ResourceRecordSets", []))
                
                zone["ResourceRecordSets"] = records
                zones_data.append(zone)
    except ClientError as e:
        print(f"    [!] Error pulling Route53 zones: {e}")
    return zones_data

def process_region_task(acc_id, acc_name, region, role_name, base_output_path):
    """Worker task handling a single region for a single account."""
    spoke_session = assume_spoke_role(acc_id, role_name)
    if not spoke_session:
        return

    account_dir = base_output_path / f"{acc_id}_{acc_name}"
    regional_data = harvest_region_data(spoke_session, region)
    region_dir = account_dir / region
    region_dir.mkdir(parents=True, exist_ok=True)

    for service_type, items in regional_data.items():
        if not items:
            continue
        file_path = region_dir / f"{service_type}.json"
        with open(file_path, "w", encoding="utf-8") as sf:
            json.dump(items, sf, indent=2, default=serialize_datetime)

def process_global_task(acc_id, acc_name, role_name, base_output_path):
    """Worker task handling global Route53 for a single account."""
    spoke_session = assume_spoke_role(acc_id, role_name)
    if not spoke_session:
        return

    r53_data = harvest_global_route53(spoke_session)
    if r53_data:
        account_dir = base_output_path / f"{acc_id}_{acc_name}"
        global_dir = account_dir / "global"
        global_dir.mkdir(parents=True, exist_ok=True)
        with open(global_dir / "route53_zones_and_records.json", "w", encoding="utf-8") as rf:
            json.dump(r53_data, rf, indent=2, default=serialize_datetime)

def main():
    parser = argparse.ArgumentParser(description="Multithreaded AWS Infrastructure Ingester")
    parser.add_argument("--org-file", default="org_topology.json", help="Path to organization JSON")[cite: 4]
    parser.add_argument("--role-name", default="OrganizationAccountAccessRole", help="Cross-account role name")[cite: 4]
    parser.add_argument("--output-dir", default="./aws_parsed", help="Root directory for output records")[cite: 4]
    parser.add_argument("--max-workers", type=int, default=50, help="Number of concurrent regional/global threads")
    args = parser.parse_args()

    if not os.path.exists(args.org_file):
        print(f"[X] Organization file '{args.org_file}' not found. Run script 1 first.")[cite: 4]
        return

    with open(args.org_file, "r", encoding="utf-8") as f:
        org_data = json.load(f)

    accounts = flatten_accounts(org_data["Hierarchy"])
    print(f"[*] Found {len(accounts)} active accounts. Launching fine-grained ThreadPoolExecutor with {args.max_workers} workers...")[cite: 4]

    base_output_path = Path(args.output_dir)
    base_output_path.mkdir(parents=True, exist_ok=True)

    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        futures = []
        for acc in accounts:
            acc_id = acc["Id"]
            acc_name = acc["Name"].replace(" ", "_")
            
            # Submit individual tasks for each region across all accounts concurrently
            for region in TARGET_REGIONS:
                futures.append(
                    executor.submit(process_region_task, acc_id, acc_name, region, args.role_name, base_output_path)
                )
            
            # Submit global route53 task for the account
            futures.append(
                executor.submit(process_global_task, acc_id, acc_name, args.role_name, base_output_path)
            )

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"[X] Exception encountered in worker task: {e}")[cite: 4]

    print(f"\n[+] All fine-grained multithreaded account ingestion jobs complete! Artifacts saved under: {args.output_dir}")[cite: 4]

if __name__ == "__main__":
    main()
