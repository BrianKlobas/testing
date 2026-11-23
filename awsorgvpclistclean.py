import re
import time
import threading
import concurrent.futures
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# ==============================================================================
# CONFIGURATION
# ==============================================================================
INPUT_ORG_EXCEL = "aws_organization_inventory.xlsx"
OUTPUT_VPC_EXCEL = "aws_vpc_cidr_inventory.xlsx"
TARGET_REGIONS = ["us-east-1", "us-east-2", "us-west-2"]

# Cross-account IAM role name assumed in each member account
CROSS_ACCOUNT_ROLE_NAME = "OrganizationAccountAccessRole"

# High-throughput concurrency settings:
# Effective concurrent API streams = ACCOUNT_WORKERS * len(TARGET_REGIONS) (40 * 3 = 120)
ACCOUNT_WORKERS = 40
REGION_WORKERS_PER_ACCOUNT = len(TARGET_REGIONS)

# Boto3 client config: larger connection pool + adaptive retries for AWS API rate limits
BOTO_CONFIG = Config(
    max_pool_connections=100,
    retries={
        "max_attempts": 10,
        "mode": "adaptive",
    },
    connect_timeout=10,
    read_timeout=30,
)

_thread_local = threading.local()


def get_thread_sts_client():
    """Return a thread-local STS client with adaptive retries and expanded connection pool."""
    if not hasattr(_thread_local, "sts"):
        _thread_local.sts = boto3.client("sts", config=BOTO_CONFIG)
    return _thread_local.sts


def sanitize_sheet_title(name: str, existing_titles: set) -> str:
    """Sanitize and deduplicate Excel worksheet names (max 31 chars, no invalid chars)."""
    cleaned = re.sub(r'[:\\/?*\[\]]', '_', name).strip()
    if not cleaned:
        cleaned = "Sheet"
    base = cleaned[:31]
    candidate = base
    counter = 1
    while candidate.lower() in {t.lower() for t in existing_titles}:
        suffix = f"_{counter}"
        candidate = f"{base[:31 - len(suffix)]}{suffix}"
        counter += 1
    existing_titles.add(candidate)
    return candidate


def load_active_accounts_from_excel(excel_path: str) -> dict:
    """
    Parse the previously generated AWS Organization workbook.
    Returns a dict keyed by top-level sheet/OU name containing active accounts
    with their OU path and metadata.
    """
    wb = openpyxl.load_workbook(excel_path, data_only=True)
    sections = {}

    for sheet_name in wb.sheetnames:
        if sheet_name.strip().lower() == "org overview":
            continue

        ws = wb[sheet_name]
        rows = list(ws.iter_rows(values_only=True))
        if not rows:
            continue

        headers = [str(h).strip() if h is not None else "" for h in rows[0]]
        col_map = {h: idx for idx, h in enumerate(headers)}

        required_cols = {"Resource Type", "Name", "ID", "Status", "Hierarchy Path"}
        if not required_cols.issubset(col_map.keys()):
            continue

        active_accounts = []
        for row in rows[1:]:
            res_type = row[col_map["Resource Type"]]
            status = str(row[col_map["Status"]] or "").strip().upper()

            if res_type == "Account" and status == "ACTIVE":
                raw_path = str(row[col_map["Hierarchy Path"]] or "").strip()
                path_parts = [p.strip() for p in raw_path.split("/")]
                ou_path = " / ".join(path_parts[:-1]) if len(path_parts) > 1 else sheet_name

                acct_id = str(row[col_map["ID"]] or "").strip()
                if acct_id.isdigit() and len(acct_id) < 12:
                    acct_id = acct_id.zfill(12)

                active_accounts.append({
                    "TopLevelSection": sheet_name,
                    "OUPath": ou_path,
                    "AccountName": str(row[col_map["Name"]] or "").strip(),
                    "AccountId": acct_id,
                    "Email": str(row[col_map["Email"]] or "").strip() if "Email" in col_map else "",
                    "TagsSummary": str(row[col_map["All Tags (Summary)"]] or "").strip()
                    if "All Tags (Summary)" in col_map
                    else "",
                })

        sections[sheet_name] = active_accounts

    return sections


def get_account_credentials(current_account_id: str, target_account_id: str, role_name: str) -> dict:
    """
    Assume role into target account using thread-local STS client.
    Returns raw temporary credential dict (or None if scanning the current account).
    """
    if target_account_id == current_account_id:
        return None

    sts = get_thread_sts_client()
    role_arn = f"arn:aws:iam::{target_account_id}:role/{role_name}"
    return sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=f"VPCInventory-{target_account_id}",
    )["Credentials"]


def fetch_region_vpcs(account: dict, region: str, creds: dict) -> list:
    """Query all VPCs in a single region for an account using pre-assumed credentials."""
    try:
        if creds is None:
            ec2 = boto3.client("ec2", region_name=region, config=BOTO_CONFIG)
        else:
            ec2 = boto3.client(
                "ec2",
                region_name=region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                config=BOTO_CONFIG,
            )

        paginator = ec2.get_paginator("describe_vpcs")
        vpcs = []
        for page in paginator.paginate():
            vpcs.extend(page.get("Vpcs", []))

        if not vpcs:
            return [{
                **account,
                "Region": region,
                "VpcId": "None",
                "VpcName": "-",
                "PrimaryCidr": "-",
                "SecondaryCidrs": "",
                "Ipv6Cidrs": "",
                "IsDefault": "",
                "State": "No VPCs",
                "DhcpOptionsId": "",
                "InstanceTenancy": "",
                "VpcTags": "",
            }]

        region_rows = []
        for vpc in vpcs:
            tags_dict = {t["Key"]: t["Value"] for t in vpc.get("Tags", [])}
            vpc_name = tags_dict.get("Name", "")
            tags_summary = ", ".join(f"{k}={v}" for k, v in sorted(tags_dict.items()))

            primary_cidr = vpc.get("CidrBlock", "")
            assoc_cidrs = [
                c["CidrBlock"]
                for c in vpc.get("CidrBlockAssociationSet", [])
                if c.get("CidrBlockState", {}).get("State") == "associated"
                and c.get("CidrBlock") != primary_cidr
            ]
            ipv6_cidrs = [
                c["Ipv6CidrBlock"]
                for c in vpc.get("Ipv6CidrBlockAssociationSet", [])
                if c.get("Ipv6CidrBlockState", {}).get("State") == "associated"
            ]

            region_rows.append({
                **account,
                "Region": region,
                "VpcId": vpc["VpcId"],
                "VpcName": vpc_name,
                "PrimaryCidr": primary_cidr,
                "SecondaryCidrs": ", ".join(assoc_cidrs),
                "Ipv6Cidrs": ", ".join(ipv6_cidrs),
                "IsDefault": "Yes" if vpc.get("IsDefault") else "No",
                "State": vpc.get("State", ""),
                "DhcpOptionsId": vpc.get("DhcpOptionsId", ""),
                "InstanceTenancy": vpc.get("InstanceTenancy", ""),
                "VpcTags": tags_summary,
            })
        return region_rows

    except ClientError as e:
        err_code = e.response["Error"]["Code"]
        return [{
            **account,
            "Region": region,
            "VpcId": "ERROR",
            "VpcName": "",
            "PrimaryCidr": "",
            "SecondaryCidrs": "",
            "Ipv6Cidrs": "",
            "IsDefault": "",
            "State": f"EC2Error ({err_code})",
            "DhcpOptionsId": "",
            "InstanceTenancy": "",
            "VpcTags": e.response["Error"]["Message"][:120],
        }]


def scan_account_vpcs(
    account: dict,
    regions: list,
    current_account_id: str,
    role_name: str,
) -> list:
    """
    Assume role once for the account, then fan out across all target regions
    simultaneously in parallel threads.
    """
    acct_id = account["AccountId"]

    try:
        creds = get_account_credentials(current_account_id, acct_id, role_name)
    except ClientError as e:
        err_code = e.response["Error"]["Code"]
        err_msg = e.response["Error"]["Message"]
        return [{
            **account,
            "Region": "ALL",
            "VpcId": "ERROR",
            "VpcName": "",
            "PrimaryCidr": "",
            "SecondaryCidrs": "",
            "Ipv6Cidrs": "",
            "IsDefault": "",
            "State": f"AssumeRoleFailed ({err_code})",
            "DhcpOptionsId": "",
            "InstanceTenancy": "",
            "VpcTags": err_msg[:120],
        }]

    results_by_region = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=REGION_WORKERS_PER_ACCOUNT) as reg_exec:
        future_map = {
            reg_exec.submit(fetch_region_vpcs, account, reg, creds): reg
            for reg in regions
        }
        for fut in concurrent.futures.as_completed(future_map):
            reg = future_map[fut]
            results_by_region[reg] = fut.result()

    ordered_results = []
    for reg in regions:
        ordered_results.extend(results_by_region[reg])
    return ordered_results


def style_ou_vpc_sheet(ws, rows: list):
    """Format an OU worksheet with clean styling, visual grouping, filters, and frozen headers."""
    headers = [
        "OU Hierarchy Path",
        "Account Name",
        "Account ID",
        "Region",
        "VPC ID",
        "VPC Name",
        "Primary IPv4 CIDR",
        "Secondary IPv4 CIDRs",
        "IPv6 CIDRs",
        "Default VPC",
        "State",
        "Tenancy",
        "DHCP Options ID",
        "VPC Tags",
        "Account Tags",
    ]

    header_fill = PatternFill(start_color="1F4E78", end_color="1F4E78", fill_type="solid")
    header_font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")

    regular_font = Font(name="Calibri", size=10, color="000000")
    muted_font = Font(name="Calibri", size=10, italic=True, color="7F7F7F")
    error_fill = PatternFill(start_color="FCE4D6", end_color="FCE4D6", fill_type="solid")
    error_font = Font(name="Calibri", size=10, bold=True, color="C00000")
    zebra_fill = PatternFill(start_color="F4F7FA", end_color="F4F7FA", fill_type="solid")
    white_fill = PatternFill(start_color="FFFFFF", end_color="FFFFFF", fill_type="solid")

    thin_side = Side(border_style="thin", color="D9D9D9")
    border = Border(left=thin_side, right=thin_side, top=thin_side, bottom=thin_side)

    ws.append(headers)
    for col_idx in range(1, len(headers) + 1):
        cell = ws.cell(row=1, column=col_idx)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
        cell.border = border
    ws.row_dimensions[1].height = 24

    last_acct = None
    band_toggle = False

    for row_idx, r in enumerate(rows, start=2):
        if r["AccountId"] != last_acct:
            band_toggle = not band_toggle
            last_acct = r["AccountId"]

        row_values = [
            r["OUPath"],
            r["AccountName"],
            r["AccountId"],
            r["Region"],
            r["VpcId"],
            r["VpcName"],
            r["PrimaryCidr"],
            r["SecondaryCidrs"],
            r["Ipv6Cidrs"],
            r["IsDefault"],
            r["State"],
            r["InstanceTenancy"],
            r["DhcpOptionsId"],
            r["VpcTags"],
            r["TagsSummary"],
        ]
        ws.append(row_values)

        is_error = r["VpcId"] == "ERROR"
        is_empty = r["VpcId"] == "None"

        for col_idx in range(1, len(headers) + 1):
            cell = ws.cell(row=row_idx, column=col_idx)
            cell.border = border
            cell.alignment = Alignment(vertical="center", wrap_text=False)

            if is_error:
                cell.fill = error_fill
                cell.font = error_font
            elif is_empty:
                cell.fill = zebra_fill if band_toggle else white_fill
                cell.font = muted_font
            else:
                cell.fill = zebra_fill if band_toggle else white_fill
                cell.font = regular_font

    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{max(len(rows) + 1, 1)}"

    for col_idx, header in enumerate(headers, start=1):
        col_letter = get_column_letter(col_idx)
        max_len = len(str(header))
        for r_i in range(2, len(rows) + 2):
            val = ws.cell(row=r_i, column=col_idx).value
            if val is not None:
                max_len = max(max_len, len(str(val)))
        ws.column_dimensions[col_letter].width = min(max_len + 4, 55)


def style_cidr_tracker_sheet(ws, all_vpc_rows: list):
    """
    Build a consolidated 'CIDR Master Tracker' sheet sorted numerically by IP block,
    flagging duplicate CIDRs across accounts.
    """
    headers = [
        "CIDR Block",
        "CIDR Type",
        "Overlap / Duplicate Flag",
        "Top-Level OU",
        "OU Hierarchy Path",
        "Account Name",
        "Account ID",
        "Region",
        "VPC ID",
        "VPC Name",
        "Default VPC",
        "VPC Tags",
    ]

    cidr_entries = []
    cidr_counts = {}

    for r in all_vpc_rows:
        if r["VpcId"] in ("None", "ERROR"):
            continue
        if r["PrimaryCidr"]:
            cidr_entries.append((r["PrimaryCidr"], "Primary IPv4", r))
            cidr_counts[r["PrimaryCidr"]] = cidr_counts.get(r["PrimaryCidr"], 0) + 1
        if r["SecondaryCidrs"]:
            for sec in [c.strip() for c in r["SecondaryCidrs"].split(",") if c.strip()]:
                cidr_entries.append((sec, "Secondary IPv4", r))
                cidr_counts[sec] = cidr_counts.get(sec, 0) + 1

    def cidr_sort_key(entry):
        cidr = entry[0]
        try:
            ip_part, prefix = cidr.split("/")
            octets = tuple(int(o) for o in ip_part.split("."))
            return (octets, int(prefix), entry[2]["Region"], entry[2]["AccountName"])
        except Exception:
            return ((999, 999, 999, 999), 99, "", "")

    cidr_entries.sort(key=cidr_sort_key)

    header_fill = PatternFill(start_color="1F4E78", end_color="1F4E78", fill_type="solid")
    header_font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    warn_fill = PatternFill(start_color="FFF2CC", end_color="FFF2CC", fill_type="solid")
    warn_font = Font(name="Calibri", size=10, bold=True, color="806000")
    regular_font = Font(name="Calibri", size=10, color="000000")

    thin_side = Side(border_style="thin", color="D9D9D9")
    border = Border(left=thin_side, right=thin_side, top=thin_side, bottom=thin_side)

    ws.append(headers)
    for col_idx in range(1, len(headers) + 1):
        c = ws.cell(row=1, column=col_idx)
        c.fill = header_fill
        c.font = header_font
        c.border = border
    ws.row_dimensions[1].height = 24

    for idx, (cidr, ctype, r) in enumerate(cidr_entries, start=2):
        count = cidr_counts.get(cidr, 1)
        flag = f"DUPLICATE ({count} VPCs)" if count > 1 else "Unique"

        ws.append([
            cidr,
            ctype,
            flag,
            r["TopLevelSection"],
            r["OUPath"],
            r["AccountName"],
            r["AccountId"],
            r["Region"],
            r["VpcId"],
            r["VpcName"],
            r["IsDefault"],
            r["VpcTags"],
        ])

        for col_idx in range(1, len(headers) + 1):
            cell = ws.cell(row=idx, column=col_idx)
            cell.border = border
            if count > 1:
                cell.fill = warn_fill
                cell.font = warn_font
            else:
                cell.font = regular_font

    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{max(len(cidr_entries) + 1, 1)}"

    for col_idx, header in enumerate(headers, start=1):
        col_letter = get_column_letter(col_idx)
        max_len = len(str(header))
        for r_i in range(2, len(cidr_entries) + 2):
            val = ws.cell(row=r_i, column=col_idx).value
            if val is not None:
                max_len = max(max_len, len(str(val)))
        ws.column_dimensions[col_letter].width = min(max_len + 4, 55)


def build_vpc_inventory():
    start_time = time.perf_counter()
    print(f"Loading active accounts from '{INPUT_ORG_EXCEL}'...")
    sections = load_active_accounts_from_excel(INPUT_ORG_EXCEL)

    all_accounts = [acct for accts in sections.values() for acct in accts]
    total_accts = len(all_accounts)
    print(
        f"Found {total_accts} ACTIVE accounts across {len(sections)} top-level sections.\n"
        f"Launching {ACCOUNT_WORKERS} concurrent account workers x {REGION_WORKERS_PER_ACCOUNT} "
        f"parallel region workers ({ACCOUNT_WORKERS * REGION_WORKERS_PER_ACCOUNT} max concurrent API streams)..."
    )

    sts = get_thread_sts_client()
    current_account_id = sts.get_caller_identity()["Account"]

    account_vpc_map = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=ACCOUNT_WORKERS) as executor:
        future_to_acct = {
            executor.submit(
                scan_account_vpcs,
                acct,
                TARGET_REGIONS,
                current_account_id,
                CROSS_ACCOUNT_ROLE_NAME,
            ): acct
            for acct in all_accounts
        }

        completed = 0
        for future in concurrent.futures.as_completed(future_to_acct):
            acct = future_to_acct[future]
            completed += 1
            account_vpc_map[acct["AccountId"]] = future.result()

            if completed % 25 == 0 or completed == total_accts:
                elapsed = time.perf_counter() - start_time
                rate = completed / elapsed if elapsed > 0 else 0
                eta = (total_accts - completed) / rate if rate > 0 else 0
                print(
                    f"Progress: {completed}/{total_accts} accounts "
                    f"({elapsed:.1f}s elapsed | {rate:.1f} accts/sec | ETA: {eta:.1f}s)"
                )

    section_results = []
    all_rows_flat = []

    for sec_name, accts in sections.items():
        sec_rows = []
        for acct in accts:
            sec_rows.extend(account_vpc_map.get(acct["AccountId"], []))
        section_results.append((sec_name, accts, sec_rows))
        all_rows_flat.extend(sec_rows)

    wb = openpyxl.Workbook()
    wb.remove(wb.active)
    used_titles = set()

    # 1. Overview Sheet
    overview_ws = wb.create_sheet(title=sanitize_sheet_title("VPC Overview", used_titles))
    overview_headers = [
        "Top-Level OU / Section",
        "Active Accounts",
        *[f"VPCs ({reg})" for reg in TARGET_REGIONS],
        "Total VPCs",
        "Non-Default VPCs",
        "Accounts w/ Errors",
    ]

    header_fill = PatternFill(start_color="1F4E78", end_color="1F4E78", fill_type="solid")
    header_font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    thin_side = Side(border_style="thin", color="D9D9D9")
    border = Border(left=thin_side, right=thin_side, top=thin_side, bottom=thin_side)

    overview_ws.append(overview_headers)
    for col_idx in range(1, len(overview_headers) + 1):
        c = overview_ws.cell(row=1, column=col_idx)
        c.fill = header_fill
        c.font = header_font
        c.border = border
    overview_ws.row_dimensions[1].height = 24

    num_regions = len(TARGET_REGIONS)
    first_reg_col = get_column_letter(3)
    last_reg_col = get_column_letter(2 + num_regions)

    for idx, (sec_name, accts, sec_rows) in enumerate(section_results, start=2):
        valid_vpcs = [r for r in sec_rows if r["VpcId"] not in ("None", "ERROR")]
        reg_counts = [sum(1 for v in valid_vpcs if v["Region"] == reg) for reg in TARGET_REGIONS]
        non_default = sum(1 for v in valid_vpcs if v["IsDefault"] == "No")
        err_accts = len({r["AccountId"] for r in sec_rows if r["VpcId"] == "ERROR"})

        overview_ws.append([
            sec_name,
            len(accts),
            *reg_counts,
            f"=SUM({first_reg_col}{idx}:{last_reg_col}{idx})",
            non_default,
            err_accts,
        ])
        for col_idx in range(1, len(overview_headers) + 1):
            overview_ws.cell(row=idx, column=col_idx).border = border

    total_row = len(section_results) + 2
    sum_formulas = [
        f"=SUM({get_column_letter(c)}{2}:{get_column_letter(c)}{total_row - 1})"
        for c in range(2, len(overview_headers) + 1)
    ]
    overview_ws.append(["TOTAL", *sum_formulas])
    for col_idx in range(1, len(overview_headers) + 1):
        c = overview_ws.cell(row=total_row, column=col_idx)
        c.font = Font(name="Calibri", size=11, bold=True)
        c.border = border

    overview_ws.freeze_panes = "A2"
    for col_idx, header in enumerate(overview_headers, start=1):
        col_letter = get_column_letter(col_idx)
        max_len = max(
            len(str(header)),
            *(len(str(overview_ws.cell(row=r, column=col_idx).value or "")) for r in range(2, total_row + 1)),
        )
        overview_ws.column_dimensions[col_letter].width = min(max_len + 4, 50)

    # 2. Global CIDR Master Tracker Sheet
    cidr_ws = wb.create_sheet(title=sanitize_sheet_title("CIDR Master Tracker", used_titles))
    style_cidr_tracker_sheet(cidr_ws, all_rows_flat)

    # 3. One Dedicated Tab per Top-Level OU
    for sec_name, _accts, sec_rows in section_results:
        ws = wb.create_sheet(title=sanitize_sheet_title(sec_name, used_titles))
        style_ou_vpc_sheet(ws, sec_rows)

    wb.save(OUTPUT_VPC_EXCEL)
    total_elapsed = time.perf_counter() - start_time
    print(f"Completed in {total_elapsed:.1f}s! Exported '{OUTPUT_VPC_EXCEL}'.")


if __name__ == "__main__":
    build_vpc_inventory()
