#!/usr/bin/env python3

import argparse
import getpass
import os
import sys
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def pano_api(panorama, api_key, params, verify_ssl=False):
    url = f"https://{panorama}/api/"

    response = requests.post(
        url,
        params=params,
        headers={"X-PAN-KEY": api_key},
        verify=verify_ssl,
        timeout=120,
    )

    response.raise_for_status()

    try:
        root = ET.fromstring(response.content)
    except ET.ParseError:
        raise RuntimeError(
            f"Panorama returned invalid XML:\n{response.text[:1000]}"
        )

    if root.attrib.get("status") != "success":
        msg = root.findtext(".//msg")
        raise RuntimeError(
            f"Panorama API error: {msg or response.text[:1000]}"
        )

    return response.content, root


def get_panorama_config(panorama, api_key, verify_ssl=False):
    """
    Pull the complete active Panorama configuration.
    """

    params = {
        "type": "config",
        "action": "show",
    }

    content, _ = pano_api(
        panorama,
        api_key,
        params,
        verify_ssl,
    )

    return content


def get_connected_firewalls(panorama, api_key, verify_ssl=False):
    """
    Get Panorama's currently connected managed firewalls.
    """

    params = {
        "type": "op",
        "cmd": "<show><devices><connected></connected></devices></show>",
    }

    content, root = pano_api(
        panorama,
        api_key,
        params,
        verify_ssl,
    )

    firewalls = []

    for entry in root.findall(".//devices/entry"):
        hostname = entry.findtext("hostname")
        serial = entry.findtext("serial")
        ip_address = entry.findtext("ip-address")

        if not serial:
            continue

        firewalls.append({
            "hostname": hostname or serial,
            "ip": ip_address or "",
            "serial": serial,
        })

    return firewalls


def main():

    parser = argparse.ArgumentParser(
        description="Pull Panorama XML and connected firewall inventory."
    )

    parser.add_argument(
        "--panorama",
        required=True,
        help="Panorama hostname or IP",
    )

    parser.add_argument(
        "--pan-key",
        default=os.environ.get("PAN_KEY"),
        help="Panorama API key or PAN_KEY environment variable",
    )

    parser.add_argument(
        "--output",
        default="pan-backup",
        help="Output directory",
    )

    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify Panorama TLS certificate",
    )

    args = parser.parse_args()

    if not args.pan_key:
        print(
            "ERROR: Panorama API key required.\n"
            "Use --pan-key or set PAN_KEY.",
            file=sys.stderr,
        )
        sys.exit(1)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    date_string = datetime.now().strftime("%Y-%m-%d")

    print()
    print("=" * 70)
    print("PANORAMA BACKUP / INVENTORY")
    print("=" * 70)
    print(f"Panorama: {args.panorama}")
    print(f"Output  : {output_dir.resolve()}")
    print()

    # ------------------------------------------------------------
    # 1. Pull Panorama configuration
    # ------------------------------------------------------------

    print("[1/2] Pulling Panorama full XML...")

    try:
        panorama_xml = get_panorama_config(
            args.panorama,
            args.pan_key,
            args.verify_ssl,
        )

        panorama_file = (
            output_dir / f"panorama-{date_string}.xml"
        )

        panorama_file.write_bytes(panorama_xml)

        print(f"      Saved: {panorama_file}")

    except Exception as exc:
        print(
            f"ERROR pulling Panorama config: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)

    # ------------------------------------------------------------
    # 2. Get connected firewalls
    # ------------------------------------------------------------

    print()
    print("[2/2] Getting connected firewall list...")

    try:
        firewalls = get_connected_firewalls(
            args.panorama,
            args.pan_key,
            args.verify_ssl,
        )

    except Exception as exc:
        print(
            f"ERROR getting firewall inventory: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)

    firewall_file = (
        output_dir / f"firewalls-{date_string}.txt"
    )

    with firewall_file.open("w") as f:

        # Header
        f.write("# hostname|ip|serial\n")

        for firewall in firewalls:
            f.write(
                f"{firewall['hostname']}|"
                f"{firewall['ip']}|"
                f"{firewall['serial']}\n"
            )

    print(f"      Found {len(firewalls)} connected firewalls")
    print(f"      Saved: {firewall_file}")

    print()
    print("Firewalls:")
    print()

    for firewall in firewalls:
        print(
            f"  {firewall['hostname']:<30} "
            f"{firewall['ip']:<16} "
            f"{firewall['serial']}"
        )

    print()
    print("Done.")


if __name__ == "__main__":
    main()
