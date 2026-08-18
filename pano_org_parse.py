#!/usr/bin/env python3
"""
Deep Panorama XML Config to Topology Generator
----------------------------------------------
Extracts full metadata for all managed firewalls, templates, template stacks,
and device groups from a Panorama running-config.xml dump.

Usage:
    python parse_panorama_xml.py -x running-config.xml -o panorama_topology.json
"""

from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def parse_panorama_xml(xml_path: Path) -> dict[str, Any]:
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # 1. Map Managed Devices (Serial -> Rich Metadata)
    devices_map: dict[str, dict[str, Any]] = {}

    # Scan all possible locations where managed devices are registered
    device_nodes = (
        root.findall(".//mgt-config/devices/entry") +
        root.findall(".//config/devices/entry/device/entry") +
        root.findall(".//devices/entry")
    )

    for dev in device_nodes:
        serial = dev.get("name", "").strip()
        # Skip local panorama node identifiers
        if not serial or serial in ("localhost.localdomain", "localhost"):
            continue

        hostname = dev.findtext("hostname", default="").strip()
        model = dev.findtext("model", default="PAN-OS Device").strip()
        ip = dev.findtext("ip-address", default="").strip()
        sw_version = dev.findtext("sw-version", default="").strip()

        # Extract vsys bindings if present
        vsys_list = [v.get("name") for v in dev.findall("./vsys/entry") if v.get("name")]

        devices_map[serial] = {
            "Serial": serial,
            "Hostname": hostname if hostname else serial,
            "Model": model,
            "IP": ip,
            "SoftwareVersion": sw_version,
            "VSYS": vsys_list
        }

    # Helper function to extract serials from any node structure
    def extract_serials(parent_node: ET.Element) -> list[dict[str, Any]]:
        resolved = []
        found_serials = set()

        # Check <devices/entry name="SERIAL">
        for dev_entry in parent_node.findall(".//devices/entry"):
            s_id = dev_entry.get("name", "").strip()
            if s_id and s_id not in ("localhost.localdomain", "localhost"):
                found_serials.add(s_id)

        # Check <devices/member>SERIAL</member> or <target/devices/entry>
        for member in parent_node.findall(".//devices/member") + parent_node.findall(".//target/devices/entry"):
            s_id = (member.get("name") or member.text or "").strip()
            if s_id and s_id not in ("localhost.localdomain", "localhost"):
                found_serials.add(s_id)

        for s_id in sorted(found_serials):
            if s_id in devices_map:
                resolved.append(devices_map[s_id])
            else:
                resolved.append({
                    "Serial": s_id,
                    "Hostname": s_id,
                    "Model": "Managed Firewall",
                    "IP": "",
                    "SoftwareVersion": "",
                    "VSYS": []
                })
        return resolved

    # 2. Parse Templates & Template Stacks (Deep Search)
    templates_list = []

    # Individual Templates
    for tpl in root.findall(".//template/entry"):
        tpl_name = tpl.get("name", "")
        if not tpl_name:
            continue
        desc = tpl.findtext("description", default="").strip()
        templates_list.append({
            "Name": tpl_name,
            "Type": "Template",
            "Description": desc,
            "Firewalls": extract_serials(tpl)
        })

    # Template Stacks
    for stack in root.findall(".//template-stack/entry"):
        stack_name = stack.get("name", "")
        if not stack_name:
            continue
        desc = stack.findtext("description", default="").strip()
        members = [m.text.strip() for m in stack.findall("./templates/member") if m.text]
        if members:
            desc = f"Stack Members: [{', '.join(members)}]. {desc}".strip()

        templates_list.append({
            "Name": stack_name,
            "Type": "Template Stack",
            "Description": desc,
            "Firewalls": extract_serials(stack)
        })

    # 3. Parse Device Groups (Deep Search)
    device_groups_list = []
    for dg in root.findall(".//device-group/entry"):
        dg_name = dg.get("name", "")
        if not dg_name:
            continue
        desc = dg.findtext("description", default="").strip()
        parent = dg.findtext("parent-dg", default="shared").strip()

        device_groups_list.append({
            "Name": dg_name,
            "Parent": parent,
            "Description": desc,
            "Firewalls": extract_serials(dg)
        })

    # 4. Global Metadata & Fallback Standalone Managed Devices Group
    pano_name = root.findtext(".//config/mgt-config/system/hostname", default="Panorama").strip()

    # Create an explicit inventory node containing all 182 devices
    all_managed_devices = list(devices_map.values())

    return {
        "PanoramaName": pano_name,
        "TotalManagedDevices": len(all_managed_devices),
        "ManagedDevices": all_managed_devices,
        "Templates": templates_list,
        "DeviceGroups": device_groups_list
    }


def main():
    parser = argparse.ArgumentParser(description="Extract Full Panorama Firewall Topology")
    parser.add_argument("-x", "--xml", required=True, help="Panorama running-config XML file")
    parser.add_argument("-o", "--out", default="panorama_topology.json", help="Output JSON path")
    args = parser.parse_args()

    xml_file = Path(args.xml).resolve()
    out_file = Path(args.out).resolve()

    if not xml_file.exists():
        raise FileNotFoundError(f"XML file not found: {xml_file}")

    print(f"[*] Parsing Panorama XML: {xml_file} ...")
    topology = parse_panorama_xml(xml_file)

    with out_file.open("w", encoding="utf-8") as f:
        json.dump(topology, f, indent=2)

    print(f"[✓] Extracted metadata for {topology['TotalManagedDevices']} managed firewalls.")
    print(f"[✓] Found {len(topology['Templates'])} templates/stacks and {len(topology['DeviceGroups'])} device groups.")
    print(f"[*] Exported to: {out_file}")


if __name__ == "__main__":
    main()
