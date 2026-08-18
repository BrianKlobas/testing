#!/usr/bin/env python3
"""
Robust Panorama XML Config to Topology Generator
------------------------------------------------
Parses Panorama running-config.xml and builds panorama_topology.json
handling flexible XML structure formats for device members.
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

    # 1. Map Managed Devices (Serial -> Metadata)
    devices_map: dict[str, dict[str, str]] = {}

    # Scan both mgt-config and standard devices config paths
    device_entries = root.findall(".//mgt-config/devices/entry") + root.findall(".//config/devices/entry/device/entry")
    if not device_entries:
        device_entries = root.findall(".//devices/entry")

    for dev in device_entries:
        serial = dev.get("name", "").strip()
        if not serial or serial in ("localhost.localdomain", "localhost"):
            continue

        hostname = dev.findtext("hostname", default=serial).strip()
        model = dev.findtext("model", default="PAN-OS Device").strip()
        ip = dev.findtext("ip-address", default="").strip()

        devices_map[serial] = {
            "Serial": serial,
            "Hostname": hostname if hostname else serial,
            "Model": model,
            "IP": ip
        }

    def resolve_firewalls_from_parent(parent_node: ET.Element) -> list[dict[str, str]]:
        """Extracts firewalls referenced either as <entry name='SERIAL'/> or <member>SERIAL</member>."""
        resolved = []
        found_serials = set()

        # Check <devices/entry name="SERIAL">
        for dev_entry in parent_node.findall("./devices/entry"):
            s_id = dev_entry.get("name", "").strip()
            if s_id:
                found_serials.add(s_id)

        # Check <devices/member>SERIAL</member>
        for dev_member in parent_node.findall("./devices/member"):
            s_id = (dev_member.text or "").strip()
            if s_id:
                found_serials.add(s_id)

        # Map serials to rich device data
        for s_id in sorted(found_serials):
            if s_id in devices_map:
                resolved.append(devices_map[s_id])
            else:
                resolved.append({
                    "Serial": s_id,
                    "Hostname": s_id,
                    "Model": "Managed Firewall",
                    "IP": ""
                })
        return resolved

    # 2. Parse Templates & Template Stacks
    templates_list = []

    # Standalone Templates
    for tpl in root.findall(".//config/devices/entry/template/entry"):
        tpl_name = tpl.get("name", "")
        desc = tpl.findtext("description", default="").strip()
        templates_list.append({
            "Name": tpl_name,
            "Type": "Template",
            "Description": desc,
            "Firewalls": resolve_firewalls_from_parent(tpl)
        })

    # Template Stacks
    for stack in root.findall(".//config/devices/entry/template-stack/entry"):
        stack_name = stack.get("name", "")
        desc = stack.findtext("description", default="").strip()
        
        members = [m.text.strip() for m in stack.findall("./templates/member") if m.text]
        if members:
            desc = f"Stack Members: [{', '.join(members)}]. {desc}".strip()

        templates_list.append({
            "Name": stack_name,
            "Type": "Template Stack",
            "Description": desc,
            "Firewalls": resolve_firewalls_from_parent(stack)
        })

    # 3. Parse Device Groups
    device_groups_list = []
    for dg in root.findall(".//config/devices/entry/device-group/entry"):
        dg_name = dg.get("name", "")
        desc = dg.findtext("description", default="").strip()
        parent = dg.findtext("parent-dg", default="shared").strip()

        device_groups_list.append({
            "Name": dg_name,
            "Parent": parent,
            "Description": desc,
            "Firewalls": resolve_firewalls_from_parent(dg)
        })

    # 4. Global Metadata
    pano_name = root.findtext(".//config/mgt-config/system/hostname", default="Panorama").strip()

    return {
        "PanoramaName": pano_name,
        "TotalManagedDevices": len(devices_map),
        "Templates": templates_list,
        "DeviceGroups": device_groups_list
    }


def main():
    parser = argparse.ArgumentParser(description="Extract Panorama Firewall Topology")
    parser.add_argument("-x", "--xml", required=True, help="Panorama running-config XML file")
    parser.add_argument("-o", "--out", default="panorama_topology.json", help="Output JSON path")
    args = parser.parse_args()

    xml_file = Path(args.xml).resolve()
    out_file = Path(args.out).resolve()

    print(f"[*] Parsing Panorama XML: {xml_file} ...")
    topology = parse_panorama_xml(xml_file)

    with out_file.open("w", encoding="utf-8") as f:
        json.dump(topology, f, indent=2)

    print(f"[✓] Created topology with {topology['TotalManagedDevices']} firewalls, "
          f"{len(topology['Templates'])} templates/stacks, and {len(topology['DeviceGroups'])} device groups.")


if __name__ == "__main__":
    main()
