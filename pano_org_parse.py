#!/usr/bin/env python3
"""
Panorama XML Config to Topology Generator
-----------------------------------------
Parses a Panorama running configuration XML dump and exports a structured
JSON topology file (`panorama_topology.json`) containing Templates, Template Stacks,
Device Groups, and associated Firewall devices.

Usage:
    python parse_panorama_xml.py --xml running-config.xml --out panorama_topology.json
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
    
    # Check both standard config locations for managed devices
    device_entries = root.findall(".//devices/entry") + root.findall(".//mgt-config/devices/entry")
    for dev in device_entries:
        serial = dev.get("name", "").strip()
        if not serial or serial == "localhost.localdomain":
            continue

        hostname_node = dev.find("hostname")
        model_node = dev.find("model")
        ip_node = dev.find("ip-address")

        hostname = hostname_node.text.strip() if hostname_node is not None and hostname_node.text else serial
        model = model_node.text.strip() if model_node is not None and model_node.text else "PAN-OS Device"
        ip = ip_node.text.strip() if ip_node is not None and ip_node.text else ""

        devices_map[serial] = {
            "Serial": serial,
            "Hostname": hostname,
            "Model": model,
            "IP": ip
        }

    # Helper function to get device metadata list from serial strings or nodes
    def resolve_devices(device_nodes) -> list[dict[str, str]]:
        resolved = []
        for dev_node in device_nodes:
            # Serial can be in the 'name' attribute or node text
            s_id = dev_node.get("name") or dev_node.text
            if s_id:
                s_id = s_id.strip()
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

    # Individual Templates
    for tpl in root.findall(".//config/devices/entry/template/entry"):
        tpl_name = tpl.get("name", "")
        desc_node = tpl.find("description")
        desc = desc_node.text.strip() if desc_node is not None and desc_node.text else ""
        dev_nodes = tpl.findall("./devices/entry")

        templates_list.append({
            "Name": tpl_name,
            "Type": "Template",
            "Description": desc,
            "Firewalls": resolve_devices(dev_nodes)
        })

    # Template Stacks
    for stack in root.findall(".//config/devices/entry/template-stack/entry"):
        stack_name = stack.get("name", "")
        desc_node = stack.find("description")
        desc = desc_node.text.strip() if desc_node is not None and desc_node.text else ""
        dev_nodes = stack.findall("./devices/entry")
        
        # Associated sub-templates in stack
        member_templates = [t.text.strip() for t in stack.findall("./templates/member") if t.text]
        if member_templates:
            desc = f"Stack members: [{', '.join(member_templates)}]. {desc}".strip()

        templates_list.append({
            "Name": stack_name,
            "Type": "Template Stack",
            "Description": desc,
            "Firewalls": resolve_devices(dev_nodes)
        })

    # 3. Parse Device Groups
    device_groups_list = []

    for dg in root.findall(".//config/devices/entry/device-group/entry"):
        dg_name = dg.get("name", "")
        desc_node = dg.find("description")
        parent_node = dg.find("parent-dg")
        
        desc = desc_node.text.strip() if desc_node is not None and desc_node.text else ""
        parent = parent_node.text.strip() if parent_node is not None and parent_node.text else "shared"
        
        dev_nodes = dg.findall("./devices/entry")

        device_groups_list.append({
            "Name": dg_name,
            "Parent": parent,
            "Description": desc,
            "Firewalls": resolve_devices(dev_nodes)
        })

    # 4. Construct Final Topology JSON Payload
    panorama_name_node = root.find(".//config/mgt-config/system/hostname")
    pano_name = panorama_name_node.text.strip() if panorama_name_node is not None and panorama_name_node.text else "Panorama"

    return {
        "PanoramaName": pano_name,
        "Templates": templates_list,
        "DeviceGroups": device_groups_list
    }


def main():
    parser = argparse.ArgumentParser(description="Parse Panorama running-config XML into panorama_topology.json")
    parser.add_argument("-x", "--xml", required=True, help="Path to Panorama XML configuration file")
    parser.add_argument("-o", "--out", default="panorama_topology.json", help="Output JSON path (default: panorama_topology.json)")
    args = parser.parse_args()

    xml_file = Path(args.xml).resolve()
    out_file = Path(args.out).resolve()

    if not xml_file.exists():
        raise FileNotFoundError(f"XML file not found: {xml_file}")

    print(f"[*] Parsing Panorama XML: {xml_file} ...")
    topology = parse_panorama_xml(xml_file)

    with out_file.open("w", encoding="utf-8") as f:
        json.dump(topology, f, indent=2)

    print(f"[✓] Successfully generated topology JSON with {len(topology['Templates'])} templates/stacks and {len(topology['DeviceGroups'])} device groups.")
    print(f"[*] Saved to: {out_file}")


if __name__ == "__main__":
    main()
