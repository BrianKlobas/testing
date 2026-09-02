#!/usr/bin/env python3

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET


# ================================================================
# Configuration
# ================================================================

# XML containers that we know how to turn into individual objects.
#
# Each tuple is a sequence of XML path components. Matching is done
# against the complete path, but only the ending components need to
# match.
#
# This allows the parser to work with:
#
#   /config/shared/address
#   /config/devices/entry/shared/address
#   /config/devices/entry/device-group/entry/address
#
# etc.

OBJECT_TYPES = {

    "addresses": [
        ("shared", "address"),
        ("address",),
    ],

    "address_groups": [
        ("shared", "address-group"),
        ("address-group",),
    ],

    "services": [
        ("shared", "service"),
        ("service",),
    ],

    "service_groups": [
        ("shared", "service-group"),
        ("service-group",),
    ],

    "tags": [
        ("shared", "tag"),
        ("tag",),
    ],

    "security_rules": [
        ("pre-rulebase", "security", "rules"),
        ("post-rulebase", "security", "rules"),
        ("rulebase", "security", "rules"),
        ("security", "rules"),
    ],

    "nat_rules": [
        ("pre-rulebase", "nat", "rules"),
        ("post-rulebase", "nat", "rules"),
        ("rulebase", "nat", "rules"),
        ("nat", "rules"),
    ],

    "pbf_rules": [
        ("pre-rulebase", "pbf", "rules"),
        ("post-rulebase", "pbf", "rules"),
        ("rulebase", "pbf", "rules"),
        ("pbf", "rules"),
    ],

    "qos_rules": [
        ("pre-rulebase", "qos", "rules"),
        ("post-rulebase", "qos", "rules"),
        ("rulebase", "qos", "rules"),
        ("qos", "rules"),
    ],

    "decryption_rules": [
        ("pre-rulebase", "decryption", "rules"),
        ("post-rulebase", "decryption", "rules"),
        ("rulebase", "decryption", "rules"),
        ("decryption", "rules"),
    ],

    "application_override_rules": [
        ("pre-rulebase", "application-override", "rules"),
        ("post-rulebase", "application-override", "rules"),
        ("rulebase", "application-override", "rules"),
        ("application-override", "rules"),
    ],

    "authentication_rules": [
        ("pre-rulebase", "authentication", "rules"),
        ("post-rulebase", "authentication", "rules"),
        ("rulebase", "authentication", "rules"),
        ("authentication", "rules"),
    ],

    "zones": [
        ("zones",),
        ("zone",),
    ],

    "interfaces": [
        ("interface",),
    ],

    "virtual_routers": [
        ("virtual-router",),
    ],

    "ipsec_tunnels": [
        ("tunnel", "ipsec"),
        ("ipsec",),
    ],

}


# ================================================================
# Utility functions
# ================================================================

def strip_namespace(tag):
    """
    Remove XML namespace if one exists.
    """

    if "}" in tag:
        return tag.split("}", 1)[1]

    return tag


def clean_name(name):
    """
    Make a string safe for JSON / display.
    """

    if name is None:
        return ""

    return str(name)


def xml_to_dict(element):
    """
    Recursively convert an XML element into a Python dictionary.

    Repeated child elements are converted into lists.

    XML attributes are stored under @attributes.
    """

    result = {}

    # Preserve XML attributes.
    if element.attrib:
        result["@attributes"] = dict(element.attrib)

    children = list(element)

    if not children:

        text = element.text

        if text is not None:
            text = text.strip()

            if text:
                return text

        return result

    for child in children:

        tag = strip_namespace(child.tag)

        value = xml_to_dict(child)

        if tag in result:

            if not isinstance(result[tag], list):
                result[tag] = [result[tag]]

            result[tag].append(value)

        else:

            result[tag] = value

    return result


def normalize_for_json(value):
    """
    Make sure all values are JSON serializable.
    """

    if isinstance(value, dict):

        return {
            str(k): normalize_for_json(v)
            for k, v in value.items()
        }

    if isinstance(value, list):

        return [
            normalize_for_json(v)
            for v in value
        ]

    return value


def path_matches(path, pattern):
    """
    True if the end of 'path' matches 'pattern'.

    Example:

        path =
        config/devices/entry/device-group/entry/address

        pattern =
        address

    True.

    Or:

        pattern =
        device-group/entry/address

    True.
    """

    if len(path) < len(pattern):
        return False

    return tuple(path[-len(pattern):]) == tuple(pattern)


def element_path_string(path):
    return "/" + "/".join(path)


def get_entry_name(element):
    """
    Most PAN-OS objects are represented as:

        <entry name="object-name">

    Return that name.
    """

    return element.attrib.get("name", "")


# ================================================================
# XML traversal
# ================================================================

def walk_tree(element, path=None):
    """
    Yield:

        path, element

    for every XML element.
    """

    if path is None:
        path = []

    current_path = path + [strip_namespace(element.tag)]

    yield current_path, element

    for child in element:
        yield from walk_tree(
            child,
            current_path,
        )


def find_matching_containers(root, patterns):
    """
    Find XML containers matching one of the supplied patterns.

    Returns:

        (path, element)
    """

    matches = []

    for path, element in walk_tree(root):

        for pattern in patterns:

            if path_matches(path, pattern):

                matches.append(
                    (path, element)
                )

                break

    return matches


# ================================================================
# Object extraction
# ================================================================

def extract_entries(root, patterns):
    """
    Find <entry> children underneath matching containers.

    Returns a list of dictionaries.
    """

    results = []

    containers = find_matching_containers(
        root,
        patterns,
    )

    seen = set()

    for container_path, container in containers:

        for entry in container:

            if strip_namespace(entry.tag) != "entry":
                continue

            name = get_entry_name(entry)

            # Prevent duplicates when multiple patterns hit the
            # same container.
            identity = (
                element_path_string(container_path),
                name,
            )

            if identity in seen:
                continue

            seen.add(identity)

            obj = xml_to_dict(entry)

            results.append({
                "name": name,
                "path": element_path_string(
                    container_path + ["entry"]
                ),
                "object": normalize_for_json(obj),
            })

    return results


# ================================================================
# Rule extraction
# ================================================================

def extract_rules(root, patterns):
    """
    Extract rules from rule containers.

    Rules are structurally the same as most PAN-OS entry objects,
    but we add useful metadata.
    """

    rules = []

    containers = find_matching_containers(
        root,
        patterns,
    )

    seen = set()

    for container_path, container in containers:

        for entry in container:

            if strip_namespace(entry.tag) != "entry":
                continue

            name = get_entry_name(entry)

            identity = (
                element_path_string(container_path),
                name,
            )

            if identity in seen:
                continue

            seen.add(identity)

            rule = xml_to_dict(entry)

            rules.append({
                "name": name,
                "path": element_path_string(
                    container_path + ["entry"]
                ),
                "rule": normalize_for_json(rule),
            })

    return rules


# ================================================================
# Profiles
# ================================================================

def extract_profiles(root):
    """
    Extract common security profile structures.

    Instead of assuming every PAN-OS version has exactly the same
    profile layout, preserve the profile hierarchy.
    """

    profiles = []

    for path, element in walk_tree(root):

        if not path:
            continue

        # Look for:
        #
        # profiles/security/*
        #
        # profiles/group/*
        #
        if "profiles" not in path:
            continue

        profiles_index = len(path) - 1 - path[::-1].index(
            "profiles"
        )

        remaining = path[
            profiles_index:
        ]

        # We are interested in containers beneath profiles.
        if len(remaining) < 2:
            continue

        # Profile objects are generally entry containers.
        if strip_namespace(element.tag) not in (
            "entry",
        ):
            continue

        name = get_entry_name(element)

        if not name:
            continue

        profiles.append({
            "name": name,
            "path": element_path_string(path),
            "profile": normalize_for_json(
                xml_to_dict(element)
            ),
        })

    return profiles


# ================================================================
# Metadata
# ================================================================

def get_xml_metadata(root, source_file):
    """
    Gather basic information about the configuration.
    """

    metadata = {
        "source_file": str(source_file),
        "parsed_at": datetime.now().isoformat(),
        "root": strip_namespace(root.tag),
    }

    # PAN-OS configs generally contain:
    #
    # <config version="...">
    #
    if "version" in root.attrib:
        metadata["config_version"] = root.attrib["version"]

    # Try to find device hostname.
    hostname_candidates = [
        ".//hostname",
        ".//system/hostname",
    ]

    for xpath in hostname_candidates:

        try:
            node = root.find(xpath)

            if node is not None and node.text:
                metadata["hostname"] = node.text.strip()
                break

        except Exception:
            pass

    return metadata


# ================================================================
# Generic "entry" inventory
# ================================================================

def extract_all_entries(root):
    """
    Create a broad inventory of every <entry> element.

    This is intentionally included so that if PAN-OS contains
    something we haven't explicitly classified above, we don't
    lose it.
    """

    results = []

    for path, element in walk_tree(root):

        if strip_namespace(element.tag) != "entry":
            continue

        name = get_entry_name(element)

        results.append({
            "name": name,
            "path": element_path_string(path),
            "object": normalize_for_json(
                xml_to_dict(element)
            ),
        })

    return results


# ================================================================
# JSON output
# ================================================================

def write_json(filename, data):
    """
    Write formatted JSON.
    """

    with filename.open(
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            data,
            f,
            indent=2,
            sort_keys=False,
        )

        f.write("\n")


# ================================================================
# Device identification
# ================================================================

def determine_device_name(xml_file):
    """
    Determine output directory name.

    panorama-YYYY-MM-DD.xml -> panorama

    Everything else:
        hostname-YYYY-MM-DD.xml -> hostname
    """

    stem = xml_file.stem

    if stem.lower().startswith("panorama-"):
        return "panorama"

    # Remove date suffix.
    #
    # Example:
    #
    # PA-DC-01-2026-08-13
    #
    # -> PA-DC-01
    #

    match = re.match(
        r"^(.*)-\d{4}-\d{2}-\d{2}$",
        stem,
    )

    if match:
        return match.group(1)

    return stem


# ================================================================
# Parse one configuration
# ================================================================

def parse_config(xml_file, output_root):

    print()
    print("=" * 70)
    print(f"Parsing: {xml_file}")
    print("=" * 70)

    device_name = determine_device_name(
        xml_file
    )

    device_dir = (
        output_root / device_name
    )

    device_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    # ------------------------------------------------------------
    # Load XML
    # ------------------------------------------------------------

    try:

        tree = ET.parse(xml_file)

        root = tree.getroot()

    except ET.ParseError as exc:

        print(
            f"ERROR parsing {xml_file}: {exc}",
            file=sys.stderr,
        )

        return False, 0

    # ------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------

    metadata = get_xml_metadata(
        root,
        xml_file,
    )

    metadata["device_directory"] = device_name

    write_json(
        device_dir / "metadata.json",
        metadata,
    )

    # ------------------------------------------------------------
    # Standard objects
    # ------------------------------------------------------------

    extraction_counts = {}
    total_extracted_resources = 0

    for object_type, patterns in OBJECT_TYPES.items():

        if object_type.endswith("_rules"):

            objects = extract_rules(
                root,
                patterns,
            )

        else:

            objects = extract_entries(
                root,
                patterns,
            )

        extraction_counts[
            object_type
        ] = len(objects)
        
        total_extracted_resources += len(objects)

        write_json(
            device_dir / f"{object_type}.json",
            objects,
        )

        print(
            f"  {object_type:<35} "
            f"{len(objects):>6}"
        )

    # ------------------------------------------------------------
    # Security profiles
    # ------------------------------------------------------------

    profiles = extract_profiles(root)

    extraction_counts[
        "security_profiles"
    ] = len(profiles)
    
    total_extracted_resources += len(profiles)

    write_json(
        device_dir / "security_profiles.json",
        profiles,
    )

    print(
        f"  {'security_profiles':<35} "
        f"{len(profiles):>6}"
    )

    # ------------------------------------------------------------
    # All entries
    #
    # This is our safety net. It means an object that hasn't been
    # explicitly classified above is still available.
    # ------------------------------------------------------------

    all_entries = extract_all_entries(root)

    write_json(
        device_dir / "all_entries.json",
        all_entries,
    )

    extraction_counts[
        "all_entries"
    ] = len(all_entries)

    print(
        f"  {'all_entries':<35} "
        f"{len(all_entries):>6}"
    )

    # ------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------

    summary = {
        "source_file": str(xml_file),
        "device": device_name,
        "parsed_at": datetime.now().isoformat(),
        "counts": extraction_counts,
    }

    write_json(
        device_dir / "summary.json",
        summary,
    )

    print()
    print(
        f"Output: {device_dir}"
    )

    return True, total_extracted_resources


# ================================================================
# Main
# ================================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Parse PAN-OS XML configuration dumps into "
            "structured JSON files."
        )
    )

    parser.add_argument(
        "--input",
        required=True,
        help=(
            "Directory containing Panorama/firewall XML files"
        ),
    )

    parser.add_argument(
        "--output",
        default="parsed",
        help="Output directory",
    )

    parser.add_argument(
        "--file",
        help=(
            "Parse only this XML file instead of the "
            "entire input directory"
        ),
    )

    args = parser.parse_args()

    input_dir = Path(args.input)
    output_dir = Path(args.output)

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    # ------------------------------------------------------------
    # Determine files to process
    # ------------------------------------------------------------

    if args.file:

        xml_files = [
            Path(args.file)
        ]

    else:

        xml_files = sorted(
            input_dir.glob("*.xml")
        )

    if not xml_files:

        print(
            "No XML files found.",
            file=sys.stderr,
        )

        sys.exit(1)

    print()
    print("=" * 70)
    print("PAN-OS XML CONFIG PARSER")
    print("=" * 70)
    print(f"Input : {input_dir.resolve()}")
    print(f"Output: {output_dir.resolve()}")
    print(f"Files : {len(xml_files)}")

    successful = 0
    failed = 0
    total_resources_found = 0
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for xml_file in xml_files:

        success, res_count = parse_config(
            xml_file,
            output_dir,
        )
        if success:
            successful += 1
            total_resources_found += res_count
        else:
            failed += 1

    print()
    print("=" * 70)
    print("COMPLETE")
    print("=" * 70)
    print(f"Successful: {successful}")
    print(f"Failed    : {failed}")
    print()

    # Write automation results status file
    automation_dir = Path("automation_results")
    automation_dir.mkdir(parents=True, exist_ok=True)
    
    result_payload = {
        "Name": "PAN-OS XML Parsing",
        "Status": "Successful" if failed == 0 and successful > 0 else "Failed",
        "Lastrun": timestamp,
        "TotalResourcesFound": total_resources_found
    }

    result_file = automation_dir / "pa_parse_status.json"
    with open(result_file, "w", encoding="utf-8") as rf:
        json.dump(result_payload, rf, indent=2)
    print(f"[+] Automation run status saved to {result_file}")


if __name__ == "__main__":
    main()
