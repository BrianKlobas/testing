#!/usr/bin/env python3
"""Flask application for Infrastructure Intelligence.

IMPORTANT: this module does NOT ingest source JSON. Run ingest.py separately
when the source JSON changes, then start this app for fast development/testing:
    python app.py
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request

from database import (
    DEFAULT_DB_PATH,
    extract_direct_attached_sg_ids,
    extract_ip_or_cidr,
    get_db,
    get_file_modified_time,
    get_latest_dir_mtime,
    sqlite_ip_contains,
    classify_ip_search,
    value_matches_network_or_range,
)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = DEFAULT_DB_PATH
FW_DATA_ROOT = BASE_DIR / "parsed"
AWS_DATA_ROOT = BASE_DIR / "aws_parsed"
ORG_FILE_PATH = BASE_DIR / "org_topology.json"
PAN_TOPOLOGY_PATH = BASE_DIR / "panorama_topology.json"

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))


def _extract_values(obj: Any) -> list[str]:
    if obj is None:
        return []
    if isinstance(obj, (str, int, float, bool)):
        return [str(obj)]
    if isinstance(obj, list):
        values: list[str] = []
        for item in obj:
            values.extend(_extract_values(item))
        return values
    if isinstance(obj, dict):
        results: list[str] = []
        if obj.get("member") is not None:
            results.extend(_extract_values(obj["member"]))
        if obj.get("entry") is not None:
            results.extend(_extract_values(obj["entry"]))
        if obj.get("#text") is not None:
            results.append(str(obj["#text"]))
        if isinstance(obj.get("name"), str):
            results.append(obj["name"])
        if obj.get("@name") is not None:
            results.append(str(obj["@name"]))

        if results:
            return results

        for key, value in obj.items():
            if not key.startswith("@"):
                results.extend(_extract_values(value))
        return results
    return []


def _find_key_recursively(obj: Any, keys: list[str]) -> Any:
    if not isinstance(obj, dict):
        if isinstance(obj, list):
            for item in obj:
                found = _find_key_recursively(item, keys)
                if found is not None:
                    return found
        return None

    for key in keys:
        if key in obj:
            return obj[key]

    for value in obj.values():
        if isinstance(value, (dict, list)):
            found = _find_key_recursively(value, keys)
            if found is not None:
                return found
    return None


def _clean_fts_query(query: str) -> str:
    # Allow broader terms or tokenize correctly for FTS5 matching
    tokens = re.findall(r"[a-zA-Z0-9_\-\.]+", query)
    if not tokens:
        return ""
    # Use NEAR or simple prefix matching safely without forcing strict phrase wrapping unless quoted
    return " ".join(f"{t}*" for t in tokens)

def _classify_panos_record(row: Any, item_payload: Any, output: dict[str, Any]) -> None:
    filename = str(row["filename"]).lower()
    category = str(row["category"]).lower()
    record = {
        "device": row["device"],
        "type": row["category"],
        "file": row["filename"],
        "name": row["name"],
        "data": item_payload,
    }

    if "all_entries" in filename or "all_entries" in category:
        output["all_entries_matches"].append(record)
    elif "rule" in category or "policy" in category or "nat" in category:
        output["matched_rules"].append(record)
    else:
        output["matched_objects"].append(record)


def _get_panos_targets(obj: Any) -> list[str]:
    targets: list[str] = []
    interesting_keys = {
        "ip-netmask", "ip_netmask", "ip-range", "ip_range", "fqdn",
        "value", "member", "address", "source", "destination",
    }

    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in interesting_keys:
                if isinstance(value, str):
                    targets.append(value)
                elif isinstance(value, list):
                    targets.extend(str(x) for x in value if isinstance(x, (str, int)))
                elif isinstance(value, dict):
                    targets.extend(_get_panos_targets(value))
            elif isinstance(value, (dict, list)):
                targets.extend(_get_panos_targets(value))
    elif isinstance(obj, list):
        for item in obj:
            targets.extend(_get_panos_targets(item))

    return targets


class InfrastructureDataSource:
    def __init__(self, db_file: Path | None = None):
        self._db_file = db_file

    @property
    def db_file(self) -> Path:
        return self._db_file if self._db_file is not None else DB_PATH

    def files_count(self) -> int:
        conn = get_db(self.db_file)
        try:
            return int(conn.execute("SELECT COUNT(*) FROM records").fetchone()[0])
        finally:
            conn.close()

    def devices_count(self) -> int:
        conn = get_db(self.db_file)
        try:
            return int(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0])
        finally:
            conn.close()

    def get_stats(self) -> dict[str, Any]:
        conn = get_db(self.db_file)
        try:
            panos_counts = {
                row["category"]: row["cnt"]
                for row in conn.execute(
                    "SELECT category, COUNT(*) AS cnt FROM records WHERE platform='panos' GROUP BY category"
                ).fetchall()
            }
            aws_summary = {
                row["category"]: row["cnt"]
                for row in conn.execute(
                    "SELECT category, COUNT(*) AS cnt FROM records WHERE platform='aws' GROUP BY category"
                ).fetchall()
            }
            aws_accounts_count = conn.execute(
                "SELECT COUNT(DISTINCT name) FROM devices WHERE name LIKE 'AWS:%'"
            ).fetchone()[0]
            total_records = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
            return {
                "panos": panos_counts,
                "aws_resources": aws_summary,
                "aws_accounts_scanned": aws_accounts_count,
                "total_files": total_records,
            }
        finally:
            conn.close()

    def investigate(self, query: str, limit: int = 500) -> dict[str, Any]:
        query = query.strip()
        query_network = extract_ip_or_cidr(query)
        search_info = classify_ip_search(query) if 'classify_ip_search' in globals() else {"type": "unknown", "family": "unknown"}

        output: dict[str, Any] = {
            "query": query,
            "query_type": search_info.get("type", "unknown"),
            "query_family": search_info.get("family", "unknown"),
            "matched_objects": [],
            "matched_rules": [],
            "all_entries_matches": [],
            "aws_matches": [],
            "attached_security_groups": [],
            "palo_matches": [],
            "summary": {},
        }

        conn = get_db(self.db_file)
        cursor = conn.cursor()
        try:
            matched_aws_record_ids: set[int] = set()
            attached_sg_ids: set[tuple[str, str]] = set()
            related_cidrs_to_match: set[str] = set()

            if query_network:
                related_cidrs_to_match.add(query_network.compressed)

            pending_aws_lookups: list[Any] = []
            if query_network:
                target_ip = str(query_network.network_address)
                target_cidr = query_network.compressed
                cursor.execute(
                    """
                    SELECT r.id, d.name AS device, r.platform, r.category,
                           r.filename, r.name, r.data
                    FROM records r
                    JOIN devices d ON r.device_id = d.id
                    WHERE r.platform = 'aws' AND (r.data LIKE ? OR r.data LIKE ?)
                    LIMIT ?
                    """,
                    (f"%{target_ip}%", f"%{target_cidr}%", limit),
                )
                pending_aws_lookups.extend(cursor.fetchall())
            else:
                clean_q = _clean_fts_query(query)
                if clean_q:
                    cursor.execute(
                        """
                        SELECT r.id, d.name AS device, r.platform, r.category,
                               r.filename, r.name, r.data
                        FROM records_fts fts
                        JOIN records r ON r.id = fts.rowid
                        JOIN devices d ON r.device_id = d.id
                        WHERE r.platform = 'aws' AND records_fts MATCH ?
                        LIMIT ?
                        """,
                        (clean_q, limit),
                    )
                    pending_aws_lookups.extend(cursor.fetchall())

            for row in pending_aws_lookups:
                if row["id"] in matched_aws_record_ids:
                    continue
                matched_aws_record_ids.add(row["id"])
                try:
                    item = json.loads(row["data"])
                except json.JSONDecodeError:
                    continue

                output["aws_matches"].append({
                    "device": row["device"],
                    "type": row["category"],
                    "file": row["filename"],
                    "name": row["name"],
                    "data": item,
                })

                dev_name = row["device"]
                for sg_id in extract_direct_attached_sg_ids(item):
                    attached_sg_ids.add((dev_name, sg_id))

                subnet_id = item.get("SubnetId")
                vpc_id = item.get("VpcId")
                item_cidr = item.get("CidrBlock")
                if item_cidr:
                    related_cidrs_to_match.add(str(item_cidr))

                cursor.execute(
                    """
                    SELECT data FROM records r JOIN devices d ON r.device_id = d.id
                    WHERE r.category LIKE '%subnet%' AND d.name = ?
                    """,
                    (dev_name,),
                )
                for s_row in cursor.fetchall():
                    try:
                        s_data = json.loads(s_row["data"])
                    except json.JSONDecodeError:
                        continue
                    s_cidr = s_data.get("CidrBlock")
                    if s_cidr and query_network:
                        s_net = extract_ip_or_cidr(s_cidr)
                        if s_net and query_network.version == s_net.version and query_network.subnet_of(s_net):
                            related_cidrs_to_match.add(str(s_cidr))

                cursor.execute(
                    """
                    SELECT data FROM records r JOIN devices d ON r.device_id = d.id
                    WHERE r.category LIKE '%vpc%' AND d.name = ?
                    """,
                    (dev_name,),
                )
                for v_row in cursor.fetchall():
                    try:
                        v_data = json.loads(v_row["data"])
                    except json.JSONDecodeError:
                        continue
                    v_cidr = v_data.get("CidrBlock")
                    if v_cidr and query_network:
                        v_net = extract_ip_or_cidr(v_cidr)
                        if v_net and query_network.version == v_net.version and query_network.subnet_of(v_net):
                            related_cidrs_to_match.add(str(v_cidr))
                    for block in v_data.get("CidrBlockAssociationSet", []):
                        if isinstance(block, dict) and block.get("CidrBlock") and query_network:
                            b_net = extract_ip_or_cidr(block["CidrBlock"])
                            if b_net and query_network.version == b_net.version and query_network.subnet_of(b_net):
                                related_cidrs_to_match.add(str(block["CidrBlock"]))

                if subnet_id:
                    cursor.execute(
                        """
                        SELECT data FROM records r JOIN devices d ON r.device_id = d.id
                        WHERE r.category LIKE '%subnet%'
                          AND (r.name = ? OR json_extract(r.data, '$.SubnetId') = ?)
                          AND d.name = ?
                        """,
                        (subnet_id, subnet_id, dev_name),
                    )
                    for s_row in cursor.fetchall():
                        try:
                            s_data = json.loads(s_row["data"])
                        except json.JSONDecodeError:
                            continue
                        if s_data.get("CidrBlock"):
                            related_cidrs_to_match.add(str(s_data["CidrBlock"]))

                if vpc_id:
                    cursor.execute(
                        """
                        SELECT data FROM records r JOIN devices d ON r.device_id = d.id
                        WHERE r.category LIKE '%vpc%'
                          AND (r.name = ? OR json_extract(r.data, '$.VpcId') = ?)
                          AND d.name = ?
                        """,
                        (vpc_id, vpc_id, dev_name),
                    )
                    for v_row in cursor.fetchall():
                        try:
                            v_data = json.loads(v_row["data"])
                        except json.JSONDecodeError:
                            continue
                        if v_data.get("CidrBlock"):
                            related_cidrs_to_match.add(str(v_data["CidrBlock"]))
                        for block in v_data.get("CidrBlockAssociationSet", []):
                            if isinstance(block, dict) and block.get("CidrBlock"):
                                related_cidrs_to_match.add(str(block["CidrBlock"]))

            all_target_nets = [query_network] if query_network else []
            for cidr in related_cidrs_to_match:
                net_obj = extract_ip_or_cidr(cidr)
                if net_obj:
                    all_target_nets.append(net_obj)

            cursor.execute(
                """
                SELECT r.id, r.name, r.category, r.data, d.name AS device_name
                FROM records r JOIN devices d ON r.device_id = d.id
                WHERE r.platform = 'panos'
                  AND (r.category LIKE '%object%'
                    OR r.category LIKE '%address%'
                    OR r.category LIKE '%group%')
                """
            )
            for row in cursor.fetchall():
                try:
                    p_data = json.loads(row["data"])
                except json.JSONDecodeError:
                    continue
                p_val = p_data.get("ip_net") or p_data.get("address") or p_data.get("value") or row["name"]
                p_net = extract_ip_or_cidr(str(p_val))
                if not p_net:
                    continue
                for target_net in all_target_nets:
                    if target_net.version != p_net.version:
                        continue
                    if target_net.overlaps(p_net):
                        match_entry = {
                            "device": row["device_name"],
                            "type": row["category"],
                            "file": "",
                            "name": row["name"],
                            "data": p_data,
                            "match_context": "aws_network_context" if target_net != query_network else "query",
                            "matched_cidr": str(target_net),
                        }
                        output["palo_matches"].append(match_entry)
                        if "rule" in row["category"].lower():
                            output["matched_rules"].append(match_entry)
                        else:
                            output["matched_objects"].append(match_entry)
                        break

            for dev_name, sg_id in attached_sg_ids:
                cursor.execute(
                    """
                    SELECT r.id, d.name AS device, r.category, r.filename, r.name, r.data
                    FROM records r JOIN devices d ON r.device_id = d.id
                    WHERE r.platform = 'aws' AND (r.category = 'security_groups'
                        OR r.category = 'security_group'
                        OR r.category LIKE '%security-group%')
                      AND (r.name = ? OR json_extract(r.data, '$.GroupId') = ?)
                      AND d.name = ?
                    """,
                    (sg_id, sg_id, dev_name),
                )
                for sg_row in cursor.fetchall():
                    try:
                        sg_item = json.loads(sg_row["data"])
                    except json.JSONDecodeError:
                        continue
                    if not any(x["record_id"] == sg_row["id"] for x in output["attached_security_groups"]):
                        output["attached_security_groups"].append({
                            "record_id": sg_row["id"],
                            "device": sg_row["device"],
                            "type": sg_row["category"],
                            "file": sg_row["filename"],
                            "name": sg_row["name"],
                            "data": sg_item,
                        })

            matched_panos_ids: set[int] = set()
            matched_object_names: set[str] = set()

            if related_cidrs_to_match:
                cursor.execute(
                    """
                    SELECT r.id, d.name AS device, r.platform, r.category,
                           r.filename, r.name, r.data
                    FROM records r JOIN devices d ON r.device_id = d.id
                    WHERE r.platform = 'panos'
                    """
                )
                all_panos_records = cursor.fetchall()

                for row in all_panos_records:
                    try:
                        item_data = json.loads(row["data"])
                    except json.JSONDecodeError:
                        continue

                    is_match = False
                    targets = _get_panos_targets(item_data) if '_get_panos_targets' in globals() else []
                    for cidr in related_cidrs_to_match:
                        for target in targets:
                            if target and ('value_matches_network_or_range' not in globals() or value_matches_network_or_range(cidr, target)):
                                is_match = True
                                break
                        if is_match:
                            break

                    if is_match:
                        matched_panos_ids.add(row["id"])
                        eval_obj = item_data.get("entry", item_data) if isinstance(item_data, dict) else item_data
                        obj_name = row["name"] or (
                            item_data.get("name") if isinstance(item_data, dict) else ""
                        ) or (
                            eval_obj.get("@name") if isinstance(eval_obj, dict) else ""
                        )
                        if obj_name:
                            matched_object_names.add(str(obj_name))
                        
                        match_entry = {
                            "device": row["device"],
                            "type": row["category"],
                            "file": row["filename"],
                            "name": row["name"],
                            "data": item_data,
                        }
                        output["all_entries_matches"].append(match_entry)
                        if "rule" in row["category"].lower():
                            output["matched_rules"].append(match_entry)
                        else:
                            output["matched_objects"].append(match_entry)

                expanded = True
                expansion_depth = 0
                while expanded and expansion_depth < 5:
                    expanded = False
                    expansion_depth += 1
                    for row in all_panos_records:
                        if row["id"] in matched_panos_ids:
                            continue
                        try:
                            item_data = json.loads(row["data"])
                        except json.JSONDecodeError:
                            continue
                        data_str = row["data"]
                        for name in list(matched_object_names):
                            if name and re.search(r"\b" + re.escape(name) + r"\b", data_str, re.IGNORECASE):
                                matched_panos_ids.add(row["id"])
                                eval_obj = item_data.get("entry", item_data) if isinstance(item_data, dict) else item_data
                                obj_name = row["name"] or (
                                    eval_obj.get("@name") if isinstance(eval_obj, dict) else ""
                                )
                                if obj_name and str(obj_name) not in matched_object_names:
                                    matched_object_names.add(str(obj_name))
                                    expanded = True
                                
                                match_entry = {
                                    "device": row["device"],
                                    "type": row["category"],
                                    "file": row["filename"],
                                    "name": row["name"],
                                    "data": item_data,
                                }
                                output["all_entries_matches"].append(match_entry)
                                if "rule" in row["category"].lower():
                                    output["matched_rules"].append(match_entry)
                                else:
                                    output["matched_objects"].append(match_entry)
                                break
            
            clean_q = _clean_fts_query(query)
            if clean_q and not query_network:
                cursor.execute(
                    """
                    SELECT r.id, d.name AS device, r.platform, r.category,
                           r.filename, r.name, r.data
                    FROM records_fts fts
                    JOIN records r ON r.id = fts.rowid
                    JOIN devices d ON r.device_id = d.id
                    WHERE records_fts MATCH ?
                    LIMIT ?
                    """,
                    (clean_q, limit),
                )
                for row in cursor.fetchall():
                    if row["id"] in matched_panos_ids:
                        continue
                    try:
                        item_data = json.loads(row["data"])
                    except json.JSONDecodeError:
                        continue
                    matched_panos_ids.add(row["id"])
                    
                    match_entry = {
                        "device": row["device"],
                        "type": row["category"],
                        "file": row["filename"],
                        "name": row["name"],
                        "data": item_data,
                    }
                    if row["platform"] == "panos":
                        output["all_entries_matches"].append(match_entry)
                        if "rule" in row["category"].lower():
                            output["matched_rules"].append(match_entry)
                        else:
                            output["matched_objects"].append(match_entry)
                    else:
                        if not any(x["data"] == item_data for x in output["aws_matches"]):
                            output["aws_matches"].append(match_entry)

            output["summary"] = {
                "aws_resources": len(output["aws_matches"]),
                "attached_sgs": len(output["attached_security_groups"]),
                "palo_objects": len(output["matched_objects"]),
                "palo_rules": len(output["matched_rules"]),
                "all_entries": len(output["all_entries_matches"]),
            }
            return output
        finally:
            conn.close()

    def policy_lookup(self, src_query: str = "", dst_query: str = "", port_query: str = "") -> list[dict[str, Any]]:
        """Find PAN-OS rules where source, destination and optional service all intersect."""
        src_query = src_query.strip().lower()
        dst_query = dst_query.strip().lower()
        port_query = port_query.strip().lower()

        conn = get_db(self.db_file)
        try:
            rows = conn.execute(
                """
                SELECT r.id, d.name AS device, r.platform, r.category,
                       r.filename, r.name, r.data
                FROM records r
                JOIN devices d ON r.device_id = d.id
                WHERE r.platform = 'panos'
                  AND (r.category LIKE '%rule%'
                    OR r.category LIKE '%policy%'
                    OR r.category LIKE '%nat%')
                """
            ).fetchall()

            matched_rules: list[dict[str, Any]] = []
            for row in rows:
                try:
                    item_data = json.loads(row["data"])
                except json.JSONDecodeError:
                    continue

                rule = item_data.get("entry", item_data) if isinstance(item_data, dict) else item_data
                if not isinstance(rule, dict):
                    continue

                sources = [x.lower() for x in _extract_values(_find_key_recursively(rule, ["source"]))]
                destinations = [x.lower() for x in _extract_values(_find_key_recursively(rule, ["destination", "dest"]))]
                services = [x.lower() for x in _extract_values(_find_key_recursively(rule, ["service", "port"]))]

                def matches_any(query_str: str, values: list[str]) -> bool:
                    if not query_str:
                        return True
                    if "any" in values:
                        return True
                    for value in values:
                        if query_str in value or value in query_str:
                            return True
                        if sqlite_ip_contains(query_str, value) or sqlite_ip_contains(value, query_str):
                            return True
                    return False

                if src_query and not matches_any(src_query, sources):
                    continue
                if dst_query and not matches_any(dst_query, destinations):
                    continue
                if port_query and not matches_any(port_query, services):
                    continue

                matched_rules.append({
                    "device": row["device"],
                    "type": row["category"],
                    "file": row["filename"],
                    "name": row["name"],
                    "data": item_data,
                })

            return matched_rules
        finally:
            conn.close()


DATA = InfrastructureDataSource()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/info")
def api_info():
    return jsonify({"files": DATA.files_count(), "devices": DATA.devices_count()})


@app.route("/api/stats")
def api_stats():
    return jsonify(DATA.get_stats())


@app.route("/api/automation/status")
def api_automation_status():
    return jsonify({
        "aws_org_mtime": get_file_modified_time(ORG_FILE_PATH),
        "aws_data_mtime": get_latest_dir_mtime(AWS_DATA_ROOT),
        "pan_org_mtime": get_file_modified_time(PAN_TOPOLOGY_PATH),
        "pan_data_mtime": get_latest_dir_mtime(FW_DATA_ROOT),
    })


@app.route("/api/topology/aws")
def api_topology_aws():
    if not ORG_FILE_PATH.exists():
        return jsonify({"error": "AWS Organization Topology file not found."}), 404
    try:
        with ORG_FILE_PATH.open("r", encoding="utf-8") as handle:
            return jsonify(json.load(handle))
    except Exception as exc:
        return jsonify({"error": f"Failed to read AWS Org topology file: {exc}"}), 500


@app.route("/api/topology/pan")
def api_topology_pan():
    if not PAN_TOPOLOGY_PATH.exists():
        return jsonify({"error": "Panorama Topology file not found."}), 404
    try:
        with PAN_TOPOLOGY_PATH.open("r", encoding="utf-8") as handle:
            return jsonify(json.load(handle))
    except Exception as exc:
        return jsonify({"error": f"Failed to read Panorama topology file: {exc}"}), 500


@app.route("/api/investigate")
def api_investigate():
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify({"error": "A search query is required."}), 400
    try:
        return jsonify(DATA.investigate(query))
    except Exception as exc:
        app.logger.exception("Investigation failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/policy-lookup")
def api_policy_lookup():
    try:
        rules = DATA.policy_lookup(
            request.args.get("src", ""),
            request.args.get("dst", ""),
            request.args.get("port", ""),
        )
        return jsonify({"rules": rules})
    except Exception as exc:
        app.logger.exception("Policy lookup failed")
        return jsonify({"error": str(exc)}), 500


def main() -> None:
    global DB_PATH, FW_DATA_ROOT, AWS_DATA_ROOT, ORG_FILE_PATH, PAN_TOPOLOGY_PATH, DATA

    parser = argparse.ArgumentParser(description="Infrastructure Intelligence Dashboard")
    parser.add_argument("--db", default=str(DB_PATH), help="Path to SQLite database")
    parser.add_argument("--firewall-data", default=str(FW_DATA_ROOT), help="Path to parsed Firewall JSON folder")
    parser.add_argument("--aws-data", default=str(AWS_DATA_ROOT), help="Path to parsed AWS JSON folder")
    parser.add_argument("--org-file", default=str(ORG_FILE_PATH), help="Path to AWS Org topology JSON file")
    parser.add_argument("--pan-file", default=str(PAN_TOPOLOGY_PATH), help="Path to Panorama topology JSON file")
    parser.add_argument("--port", type=int, default=8080, help="Web server port")
    parser.add_argument("--host", default="0.0.0.0", help="Web server bind address")
    args = parser.parse_args()

    DB_PATH = Path(args.db).resolve()
    FW_DATA_ROOT = Path(args.firewall_data).resolve()
    AWS_DATA_ROOT = Path(args.aws_data).resolve()
    ORG_FILE_PATH = Path(args.org_file).resolve()
    PAN_TOPOLOGY_PATH = Path(args.pan_file).resolve()
    DATA = InfrastructureDataSource(DB_PATH)

    print(f"[*] Starting web server on http://localhost:{args.port}/")
    print(f"[*] Database: {DB_PATH}")
    print("[*] Source JSON is NOT ingested by app.py; run ingest.py when source data changes.")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
