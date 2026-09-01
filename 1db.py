from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import re
from datetime import datetime
from pathlib import Path
from typing import Any

DB_PATH = Path("infra_intel.db")
DEFAULT_DB_PATH = DB_PATH
FW_DATA_ROOT = Path("parsed").resolve()
AWS_DATA_ROOT = Path("aws_parsed").resolve()
ORG_FILE_PATH = Path("org_topology.json").resolve()
PAN_TOPOLOGY_PATH = Path("panorama_topology.json").resolve()


def extract_ip_or_cidr(val: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if not val:
        return None
    val = str(val).strip()
    try:
        if "/" in val:
            return ipaddress.ip_network(val, strict=False)
        return ipaddress.ip_network(val + "/32", strict=False)
    except ValueError:
        return None


def sqlite_ip_contains(target_str: str, cidr_or_range_str: str) -> int:
    if not target_str or not cidr_or_range_str:
        return 0
    
    target_net = extract_ip_or_cidr(target_str)
    if not target_net:
        return 0

    val = str(cidr_or_range_str).strip()
    
    if "-" in val and "/" not in val:
        parts = val.split("-")
        if len(parts) == 2:
            try:
                start = ipaddress.ip_address(parts[0].strip())
                end = ipaddress.ip_address(parts[1].strip())
                return 1 if start <= target_net.network_address <= end or start <= target_net.broadcast_address <= end else 0
            except ValueError:
                pass

    fw_net = extract_ip_or_cidr(val)
    if fw_net:
        try:
            return 1 if target_net.overlaps(fw_net) or target_net.subnet_of(fw_net) or fw_net.subnet_of(target_net) else 0
        except ValueError:
            return 1 if target_net.overlaps(fw_net) else 0
        
    return 0


def classify_ip_search(val: str) -> str:
    net = extract_ip_or_cidr(val)
    return "ip_or_cidr" if net else "text"


def extract_direct_attached_sg_ids(item: dict[str, Any]) -> set[str]:
    sg_ids = set()
    groups = item.get("Groups") or item.get("SecurityGroups")
    if isinstance(groups, list):
        for g in groups:
            if isinstance(g, str) and g.startswith("sg-"):
                sg_ids.add(g)
            elif isinstance(g, dict):
                gid = g.get("GroupId") or g.get("VpcSecurityGroupId")
                if gid and str(gid).startswith("sg-"):
                    sg_ids.add(str(gid))

    nis = item.get("NetworkInterfaces")
    if isinstance(nis, list):
        for ni in nis:
            if isinstance(ni, dict):
                ni_groups = ni.get("Groups") or ni.get("SecurityGroups")
                if isinstance(ni_groups, list):
                    for g in ni_groups:
                        if isinstance(g, str) and g.startswith("sg-"):
                            sg_ids.add(g)
                        elif isinstance(g, dict):
                            gid = g.get("GroupId") or g.get("VpcSecurityGroupId")
                            if gid and str(gid).startswith("sg-"):
                                sg_ids.add(str(gid))
                                
    return sg_ids


def get_file_modified_time(filepath: Path) -> str:
    if filepath.exists():
        mtime = os.path.getmtime(filepath)
        return datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
    return "N/A"


def get_latest_dir_mtime(dirpath: Path) -> str:
    if not dirpath.exists():
        return "N/A"
    latest = 0.0
    for p in dirpath.rglob("*.json"):
        if p.is_file():
            mtime = os.path.getmtime(p)
            if mtime > latest:
                latest = mtime
    if latest > 0:
        return datetime.fromtimestamp(latest).strftime('%Y-%m-%d %H:%M:%S')
    return "N/A"


def get_db(db_file: Path | None = None):
    if db_file is None:
        db_file = DB_PATH
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    conn.create_function("IP_CONTAINS", 2, sqlite_ip_contains)
    return conn


def init_db(db_file: Path | None = None):
    if db_file is None:
        db_file = DB_PATH
    if db_file.exists():
        db_file.unlink()
        
    conn = get_db(db_file)
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        );

        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            platform TEXT,
            category TEXT,
            filename TEXT,
            name TEXT,           
            data TEXT,           
            FOREIGN KEY(device_id) REFERENCES devices(id)
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS records_fts USING fts5(
            name, data, content='records', content_rowid='id'
        );

        CREATE TRIGGER records_ai AFTER INSERT ON records BEGIN
            INSERT INTO records_fts(rowid, name, data) VALUES (new.id, new.name, new.data);
        END;
    """)
    conn.commit()
    conn.close()


def find_key_recursively(obj: Any, keys: list[str]) -> Any:
    if not isinstance(obj, dict):
        return None
    for k in keys:
        if k in obj:
            return obj[k]
    for k, v in obj.items():
        if isinstance(v, dict):
            res = find_key_recursively(v, keys)
            if res is not None:
                return res
        elif isinstance(v, list):
            for item in v:
                res = find_key_recursively(item, keys)
                if res is not None:
                    return res
    return None


def extract_values(obj: Any) -> list[str]:
    if obj is None:
        return []
    if isinstance(obj, (str, int, float, bool)):
        return [str(obj)]
    if isinstance(obj, list):
        results = []
        for item in obj:
            results.extend(extract_values(item))
        return results
    if isinstance(obj, dict):
        results = []
        if "member" in obj:
            results.extend(extract_values(obj["member"]))
        if "entry" in obj:
            results.extend(extract_values(obj["entry"]))
        if "#text" in obj:
            results.append(str(obj["#text"]))
        if "name" in obj and isinstance(obj["name"], str):
            results.append(obj["name"])
        if "@name" in obj:
            results.append(str(obj["@name"]))
        if results:
            return results
        for k, v in obj.items():
            if not str(k).startswith("@"):
                results.extend(extract_values(v))
        return results
    return []


class InfrastructureDataSource:
    def __init__(self, db_file: Path | None = None):
        self._db_file = db_file

    @property
    def db_file(self) -> Path:
        return self._db_file if self._db_file is not None else DB_PATH

    def get_stats(self) -> dict[str, Any]:
        conn = get_db(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("SELECT category, COUNT(*) as cnt FROM records WHERE platform='panos' GROUP BY category")
        panos_counts = {row["category"]: row["cnt"] for row in cursor.fetchall()}
        
        cursor.execute("SELECT category, COUNT(*) as cnt FROM records WHERE platform='aws' GROUP BY category")
        aws_summary = {row["category"]: row["cnt"] for row in cursor.fetchall()}

        cursor.execute("SELECT COUNT(DISTINCT name) FROM devices WHERE name LIKE 'AWS:%'")
        aws_accounts_count = cursor.fetchone()[0]

        conn.close()
        return {
            "panos": panos_counts,
            "aws_resources": aws_summary,
            "aws_accounts_scanned": aws_accounts_count,
            "total_files": self.files_count()
        }

    def files_count(self) -> int:
        conn = get_db(self.db_file)
        count = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        conn.close()
        return count

    def devices_count(self) -> int:
        conn = get_db(self.db_file)
        count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        conn.close()
        return count

    def investigate(self, query: str, limit: int = 500) -> dict[str, Any]:
        query = query.strip()
        query_network = extract_ip_or_cidr(query)
        
        output = {
            "query": query,
            "query_type": classify_ip_search(query),
            "matched_objects": [],
            "matched_rules": [],
            "all_entries_matches": [],
            "aws_matches": [],
            "attached_security_groups": [],
            "palo_matches": [],
            "summary": {}
        }

        conn = get_db(self.db_file)
        cursor = conn.cursor()

        matched_aws_record_ids = set()
        attached_sg_ids = set()
        related_cidrs_to_match = set()

        if query_network:
            related_cidrs_to_match.add(query_network.compressed)

        pending_aws_lookups = []
        if query_network:
            target_ip = str(query_network.network_address)
            target_cidr = query_network.compressed
            
            cursor.execute("""
                SELECT r.id, d.name as device, r.platform, r.category, r.filename, r.name, r.data
                FROM records r
                JOIN devices d ON r.device_id = d.id
                WHERE r.platform = 'aws' AND (r.data LIKE ? OR r.data LIKE ?)
                LIMIT ?
            """, (f"%{target_ip}%", f"%{target_cidr}%", limit))
            
            for row in cursor.fetchall():
                if row["id"] not in matched_aws_record_ids:
                    matched_aws_record_ids.add(row["id"])
                    pending_aws_lookups.append(row)
        else:
            clean_q = re.sub(r'[^a-zA-Z0-9_\-\.]', ' ', query).strip()
            if clean_q:
                fts_query = f'"{clean_q}"*'
                cursor.execute("""
                    SELECT r.id, d.name as device, r.platform, r.category, r.filename, r.name, r.data
                    FROM records r
                    JOIN devices d ON r.device_id = d.id
                    JOIN records_fts fts ON fts.rowid = r.id
                    WHERE r.platform = 'aws' AND records_fts MATCH ?
                    LIMIT ?
                """, (fts_query, limit))
                
                for row in cursor.fetchall():
                    if row["id"] not in matched_aws_record_ids:
                        matched_aws_record_ids.add(row["id"])
                        pending_aws_lookups.append(row)

        for row in pending_aws_lookups:
            item = json.loads(row["data"])

            output["aws_matches"].append({
                "device": row["device"],
                "type": row["category"],
                "file": row["filename"],
                "name": row["name"],
                "data": item
            })

            dev_name = row["device"]
            
            direct_sgs = extract_direct_attached_sg_ids(item)
            for sg_id in direct_sgs:
                attached_sg_ids.add((dev_name, sg_id))

            subnet_id = item.get("SubnetId")
            vpc_id = item.get("VpcId")

            item_cidr = item.get("CidrBlock")
            if item_cidr:
                related_cidrs_to_match.add(item_cidr)

            cursor.execute("""
                SELECT data FROM records r JOIN devices d ON r.device_id = d.id
                WHERE (r.category LIKE '%subnet%') AND d.name = ?
            """, (dev_name,))
            for s_row in cursor.fetchall():
                s_data = json.loads(s_row["data"])
                s_cidr = s_data.get("CidrBlock")
                if s_cidr and query_network:
                    s_net = extract_ip_or_cidr(s_cidr)
                    if s_net and query_network.subnet_of(s_net):
                        related_cidrs_to_match.add(s_cidr)

            cursor.execute("""
                SELECT data FROM records r JOIN devices d ON r.device_id = d.id
                WHERE (r.category LIKE '%vpc%') AND d.name = ?
            """, (dev_name,))
            for v_row in cursor.fetchall():
                v_data = json.loads(v_row["data"])
                v_cidr = v_data.get("CidrBlock")
                if v_cidr and query_network:
                    v_net = extract_ip_or_cidr(v_cidr)
                    if v_net and query_network.subnet_of(v_net):
                        related_cidrs_to_match.add(v_cidr)
                for block in v_data.get("CidrBlockAssociationSet", []):
                    if isinstance(block, dict) and block.get("CidrBlock") and query_network:
                        b_net = extract_ip_or_cidr(block["CidrBlock"])
                        if b_net and query_network.subnet_of(b_net):
                            related_cidrs_to_match.add(block["CidrBlock"])

            if subnet_id:
                cursor.execute("""
                    SELECT data FROM records r JOIN devices d ON r.device_id = d.id
                    WHERE (r.category LIKE '%subnet%') AND (r.name = ? OR json_extract(r.data, '$.SubnetId') = ?) AND d.name = ?
                """, (subnet_id, subnet_id, dev_name))
                for s_row in cursor.fetchall():
                    s_data = json.loads(s_row["data"])
                    cidr = s_data.get("CidrBlock")
                    if cidr:
                        related_cidrs_to_match.add(cidr)

            if vpc_id:
                cursor.execute("""
                    SELECT data FROM records r JOIN devices d ON r.device_id = d.id
                    WHERE (r.category LIKE '%vpc%') AND (r.name = ? OR json_extract(r.data, '$.VpcId') = ?) AND d.name = ?
                """, (vpc_id, vpc_id, dev_name))
                for v_row in cursor.fetchall():
                    v_data = json.loads(v_row["data"])
                    cidr = v_data.get("CidrBlock")
                    if cidr:
                        related_cidrs_to_match.add(cidr)
                    for block in v_data.get("CidrBlockAssociationSet", []):
                        if isinstance(block, dict) and block.get("CidrBlock"):
                            related_cidrs_to_match.add(block["CidrBlock"])

        all_target_nets = [query_network] if query_network else []
        for c_str in related_cidrs_to_match:
            net_obj = extract_ip_or_cidr(c_str)
            if net_obj:
                all_target_nets.append(net_obj)

        cursor.execute("""
            SELECT r.id, r.name, r.category, r.data, d.name as device_name 
            FROM records r JOIN devices d ON r.device_id = d.id 
            WHERE r.category LIKE '%object%' OR r.category LIKE '%address%' OR r.category LIKE '%group%'
        """)
        
        for row in cursor.fetchall():
            try:
                p_data = json.loads(row["data"])
                p_val = p_data.get("ip_net") or p_data.get("address") or p_data.get("value") or row["name"]
                p_net = extract_ip_or_cidr(str(p_val))
                
                if p_net:
                    for t_net in all_target_nets:
                        if t_net.subnet_of(p_net) or p_net.subnet_of(t_net) or t_net == t_net:
                            output["palo_matches"].append({
                                "device": row["device_name"],
                                "type": row["category"],
                                "file": "",
                                "name": row["name"],
                                "data": p_data
                            })
                            break
            except Exception:
                continue
                          
        for dev_name, sg_id in attached_sg_ids:
            cursor.execute("""
                SELECT r.id, d.name as device, r.category, r.filename, r.name, r.data
                FROM records r
                JOIN devices d ON r.device_id = d.id
                WHERE (r.category = 'security_groups' OR r.category = 'security_group' OR r.category LIKE '%security-group%')
                  AND (r.name = ? OR json_extract(r.data, '$.GroupId') = ?) AND d.name = ?
            """, (sg_id, sg_id, dev_name))
            
            for sg_row in cursor.fetchall():
                sg_item = json.loads(sg_row["data"])
                exists = any(s.get("record_id") == sg_row["id"] for s in output["attached_security_groups"])
                if not exists:
                    output["attached_security_groups"].append({
                        "record_id": sg_row["id"],
                        "device": sg_row["device"],
                        "type": sg_row["category"],
                        "file": sg_row["filename"],
                        "name": sg_row["name"],
                        "data": sg_item
                    })

        matched_panos_ids = set()
        matched_object_names = set()

        cursor.execute("""
            SELECT r.id, d.name as device, r.platform, r.category, r.filename, r.name, r.data
            FROM records r
            JOIN devices d ON r.device_id = d.id
            WHERE r.platform = 'panos'
        """)
        
        all_panos_records = cursor.fetchall()

        def classify_and_append_panos(row_dict, item_payload):
            filename = str(row_dict["filename"]).lower()
            cat = str(row_dict["category"]).lower()
            rec = {
                "device": row_dict["device"],
                "type": row_dict["category"],
                "file": row_dict["filename"],
                "name": row_dict["name"],
                "data": item_payload
            }

            if "all_entries" in filename or "all_entries" in cat:
                output["all_entries_matches"].append(rec)
            elif "rule" in cat or "policy" in cat or "nat" in cat:
                output["matched_rules"].append(rec)
            else:
                output["matched_objects"].append(rec)

        if related_cidrs_to_match:
            def get_panos_targets(obj: Any) -> list[str]:
                targets = []
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if k in ("ip-netmask", "ip_netmask", "ip-range", "ip_range", "fqdn", "value", "member", "address", "source", "destination"):
                            if isinstance(v, str):
                                targets.append(v)
                            elif isinstance(v, list):
                                targets.extend([str(x) for x in v if isinstance(x, (str, int))])
                            elif isinstance(v, dict):
                                targets.extend(get_panos_targets(v))
                        elif isinstance(v, (dict, list)):
                            targets.extend(get_panos_targets(v))
                elif isinstance(obj, list):
                    for item in obj:
                        targets.extend(get_panos_targets(item))
                return targets

            for row in all_panos_records:
                row_data_str = row["data"]
                if related_cidrs_to_match and not any(cidr.split('/')[0] in row_data_str for cidr in related_cidrs_to_match):
                    continue

                try:
                    item_data = json.loads(row_data_str)
                except Exception:
                    continue
                
                is_match = False
                targets = get_panos_targets(item_data)

                for cidr in related_cidrs_to_match:
                    try:
                        cidr_net = extract_ip_or_cidr(cidr)
                        for target in targets:
                            try:
                                target_net = extract_ip_or_cidr(target)
                                if cidr_net and target_net:
                                    if cidr_net.version == target_net.version:
                                        if cidr_net.overlaps(target_net) or cidr_net.subnet_of(target_net) or target_net.subnet_of(cidr_net):
                                            is_match = True
                                            break
                                elif target and sqlite_ip_contains(cidr, target):
                                    is_match = True
                                    break
                            except Exception:
                                continue
                        if is_match:
                            break
                    except Exception:
                        continue

                if is_match:
                    matched_panos_ids.add(row["id"])
                    eval_obj = item_data.get("entry", item_data) if isinstance(item_data, dict) else item_data
                    obj_name = row["name"] or item_data.get("name") or (eval_obj.get("@name") if isinstance(eval_obj, dict) else "")
                    if obj_name:
                        matched_object_names.add(str(obj_name))
                    classify_and_append_panos(row, item_data)

            expanded_new_names = True
            while expanded_new_names:
                expanded_new_names = False
                for row in all_panos_records:
                    if row["id"] in matched_panos_ids:
                        continue

                    item_data = json.loads(row["data"])
                    data_str = json.dumps(item_data)

                    for name in list(matched_object_names):
                        if re.search(r'\b' + re.escape(name) + r'\b', data_str):
                            matched_panos_ids.add(row["id"])
                            eval_obj = item_data.get("entry", item_data) if isinstance(item_data, dict) else item_data
                            obj_name = row["name"] or (eval_obj.get("@name") if isinstance(eval_obj, dict) else "")
                            if obj_name and str(obj_name) not in matched_object_names:
                                matched_object_names.add(str(obj_name))
                                expanded_new_names = True
                            classify_and_append_panos(row, item_data)
                            break

        else:
            clean_q = re.sub(r'[^a-zA-Z0-9_\-\.]', ' ', query).strip()
            if clean_q:
                fts_query = f'"{clean_q}"*'
                cursor.execute("""
                    SELECT r.id, d.name as device, r.platform, r.category, r.filename, r.name, r.data
                    FROM records r
                    JOIN devices d ON r.device_id = d.id
                    JOIN records_fts fts ON fts.rowid = r.id
                    WHERE r.platform = 'panos' AND records_fts MATCH ?
                    LIMIT ?
                """, (fts_query, limit))
                for row in cursor.fetchall():
                    if row["id"] not in matched_panos_ids:
                        matched_panos_ids.add(row["id"])
                        classify_and_append_panos(row, json.loads(row["data"]))

        output["summary"] = {
            "aws_resources": len(output["aws_matches"]),
            "attached_sgs": len(output["attached_security_groups"]),
            "palo_objects": len(output["matched_objects"]),
            "palo_rules": len(output["matched_rules"]),
            "all_entries": len(output["all_entries_matches"])
        }

        conn.close()
        return output
