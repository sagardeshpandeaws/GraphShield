import csv
import os
from analytics.constants import COMPLIANCE_MAP
from analytics.groups import GROUPS

def export_csv(findings, output, client_config=None, report_title=""):
    cfg = client_config or {}
    client_name = cfg.get("client_name", "Client")

    os.makedirs(os.path.dirname(output), exist_ok=True)

    headers = [
        "Finding ID", "Title", "Severity", "Confidence", "Source",
        "Group",
        "MITRE ID", "MITRE Technique", "MITRE Tactic",
        "CIS Controls v8.1", "NIST CSF 2.0", "ISO/IEC 27001:2022", "SA 315 (ICAI)", "DPDP Act 2023",
        "Impact", "Remediation", "Detection",
        "Service Principals", "Managed Identities", "Applications", "Key Vaults",
        "Users", "Groups", "Computers",
        "Source Node", "Target Node", "Attack Path"
    ]

    with open(output, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        if report_title:
            writer.writerow([report_title])
            writer.writerow([])
        writer.writerow(headers)

        ad_n = 0
        az_n = 0
        for fnd in findings:
            if fnd.get("source") == "Azure":
                az_n += 1
                finding_id = f"AZ-{az_n:03d}"
            else:
                ad_n += 1
                finding_id = f"AD-{ad_n:03d}"
            mitre = fnd.get("mitre", {}) or {}
            cat_id = fnd.get("id", "")
            comp = COMPLIANCE_MAP.get(cat_id, {})

            group_key = fnd.get("group", "")
            group_name = GROUPS.get(group_key, {}).get("name", group_key) if group_key else ""
            base = [
                finding_id,
                fnd.get("title", ""),
                fnd.get("severity", ""),
                fnd.get("confidence", "No Data"),
                fnd.get("source", ""),
                group_name,
                mitre.get("id", ""),
                mitre.get("technique", ""),
                mitre.get("tactic", ""),
                comp.get("CIS", ""),
                comp.get("NIST", ""),
                comp.get("ISO 27001", ""),
                comp.get("SA 315", ""),
                comp.get("DPDP", ""),
                fnd.get("impact", ""),
                "; ".join(fnd.get("remediation", [])),
                "; ".join(fnd.get("detection", [])),
            ]

            ad = fnd.get("ad_objects", {})

            # Azure entity counts
            az_sp = "; ".join(ad.get("service_principals", [])[:5])
            az_mi = "; ".join(ad.get("managed_identities", [])[:5])
            az_apps = "; ".join(ad.get("applications", [])[:5])
            az_kv = "; ".join(ad.get("key_vaults", [])[:5])

            # AD entity counts
            users = "; ".join(ad.get("users", [])[:5])
            groups_csv = "; ".join(ad.get("groups", [])[:5])
            comps = "; ".join(ad.get("computers", [])[:5])

            entity_cols = [az_sp, az_mi, az_apps, az_kv, users, groups_csv, comps]

            relationships = ad.get("relationships", [])

            if not relationships:
                writer.writerow(base + entity_cols + ["", "", ""])
                continue

            for rel in relationships:
                parts = [x.strip() for x in rel.split("\u2192")]
                source_node = parts[0] if parts else ""
                target_node = parts[-1] if len(parts) > 1 else ""
                writer.writerow(base + entity_cols + [source_node, target_node, rel])
