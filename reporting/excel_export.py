import os
import json
from datetime import datetime
from openpyxl import Workbook
from openpyxl.styles import (
    Font, PatternFill, Alignment, Border, Side, numbers
)
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.worksheet.hyperlink import Hyperlink
from openpyxl.formatting.rule import FormulaRule
from analytics.constants import COMPLIANCE_MAP, EXCLUSIONS_MAP
from analytics.groups import GROUPS
from analytics.nhi_lifecycle import corroboration_label as _corroboration
from config import compute_env_stats, BASE_OUTPUT_DIR

# â”€â”€â”€ Styling Constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
NAVY = "1e3a5f"
SLATE = "334155"
GRAY = "94a3b8"
LIGHT = "f8fafc"
WHITE = "ffffff"

HDR_FILL = PatternFill(start_color=NAVY, end_color=NAVY, fill_type="solid")
HDR_FONT = Font(name="Calibri", bold=True, size=10, color=WHITE)
TITLE_FONT = Font(name="Calibri", bold=True, size=14, color=NAVY)
SUB_FONT = Font(name="Calibri", bold=True, size=11, color=SLATE)
BODY_FONT = Font(name="Calibri", size=10)
BOLD_FONT = Font(name="Calibri", bold=True, size=10)
LINK_FONT = Font(name="Calibri", size=10, color="2563eb", underline="single")

THIN = Border(
    left=Side("thin", "cbd5e1"), right=Side("thin", "cbd5e1"),
    top=Side("thin", "cbd5e1"), bottom=Side("thin", "cbd5e1"),
)

SEV_FILL = {
    "CRITICAL": PatternFill("solid", fgColor="fef2f2"),
    "HIGH": PatternFill("solid", fgColor="fff7ed"),
    "MEDIUM": PatternFill("solid", fgColor="fefce8"),
    "LOW": PatternFill("solid", fgColor="eff6ff"),
}
SEV_FONT = {
    "CRITICAL": Font(name="Calibri", bold=True, size=10, color="dc2626"),
    "HIGH": Font(name="Calibri", bold=True, size=10, color="ea580c"),
    "MEDIUM": Font(name="Calibri", bold=True, size=10, color="ca8a04"),
    "LOW": Font(name="Calibri", bold=True, size=10, color="2563eb"),
}

STATUS_FILL = {
    "Open": PatternFill("solid", fgColor="fef2f2"),
    "In Progress": PatternFill("solid", fgColor="fff7ed"),
    "Closed": PatternFill("solid", fgColor="f0fdf4"),
    "Accepted Risk": PatternFill("solid", fgColor="f1f5f9"),
}

STATUS_VALUES = '"Open,In Progress,Closed,Accepted Risk"'


# â”€â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def _apply_header(ws, row, cols):
    for c in range(1, cols + 1):
        cell = ws.cell(row=row, column=c)
        cell.fill = HDR_FILL
        cell.font = HDR_FONT
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = THIN


def _apply_body(ws, start, end, cols, sev_list=None):
    for r in range(start, end + 1):
        idx = r - start
        sev = sev_list[idx] if sev_list and idx < len(sev_list) else None
        for c in range(1, cols + 1):
            cell = ws.cell(row=r, column=c)
            cell.font = BODY_FONT
            cell.alignment = Alignment(vertical="top", wrap_text=True)
            cell.border = THIN
            if c == 3 and sev:
                cell.font = SEV_FONT.get(sev, BODY_FONT)
            if sev:
                cell.fill = SEV_FILL.get(sev, PatternFill())


def _auto_width(ws, cols, mx=65):
    for c in range(1, cols + 1):
        lengths = []
        for cell in ws[get_column_letter(c)]:
            if cell.value:
                for line in str(cell.value).split("\n"):
                    lengths.append(len(line))
        best = max(lengths) + 3 if lengths else 12
        ws.column_dimensions[get_column_letter(c)].width = min(best, mx)


def _write_title(ws, title, subtitle, row=1, cols=10):
    ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=cols)
    cell = ws.cell(row=row, column=1, value=title)
    cell.font = TITLE_FONT
    ws.merge_cells(start_row=row + 1, start_column=1, end_row=row + 1, end_column=cols)
    ws.cell(row=row + 1, column=1, value=subtitle).font = SUB_FONT
    return row + 2


# â”€â”€â”€ Main Export â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def export_excel(findings, chains, filepath=None, client_config=None, risk=None, env_stats=None, report_title=""):
    """Generate a professional audit findings workbook.
    
    Sheets:
      1. Dashboard       - Executive summary, risk scores, statistics
      2. Findings Register - Main audit tracker with Action Taken / Status / Owner
      3. Attack Paths     - All identified attack chain paths
      4. Compliance       - Framework mapping per finding
      5. Affected Assets  - Users, Groups, Computers, GPOs, OUs
      6. Remediation Status - Pivot summary of open vs closed
      7. AD Environment   - Directory object counts and metrics
      8. Trend Comparison - Current vs previous assessment

    Args:
        findings: list of finding dicts
        chains: list of chain dicts
        filepath: output file path (auto-generated from client_config if None)
        client_config: dict with client_name, engagement_id, assessor, data_version
        risk: risk dict
        env_stats: precomputed environment stats dict
    Returns:
        output path string
    """
    cfg = client_config or {}
    client_name = cfg.get("client_name", "Client")
    engagement = cfg.get("engagement_id", "")
    assessor = cfg.get("assessor", "Security Assessment Team")
    data_ver = cfg.get("data_version", "1.0")

    if filepath:
        output = filepath
    else:
        from config import get_output_paths
        output = get_output_paths(client_name, data_ver)["engineering_xlsx"]
    os.makedirs(os.path.dirname(output), exist_ok=True)

    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    if env_stats is None:
        env_stats = compute_env_stats(findings, chains, risk)

    has_ad = any(f.get("source") == "Active Directory" for f in findings)
    has_az = any(f.get("source") == "Azure" for f in findings)

    wb = Workbook()

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # SHEET 1: DASHBOARD
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    ws_dash = wb.active
    ws_dash.title = "Dashboard"
    ws_dash.sheet_properties.tabColor = NAVY

    r = _write_title(ws_dash, report_title or "Hybrid Identity Security Assessment",
                     f"{assessor} | {client_name} | {engagement} | Generated: {now}", 1, 6)

    critical = env_stats["critical_findings"]
    high = env_stats["high_findings"]
    medium = env_stats["medium_findings"]
    low = env_stats["low_findings"]
    total_active = env_stats["total_active"]
    risk_score = env_stats["risk_score"]

    # KPI block
    kpi_data = [
        ["Metric", "Value"],
        ["Client", client_name],
        ["Engagement ID", engagement],
        ["Assessment Date", now],
        ["Data Version", data_ver],
        ["Total Findings (active)", total_active],
        ["Critical", critical],
        ["High", high],
        ["Medium", medium],
        ["Low", low],
        ["Attack Chains", env_stats["attack_chains"]],
        ["Attack Paths", env_stats["attack_paths"]],
        ["Affected Accounts", env_stats["affected_accounts"]],
        ["Tier-0 Exposure", env_stats["tier0_exposure"]],
        ["DCSync Exposure", env_stats["dcsync_exposure"]],
        ["Risk Score", f"{risk_score}/100"],
        ["Overall Rating", "CRITICAL" if risk_score >= 70 else "HIGH" if risk_score >= 30 else "MEDIUM" if risk_score >= 15 else "LOW"],
    ]
    for i, (k, v) in enumerate(kpi_data):
        ws_dash.cell(row=r + i, column=1, value=k).font = BOLD_FONT
        ws_dash.cell(row=r + i, column=2, value=v).font = BODY_FONT
        ws_dash.cell(row=r + i, column=1).border = THIN
        ws_dash.cell(row=r + i, column=2).border = THIN

    ws_dash.column_dimensions["A"].width = 28
    ws_dash.column_dimensions["B"].width = 45

    cr = r + len(kpi_data) + 2
    ws_dash.cell(row=cr, column=1, value="Generated with GraphShield Hybrid Identity Security Platform").font = Font(name="Calibri", italic=True, size=9, color="808080")

    # Navigation hyperlinks
    cr += 1
    ws_dash.cell(row=cr, column=1, value="Quick Navigation").font = SUB_FONT
    cr += 1
    def _nav(sheet, cell="A1"):
        q = f"'{sheet}'" if " " in sheet else sheet
        return f"{q}!{cell}"

    nav_items = [
        ("\u2192 Open Findings Register (add Status / Owner / Due Date)", _nav("Findings Register")),
        ("\u2192 View Attack Chains", _nav("Attack Chains")),
        ("\u2192 View Compliance Mapping", _nav("Compliance")),
        ("\u2192 View Remediation Status", _nav("Remediation Status")),
    ]
    if has_ad:
        nav_items.append(("\u2192 View AD Environment", _nav("AD Environment")))
    if has_az:
        nav_items.append(("\u2192 View Azure Environment", _nav("Azure Environment")))
    nav_items.append(("\u2192 View Trend Comparison", _nav("Trend Comparison")))

    for label, target in nav_items:
        cell = ws_dash.cell(row=cr, column=1, value=label)
        cell.hyperlink = Hyperlink(ref=cell.coordinate, location=target)
        cell.font = LINK_FONT
        cr += 1

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # SHEET 2: LIMITATIONS & RELIANCE
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    ws_lim = wb.create_sheet("Limitations")
    ws_lim.sheet_properties.tabColor = NAVY

    data_src = cfg.get("data_source_type", "Neo4j Graph Database (live)")
    sh_sha256 = cfg.get("sharphound_sha256", None)
    sh_method = cfg.get("sharphound_collection_method", None)
    sh_ts = cfg.get("sharphound_timestamp", None)
    ah_sha256 = cfg.get("azurehound_sha256", None)
    ah_method = cfg.get("azurehound_collection_method", None)
    ah_ts = cfg.get("azurehound_timestamp", None)

    r = _write_title(ws_lim, "Limitations & Reliance",
                     f"{client_name} | {engagement} | This section governs report reliance", 1, 2)

    data_srcs = []
    if has_ad:
        data_srcs.append("SharpHound (.zip/JSON)")
    if has_az:
        data_srcs.append("AzureHound (.zip/JSON)")
    data_src_text = " and ".join(data_srcs) if data_srcs else "SharpHound (.zip/JSON) and AzureHound (.zip/JSON)"

    lim_sections = [
        ("Data Source", data_src),
    ]
    if has_ad:
        lim_sections += [
            ("", ""),
            ("SharpHound (AD) - SHA-256", sh_sha256 if sh_sha256 else "Not applicable (Neo4j direct connection)"),
            ("SharpHound (AD) - Collection Method", sh_method if sh_method else "Inferred from Neo4j graph"),
            ("SharpHound (AD) - Collection Timestamp", sh_ts if sh_ts else "Not available"),
        ]
    if has_az:
        lim_sections += [
            ("", ""),
            ("AzureHound (Azure) - SHA-256", ah_sha256 if ah_sha256 else "Not applicable (Neo4j direct connection)"),
            ("AzureHound (Azure) - Collection Method", ah_method if ah_method else "Inferred from Neo4j graph"),
            ("AzureHound (Azure) - Collection Timestamp", ah_ts if ah_ts else "Not available"),
        ]
    lim_sections += [
        ("", ""),
        ("Reliance on Client-Provided BloodHound CE Ingestion Data",
         f"The findings, graph calculations, and attack-path visualizations outlined in this report are "
         f"strictly dependent on the static {data_src_text} data packages "
         "provided directly by the Client's IT personnel. The Consultant did not control, verify, or execute "
         "the underlying data collection binaries within the production environment."),
        ("Tool Logic & Data Authenticity Limits",
         "The Consultant operates under the absolute assumption that the source ingestor scripts were "
         "executed comprehensively (e.g., using complete Collection Method scopes) and with unhindered "
         "read privileges across all domain controllers, forests, and cloud tenants. The Consultant accepts "
         "no liability for hidden privilege escalation paths or structural directory backdoors that went "
         "unresolved or undetected due to corrupt, truncated, out-of-date, or intentionally filtered output "
         "datasets provided by the client. "
         "The BloodHound tool suite performs a static, query-based analysis of AD and Azure/Entra ID "
         "relationships. It does not execute exploit code or validate whether a path is actively "
         "weaponisable. Findings represent theoretical attack paths and are subject to the completeness "
         "of the collected data. The Consultant disclaims liability for paths BloodHound failed to "
         "enumerate due to tool version limitations, unsupported collection methods, or language/region "
         "configuration differences."),
        ("Point-in-Time Assessment",
         f"The findings, risk scores, and attack-path analysis reflect the state of the environment as "
         f"captured by the {data_src_text} data snapshots at the timestamps listed above. "
         "AD and cloud identity environments are inherently dynamic. This assessment does not constitute a "
         "forward-looking guarantee of the security posture at any future date."),
        ("Not a Penetration Test",
         "This engagement is a static graph-based identity security review, not a penetration test. No "
         "active exploitation, credential compromise, social engineering, or adversarial simulation was "
         "employed. The assessment relies entirely on pre-collected BloodHound graph data and does not "
         "include live scanning or runtime validation of attack paths."),
        ("No Guarantee of Total Immunity",
         "Remediation of all findings does not guarantee the environment is free from all security "
         "vulnerabilities or attack paths. This assessment is limited to the relationships captured in "
         "the provided BloodHound graph data. Other vectorsâ€”including application-layer, network-level, "
         "endpoint, and social engineering risksâ€”remain outside scope."),
        ("Limitation of Liability",
         "UNDER NO CIRCUMSTANCES SHALL THE CONSULTANT BE LIABLE TO ANY ENTITY WHOMSOEVER FOR ANY DAMAGES, "
         "CLAIMS, LOSSES, OR EXPENSES ARISING OUT OF OR RELATED TO THIS REPORT, THE DATA COLLECTION "
         "METHODOLOGY, THE ACCURACY OR COMPLETENESS OF FINDINGS, OR ANY ACTIONS TAKEN OR OMITTED BASED ON "
         "THIS REPORT, WHETHER IN CONTRACT, TORT (INCLUDING NEGLIGENCE), OR OTHERWISE. ANY ENGAGING ENTITY "
         "ASSUMES ALL RISK AND RESPONSIBILITY FOR ANY DECISIONS MADE BASED ON THIS REPORT. IN NO EVENT "
         "SHALL THE CONSULTANT'S AGGREGATE LIABILITY EXCEED THE TOTAL FEES PAID TO THE CONSULTANT FOR "
         "THIS ENGAGEMENT."),
        ("No Warranty / As-Is Disclaimer",
         'THIS REPORT AND ALL FINDINGS, DATA, AND RECOMMENDATIONS CONTAINED HEREIN ARE PROVIDED "AS IS" '
         'AND "AS AVAILABLE" WITHOUT ANY WARRANTY WHATSOEVER, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED '
         "TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR "
         "NON-INFRINGEMENT. THE CONSULTANT DOES NOT WARRANT THAT REMEDIATION OF IDENTIFIED FINDINGS WILL "
         "PREVENT SECURITY INCIDENTS, UNAUTHORIZED ACCESS, OR DATA BREACHES. THE ENGAGING ENTITY(S) "
         "ACKNOWLEDGE THAT THEY HAVE NOT RELIED UPON ANY REPRESENTATION OR WARRANTY MADE BY THE CONSULTANT "
         "EXCEPT AS EXPRESSLY SET FORTH HEREIN."),
        ("Report Use Restriction",
         "This report is prepared exclusively for the named engaging entity/entities listed on the "
         "cover page. No other person or entity is entitled to rely on this report for any purpose whatsoever. "
         "This report shall not be reproduced, distributed, or disclosed to any third party without the prior "
         "written consent of the Consultant. Any unauthorized use, reliance, or distribution by any third party "
         "shall be at such party's sole risk, and the Consultant disclaims all liability arising therefrom."),
        ("Explicit Treatment of [NO DATA] Markers",
         'Metrics or finding groups marked as [NO DATA] explicitly reflect zero data entries present inside '
         "the client's provided JSON blobs. This signifier does not mean a security risk is absent from the "
         "infrastructure. Instead, it indicates data collection limitations, such as restricted Active "
         "Directory permissions, disabled domain logging, endpoint security filtering (e.g., EDR blocks during "
         "SharpHound execution), or missing cloud API configurations. Remediation of data collection gaps "
         "remains the exclusive responsibility of the Client."),
    ]

    for section_title, body in lim_sections:
        if section_title:
            ws_lim.cell(row=r, column=1, value=section_title).font = BOLD_FONT
            ws_lim.cell(row=r, column=1).border = THIN
            ws_lim.cell(row=r, column=1).alignment = Alignment(vertical="top", wrap_text=True)
            ws_lim.cell(row=r, column=2, value=body).font = BODY_FONT
            ws_lim.cell(row=r, column=2).border = THIN
            ws_lim.cell(row=r, column=2).alignment = Alignment(vertical="top", wrap_text=True)
        r += 1

    ws_lim.column_dimensions["A"].width = 45
    ws_lim.column_dimensions["B"].width = 80

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # SHEET 3: FINDINGS REGISTER (main audit tracker)
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    ws_reg = wb.create_sheet("Findings Register")
    ws_reg.sheet_properties.tabColor = NAVY

    reg_headers = [
        "Finding ID", "Title", "Severity", "Confidence", "Source",
        "Group",
        "MITRE ID", "MITRE Technique", "MITRE Tactic",
        "CIS Controls v8.1", "NIST CSF 2.0", "ISO/IEC 27001:2022", "OWASP NHI Top 10 (2025)",
        "Affected Objects",
        "Impact", "Recommended Action", "Detection Strategy",
        "Action Taken", "Status", "Owner", "Due Date", "Notes",
        "Corroboration (NHI)"
    ]
    reg_cols = len(reg_headers)

    r = _write_title(ws_reg, "Findings Register - Audit Action Tracker",
                     f"{client_name} | {engagement} | Instructions: Update columns R-U (Status, Owner, Due Date, Notes) as work progresses",
                     1, reg_cols)
    reg_header_row = r

    # Validation dropdown for Status column (col 18)
    dv = DataValidation(type="list", formula1=STATUS_VALUES, allow_blank=True, showErrorMessage=True, errorStyle="stop")
    dv.error = "Please select a valid status"
    dv.errorTitle = "Invalid Status"
    ws_reg.add_data_validation(dv)

    # Date validation for Due Date column (col 20)
    dd_dv = DataValidation(type="date", allow_blank=True)
    dd_dv.error = "Please enter a valid date (YYYY-MM-DD)"
    dd_dv.errorTitle = "Invalid Date"
    ws_reg.add_data_validation(dd_dv)

    for ci, h in enumerate(reg_headers, 1):
        ws_reg.cell(row=r, column=ci, value=h)
    _apply_header(ws_reg, r, reg_cols)
    r += 1

    sev_order = []
    ad_n = 0
    az_n = 0
    last_group = None
    for f in findings:
        group_key = f.get("group")
        if group_key and group_key != last_group:
            group_name = GROUPS.get(group_key, {}).get("name", group_key)
            ws_reg.merge_cells(start_row=r, start_column=1, end_row=r, end_column=reg_cols)
            cell = ws_reg.cell(row=r, column=1, value=group_name)
            cell.font = Font(bold=True, color=NAVY)
            cell.fill = PatternFill(start_color="E2E8F0", end_color="E2E8F0", fill_type="solid")
            cell.alignment = Alignment(horizontal="center", vertical="center")
            r += 1
            last_group = group_key
        if f.get("source") == "Azure":
            az_n += 1
            fid = f"AZ-{az_n:03d}"
        else:
            ad_n += 1
            fid = f"AD-{ad_n:03d}"
        mitre = f.get("mitre", {}) or {}
        cat_id = f.get("id", "")
        comp = COMPLIANCE_MAP.get(cat_id, {})
        has_ev = f.get("has_evidence", False)

        ad = f.get("ad_objects", {})
        obj_parts = []
        for k in ("users", "groups", "computers", "gpos"):
            vals = ad.get(k, [])
            if vals:
                label = k.capitalize()
                if len(vals) <= 3:
                    obj_parts.append(f"{label}: {', '.join(vals)}")
                else:
                    obj_parts.append(f"{label}: {len(vals)} items")
        # Azure entity types
        for k, label in [("service_principals", "Service Principals"), ("managed_identities", "Managed Identities"),
                         ("applications", "Applications"), ("key_vaults", "Key Vaults"),
                         ("tenants", "Tenants")]:
            vals = ad.get(k, [])
            if vals:
                if len(vals) <= 3:
                    obj_parts.append(f"{label}: {', '.join(vals)}")
                else:
                    obj_parts.append(f"{label}: {len(vals)} items")
        affected = "; ".join(obj_parts) if obj_parts else "N/A"
        if len(affected) > 500:
            affected = affected[:500] + "..."

        title_val = f.get("title", "")
        if not has_ev:
            title_val += " [NO DATA]"

        group_key = f.get("group", "")
        group_name = GROUPS.get(group_key, {}).get("name", group_key) if group_key else ""
        row_data = [
            fid,
            title_val,
            f.get("severity", ""),
            f.get("confidence", "No Data"),
            f.get("source", ""),
            group_name,
            mitre.get("id", ""),
            mitre.get("technique", ""),
            mitre.get("tactic", ""),
            comp.get("CIS", ""),
            comp.get("NIST", ""),
            comp.get("ISO 27001", ""),
            comp.get("OWASP NHI", ""),
            affected,
            f.get("impact", ""),
            "\n".join(f.get("remediation", [])),
            "\n".join(f.get("detection", [])),
            "",  # Action Taken (empty for engineer)
            "Open",  # Default Status
            "",  # Owner
            "",  # Due Date
            "",  # Notes
            _corroboration(f),  # Corroboration (NHI) - NHI assessment only
        ]
        for ci, val in enumerate(row_data, 1):
            cell = ws_reg.cell(row=r, column=ci, value=val)
            if ci == 19:  # Status column
                dv.add(cell)
            if ci == 21:  # Due Date column
                dd_dv.add(cell)
        sev_order.append(f.get("severity", ""))
        r += 1

    _apply_body(ws_reg, r - len(findings), r - 1, reg_cols, sev_order)

    # Freeze panes below header
    ws_reg.freeze_panes = ws_reg.cell(row=reg_header_row + 1, column=1).coordinate if findings else "A3"

    # Auto-filter on header row
    if findings:
        ws_reg.auto_filter.ref = f"A{reg_header_row}:{get_column_letter(reg_cols)}{r - 1}"

    # Conditional formatting for severity and status
    if findings:
        data_range = f"A{reg_header_row + 1}:{get_column_letter(reg_cols)}{r - 1}"
        # Highlight Critical severity rows (col C)
        ws_reg.conditional_formatting.add(data_range,
            FormulaRule(formula=[f'$C{reg_header_row + 1}="CRITICAL"'],
                        fill=PatternFill("solid", fgColor="FFC7CE"),
                        font=Font(color="9C0006")))
        # Highlight Closed status rows green (col R)
        ws_reg.conditional_formatting.add(data_range,
            FormulaRule(formula=[f'$S{reg_header_row + 1}="Closed"'],
                        fill=PatternFill("solid", fgColor="C6EFCE"),
                        font=Font(color="006100")))
        # Highlight Accepted Risk rows gray (col R)
        ws_reg.conditional_formatting.add(data_range,
            FormulaRule(formula=[f'$S{reg_header_row + 1}="Accepted Risk"'],
                        fill=PatternFill("solid", fgColor="D9D9D9"),
                        font=Font(color="333333")))
        # Highlight In Progress rows yellow (col R)
        ws_reg.conditional_formatting.add(data_range,
            FormulaRule(formula=[f'$S{reg_header_row + 1}="In Progress"'],
                        fill=PatternFill("solid", fgColor="FFEB9C"),
                        font=Font(color="9C6500")))

    # Print setup: landscape, fit to width, repeat header row
    ws_reg.page_setup.orientation = "landscape"
    ws_reg.page_setup.fitToWidth = 1
    ws_reg.page_setup.fitToHeight = 0
    ws_reg.print_title_rows = f"{reg_header_row}:{reg_header_row}"

    _auto_width(ws_reg, reg_cols, 60)
    # Make certain columns wider
    for ci in [1, 2, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22]:
        letter = get_column_letter(ci)
        if ws_reg.column_dimensions[letter].width < 40:
            ws_reg.column_dimensions[letter].width = 40
    # Extra width for long text columns
    for ci in [14, 16, 17]:
        ws_reg.column_dimensions[get_column_letter(ci)].width = 55

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # SHEET 3: ATTACK PATHS
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    ws_ap = wb.create_sheet("Attack Chains")
    ws_ap.sheet_properties.tabColor = NAVY

    ap_headers = ["#", "Risk Type", "Severity", "Attack Path", "MITRE ID", "MITRE Technique"]
    ap_cols = len(ap_headers)
    r = _write_title(ws_ap, "Attack Chain Analysis", client_name, 1, ap_cols)

    for ci, h in enumerate(ap_headers, 1):
        ws_ap.cell(row=r, column=ci, value=h)
    _apply_header(ws_ap, r, ap_cols)
    r += 1

    for idx, c in enumerate(chains, 1):
        mitre = c.get("mitre", {}) or {}
        row_data = [idx, c.get("risk", ""), c.get("severity", ""),
                    c.get("attack_path", ""), mitre.get("id", ""), mitre.get("technique", "")]
        for ci, val in enumerate(row_data, 1):
            ws_ap.cell(row=r, column=ci, value=val)
        r += 1

    _apply_body(ws_ap, r - len(chains), r - 1, ap_cols)

    if chains:
        ws_ap.auto_filter.ref = f"A{r - len(chains) - 1}:{get_column_letter(ap_cols)}{r - 1}"
    ws_ap.page_setup.orientation = "landscape"
    ws_ap.page_setup.fitToWidth = 1
    ws_ap.page_setup.fitToHeight = 0

    _auto_width(ws_ap, ap_cols, 60)
    ws_ap.column_dimensions["D"].width = 80

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # SHEET 4: COMPLIANCE MAPPING
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    ws_cm = wb.create_sheet("Compliance")
    ws_cm.sheet_properties.tabColor = NAVY

    cm_headers = ["Finding ID", "Finding Title", "Severity", "CIS Controls v8.1", "NIST CSF 2.0", "ISO/IEC 27001:2022", "SA 315 (ICAI)", "DPDP Act 2023", "OWASP NHI Top 10 (2025)"]
    cm_cols = len(cm_headers)
    r = _write_title(ws_cm, "Compliance Framework Mapping", client_name, 1, cm_cols)

    for ci, h in enumerate(cm_headers, 1):
        ws_cm.cell(row=r, column=ci, value=h)
    _apply_header(ws_cm, r, cm_cols)
    r += 1

    ac_n = 0
    azc_n = 0
    for f in findings:
        cat_id = f.get("id", "")
        comp = COMPLIANCE_MAP.get(cat_id, {})
        if f.get("source") == "Azure":
            azc_n += 1
            fid_c = f"AZ-{azc_n:03d}"
        else:
            ac_n += 1
            fid_c = f"AD-{ac_n:03d}"
        row_data = [fid_c, f.get("title", ""), f.get("severity", ""),
                    comp.get("CIS", ""), comp.get("NIST", ""), comp.get("ISO 27001", ""),
                    comp.get("SA 315", ""), comp.get("DPDP", ""), comp.get("OWASP NHI", "")]
        for ci, val in enumerate(row_data, 1):
            ws_cm.cell(row=r, column=ci, value=val)
        r += 1

    _apply_body(ws_cm, r - len(findings), r - 1, cm_cols)

    if findings:
        ws_cm.auto_filter.ref = f"A{r - len(findings) - 1}:{get_column_letter(cm_cols)}{r - 1}"
    ws_cm.page_setup.orientation = "landscape"
    ws_cm.page_setup.fitToWidth = 1
    ws_cm.page_setup.fitToHeight = 0

    _auto_width(ws_cm, cm_cols, 50)

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # SHEET 5: AFFECTED ASSETS
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    ws_aa = wb.create_sheet("Affected Assets")
    ws_aa.sheet_properties.tabColor = NAVY

    aa_headers = ["Finding ID", "Title", "Severity", "Category", "Asset Name"]
    aa_cols = len(aa_headers)
    r = _write_title(ws_aa, "Affected Directory Assets", client_name, 1, aa_cols)

    for ci, h in enumerate(aa_headers, 1):
        ws_aa.cell(row=r, column=ci, value=h)
    _apply_header(ws_aa, r, aa_cols)
    r += 1

    aad_n = 0
    aaz_n = 0
    for f in findings:
        if f.get("source") == "Azure":
            aaz_n += 1
            fid = f"AZ-{aaz_n:03d}"
        else:
            aad_n += 1
            fid = f"AD-{aad_n:03d}"
        sev = f.get("severity", "")
        title = f.get("title", "")
        ad = f.get("ad_objects", {})
        for cat in ("users", "groups", "computers", "gpos", "organizational_units"):
            for asset in ad.get(cat, []):
                ws_aa.cell(row=r, column=1, value=fid)
                ws_aa.cell(row=r, column=2, value=title)
                ws_aa.cell(row=r, column=3, value=sev)
                ws_aa.cell(row=r, column=4, value=cat.capitalize())
                ws_aa.cell(row=r, column=5, value=asset)
                r += 1
        for cat, label in [("service_principals", "Service Principal"), ("managed_identities", "Managed Identity"),
                           ("applications", "Application"), ("key_vaults", "Key Vault"),
                           ("tenants", "Tenant")]:
            for asset in ad.get(cat, []):
                ws_aa.cell(row=r, column=1, value=fid)
                ws_aa.cell(row=r, column=2, value=title)
                ws_aa.cell(row=r, column=3, value=sev)
                ws_aa.cell(row=r, column=4, value=label)
                ws_aa.cell(row=r, column=5, value=asset)
                r += 1

    if r <= 5:  # only header + title rows written
        ws_aa.cell(row=r, column=1, value="No affected assets mapped. Connect to Neo4j to populate.")
    else:
        _apply_body(ws_aa, 5, r - 1, aa_cols)
    _auto_width(ws_aa, aa_cols, 50)
    ws_aa.column_dimensions["E"].width = 55

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # SHEET 6: REMEDIATION STATUS (summary pivot)
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    ws_rs = wb.create_sheet("Remediation Status")
    ws_rs.sheet_properties.tabColor = NAVY

    r = _write_title(ws_rs, "Remediation Status Summary",
                     "Aggregate view of findings by severity and status. Update the Findings Register first.",
                     1, 4)

    # Dynamic formulas referencing Findings Register column R (Status)
    fr_row1 = reg_header_row + 1
    fr_rowN = reg_header_row + len(findings)
    fr_range = f"'Findings Register'!R${fr_row1}:R${fr_rowN}"

    status_list = ["Open", "In Progress", "Closed", "Accepted Risk"]
    pivot_headers = ["Status", "Count", "Severity Breakdown"]
    for ci, h in enumerate(pivot_headers, 1):
        ws_rs.cell(row=r, column=ci, value=h)
    _apply_header(ws_rs, r, 3)
    r += 1

    for status in status_list:
        ws_rs.cell(row=r, column=1, value=status)
        ws_rs.cell(row=r, column=2).value = f"=COUNTIF({fr_range},A{r})"
        # Severity: column C (3) = CRITICAL, D (4) = HIGH, E (5) = MEDIUM, F (6) = LOW
        sev_range_c = f"'Findings Register'!C${fr_row1}:C${fr_rowN}"
        ws_rs.cell(row=r, column=3).value = (
            f'="C: "&COUNTIFS({fr_range},A{r},{sev_range_c},"CRITICAL")'
            f'&" | H: "&COUNTIFS({fr_range},A{r},{sev_range_c},"HIGH")'
            f'&" | M: "&COUNTIFS({fr_range},A{r},{sev_range_c},"MEDIUM")'
            f'&" | L: "&COUNTIFS({fr_range},A{r},{sev_range_c},"LOW")'
        )
        for ci in range(1, 4):
            ws_rs.cell(row=r, column=ci).font = BODY_FONT
            ws_rs.cell(row=r, column=ci).border = THIN
            if status in STATUS_FILL:
                ws_rs.cell(row=r, column=ci).fill = STATUS_FILL[status]
        r += 1

    ws_rs.column_dimensions["A"].width = 20
    ws_rs.column_dimensions["B"].width = 15
    ws_rs.column_dimensions["C"].width = 55

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # SHEET 7: AD ENVIRONMENT OVERVIEW
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    if has_ad:
        ws_env = wb.create_sheet("AD Environment")
        ws_env.sheet_properties.tabColor = NAVY

        r = _write_title(ws_env, "AD Environment Overview",
                         f"{client_name} | Objects identified across all findings", 1, 2)

        env_headers = ["Metric", "Value"]
        for ci, h in enumerate(env_headers, 1):
            ws_env.cell(row=r, column=ci, value=h)
        _apply_header(ws_env, r, 2)
        r += 1

        env_rows = [
            ("Users (Affected)", env_stats["total_users"]),
            ("Computers", env_stats["total_computers"]),
            ("Servers", env_stats["servers"]),
            ("Domain Controllers", env_stats["domain_controllers"]),
            ("Groups", env_stats["total_groups"]),
            ("Tier-0 Accounts", env_stats["tier0_accounts"]),
            ("Service Accounts", env_stats["service_accounts"]),
            ("Trust Relationships", env_stats["trusts"]),
            ("Tier-0 Exposure", env_stats["tier0_exposure"]),
            ("DCSync Exposure", env_stats["dcsync_exposure"]),
        ]
        for metric, value in env_rows:
            ws_env.cell(row=r, column=1, value=metric).font = BOLD_FONT
            ws_env.cell(row=r, column=2, value=value).font = BODY_FONT
            ws_env.cell(row=r, column=1).border = THIN
            ws_env.cell(row=r, column=2).border = THIN
            r += 1

        ws_env.column_dimensions["A"].width = 25
        ws_env.column_dimensions["B"].width = 20

        # Per-forest breakdown
        forests = env_stats.get("forests", [])
        if forests:
            has_dcsync = any(
                f.get("id") == "DCSYNC" and f.get("has_evidence", False)
                for f in findings
            )
            r += 1
            r = _write_title(ws_env, "Environment Breakdown by Forest", "", r, 3)

            forest_metrics = [
                ("users", "Users (Affected)"),
                ("computers", "Computers"),
                ("servers", "Servers"),
                ("domain_controllers", "Domain Controllers"),
                ("groups", "Groups"),
                ("tier0_accounts", "Tier-0 Accounts"),
                ("service_accounts", "Service Accounts"),
                ("trusts", "Trust Relationships"),
                ("tier0_exposure", "Tier-0 Exposure"),
                ("dcsync_exposure", "DCSync Exposure"),
            ]

            # Group forests into pairs (2 per block)
            pairs = [forests[i:i+2] for i in range(0, len(forests), 2)]
            for pair_idx, pair in enumerate(pairs):
                n_in_pair = len(pair)
                total_cols = n_in_pair * 2

                # Forest name header
                col = 1
                for fb in pair:
                    ws_env.merge_cells(start_row=r, start_column=col, end_row=r, end_column=col + 1)
                    ws_env.cell(row=r, column=col, value=f"Forest: {fb['name']}").font = HDR_FONT
                    ws_env.cell(row=r, column=col).fill = HDR_FILL
                    ws_env.cell(row=r, column=col + 1).fill = HDR_FILL
                    col += 2
                r += 1

                # Metric / Value sub-header
                col = 1
                for fb in pair:
                    ws_env.cell(row=r, column=col, value="Metric")
                    ws_env.cell(row=r, column=col + 1, value="Value")
                    col += 2
                _apply_header(ws_env, r, total_cols)
                r += 1

                # Data rows
                for meta_key, meta_label in forest_metrics:
                    col = 1
                    for fb in pair:
                        metrics = fb.get("metrics", {})
                        if meta_key == "tier0_exposure":
                            val = "YES" if metrics.get("tier0_accounts", 0) > 0 else "NO"
                        elif meta_key == "dcsync_exposure":
                            val = "YES" if has_dcsync else "NO"
                        else:
                            val = metrics.get(meta_key, 0)
                        ws_env.cell(row=r, column=col, value=meta_label).font = BOLD_FONT
                        ws_env.cell(row=r, column=col + 1, value=val).font = BODY_FONT
                        ws_env.cell(row=r, column=col).border = THIN
                        ws_env.cell(row=r, column=col + 1).border = THIN
                        col += 2
                    r += 1

                # Column widths
                col = 1
                for fb in pair:
                    ws_env.column_dimensions[get_column_letter(col)].width = 22
                    ws_env.column_dimensions[get_column_letter(col + 1)].width = 12
                    col += 2

                if pair_idx < len(pairs) - 1:
                    r += 1  # blank row between pairs

            r += 1
            note = ("Per-forest counts are scoped to objects whose SID prefix matches each domain. "
                    "Built-in groups, well-known SIDs, and cross-domain objects appear only in the "
                    "global AD Environment Overview totals above, which may exceed the sum of per-forest counts.")
            ws_env.merge_cells(start_row=r, start_column=1, end_row=r, end_column=3)
            ws_env.cell(row=r, column=1, value=note).font = Font(italic=True, size=8, color="666666")
            ws_env.cell(row=r, column=1).alignment = Alignment(wrap_text=True, vertical="top")

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # SHEET 8: AZURE / ENTRA ID ENVIRONMENT
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    if has_az:
        az_tenants = env_stats.get("azure_tenants", [])
        ws_az = wb.create_sheet("Azure Environment")
        ws_az.sheet_properties.tabColor = NAVY

        r = _write_title(ws_az, "Azure / Entra ID Environment Overview",
                         f"{client_name} | Objects discovered across all Azure tenants", 1, 2)

        env_headers = ["Metric", "Value"]
        for ci, h in enumerate(env_headers, 1):
            ws_az.cell(row=r, column=ci, value=h)
        _apply_header(ws_az, r, 2)
        r += 1

        if az_tenants:
            az_rows = [
                ("Tenants", len(az_tenants)),
                ("Entra ID Users", env_stats.get("azure_users", 0)),
                ("Entra ID Groups", env_stats.get("azure_groups", 0)),
                ("Service Principals", env_stats.get("azure_service_principals", 0)),
                ("Managed Identities", env_stats.get("azure_managed_identities", 0)),
                ("Applications", env_stats.get("azure_applications", 0)),
                ("Key Vaults", env_stats.get("azure_key_vaults", 0)),
                ("Virtual Machines", env_stats.get("azure_vms", 0)),
                ("Subscriptions", env_stats.get("azure_subscriptions", 0)),
            ]
            for metric, value in az_rows:
                ws_az.cell(row=r, column=1, value=metric).font = BOLD_FONT
                ws_az.cell(row=r, column=2, value=value).font = BODY_FONT
                ws_az.cell(row=r, column=1).border = THIN
                ws_az.cell(row=r, column=2).border = THIN
                r += 1
        else:
            for metric in ["Tenants", "Entra ID Users", "Entra ID Groups", "Service Principals",
                           "Managed Identities", "Applications", "Key Vaults",
                           "Virtual Machines", "Subscriptions"]:
                ws_az.cell(row=r, column=1, value=metric).font = BOLD_FONT
                ws_az.cell(row=r, column=2, value="[NO DATA]").font = BODY_FONT
                ws_az.cell(row=r, column=1).border = THIN
                ws_az.cell(row=r, column=2).border = THIN
                r += 1

        az_tenants_detail = env_stats.get("azure_tenants_detail", [])

        # Per-tenant breakdown (only available with real data)
        if az_tenants and az_tenants_detail:
            r += 1
            r = _write_title(ws_az, "Environment Breakdown by Tenant", "", r, 3)

            az_tenant_metrics = [
                ("users", "Entra ID Users"),
                ("groups", "Groups"),
                ("service_principals", "Service Principals"),
                ("managed_identities", "Managed Identities"),
                ("applications", "Applications"),
                ("global_admins", "Global Admins"),
            ]

            az_pairs = [az_tenants_detail[i:i+2] for i in range(0, len(az_tenants_detail), 2)]
            for pair_idx, pair in enumerate(az_pairs):
                n_in_pair = len(pair)
                total_cols = n_in_pair * 2

                col = 1
                for tb in pair:
                    ws_az.merge_cells(start_row=r, start_column=col, end_row=r, end_column=col + 1)
                    ws_az.cell(row=r, column=col, value=f"Tenant: {tb['name']}").font = HDR_FONT
                    ws_az.cell(row=r, column=col).fill = HDR_FILL
                    ws_az.cell(row=r, column=col + 1).fill = HDR_FILL
                    col += 2
                r += 1

                col = 1
                for tb in pair:
                    ws_az.cell(row=r, column=col, value="Metric")
                    ws_az.cell(row=r, column=col + 1, value="Value")
                    col += 2
                _apply_header(ws_az, r, total_cols)
                r += 1

                for meta_key, meta_label in az_tenant_metrics:
                    col = 1
                    for tb in pair:
                        val = tb.get("metrics", {}).get(meta_key, 0)
                        ws_az.cell(row=r, column=col, value=meta_label).font = BOLD_FONT
                        ws_az.cell(row=r, column=col + 1, value=val).font = BODY_FONT
                        ws_az.cell(row=r, column=col).border = THIN
                        ws_az.cell(row=r, column=col + 1).border = THIN
                        col += 2
                    r += 1

                col = 1
                for tb in pair:
                    ws_az.column_dimensions[get_column_letter(col)].width = 22
                    ws_az.column_dimensions[get_column_letter(col + 1)].width = 12
                    col += 2

                if pair_idx < len(az_pairs) - 1:
                    r += 1

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # SHEET 9: TREND COMPARISON
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    ws_tr = wb.create_sheet("Trend Comparison")
    ws_tr.sheet_properties.tabColor = NAVY

    r = _write_title(ws_tr, "Trend Comparison (Current vs Previous)",
                     f"{client_name} | Current: v{data_ver}", 1, 4)

    current_groups = sorted({f.get("group") for f in findings if f.get("group")},
                            key=lambda g: list(GROUPS.keys()).index(g) if g in GROUPS else 99)
    current_scope_names = [GROUPS[g]["name"] for g in current_groups if g in GROUPS]
    current_scope_label = "; ".join(current_scope_names) if current_scope_names else "N/A"

    ws_tr.cell(row=r, column=1, value="Current Scope:").font = BOLD_FONT
    ws_tr.cell(row=r, column=2, value=current_scope_label).font = BODY_FONT
    ws_tr.merge_cells(start_row=r, start_column=2, end_row=r, end_column=4)
    r += 1

    prev_stats = _load_prev_stats(client_name, data_ver)
    if prev_stats:
        prev_scope = prev_stats.get("scope", {})
        prev_groups = prev_scope.get("groups", [])
        prev_scope_names = [GROUPS[g]["name"] for g in prev_groups if g in GROUPS]
        prev_scope_label = "; ".join(prev_scope_names) if prev_scope_names else "N/A"

        ws_tr.cell(row=r, column=1, value="Previous Scope:").font = BOLD_FONT
        ws_tr.cell(row=r, column=2, value=prev_scope_label).font = BODY_FONT
        ws_tr.merge_cells(start_row=r, start_column=2, end_row=r, end_column=4)
        r += 1
        ws_tr.cell(row=r, column=1, value="").font = BODY_FONT
        r += 1

        same_scope = set(current_groups) == set(prev_groups)
        if same_scope:
            trend_headers = ["Metric", "Previous", "Current", "Change"]
            for ci, h in enumerate(trend_headers, 1):
                ws_tr.cell(row=r, column=ci, value=h)
            _apply_header(ws_tr, r, 4)
            r += 1

            def _delta(a, b):
                d = a - b
                return f"+{d}" if d > 0 else str(d) if d < 0 else "0"

            trend_items = [
                ("Critical Findings", prev_stats.get("critical_findings", 0), env_stats["critical_findings"]),
                ("High Findings", prev_stats.get("high_findings", 0), env_stats["high_findings"]),
                ("Medium Findings", prev_stats.get("medium_findings", 0), env_stats["medium_findings"]),
                ("Total Active", prev_stats.get("total_active", 0), env_stats["total_active"]),
                ("Attack Chains", prev_stats.get("attack_chains", 0), env_stats["attack_chains"]),
                ("Risk Score", prev_stats.get("risk_score", 0), env_stats["risk_score"]),
            ]
            for metric, prev, curr in trend_items:
                ws_tr.cell(row=r, column=1, value=metric).font = BOLD_FONT
                ws_tr.cell(row=r, column=2, value=prev).font = BODY_FONT
                ws_tr.cell(row=r, column=3, value=curr).font = BODY_FONT
                ws_tr.cell(row=r, column=4, value=_delta(curr, prev)).font = BODY_FONT
                for c in range(1, 5):
                    ws_tr.cell(row=r, column=c).border = THIN
                r += 1
        else:
            ws_tr.cell(row=r, column=1, value="Scopes differ \u2014 trend comparison skipped.").font = Font(name='Calibri', italic=True, color='FF0000')
            ws_tr.merge_cells(start_row=r, start_column=1, end_row=r, end_column=4)
            r += 1
    else:
        ws_tr.cell(row=r, column=1, value="No previous assessment found for trend comparison.").font = BODY_FONT
        ws_tr.merge_cells(start_row=r, start_column=1, end_row=r, end_column=4)
        r += 1

    ws_tr.column_dimensions["A"].width = 20
    ws_tr.column_dimensions["B"].width = 15
    ws_tr.column_dimensions["C"].width = 15
    ws_tr.column_dimensions["D"].width = 15

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # SHEET 10: EXCLUSIONS REFERENCE
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    ws_ex = wb.create_sheet("Exclusions Reference")
    ws_ex.sheet_properties.tabColor = NAVY

    r = _write_title(ws_ex, "Exclusions by Finding Type",
                     f"Built-in accounts, groups, and objects excluded from each finding's analysis", 1, 2)

    for ci, h in enumerate(["Finding Type", "Exclusions"], 1):
        ws_ex.cell(row=r, column=ci, value=h)
    _apply_header(ws_ex, r, 2)
    r += 1

    _active_keys = {f["id"] for f in findings if f.get("id")}
    for fid, exc_list in EXCLUSIONS_MAP.items():
        if fid not in _active_keys:
            continue
        ws_ex.cell(row=r, column=1, value=fid.replace("_", " ").title()).font = BOLD_FONT
        ws_ex.cell(row=r, column=2, value="; ".join(exc_list) if exc_list else "None").font = BODY_FONT
        ws_ex.cell(row=r, column=1).border = THIN
        ws_ex.cell(row=r, column=2).border = THIN
        ws_ex.cell(row=r, column=2).alignment = Alignment(vertical="top", wrap_text=True)
        r += 1

    ws_ex.column_dimensions["A"].width = 30
    ws_ex.column_dimensions["B"].width = 80

    # â”€â”€â”€ Save â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    wb.save(output)
    return output


def _load_prev_stats(client_name, current_version):
    """Load previous assessment stats for trend comparison."""
    try:
        from config import _safe_filename
        safe = _safe_filename(client_name)
        cdir = os.path.join(BASE_OUTPUT_DIR, safe)
        if not os.path.isdir(cdir):
            return None
        
        versions = sorted([d for d in os.listdir(cdir)
                          if d.startswith("v") and d != f"v{current_version}"], reverse=True)
        if not versions:
            return None
        
        for ver in versions:
            vdir = os.path.join(cdir, ver)
            for fn in os.listdir(vdir):
                if fn.endswith(".json") and "Evidence" in fn:
                    path = os.path.join(vdir, fn)
                    with open(path, encoding="utf-8") as f:
                        data = json.load(f)
                    stats = data.get("assessment", {}).get("statistics", {})
                    risk_data = data.get("risk", {})
                    return {
                        "critical_findings": stats.get("critical", 0),
                        "high_findings": stats.get("high", 0),
                        "medium_findings": stats.get("medium", 0),
                        "total_active": stats.get("active_findings", 0),
                        "attack_chains": stats.get("total_attack_chains", 0),
                        "risk_score": min(risk_data.get("total_score", 0), 100),
                        "scope": stats.get("assessment_scope", {}),
                    }
    except Exception:
        pass
    return None
