import os
import json
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak,
    Table, TableStyle, HRFlowable, KeepTogether, Image
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.units import inch, mm
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas as pdfcanvas
from datetime import datetime
from analytics.constants import COMPLIANCE_MAP, SEVERITY_COLORS as SEV_HEX
from analytics.groups import GROUPS
from config import compute_env_stats, BASE_OUTPUT_DIR, LOGO_PATH

SEVERITY_COLORS = {
    k: colors.HexColor(v) for k, v in SEV_HEX.items()
}

def add_page_number(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.drawString(40, 20, "Confidential")
    canvas.drawRightString(540, 20, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()

def safe_escape(text):
    if not text:
        return ""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def build_styles():
    styles = getSampleStyleSheet()
    custom = {
        "CoverTitle": ParagraphStyle("CoverTitle", parent=styles["Title"], fontSize=26, leading=32, alignment=TA_CENTER, textColor=colors.HexColor("#1e3a5f"), spaceAfter=6),
        "CoverSubtitle": ParagraphStyle("CoverSubtitle", parent=styles["Normal"], fontSize=14, leading=18, alignment=TA_CENTER, textColor=colors.HexColor("#475569"), spaceAfter=4),
        "SectionH1": ParagraphStyle("SectionH1", parent=styles["Heading1"], fontSize=16, leading=22, textColor=colors.HexColor("#1e3a5f"), spaceBefore=20, spaceAfter=10),
        "SectionH2": ParagraphStyle("SectionH2", parent=styles["Heading2"], fontSize=13, leading=18, textColor=colors.HexColor("#334155"), spaceBefore=12, spaceAfter=6),
        "SectionH3": ParagraphStyle("SectionH3", parent=styles["Heading3"], fontSize=11, leading=15, textColor=colors.HexColor("#475569"), spaceBefore=8, spaceAfter=4),
        "BodyJ": ParagraphStyle("BodyJ", parent=styles["Normal"], fontSize=9.5, leading=13, alignment=TA_JUSTIFY, spaceAfter=6),
        "BodySmall": ParagraphStyle("BodySmall", parent=styles["Normal"], fontSize=8.5, leading=11, spaceAfter=4),
        "Code": ParagraphStyle("Code", parent=styles["Code"], fontSize=8, leading=10, backColor=colors.HexColor("#f8fafc")),
        "Disclaimer": ParagraphStyle("Disclaimer", parent=styles["Normal"], fontSize=8, leading=10, textColor=colors.HexColor("#64748b"), alignment=TA_JUSTIFY),
        "BoldRed": ParagraphStyle("BoldRed", parent=styles["Normal"], fontSize=9.5, leading=13, textColor=colors.red, alignment=TA_JUSTIFY, spaceAfter=6),
    }
    return styles, custom

def severity_indicator(sev):
    dots = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
    n = dots.get(sev, 0)
    return "|" * n + "." * (3 - n)

def export_pdf(findings, chains, output, client_config=None, risk=None, env_stats=None, report_title=""):
    cfg = client_config or {}
    client_name = cfg.get("client_name", "Client")
    engagement = cfg.get("engagement_id", "")
    assessor = cfg.get("assessor", "Security Assessment Team")
    data_ver = cfg.get("data_version", "1.0")

    os.makedirs(os.path.dirname(output), exist_ok=True)

    doc = SimpleDocTemplate(output, pagesize=A4, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
    styles, cust = build_styles()
    story = []
    now = datetime.now().strftime("%B %d, %Y")

    active = [f for f in findings if f.get("has_evidence", False)]
    critical = sum(1 for f in active if f["severity"] == "CRITICAL")
    high = sum(1 for f in active if f["severity"] == "HIGH")
    medium = sum(1 for f in active if f["severity"] == "MEDIUM")
    low = sum(1 for f in active if f["severity"] == "LOW")
    total = len(active)

    has_ad = any(f.get("source") == "Active Directory" for f in findings)
    has_az = any(f.get("source") == "Azure" for f in findings)

    risk_score = min(risk.get("total_score", 0), 100) if risk else min((critical * 25) + (high * 10) + (medium * 5), 100)
    risk_label = "LOW"
    if risk_score >= 70: risk_label = "CRITICAL"
    elif risk_score >= 30: risk_label = "HIGH"
    elif risk_score >= 15: risk_label = "MEDIUM"
    risk_color = SEVERITY_COLORS.get(risk_label, colors.black)

    if env_stats is None:
        env_stats = compute_env_stats(findings, chains, risk)

    # â”€â”€â”€ COVER â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    story.append(Spacer(1, 80))
    # Logo on cover (optional custom branding)
    if LOGO_PATH and os.path.exists(LOGO_PATH):
        try:
            img = Image(LOGO_PATH, width=2*inch, height=1*inch)
            img.hAlign = "CENTER"
            story.append(img)
            story.append(Spacer(1, 20))
        except Exception:
            pass
    story.append(HRFlowable(width="60%", thickness=3, color=colors.HexColor("#1e3a5f"), spaceAfter=20))
    story.append(Paragraph(safe_escape(report_title or "Hybrid Identity Security Assessment Report"), cust["CoverTitle"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Prepared for: <b>{safe_escape(client_name)}</b>", cust["CoverSubtitle"]))
    story.append(Paragraph(f"Engagement: {safe_escape(engagement)}", cust["CoverSubtitle"]))
    story.append(Paragraph(f"Prepared by: {safe_escape(assessor)}", cust["CoverSubtitle"]))
    story.append(Paragraph(f"Date: {now}", cust["CoverSubtitle"]))
    story.append(Paragraph(f"Classification: Confidential", cust["CoverSubtitle"]))
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="60%", thickness=3, color=colors.HexColor("#1e3a5f"), spaceAfter=20))
    story.append(Spacer(1, 20))
    story.append(Paragraph("Overall Risk Rating:", ParagraphStyle("rl", parent=cust["BodyJ"], fontSize=11, alignment=TA_CENTER)))
    story.append(Paragraph(f"{risk_label}", ParagraphStyle("rv", parent=cust["CoverTitle"], fontSize=28, textColor=risk_color, alignment=TA_CENTER)))
    story.append(Paragraph(f"Risk Score: {risk_score}/100  |  Active Findings: {total}  |  Attack Chains: {len(chains)}", cust["CoverSubtitle"]))
    story.append(PageBreak())

    # â”€â”€â”€ EXECUTIVE DASHBOARD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    story.append(Paragraph("Executive Dashboard", cust["SectionH1"]))
    story.append(Spacer(1, 10))

    box_w = int((A4[0] - 100) / 4)
    kpi_items = [
        ("CRITICAL",       str(env_stats['critical_findings']),  colors.HexColor("#dc2626"), colors.HexColor("#fef2f2")),
        ("HIGH",           str(env_stats['high_findings']),      colors.HexColor("#ea580c"), colors.HexColor("#fff7ed")),
        ("ATTACK PATHS",   str(env_stats['attack_paths']),       colors.HexColor("#ca8a04"), colors.HexColor("#fefce8")),
        ("AFFECTED\nACCOUNTS", str(env_stats['affected_accounts']), colors.HexColor("#475569"), colors.HexColor("#f8fafc")),
    ]
    kpi_cells = []
    kpi_bgs = []
    for label, val, fg, bg in kpi_items:
        cell = Paragraph(
            f"<font size='7'><b>{label}</b></font><br/>"
            f"<font size='22'><b>{val}</b></font>",
            ParagraphStyle("kp", fontSize=7, leading=28, alignment=TA_CENTER, textColor=fg)
        )
        kpi_cells.append(cell)
        kpi_bgs.append(bg)
    kt = Table([kpi_cells], colWidths=[box_w]*4)
    kt.setStyle(TableStyle([
        ("BOX", (0,0),(-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0,0),(-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0,0),(-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0),(-1,-1), 8), ("BOTTOMPADDING", (0,0),(-1,-1), 8),
    ]))
    for i, bg in enumerate(kpi_bgs):
        kt.setStyle(TableStyle([("BACKGROUND", (i,0),(i,0), bg)]))
    story.append(kt)
    story.append(Spacer(1, 12))

    t0s = "YES" if env_stats.get("tier0_exposure", "NO") == "YES" else "NO"
    dss = "YES" if env_stats.get("dcsync_exposure", "NO") == "YES" else "NO"
    exp_data = [[Paragraph("<b>Exposure Indicator</b>", ParagraphStyle("exh", fontSize=9, alignment=TA_CENTER, textColor=colors.white)),
                  Paragraph("<b>Status</b>", ParagraphStyle("exh2", fontSize=9, alignment=TA_CENTER, textColor=colors.white))],
                [Paragraph(safe_escape("Tier-0 Exposure (Direct Path to Domain Admin)"), ParagraphStyle("exb", fontSize=9)),
                 Paragraph(t0s, ParagraphStyle("exb2", fontSize=9, alignment=TA_CENTER))],
                [Paragraph(safe_escape("DCSync Exposure (Credential Replication Rights)"), ParagraphStyle("exb3", fontSize=9)),
                 Paragraph(dss, ParagraphStyle("exb4", fontSize=9, alignment=TA_CENTER))]]
    exp_t = Table(exp_data, colWidths=[280, 120])
    exp_t.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,0), colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR", (0,0),(-1,0), colors.white),
        ("FONTNAME", (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0),(-1,-1), 9),
        ("GRID", (0,0),(-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0,1),(-1,-1), [colors.HexColor("#f8fafc"), colors.white]),
        ("VALIGN", (0,0),(-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0),(-1,-1), 5), ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ("ALIGN", (1,0),(1,-1), "CENTER"),
    ]))
    story.append(exp_t)
    story.append(Spacer(1, 10))

    story.append(Paragraph(
        f"Assessment identified <b>{env_stats['critical_findings']}</b> Critical and <b>{env_stats['high_findings']}</b> High risk findings "
        f"with <b>{env_stats['attack_paths']}</b> attack paths affecting <b>{env_stats['affected_accounts']}</b> accounts. "
        f"Overall Risk Score: <b>{risk_score}/100</b> ({risk_label}).",
        cust["BodyJ"]
    ))
    story.append(PageBreak())

    # â”€â”€â”€ TABLE OF CONTENTS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    story.append(Paragraph("Table of Contents", cust["SectionH1"]))
    story.append(Spacer(1, 12))
    toc_entries = [("1.","Executive Summary")]
    if has_ad:
        toc_entries.append(("2.","AD Environment Overview"))
    if has_az:
        toc_entries.append(("2a.","Azure / Entra ID Environment Overview"))
    toc_entries += [("3.","Scope & Methodology"), ("4.","Limitations & Reliance"),
                    ("5.","Risk Overview"), ("6.","Detailed Findings"),
                    ("7.","Attack Chain Analysis"), ("8.","Compliance Mapping"),
                    ("9.","Remediation Roadmap"), ("10.","Trend Comparison"), ("11.","Appendix")]
    for num, title in toc_entries:
        story.append(Paragraph(f"<b>{num}</b>&nbsp;&nbsp;{title}", cust["BodyJ"]))
        story.append(Spacer(1, 4))
    story.append(PageBreak())

    # â”€â”€â”€ 1. EXECUTIVE SUMMARY â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    story.append(Paragraph("1. Executive Summary", cust["SectionH1"]))
    story.append(Spacer(1, 6))
    scope_parts = []
    if has_ad:
        scope_parts.append("Active Directory")
    if has_az:
        scope_parts.append("Azure/Entra ID")
    scope_label = " & ".join(scope_parts) if scope_parts else "Hybrid Identity"
    impact_text_parts = []
    if has_ad:
        impact_text_parts.append("Active Directory domain compromise")
    if has_az:
        impact_text_parts.append("Azure/Entra ID tenant takeover")
    impact_text = ", ".join(impact_text_parts)
    if impact_text:
        impact_text += ", cloud privilege escalation, credential theft, and lateral movement across " + ("the hybrid environment" if has_ad and has_az else "the " + scope_label.lower() + " environment")
    else:
        impact_text = "privilege escalation, credential theft, and lateral movement across the environment"

    story.append(Paragraph(
        f"{safe_escape(assessor)} performed a {scope_label} security assessment for <b>{safe_escape(client_name)}</b> "
        f"(Engagement: {safe_escape(engagement)}). The assessment identified <b>{total}</b> active security findings "
        f"across <b>{len(chains)}</b> attack chains, with an overall risk rating of <b>{risk_label}</b> (Score: {risk_score}/100).",
        cust["BodyJ"]
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"Of the {total} active findings, <b>{critical}</b> Critical, <b>{high}</b> High, <b>{medium}</b> Medium, "
        f"and <b>{low}</b> Low were identified. These represent potential attack paths that could lead to "
        f"{impact_text}.",
        cust["BodyJ"]
    ))
    story.append(Spacer(1, 10))
    exec_table = Table(
        [["Metric", "Value"],["Client", client_name],["Engagement", engagement],["Data Version", data_ver],
         ["Total Findings (active)", str(total)],["Critical", str(critical)],["High", str(high)],
         ["Attack Chains", str(len(chains))],["Risk Score", f"{risk_score}/100"],["Overall Rating", risk_label]],
        colWidths=[200, 200]
    )
    exec_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,0), colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR", (0,0),(-1,0), colors.white),
        ("FONTNAME", (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0),(-1,-1), 9),
        ("GRID", (0,0),(-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0,1),(-1,-1), [colors.HexColor("#f8fafc"), colors.white]),
        ("ALIGN", (1,0),(1,-1), "CENTER"),
        ("VALIGN", (0,0),(-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0),(-1,-1), 6), ("BOTTOMPADDING", (0,0),(-1,-1), 6),
    ]))
    story.append(exec_table)
    story.append(PageBreak())

    # â”€â”€â”€ 2. AD ENVIRONMENT OVERVIEW â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if has_ad:
        story.append(Paragraph("2. AD Environment Overview", cust["SectionH1"]))
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            "Environment overview based on real object counts from the Neo4j graph database "
            "showing the total number of Active Directory objects discovered during assessment.",
            cust["BodyJ"]
        ))
        story.append(Spacer(1, 8))

        # â”€â”€â”€ Global AD Environment Overview â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        env_data = [["Metric", "Value"],
                    ["Users (Affected)", f"{env_stats['total_users']}"],
                    ["Computers", f"{env_stats['total_computers']}"],
                    ["Servers", f"{env_stats['servers']}"],
                    ["Domain Controllers", f"{env_stats['domain_controllers']}"],
                    ["Groups", f"{env_stats['total_groups']}"],
                    ["Tier-0 Accounts", f"{env_stats['tier0_accounts']}"],
                    ["Service Accounts", f"{env_stats['service_accounts']}"],
                    ["Trust Relationships", f"{env_stats['trusts']}"]]
        env_table = Table(env_data, colWidths=[200, 200])
        env_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,0), colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR", (0,0),(-1,0), colors.white),
            ("FONTNAME", (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0),(-1,-1), 9),
            ("GRID", (0,0),(-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0,1),(-1,-1), [colors.HexColor("#f8fafc"), colors.white]),
            ("ALIGN", (1,0),(1,-1), "CENTER"),
            ("VALIGN", (0,0),(-1,-1), "MIDDLE"),
            ("TOPPADDING", (0,0),(-1,-1), 5), ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ]))
        story.append(env_table)
        story.append(Spacer(1, 10))

        # â”€â”€â”€ Per-forest breakdown (supplementary) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        forests = env_stats.get("forests", [])
        if forests:
            story.append(Paragraph("<b>Environment Breakdown by Forest</b>", cust["SectionH2"]))
            story.append(Spacer(1, 4))

            forest_metrics_order = [
                ("users", "Users (Affected)"),
                ("computers", "Computers"),
                ("servers", "Servers"),
                ("domain_controllers", "Domain Controllers"),
                ("groups", "Groups"),
                ("tier0_accounts", "Tier-0 Accounts"),
                ("service_accounts", "Service Accounts"),
                ("trusts", "Trust Relationships"),
            ]

            white_style = ParagraphStyle("white_hdr", parent=cust["BodyJ"], textColor=colors.black, fontSize=8, leading=10)

            # Group forests into pairs (2 per row)
            pairs = [forests[i:i+2] for i in range(0, len(forests), 2)]
            for pair_idx, pair in enumerate(pairs):
                n_in_pair = len(pair)
                col_widths = [90, 40] * n_in_pair

                hdr = []
                for fb in pair:
                    hdr.append(Paragraph(f"<b>Forest: {fb['name']}</b>", white_style))
                    hdr.append(Paragraph("", cust["BodyJ"]))
                if hdr:
                    hdr.pop()

                sub = []
                for fb in pair:
                    sub.append(Paragraph("Metric", white_style))
                    sub.append(Paragraph("Value", white_style))
                if sub:
                    sub.pop()
                    sub.append(Paragraph("Value", white_style))

                table_data = [hdr, sub]

                for meta_key, meta_label in forest_metrics_order:
                    row = []
                    for fb in pair:
                        val = fb.get("metrics", {}).get(meta_key, 0)
                        row.append(Paragraph(meta_label, cust["BodySmall"]))
                        row.append(Paragraph(str(val), cust["BodySmall"]))
                    if row:
                        row.pop()
                        row.append(Paragraph(str(pair[-1].get("metrics", {}).get(meta_key, 0)), cust["BodySmall"]))
                    table_data.append(row)

                ft = Table(table_data, colWidths=col_widths)
                ft.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#cbd5e1")),
                    ("FONTNAME", (0, 0), (-1, 1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("LEADING", (0, 0), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                    ("ROWBACKGROUNDS", (0, 2), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
                    ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ]))
                story.append(ft)
                if pair_idx < len(pairs) - 1:
                    story.append(Spacer(1, 12))

            story.append(Spacer(1, 4))
            story.append(Paragraph(
                "<i>Per-forest counts are scoped to objects whose SID prefix matches each domain. "
                "Built-in groups (e.g., Everyone, Authenticated Users), well-known SIDs, and cross-domain objects "
                "are included only in the global AD totals above, which may be higher than the sum of per-forest counts.</i>",
                cust["Disclaimer"]
            ))

        story.append(Spacer(1, 6))

        # Cross-forest trust details from findings if available
        for f in findings:
            if f.get("id") == "CROSS_FOREST" and f.get("has_evidence", False):
                rels = f.get("ad_objects", {}).get("relationships", [])
                if rels:
                    story.append(Paragraph("<b>Cross-Forest Trust Details:</b>", cust["BodyJ"]))
                    for r in rels:
                        story.append(Paragraph(f"&bull; {r}", cust["BodyJ"]))
                    story.append(Spacer(1, 4))
                break

        story.append(Paragraph(
            "<i>Note: Multi-domain and cross-forest environments are fully supported. "
            "Findings span all discovered domains and trusts. Findings below indicate which domain(s) they affect.</i>",
            cust["Disclaimer"]
        ))
        story.append(PageBreak())

    # â”€â”€â”€ Azure / Entra ID Environment Overview â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if has_az:
        az_tenants = env_stats.get("azure_tenants", [])
        story.append(Paragraph("2a. Azure / Entra ID Environment Overview", cust["SectionH1"]))
        story.append(Spacer(1, 6))
        if az_tenants:
            story.append(Paragraph(
                "Azure and Entra ID environment overview based on AzureHound data loaded into BloodHound CE. "
                "The following counts reflect total objects discovered across all Azure tenants.",
                cust["BodyJ"]
            ))
            story.append(Spacer(1, 8))

            az_env_data = [["Metric", "Value"],
                ["Tenants", f"{len(az_tenants)}"],
                ["Entra ID Users", f"{env_stats.get('azure_users', 0)}"],
                ["Entra ID Groups", f"{env_stats.get('azure_groups', 0)}"],
                ["Service Principals", f"{env_stats.get('azure_service_principals', 0)}"],
                ["Managed Identities", f"{env_stats.get('azure_managed_identities', 0)}"],
                ["Applications", f"{env_stats.get('azure_applications', 0)}"],
                ["Key Vaults", f"{env_stats.get('azure_key_vaults', 0)}"],
                ["Virtual Machines", f"{env_stats.get('azure_vms', 0)}"],
                ["Subscriptions", f"{env_stats.get('azure_subscriptions', 0)}"],
            ]
            az_env_table = Table(az_env_data, colWidths=[200, 200])
            az_env_table.setStyle(TableStyle([
                ("BACKGROUND", (0,0),(-1,0), colors.HexColor("#1e3a5f")),
                ("TEXTCOLOR", (0,0),(-1,0), colors.white),
                ("FONTNAME", (0,0),(-1,0), "Helvetica-Bold"),
                ("FONTSIZE", (0,0),(-1,-1), 9),
                ("GRID", (0,0),(-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0,1),(-1,-1), [colors.HexColor("#f8fafc"), colors.white]),
                ("ALIGN", (1,0),(1,-1), "CENTER"),
                ("VALIGN", (0,0),(-1,-1), "MIDDLE"),
                ("TOPPADDING", (0,0),(-1,-1), 5), ("BOTTOMPADDING", (0,0),(-1,-1), 5),
            ]))
            story.append(az_env_table)
            story.append(Spacer(1, 10))

            # Per-tenant breakdown
            az_tenants_detail = env_stats.get("azure_tenants_detail", [])
            if az_tenants_detail:
                story.append(Paragraph("<b>Environment Breakdown by Tenant</b>", cust["SectionH2"]))
                story.append(Spacer(1, 4))

                az_tenant_metrics_order = [
                    ("users", "Entra ID Users"),
                    ("groups", "Groups"),
                    ("service_principals", "Service Principals"),
                    ("managed_identities", "Managed Identities"),
                    ("applications", "Applications"),
                    ("global_admins", "Global Admins"),
                ]

                white_style = ParagraphStyle("white_hdr", parent=cust["BodyJ"], textColor=colors.black, fontSize=8, leading=10)
                az_pairs = [az_tenants_detail[i:i+2] for i in range(0, len(az_tenants_detail), 2)]
                for pair_idx, pair in enumerate(az_pairs):
                    n_in_pair = len(pair)
                    col_widths = [110, 40] * n_in_pair

                    hdr = []
                    for tb in pair:
                        hdr.append(Paragraph(f"<b>Tenant: {tb['name']}</b>", white_style))
                        hdr.append(Paragraph("", cust["BodyJ"]))
                    if hdr:
                        hdr.pop()

                    sub = []
                    for tb in pair:
                        sub.append(Paragraph("Metric", white_style))
                        sub.append(Paragraph("Value", white_style))
                    if sub:
                        sub.pop()
                        sub.append(Paragraph("Value", white_style))

                    table_data = [hdr, sub]

                    for meta_key, meta_label in az_tenant_metrics_order:
                        row = []
                        for tb in pair:
                            val = tb.get("metrics", {}).get(meta_key, 0)
                            row.append(Paragraph(meta_label, cust["BodySmall"]))
                            row.append(Paragraph(str(val), cust["BodySmall"]))
                        if row:
                            row.pop()
                            row.append(Paragraph(str(pair[-1].get("metrics", {}).get(meta_key, 0)), cust["BodySmall"]))
                        table_data.append(row)

                    az_ft = Table(table_data, colWidths=col_widths)
                    az_ft.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#cbd5e1")),
                        ("FONTNAME", (0, 0), (-1, 1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                        ("LEADING", (0, 0), (-1, -1), 10),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                        ("ROWBACKGROUNDS", (0, 2), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
                        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("LEFTPADDING", (0, 0), (-1, -1), 4),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ]))
                    story.append(az_ft)
                    if pair_idx < len(az_pairs) - 1:
                        story.append(Spacer(1, 12))

            story.append(Spacer(1, 6))

        else:
            story.append(Paragraph("No Azure/Entra ID data detected. [NO DATA]", cust["BodyJ"]))
            story.append(Spacer(1, 6))

        story.append(PageBreak())

    # â”€â”€â”€ 3. SCOPE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    story.append(Paragraph("3. Assessment Scope &amp; Methodology", cust["SectionH1"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"<b>Client:</b> {safe_escape(client_name)}", cust["SectionH2"]))
    story.append(Paragraph(f"<b>Engagement:</b> {safe_escape(engagement)}", cust["SectionH2"]))
    scope_env_parts = []
    if has_ad:
        scope_env_parts.append("Active Directory")
    if has_az:
        scope_env_parts.append("Azure/Entra ID")
    scope_env_text = " and ".join(scope_env_parts) if scope_env_parts else "Active Directory and Azure/Entra ID"
    story.append(Paragraph(
        f"The assessment covers the {scope_env_text} environment using BloodHound SharpHound & AzureHound data and Neo4j graph "
        "analysis. Findings are aligned with MITRE ATT&amp;CK and mapped to NIST CSF 2.0, CIS Controls v8.1, ISO/IEC 27001:2022, SA 315 (ICAI), and DPDP Act 2023.",
        cust["BodyJ"]
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph("<b>Frameworks Referenced</b>", cust["SectionH2"]))
    for fw in ["MITRE ATT&CK v14", "NIST CSF 2.0", "CIS Controls v8.1",
               "ISO/IEC 27001:2022", "SA 315 (ICAI)", "DPDP Act 2023"]:
        story.append(Paragraph(f"&bull;  {fw}", cust["BodyJ"]))
    story.append(PageBreak())

    # â”€â”€â”€ 4. LIMITATIONS & RELIANCE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    story.append(Paragraph("4. Limitations &amp; Reliance", cust["SectionH1"]))
    story.append(Spacer(1, 6))

    data_src = cfg.get("data_source_type", "Neo4j Graph Database (live)")
    sh_sha256 = cfg.get("sharphound_sha256", None)
    sh_method = cfg.get("sharphound_collection_method", None)
    sh_ts = cfg.get("sharphound_timestamp", None)
    ah_sha256 = cfg.get("azurehound_sha256", None)
    ah_method = cfg.get("azurehound_collection_method", None)
    ah_ts = cfg.get("azurehound_timestamp", None)

    story.append(Paragraph("<b>Data Source</b>", cust["SectionH2"]))
    story.append(Paragraph(f"Data Source: {safe_escape(data_src)}", cust["BodyJ"]))

    if has_ad:
        story.append(Paragraph("<b>SharpHound (Active Directory)</b>", cust["SectionH3"]))
        if sh_sha256:
            story.append(Paragraph(f"SHA-256: <code>{safe_escape(sh_sha256)}</code>", cust["Code"]))
        else:
            story.append(Paragraph("SHA-256: Not applicable (data loaded via Neo4j, not direct file)", cust["BodySmall"]))
        if sh_method:
            story.append(Paragraph(f"Collection Method: {safe_escape(sh_method.replace('+', ' + '))}", cust["BodyJ"]))
        else:
            story.append(Paragraph("Collection Method: Inferred from Neo4j graph â€” see collected query types below", cust["BodySmall"]))
        story.append(Paragraph(f"Collection Timestamp: {safe_escape(sh_ts if sh_ts else 'Not available')}", cust["BodyJ"]))

    if has_az:
        story.append(Paragraph("<b>AzureHound (Azure / Entra ID)</b>", cust["SectionH3"]))
        if ah_sha256:
            story.append(Paragraph(f"SHA-256: <code>{safe_escape(ah_sha256)}</code>", cust["Code"]))
        else:
            story.append(Paragraph("SHA-256: Not applicable (data loaded via Neo4j, not direct file)", cust["BodySmall"]))
        if ah_method:
            story.append(Paragraph(f"Collection Method: {safe_escape(ah_method.replace('+', ' + '))}", cust["BodyJ"]))
        else:
            story.append(Paragraph("Collection Method: Inferred from Neo4j graph â€” see collected query types below", cust["BodySmall"]))
        story.append(Paragraph(f"Collection Timestamp: {safe_escape(ah_ts if ah_ts else 'Not available')}", cust["BodyJ"]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("<b>Reliance on Client-Provided BloodHound CE Ingestion Data</b>", cust["SectionH2"]))
    data_srcs = []
    if has_ad:
        data_srcs.append("SharpHound (.zip/JSON)")
    if has_az:
        data_srcs.append("AzureHound (.zip/JSON)")
    data_src_text = " and ".join(data_srcs) if data_srcs else "SharpHound (.zip/JSON) and AzureHound (.zip/JSON)"
    story.append(Paragraph(
        f"The findings, graph calculations, and attack-path visualizations outlined in this report are "
        f"strictly dependent on the static {data_src_text} data packages "
        "provided directly by the Client's IT personnel. The Consultant did not control, verify, or execute "
        "the underlying data collection binaries within the production environment.",
        cust["BodyJ"]
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Tool Logic &amp; Data Authenticity Limits</b>", cust["SectionH2"]))
    story.append(Paragraph(
        "The Consultant operates under the absolute assumption that the source ingestor scripts were "
        "executed comprehensively (e.g., using complete Collection Method scopes) and with unhindered "
        "read privileges across all domain controllers, forests, and cloud tenants. The Consultant accepts "
        "no liability for hidden privilege escalation paths or structural directory backdoors that went "
        "unresolved or undetected due to corrupt, truncated, out-of-date, or intentionally filtered output "
        "datasets provided by the client.",
        cust["BodyJ"]
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "The BloodHound tool suite (SharpHound, AzureHound, and the BloodHound Community Edition graph engine) "
        "performs a static, query-based analysis of Active Directory and Azure/Entra ID relationships. It does "
        "not execute exploit code, validate whether a detected path is actively weaponisable, or account for "
        "runtime defences such as endpoint detection, network segmentation, or real-time authentication policies. "
        "Findings represent theoretical attack paths identified by the tool's query language and are subject to "
        "the completeness of the collected data. The Consultant disclaims any liability for attack paths that "
        "BloodHound failed to enumerate due to tool version limitations, unsupported collection methods, or "
        "language/region configuration differences.",
        cust["BodyJ"]
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Point-in-Time Assessment</b>", cust["SectionH2"]))
    story.append(Paragraph(
        "The findings, risk scores, and attack-path analysis presented in this report reflect the state of "
        "the Active Directory and Azure/Entra ID environment as captured by the SharpHound and AzureHound "
        "data snapshots at the specific dates and times indicated under Data Source above. Active Directory "
        "and cloud identity environments are inherently dynamic: user memberships change, group scopes are "
        "modified, new applications are registered, and privileged access is granted or revoked continuously. "
        "This assessment does not constitute a forward-looking guarantee of the security posture at any future "
        "date. It is solely a record of the assessed configuration at the point of data collection.",
        cust["BodyJ"]
    ))
    story.append(PageBreak())

    story.append(Paragraph("<b>Not a Penetration Test</b>", cust["SectionH2"]))
    story.append(Paragraph(
        "This engagement is a static graph-based identity security review, not a penetration test. No active "
        "exploitation, credential compromise, social engineering, denial-of-service, or other adversarial "
        "simulation techniques were employed. The assessment relies entirely on pre-collected BloodHound graph "
        "data and does not include live scanning, authenticated probing, or runtime validation of identified "
        "attack paths. Findings should be validated through manual testing or complementary security assessments "
        "before being used as the sole basis for remediation decisions.",
        cust["BodyJ"]
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>No Guarantee of Total Immunity</b>", cust["SectionH2"]))
    story.append(Paragraph(
        "Remediation of all findings identified in this report does not guarantee that the Client's identity "
        "infrastructure is free from all security vulnerabilities, misconfigurations, or attack paths. This "
        "assessment is limited to the relationships and objects captured within the provided BloodHound graph "
        "data. Other vectorsâ€”including but not limited to application-layer vulnerabilities, network-level "
        "exposures, endpoint security gaps, and social engineeringâ€”remain outside the scope of this review "
        "and must be addressed through separate assessments as deemed appropriate by the Client.",
        cust["BodyJ"]
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Limitation of Liability</b>", cust["SectionH2"]))
    story.append(Paragraph(
        "UNDER NO CIRCUMSTANCES SHALL THE CONSULTANT BE LIABLE TO ANY ENTITY WHOMSOEVER FOR ANY DAMAGES, "
        "CLAIMS, LOSSES, OR EXPENSES ARISING OUT OF OR RELATED TO THIS REPORT, THE DATA COLLECTION "
        "METHODOLOGY, THE ACCURACY OR COMPLETENESS OF FINDINGS, OR ANY ACTIONS TAKEN OR OMITTED BASED ON "
        "THIS REPORT, WHETHER IN CONTRACT, TORT (INCLUDING NEGLIGENCE), OR OTHERWISE. ANY ENGAGING ENTITY "
        "ASSUMES ALL RISK AND RESPONSIBILITY FOR ANY DECISIONS MADE BASED ON THIS REPORT. IN NO EVENT "
        "SHALL THE CONSULTANT'S AGGREGATE LIABILITY EXCEED THE TOTAL FEES PAID TO THE CONSULTANT FOR "
        "THIS ENGAGEMENT.",
        cust["BodyJ"]
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>No Warranty / &ldquo;As-Is&rdquo; Disclaimer</b>", cust["SectionH2"]))
    story.append(Paragraph(
        "THIS REPORT AND ALL FINDINGS, DATA, AND RECOMMENDATIONS CONTAINED HEREIN ARE PROVIDED &ldquo;AS "
        "IS&rdquo; AND &ldquo;AS AVAILABLE&rdquo; WITHOUT ANY WARRANTY WHATSOEVER, EXPRESS OR IMPLIED, "
        "INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, "
        "ACCURACY, COMPLETENESS, OR NON-INFRINGEMENT. THE CONSULTANT DOES NOT WARRANT THAT REMEDIATION "
        "OF IDENTIFIED FINDINGS WILL PREVENT SECURITY INCIDENTS, UNAUTHORIZED ACCESS, OR DATA BREACHES. "
        "THE ENGAGING ENTITY(S) ACKNOWLEDGE THAT THEY HAVE NOT RELIED UPON ANY REPRESENTATION OR WARRANTY "
        "MADE BY THE CONSULTANT EXCEPT AS EXPRESSLY SET FORTH HEREIN.",
        cust["BodyJ"]
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Report Use Restriction</b>", cust["SectionH2"]))
    story.append(Paragraph(
        "This report is prepared exclusively for the named engaging entity/entities listed on the "
        "cover page. No other person or entity is entitled to rely on this report for any purpose whatsoever. "
        "This report shall not be reproduced, distributed, or disclosed to any third party without the prior "
        "written consent of the Consultant. Any unauthorized use, reliance, or distribution by any third party "
        "shall be at such party's sole risk, and the Consultant disclaims all liability arising therefrom.",
        cust["BodyJ"]
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Explicit Treatment of [NO DATA] Markers</b>", cust["SectionH2"]))
    story.append(Paragraph(
        "Metrics or finding groups marked as [NO DATA] explicitly reflect zero data entries present inside "
        "the client's provided JSON blobs. This signifier does not mean a security risk is absent from the "
        "infrastructure. Instead, it indicates data collection limitations, such as restricted Active "
        "Directory permissions, disabled domain logging, endpoint security filtering (e.g., EDR blocks during "
        "SharpHound execution), or missing cloud API configurations. Remediation of data collection gaps "
        "remains the exclusive responsibility of the Client.",
        cust["BodyJ"]
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Exclusions by Finding Type</b>", cust["SectionH2"]))
    story.append(Paragraph(
        "Each finding type excludes certain built-in accounts, groups, or objects by design. "
        "Refer to Section 11 (Appendix - Exclusions by Finding) for the complete reference.",
        cust["BodyJ"]
    ))
    story.append(PageBreak())

    # â”€â”€â”€ 5. RISK OVERVIEW â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    story.append(Paragraph("5. Risk Overview", cust["SectionH1"]))
    pie_data = [["Severity","Count","Weighted Score"],
                ["CRITICAL",str(critical),str(critical*10)],
                ["HIGH",str(high),str(high*5)],
                ["MEDIUM",str(medium),str(medium*3)],
                ["LOW",str(low),str(low*1)]]
    pie_table = Table(pie_data, colWidths=[120,100,120])
    pie_table.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0), colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR",(0,0),(-1,0), colors.white),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),9),
        ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#f8fafc"),colors.white]),
        ("ALIGN",(1,0),(2,-1),"CENTER"),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
    ]))
    story.append(pie_table)
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Composite Risk Score:</b> {risk_score}/100", cust["SectionH2"]))
    story.append(Paragraph(f"Score {risk_score}/100 based on severity-weighted counts. Above 70 = Critical.", cust["BodyJ"]))
    story.append(PageBreak())

    # â”€â”€â”€ 6. DETAILED FINDINGS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    story.append(Paragraph("6. Detailed Security Findings", cust["SectionH1"]))
    ad_n = 0
    az_n = 0
    last_group = None
    for f in findings:
        group_key = f.get("group")
        if group_key and group_key != last_group:
            group_name = GROUPS.get(group_key, {}).get("name", group_key)
            story.append(Paragraph(f"&mdash; {safe_escape(group_name)} &mdash;",
                ParagraphStyle("GroupHeader", parent=cust["SectionH2"], fontSize=12, textColor=colors.HexColor("#1e3a5f"),
                               alignment=TA_CENTER, spaceBefore=16, spaceAfter=8, backColor=colors.HexColor("#f1f5f9"))))
            last_group = group_key
        sev = f.get("severity","LOW")
        raw_t = f.get("title","")
        display_t = raw_t.split("|")[-1].strip().upper().replace("_"," ")
        if f.get("source") == "Azure":
            az_n += 1
            fid = f"AZ-{az_n:03d}"
        else:
            ad_n += 1
            fid = f"AD-{ad_n:03d}"
        has_ev = f.get("has_evidence", False)
        
        label = f"{severity_indicator(sev)}  {fid} | {sev} | {safe_escape(display_t)}"
        if not has_ev:
            label += " [NO DATA]"
        
        sev_style = ParagraphStyle(f"s_{fid}", parent=cust["SectionH2"], textColor=SEVERITY_COLORS.get(sev,colors.black), spaceBefore=8, keepWithNext=True)
        story.append(Paragraph(label, sev_style))
        mitre = f.get("mitre",{}) or {}
        confidence = f.get("confidence", "No Data")
        g_key = f.get("group", "")
        group_name = GROUPS.get(g_key, {}).get("name", g_key) if g_key else ""
        d = [["Attribute","Value"],["Finding ID",fid],["Severity",sev],["Confidence",confidence],
             ["Source",f.get("source","")],
             ["Group", safe_escape(group_name)],
             ["MITRE ID",mitre.get("id","-")],["MITRE Technique",mitre.get("technique","-")],["MITRE Tactic",mitre.get("tactic","-")]]
        domains = f.get("ad_objects", {}).get("domains", [])
        if domains:
            d.append(["Domains/Trusts", ", ".join(domains)])
        # Azure-specific object rendering
        azure_cats = [
            ("service_principals", "Service Principals"),
            ("managed_identities", "Managed Identities"),
            ("applications", "Applications"),
            ("key_vaults", "Key Vaults"),
            ("tenants", "Tenants"),
        ]
        for key, label in azure_cats:
            items = f.get("ad_objects", {}).get(key, [])
            if items:
                display = ", ".join(items[:5])
                if len(items) > 5:
                    display += f" (+{len(items)-5} more)"
                d.append([label, display])
        if not has_ev:
            d.append(["Status", "NO DATA - No evidence collected for this finding type"])
        dt = Table(d, colWidths=[120, 330])
        dt.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#f1f5f9")),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"), ("FONTSIZE",(0,0),(-1,-1),8.5),
            ("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#e2e8f0")),
            ("VALIGN",(0,0),(-1,-1),"TOP"), ("TOPPADDING",(0,0),(-1,-1),3), ("BOTTOMPADDING",(0,0),(-1,-1),3),
        ]))
        story.append(dt)
        story.append(Spacer(1,4))
        story.append(Paragraph("<b>Business Impact</b>", cust["SectionH3"]))
        if has_ev:
            story.append(Paragraph(safe_escape(f.get("impact","No impact info.")), cust["BodyJ"]))
        else:
            story.append(Paragraph("No evidence available for this finding type. Impact cannot be assessed without data.", cust["BodyJ"]))
        rem = f.get("remediation",[])
        if rem:
            story.append(Paragraph("<b>Remediation</b>", cust["SectionH3"]))
            for r in rem:
                story.append(Paragraph(f"&bull;  {safe_escape(r)}", cust["BodyJ"]))
        det = f.get("detection",[])
        if det:
            story.append(Paragraph("<b>Detection</b>", cust["SectionH3"]))
            for d in det:
                story.append(Paragraph(f"&bull;  {safe_escape(d)}", cust["BodyJ"]))
        comp = COMPLIANCE_MAP.get(f.get("id",""), {})
        if comp:
            story.append(Paragraph("<b>Compliance</b>", cust["SectionH3"]))
            story.append(Paragraph(safe_escape(" | ".join([f"{k}: {v}" for k,v in comp.items()])), cust["BodyJ"]))
        story.append(Spacer(1, 12))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceAfter=6))
    story.append(PageBreak())

    # â”€â”€â”€ 7. ATTACK CHAINS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    story.append(Paragraph("7. Attack Chain Analysis", cust["SectionH1"]))
    if chains:
        cd = [[Paragraph("<b>#</b>",cust["BodySmall"]),Paragraph("<b>Risk</b>",cust["BodySmall"]),
               Paragraph("<b>Severity</b>",cust["BodySmall"]),Paragraph("<b>Attack Path</b>",cust["BodySmall"])]]
        for idx, c in enumerate(chains, 1):
            ap = c.get("attack_path","")
            ap_nodes = ap.split(" -> ")
            if len(ap_nodes) > 12:
                ap = " -> ".join(ap_nodes[:12]) + " -> ..."
            cd.append([Paragraph(str(idx),cust["BodySmall"]),
                       Paragraph(safe_escape(c.get("risk","")),cust["BodySmall"]),
                       Paragraph(safe_escape(c.get("severity","")),cust["BodySmall"]),
                       Paragraph(safe_escape(ap),cust["BodySmall"])])
        ct = Table(cd, colWidths=[25,100,55,315])
        ct.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#f8fafc"),colors.white]),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
            ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
            ("ALIGN",(0,0),(0,-1),"CENTER"),
        ]))
        story.append(ct)
        story.append(Spacer(1, 4))
        for idx, c in enumerate(chains, 1):
            chain_objs = c.get("ad_objects", {})
            chain_parts = []
            for k, label in [("users", "Users"), ("groups", "Groups"), ("service_principals", "Service Principals"),
                             ("managed_identities", "Managed Identities"), ("applications", "Applications"),
                             ("tenants", "Tenants")]:
                items = chain_objs.get(k, [])
                if items:
                    display = ", ".join(items[:4])
                    if len(items) > 4:
                        display += f" (+{len(items)-4} more)"
                    chain_parts.append(f"{label}: {display}")
            if chain_parts:
                story.append(Paragraph(
                    f"<b>Chain {idx} Assets:</b> {'; '.join(chain_parts)}",
                    cust["BodySmall"]
                ))
    else:
        story.append(Paragraph("No attack chains identified.", cust["BodyJ"]))
    story.append(PageBreak())

    # â”€â”€â”€ 8. COMPLIANCE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    story.append(Paragraph("8. Compliance Mapping", cust["SectionH1"]))
    story.append(Paragraph("Each finding mapped to CIS Controls v8.1, NIST CSF 2.0, ISO/IEC 27001:2022, SA 315 (ICAI), and DPDP Act 2023.", cust["BodyJ"]))
    cr = [[Paragraph("<b>Control</b>",cust["BodySmall"]),Paragraph("<b>CIS Controls v8.1</b>",cust["BodySmall"]),
           Paragraph("<b>NIST CSF 2.0</b>",cust["BodySmall"]),Paragraph("<b>ISO/IEC 27001:2022</b>",cust["BodySmall"]),
           Paragraph("<b>SA 315 (ICAI)</b>",cust["BodySmall"]),Paragraph("<b>DPDP Act 2023</b>",cust["BodySmall"])]]
    _active_ids = {f["id"] for f in findings if f.get("id")}
    for fid, m in COMPLIANCE_MAP.items():
        if fid not in _active_ids:
            continue
        cr.append([Paragraph(safe_escape(fid.replace("_"," ").title()),cust["BodySmall"]),
                   Paragraph(m.get("CIS","-"),cust["BodySmall"]),
                   Paragraph(m.get("NIST","-"),cust["BodySmall"]),
                   Paragraph(m.get("ISO 27001","-"),cust["BodySmall"]),
                   Paragraph(m.get("SA 315","-"),cust["BodySmall"]),
                   Paragraph(m.get("DPDP","-"),cust["BodySmall"])])
    ctable = Table(cr, colWidths=[110,55,65,65,50,50])
    ctable.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"), ("FONTSIZE",(0,0),(-1,-1),8),
        ("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#f8fafc"),colors.white]),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
        ("ALIGN",(1,0),(-1,-1),"CENTER"),
    ]))
    story.append(ctable)
    story.append(PageBreak())

    # â”€â”€â”€ 9. REMEDIATION ROADMAP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    story.append(Paragraph("9. Remediation Roadmap", cust["SectionH1"]))
    story.append(Paragraph("30-day remediation plans prioritized by severity, organized per assessment scope.", cust["BodyJ"]))
    story.append(Spacer(1, 6))

    ROADMAPS = {
        "ad_core": [
            ["Week","Focus","Actions"],
            ["Week 1","Critical","Remediate Tier-0 attack paths and DCSync rights; remove excess privileged group memberships; reset compromised credentials"],
            ["Week 2","High","Disable unconstrained delegation; enable Kerberos pre-authentication; review constrained delegation and RBCD configurations"],
            ["Week 3","Medium","Review GPO permissions; audit object ACLs; implement LAPS; review trust relationships and SID history"],
            ["Week 4","Monitor","Deploy detection rules; schedule recurring BloodHound scans; document exceptions and risk acceptances"],
        ],
        "ad_attack": [
            ["Week","Focus","Actions"],
            ["Week 1","Critical","Patch certificate templates vulnerable to ESC1/ESC3; remove dangerous object ACLs; disable NTLM relay paths"],
            ["Week 2","High","Address shadow credentials; remediate SQL linked server abuse paths; audit domain trust escalation vectors"],
            ["Week 3","Medium","Implement LAPS where missing; review constrained delegation configurations; validate certificate authority security"],
            ["Week 4","Monitor","Deploy NTLM relay detection rules; schedule recurring attack path validation; document risk acceptances"],
        ],
        "az_core": [
            ["Week","Focus","Actions"],
            ["Week 1","Critical","Review Global Administrator and Privileged Role Administrator assignments; enable Privileged Identity Management (PIM); audit external/guest user access"],
            ["Week 2","High","Review service principal permissions; remediate contributor/owner role sprawl; audit key vault configurations; review hybrid identity admin assignments"],
            ["Week 3","Medium","Audit add-secret and add-owner permissions; review group membership management; execute command and reset password capabilities; review custom roles"],
            ["Week 4","Monitor","Review Application Admin and Cloud App Admin roles; deploy automation for role review reminders; document approved exceptions"],
        ],
        "az_zt_review": [
            ["Week","Focus","Actions"],
            ["Week 1","Critical","Enforce MFA for all users via Conditional Access; review and close CA policy gaps; audit PIM activation settings and approval workflows"],
            ["Week 2","High","Review service principal permissions and consent grants; audit cross-tenant access settings; enable legacy authentication blocking"],
            ["Week 3","Medium","Enable Entra ID password protection; configure authentication methods policy (phishing-resistant MFA); implement identity governance reviews"],
            ["Week 4","Monitor","Configure Entra ID diagnostic logging to SIEM; review custom RBAC roles; schedule recurring Zero Trust audits"],
        ],
        "az_arch_sim": [
            ["Week","Focus","Actions"],
            ["Week 1","Critical","Remediate Graph API token abuse paths; review sync account compromise vectors; audit PRT token theft scenarios"],
            ["Week 2","High","Review and harden Conditional Access bypass paths; audit cross-tenant authentication chains; address device join abuse scenarios"],
            ["Week 3","Medium","Review managed identity token theft risks; audit function key permissions; review PAG (Privileged Access Group) escalation paths"],
            ["Week 4","Monitor","Deploy monitoring for token abuse patterns; schedule recurring architecture simulation reviews; document residual risks"],
        ],
        "nhi_governance": [
            ["Week","Focus","Actions"],
            ["Week 1","Critical","Assign owners to all unowned service principals and app registrations; rotate credentials on over-consented and orphaned apps; remediate privileged SPs with broad Graph permissions; split combined directory+ARM privileged SPs"],
            ["Week 2","High","Enable workload identity Conditional Access for privileged service principals; move permanent privileged SP roles to PIM-eligible; remove unused tenant-wide Graph scopes; remove roles from disabled SPs before decommission"],
            ["Week 3","Medium","Transition user-assigned managed identities to system-assigned (or justify); add dual-owner and owner-attestation workflows; enforce credential expiry via app management policies; review group-owned SP accountability"],
            ["Week 4","Monitor","Review stale/uncollected SPs, managed identities, and devices for decommissioning; schedule quarterly NHI access reviews; deploy detection for SP credential, consent, and owner changes; document legacy/unknown SP types"],
        ],
    }

    selected_groups = sorted({f.get("group") for f in findings if f.get("group")},
                             key=lambda g: list(GROUPS.keys()).index(g) if g in GROUPS else 99)
    for g in selected_groups:
        rm = ROADMAPS.get(g)
        if not rm:
            continue
        gname = GROUPS.get(g, {}).get("name", g)
        story.append(Paragraph(f"<b>{safe_escape(gname)}</b>", cust["SectionH2"]))
        rt = Table(rm, colWidths=[55,100,340])
        rt.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"), ("FONTSIZE",(0,0),(-1,-1),8),
            ("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#f8fafc"),colors.white]),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
            ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
        ]))
        story.append(rt)
        story.append(Spacer(1, 10))
    story.append(Spacer(1,6))
    story.append(Paragraph("<i>Adapt based on organizational risk tolerance. Some actions may require change windows.</i>", cust["Disclaimer"]))
    story.append(PageBreak())

    # â”€â”€â”€ 10. TREND COMPARISON â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    story.append(Paragraph("10. Trend Comparison (Current vs Previous)", cust["SectionH1"]))
    story.append(Spacer(1, 6))
    
    # Compute current assessment scope from findings
    current_groups = sorted({f.get("group") for f in findings if f.get("group")},
                            key=lambda g: list(GROUPS.keys()).index(g) if g in GROUPS else 99)
    current_scope_names = [GROUPS[g]["name"] for g in current_groups if g in GROUPS]
    current_scope_label = "; ".join(current_scope_names) if current_scope_names else "N/A"
    
    prev_stats = _load_previous_stats(client_name, data_ver)
    if prev_stats:
        prev_scope = prev_stats.get("scope", {})
        prev_groups = prev_scope.get("groups", [])
        prev_scope_names = [GROUPS[g]["name"] for g in prev_groups if g in GROUPS]
        prev_scope_label = "; ".join(prev_scope_names) if prev_scope_names else "N/A"
        
        same_scope = set(current_groups) == set(prev_groups)
        
        story.append(Paragraph(
            f"Current scope: <b>{safe_escape(current_scope_label)}</b> | "
            f"Previous scope: <b>{safe_escape(prev_scope_label)}</b>",
            cust["BodyJ"]
        ))
        story.append(Spacer(1, 8))
        
        if not same_scope:
            story.append(Paragraph(
                "Scopes differ â€” trend comparison skipped.",
                cust["BodyJ"]
            ))
        else:
            def _delta_str(curr, prev):
                d = curr - prev
                if d > 0: return f"+{d}"
                if d < 0: return str(d)
                return "0"
            
            trend_data = [["Metric", "Previous", "Current", "Change"]]
            trend_data.append(["Critical Findings", str(prev_stats.get("critical_findings", 0)),
                              str(env_stats["critical_findings"]),
                              _delta_str(env_stats["critical_findings"], prev_stats.get("critical_findings", 0))])
            trend_data.append(["High Findings", str(prev_stats.get("high_findings", 0)),
                              str(env_stats["high_findings"]),
                              _delta_str(env_stats["high_findings"], prev_stats.get("high_findings", 0))])
            trend_data.append(["Medium Findings", str(prev_stats.get("medium_findings", 0)),
                              str(env_stats["medium_findings"]),
                              _delta_str(env_stats["medium_findings"], prev_stats.get("medium_findings", 0))])
            trend_data.append(["Total Active Findings", str(prev_stats.get("total_active", 0)),
                              str(env_stats["total_active"]),
                              _delta_str(env_stats["total_active"], prev_stats.get("total_active", 0))])
            trend_data.append(["Attack Chains", str(prev_stats.get("attack_chains", 0)),
                              str(env_stats["attack_chains"]),
                              _delta_str(env_stats["attack_chains"], prev_stats.get("attack_chains", 0))])
            trend_data.append(["Risk Score", f'{prev_stats.get("risk_score", 0)}/100',
                              f'{env_stats["risk_score"]}/100',
                              _delta_str(env_stats["risk_score"], prev_stats.get("risk_score", 0))])
            
            tt = Table(trend_data, colWidths=[150, 100, 100, 100])
            tt.setStyle(TableStyle([
                ("BACKGROUND", (0,0),(-1,0), colors.HexColor("#1e3a5f")),
                ("TEXTCOLOR", (0,0),(-1,0), colors.white),
                ("FONTNAME", (0,0),(-1,0), "Helvetica-Bold"), ("FONTSIZE", (0,0),(-1,-1), 9),
                ("GRID", (0,0),(-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0,1),(-1,-1), [colors.HexColor("#f8fafc"), colors.white]),
                ("ALIGN", (1,0),(-1,-1), "CENTER"),
                ("VALIGN", (0,0),(-1,-1), "MIDDLE"),
                ("TOPPADDING", (0,0),(-1,-1), 4), ("BOTTOMPADDING", (0,0),(-1,-1), 4),
            ]))
            story.append(tt)
        story.append(Spacer(1, 10))
        story.append(Paragraph(
            "<i>Trend analysis enables tracking of security posture improvement over time. "
            "Green changes (â†“) indicate reduced risk; red changes (â†‘) indicate new or increased risk.</i>",
            cust["Disclaimer"]
        ))
    else:
        story.append(Paragraph(
            "No previous assessment found for trend comparison.",
            cust["BodyJ"]
        ))
    story.append(PageBreak())

    # â”€â”€â”€ 11. APPENDIX â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    story.append(Paragraph("11. Appendix", cust["SectionH1"]))
    story.append(Paragraph("<b>Risk Definitions</b>", cust["SectionH2"]))
    rd = [["Severity","Definition"],
          ["CRITICAL","Immediate threat of domain/forest compromise. Act within days."],
          ["HIGH","Significant risk of escalation or lateral movement. Remediate within 2 weeks."],
          ["MEDIUM","Moderate risk. Address within 30-60 days."],
          ["LOW","Informational or best-practice recommendations."]]
    rdt = Table(rd, colWidths=[100, 395])
    rdt.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"), ("FONTSIZE",(0,0),(-1,-1),8.5),
        ("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#f8fafc"),colors.white]),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
    ]))
    story.append(rdt)
    story.append(Spacer(1,20))
    # â”€â”€ Exclusions by Finding table â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    from analytics.constants import EXCLUSIONS_MAP
    _active_keys = {f["id"] for f in findings if f.get("id")}
    story.append(Paragraph("<b>Exclusions by Finding</b>", cust["SectionH2"]))
    story.append(Paragraph(
        "Each finding type excludes certain built-in accounts, groups, or objects from its "
        "analysis by design. The table below lists these exclusions per finding type.",
        cust["BodyJ"]
    ))
    story.append(Spacer(1, 6))
    excl_headers = [Paragraph("<b>Finding</b>", cust["BodySmall"]), Paragraph("<b>Exclusions</b>", cust["BodySmall"])]
    excl_rows = [excl_headers]
    for fid, exc_list in EXCLUSIONS_MAP.items():
        if fid not in _active_keys:
            continue
        finding_label = fid.replace("_", " ").title()
        excl_text = "; ".join(exc_list) if exc_list else "None"
        excl_rows.append([
            Paragraph(finding_label, cust["BodySmall"]),
            Paragraph(excl_text, cust["BodySmall"]),
        ])
    excl_table = Table(excl_rows, colWidths=[120, 330])
    excl_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,0), colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR", (0,0),(-1,0), colors.white),
        ("FONTNAME", (0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE", (0,0),(-1,-1), 8),
        ("GRID", (0,0),(-1,-1), 0.3, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0,1),(-1,-1), [colors.HexColor("#f8fafc"), colors.white]),
        ("VALIGN", (0,0),(-1,-1), "TOP"),
        ("TOPPADDING", (0,0),(-1,-1), 3),
        ("BOTTOMPADDING", (0,0),(-1,-1), 3),
    ]))
    story.append(excl_table)
    story.append(Spacer(1, 16))

    story.append(Paragraph("<b>Tools Used</b>", cust["SectionH2"]))
    for t in ["BloodHound CE (SharpHound + AzureHound + Neo4j)", "GraphShield Hybrid Identity Security Platform", "MITRE ATT&CK Navigator"]:
        story.append(Paragraph(f"&bull;  {t}", cust["BodyJ"]))
    story.append(Spacer(1,20))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=10))
    story.append(Paragraph(
        "This report is confidential and intended solely for the named recipient. "
        f"Prepared for {safe_escape(client_name)} by {safe_escape(assessor)}. "
        "Findings reflect the environment at time of assessment. "
        "Generated with GraphShield Hybrid Identity Security Platform.",
        cust["Disclaimer"]
    ))

    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    return output


def _load_previous_stats(client_name, current_version):
    """Load previous assessment stats for trend comparison."""
    try:
        from config import _safe_filename
        safe = _safe_filename(client_name)
        client_dir = os.path.join(BASE_OUTPUT_DIR, safe)
        if not os.path.isdir(client_dir):
            return None
        
        versions = sorted([d for d in os.listdir(client_dir)
                          if d.startswith("v") and d != f"v{current_version}"], reverse=True)
        if not versions:
            return None
        
        # Check latest previous version for evidence JSON
        for ver in versions:
            vdir = os.path.join(client_dir, ver)
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
