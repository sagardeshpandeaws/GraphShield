import os
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak,
    Table, TableStyle, HRFlowable, Image
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from datetime import datetime
from analytics.groups import GROUPS
from config import LOGO_PATH


NAVY = colors.HexColor("#1e3a5f")
SLATE = colors.HexColor("#64748b")
BORDER = colors.HexColor("#cbd5e1")


def _clean_md(text):
    """Strip markdown formatting from AI-generated text."""
    import re
    text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
    text = re.sub(r'__(.+?)__', r'\1', text)
    text = re.sub(r'#+\s*', '', text)
    text = re.sub(r'^[\s\-*\u2022\u00b7\u25c6\u25c7\u2192\u21d2#]+', '', text)
    text = re.sub(r'^\d+\.\s*', '', text)
    return text.strip()


def _safe_escape(text):
    """Escape XML special characters for reportlab Paragraph."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColorRGB(0, 0, 0)
    canvas.drawString(50, 20, "Confidential")
    canvas.drawRightString(540, 20, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()


def export_ai_pdf(text, filename, findings=None, chains=None, risk=None, env_stats=None, client_config=None, report_title=""):
    cfg = client_config or {}
    client_name = cfg.get("client_name", "Client")
    assessor = cfg.get("assessor", "Security Assessment Team")
    date_str = datetime.now().strftime("%B %d, %Y")

    os.makedirs(os.path.dirname(filename), exist_ok=True)

    has_ad = findings and any(f.get("source") in ("Active Directory", None) for f in findings)
    has_az = findings and any(f.get("source") == "Azure" for f in findings)

    doc = SimpleDocTemplate(filename, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50, pagesize=A4)

    H1 = ParagraphStyle("H1", fontSize=16, leading=20, textColor=NAVY, spaceBefore=4, spaceAfter=8)
    H2 = ParagraphStyle("H2", fontSize=13, leading=17, textColor=colors.HexColor("#334155"), spaceBefore=6, spaceAfter=4)
    H3 = ParagraphStyle("H3", fontSize=11, leading=14, textColor=colors.HexColor("#475569"), spaceBefore=4, spaceAfter=3)
    B = ParagraphStyle("B", fontSize=9.5, leading=13, alignment=TA_JUSTIFY, spaceAfter=6)
    BS = ParagraphStyle("BS", fontSize=8.5, leading=11, alignment=TA_JUSTIFY, spaceAfter=4)
    BL = ParagraphStyle("BL", fontSize=9.5, leading=13, leftIndent=14, bulletIndent=4, spaceAfter=3)
    DISC = ParagraphStyle("DISC", fontSize=8, leading=10, textColor=SLATE, alignment=TA_CENTER)

    PAGE_W = 495
    def tw(pct):
        return int(PAGE_W * pct / 100)

    content = []

    # ═════════════ PAGE 1: COVER + KPI DASHBOARD ═════════════
    content.append(Spacer(1, 80))
    if LOGO_PATH and os.path.exists(LOGO_PATH):
        try:
            img = Image(LOGO_PATH, width=2*inch, height=1*inch)
            img.hAlign = "CENTER"
            content.append(img)
            content.append(Spacer(1, 20))
        except Exception:
            pass
    content.append(HRFlowable(width="60%", thickness=3, color=NAVY, spaceAfter=16))
    content.append(Paragraph(_safe_escape(report_title or "Executive Security Brief"), ParagraphStyle("CT", fontSize=26, leading=32, textColor=NAVY, alignment=TA_CENTER, spaceAfter=6)))
    content.append(Paragraph(f"{client_name} | {date_str}", ParagraphStyle("CS", fontSize=11, textColor=SLATE, alignment=TA_CENTER, spaceAfter=4)))
    content.append(Paragraph(f"Prepared by {assessor}", ParagraphStyle("CS2", fontSize=10, textColor=colors.HexColor("#94a3b8"), alignment=TA_CENTER, spaceAfter=6)))

    # KPI boxes with colored backgrounds
    stats = env_stats or {}
    _ad_count = sum(1 for f in (findings or []) if f.get("source") in ("Active Directory", None))
    _az_count = sum(1 for f in (findings or []) if f.get("source") == "Azure")
    _total_findings = _ad_count + _az_count
    box_w = tw(24)
    kpis = [
        ("CRITICAL", str(stats.get("critical_findings", 0)), colors.HexColor("#dc2626"), colors.HexColor("#fef2f2")),
        ("HIGH",     str(stats.get("high_findings", 0)),      colors.HexColor("#ea580c"), colors.HexColor("#fff7ed")),
        ("MEDIUM",   str(stats.get("medium_findings", 0)),    colors.HexColor("#ca8a04"), colors.HexColor("#fefce8")),
        ("LOW",      str(stats.get("low_findings", 0)),       colors.HexColor("#2563eb"), colors.HexColor("#eff6ff")),
    ]
    kpi_cells = []
    for label, val, fg, bg in kpis:
        kpi_cells.append(Paragraph(
            f"<font size='7' color='{fg.hexval()}'><b>{label}</b></font><br/>"
            f"<font size='24' color='{fg.hexval()}'><b>{val}</b></font>",
            ParagraphStyle("kp", fontSize=7, leading=30, alignment=TA_CENTER)
        ))
    kpi_t = Table([kpi_cells], colWidths=[box_w]*4)
    kpi_t.setStyle(TableStyle([
        ("BOX", (0,0),(-1,-1), 0.5, BORDER),
        ("INNERGRID", (0,0),(-1,-1), 0.5, BORDER),
        ("VALIGN", (0,0),(-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0),(-1,-1), 8), ("BOTTOMPADDING", (0,0),(-1,-1), 8),
    ]))
    # Per-cell background colors
    for i, (_, _, _, bg) in enumerate(kpis):
        kpi_t.setStyle(TableStyle([("BACKGROUND", (i,0), (i,0), bg)]))
    content.append(kpi_t)
    content.append(Spacer(1, 10))

    # Exposure flags
    t0 = stats.get("tier0_exposure", "NO")
    ds = stats.get("dcsync_exposure", "NO")
    rs = stats.get("risk_score", 0)
    rl = "Critical" if rs >= 70 else ("High" if rs >= 50 else ("Medium" if rs >= 30 else "Low"))
    rc = "#dc2626" if rs >= 70 else ("#ea580c" if rs >= 50 else ("#ca8a04" if rs >= 30 else "#2563eb"))
    content.append(Paragraph(
        f"Tier-0 Exposure: <b><font color='{'red' if t0 == 'YES' else 'green'}'>{t0}</font></b>"
        f"&nbsp;&nbsp;|&nbsp;&nbsp;"
        f"DCSync Exposure: <b><font color='{'red' if ds == 'YES' else 'green'}'>{ds}</font></b>"
        f"&nbsp;&nbsp;|&nbsp;&nbsp;"
        f"Risk Score: <b><font color='{rc}'>{rs}/100 ({rl})</font></b>",
        ParagraphStyle("EXP", fontSize=10, leading=14, spaceAfter=4)
    ))

    # Severity breakdown table (mini pie as table)
    content.append(Spacer(1, 6))
    sev_data = [["Severity", "Findings", "Weight"]]
    for sev, count in [("CRITICAL", stats.get("critical_findings", 0)), ("HIGH", stats.get("high_findings", 0)),
                        ("MEDIUM", stats.get("medium_findings", 0)), ("LOW", stats.get("low_findings", 0))]:
        sev_data.append([sev, str(count), str({"CRITICAL":10,"HIGH":5,"MEDIUM":3,"LOW":1}.get(sev, 1) * count)])
    sev_t = Table(sev_data, colWidths=[tw(25), tw(15), tw(15)])
    sev_t.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,0), NAVY),
        ("TEXTCOLOR", (0,0),(-1,0), colors.white),
        ("FONTNAME", (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0),(-1,-1), 8.5),
        ("GRID", (0,0),(-1,-1), 0.3, BORDER),
        ("ROWBACKGROUNDS", (0,1),(-1,-1), [colors.HexColor("#f8fafc"), colors.white]),
        ("ALIGN", (1,0),(2,-1), "CENTER"),
        ("VALIGN", (0,0),(-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0),(-1,-1), 5), ("BOTTOMPADDING", (0,0),(-1,-1), 5),
    ]))
    content.append(sev_t)

    content.append(PageBreak())

    # ═════════════ PAGE 2: ENVIRONMENT + AI SUMMARY ═════════════
    env_items = []
    if has_ad:
        env_items += [
            ("Users (AD)", stats.get("total_users", "-")),
            ("Computers (AD)", stats.get("total_computers", "-")),
            ("Servers", stats.get("servers", "-")),
            ("Domain Controllers", stats.get("domain_controllers", "-")),
            ("Tier-0 Accounts", stats.get("tier0_accounts", "-")),
            ("Service Accounts (SPN)", stats.get("service_accounts", "-")),
            ("Trusts", stats.get("trusts", "-")),
        ]

    az_tenants = stats.get("azure_tenants", [])
    if has_az and az_tenants:
        env_items += [
            ("Azure Tenants", str(len(az_tenants))),
            ("Entra ID Users", str(stats.get("azure_users", 0))),
            ("Service Principals", str(stats.get("azure_service_principals", 0))),
            ("Managed Identities", str(stats.get("azure_managed_identities", 0))),
            ("Applications", str(stats.get("azure_applications", 0))),
            ("Key Vaults", str(stats.get("azure_key_vaults", 0))),
        ]
    if env_items:
        content.append(Paragraph("Environment Overview", H1))
        content.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=8))
        env_data = [["Object Type", "Count"]]
        for label, val in env_items:
            env_data.append([label, str(val)])
        env_t = Table(env_data, colWidths=[tw(40), tw(15)])
        env_t.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,0), NAVY),
            ("TEXTCOLOR", (0,0),(-1,0), colors.white),
            ("FONTNAME", (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0),(-1,-1), 9),
            ("GRID", (0,0),(-1,-1), 0.3, BORDER),
            ("ROWBACKGROUNDS", (0,1),(-1,-1), [colors.HexColor("#f8fafc"), colors.white]),
            ("ALIGN", (1,0),(1,-1), "CENTER"),
            ("VALIGN", (0,0),(-1,-1), "MIDDLE"),
            ("TOPPADDING", (0,0),(-1,-1), 5), ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ]))
        content.append(env_t)
        content.append(Spacer(1, 14))

    # AI Executive Summary
    content.append(Paragraph("Executive Summary", H1))
    content.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=8))

    # Extract AI text sections by tracking section headers
    skip_phrases = ["here is the rewritten report", "based on the provided data"]
    section_headers = {"executive summary", "business impact", "top risks",
                       "attack path analysis", "30-day remediation plan"}
    mode = "exec_summary"
    exec_lines = []
    impact_lines = []
    import re as _re
    for line in text.split("\n"):
        ln = line.strip()
        if not ln:
            continue
        low = _re.sub(r'^[\s\-*\u2022\u00b7\u25c6\u25c7\u2192\u21d2#]+', '', ln.lower())
        low = _re.sub(r'^\d+\.\s*', '', low)
        if any(sp in low for sp in skip_phrases):
            continue
        matched = [h for h in section_headers if low.startswith(h)]
        if matched:
            h = matched[0]
            if h == "business impact":
                mode = "impact"
            elif h in ("top risks", "attack path analysis", "30-day remediation plan"):
                mode = "skip"
            continue
        if mode == "exec_summary":
            exec_lines.append(ln)
        elif mode == "impact":
            impact_lines.append(ln)

    # Show Executive Summary bullets (skip TOP RISKS / ATTACK PATH ANALYSIS - covered by data sections)
    for line in exec_lines[:8]:
        cleaned = _clean_md(line).lstrip("-* ")
        content.append(Paragraph(f"&bull;  {_safe_escape(cleaned)}", BL))

    # Business Impact
    if impact_lines:
        content.append(Spacer(1, 6))
        content.append(Paragraph("Business Impact", H2))
        for line in impact_lines[:6]:
            cleaned = _clean_md(line).lstrip("-* ")
            content.append(Paragraph(f"&bull;  {_safe_escape(cleaned)}", BL))

    # Key findings highlight (from findings data, not AI text)
    if findings:
        content.append(Spacer(1, 8))
        content.append(Paragraph("Key Risks", H2))
        high_count = 0
        for f in findings:
            if f.get("has_evidence"):
                sev = f.get("severity", "")
                if sev == "CRITICAL":
                    title = f.get("title", "").split("|")[-1].strip().replace("_", " ").title()
                    content.append(Paragraph(
                        f"&bull;  <font color='#dc2626'><b>[CRITICAL]</b></font> {title}", BL))
                elif sev == "HIGH" and high_count < 6:
                    title = f.get("title", "").split("|")[-1].strip().replace("_", " ").title()
                    content.append(Paragraph(
                        f"&bull;  <font color='#ea580c'><b>[HIGH]</b></font> {title}", BL))
                    high_count += 1

    content.append(PageBreak())

    # ═════════════ PAGE 3: ATTACK PATHS + RECOMMENDATIONS ═════════════
    content.append(Paragraph("Attack Path Analysis", H1))
    content.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=8))

    cc = len(chains) if chains else 0
    if cc:
        content.append(Paragraph(f"<b>{cc}</b> distinct attack path{' was' if cc == 1 else 's were'} identified.", B))
        content.append(Spacer(1, 4))
        for c in chains[:6]:
            path = c.get("attack_path", "")
            sev = c.get("severity", "")
            content.append(Paragraph(f"&bull;  <b>[{sev}]</b> {path}", BL))
    else:
        content.append(Paragraph("No attack chains identified.", B))

    content.append(Spacer(1, 14))
    content.append(Paragraph("Strategic Recommendations", H1))
    content.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=8))

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

    selected_groups = sorted({f.get("group") for f in (findings or []) if f.get("group")},
                             key=lambda g: list(GROUPS.keys()).index(g) if g in GROUPS else 99)
    for g in selected_groups:
        rm = ROADMAPS.get(g)
        if not rm:
            continue
        gname = GROUPS.get(g, {}).get("name", g)
        content.append(Paragraph(f"<b>{_safe_escape(gname)}</b>", H2))
        rt = Table(rm, colWidths=[tw(16), tw(18), tw(66)])
        rt.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,0), NAVY),
            ("TEXTCOLOR", (0,0),(-1,0), colors.white),
            ("FONTNAME", (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0),(-1,-1), 8.5),
            ("GRID", (0,0),(-1,-1), 0.3, BORDER),
            ("ROWBACKGROUNDS", (0,1),(-1,-1), [colors.HexColor("#f8fafc"), colors.white]),
            ("VALIGN", (0,0),(-1,-1), "TOP"),
            ("TOPPADDING", (0,0),(-1,-1), 5), ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ]))
        content.append(rt)
        content.append(Spacer(1, 10))
    content.append(Spacer(1, 6))

    content.append(PageBreak())

    # ═════════════ PAGE 4: APPENDIX ═════════════
    content.append(Paragraph("Appendix", H1))
    content.append(HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=8))

    risk_defs = [["Severity", "Definition"],
                 ["CRITICAL", "Immediate threat of domain/forest compromise. Act within days."],
                 ["HIGH", "Significant risk of escalation or lateral movement. Remediate within 2 weeks."],
                 ["MEDIUM", "Moderate risk. Address within 30-60 days."],
                 ["LOW", "Informational or best-practice recommendations."]]
    rdt = Table(risk_defs, colWidths=[tw(20), tw(80)])
    rdt.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,0), NAVY),
        ("TEXTCOLOR", (0,0),(-1,0), colors.white),
        ("FONTNAME", (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0),(-1,-1), 8.5),
        ("GRID", (0,0),(-1,-1), 0.3, BORDER),
        ("ROWBACKGROUNDS", (0,1),(-1,-1), [colors.HexColor("#f8fafc"), colors.white]),
        ("VALIGN", (0,0),(-1,-1), "TOP"),
        ("TOPPADDING", (0,0),(-1,-1), 5), ("BOTTOMPADDING", (0,0),(-1,-1), 5),
    ]))
    content.append(rdt)
    content.append(Spacer(1, 14))

    content.append(Paragraph("Methodology", H2))
    content.append(Paragraph(
        f"Assessment conducted using BloodHound Community Edition (SharpHound + Neo4j). "
        f"Findings aligned with MITRE ATT&CK v14, NIST CSF 2.0, CIS Controls v8.1, "
        f"ISO/IEC 27001:2022, SA 315 (ICAI), DPDP Act 2023, and OWASP NHI Top 10 (2025). "
        f"{_total_findings} finding types evaluated ({_ad_count} AD + {_az_count} Azure/Entra ID); those without evidence marked [NO DATA].",
        BS
    ))
    content.append(Spacer(1, 14))

    content.append(Paragraph("Findings Summary", H2))
    ta = stats.get("total_active", 0)
    content.append(Paragraph(
        f"<b>{ta}</b> active finding{'s' if ta != 1 else ''} identified across {_total_findings} evaluated categories "
        f"({_ad_count} AD + {_az_count} Azure/Entra ID). "
        f"<b>{stats.get('critical_findings', 0)}</b> Critical, <b>{stats.get('high_findings', 0)}</b> High, "
        f"<b>{stats.get('medium_findings', 0)}</b> Medium, <b>{stats.get('low_findings', 0)}</b> Low. "
        f"Confidence labels: <b>Confirmed</b> (direct evidence) and <b>Informational</b> (supplementary).",
        BS
    ))
    content.append(Spacer(1, 14))

    # ── Data Source Integrity ────────────────────────────────────
    content.append(Paragraph("Data Source Integrity", H2))
    content.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=4))

    sh_sha = (cfg or {}).get("sharphound_sha256") or "Not applicable"
    sh_mth = ((cfg or {}).get("sharphound_collection_method") or "Not available").replace("+", " + ")
    sh_ts = (cfg or {}).get("sharphound_timestamp") or "Not available"
    ah_sha = (cfg or {}).get("azurehound_sha256") or "Not applicable"
    ah_mth = ((cfg or {}).get("azurehound_collection_method") or "Not available").replace("+", " + ")
    ah_ts = (cfg or {}).get("azurehound_timestamp") or "Not available"

    SI_CELL = ParagraphStyle("SI_CELL", fontSize=7, leading=9, spaceAfter=0)
    si_data = [
        [Paragraph("<b>Source</b>", SI_CELL),
         Paragraph("<b>SHA-256</b>", SI_CELL),
         Paragraph("<b>Collection Method</b>", SI_CELL),
         Paragraph("<b>Timestamp</b>", SI_CELL)],
    ]
    if has_ad:
        si_data.append([Paragraph("SharpHound (AD)", SI_CELL),
                        Paragraph(sh_sha[:48] + "..." if len(sh_sha) > 48 else sh_sha, SI_CELL),
                        Paragraph(sh_mth, SI_CELL),
                        Paragraph(sh_ts, SI_CELL)])
    if has_az:
        si_data.append([Paragraph("AzureHound (Azure)", SI_CELL),
                        Paragraph(ah_sha[:48] + "..." if len(ah_sha) > 48 else ah_sha, SI_CELL),
                        Paragraph(ah_mth, SI_CELL),
                        Paragraph(ah_ts, SI_CELL)])
    si_t = Table(si_data, colWidths=[tw(18), tw(34), tw(30), tw(18)])
    si_t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    content.append(si_t)
    content.append(Spacer(1, 6))
    SI_sources = []
    if has_ad:
        SI_sources.append("SharpHound")
    if has_az:
        SI_sources.append("AzureHound")
    SI_src_text = "/".join(SI_sources) if SI_sources else "SharpHound/AzureHound"
    content.append(Paragraph(
        f"<i>SHA-256 hashes verify file integrity of original {SI_src_text} collection files. "
        "'Not applicable' indicates data was loaded via Neo4j without file upload.</i>",
        ParagraphStyle("SI_note", fontSize=8, leading=10, textColor=SLATE, spaceAfter=10)
    ))

    # ── Limitations ──────────────────────────────────────────────
    content.append(Paragraph("Limitations &amp; Reliance", H2))
    content.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=4))

    lims = [
        "This executive brief is a summary only. Refer to the full assessment report for detailed findings, evidence, "
        "exclusions by finding type, and complete limitation clauses including Limitation of Liability, No Warranty, "
        "and Report Use Restriction.",

        "The assessment reflects the environment at a single point in time determined by the collection timestamp above. "
        "Changes after collection are not reflected.",

        "Findings are based on BloodHound graph analysis and do not constitute a penetration test or vulnerability scan. "
        "No guarantee of total immunity from security threats is expressed or implied.",
    ]
    for lim in lims:
        content.append(Paragraph(f"&bull;  {lim}", BS))
    content.append(Spacer(1, 14))

    content.append(HRFlowable(width="100%", thickness=1, color=BORDER, spaceAfter=6))
    content.append(Paragraph(
        f"Confidential. Prepared for {client_name} by {assessor} using GraphShield Hybrid Identity Security Platform. "
        "Findings reflect environment at time of assessment.",
        DISC
    ))

    doc.build(content, onFirstPage=_header_footer, onLaterPages=_header_footer)
