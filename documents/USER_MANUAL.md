# User Manual — Hybrid Identity Security Assessment Platform

## 1. Quick Start

```powershell
# 1. Ensure Neo4j is running (BloodHound data must be imported — both AD and Azure)
# 2. Ensure Ollama is running (for AI summaries)

# 3. Launch the app
cd path\to\GraphShield
streamlit run app.py

# Or use the batch file
.\scripts\Launch_App.bat
```

Open browser to `http://localhost:8501`

## 2. Application Overview

The GraphShield – Hybrid Identity Security Assessment Platform is a Streamlit-based web application that:

1. **Connects to Neo4j** (populated by BloodHound CE) to retrieve AD AND Azure/Entra ID attack path data
2. **Analyses findings** across **72 categories** — 26 Active Directory + 46 Azure/Entra ID
3. **Generates professional reports** (PDF, Excel, CSV, JSON) with client branding
4. **Produces AI-powered executive summaries** via local Ollama LLM

### Architecture Flow

```
SharpHound ──┐
             ├──► BloodHound CE (Neo4j) ◄── GraphShield ──► Browser (Streamlit UI)
AzureHound ──┘                                              │
															 ├──► PDF Assessment Report
															 ├──► PDF Executive Brief (AI)
															 ├──► Excel Audit Workbook
															 ├──► CSV Findings Export
															 ├──► JSON Evidence Export
															 ├──► HTML Attack Graph (PyVis)
															 └──► ZIP Package (all above)
```

**Key difference from legacy pipeline:** Both SharpHound (AD) and AzureHound (Azure/Entra ID) data are uploaded directly into BloodHound CE via its web UI. The app queries Neo4j once for both AD and Azure data.

## 3. Step-by-Step Operation

### Step 1: Collect AD Data (see DATA_COLLECTION.md)

Before using the app, you must populate Neo4j with BloodHound data:

```powershell
# On a domain-joined machine:
.\SharpHound.exe --CollectionMethods All --OutputDirectory C:\BH_Data

# Import the resulting .zip file into BloodHound CE web UI at http://localhost:8080
```

### Step 2: Collect Azure/Entra ID Data (see DATA_COLLECTION.md)

For Azure/Entra ID assessment, export data using AzureHound and upload to BloodHound CE:

```powershell
# On any machine with internet:
azurehound login
azurehound collect --output azurehound.json

# Upload azurehound.json to BloodHound CE web UI at http://localhost:8080
# BloodHound CE accepts AzureHound JSON files natively
```

### Step 3: Configure Client

In the sidebar, set the engagement parameters:

| Field | Description | Example |
|-------|-------------|---------|
| **Client Profile** | Select a saved profile or choose `[Manual Entry]` | `sample_client.json` |
| **Client Name** | Organisation being assessed | `Acme_Corp` |
| **Engagement ID** | Your internal engagement reference | `ACME-2026-001` |
| **Data Version** | Version of the dataset (change for re-audits) | `1.0`, `2.0` |
| **Assessor** | Firm/consultant name | `Security Assessment Team` |

**Data Version for re-audits**: If you audit the same client again after 6 months, use `2.0` as the version. The app will:
- Create `outputs/Acme_Corp/v2.0/` for the new reports
- Auto-backup the old cache as `outputs/Acme_Corp/raw_bloodhound_v1.0_<date>.json`
- Keep the `v1.0/` directory intact with previous reports

### Step 4: Select Assessment Scope

In the sidebar, choose one assessment scope via the radio buttons:

| Group | Focus |
|-------|-------|
| **Active Directory Core Assessment** | 18 AD findings — privilege escalation, ACL abuse, delegation, kerberoasting, etc. |
| **Identity Attack Path Assessment** | 8 AD findings — certificate abuse (ESC1/ESC3), shadow credentials, LAPS gaps, NTLM relay, SQL linked servers, domain trust escalation |
| **Azure/Entra ID Core Assessment** | 20 Azure findings — privileged roles, app permissions, key vault abuse, external users, etc. |
| **Zero Trust Identity Hardening Review** | 11 Azure findings — MFA gaps, CA policy gaps, PIM audit, legacy auth, logging, etc. |
| **Security Architecture Simulation** | 9 Azure findings — Graph API abuse, PRT token abuse, device join abuse, MI token theft, etc. |
| **Non-Human Identity Governance** | 6 Azure findings — unowned SPs, orphaned apps, over-consented apps, privileged SPs without CA, user-assigned MI proliferation, stale SPs |

Only the selected scope will be queried from Neo4j and appear in reports.

### Step 5: Load Data

| Option | Behavior |
|--------|----------|
| **Use cached data** (checked) | Loads from `outputs/<Client>/raw_bloodhound.json` — no Neo4j connection needed |
| **Use cached data** (unchecked) | Connects to Neo4j and fetches fresh data for selected groups only |
| **Reload from Neo4j** button | Force re-fetch even if cache exists (disabled until at least one group is selected) |

**Tip**: For demos or when Neo4j is unavailable, ensure cache was saved previously, then check "Use cached data".

**Note**: The **Reload from Neo4j** button is disabled until you select at least one assessment group. This ensures you always scope the data fetch to the relevant environment(s).

### Step 6: Review Findings

The main dashboard shows:

- **Risk Gauge**: Overall risk score 0–100 (aligned with RiskEngine calculation)
- **Finding Cards** (only groups you selected):
  - **26 AD finding types** (AD-001 through AD-026) from BloodHound data
  - **46 Azure/Entra ID finding types** (AZ-001 through AZ-046) from AzureHound data
  - Findings WITH evidence show full data (identified assets, relationships, severity)
  - Findings WITHOUT evidence show `[NO DATA]` — the framework is still visible for audit scope
- Each finding has tabs:
  - **Business Impact**: Risk analysis and detection strategies
  - **Remediation**: Step-by-step fix instructions
  - **Compliance**: CIS Controls v8.1 / NIST CSF 2.0 / ISO 27001:2022 / SA 315 / DPDP Act mappings
  - **Exclusions**: Limitations and conditions for each finding
  - **Targeted Assets**: Specific users, groups, computers, service principals, managed identities, applications, key vaults, tenants affected
- **Attack Chains**: Evaluated attack paths (AD-only + hybrid AD–Azure) with severity ratings
- **Hybrid Identity Risk**: AD vs Cloud score breakdown

Reports dynamically adapt to selected scope:
- **Report title** reflects selected groups (e.g., "Active Directory Core Security Assessment Report")
- **Environment Overview** sections only show for selected environments (AD and/or Azure)
- **Data Source Integrity** only shows SharpHound or AzureHound metadata relevant to selected groups
- **TOC entries** are omitted for sections that don't apply

### Step 7: Generate AI Executive Summary

1. Click **"Generate CISO Summary"** button
2. Wait for Ollama to process (10–30 seconds depending on hardware)
3. AI report is displayed in the browser AND saved as PDF in the output folder

### Step 8: Generate All Reports

The **Reports** section in the sidebar (top-right) has the "Generate All Reports" button — no need to scroll down.

The following files are created in `outputs/<Client>/v<version>/`:

| File | Description |
|------|-------------|
| `<Client>_GraphShield_Assessment_Report_<date>.pdf` | Full PDF report — cover, risk gauge, AD and/or Azure env overview (based on scope), findings with group column, compliance, exclusions appendix, remediation roadmap |
| `<Client>_GraphShield_Executive_Security_Brief_<date>.pdf` | AI-generated CISO executive summary PDF |
| `<Client>_GraphShield_Engineering_<date>.xlsx` | **Excel Audit Workbook** — up to 11 sheets (AD Environment and Azure Environment sheets only appear when corresponding groups are selected) |
| `<Client>_GraphShield_Findings_<date>.csv` | CSV findings register with compliance columns |
| `<Client>_GraphShield_Evidence_<date>.json` | Structured evidence JSON |
| `<Client>_GraphShield_Attack_Graph_<date>.html` | Interactive attack path graph (PyVis) |
| `<Client>_GraphShield_Package_<date>.zip` | All of the above bundled |

### Step 8: Audit Tracking (Excel Workbook)

The Excel workbook is designed as a **living audit tracker**:

| Sheet | Use |
|-------|-----|
| **Dashboard** | Executive KPIs, risk score, finding counts |
| **Findings Register** | **The main tracker** — engineers update these columns: |
| | → **Action Taken**: Document remediation actions performed |
| | → **Status**: Dropdown (Open / In Progress / Closed / Accepted Risk) |
| | → **Owner**: Assign responsible person |
| | → **Due Date**: Target remediation date |
| | → **Notes**: Free text for audit trail |
| **Attack Paths** | All identified attack chains for reference |
| **Compliance** | Per-finding CIS / NIST / ISO mapping |
| **Affected Assets** | Every object mapped to findings |
| **Remediation Status** | Pivot summary of open vs closed by severity |
| **Azure Environment** | Per-tenant Azure/Entra ID environment statistics |
| **Trend Comparison** | Current vs previous assessment delta tracking |

## 4. File Structure Overview

```
GraphShield/
├── app.py                          ── Main Streamlit UI
├── main.py                         ── Streamlit bootstrap (EXE entry point)
├── config.py                       ── Multi-client config, paths, cache management
├── scripts/
│   ├── build_exe.py                ── PyInstaller EXE builder
│   ├── generate_report.py          ── Offline report generator (no UI)
│   ├── Launch_App.bat              ── Windows launcher
│   └── setup_windows.ps1           ── Windows dependency setup
├── documents/
│   ├── PREREQUISITES.md            ── Prerequisites guide
│   ├── DATA_COLLECTION.md          ── Data collection instructions
│   ├── USER_MANUAL.md              ── This file
│   └── requirements.txt            ── Python dependencies
├── analytics/
│   ├── constants.py                 ── Shared compliance map, severity weights, colors
│   ├── finding_builder.py          ── 72 finding definitions (26 AD + 46 Azure)
│   ├── finding_enrichment.py       ── Severity/impact/remediation/compliance enrichment
│   ├── groups.py                   ── 5 assessment group definitions and query key map
│   ├── risk_engine.py              ── Weighted risk scoring (AD + Cloud split)
│   ├── attack_chain.py             ── AD + Azure attack chain construction
│   ├── hybrid_attack_chain.py      ── AD–Azure hybrid chain configs
│   ├── identity_normalizer.py      ── Data normalization (AD + Azure entity types)
│   ├── graph_builder.py            ── PyVis attack graph generation
│   └── preflight.py                ── Pre-connect environment checks
├── collectors/
│   ├── neo4j_collector.py          ── Neo4j/BloodHound data fetcher (AD + Azure queries)
│   ├── bloodhound_queries.py       ── 26 Cypher queries (AD findings)
│   ├── azure_queries.py            ── 47 Cypher queries (46 Azure/Entra ID findings + 1 supporting query)
│   ├── query_registry.py           ── Built-in query registry
│   └── schema_probe.py             ── Per-group schema validation at connect time
├── reporting/
│   ├── pdf_export.py               ── Big 4-style PDF assessment report
│   ├── ai_pdf_export.py            ── AI executive brief PDF
│   ├── excel_export.py             ── Audit workbook (11 sheets)
│   ├── csv_export.py               ── CSV with compliance + entity columns
│   ├── json_export.py              ── Evidence JSON
│   ├── zip_package.py              ── ZIP bundler
│   └── evidence_manager.py         ── File upload handler
├── ai/
│   └── analyst.py                  ── Olama API client (hybrid identity prompt)
├── client_profiles/
│   └── sample_client.json          ── Example profile
├── outputs/
│   └── <Client>/
│       ├── raw_bloodhound.json     ── Per-client cache (AD + Azure combined)
│       ├── raw_bloodhound_v1.0_<date>.json  ── Historical backup
│       └── v<version>/
│           ├── <Client>_GraphShield_Assessment_Report_<date>.pdf
│           ├── <Client>_GraphShield_Executive_Security_Brief_<date>.pdf
│           ├── <Client>_GraphShield_Engineering_<date>.xlsx
│           ├── <Client>_GraphShield_Findings_<date>.csv
│           ├── <Client>_GraphShield_Evidence_<date>.json
│           ├── <Client>_GraphShield_Attack_Graph_<date>.html
│           └── <Client>_GraphShield_Package_<date>.zip
├── evidence/                       ── Uploaded evidence files
├── documents/                      ── Technical documentation
└── test_output/                    ── Test scripts and generated test reports
```

## 5. Standalone EXE Build

The app can be packaged as a standalone Windows executable:

```powershell
# From project root:
python scripts\build_exe.py                # Standard build
python scripts\build_exe.py --logo logo.png --icon icon.png   # With branding
```

This creates `dist/GraphShield.exe` — a single file, no Python needed on the target machine.
| `client_profiles/` | Pre-loaded client profile templates |
| `_internal/` | Python runtime and dependencies (managed by PyInstaller) |
| `documents/` | PREREQUISITES.md, USER_MANUAL.md, DATA_COLLECTION.md |

**To distribute**:
1. Build: `python scripts\build_exe.py`
2. Copy `dist/GraphShield.exe` to the target machine
3. Double-click the EXE
4. Open `http://localhost:8501` in the browser
5. Ensure BloodHound CE is running with both SharpHound and AzureHound data imported
6. Generated reports appear in `outputs/<Client>/v<version>/`

**No Python installation required** on the target machine.

## 6. Configuration Options

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j connection string |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | `bloodhoundcommunityedition` | Neo4j password |
| `OLLAMA_URL` | `http://localhost:11434/api/generate` | Ollama API endpoint |
| `OLLAMA_MODEL` | `llama3.1:latest` | LLM model for AI summaries |
| `CLIENT_NAME` | `Default_Client` | Client name (fallback) |
| `ENGAGEMENT_ID` | `AD-YYYY-001` | Engagement reference |
| `ASSESSOR` | `Security Assessment Team` | Assessor firm name |
| `DATA_VERSION` | `1.0` | Data version identifier |
| `CLIENT_PROFILE` | (none) | Path to profile JSON file |
| `BASE_OUTPUT_DIR` | `outputs` | Root output directory |

### Client Profiles

Create JSON files in `client_profiles/`:

```json
{
  "client_name": "Acme_Corp",
  "engagement_id": "ACME-2026-001",
  "data_version": "1.0",
  "assessor": "Your Firm Name"
}
```

## 7. Re-auditing the Same Client

When you reassess a client after 6+ months:

1. Set **Data Version** to `2.0` (or new version number)
2. The app auto-creates `outputs/<Client>/v2.0/` for new reports
3. Old cache is auto-backed up as `raw_bloodhound_v1.0_<date>.json`
4. Previous reports remain in `v1.0/` — no data loss
5. The sidebar shows previous assessments in the "Previous Assessments" expander

## 8. Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| "Neo4j connection failed" | Neo4j not running or wrong credentials | Check `NEO4J_PASSWORD` env var; ensure Neo4j is started |
| No findings with data | Neo4j empty or BloodHound not imported | Run SharpHound + AzureHound, import .zip and .json into BloodHound CE |
| AI button hangs | Ollama not running or wrong model | Run `ollama serve`; pull `llama3.1:latest` |
| Excel file has dropdown not working | openpyxl version | `pip install --upgrade openpyxl` |
| "[NO DATA]" on all findings | Cache loaded but has no evidence data | Normal if using cached data without Neo4j — framework scope is still visible |
| PDF generation error | reportlab not installed | `pip install reportlab` |
| Wrong client name in files | Client config not set before generation | Set client name in sidebar before generating reports |
| No Azure findings loaded | AzureHound data not imported to BloodHound CE | Upload `azurehound.json` to BloodHound CE at http://localhost:8080 |
| Azure findings missing [NO DATA] | Stale cache from previous version | Clear cache: delete `outputs/<Client>/raw_bloodhound.json` and reload from Neo4j |
| "Connection error" on EXE launch | Port 8501 already in use | Close other Streamlit instances or change port via `--server.port=8502` |
