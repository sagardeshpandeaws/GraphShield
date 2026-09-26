# GraphShield — Hybrid Identity Security Assessment Platform

GraphShield transforms BloodHound CE telemetry into auditor-ready security
assessment reports for **Active Directory** and **Microsoft Entra ID (Azure)**.

It connects directly to your BloodHound CE Neo4j database, runs 80
MITRE ATT&CK-mapped checks (26 AD + 54 Azure), and generates:

- Full PDF assessment report with compliance mapping (NIST CSF, CIS, ISO 27001, SA 315, DPDP Act, OWASP NHI Top 10)
- Excel audit workbook with findings register and remediation tracking
- CSV findings export + machine-readable JSON evidence
- Interactive attack-path graph (HTML)
- Optional AI executive summary via a local Ollama LLM

## Features

- **Direct Neo4j integration** — works with any BloodHound CE version that populates the standard schema; no dependency on the BH web UI
- **80 automated findings** across Tier-0 exposure, credential attacks, delegation abuse, ACL misuse, certificate services, trust paths, Entra ID privilege roles, and non-human identity governance
- **Non-Human Identity (NHI) governance module** — a first-class workload- / agentic-identity assessment covering **14 NHI findings** (AZ-041→AZ-054): unowned/disabled-owner/single-owner service principals, orphaned/over-consented applications, privileged SPs without conditional access, managed-identity & device lifecycle, combined-privilege SPs, legacy SP types — plus an **NHI lifecycle feed adapter** (`analytics/nhi_lifecycle.py`: `load_lifecycle_feed` → `feed_summary` → `build_lifecycle_findings`). Set `GRAPH_SHIELD_LIFECYCLE_FEED` (Entra sign-in/audit-log JSON path, glob, or in-memory dict) to append feed-gated non-human-identity **lifecycle governance findings** (orphaned / dormant / credential-expired / sign-in anomaly / consent-after-review / attestation-overdue / rotation-overdue / new-unowned-onboarding, AZ-055→AZ-062 — 88 findings with a feed). A supplied feed is also **correlated against the graph**: `correlate_nhi_sources()` binds the log-derived lifecycle findings to the graph-derived NHI governance findings per workload identity (Entra AppId / object id / display name), so one identity that is both unowned *in the graph* and attestation-overdue *in the logs* is reported as a single correlated identity (`nhi_correlation`). A supplied feed also renders a **per-identity NHI Lifecycle Dashboard** (identity, last sign-in, sign-in count, activity period, credential type, lifecycle stages, attestation / rotation / onboarding / cross-source). No feed → deterministic no-op; the 80-finding baseline is untouched.
- **Hybrid AD + Azure attack chains** — cross-premise escalation scenarios
- **Weighted risk scoring** with executive dashboard
- **Source integrity tracking** — SHA-256 of original SharpHound/AzureHound collections embedded in evidence
- **Multi-client support** — client profiles, versioned outputs, re-audit friendly
- **Standalone EXE build** — optional PyInstaller packaging for machines without Python

## Quick Start

### Prerequisites

| Item | How to Get It |
|------|---------------|
| BloodHound CE | `docker compose up` — [BH CE Quickstart](https://github.com/SpecterOps/BloodHound) |
| SharpHound data | `SharpHound.exe -c All` on a domain-joined machine ([releases](https://github.com/BloodHoundAD/SharpHound/releases)) |
| AzureHound data (optional) | `AzureHound.exe -c All` for Entra ID findings ([releases](https://github.com/BloodHoundAD/AzureHound/releases)) |
| Python 3.10+ | python.org |
| Docker Desktop | docker.com |

### Install & Run

```powershell
git clone https://github.com/sagardeshpandeaws/GraphShield.git
cd GraphShield
pip install -r documents/requirements.txt
scripts\Launch_App.bat        # or: streamlit run app.py
```

Open http://localhost:8501, upload your SharpHound ZIP (and AzureHound ZIP
if assessing Entra ID), connect to Neo4j, and generate reports.
See [documents/QUICKSTART_GUIDE.md](documents/QUICKSTART_GUIDE.md).

## Documentation

| Document | Contents |
|----------|----------|
| [QUICKSTART_GUIDE.md](documents/QUICKSTART_GUIDE.md) | 15-minute setup walkthrough |
| [PREREQUISITES.md](documents/PREREQUISITES.md) | BloodHound CE, Neo4j, tooling requirements |
| [DATA_COLLECTION.md](documents/DATA_COLLECTION.md) | SharpHound / AzureHound collection methods |
| [USER_MANUAL.md](documents/USER_MANUAL.md) | Full feature reference, config, troubleshooting |
| [QUERY_LOGIC.md](documents/QUERY_LOGIC.md) | How each Cypher finding query works |
| [ASSESSMENT_SCOPE.md](documents/ASSESSMENT_SCOPE.md) | Finding catalog and scope |

## Building a Standalone EXE (optional)

```powershell
python scripts\build_exe.py
# → dist/GraphShield.exe (single file, no Python required on target)
```

## Tests

```powershell
pytest tests/
```

## Legal & Responsible Use

GraphShield is a **defensive security assessment tool**. Only use it on
environments you are explicitly authorized to assess. You are responsible for
complying with all applicable laws and obtaining proper authorization before
collecting Active Directory / Entra ID data.

Report artifacts may contain sensitive security information — handle per your
engagement's confidentiality terms.

## License

[MIT](LICENSE)
