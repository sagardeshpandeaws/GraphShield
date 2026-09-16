# GraphShield — Hybrid Identity Security Assessment Platform

GraphShield transforms BloodHound CE telemetry into auditor-ready security
assessment reports for **Active Directory** and **Microsoft Entra ID (Azure)**.

It connects directly to your BloodHound CE Neo4j database, runs 80
MITRE ATT&CK-mapped checks (26 AD + 54 Azure), and generates:

- Full PDF assessment report with compliance mapping (NIST CSF, CIS, ISO 27001, SA 315, DPDP Act)
- Excel audit workbook with findings register and remediation tracking
- CSV findings export + machine-readable JSON evidence
- Interactive attack-path graph (HTML)
- Optional AI executive summary via a local Ollama LLM

## Features

- **Direct Neo4j integration** — works with any BloodHound CE version that populates the standard schema; no dependency on the BH web UI
- **80 automated findings** across Tier-0 exposure, credential attacks, delegation abuse, ACL misuse, certificate services, trust paths, Entra ID privilege roles, and non-human identity governance
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
