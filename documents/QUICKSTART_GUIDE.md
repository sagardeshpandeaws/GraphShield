# GraphShield AD Assessor — Quick-Start Guide

## What You Need

| Item | How to Get It |
|------|---------------|
| BloodHound CE | `docker compose up` — See [BH CE Quickstart](https://github.com/SpecterOps/BloodHound) |
| SharpHound data | Run `SharpHound.exe -c All` on a domain-joined machine |
| Docker Desktop | Free download from docker.com |
| 15 minutes | That's all it takes |

## Step 1 — Start BloodHound CE

```powershell
# In your BH CE directory
docker compose up -d
```

Wait 30 seconds. Open http://localhost:8080 — you should see the BH login.

## Step 2 — Collect Data

On any domain-joined Windows machine:

```powershell
# Download SharpHound.exe (latest: github.com/BloodHoundAD/SharpHound/releases)
.\SharpHound.exe -c All
```

This creates a ZIP like `20260702120000_BloodHound.zip`.

(Optional) For Azure: `.\AzureHound.exe -c All` → creates a ZIP.

## Step 3 — Launch GraphShield

1. Clone this repository (or download and extract it)
2. Install dependencies: `pip install -r documents/requirements.txt`
3. Run **`scripts\Launch_App.bat`** (or `streamlit run app.py`)
4. Wait 20-30 seconds for the app to start
5. Your browser opens to `http://localhost:8501`

## Step 4 — Upload Data

1. Enter your **Company Name** in the sidebar
2. Click **"Upload SharpHound ZIP"** → select your SharpHound export
3. (Optional) Upload AzureHound ZIP
4. **Select assessment groups** in the sidebar — choose which environments to assess (AD, Azure, or both). All are checked by default.
5. Click **"Reload from Neo4j"** (disabled until at least one group is selected) → enters your BH CE Neo4j credentials

  > Default Neo4j credentials (BH CE defaults):
  > - Host: `localhost`
  > - Bolt Port: `7687`
  > - User: `neo4j`
  > - Password: `bloodhoundcommunity`

6. Wait for data collection (1-5 minutes depending on domain size). Only queries for selected groups are executed.

## Step 5 — Generate Reports

1. Click **"Generate All Reports"**
2. Wait 30-60 seconds
3. Download your files:

| File | What It Is |
|------|------------|
| `*_Security_Assessment.pdf` | Full 40-page client-ready report |
| `*_Audit_Workbook.xlsx` | Filterable findings register with compliance mapping |
| `*_Findings.csv` | Raw data for your own analysis |
| `*_Evidence.json` | Machine-readable evidence dump |
| `*_Attack_Graph.html` | Interactive privilege escalation map |
| `*_AI_Executive.pdf` | CISO-ready executive summary |

## Troubleshooting

| Problem | Fix |
|---------|-----|
| **Browser shows "Could not connect"** | Docker not running. Start Docker Desktop. |
| **Neo4j connection refused** | BH CE not running. Run `docker compose up -d`. |
| **"No data loaded"** | Upload SharpHound ZIP first, then click "Reload from Neo4j". |
| **App won't start** | Port 8501 in use? Close other Streamlit apps. |
| **Ollama AI not working** | Optional — skip it. Reports work without AI summary. |

## Need Help?

- Open an issue on the GitHub repository
