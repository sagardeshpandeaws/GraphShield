# Prerequisites & Installation Guide

## Version Compatibility Matrix

The app works directly with **Neo4j** (via Bolt protocol on port 7687) — it does NOT depend on the BloodHound CE web UI version. Any BloodHound CE version that runs Neo4j 5.x and populates it with the standard BloodHound node/relationship schema is compatible.

| Component | Supported Versions | Notes |
|-----------|-------------------|-------|
| **Neo4j** | 5.x (what BloodHound CE uses internally) | App connects via `neo4j` Python driver >=5.0.0 on Bolt port 7687 |
| **BloodHound CE** | Any version with Neo4j 5.x backend | Compatibility is via Neo4j schema, not BH CE UI version |
| **SharpHound** | v2.x (v2.13.0 bundled) | Older v1.x may work but v2.x recommended for full schema support |
| **AzureHound** | Any version producing BloodHound CE-compatible JSON | Upload JSON to BH CE web UI — app reads from Neo4j |
| **Python** | 3.10, 3.11, or 3.12 (3.10+) | Built EXE uses embedded Python 3.13 |
| **Streamlit** | >=1.28.0 (tested up to 1.58.0) | Lower versions may work but not tested |
| **Ollama** | Any version supporting `llama3.1:latest` | API-compatible with `http://localhost:11434/api/generate` |
| **Docker** | Any recent version | Needed only for running BloodHound CE |
| **Windows** | 10 or 11, Server 2016+ | Preflight checks OS version starting with "10." or "6." |
| **Linux** | Ubuntu/Debian (any recent) | Tested on Ubuntu 22.04+ |

### How Schema Compatibility Works

The app issues pre-defined Cypher queries against Neo4j using BloodHound's node labels and relationship types:

```
AD:  User, Group, Computer, Domain, GPO, OU, Base, etc.
     MemberOf, AdminTo, GenericAll, GenericWrite, WriteDacl, etc.

Azure:  AZUser, AZGroup, AZServicePrincipal, AZManagedIdentity,
        AZApplication, AZKeyVault, AZVM, AZTenant, AZSubscription,
        AZResourceGroup, AZManagementGroup
        AZHasRole, AZMemberOf, AZAppAdmin, AZOwns, etc.
```

These labels have been stable since BloodHound CE v4.x / Neo4j 5.x. As long as the data in Neo4j uses these standard labels, the app works — regardless of the BloodHound CE UI version.

### How to Check Your Versions

```powershell
# Check Neo4j version (via Cypher)
docker exec bloodhound-ce-neo4j-1 cypher-shell -u neo4j -p "password" "CALL dbms.components() YIELD versions;"

# Check BloodHound CE version
docker exec bloodhound-ce-bloodhound-1 bloodhound-cli --version

# Check Python version
python --version

# Check Streamlit version
streamlit --version

# Check Ollama version
ollama --version

# Check SharpHound version
.\SharpHound.exe --version
```

---

## Overview for Non-Technical Users

This guide helps you set up everything needed to run the AD Security Assessment Platform.

**What you need:**
1. A computer (laptop or server) — minimum 8 GB RAM, 4 CPU cores, 30 GB free disk
2. An Active Directory domain to assess
3. An Azure/Entra ID tenant (optional, for cloud assessment)
4. Internet access (to download tools)

**What the app does:** Connects to your BloodHound Neo4j database, reads AD attack path data,
analyses it across 66 security categories, and generates professional reports.

---

## Recommended Architecture (Simplified)

```
┌──────────────────────────────────────────────────────────┐
│  SAME MACHINE (for simplicity — use a laptop or server)   │
│                                                            │
│  ┌──────────────────┐   ┌──────────────┐                   │
│  │  BloodHound CE    │   │  Ollama       │                  │
│  │  (via Docker)     │   │  (Local AI)   │                  │
│  │  ┌──────────────┐│   │              │                   │
│  │  │ Neo4j DB     ││   │  llama3.1    │                   │
│  │  └──────────────┘│   └──────────────┘                   │
│  └──────────────────┘                                      │
│                                                            │
│  ┌──────────────────────────────────────┐                   │
│  │  AD Assessment App (Streamlit)       │                  │
│  │  http://localhost:8501               │                  │
│  └──────────────────────────────────────┘                   │
│                                                            │
│   DOMAIN-CONTROLLER-1    DOMAIN-CONTROLLER-2               │
│   (run SharpHound here)                                    │
└──────────────────────────────────────────────────────────┘
```

**For production/large environments**, put the app on a dedicated server and access it
via web browser from your laptop.

---

## 1. Hardware Sizing (All Free/Community Tiers)

### Small Company — <5,000 AD objects (e.g., 500 users)
| Item | Spec | Cost |
|------|------|------|
| Any Windows/Linux machine | 4 GB RAM, 2 CPU, 20 GB disk | Already have |
| **Total** | | **$0** |

### Medium Company — 5,000–50,000 AD objects (e.g., 2,000 users)
| Item | Spec | Cost |
|------|------|------|
| Laptop or small server | 8 GB RAM, 4 CPU, 50 GB SSD | Already have |
| **Total** | | **$0** |

### Large Company — 50,000–200,000 AD objects
| Item | Spec | Cost |
|------|------|------|
| Dedicated server | 16 GB RAM, 8 CPU, 100 GB SSD | ~$50–100/month cloud VM |
| **Total** | | **~$50–100/month** |

### Enterprise — 200,000+ AD objects
| Item | Spec | Cost |
|------|------|------|
| Dedicated server for Neo4j + App | 32 GB RAM, 8 CPU, 200 GB SSD | ~$150–300/month cloud VM |
| Collector machine | 4 GB RAM, 2 CPU | Already have (domain-joined) |
| **Total** | | **~$150–300/month** |

**All software is FREE** — no paid licenses required.

---

## 2. Installing BloodHound Community Edition + Neo4j (via Docker)

This is the easiest method. Docker installs BloodHound CE AND Neo4j together automatically.

### Step 2.1: Install Docker

#### Windows
```powershell
# 1. Download Docker Desktop from https://www.docker.com/products/docker-desktop/
# 2. Run the installer (follow wizard, use default settings)
# 3. After install, restart your computer
# 4. Launch Docker Desktop from Start Menu (wait for "Engine Running" status)
# 5. Open PowerShell or Command Prompt and test:
docker --version
```

#### Linux (Ubuntu/Debian)
```bash
# One-line install:
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
# Log out and back in, then test:
docker --version
```

### Step 2.2: Download & Start BloodHound CE

```powershell
# Create a folder for BloodHound
mkdir C:\BloodHound
cd C:\BloodHound

# Download the docker-compose file
# Get the latest from: https://github.com/BloodHoundAD/BloodHound/releases
# OR use this direct link:
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/BloodHoundAD/BloodHound/main/examples/docker-compose/docker-compose.yml" -OutFile docker-compose.yml

# Start BloodHound CE (this downloads and starts everything)
docker compose up -d

# Wait 2–3 minutes for first-time setup (downloading images)

# Check it's running:
docker compose ps
# You should see 3 services: neo4j, bloodhound, bloodhound-ui
```

```bash
# Linux version of same:
mkdir ~/BloodHound && cd ~/BloodHound
wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/main/examples/docker-compose/docker-compose.yml
docker compose up -d
docker compose ps
```

### Step 2.3: Set BloodHound CE Password (CRITICAL!)

BloodHound CE uses default credentials that you MUST change in production.

#### Method A: Change Password Before Starting (Recommended)

Edit the `docker-compose.yml` file BEFORE running `docker compose up`:

```powershell
# 1. Open docker-compose.yml in Notepad:
notepad C:\BloodHound\docker-compose.yml

# 2. Find this section (near the top):
#    - NEO4J_SECRETS_PASSWORD=bloodhoundcommunityedition
#
# 3. Change the password to something strong, e.g.:
#    - NEO4J_SECRETS_PASSWORD=My$ecureP@ss123!

# 4. Save the file, then start:
docker compose up -d
```

#### Method B: Change Password After Starting (via BloodHound CE CLI)

If BloodHound CE is already running and you want to change the password:

```powershell
# Windows (PowerShell) — Reset Neo4j password using BloodHound CLI inside the container:

# Step 1: Find the BloodHound container name
docker ps --format "table {{.Names}}\t{{.Image}}"
# Look for the container with "bloodhound" in the name (not neo4j)

# Step 2: Open a shell inside the BloodHound container
docker exec -it bloodhound-ce-bloodhound-1 /bin/bash
# (Container name may vary — use what you see from docker ps)

# Step 3: Inside the container, run the password reset command
bloodhound-cli reset-password
# Follow the prompts to enter username (admin) and new password

# OR reset directly with arguments:
bloodhound-cli reset-password --username admin --password "My$ecureP@ss123!"

# Step 4: Type "exit" to leave the container shell
exit
```

```powershell
# Linux version (same commands):
docker exec -it bloodhound-ce-bloodhound-1 /bin/bash
bloodhound-cli reset-password --username admin --password "My$ecureP@ss123!"
exit
```

#### Method C: Reset Neo4j Password Directly (if you know the current Neo4j password)

If you know the current Neo4j password and want to change it:

```powershell
# Connect to the Neo4j container
docker exec -it bloodhound-ce-neo4j-1 /bin/bash

# Inside the container, run Cypher via cypher-shell
cypher-shell -u neo4j -p "current_password" "ALTER USER neo4j SET PASSWORD 'NewP@ss123!';"

# Exit
exit
```

#### Method D: Reset Neo4j Password When You've Forgotten It

If you forgot both the BloodHound admin and Neo4j passwords:

```powershell
# WARNING: This deletes ALL BloodHound data (users, uploaded data)
# Only do this if you have a fresh backup or can re-import SharpHound data

# 1. Stop and remove containers (keeps the Neo4j data volume):
docker compose down

# 2. Remove the volumes to reset everything:
docker compose down -v

# 3. Edit docker-compose.yml and set a new password:
#    NEO4J_SECRETS_PASSWORD=YourNewPassword123

# 4. Start fresh:
docker compose up -d

# 5. Re-import your SharpHound .zip files into BloodHound UI at http://localhost:8080
```

#### Important: Getting the Password for the App

The app reads the Neo4j password from:
1. Environment variable `NEO4J_PASSWORD` (set in PowerShell/command line), OR
2. In `config.py` (default: `bloodhoundcommunityedition`)

```powershell
# If you changed the password, tell the app about it:
$env:NEO4J_PASSWORD = "YourNewPassword123"
streamlit run app.py

# OR for persistent setting:
# Open System Properties → Environment Variables → Add NEO4J_PASSWORD
```

### Step 2.5: BloodHound CE Web UI Admin Login

BloodHound CE has its OWN admin user (separate from Neo4j). You use this to log into the web UI at http://localhost:8080.

```powershell
# Default BloodHound CE web admin credentials:
#     Username: admin
#     Password: admin   (some versions: BloodHound)

# After first login, the web UI will ask you to set a new password.
# This is DIFFERENT from the Neo4j password — don't confuse them.

# To reset the web admin password via CLI:
docker exec -it bloodhound-ce-bloodhound-1 bloodhound-cli reset-password `
    --username admin --password "NewWebAdminPassword"
```

**Remember:**
- Neo4j password = used by our app to connect to the database
- BloodHound CE admin password = used to log into the web UI at http://localhost:8080
- You need BOTH: Neo4j password for the app, BloodHound admin to upload SharpHound data

### Step 2.6: Find Your Neo4j Password (if auto-generated)

Some BloodHound CE Docker setups auto-generate a Neo4j password. Find it like this:

```powershell
# Check docker-compose.yml for the password:
Get-Content C:\BloodHound\docker-compose.yml | Select-String "NEO4J_SECRETS_PASSWORD"

# OR check the container's environment:
docker exec bloodhound-ce-neo4j-1 env | findstr NEO4J

# OR check Docker logs (look for the line that shows the password):
docker compose logs bloodhound | Select-String "password"
```

### Step 2.5: Verify Neo4j is accessible

```powershell
# Open http://localhost:7474 in your browser
# Login: neo4j / bloodhoundcommunityedition
# (Use whatever password you set in docker-compose.yml)
# You should see the Neo4j Browser interface

# Neo4j Bolt port (7687) is what our app uses to connect
# Test it:
Test-NetConnection -ComputerName localhost -Port 7687
# Should show: TcpTestSucceeded : True
```

---

## 3. Installing Ollama (Free Local AI)

Ollama runs the AI model that generates executive summaries. It runs locally — no internet needed after download.

### Windows
```powershell
# 1. Download from https://ollama.com/download/windows
# 2. Run the installer (it installs as a background service)
# 3. After install, open Command Prompt:
ollama --version

# 4. Download the AI model (~4 GB download):
ollama pull llama3.1:latest

# 5. Verify it works:
ollama list
# Should show: llama3.1:latest

# The API will be available at: http://localhost:11434
```

### Linux
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.1:latest
ollama list
```

---

## 4. Installing Python

### Windows
```powershell
# 1. Go to https://www.python.org/downloads/
# 2. Download Python 3.10, 3.11, or 3.12
# 3. Run the installer
#    ⚠️ IMPORTANT: CHECK "Add Python to PATH" at the bottom of the first screen
# 4. After install, open a NEW Command Prompt:
python --version
# Should show: Python 3.x.x
```

### Linux
```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv
python3 --version
```

---

## 5. Installing the AD Assessment App

### Download/Extract the App
```powershell
# Extract the app package to C:\AD_Assessment or D:\AD_Assessment (any drive)
# Example: D:\AD_Assessment\

# Navigate to the app folder:
cd D:\AD_Assessment
```

### Install App Dependencies
```powershell
# Inside the app folder, run:
pip install -r requirements.txt

# If requirements.txt is missing, install individually:
pip install streamlit plotly pyvis neo4j reportlab openpyxl requests
```

---

## 6. Configuring the App to Connect to Neo4j

### Default Configuration (works if you used Docker with default password)

The app defaults to:
- Neo4j address: `bolt://localhost:7687`
- Username: `neo4j`
- Password: `bloodhoundcommunityedition`

If you changed the password in docker-compose.yml, set it as an environment variable:

#### Windows (Command Prompt)
```cmd
set NEO4J_PASSWORD=your_new_password
streamlit run app.py
```

#### Windows (PowerShell)
```powershell
$env:NEO4J_PASSWORD = "your_new_password"
streamlit run app.py
```

#### Linux / Mac
```bash
export NEO4J_PASSWORD="your_new_password"
streamlit run app.py
```

### All Available Configuration Options

| Environment Variable | Default | When to Change |
|---------------------|---------|----------------|
| `NEO4J_PASSWORD` | `bloodhoundcommunityedition` | If you changed it in Docker |
| `NEO4J_URI` | `bolt://localhost:7687` | If Neo4j is on a different computer |
| `NEO4J_USER` | `neo4j` | Rarely changed |
| `OLLAMA_URL` | `http://localhost:11434/api/generate` | If Ollama is on a different computer |
| `OLLAMA_MODEL` | `llama3.1:latest` | If you use a different model |
| `CLIENT_NAME` | `Default_Client` | Override in the app sidebar |

---

## 7. Launching the App

```powershell
cd D:\AD_Assessment

# If you changed the Neo4j password, set it first:
$env:NEO4J_PASSWORD = "YourNewPassword123"

# Launch the app:
streamlit run app.py
```

Your browser will open to `http://localhost:8501`

---

## 8. What To Do After Installation (Next Steps)

Once everything is installed and the app is running:

1. **Collect AD data** — Run SharpHound on a domain-joined computer (see DATA_COLLECTION.md)
2. **Import into BloodHound** — Upload the SharpHound .zip file to BloodHound CE web UI at http://localhost:8080
3. **Collect Azure data** (optional) — Run AzureHound and copy `azurehound.json` to the `inputs/` folder
4. **Use the app** — Open http://localhost:8501, select client, click "Generate All Reports"
5. **Review findings** — Open the generated PDF and Excel files from `outputs/<Client>/v<version>/`

---

## 9. What to Do If Something Goes Wrong

### "Neo4j connection failed" error
1. Is Docker running? Open Docker Desktop and check
2. Is BloodHound CE started? Run: `docker compose ps` in the BloodHound folder
3. Wait 30 seconds and try again (Neo4j can be slow to start)
4. Check password: The password in the app must match the one in docker-compose.yml
5. Can't find docker-compose.yml? Look in C:\BloodHound\ (or wherever you ran `docker compose up`)

### "BloodHound web UI (http://localhost:8080) not loading"
1. Is Docker running? Check Docker Desktop/Docker service
2. Run `docker compose ps` in the BloodHound folder — you should see 3 containers running:
   - `bloodhound-ce-neo4j-1` (Neo4j database)
   - `bloodhound-ce-bloodhound-1` (Backend API)
   - `bloodhound-ce-bloodhound-ui-1` (Frontend web UI)
3. If some are missing or restarting: `docker compose logs bloodhound-ui` to see errors
4. Wait 2–3 minutes after first `docker compose up -d` — first-time setup downloads images
5. Restart everything: `docker compose down && docker compose up -d`

### "Cannot log into BloodHound web UI at http://localhost:8080"
1. BloodHound CE web admin uses DIFFERENT credentials than Neo4j
2. Default BloodHound CE credentials: username `admin`, password `admin` (some versions: `BloodHound`)
3. NOT the same as Neo4j username `neo4j` and password you set in docker-compose.yml
4. If you forgot the web admin password, reset it:
   ```powershell
   docker exec -it bloodhound-ce-bloodhound-1 bloodhound-cli reset-password --username admin --password "NewPassword"
   ```
1. Is Docker running? Open Docker Desktop and check
2. Is BloodHound CE started? Run: `docker compose ps` in the BloodHound folder
3. Wait 30 seconds and try again (Neo4j can be slow to start)
4. Check password: The password in the app must match the one in docker-compose.yml
5. Can't find docker-compose.yml? Look in C:\BloodHound\ (or wherever you ran `docker compose up`)

### "Ollama not responding" or AI button hangs
1. Is Ollama installed? Run: `ollama --version`
2. Is the model downloaded? Run: `ollama list`
3. If no model shown: `ollama pull llama3.1:latest` (takes 5–15 minutes)
4. Restart Ollama from the system tray (Windows) or run: `ollama serve`

### Port already in use
- Port 7687 used by another app? Change Neo4j port in docker-compose.yml and set `NEO4J_URI=bolt://localhost:7688`
- Port 8501 used by another app? Change Streamlit port: `streamlit run app.py --server.port 8502`

### "Python is not recognized"
- You forgot to check "Add Python to PATH" during installation
- Reinstall Python and CHECK the box, or add Python to PATH manually

---

## 10. Where to Install Each Component

| Component | Install On | Why |
|-----------|-----------|-----|
| **AD Assessment App** | Your laptop or any Windows/Linux server | Lightweight — runs anywhere |
| **BloodHound CE (Docker + Neo4j)** | Same machine as app (for simplicity) or a server | Docker handles everything |
| **Ollama** | Same machine as app (for simplicity) | Local AI — no data leaves your network |
| **SharpHound** | A domain-joined Windows computer | Must be inside the AD network |
| **AzureHound** | Any computer with internet | Just needs Azure login |

---

## 11. Security Checklist (for Production)

- [ ] Change default Neo4j password in docker-compose.yml
- [ ] Changed the Docker port 8080/7474/7687 from being exposed to the internet
- [ ] Running the app behind a password-protected web page (Nginx + basic auth)
- [ ] Using HTTPS (not plain HTTP) for remote access
- [ ] Deleted SharpHound .zip files after importing to BloodHound
- [ ] Deleted `azurehound.json` after importing to BloodHound CE (contains refresh tokens)
- [ ] Set `BASE_OUTPUT_DIR` to encrypted drive if storing sensitive client data

---

## Appendix: Quick Install Summary (for experienced users)

```powershell
# 1. Install Docker Desktop (https://www.docker.com)
# 2. Install Ollama (https://ollama.com)
# 3. Install Python 3.10+ (https://python.org)

# 4. Start BloodHound CE + Neo4j
mkdir C:\BloodHound; cd C:\BloodHound
curl -O https://raw.githubusercontent.com/BloodHoundAD/BloodHound/main/examples/docker-compose/docker-compose.yml
docker compose up -d

# 5. Download AI model
ollama pull llama3.1:latest

# 6. Setup the app
cd D:\AD_Assessment
pip install -r requirements.txt
streamlit run app.py
```
