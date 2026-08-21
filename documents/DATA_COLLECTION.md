# Data Collection Guide — SharpHound & AzureHound

## Overview

This app requires two data sources:

| Source | Tool | What it collects | Output |
|--------|------|-----------------|--------|
| **Active Directory** | SharpHound | Users, groups, computers, GPOs, OUs, ACLs, trust relationships | `.zip` file → import into BloodHound CE (Neo4j) |
| **Azure / Entra ID** | AzureHound | Azure AD users, groups, service principals, roles, conditional access | `azurehound.json` → upload to BloodHound CE web UI |

---

## 1. SharpHound — AD Data Collection

### 1.1 What is SharpHound?

SharpHound is the BloodHound data collector. It enumerates Active Directory objects and their relationships via LDAP queries, RPC calls, and SMB sessions. The output is a `.zip` file that must be imported into Neo4j via BloodHound CE.

### 1.2 Prerequisites

- **Domain-joined Windows machine** (or Linux with .NET and domain credentials)
- **Account with domain user rights** (Domain Admin is NOT required; Domain User is sufficient for most data)
- **Network access** to Domain Controllers (ports 389/636, 135/445)
- **BloodHound CE** installed and Neo4j running (see PREREQUISITES.md)

### 1.3 Installation

#### Windows

```powershell
# Option 1: Download pre-built binary
# Go to https://github.com/BloodHoundAD/SharpHound/releases/latest
# Download SharpHound.exe

# Option 2: Via Chocolatey
choco install sharphound -y

# Option 3: From PowerShell Gallery
Install-Module -Name Sharphound -Force
Import-Module Sharphound
```

#### Linux

```bash
# Install .NET runtime if not present
sudo apt install -y dotnet-runtime-8.0

# Download SharpHound Linux binary
wget https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound-linux-x64.zip
unzip SharpHound-linux-x64.zip -d sharphound
cd sharphound
chmod +x SharpHound
```

### 1.4 Data Collection Commands

#### Standard Collection (Recommended)

```powershell
# Windows — All collection methods, output to current directory
.\SharpHound.exe --CollectionMethods All --OutputDirectory C:\BH_Data

# Linux
./SharpHound --CollectionMethods All --OutputDirectory /tmp/BH_Data
```

#### With Loopback / Session Collection (for Tier 0 analysis)

```powershell
# Includes computer sessions (requires admin rights on target computers)
.\SharpHound.exe --CollectionMethods All,Session --OutputDirectory C:\BH_Data
```

#### Stealth Collection (minimal noise)

```powershell
# Only basic AD objects, no session data, reduces network traffic by ~80%
.\SharpHound.exe --CollectionMethods Group,LocalAdmin,ACL,Trusts --OutputDirectory C:\BH_Data
```

#### Large Domain / Multi-Domain Forest

```powershell
# Use multiple collectors per domain to distribute load
# Run simultaneously on separate domain-joined machines
.\SharpHound.exe --CollectionMethods All --Domain acme.com --OutputDirectory C:\BH_Data
.\SharpHound.exe --CollectionMethods All --Domain subsidiary.com --OutputDirectory C:\BH_Data
```

#### Using Alternate Credentials

```powershell
# Provide explicit domain credentials (bypasses current user context)
.\SharpHound.exe --CollectionMethods All --Domain acme.com `
    --LdapUsername ACME\svc-bh-collect `
    --LdapPassword "YourPassword" `
    --OutputDirectory C:\BH_Data
```

### 1.5 Collection Time Estimates

| Domain Size | Objects | Collection Method | Estimated Time | Output Size |
|-------------|---------|-------------------|---------------|-------------|
| Small | < 5,000 | All | 2–5 minutes | 1–5 MB |
| Medium | 5K–50K | All | 5–20 minutes | 5–50 MB |
| Large | 50K–200K | All | 20–60 minutes | 50–200 MB |
| Enterprise | >200K | All | 1–4 hours | 200 MB–1 GB |

### 1.6 Importing into BloodHound CE

```powershell
# 1. Ensure Neo4j is running
#    http://localhost:7474 (username: neo4j, password: bloodhoundcommunityedition)

# 2. Open BloodHound CE in browser
#    http://localhost:8080 (or wherever BloodHound CE is hosted)

# 3. Upload the .zip file
#    BloodHound UI → Upload Data → Select .zip file
#    OR via BloodHound CE REST API:
```

```bash
# Via REST API (scripted upload)
curl -X POST \
  -F "file=@/tmp/BH_Data/20260519120000_BloodHound.zip" \
  http://localhost:8080/api/v1/upload/file
```

### 1.7 Post-Collection Cleanup

```powershell
# Delete collected .zip files after import to avoid data leakage
Remove-Item C:\BH_Data\*.zip -Force

# The SharpHound binary itself leaves no persistent footprint
# unless you installed it system-wide
```

---

## 2. AzureHound — Azure/Entra ID Data Collection

### 2.1 What is AzureHound?

AzureHound collects Azure AD (Entra ID) object relationships including users, groups, service principals, administrative units, role assignments, conditional access policies, and device registrations. It outputs a single `azurehound.json` file that must be uploaded to BloodHound CE web UI — the app reads the data from Neo4j, not the JSON file directly.

### 2.2 Prerequisites

- **Azure AD tenant** with appropriate permissions
- **Azure CLI** installed (optional, for auth)
- **Internet access** to `login.microsoftonline.com` and `graph.microsoft.com`

### 2.3 Required Azure Permissions

The AzureHound identity needs at minimum:

| Permission | Type | Purpose |
|------------|------|---------|
| `Directory.Read.All` | Application or Delegated | Read Azure AD directory data |
| `Global Reader` role | Azure AD role | Alternative: assign to user account |

**For full data collection**, use an account with:
- `Global Reader` or `Global Administrator`
- `Application.Read.All` (to enumerate service principals and apps)

### 2.4 Installation

#### Windows

```powershell
# Download from: https://github.com/BloodHoundAD/AzureHound/releases/latest
# Extract azurehound.exe

# Or via PowerShell:
Invoke-WebRequest -Uri "https://github.com/BloodHoundAD/AzureHound/releases/latest/download/azurehound-windows-amd64.zip" `
    -OutFile "azurehound.zip"
Expand-Archive -Path azurehound.zip -DestinationPath .
```

#### Linux

```bash
wget https://github.com/BloodHoundAD/AzureHound/releases/latest/download/azurehound-linux-amd64.zip
unzip azurehound-linux-amd64.zip
chmod +x azurehound
```

### 2.5 Authentication

```powershell
# Method 1: Interactive device login (recommended for ad-hoc)
.\azurehound.exe login

# Follow the on-screen instructions:
# 1. Open https://microsoft.com/devicelogin
# 2. Enter the code shown
# 3. Authenticate with your Azure AD account

# Method 2: Using existing Azure CLI session
az login
.\azurehound.exe login --use-cli

# Method 3: Service principal (automated / CI/CD)
.\azurehound.exe login `
    --tenant-id "your-tenant-id" `
    --client-id "your-sp-client-id" `
    --client-secret "your-sp-secret"
```

### 2.6 Data Collection

```powershell
# Standard collection (all objects)
.\azurehound.exe collect --output azurehound.json

# Collection with specific scope
.\azurehound.exe collect --output azurehound.json --tenant-id "your-tenant-id"

# Verbose output for troubleshooting
.\azurehound.exe collect --output azurehound.json --verbose
```

### 2.7 Collection Time Estimates

| Tenant Size | Objects | Estimated Time | Output Size |
|-------------|---------|---------------|-------------|
| Small | < 1,000 | 30–60 seconds | 1–5 MB |
| Medium | 1K–10K | 1–5 minutes | 5–20 MB |
| Large | >10K | 5–15 minutes | 20–100 MB |

### 2.8 Post-Collection

```powershell
# Upload the output to BloodHound CE web UI
# Open http://localhost:8080 → Upload Data → Select azurehound.json
```

---

## 3. Complete Data Collection Workflow

### Typical Engagement Flow

```
Phase 1: Scope
  1. Identify domains to assess (prod, dev, subdomains)
  2. Identify Azure tenants to assess
  3. Obtain credentials/permissions

Phase 2: Collect AD (SharpHound)
  4. Deploy SharpHound to domain-joined machine(s)
  5. Run: .\SharpHound.exe --CollectionMethods All --OutputDirectory C:\BH_Data
  6. Transfer .zip file to machine with BloodHound CE
  7. Import .zip into BloodHound CE UI

Phase 3: Collect Azure (AzureHound)
   8. Run: .\azurehound.exe login
   9. Run: .\azurehound.exe collect --output azurehound.json
   10. Upload azurehound.json to BloodHound CE web UI at http://localhost:8080

Phase 4: Assess
   11. Launch the assessment app: streamlit run app.py
   12. Select client, load data, generate reports
```

### Sample PowerShell Script (Windows)

```powershell
# collect_all.ps1 — Run from assessment server

param(
    [Parameter(Mandatory)]
    [string]$ClientName,

    [Parameter(Mandatory)]
    [string]$Domain
)

$date = Get-Date -Format "yyyy-MM-dd"
$bhDir = "C:\BH_Data_$ClientName"

Write-Host "=== AD Security Assessment Data Collection ===" -ForegroundColor Cyan
Write-Host "Client: $ClientName"
Write-Host "Domain: $Domain"
Write-Host "Date:   $date"
Write-Host ""

# Step 1: Collect AD data with SharpHound
Write-Host "[1/3] Running SharpHound..." -ForegroundColor Yellow
New-Item -ItemType Directory -Path $bhDir -Force | Out-Null
.\SharpHound.exe --CollectionMethods All --Domain $Domain --OutputDirectory $bhDir
Write-Host "[OK] SharpHound complete" -ForegroundColor Green

# Step 2: Collect Azure data with AzureHound
Write-Host "[2/3] Running AzureHound..." -ForegroundColor Yellow
.\azurehound.exe login
.\azurehound.exe collect --output "azurehound.json"
Write-Host "[OK] AzureHound complete" -ForegroundColor Green

Write-Host "[3/3] Data collection complete" -ForegroundColor Green
Write-Host "  AD data:     $bhDir"
Write-Host "  Azure data:  azurehound.json"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Import SharpHound .zip into BloodHound CE (http://localhost:8080)"
Write-Host "  2. Import azurehound.json into BloodHound CE"
Write-Host "  3. Launch assessment app: streamlit run app.py"
```

### Sample Bash Script (Linux)

```bash
#!/bin/bash
# collect_all.sh — Run from assessment server

CLIENT_NAME="${1:-Default_Client}"
DOMAIN="${2:-acme.com}"
DATE=$(date +%Y-%m-%d)
BH_DIR="/tmp/BH_Data_$CLIENT_NAME"

echo "=== AD Security Assessment Data Collection ==="
echo "Client: $CLIENT_NAME"
echo "Domain: $DOMAIN"
echo "Date:   $DATE"
echo ""

# Step 1: Collect AD data
echo "[1/3] Running SharpHound..."
mkdir -p "$BH_DIR"
./SharpHound --CollectionMethods All --Domain "$DOMAIN" --OutputDirectory "$BH_DIR"
echo "[OK] SharpHound complete"

# Step 2: Collect Azure data
echo "[2/3] Running AzureHound..."
./azurehound login
./azurehound collect --output "azurehound.json"
echo "[OK] AzureHound complete"

echo "[3/3] Done"
echo "  AD data:     $BH_DIR"
echo "  Azure data:  azurehound.json"
echo ""
echo "Next steps:"
echo "  1. Import SharpHound .zip into BloodHound CE (http://localhost:8080)"
echo "  2. Import azurehound.json into BloodHound CE"
echo "  3. Launch assessment app: streamlit run app.py"
```

---

## 4. Troubleshooting Data Collection

### SharpHound

| Problem | Likely Cause | Solution |
|---------|-------------|----------|
| "Access Denied" on LDAP | Account lacks read permissions | Use domain user account; Domain Admin not required but certain attributes need read |
| No session data collected | No admin rights on target machines | Use `--CollectionMethods Group,LocalAdmin,ACL,Trusts` without Session |
| Collection very slow | Large domain or network latency | Run on domain-joined machine inside same site as DC; use "Stealth Collection" |
| Empty output / 0 objects | Wrong domain or connectivity | Verify `--Domain` parameter; test LDAP connectivity: `nltest /dsgetdc:domain.com` |
| "Port 445 connection failed" | SMB blocked by firewall | Ensure port 445 is open between collector and DCs; use `--CollectionMethods Group` to skip SMB methods |

### AzureHound

| Problem | Likely Cause | Solution |
|--------|-------------|----------|
| "Authentication failed" | Invalid tenant ID or permissions | Verify Azure AD tenant; ensure user/SP has `Directory.Read.All` |
| "Insufficient privileges" | Account lacks role | Assign `Global Reader` or `Directory.Read.All` API permission |
| Empty output | No data or no access to objects | Check tenant has Azure AD objects; use `--verbose` flag |
| Rate limiting | Too many API calls | Wait and retry; AzureHound handles throttling automatically |
| Token expired | Refresh token expired | Re-run `azurehound login` |
