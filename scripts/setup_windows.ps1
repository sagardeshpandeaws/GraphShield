<#
.SYNOPSIS
    GraphShield - Windows Installer
.DESCRIPTION
    Installs GraphShield to any drive, creates necessary folders,
    installs Python dependencies, and sets up desktop shortcuts.

    Run this from the extracted package folder:
        powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1

    Or double-click (if ExecutionPolicy allows), otherwise run from PowerShell ISE.
#>

param(
    [string]$InstallDir = "",
    [switch]$SkipDeps = $false
)

$ErrorActionPreference = "Stop"
$ScriptRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

# ─── BANNER ────────────────────────────────────────────────
Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  GraphShield - Setup" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

# ─── SELECT INSTALL DIRECTORY ──────────────────────────────
if (-not $InstallDir) {
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\' }
    Write-Host "Available drives:" -ForegroundColor Yellow
    $drives | ForEach-Object { Write-Host "  $($_.Root)  ($($_.Used/1GB -as [int]) GB used of $($_.Free/1GB -as [int]) GB free)" }

    $selectedDrive = Read-Host "Enter drive letter (e.g., D) to install, or press Enter for current directory"
    if ($selectedDrive) {
        $InstallDir = "$($selectedDrive.ToUpper()):\GraphShield"
    } else {
        $InstallDir = $ScriptRoot
    }
}

# ─── CREATE FOLDERS ───────────────────────────────────────
Write-Host "[1/6] Creating folders..." -ForegroundColor Green
$folders = @(
    $InstallDir,
    Join-Path $InstallDir "inputs",
    Join-Path $InstallDir "outputs",
    Join-Path $InstallDir "client_profiles",
    Join-Path $InstallDir "evidence",
    Join-Path $InstallDir "logs"
)
foreach ($f in $folders) {
    if (-not (Test-Path $f)) {
        New-Item -ItemType Directory -Path $f -Force | Out-Null
        Write-Host "  Created: $f"
    } else {
        Write-Host "  Exists:  $f"
    }
}

# ─── COPY APP FILES ────────────────────────────────────────
Write-Host "[2/6] Copying application files..." -ForegroundColor Green
$exclude = @("__pycache__", ".git", "build", "dist", "*.pyc", ".venv", "venv")
$items = Get-ChildItem -Path $ScriptRoot -Exclude $exclude
foreach ($item in $items) {
    $dest = Join-Path $InstallDir $item.Name
    if ($item.PSIsContainer) {
        Copy-Item -Path $item.FullName -Destination $dest -Recurse -Force
    } else {
        Copy-Item -Path $item.FullName -Destination $dest -Force
    }
}
Write-Host "  Files copied to: $InstallDir"

# ─── CREATE desktop shortcut ───────────────────────────────
Write-Host "[3/6] Creating desktop shortcut..." -ForegroundColor Green
$launcherPath = Join-Path $InstallDir "scripts\Launch_App.bat"
@"
@echo off
title AD Security Assessment
cd /d "%~dp0"
echo =====================================================
echo  AD Security Assessment Platform
echo =====================================================
echo.
echo Starting Streamlit app...
echo Open http://localhost:8501 in your browser
echo.
python -m streamlit run app.py --server.port=8501 --server.address=127.0.0.1
pause
"@ | Out-File -FilePath $launcherPath -Encoding ASCII

$shortcutPath = [Environment]::GetFolderPath("Desktop") + "\GraphShield.lnk"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $launcherPath
$shortcut.WorkingDirectory = $InstallDir
$shortcut.Description = "Launch AD Security Assessment Platform"
$shortcut.Save()
Write-Host "  Shortcut created on desktop"

# ─── CREATE START MENU shortcut ────────────────────────────
Write-Host "[4/6] Creating Start Menu shortcut..." -ForegroundColor Green
$startMenuPath = [Environment]::GetFolderPath("Programs") + "\GraphShield"
if (-not (Test-Path $startMenuPath)) {
    New-Item -ItemType Directory -Path $startMenuPath -Force | Out-Null
}
$startMenuShortcut = Join-Path $startMenuPath "GraphShield.lnk"
$shortcut2 = $shell.CreateShortcut($startMenuShortcut)
$shortcut2.TargetPath = $launcherPath
$shortcut2.WorkingDirectory = $InstallDir
$shortcut2.Description = "Launch AD Security Assessment Platform"
$shortcut2.Save()
Write-Host "  Start Menu entry created"

# ─── INSTALL PYTHON DEPENDENCIES ───────────────────────────
if (-not $SkipDeps) {
    Write-Host "[5/6] Installing Python dependencies..." -ForegroundColor Green
    $reqFile = Join-Path $InstallDir "documents\requirements.txt"
    if (Test-Path $reqFile) {
        try {
            & pip install -r $reqFile 2>&1 | ForEach-Object { Write-Host "  $_" }
            Write-Host "  Dependencies installed"
        } catch {
            Write-Host "  WARNING: pip install failed. Run manually:" -ForegroundColor Yellow
            Write-Host "    cd $InstallDir && pip install -r documents\requirements.txt"
        }
    } else {
        Write-Host "  requirements.txt not found, skipping" -ForegroundColor Yellow
    }
} else {
    Write-Host "[5/6] Skipping Python dependencies (-SkipDeps)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Green
Write-Host "  SETUP COMPLETE!" -ForegroundColor Green
Write-Host "=====================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Installed to: $InstallDir" -ForegroundColor White
Write-Host "  Desktop shortcut: GraphShield.lnk" -ForegroundColor White
Write-Host ""
Write-Host "  BEFORE LAUNCHING THE APP, ensure:" -ForegroundColor Yellow
Write-Host "    1. BloodHound CE (Docker) is running -- see PREREQUISITES.md"
Write-Host "    2. Ollama is running -- see PREREQUISITES.md"
Write-Host "    3. SharpHound data has been collected and imported to BloodHound"
Write-Host "       See DATA_COLLECTION.md for instructions"
Write-Host ""
Write-Host "  To launch:" -ForegroundColor Cyan
Write-Host "    - Double-click the desktop shortcut: GraphShield"
Write-Host "    OR"
Write-Host "    - Run: cd $InstallDir && streamlit run app.py"
Write-Host ""
Write-Host "  Documentation:" -ForegroundColor Cyan
Write-Host "    - $InstallDir\documents\PREREQUISITES.md"
Write-Host "    - $InstallDir\documents\USER_MANUAL.md"
Write-Host ""
Read-Host "Press ENTER to exit"
