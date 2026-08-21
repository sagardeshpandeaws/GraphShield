import os
import sys
import subprocess
import socket


def _ps(cmd):
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=5
        )
        return r.stdout.strip()
    except:
        return ""


def check_os():
    if sys.platform != "win32":
        return (False, "Windows OS required")
    version = _ps("(Get-CimInstance Win32_OperatingSystem).Version")
    if version.startswith("10.") or version.startswith("6."):
        return (True, f"Windows {version}")
    return (True, f"Windows {version}")


def check_docker():
    try:
        r = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            containers = [c for c in r.stdout.strip().split("\n") if c]
            return (True, f"Running ({len(containers)} containers)")
        return (False, "Docker installed but not running")
    except FileNotFoundError:
        return (False, "Docker not found")
    except:
        return (False, "Docker check failed")


def check_neo4j():
    try:
        s = socket.create_connection(("127.0.0.1", 7687), timeout=3)
        s.close()
        return (True, "Port 7687 open")
    except:
        return (False, "Neo4j not reachable on localhost:7687")


def check_ollama():
    try:
        import requests
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        if r.status_code == 200:
            models = r.json().get("models", [])
            return (True, f"Running ({len(models)} models)")
        return (False, "Ollama API returned unexpected response")
    except:
        return (False, "Ollama not running on localhost:11434")


def check_disk_space(min_gb=2):
    try:
        import ctypes
        free_bytes = ctypes.c_ulonglong(0)
        ctypes.windll.kernel32.GetDiskFreeSpaceExW(
            ctypes.c_wchar_p(os.getcwd()), None, None, ctypes.pointer(free_bytes)
        )
        free_gb = free_bytes.value / (1024**3)
        if free_gb >= min_gb:
            return (True, f"{free_gb:.1f} GB free")
        return (False, f"Only {free_gb:.1f} GB free (need {min_gb} GB)")
    except:
        return (True, "Could not check")


def run_all():
    checks = [
        ("OS", check_os()),
        ("Docker", check_docker()),
        ("Neo4j", check_neo4j()),
        ("Ollama", check_ollama()),
        ("Disk Space", check_disk_space()),
    ]
    all_pass = True
    results = []
    for name, (ok, msg) in checks:
        results.append({"name": name, "ok": ok, "message": msg})
        if not ok:
            all_pass = False
    return {"pass": all_pass, "checks": results}
