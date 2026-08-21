"""
Build GraphShield into a standalone Windows executable (onefile).

Usage:
    python scripts\\build_exe.py                              # Standard build
    python scripts\\build_exe.py --logo path\\to\\logo.png     # Bundle a logo
    python scripts\\build_exe.py --icon path\\to\\icon.png     # PNG auto-converted to ICO

Output:
    dist/GraphShield.exe — single file, no Python required on target machine.

Copy the EXE into a folder and run it. Folders (client_profiles, outputs,
logs) are auto-created on first run next to the EXE.
"""
import os
import sys
import shutil
import subprocess


def _file_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _clean_path(path, label=None):
    """Remove a file or directory with retries."""
    if not os.path.exists(path):
        return
    label = label or os.path.basename(path)
    for attempt in range(5):
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            print(f"[*] Cleaned {label}")
            return
        except PermissionError:
            if attempt < 4:
                import time; time.sleep(2)
            else:
                subprocess.check_call(f'cmd /c "rmdir /s /q "{path}"" 2>nul', shell=True)
                if os.path.exists(path):
                    print(f"[!] Could not fully clean {label}, continuing anyway")


def main():
    logo_path = None
    if "--logo" in sys.argv:
        idx = sys.argv.index("--logo")
        if idx + 1 < len(sys.argv):
            logo_path = sys.argv[idx + 1]
            if not os.path.exists(logo_path):
                print(f"[-] Logo file not found: {logo_path}")
                sys.exit(1)

    icon_path = None
    if "--icon" in sys.argv:
        idx = sys.argv.index("--icon")
        if idx + 1 < len(sys.argv):
            icon_path = sys.argv[idx + 1]
            if not os.path.exists(icon_path):
                print(f"[-] Icon file not found: {icon_path}")
                sys.exit(1)
            # Auto-convert PNG to ICO if needed
            if icon_path.lower().endswith(".png"):
                try:
                    from PIL import Image
                    ico_path = icon_path.rsplit(".", 1)[0] + ".ico"
                    img = Image.open(icon_path)
                    img.save(ico_path, format="ICO", sizes=[(256, 256)])
                    icon_path = ico_path
                    print(f"[+] PNG converted to ICO: {ico_path}")
                except ImportError:
                    print(f"[-] Pillow not installed. Install it: pip install Pillow")
                    print(f"    Or provide a .ico file directly (not .png)")
                    sys.exit(1)

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    exe_name = "GraphShield"

    print(f"[*] Building GraphShield...")
    print(f"[*] Output: dist/{exe_name}.exe (single file)")

    # Clean previous build artifacts
    _clean_path(os.path.join(root, "build"), "build/")
    _clean_path(os.path.join(root, "brand_logo"), "brand_logo/")
    for spec_name in [f"{exe_name}.spec"]:
        _clean_path(os.path.join(root, spec_name), spec_name)

    # Create inputs/ directory if missing (needed for azurehound data path)
    inputs_dir = os.path.join(root, "inputs")
    if not os.path.exists(inputs_dir):
        os.makedirs(inputs_dir)

    # Copy logo to brand_logo/ directory for PyInstaller bundling
    brand_logo_dir = os.path.join(root, "brand_logo")
    os.makedirs(brand_logo_dir, exist_ok=True)
    if logo_path:
        shutil.copy2(logo_path, os.path.join(brand_logo_dir, "logo.png"))
        print(f"[+] Logo bundled: {logo_path}")
    else:
        print("[*] No logo provided. App will run without custom branding.")

    # Find pyvis templates directory for bundling
    import importlib
    pyvis_templates = os.path.join(
        os.path.dirname(importlib.import_module('pyvis').__file__), 'templates'
    )

    cmd = [
        sys.executable, "-m", "PyInstaller",
        f"--name={exe_name}",
        "--onefile",
        *([f"--icon={icon_path}"] if icon_path else []),
        "--add-data", f"app.py{os.pathsep}.",
        "--add-data", f"client_profiles{os.pathsep}client_profiles",
        "--add-data", f"inputs{os.pathsep}inputs",
        "--add-data", f"documents/PREREQUISITES.md{os.pathsep}.",
        "--add-data", f"documents/USER_MANUAL.md{os.pathsep}.",
        "--add-data", f"documents/DATA_COLLECTION.md{os.pathsep}.",
        "--add-data", f"brand_logo{os.pathsep}.",
        "--add-data", f"{pyvis_templates}{os.pathsep}pyvis/templates",
        "--hidden-import=neo4j",
        "--collect-submodules=collectors",
        "--collect-submodules=analytics",
        "--collect-submodules=ai",
        "--hidden-import=reporting",
        "--collect-submodules=reporting",
        "--hidden-import=plotly",
        "--hidden-import=pyvis",
        "--hidden-import=reportlab",
        "--hidden-import=openpyxl",
        "--hidden-import=pandas",
        "--hidden-import=networkx",
        "--hidden-import=requests",
        "--hidden-import=cryptography",
        "--hidden-import=cryptography.hazmat.backends.openssl",
        "--hidden-import=cryptography.hazmat.primitives.asymmetric.rsa",
        "--hidden-import=cryptography.hazmat.primitives.asymmetric.padding",
        "--hidden-import=cryptography.hazmat.primitives.asymmetric.utils",
        "--hidden-import=cryptography.hazmat.primitives.hashes",
        "--hidden-import=cryptography.hazmat.primitives.serialization",
        "--collect-all=streamlit",
        "--collect-all=plotly",
        "--collect-all=cryptography",
        os.path.join(root, "main.py"),
    ]

    print("[*] Running PyInstaller (onefile mode)...")
    subprocess.check_call(cmd, cwd=root)

    exe_path = os.path.join(root, "dist", f"{exe_name}.exe")

    # Clean up temporary brand_logo directory
    if os.path.exists(brand_logo_dir):
        shutil.rmtree(brand_logo_dir)

    print(f"\n[+] BUILD COMPLETE!")
    print(f"    EXE:    {exe_path}")
    print(f"    Size:   {_file_size(exe_path) / 1024 / 1024:.1f} MB")
    if logo_path:
        print(f"    Logo:   {os.path.basename(logo_path)}")
    if icon_path:
        print(f"    Icon:   {os.path.basename(icon_path)}")

    print()
    print("To distribute:")
    print(f"  1. Create a folder on the target machine (e.g. C:\\GraphShield\\)")
    print(f"  2. Copy {exe_name}.exe into that folder")
    print(f"  3. Double-click the EXE — folders (outputs, client_profiles, logs) auto-create")
    print(f"  4. Open http://localhost:8501 in your browser")
    print()
    print("Azure/Entra ID (optional):")
    print(f"  - Place AzureHound JSON export(s) in 'inputs/' folder next to the EXE")
    print("  - The app will auto-detect and load all .json files")
    print("  - Multiple files are merged (e.g. separate tenant scans)")


if __name__ == "__main__":
    main()
