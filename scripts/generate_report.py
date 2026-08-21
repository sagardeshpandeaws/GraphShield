"""
Standalone report generator for the GraphShield.

Usage:
    python scripts\generate_report.py --client "Client Name"
    python scripts\generate_report.py --client "Client Name" --version 2
    python scripts\generate_report.py --client "Client Name" --version 2 --output "custom/path"

Generates PDF, Excel, CSV, JSON, and ZIP package from cached data.
"""
import sys, os, json, shutil
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["STREAMLIT_RUN"] = "1"

from config import (
    BASE_OUTPUT_DIR, CLIENT_PROFILES_DIR,
    load_client_config, compute_env_stats,
    get_latest_client_profile, load_raw_cache,
    LOGO_PATH, setup_logging
)

setup_logging()

def generate_reports(client_name, version=None, output_dir=None):
    from analytics.finding_builder import FindingBuilder
    from analytics.risk_engine import RiskEngine
    from analytics.attack_chain import AttackChainBuilder
    from reporting.pdf_export import export_pdf
    from reporting.excel_export import export_excel
    from reporting.csv_export import export_csv
    from reporting.json_export import export_json
    from reporting.zip_package import create_package
    from reporting.ai_pdf_export import export_ai_pdf
    from ai.analyst import ask_ollama

    print(f"[*] Generating reports for client: {client_name}")
    cfg = load_client_config(client_name)
    if not cfg:
        print(f"[-] No profile found for: {client_name}")
        return

    data_ver = str(version) if version else cfg.get("data_version", "1")
    cache = load_raw_cache(client_name, data_ver)
    if not cache:
        print(f"[-] No cached data for {client_name} v{data_ver}. Load from Neo4j first.")
        return

    client_dir = os.path.join(BASE_OUTPUT_DIR, client_name, f"v{data_ver}")
    os.makedirs(client_dir, exist_ok=True)

    print(f"[*] Analyzing {len(cache)} data keys...")
    builder = FindingBuilder(cache)
    findings = builder.build()
    print(f"  -> {len(findings)} finding types evaluated")

    enriched = []
    for f in findings:
        if f.get("has_evidence"):
            enriched.append(f)
    print(f"  -> {len(enriched)} with evidence")

    risk_engine = RiskEngine(enriched)
    risk = risk_engine.calculate()
    print(f"  -> Risk score: {risk.get('score', '?')} ({risk.get('level', '?')})")

    chain_builder = AttackChainBuilder(enriched, cache, risk)
    chains = chain_builder.build()
    print(f"  -> {len(chains)} attack chains identified")

    env_stats = compute_env_stats(enriched, chains, risk, cache, cfg)
    print(f"  -> Environment stats computed")

    info = cfg.get("client_name", client_name).replace(" ", "_")
    date_tag = datetime.now().strftime("%Y-%m-%d")

    paths = {
        "report_pdf":   os.path.join(client_dir, f"{info}_GraphShield_Assessment_Report_{date_tag}.pdf"),
        "ai_report_pdf": os.path.join(client_dir, f"{info}_GraphShield_Executive_Security_Brief_{date_tag}.pdf"),
        "engineering_xlsx": os.path.join(client_dir, f"{info}_GraphShield_Engineering_{date_tag}.xlsx"),
        "findings_csv": os.path.join(client_dir, f"{info}_GraphShield_Findings_{date_tag}.csv"),
        "evidence_json": os.path.join(client_dir, f"{info}_GraphShield_Evidence_{date_tag}.json"),
        "attack_graph_html": os.path.join(client_dir, f"{info}_GraphShield_Attack_Graph_{date_tag}.html"),
        "zip_package":  os.path.join(client_dir, f"{info}_GraphShield_Package_{date_tag}.zip"),
    }

    print(f"\n[*] Generating PDF report...")
    export_pdf(enriched, chains, paths["report_pdf"], client_config=cfg, risk=risk, env_stats=env_stats)
    print(f"[+] PDF: {os.path.basename(paths['report_pdf'])}")

    print(f"[*] Generating Excel workbook...")
    export_excel(enriched, chains, paths["engineering_xlsx"], client_config=cfg, risk=risk, env_stats=env_stats)
    print(f"[+] Excel: {os.path.basename(paths['engineering_xlsx'])}")

    print(f"[*] Generating CSV...")
    export_csv(enriched, paths["findings_csv"])
    print(f"[+] CSV: {os.path.basename(paths['findings_csv'])}")

    print(f"[*] Generating evidence JSON...")
    export_json(enriched, paths["evidence_json"])
    print(f"[+] JSON: {os.path.basename(paths['evidence_json'])}")

    print(f"[*] Generating AI executive brief...")
    try:
        ollama_text = ask_ollama(findings=enriched, risk=risk, env_stats=env_stats, chains=chains)
        if ollama_text:
            export_ai_pdf(ollama_text, paths["ai_report_pdf"], findings=enriched, chains=chains, risk=risk, env_stats=env_stats, client_config=cfg)
    except Exception as e:
        print(f"  [!] AI brief skipped: {e}")
    if os.path.exists(paths.get("ai_report_pdf", "")):
        print(f"[+] AI Brief: {os.path.basename(paths['ai_report_pdf'])}")

    print(f"[*] Generating attack graph...")
    try:
        from analytics.graph_builder import build_attack_graph
        build_attack_graph(enriched, chains, paths["attack_graph_html"], client_config=cfg)
    except Exception as e:
        print(f"  [!] Attack graph skipped: {e}")
    if os.path.exists(paths.get("attack_graph_html", "")):
        print(f"[+] Attack Graph: {os.path.basename(paths['attack_graph_html'])}")

    print(f"[*] Creating ZIP package...")
    create_package(paths, paths["zip_package"])
    print(f"[+] ZIP: {os.path.basename(paths['zip_package'])}")

    print(f"\n  All reports generated in: {os.path.dirname(paths['report_pdf'])}")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    client_name = None
    version = None
    output_dir = None

    if "--client" in sys.argv:
        idx = sys.argv.index("--client")
        if idx + 1 < len(sys.argv):
            client_name = sys.argv[idx + 1]
    if "--version" in sys.argv:
        idx = sys.argv.index("--version")
        if idx + 1 < len(sys.argv):
            version = int(sys.argv[idx + 1])
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        if idx + 1 < len(sys.argv):
            output_dir = sys.argv[idx + 1]

    if not client_name:
        profiles = [f.replace(".json", "") for f in os.listdir(CLIENT_PROFILES_DIR) if f.endswith(".json")]
        if len(profiles) == 1:
            client_name = profiles[0]
            print(f"[*] Auto-detected client: {client_name}")
        else:
            print("Usage: python scripts\\generate_report.py --client \"Client Name\" [--version N] [--output path]")
            print(f"  Available profiles: {', '.join(profiles)}")
            sys.exit(1)

    generate_reports(client_name, version, output_dir)
