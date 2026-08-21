import json
import os
from datetime import datetime


def export_json(findings, chains, risk=None, output=None, client_config=None):
    cfg = client_config or {}
    client_name = cfg.get("client_name", "Client")
    engagement = cfg.get("engagement_id", "")
    assessor = cfg.get("assessor", "Security Assessment Team")
    data_ver = cfg.get("data_version", "1.0")

    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)

    clean_findings = []
    for f in findings:
        clean_findings.append({
            "id": f.get("id"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "source": f.get("source"),
            "impact": f.get("impact"),
            "remediation": f.get("remediation", []),
            "detection": f.get("detection", []),
            "mitre": f.get("mitre", {}),
            "compliance": f.get("compliance", {}),
            "ad_objects": f.get("ad_objects", {}),
            "has_evidence": f.get("has_evidence", False),
        })

    clean_chains = []
    for c in chains:
        clean_chains.append({
            "risk": c.get("risk"),
            "severity": c.get("severity"),
            "attack_path": c.get("attack_path"),
            "mitre": c.get("mitre", {}),
            "ad_objects": c.get("ad_objects", {}),
        })

    active = [f for f in findings if f.get("has_evidence", False)]

    report = {
        "assessment": {
            "platform": "GraphShield Hybrid Identity Security Platform",
            "vendor": assessor,
            "client": client_name,
            "engagement_id": engagement,
            "data_version": data_ver,
            "generated": datetime.utcnow().isoformat(),
            "statistics": {
                "total_findings_configured": len(findings),
                "active_findings": len(active),
                "critical": sum(1 for f in active if f.get("severity") == "CRITICAL"),
                "high": sum(1 for f in active if f.get("severity") == "HIGH"),
                "medium": sum(1 for f in active if f.get("severity") == "MEDIUM"),
                "low": sum(1 for f in active if f.get("severity") == "LOW"),
                "total_attack_chains": len(chains),
                "assessment_scope": {
                    "groups": list({f.get("group") for f in findings if f.get("group")}),
                    "has_ad": any(f.get("source") == "Active Directory" for f in findings),
                    "has_az": any(f.get("source") == "Azure" for f in findings),
                },
            }
        },
        "risk": risk or {},
        "findings": clean_findings,
        "attack_chains": clean_chains,
    }

    if output:
        with open(output, "w", encoding="utf-8") as fp:
            json.dump(report, fp, indent=2, ensure_ascii=False)

    return report
