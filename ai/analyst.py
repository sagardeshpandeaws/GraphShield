import requests
import json
from config import OLLAMA_URL, OLLAMA_MODEL
from analytics.nhi_lifecycle import corroboration_label


def ask_ollama(
    findings,
    chains=None,
    risk=None,
):

    safe_findings = []

    for f in findings:

        ad = f.get("ad_objects", {})

        entry = {

            "id": f.get("id"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "source": f.get("source", "Active Directory"),
            "impact": f.get("impact"),
            "mitre": f.get("mitre"),
            "users": ad.get("users", []),
            "groups": ad.get("groups", []),
            "service_principals": ad.get("service_principals", []),
            "managed_identities": ad.get("managed_identities", []),
            "applications": ad.get("applications", []),
            "key_vaults": ad.get("key_vaults", []),
            "tenants": ad.get("tenants", []),
            "computers": ad.get("computers", []),
            "relationships": ad.get("relationships", [])
        }

        # NHI assessment only: attach the graph/log corroboration summary.
        # The key is omitted entirely for every other assessment so the
        # prompt for non-NHI findings is unchanged.
        nhi_label = corroboration_label(f)
        if nhi_label:
            entry["nhi_corroboration"] = nhi_label

        safe_findings.append(entry)

    safe_chains = []

    if chains:

        for c in chains:

            safe_chains.append({

                "risk": c.get("risk"),
                "severity": c.get("severity"),
                "source": c.get("source", ""),
                "attack_path": c.get("attack_path")
            })

    has_ad = any(f.get("source") in ("Active Directory", None) for f in findings)
    has_az = any(f.get("source") == "Azure" for f in findings)
    scope_parts = []
    if has_ad:
        scope_parts.append("on-prem Active Directory")
    if has_az:
        scope_parts.append("Azure/Entra ID")
    scope_text = " and ".join(scope_parts) if scope_parts else "Active Directory and Azure/Entra ID"
    both = has_ad and has_az
    biz_impact_line = "- Include both on-prem AD and Azure/Entra ID risks" if both else f"- Focus on {scope_text} risks"
    hybrid_line = "- Cover hybrid AD-to-Cloud attack paths where applicable" if both else ""
    remediate_line = "- Separate AD and Azure/Entra tasks where applicable" if both else f"- Focus on {scope_text} tasks"

    # NHI assessment only: identities confirmed by BOTH the Neo4j graph and the
    # Entra sign-in/audit log feed. Deduplicated per identity and sorted, so the
    # prompt stays deterministic. Empty when there is no feed or no overlap,
    # which keeps the prompt byte-identical to the pre-correlation behaviour.
    corroborated = {}
    for f in findings:
        corr = f.get("nhi_correlation") or {}
        if not corr.get("both_sources"):
            continue
        ident = corr.get("identity") or corr.get("app_id")
        if not ident:
            continue
        corroborated.setdefault(ident, {
            "identity": ident,
            "app_id": corr.get("app_id"),
            "neo4j_findings": list(corr.get("graph_findings") or []),
            "log_findings": list(corr.get("lifecycle_findings") or []),
        })
    nhi_corroborated = [corroborated[k] for k in sorted(corroborated)]

    nhi_block = ""
    nhi_output = ""
    if nhi_corroborated:
        nhi_block = f"""
---

NON-HUMAN IDENTITY - GRAPH + LOG CORROBORATION (NHI assessment only):
{json.dumps(nhi_corroborated, indent=2)}
"""
        nhi_output = """
# 6. NON-HUMAN IDENTITY CORROBORATION
- Cover ONLY the workload identities listed in the CORROBORATION block above; ignore all other identities
- State that each is confirmed by two independent sources: the Neo4j graph and the Entra sign-in/audit log feed
- Explain what each source contributes: the graph proves structural posture (ownership, privilege, consent, staleness), the logs prove temporal/behavioral lifecycle (recent activity, dormancy, attestation, rotation, anomalous sign-ins)
- Because both sources agree, rank these above single-source findings and give one combined remediation priority per identity
- Do not invent identities or findings that are not listed
"""

    prompt = f"""
You are a Principal Identity Security Architect.

You are writing a CISO-level executive report covering {scope_text}.

Use only the data provided.

DO NOT hallucinate new findings.

---

FINDINGS:
{json.dumps(safe_findings, indent=2)}

---

ATTACK CHAINS:
{json.dumps(safe_chains, indent=2)}

---

RISK SCORE:
{json.dumps(risk or {}, indent=2)}
{nhi_block}
---

OUTPUT FORMAT (STRICT):

# 1. EXECUTIVE SUMMARY
- 5 to 8 bullet points max

# 2. BUSINESS IMPACT
- Real-world impact on enterprise security and operations
- {biz_impact_line}

# 3. TOP RISKS
- Ranked list (Critical -> High -> Medium)
- Must reference attack paths if available

# 4. ATTACK PATH ANALYSIS
- Explain how compromise would happen step-by-step
- {hybrid_line if hybrid_line else "Focus on identified attack paths"}

# 5. 30-DAY REMEDIATION PLAN
- Week 1 / Week 2 / Week 3 / Week 4 breakdown
- {remediate_line}
- Actionable security engineering tasks
{nhi_output}
Keep it concise, executive-ready, and structured.
"""

    r = requests.post(
        OLLAMA_URL,
        json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.2
            }
        }
    )

    return r.json()["response"]
