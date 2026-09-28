"""
Proof-of-functioning report generator for GraphShield.

Generates every report format, for every assessment group, from synthetic
(sample) data so the platform can be demonstrated without a live Neo4j or a
real client dataset.

This mirrors the app.py analysis pipeline exactly:
    FindingBuilder().build(raw, selected_groups=[group])
 -> enrich_finding(f, raw)
 -> IdentityNormalizer().normalize(...)
 -> NHI lifecycle feed append + correlate_nhi_sources(...)
 -> RiskEngine().calculate(active_evidence)
 -> AttackChainBuilder(findings).build() + HybridAttackChain().analyze(...)
 -> export_pdf / export_excel / export_csv / export_json /
    export_ai_pdf / create_attack_graph / create_zip

Usage:
    python scripts\\generate_proof_reports.py
    python scripts\\generate_proof_reports.py --client "1st_Client"
    python scripts\\generate_proof_reports.py --version v3
    python scripts\\generate_proof_reports.py --output <dir>

Executive briefs are deterministic by default so proof runs are reproducible.
Pass --ai-groups (comma- or space-separated) to call Ollama instead, e.g.
    python scripts\\generate_proof_reports.py --ai-groups nhi_governance

All data is deterministic: no randomness, no wall-clock dependency in the
findings themselves, so repeated runs produce equivalent reports.
"""
import argparse
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["STREAMLIT_RUN"] = "1"

from analytics.attack_chain import AttackChainBuilder
from analytics.finding_builder import FindingBuilder
from analytics.finding_enrichment import enrich_finding
from analytics.groups import GROUPS, GROUP_ORDER
from analytics.hybrid_attack_chain import HybridAttackChain
from analytics.identity_normalizer import IdentityNormalizer
from analytics.nhi_lifecycle import (
    NHI_GROUP,
    build_lifecycle_findings,
    correlate_nhi_sources,
    lifecycle_dashboard_rows,
    load_lifecycle_feed,
)
from analytics.risk_engine import RiskEngine
from config import compute_env_stats, ensure_client_dirs, setup_logging
from reporting.ai_pdf_export import export_ai_pdf
from reporting.csv_export import export_csv
from reporting.excel_export import export_excel
from reporting.json_export import export_json
from reporting.pdf_export import export_pdf
from reporting.zip_package import create_zip

FIXED_TS = "2026-09-26T09:00:00Z"
FIXED_DATE = "2026-09-26"
TENANT = "corp.onmicrosoft.com"

# ── Synthetic workload identities ────────────────────────────────────────
# The NHI graph rows and the lifecycle feed deliberately share appIds so the
# two-source correlation produces real, verifiable matches.
SP_NO_OWNER = {
    "Principal": "prod-deploy-controller",
    "AppId": "b800a5c2-1111-1111-1111-111111111111",
    "PrincipalType": ["AZServicePrincipal"],
    "Tenant": TENANT,
}
SP_NO_OWNER_2 = {
    "Principal": "legacy-reporting-sp",
    "AppId": "b800a5c2-2222-2222-2222-222222222222",
    "PrincipalType": ["AZServicePrincipal"],
    "Tenant": TENANT,
}

DUMMY_LIFECYCLE_FEED = {
    "value": [
        {
            "id": "9001",
            "appId": "b800a5c2-1111-1111-1111-111111111111",
            "appDisplayName": "prod-deploy-controller",
            "servicePrincipalId": "11111111-2222-3333-4444-555555555555",
            "servicePrincipalName": "prod-deploy-controller",
            "createdDateTime": "2024-03-10T09:15:00Z",
            "signInDateTime": "2026-09-19T14:02:00Z",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0) attestation overdue nhifeed",
            "conditionalAccessStatus": "attestation overdue",
            "authenticationRequirement": "federated",
            "status": "orphan",
            "attestationStatus": "overdue",
            "attestationWindowDays": 90,
        },
        {
            "id": "9002",
            "appId": "b800a5c2-2222-2222-2222-222222222222",
            "appDisplayName": "legacy-reporting-sp",
            "servicePrincipalId": "66666666-7777-8888-9999-000000000000",
            "servicePrincipalName": "legacy-reporting-sp",
            "createdDateTime": "2023-06-01T10:00:00Z",
            "signInDateTime": "2026-09-24T08:41:00Z",
            "userAgent": "azure-powershell/7.4 rotation overdue orphan no owner nhifeed",
            "conditionalAccessStatus": "rotation overdue",
            "authenticationRequirement": "client_secret",
            "status": "orphan",
            "rotationStatus": "overdue",
            "rotationIntervalDays": 90,
        },
        {
            "id": "9003",
            "appId": "b800a5c2-3333-3333-3333-333333333333",
            "appDisplayName": "ci-pipeline-sp",
            "servicePrincipalId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "servicePrincipalName": "ci-pipeline-sp",
            "createdDateTime": "2025-01-20T12:00:00Z",
            "signInDateTime": "2026-09-25T22:10:00Z",
            "userAgent": "azure-cli/2.60 signin anomaly nhifeed",
            "conditionalAccessStatus": "signin anomaly",
            "authenticationRequirement": "managed_identity",
            "status": "active",
            "onboardingStatus": "unowned",
            "onboardingAgeDays": 240,
        },
    ]
}


def _ad_path(names, types):
    return {"Path": list(names), "PathTypes": list(types)}


def build_dummy_raw():
    """Synthetic collector output keyed exactly like the real Neo4j payload.

    One entry per query key in GROUP_QUERY_KEYS, using the BloodHound /
    AzureHound field names that analytics.finding_enrichment consumes.
    """
    users = ["svc_sql_sa@corp.local", "svc_backup@corp.local",
             "a.smith@corp.local", "j.doe@corp.local", "helpdesk@corp.local"]
    groups = ["Domain Admins@corp.local", "Enterprise Admins@corp.local",
              "Backup Operators@corp.local", "Tier0 Admins@corp.local",
              "Helpdesk@corp.local"]
    computers = ["DC01.corp.local", "SQL01.corp.local", "FS01.corp.local",
                 "WEB01.corp.local", "APP01.corp.local"]
    gpos = ["GPO-BackupPolicy@corp.local", "GPO-LogonScript@corp.local"]
    ous = ["OU=Workstations,OU=Corp,DC=corp,DC=local",
           "OU=Servers,OU=Corp,DC=corp,DC=local"]

    sp = lambda n: {"Principal": n, "PrincipalType": ["AZServicePrincipal"],
                    "Tenant": TENANT}
    azu = lambda n: {"Principal": n, "PrincipalType": ["AZUser"], "Tenant": TENANT}
    mi = lambda n, r=2: {"Identity": n, "AttachedResourceCount": r,
                         "AttachedTo": ["aks-prod-cluster", "kv-prod-secrets"][:r]}

    raw = {
        # ── AD Core ──────────────────────────────────────────────
        "tier0_paths": [
            _ad_path(["a.smith@corp.local", "Tier0 Admins@corp.local",
                      "WEB01.corp.local", "SQL01.corp.local", "DC01.corp.local"],
                     ["User", "Group", "Computer", "Computer", "Computer"]),
        ],
        "enterprise_admin_paths": [
            _ad_path(["svc_sql_sa@corp.local", "Domain Admins@corp.local",
                      "DC01.corp.local"],
                     ["User", "Group", "Computer"]),
        ],
        "kerberoast": [{"User": u} for u in
                       ("svc_sql_sa@corp.local", "svc_backup@corp.local")],
        "asrep_roast": [{"User": "helpdesk@corp.local"}],
        "delegation": [{"Computer": c} for c in ("WEB01.corp.local", "APP01.corp.local")],
        "admin_to": [{"User": "svc_sql_sa@corp.local", "Computer": "SQL01.corp.local"},
                     {"User": "svc_backup@corp.local", "Computer": "FS01.corp.local"}],
        "dacl_abuse": [{"Source": "a.smith@corp.local", "SourceType": ["User"],
                        "Target": "DC01.corp.local", "TargetType": ["Computer"],
                        "Permission": "GenericAll"},
                       {"Source": "j.doe@corp.local", "SourceType": ["User"],
                        "Target": "Tier0 Admins@corp.local", "TargetType": ["Group"],
                        "Permission": "WriteDacl"}],
        "gpo_control": [{"GPO": gpos[0], "Principal": "a.smith@corp.local"},
                        {"GPO": gpos[1], "Principal": "Tier0 Admins@corp.local"}],
        "sid_history": [{"User": "j.doe@corp.local", "OldPrincipal": "old.admin@corp.local"}],
        "dcsync": [{"Principal": "a.smith@corp.local", "Rights": ["Replicating Directory Changes"]},
                   {"Principal": "svc_backup@corp.local", "Rights": ["Replicating Directory Changes All"]}],
        "constrained_delegation": [{"User": "svc_sql_sa@corp.local",
                                    "Computer": "WEB01.corp.local", "Protocol": "LDAP"}],
        "rbcd": [{"User": "j.doe@corp.local", "Computer": "SQL01.corp.local"}],
        "password_not_required": [{"User": "helpdesk@corp.local"}],
        "reversible_encryption": [{"User": "svc_backup@corp.local", "Password": "PlainText123!"}],
        "account_operators": [{"Group": "Backup Operators@corp.local"}],
        "cross_forest": [{"SourceDomain": "corp.local", "TargetDomain": "partner.local",
                          "TrustTypes": ["external", "transitive"],
                          "IsTransitive": "Yes", "SIDFiltering": "Disabled",
                          "TrustDirection": "Outbound"}],
        "privileged_groups": [{"Group": g} for g in
                              ("Domain Admins@corp.local", "Enterprise Admins@corp.local",
                               "Tier0 Admins@corp.local")],
        "disabled_privileged": [{"Principal": "old.admin@corp.local",
                                 "Group": "Domain Admins@corp.local", "Enabled": False}],
        # ── AD Attack Paths ──────────────────────────────────────
        "cert_abuse_esc1": [{"Principal": "a.smith@corp.local", "CertTemplate": "UserAuth",
                             "Enrollee": "ESC1-Low@corp.local", "Permission": "Enrol"}],
        "cert_abuse_esc3": [{"Principal": "j.doe@corp.local", "CertTemplate": "SchemaCert",
                             "EnrollmentService": "corp-DomainController-CA"}],
        "dangerous_object_acls": [{"Object": "OU=Workstations,OU=Corp,DC=corp,DC=local",
                                   "Principal": "a.smith@corp.local"}],
        "domain_trust_escalation": [{"Source": "corp.local", "Target": "partner.local",
                                      "Direction": "Outbound", "SIDFiltering": "Disabled",
                                      "Permission": "TrustedDomain"}],
        "laps_gaps": [{"Principal": "a.smith@corp.local", "Computer": "DC01.corp.local",
                        "Permission": "ReadLAPSPassword"}],
        "ntlm_relay_paths": [{"Source": "j.doe@corp.local", "Computer": "WEB01.corp.local",
                              "RelayTarget": "WEB01.corp.local", "Protocol": "NTLM"}],
        "shadow_credentials": [{"Principal": "a.smith@corp.local",
                                "Computer": "DC01.corp.local", "KeyCount": 1}],
        "sql_linked_servers": [{"Principal": "svc_sql_sa@corp.local",
                                "Target": "FIN-SQL-01", "RemoteLogin": "sa"}],
        # ── Azure / Entra Core ───────────────────────────────────
        "az_global_admin": [dict(azu("a.smith@corp.onmicrosoft.com"), Role="Global Administrator")],
        "az_privileged_role_admin": [dict(azu("j.doe@corp.onmicrosoft.com"), Role="Privileged Role Administrator")],
        "az_hybrid_identity_admin": [dict(azu("j.doe@corp.onmicrosoft.com"), Role="Hybrid Identity Administrator")],
        "az_application_admin": [dict(azu("a.smith@corp.onmicrosoft.com"), Role="Application Administrator")],
        "az_cloud_app_admin": [dict(azu("j.doe@corp.onmicrosoft.com"), Role="Cloud Application Administrator")],
        "az_conditional_access_admin": [dict(azu("a.smith@corp.onmicrosoft.com"), Role="Conditional Access Administrator")],
        "az_privileged_auth_admin": [dict(azu("j.doe@corp.onmicrosoft.com"), Role="Privileged Authentication Administrator")],
        "az_security_admin": [dict(azu("a.smith@corp.onmicrosoft.com"), Role="Security Administrator")],
        "az_user_access_admin": [dict(azu("j.doe@corp.onmicrosoft.com"), Role="User Access Administrator")],
        "az_add_secret": [dict(sp("prod-deploy-controller"), Application="Contoso Billing")],
        "az_add_owner": [dict(sp("legacy-reporting-sp"), Application="Legacy Reporting")],
        "az_add_to_group": [dict(azu("j.doe@corp.onmicrosoft.com"), TargetGroup="Helpdesk@corp.onmicrosoft.com")],
        "az_contributor": [dict(sp("ci-pipeline-sp"), Role="Contributor")],
        "az_owner": [dict(sp("legacy-reporting-sp"), Role="Owner")],
        "az_key_vault_contributor": [dict(sp("billing-sync-sp"), Role="Key Vault Contributor",
                                           KeyVault="kv-prod-secrets")],
        "az_key_vault_abuse": [dict(sp("billing-sync-sp"), KeyVault="kv-prod-secrets",
                                    Access="get/unwrap/Key")],
        "az_managed_identity": [dict(sp("billing-sync-sp"), Role="Reader")],
        "az_managed_identity_roles": [mi("mi-sql-runner", 3), mi("mi-aks-reader", 2)],
        "az_external_users": [{"User": "contractor@partner.com",
                               "UPN": "contractor_partner.com#EXT#@corp.onmicrosoft.com"}],
        "az_execute_command": [dict(sp("ci-pipeline-sp"), Role="Virtual Machine Contributor Login")],
        "az_reset_password": [dict(azu("j.doe@corp.onmicrosoft.com"),
                                    Target="helpdesk@corp.onmicrosoft.com")],
        "az_role_escalation": [dict(sp("legacy-reporting-sp"),
                                     From="Reader", To="Owner")],
        # ── Azure / Entra Zero Trust Review ─────────────────────
        "az_mfa_gap": [{"Principal": "helpdesk@corp.onmicrosoft.com",
                        "PrincipalType": ["AZUser"], "MfaEnabled": False}],
        "az_ca_policy_gaps": [{"Policy": "CA-Base", "State": "disabled", "Users": 412},
                              {"Policy": "CA-Legacy", "State": "reportOnly", "Users": 980}],
        "az_pim_audit": [{"Principal": "a.smith@corp.onmicrosoft.com", "Role": "Global Administrator",
                          "PimType": "Permanent", "ActivatedAt": "2025-04-02T00:00:00Z"}],
        "az_sp_oversight": [dict(sp("legacy-reporting-sp"), Role="Directory.ReadWrite.All",
                                  OversightRequired=False)],
        "az_cross_tenant_access": [{"Tenant": "partner.onmicrosoft.com",
                                    "Setting": "unrestricted B2B collaboration"}],
        "az_custom_roles": [{"Role": "Custom-Subnet-Deploy", "Actions": 412, "AssignableScopes": 38}],
        "az_password_protection": [{"Setting": "Password protection", "State": "notConfigured"}],
        "az_legacy_auth": [{"Protocol": "SMTP AUTH", "Enabled": True, "Users": 36},
                           {"Protocol": "POP3", "Enabled": True, "Users": 22}],
        "az_identity_governance": [{"Feature": "Access reviews", "Configured": False,
                                    "StaleEntitlements": 61}],
        "az_auth_methods_policy": [{"Policy": "authMethodsPolicy", "SmsVoiceAllowed": True,
                                     "PasswordlessConfigured": False}],
        "az_logging_audit": [{"Category": "SignInLogs", "DiagnosticSettings": 0,
                              "StreamingToSIEM": False}],
        # ── Azure / Entra Architecture Simulation ───────────────
        "az_graph_api_abuse": [dict(sp("ci-pipeline-sp"),
                                     Permission="RoleManagement.ReadWrite.Directory",
                                     Capability="password reset + role assignment via API")],
        "az_sync_account_compromise": [{"Account": "svc-entsync@corp.onmicrosoft.com",
                                         "Capability": "PHS decryption / USN rollback"}],
        "az_prt_token_abuse": [{"Principal": "j.doe@corp.onmicrosoft.com",
                                 "Device": "APP01.corp.local", "Capability": "PRT persistence"}],
        "az_ca_bypass": [{"Bypass": "Trusted IP", "Scope": "198.51.100.0/24"},
                          {"Bypass": "Compliant device claim", "Scope": "all users"}],
        "az_cross_tenant_auth_chain": [{"SourceTenant": TENANT, "TargetTenant": "partner.onmicrosoft.com",
                                         "Vector": "B2B token chaining"}],
        "az_device_join_abuse": [{"Device": "APP01.corp.local", "JoinType": "Hybrid Azure AD",
                                   "Vector": "WPAD + AD CS relay"}],
        "az_mi_token_theft": [dict(mi("mi-sql-runner", 3), Vector="downstream resource access via stolen MI token")],
        "az_function_key_abuse": [{"Function": "func-billing", "KeyLeaked": True,
                                    "Reaches": "kv-prod-secrets"}],
        "az_pag_escalation": [{"Group": "Tier0 Admins@corp.local",
                                "DeviceLocalAdmin": "APP01.corp.local",
                                "Vector": "device local admin to lateral path"}],
        # ── Non-Human Identity Governance ───────────────────────
        "az_sp_no_owner": [SP_NO_OWNER, SP_NO_OWNER_2],
        "az_orphaned_app": [{"Application": "Legacy Reporting",
                             "AppId": "b800a5c2-2222-2222-2222-222222222222",
                             "OwnerCount": 0}],
        "az_overconsented_app": [{"Principal": "legacy-reporting-sp",
                                  "AppDisplayName": "Legacy Reporting",
                                  "AppId": "b800a5c2-2222-2222-2222-222222222222",
                                  "GraphPermission": "Directory.ReadWrite.All"}],
        "az_sp_privileged_no_ca": [dict(sp("prod-deploy-controller"),
                                        Role="Contributor",
                                        AppId="b800a5c2-1111-1111-1111-111111111111")],
        "az_user_assigned_mi": [mi("mi-sql-runner", 3), mi("mi-aks-reader", 2)],
        "az_stale_service_principal": [{"Principal": "legacy-reporting-sp",
                                        "LastSignIn": "2024-02-11T00:00:00Z",
                                        "AgeDays": 928}],
        "az_sp_disabled_privileged": [dict(sp("billing-sync-sp"), Role="Contributor",
                                            Enabled=False)],
        "az_sp_single_owner": [{"Principal": "billing-sync-sp",
                                "AppId": "b800a5c2-4444-4444-4444-444444444444",
                                "OwnerCount": 1}],
        "az_sp_owner_disabled": [{"Principal": "prod-deploy-controller",
                                  "AppId": "b800a5c2-1111-1111-1111-111111111111",
                                  "OwnerCount": 2, "ActiveOwners": 0}],
        "az_stale_managed_identity": [{"Identity": "mi-legacy-batch",
                                        "LastUsed": "2024-05-04T00:00:00Z",
                                        "AgeDays": 874}],
        "az_stale_device": [{"DeviceName": "APP01.corp.local",
                              "LastCollected": "2025-06-30T00:00:00Z",
                              "IdleDays": 453}],
        "az_sp_combined_privileges": [{"Principal": "legacy-reporting-sp",
                                        "AppId": "b800a5c2-2222-2222-2222-222222222222",
                                        "DirectoryRole": "Directory.ReadWrite.All",
                                        "AzureRole": "Owner"}],
        "az_sp_owner_group": [{"Principal": "billing-sync-sp",
                                "AppId": "b800a5c2-4444-4444-4444-444444444444",
                                "OwnerType": "Group",
                                "OwnerGroup": "Helpdesk@corp.onmicrosoft.com"}],
        "az_sp_legacy_type": [{"Principal": "old-integration-sp",
                                "AppId": "b800a5c2-5555-5555-5555-555555555555",
                                "SpType": "unknown/legacy"}],
    }
    return raw


def _file_digest(path):
    """Return (sha256 hex, size in bytes) for a generated artifact."""
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def _atomic_export(fn, path, *args, **kwargs):
    """Run an exporter to a temp file, then atomically move it into place.

    Re-running the generator overwrites existing reports, and on Windows an
    AV/indexer scan can briefly hold a freshly written file open, which makes
    reportlab/openpyxl fail with PermissionError on a direct overwrite. Writing
    to a sibling temp file and using os.replace (REPLACE_EXISTING) avoids that
    and keeps a failed run from leaving a half-written report behind.

    The temp name preserves the original extension because some writers validate
    it (pyvis asserts the attack-graph output ends in .html).
    """
    tmp = os.path.join(os.path.dirname(path),
                       os.path.splitext(os.path.basename(path))[0] + ".part"
                       + os.path.splitext(path)[1])
    last = None
    for attempt in range(5):
        try:
            fn(*args, filepath=tmp, **kwargs) if _takes_filepath(fn) else fn(*args, tmp, **kwargs)
            os.replace(tmp, path)
            return path
        except PermissionError as exc:
            last = exc
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            time.sleep(0.5 * (attempt + 1))
    raise last


def _takes_filepath(fn):
    """export_excel names its output arg `filepath`; the rest use positional."""
    import inspect
    return "filepath" in inspect.signature(fn).parameters


def _client_config(client_name, report_title, data_version):
    return {
        "client_name": client_name,
        "engagement": "GraphShield Proof-of-Functioning",
        "data_version": str(data_version),
        "collection_timestamp": FIXED_TS,
        "data_source_type": "Sample Data (Synthetic)",
        "collection_method": "Sample / dummy dataset - not a real collection",
        "sharphound_timestamp": FIXED_TS,
        "azurehound_timestamp": FIXED_TS,
        "report_title": report_title,
    }


def build_findings_for_group(raw, group):
    """Run the app.py pipeline for one assessment group."""
    findings = FindingBuilder().build(raw, selected_groups=[group])
    findings = [enrich_finding(f, raw) for f in findings]
    findings = IdentityNormalizer().normalize(findings)

    lifecycle_evidence = {}
    nhi_correlation = {}
    if group == NHI_GROUP:
        lifecycle_evidence = load_lifecycle_feed(DUMMY_LIFECYCLE_FEED)
        if lifecycle_evidence:
            findings = findings + build_lifecycle_findings(lifecycle_evidence)
            correlate_nhi_sources(findings, lifecycle_evidence, nhi_correlation)

    for f in findings:
        f.setdefault("ad_objects", {
            "users": [], "groups": [], "computers": [],
            "gpos": [], "organizational_units": [], "relationships": [],
        })

    active = [f for f in findings if f.get("has_evidence", False)]
    risk = RiskEngine().calculate(active)
    ad_chains = AttackChainBuilder(findings).build()
    hybrid_chains = HybridAttackChain().analyze(findings)
    chains = ad_chains + hybrid_chains
    for c in chains:
        c.setdefault("ad_objects", {
            "users": [], "groups": [], "computers": [],
            "gpos": [], "organizational_units": [], "relationships": [],
        })
        c["mitre"] = c.get("mitre", {}) or {}
    return findings, chains, risk, lifecycle_evidence, nhi_correlation


def _ai_narrative(client_name, group, findings, risk, chains, lifecycle_evidence):
    """Deterministic fallback brief used when Ollama is unavailable.

    Clearly labelled as generated from sample data so it can never be mistaken
    for a real AI assessment.
    """
    active = [f for f in findings if f.get("has_evidence", False)]
    sev = {}
    for f in active:
        sev[f.get("severity", "LOW")] = sev.get(f.get("severity", "LOW"), 0) + 1
    lines = [
        "# 1. EXECUTIVE SUMMARY",
        f"- Client: {client_name} (sample data proof run)",
        f"- Assessment: {GROUPS.get(group, {}).get('name', group)}",
        f"- Findings with evidence: {len(active)} of {len(findings)} evaluated",
        f"- Risk score: {risk.get('total_score', 'N/A')} ({risk.get('rating', 'N/A')})",
        "- Severity spread: " + ", ".join(f"{k}={v}" for k, v in sorted(sev.items())),
        f"- Attack chains: {len(chains)}",
        "- AI generation was unavailable for this run, so this brief is a",
        "  deterministic placeholder built directly from the sample findings.",
        "",
        "# 2. BUSINESS IMPACT",
        "- Results are generated from synthetic sample data for platform",
        "  demonstration only and describe no real estate.",
        "",
        "# 5. 30-DAY REMEDIATION PLAN",
        "- Not applicable: sample dataset.",
    ]
    if lifecycle_evidence:
        rows = lifecycle_dashboard_rows(lifecycle_evidence, {})
        lines += ["", "# 6. NON-HUMAN IDENTITY CORROBORATION",
                  f"- Workload identities in the lifecycle feed: {len(rows)}"]
    return "\n".join(lines)


def generate(client_name="1st_Client", data_version="1.0", ai_groups=None,
             out_root=None, verbose=True):
    """Generate every report for every assessment group.

    ``ai_groups`` selects which groups get a genuine Ollama narrative. It is
    opt-in because a llama3.1 call takes several minutes per group and is
    non-deterministic, which makes it a poor default for proof artifacts. The
    default deterministic brief is reproducible and honours the required
    output structure, including the NHI corroboration section.
    """
    from analytics.graph_builder import create_attack_graph

    setup_logging()
    raw = build_dummy_raw()
    ensure_client_dirs(client_name, data_version)
    ai_groups = set(ai_groups or ())

    if out_root is None:
        base = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "outputs", client_name)
        out_root = os.path.join(base, "proof")

    summary = {}
    for group in GROUP_ORDER:
        gname = GROUPS.get(group, {}).get("name", group)
        report_title = GROUPS.get(group, {}).get("report_title", "GraphShield Assessment")
        cfg = _client_config(client_name, report_title, data_version)

        findings, chains, risk, lifecycle_evidence, nhi_correlation = \
            build_findings_for_group(raw, group)
        env_stats = compute_env_stats(findings, chains, risk, raw=raw)

        gdir = os.path.join(out_root, group)
        os.makedirs(gdir, exist_ok=True)
        tag = FIXED_DATE
        safe = client_name.replace(" ", "_")
        prefix = f"{safe}_{group}"
        paths = {
            "report_pdf": os.path.join(gdir, f"{prefix}_Assessment_Report_{tag}.pdf"),
            "engineering_xlsx": os.path.join(gdir, f"{prefix}_Engineering_{tag}.xlsx"),
            "findings_csv": os.path.join(gdir, f"{prefix}_Findings_{tag}.csv"),
            "evidence_json": os.path.join(gdir, f"{prefix}_Evidence_{tag}.json"),
            "attack_graph_html": os.path.join(gdir, f"{prefix}_Attack_Graph_{tag}.html"),
            "ai_report_pdf": os.path.join(gdir, f"{prefix}_Executive_Brief_{tag}.pdf"),
            "zip_package": os.path.join(gdir, f"{prefix}_Package_{tag}.zip"),
        }

        _atomic_export(export_pdf, paths["report_pdf"], findings, chains,
                       client_config=cfg, risk=risk, env_stats=env_stats,
                       report_title=report_title)
        _atomic_export(export_excel, paths["engineering_xlsx"], findings, chains,
                       client_config=cfg, risk=risk, env_stats=env_stats,
                       report_title=report_title)
        _atomic_export(export_csv, paths["findings_csv"], findings,
                       client_config=cfg, report_title=report_title)
        _atomic_export(export_json, paths["evidence_json"], findings, chains, risk,
                       client_config=cfg)
        _atomic_export(create_attack_graph, paths["attack_graph_html"], chains)

        ai_source = "deterministic brief"
        text = None
        if group in ai_groups:
            try:
                from ai.analyst import ask_ollama
                text = ask_ollama(findings=findings, chains=chains, risk=risk)
                if text:
                    ai_source = "ollama llama3.1 (live)"
            except Exception as exc:  # noqa: BLE001 - offline is expected
                ai_source = "deterministic brief (ollama error: %s)" % type(exc).__name__
                text = None
        if not text:
            if ai_source == "deterministic brief":
                pass
            text = _ai_narrative(client_name, group, findings, risk, chains,
                                 lifecycle_evidence)
        _atomic_export(export_ai_pdf, paths["ai_report_pdf"], text,
                       findings=findings, chains=chains, risk=risk,
                       env_stats=env_stats, client_config=cfg,
                       report_title=report_title)

        _atomic_export(create_zip, paths["zip_package"],
                       [paths["report_pdf"], paths["engineering_xlsx"],
                        paths["findings_csv"], paths["evidence_json"],
                        paths["attack_graph_html"], paths["ai_report_pdf"]])

        active = [f for f in findings if f.get("has_evidence", False)]
        summary[group] = {
            "group_name": gname,
            "findings": len(findings),
            "with_evidence": len(active),
            "lifecycle_findings": sum(
                1 for f in findings if str(f.get("id", "")).startswith("AZ_LC_")),
            "correlated": len(nhi_correlation),
            "chains": len(chains),
            "risk_score": risk.get("total_score"),
            "risk_level": risk.get("rating"),
            "severity_breakdown": risk.get("breakdown", {}),
            "ai_source": ai_source,
            "artifacts": sorted(os.path.basename(p) for p in paths.values()),
            "artifact_integrity": {
                os.path.basename(p): dict(zip(("sha256", "bytes"), _file_digest(p)))
                for p in sorted(paths.values())
            },
        }
        if verbose:
            s = summary[group]
            print("  %-14s %2d findings (%2d w/ evidence), %2d chains, risk %s/%s, ai=%s"
                  % (group, s["findings"], s["with_evidence"], s["chains"],
                     s["risk_score"], s["risk_level"], s["ai_source"]))

    manifest = os.path.join(out_root, "proof_manifest.json")
    manifest_data = {
        "client": client_name,
        "data_version": str(data_version),
        "report_date": FIXED_DATE,
        "generated_from": "synthetic sample data",
        "groups": summary,
    }
    with open(manifest, "w", encoding="utf-8") as fh:
        json.dump(manifest_data, fh, indent=2)
    if verbose:
        print("\n  Manifest: %s" % manifest)
    return summary, out_root


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Generate GraphShield proof reports")
    ap.add_argument("--client", default="1st_Client")
    ap.add_argument("--version", default="1.0")
    ap.add_argument("--ai-groups", default="",
                    help="comma-separated assessment groups to brief with Ollama, "
                         "e.g. 'nhi_governance'. Omit for fast deterministic briefs.")
    ap.add_argument("--output", default=None)
    args = ap.parse_args()

    ai_groups = [g.strip() for g in args.ai_groups.split(",") if g.strip()]
    print("Generating GraphShield proof reports for %r (sample data)" % args.client)
    if ai_groups:
        print("  live Ollama briefs for: %s" % ", ".join(ai_groups))
    s, root = generate(client_name=args.client, data_version=args.version,
                       ai_groups=ai_groups, out_root=args.output)
    total = sum(len(v["artifacts"]) for v in s.values())
    print("  %d groups, %d artifacts under %s" % (len(s), total, root))
