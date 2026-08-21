HYBRID_CONFIGS = [
    {
        "risk": "AD TO AZURE HYBRID TAKEOVER",
        "severity": "CRITICAL",
        "description": "On-prem AD compromise leads to full Azure tenant takeover via Hybrid Identity Administrator or AD FS compromise",
        "attack_path": "AD Domain Admin -> Hybrid Identity Admin -> Federation/Sync Config -> Azure Tenant Admin",
        "requires_ad": {"TIER0_PATHS", "DCSYNC", "ENTERPRISE_ADMIN_PATHS"},
        "requires_azure": {"AZ_HYBRID_IDENTITY_ADMIN", "AZ_GLOBAL_ADMIN", "AZ_PRIVILEGED_ROLE_ADMIN"},
    },
    {
        "risk": "PERSISTENT CLOUD BACKDOOR",
        "severity": "CRITICAL",
        "description": "Application Administrator or equivalent can create long-term persistent access to tenant data via application credentials",
        "attack_path": "Application Admin -> Add App Secret -> Backdoor Application -> Persistent Data Access",
        "requires_ad": set(),
        "requires_azure": {"AZ_APPLICATION_ADMIN", "AZ_ADD_SECRET"},
    },
    {
        "risk": "KEY VAULT CREDENTIAL THEFT",
        "severity": "CRITICAL",
        "description": "Key Vault Contributor access enables reading all secrets, keys, and certificates in Key Vault",
        "attack_path": "Key Vault Contributor -> Read Secrets -> Application Credentials -> Lateral Movement",
        "requires_ad": set(),
        "requires_azure": {"AZ_KEY_VAULT_ABUSE"},
    },
    {
        "risk": "AZURE ROLE ESCALATION CHAIN",
        "severity": "CRITICAL",
        "description": "Nested group memberships and role assignments create escalation paths to tenant-wide administrator roles",
        "attack_path": "Low-Privileged Principal -> Nested Group -> Privileged Role -> Tenant Admin",
        "requires_ad": set(),
        "requires_azure": {"AZ_ROLE_ESCALATION"},
    },
    {
        "risk": "CONDITIONAL ACCESS BYPASS",
        "severity": "HIGH",
        "description": "Conditional Access Administrator can modify or disable security policies weakening MFA and access controls",
        "attack_path": "CA Admin -> Modify Policy -> Disable MFA -> Security Control Bypass",
        "requires_ad": set(),
        "requires_azure": {"AZ_CONDITIONAL_ACCESS_ADMIN"},
    },
    {
        "risk": "MANAGED IDENTITY TOKEN ABUSE",
        "severity": "HIGH",
        "description": "Managed identities with high-privilege roles present a token theft and lateral movement risk",
        "attack_path": "Compromised Resource -> Managed Identity Token -> Inherited Role -> Subscription Access",
        "requires_ad": set(),
        "requires_azure": {"AZ_MANAGED_IDENTITY"},
    },
    {
        "risk": "EXTERNAL TENANT ACCESS",
        "severity": "MEDIUM",
        "description": "Guest users with privileged role assignments create cross-tenant access risks",
        "attack_path": "External Identity Compromise -> Guest Account -> Privileged Role -> Tenant Data Access",
        "requires_ad": set(),
        "requires_azure": {"AZ_EXTERNAL_USER"},
    },
    {
        "risk": "HYBRID PASSWORD SPRAY",
        "severity": "HIGH",
        "description": "On-prem password weaknesses combine with Azure password reset privileges to enable tenant-wide account takeover",
        "attack_path": "Weak On-Prem Password -> Password Reset Abuse -> Azure Account Takeover",
        "requires_ad": {"PASSWORD_NOT_REQUIRED", "REVERSIBLE_ENCRYPTION"},
        "requires_azure": {"AZ_RESET_PASSWORD"},
    },
    {
        "risk": "AZURE VM EXECUTION PATH",
        "severity": "HIGH",
        "description": "ExecuteCommand on Azure VMs enables remote code execution and lateral movement into VM environments",
        "attack_path": "ExecuteCommand Permission -> VM Script Execution -> Credential Harvesting",
        "requires_ad": set(),
        "requires_azure": {"AZ_EXECUTE_COMMAND"},
    },
    {
        "risk": "CROSS-TENANT APPLICATION PERSISTENCE",
        "severity": "HIGH",
        "description": "Combined application abuse permissions enable creating long-term backdoor access via application owners and secrets",
        "attack_path": "Add Owner -> App Control -> Add Secret -> Persistent Credential Backdoor",
        "requires_ad": set(),
        "requires_azure": {"AZ_ADD_OWNER", "AZ_ADD_SECRET"},
    },
]


def _build_real_path(ad_objects):
    """Build a real object path from ad_objects relationships."""
    relationships = ad_objects.get("relationships", [])
    if not relationships:
        return None
    nodes = []
    seen = set()
    for rel in relationships:
        for node in rel.split(" -> "):
            n = node.strip()
            if n and n not in seen:
                seen.add(n)
                nodes.append(n)
    return " -> ".join(nodes) if nodes else None


class HybridAttackChain:
    def analyze(self, findings):
        self._finding_map = {f.get("id"): f for f in findings}
        ad_finding_ids = {f.get("id") for f in findings if f.get("has_evidence") and f.get("source", "") == "Active Directory"}
        azure_finding_ids = {f.get("id") for f in findings if f.get("has_evidence") and f.get("source", "") == "Azure"}

        chains = []
        for cfg in HYBRID_CONFIGS:
            ad_ok = not cfg["requires_ad"] or cfg["requires_ad"].issubset(ad_finding_ids)
            azure_ok = not cfg["requires_azure"] or cfg["requires_azure"].issubset(azure_finding_ids)
            if ad_ok and azure_ok:
                required_all = cfg["requires_ad"] | cfg["requires_azure"]
                evidence_objects = {}
                for rid in required_all:
                    f = self._finding_map.get(rid)
                    if f:
                        objs = f.get("ad_objects", {})
                        for k, v in objs.items():
                            evidence_objects.setdefault(k, set()).update(v if isinstance(v, list) else [])

                evidence_objects = {k: sorted(v) for k, v in evidence_objects.items()}
                evidence_objects.setdefault("relationships", [])

                real_path = _build_real_path(evidence_objects)
                if real_path:
                    attack_path = real_path
                    attack_path_nodes = real_path.split(" -> ")
                else:
                    attack_path = cfg["attack_path"]
                    attack_path_nodes = cfg["attack_path"].split(" -> ")

                chains.append({
                    "risk": cfg["risk"],
                    "severity": cfg["severity"],
                    "description": cfg["description"],
                    "attack_path": attack_path,
                    "attack_path_nodes": attack_path_nodes,
                    "ad_objects": evidence_objects,
                    "mitre": {"id": "T1481", "tactic": "Privilege Escalation", "technique": "Cloud Account Takeover"},
                    "source": "Hybrid (AD+Azure)",
                })

        return chains
