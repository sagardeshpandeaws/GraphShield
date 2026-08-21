import itertools

ESCALATION_IDS = {
    "TIER0_PATHS": ("CRITICAL", "Direct Tier-0 attack path to Domain Admin"),
    "ENTERPRISE_ADMIN_PATHS": ("CRITICAL", "Enterprise Admin group compromise path"),
    "DCSYNC": ("CRITICAL", "DCSync attack path via replication rights"),
    "DELEGATION": ("HIGH", "Unconstrained delegation abuse path"),
    "KERBEROAST": ("HIGH", "Kerberoast credential cracking path"),
    "ASREP_ROAST": ("HIGH", "AS-REP roast password cracking path"),
    "DACL_ABUSE": ("HIGH", "DACL abuse privilege escalation path"),
    "GPO_CONTROL": ("HIGH", "GPO modification to code execution path"),
    "ADMIN_TO": ("MEDIUM", "Local admin lateral movement path"),
    "SID_HISTORY": ("MEDIUM", "SID history injection escalation path"),
    "CONSTRAINED_DELEGATION": ("HIGH", "Constrained delegation abuse path"),
    "RBCD": ("HIGH", "Resource-based constrained delegation path"),
    "PASSWORD_NOT_REQUIRED": ("MEDIUM", "Weak credential attack path"),
    "REVERSIBLE_ENCRYPTION": ("MEDIUM", "Reversible credential extraction path"),
    "ACCOUNT_OPERATORS": ("MEDIUM", "Account operator group abuse path"),
    "CROSS_FOREST": ("MEDIUM", "Cross-forest trust attack path"),
    # Azure / Entra ID
    "AZ_GLOBAL_ADMIN": ("CRITICAL", "Global Administrator privilege escalation path"),
    "AZ_PRIVILEGED_ROLE_ADMIN": ("CRITICAL", "Privileged Role Administrator escalation path"),
    "AZ_HYBRID_IDENTITY_ADMIN": ("CRITICAL", "Hybrid Identity Admin on-prem to cloud takeover path"),
    "AZ_APPLICATION_ADMIN": ("HIGH", "Application Administrator persistence path"),
    "AZ_CLOUD_APP_ADMIN": ("HIGH", "Cloud Application Administrator persistence path"),
    "AZ_CONDITIONAL_ACCESS_ADMIN": ("HIGH", "Conditional Access policy bypass path"),
    "AZ_PRIVILEGED_AUTH_ADMIN": ("CRITICAL", "Privileged Authentication Admin auth pipeline takeover path"),
    "AZ_SECURITY_ADMIN": ("HIGH", "Security Administrator security control bypass path"),
    "AZ_USER_ACCESS_ADMIN": ("HIGH", "User Access Administrator RBAC takeover path"),
    "AZ_CONTRIBUTOR": ("HIGH", "Contributor role resource management abuse path"),
    "AZ_OWNER": ("CRITICAL", "Owner role full subscription takeover path"),
    "AZ_ADD_SECRET": ("HIGH", "Application credential backdoor persistence path"),
    "AZ_ADD_OWNER": ("HIGH", "Application owner persistence escalation path"),
    "AZ_ADD_TO_GROUP": ("HIGH", "Group membership privilege escalation path"),
    "AZ_KEY_VAULT_ABUSE": ("CRITICAL", "Key Vault credential theft path"),
    "AZ_MANAGED_IDENTITY": ("HIGH", "Managed identity privilege abuse path"),
    "AZ_EXTERNAL_USER": ("MEDIUM", "External guest user privilege escalation path"),
    "AZ_EXECUTE_COMMAND": ("HIGH", "Azure VM remote command execution path"),
    "AZ_RESET_PASSWORD": ("MEDIUM", "Azure password reset abuse path"),
    "AZ_ROLE_ESCALATION": ("CRITICAL", "Azure role escalation chain to tenant admin"),
}

ATTACK_PATHS = {
    "TIER0_PATHS": "Compromised AD User -> Tier-0 Group Membership -> Domain Admin Access",
    "ENTERPRISE_ADMIN_PATHS": "Enterprise Admin Member -> Forest-wide Privilege Escalation",
    "DCSYNC": "DCSync Rights -> Domain Controller Replication -> All Credentials",
    "DELEGATION": "Unconstrained Delegation -> Kerberos Ticket Capture -> Service Impersonation",
    "KERBEROAST": "SPN Account -> Kerberos TGS Request -> Offline Cracking",
    "ASREP_ROAST": "Pre-Auth Disabled -> AS-REP Request -> Offline Cracking",
    "DACL_ABUSE": "Excessive ACL -> GenericWrite/GenericAll -> Privilege Escalation",
    "GPO_CONTROL": "GPO Write Access -> Malicious GPO -> Code Execution on Targets",
    "ADMIN_TO": "Local Admin Rights -> Lateral Movement -> High-Value Target Access",
    "SID_HISTORY": "SID History Attribute -> Token Augmentation -> Unauthorized Access",
    "CONSTRAINED_DELEGATION": "Constrained Delegation -> Service Ticket Forging -> Privilege Escalation",
    "RBCD": "RBCD Write Access -> Machine Account Control -> Service Impersonation",
    "PASSWORD_NOT_REQUIRED": "No Password Required -> Empty Credential Login -> Account Access",
    "REVERSIBLE_ENCRYPTION": "Reversible Encryption -> Credential Extraction -> Account Compromise",
    "ACCOUNT_OPERATORS": "Account Operator Group -> Group Membership Modification -> Privilege Escalation",
    "CROSS_FOREST": "Cross-Forest Trust -> SidHistory/SIDFiltering Bypass -> Forest Compromise",
    # Azure / Entra ID
    "AZ_GLOBAL_ADMIN": "Global Admin Role -> Tenant-wide Configuration Control -> Full Tenant Compromise",
    "AZ_PRIVILEGED_ROLE_ADMIN": "Privileged Role Admin -> Grant Global Admin -> Tenant Takeover",
    "AZ_HYBRID_IDENTITY_ADMIN": "Hybrid Identity Admin -> AD FS/Sync Config -> On-Prem AD to Cloud Bridge",
    "AZ_APPLICATION_ADMIN": "Application Admin -> App Credential Addition -> Persistent Backdoor Access",
    "AZ_CLOUD_APP_ADMIN": "Cloud App Admin -> M365 App Consent -> Data Exfiltration",
    "AZ_CONDITIONAL_ACCESS_ADMIN": "CA Admin -> Policy Modification -> Security Control Bypass",
    "AZ_PRIVILEGED_AUTH_ADMIN": "Privileged Auth Admin -> Authentication Agent Control -> Auth Pipeline Backdoor",
    "AZ_SECURITY_ADMIN": "Security Admin -> Policy Modification -> Security Control Bypass",
    "AZ_USER_ACCESS_ADMIN": "User Access Admin -> RBAC Assignment -> Entire Subscription Access",
    "AZ_CONTRIBUTOR": "Contributor -> Resource Deploy -> Lateral Movement via Managed Resources",
    "AZ_OWNER": "Owner -> Role Grant -> Full Subscription Takeover",
    "AZ_ADD_SECRET": "Add Secret Permission -> New App Credential -> Long-term Persistence",
    "AZ_ADD_OWNER": "Add Owner Permission -> Grant App Ownership -> Privilege Escalation",
    "AZ_ADD_TO_GROUP": "Add Member to Group -> Privileged Group Access -> Tenant Admin Escalation",
    "AZ_KEY_VAULT_ABUSE": "Key Vault Contributor -> Read Secrets -> Credential Theft",
    "AZ_MANAGED_IDENTITY": "Managed Identity Abuse -> Inherited Roles -> Lateral Movement via Tokens",
    "AZ_EXTERNAL_USER": "Guest User with Privileged Role -> External Identity Compromise -> Tenant Access",
    "AZ_EXECUTE_COMMAND": "ExecuteCommand on VM -> Remote Script Execution -> VM Compromise",
    "AZ_RESET_PASSWORD": "Password Reset Permission -> Account Takeover -> Unauthorized Access",
    "AZ_ROLE_ESCALATION": "Escalation Path -> Nested Group -> Privileged Role Assignment -> Tenant Admin",
}

CROSS_FOREST_COMPOSITES = [
    {
        "fid": "CROSS_FOREST+TIER0_PATHS",
        "title": "Cross-Forest Tier-0 Compromise",
        "severity": "CRITICAL",
        "risk_desc": "Cross-forest trust enables Tier-0 privilege escalation across forest boundaries",
        "attack_path": "Cross-Forest Trust -> Tier-0 Paths in Trusted Forest -> Multi-Forest Domain Admin Access",
    },
    {
        "fid": "CROSS_FOREST+DCSYNC",
        "title": "Cross-Forest Credential Replication",
        "severity": "CRITICAL",
        "risk_desc": "Cross-forest trust combined with DCSync rights enables credential theft across forests",
        "attack_path": "Cross-Forest Trust -> DCSync Rights -> Replicate Credentials from Trusted Domain",
    },
    {
        "fid": "CROSS_FOREST+ADMIN_TO",
        "title": "Cross-Forest Lateral Movement",
        "severity": "HIGH",
        "risk_desc": "Cross-forest trust enables lateral movement to systems in trusted forest",
        "attack_path": "Cross-Forest Trust -> Local Admin Rights -> Lateral Movement Across Forests",
    },
    {
        "fid": "CROSS_FOREST+SID_HISTORY",
        "title": "Cross-Forest SID History Injection",
        "severity": "HIGH",
        "risk_desc": "Cross-forest trust with SID history abuse enables privilege escalation across forests",
        "attack_path": "Cross-Forest Trust -> SID History Injection -> Unauthorized Forest Access",
    },
    {
        "fid": "CROSS_FOREST+DELEGATION",
        "title": "Cross-Forest Delegation Abuse",
        "severity": "HIGH",
        "risk_desc": "Cross-forest trust combined with delegation abuse enables service impersonation across forests",
        "attack_path": "Cross-Forest Trust -> Unconstrained Delegation -> Cross-Forest Ticket Capture",
    },
]


def _build_real_path(ad_objects):
    """Build a real object path from ad_objects relationships, falling back to generic."""
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


class AttackChainBuilder:
    def __init__(self, findings):
        self.findings = findings
        self._finding_map = {f.get("id"): f for f in findings}

    def build(self):
        chains = []
        for f in self.findings:
            if not f.get("has_evidence", False):
                continue
            fid = f.get("id", "")
            if fid not in ESCALATION_IDS:
                continue
            severity, risk_desc = ESCALATION_IDS[fid]
            ad_objects = f.get("ad_objects", {})
            real_path = _build_real_path(ad_objects)
            if real_path:
                attack_path = real_path
                attack_path_nodes = real_path.split(" -> ")
            else:
                attack_path = ATTACK_PATHS.get(fid, "")
                attack_path_nodes = attack_path.split(" -> ") if attack_path else []

            domains = ad_objects.get("domains", [])
            source = f.get("source", "Active Directory")

            chains.append({
                "risk": risk_desc,
                "severity": severity,
                "attack_path": attack_path,
                "attack_path_nodes": attack_path_nodes,
                "ad_objects": ad_objects,
                "mitre": f.get("mitre", {}),
                "domains": domains,
                "source": source,
            })

        cross_forest = self._finding_map.get("CROSS_FOREST")
        if cross_forest and cross_forest.get("has_evidence", False):
            cf_domains = cross_forest.get("ad_objects", {}).get("domains", [])
            for composite in CROSS_FOREST_COMPOSITES:
                needs = [fid for fid in composite["fid"].split("+") if fid != "CROSS_FOREST"]
                if all(self._finding_map.get(fid, {}).get("has_evidence", False) for fid in needs):
                    # Try real path from composite findings
                    real_rels = []
                    for fid in needs:
                        cf = self._finding_map.get(fid, {})
                        rels = cf.get("ad_objects", {}).get("relationships", [])
                        real_rels.extend(rels)
                    composite_ad = {"domains": cf_domains}
                    if real_rels:
                        composite_ad["relationships"] = real_rels
                    real_path = _build_real_path(composite_ad)
                    if real_path:
                        ap = real_path
                        apn = real_path.split(" -> ")
                    else:
                        ap = composite["attack_path"]
                        apn = composite["attack_path"].split(" -> ")
                    chains.append({
                        "risk": composite["risk_desc"],
                        "severity": composite["severity"],
                        "attack_path": ap,
                        "attack_path_nodes": apn,
                        "ad_objects": composite_ad,
                        "mitre": {"id": "T1482", "tactic": "Privilege Escalation", "technique": "Domain Trust Discovery"},
                        "domains": cf_domains,
                        "source": "Hybrid (Cross-Forest)",
                    })

        return chains
