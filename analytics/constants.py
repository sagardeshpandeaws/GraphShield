COMPLIANCE_MAP = {
    "TIER0_PATHS": {"CIS": "5.1", "NIST": "PR.AA-02", "ISO 27001": "5.15, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "ENTERPRISE_ADMIN_PATHS": {"CIS": "5.1", "NIST": "PR.AA-02", "ISO 27001": "5.15, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "KERBEROAST": {"CIS": "3.11", "NIST": "PR.DS-01", "ISO 27001": "8.24", "SA 315": "IT-2/ITAC", "DPDP": "8(1)"},
    "ASREP_ROAST": {"CIS": "3.11", "NIST": "PR.DS-01", "ISO 27001": "8.24", "SA 315": "IT-2/ITAC", "DPDP": "8(1)"},
    "DELEGATION": {"CIS": "6.1", "NIST": "PR.AA-02", "ISO 27001": "5.15, 5.16, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "ADMIN_TO": {"CIS": "6.3", "NIST": "PR.AA-03", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "DACL_ABUSE": {"CIS": "6.3", "NIST": "PR.AA-03", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "GPO_CONTROL": {"CIS": "4.1", "NIST": "PR.AA-02", "ISO 27001": "8.8, 8.9", "SA 315": "IT-1/GITC", "DPDP": "8(1)"},
    "SID_HISTORY": {"CIS": "6.3", "NIST": "PR.AA-02", "ISO 27001": "5.15, 8.2", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "DCSYNC": {"CIS": "5.4", "NIST": "PR.AA-02", "ISO 27001": "5.15, 5.16, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "CONSTRAINED_DELEGATION": {"CIS": "6.1", "NIST": "PR.AA-02", "ISO 27001": "5.15, 5.16, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "RBCD": {"CIS": "6.1", "NIST": "PR.AA-02", "ISO 27001": "5.15, 5.16, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "PASSWORD_NOT_REQUIRED": {"CIS": "5.2", "NIST": "PR.AA-01", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-2/ITAC", "DPDP": "8(1)"},
    "REVERSIBLE_ENCRYPTION": {"CIS": "5.2", "NIST": "PR.AA-01", "ISO 27001": "8.24", "SA 315": "IT-2/ITAC", "DPDP": "8(1)"},
    "ACCOUNT_OPERATORS": {"CIS": "5.4", "NIST": "PR.AA-02", "ISO 27001": "5.15, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "CROSS_FOREST": {"CIS": "5.5", "NIST": "PR.AA-03", "ISO 27001": "5.15, 5.18", "SA 315": "IT-1/GITC", "DPDP": "9(1)"},
    "PRIVILEGED_GROUPS": {"CIS": "5.4", "NIST": "PR.AA-02", "ISO 27001": "5.15, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "DISABLED_PRIVILEGED": {"CIS": "5.4", "NIST": "PR.AA-02", "ISO 27001": "5.15, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    
    # ── Heading 1: Identity Attack Path Assessment ──────────────
    "CERT_ABUSE_ESC1": {"CIS": "5.4", "NIST": "PR.AA-02", "ISO 27001": "5.15, 5.16, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "CERT_ABUSE_ESC3": {"CIS": "5.4", "NIST": "PR.AA-02", "ISO 27001": "5.15, 5.16, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "SHADOW_CREDENTIALS": {"CIS": "5.4", "NIST": "PR.AA-02", "ISO 27001": "5.15, 5.16, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "DANGEROUS_COMPUTER_ACLS": {"CIS": "6.3", "NIST": "PR.AA-03", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "NTLM_RELAY_PATHS": {"CIS": "6.1", "NIST": "PR.AA-02", "ISO 27001": "5.15, 5.16, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "LAPS_GAPS": {"CIS": "4.5", "NIST": "PR.PS-02", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-2/ITAC", "DPDP": "8(1)"},
    "SQL_LINKED_SERVERS": {"CIS": "6.1", "NIST": "PR.AA-02", "ISO 27001": "5.15, 5.16, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "DOMAIN_TRUST_ESCALATION": {"CIS": "5.5", "NIST": "PR.AA-03", "ISO 27001": "5.15, 5.18", "SA 315": "IT-1/GITC", "DPDP": "9(1)"},
    
    # ── Azure / Entra ID Compliance ────────────────────────────
    "AZ_GLOBAL_ADMIN": {"CIS": "5.4", "NIST": "PR.AA-02", "ISO 27001": "5.15, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "AZ_PRIVILEGED_ROLE_ADMIN": {"CIS": "5.4", "NIST": "PR.AA-02", "ISO 27001": "5.15, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "AZ_HYBRID_IDENTITY_ADMIN": {"CIS": "5.4", "NIST": "PR.AA-02", "ISO 27001": "5.15, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "AZ_APPLICATION_ADMIN": {"CIS": "6.1", "NIST": "PR.AA-03", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "AZ_CLOUD_APP_ADMIN": {"CIS": "6.1", "NIST": "PR.AA-03", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "AZ_CONDITIONAL_ACCESS_ADMIN": {"CIS": "5.4", "NIST": "PR.AA-03", "ISO 27001": "5.15, 5.16, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "AZ_PRIVILEGED_AUTH_ADMIN": {"CIS": "5.4", "NIST": "PR.AA-02", "ISO 27001": "5.15, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "AZ_SECURITY_ADMIN": {"CIS": "5.4", "NIST": "PR.AA-02", "ISO 27001": "5.15, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "AZ_USER_ACCESS_ADMIN": {"CIS": "5.4", "NIST": "PR.AA-02", "ISO 27001": "5.15, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "AZ_ADD_SECRET": {"CIS": "6.1", "NIST": "PR.AA-03", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "AZ_ADD_OWNER": {"CIS": "6.1", "NIST": "PR.AA-03", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "AZ_ADD_TO_GROUP": {"CIS": "6.1", "NIST": "PR.AA-03", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "AZ_CONTRIBUTOR": {"CIS": "6.3", "NIST": "PR.AA-03", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "AZ_OWNER": {"CIS": "6.3", "NIST": "PR.AA-03", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "AZ_KEY_VAULT_ABUSE": {"CIS": "3.11", "NIST": "PR.DS-01", "ISO 27001": "8.24", "SA 315": "IT-3/ITDMC", "DPDP": "8(1)"},
    "AZ_MANAGED_IDENTITY": {"CIS": "5.4", "NIST": "PR.AA-02", "ISO 27001": "5.15, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "AZ_EXTERNAL_USER": {"CIS": "5.5", "NIST": "PR.AA-03", "ISO 27001": "5.15, 5.16", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "AZ_EXECUTE_COMMAND": {"CIS": "6.3", "NIST": "PR.AA-03", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "AZ_RESET_PASSWORD": {"CIS": "5.4", "NIST": "PR.AA-01", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-2/ITAC", "DPDP": "8(1)"},
    "AZ_ROLE_ESCALATION": {"CIS": "5.4", "NIST": "PR.AA-02", "ISO 27001": "5.15, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    
    # ── Zero Trust Identity Hardening Review ──────────
    "AZ_MFA_GAP": {"CIS": "5.6", "NIST": "PR.AA-01", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-2/ITAC", "DPDP": "8(1)"},
    "AZ_CA_POLICY_GAPS": {"CIS": "6.3", "NIST": "PR.AA-03", "ISO 27001": "5.15, 5.16", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "AZ_PIM_AUDIT": {"CIS": "6.8", "NIST": "PR.AA-02", "ISO 27001": "5.15, 5.16, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "AZ_SP_OVERSIGHT": {"CIS": "6.1", "NIST": "PR.AA-03", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "AZ_CROSS_TENANT_ACCESS": {"CIS": "5.5", "NIST": "PR.AA-03", "ISO 27001": "5.15, 5.16", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "AZ_CUSTOM_ROLES": {"CIS": "5.4", "NIST": "PR.AA-02", "ISO 27001": "5.15, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "AZ_PASSWORD_PROTECTION": {"CIS": "5.2", "NIST": "PR.AA-01", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-2/ITAC", "DPDP": "8(1)"},
    "AZ_LEGACY_AUTH": {"CIS": "5.6", "NIST": "PR.AA-01", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-2/ITAC", "DPDP": "8(1)"},
    "AZ_IDENTITY_GOVERNANCE": {"CIS": "6.8", "NIST": "PR.AA-03", "ISO 27001": "5.15, 5.16, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "AZ_AUTH_METHODS_POLICY": {"CIS": "5.6", "NIST": "PR.AA-01", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-2/ITAC", "DPDP": "8(1)"},
    "AZ_LOGGING_AUDIT": {"CIS": "8.2", "NIST": "DE.AE-02", "ISO 27001": "8.15, 8.16", "SA 315": "IT-3/ITDMC", "DPDP": "10(1)"},
    
    # ── Security Architecture Simulation ─────────────
    "AZ_GRAPH_API_ABUSE": {"CIS": "6.1", "NIST": "PR.AA-02", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "AZ_SYNC_ACCOUNT_COMPROMISE": {"CIS": "5.5", "NIST": "PR.AA-02", "ISO 27001": "5.15, 5.16, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "AZ_PRT_TOKEN_ABUSE": {"CIS": "5.6", "NIST": "PR.AA-01", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-2/ITAC", "DPDP": "8(1)"},
    "AZ_CA_BYPASS": {"CIS": "6.3", "NIST": "PR.AA-03", "ISO 27001": "5.15, 5.16", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "AZ_CROSS_TENANT_AUTH_CHAIN": {"CIS": "5.5", "NIST": "PR.AA-03", "ISO 27001": "5.15, 5.16", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "AZ_DEVICE_JOIN_ABUSE": {"CIS": "6.1", "NIST": "PR.AA-01", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-2/ITAC", "DPDP": "8(1)"},
    "AZ_MI_TOKEN_THEFT": {"CIS": "6.1", "NIST": "PR.AA-02", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "AZ_FUNCTION_KEY_ABUSE": {"CIS": "6.1", "NIST": "PR.AA-02", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "AZ_PAG_ESCALATION": {"CIS": "5.4", "NIST": "PR.AA-02", "ISO 27001": "5.15, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},

    # ── Non-Human Identity Governance ──────────────────────────
    "AZ_SP_NO_OWNER": {"CIS": "6.1", "NIST": "PR.AA-03", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "AZ_ORPHANED_APP": {"CIS": "6.1", "NIST": "PR.AA-03", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "AZ_OVERCONSENTED_APP": {"CIS": "6.1", "NIST": "PR.AA-02", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "AZ_SP_PRIVILEGED_NO_CA": {"CIS": "6.3", "NIST": "PR.AA-03", "ISO 27001": "5.15, 5.16", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
    "AZ_USER_ASSIGNED_MI": {"CIS": "6.1", "NIST": "PR.AA-02", "ISO 27001": "8.2, 8.3, 8.5", "SA 315": "IT-3/ITDMC", "DPDP": "9(1)"},
    "AZ_STALE_SERVICE_PRINCIPAL": {"CIS": "6.8", "NIST": "PR.AA-03", "ISO 27001": "5.15, 5.16, 8.2", "SA 315": "IT-1/GITC", "DPDP": "6(1)"},
}
EXCLUSIONS_MAP = {
    "TIER0_PATHS": [
        "Built-in groups (RIDs -512, -518, -526, -527, -544)",
        "Groups as path source nodes",
        "Principals with RID < 1000 (built-in/service accounts)",
    ],
    "ENTERPRISE_ADMIN_PATHS": [
        "Built-in Administrator account (RID -500)",
        "Groups as path source nodes",
        "Principals with RID < 1000 (built-in/service accounts)",
    ],
    "KERBEROAST": [
        "KRBTGT account (RID -502)",
        "Disabled user accounts",
        "Machine accounts (computer$)",
    ],
    "ASREP_ROAST": [
        "Accounts with Kerberos pre-authentication enabled",
        "Disabled user accounts",
    ],
    "DELEGATION": [
        "Domain Controllers without unconstrained delegation flag",
    ],
    "ADMIN_TO": [
        "Source principals filtered by LIMIT 10000 threshold",
    ],
    "DACL_ABUSE": [
        "ADMINISTRATORS@*, DOMAIN ADMINS@*, ENTERPRISE ADMINS@*, SYSTEM@* as source",
        "Built-in groups (RIDs -512, -519, -544) as source",
        "Source principals filtered by LIMIT 10000 threshold",
    ],
    "GPO_CONTROL": [
        "Default Domain Policy and Default Domain Controllers Policy",
        "Source principals filtered by LIMIT 5000 threshold",
    ],
    "SID_HISTORY": [
        "Accounts without SID History attribute populated",
    ],
    "DCSYNC": [
        "Domain Controllers (built-in replication rights)",
    ],
    "CONSTRAINED_DELEGATION": [
        "Computers without constrained delegation configured",
    ],
    "RBCD": [
        "Domain Controllers (not subject to RBCD abuse)",
    ],
    "PASSWORD_NOT_REQUIRED": [
        "Disabled user accounts",
        "Built-in Administrator (RID -500), KRBTGT (RID -502), Guest (RID -501)",
    ],
    "REVERSIBLE_ENCRYPTION": [
        "Disabled user accounts",
        "Accounts without reversible encryption flag set",
    ],
    "ACCOUNT_OPERATORS": [
        "Disabled user accounts",
        "Built-in members of Account Operators, Backup Operators, Print Operators, Server Operators",
    ],
    "CROSS_FOREST": [
        "Intra-forest trust relationships",
        "Domains with bidirectional filtering",
    ],
    "PRIVILEGED_GROUPS": [
        "Built-in Tier-0 groups (RIDs -544, -512, -519, -518)",
        "Disabled user accounts",
        "Query matches groups containing 'ADMINISTRATORS' in name only",
    ],
    "DISABLED_PRIVILEGED": [
        "Enabled user accounts",
        "Non-privileged group memberships",
    ],
    # ── Heading 1: Identity Attack Path Assessment ──────────────
    "CERT_ABUSE_ESC1": [
        "Certificate templates with Manager Approval required",
        "Templates restricted to specific security groups outside query scope",
        "Built-in CA and Domain Controller certificates",
    ],
    "CERT_ABUSE_ESC3": [
        "Enrollment agent templates without Subject Name supply",
        "Manager approval required on the subject template",
    ],
    "SHADOW_CREDENTIALS": [
        "Group-managed service accounts (gMSA) with automatic key rotation",
        "Cross-domain shadow credential relationships",
    ],
    "DANGEROUS_COMPUTER_ACLS": [
        "Computer objects (covered by AD-012 RBCD finding)",
        "Domain Admins group as source principal (elevated by design)",
        "Source principals filtered by LIMIT 5000 threshold",
    ],
    "NTLM_RELAY_PATHS": [
        "Relay paths mitigated by SMB signing enforcement on the DC",
        "Relay paths blocked by LDAP signing + channel binding on the DC",
        "Relay paths protected by EPA (Extended Protection for Authentication)",
        "Source computers filtered by LIMIT 5000 threshold",
    ],
    "LAPS_GAPS": [
        "Domain Controllers (managed via domain-joined admin lifecycle, not LAPS)",
        "Windows Server 2003 and earlier (legacy, no LAPS support)",
    ],
    "SQL_LINKED_SERVERS": [
        "SQL Server instances not configured for linked server queries",
        "Source principals without SQLAdmin rights",
    ],
    "DOMAIN_TRUST_ESCALATION": [
        "Intra-forest trusts with SID filtering enabled",
        "Parent-child domain trusts in the same forest without delegation",
    ],
    "AZ_GLOBAL_ADMIN": [
        "Break-glass emergency access accounts (excluded from BloodHound collection)",
        "Built-in Microsoft service principals",
    ],
    "AZ_PRIVILEGED_ROLE_ADMIN": [
        "Built-in Microsoft service principals",
    ],
    "AZ_HYBRID_IDENTITY_ADMIN": [
        "Built-in Microsoft service principals",
    ],
    "AZ_APPLICATION_ADMIN": [
        "Built-in Microsoft service principals",
    ],
    "AZ_CLOUD_APP_ADMIN": [
        "Built-in Microsoft service principals",
    ],
    "AZ_CONDITIONAL_ACCESS_ADMIN": [
        "Built-in Microsoft service principals",
    ],
    "AZ_PRIVILEGED_AUTH_ADMIN": [
        "Built-in Microsoft service principals",
    ],
    "AZ_SECURITY_ADMIN": [
        "Built-in Microsoft service principals",
    ],
    "AZ_USER_ACCESS_ADMIN": [
        "Built-in Microsoft service principals",
    ],
    "AZ_ADD_SECRET": [
        "Built-in Microsoft service principals",
    ],
    "AZ_ADD_OWNER": [
        "Built-in Microsoft service principals",
    ],
    "AZ_ADD_TO_GROUP": [
        "Built-in Microsoft service principals",
    ],
    "AZ_CONTRIBUTOR": [
        "Subscription-level Contributor is a broad role; scope-based filtering may apply",
        "Built-in Microsoft service principals",
    ],
    "AZ_OWNER": [
        "Built-in Microsoft service principals",
        "Subscription-level Owner role; break-glass accounts excluded from BloodHound collection",
    ],
    "AZ_KEY_VAULT_ABUSE": [
        "Built-in Microsoft managed identities",
    ],
    "AZ_MANAGED_IDENTITY": [
        "User-assigned managed identities with no role assignments",
    ],
    "AZ_EXTERNAL_USER": [
        "Internal (non-guest) user accounts",
    ],
    "AZ_EXECUTE_COMMAND": [
        "Principals without Run Command permissions",
    ],
    "AZ_RESET_PASSWORD": [
        "Users without password reset permissions",
    ],
    "AZ_ROLE_ESCALATION": [
        "Direct role assignments (non-group-mediated)",
        "Principals filtered by query scope",
    ],
    # ── Heading 2: Zero Trust Identity Hardening Review ──────────
    "AZ_MFA_GAP": [
        "Users with MFA registered in authentication methods policy only (not visible in BHCE)",
        "Service principals and managed identities (not subject to user MFA policies)",
        "Built-in Microsoft platform accounts",
    ],
    "AZ_CA_POLICY_GAPS": [
        "Policies targeting specific applications or locations outside query scope",
        "User-level CA policy exclusions (break-glass accounts)",
        "ReportOnly policies under active evaluation",
    ],
    "AZ_PIM_AUDIT": [
        "Role assignments with PIM activation time limits under 24 hours",
        "Built-in Microsoft service principals with permanent assignments",
        "Break-glass emergency access accounts",
    ],
    "AZ_SP_OVERSIGHT": [
        "Managed identities with system-assigned roles (cannot be stolen outside VM context)",
        "Built-in Microsoft service principals (First Party)",
        "Service principals with scoped role assignments (not tenant-wide)",
    ],
    "AZ_CROSS_TENANT_ACCESS": [
        "Organizations with explicit B2B allowlists or entitlement management",
        "Cross-tenant access with inbound trust enforcement",
    ],
    "AZ_CUSTOM_ROLES": [
        "Built-in Azure role definitions (isBuiltin = true)",
        "Custom roles with no assignments",
    ],
    "AZ_PASSWORD_PROTECTION": [
        "Tenants using alternative password protection mechanisms (e.g., third-party PAM)",
        "Hybrid environments where on-premises password protection is enforced via AD FS",
        "Tenants with custom banned password lists configured outside BHCE visibility",
    ],
    "AZ_LEGACY_AUTH": [
        "Service accounts requiring legacy protocols for application compatibility (must be documented as exceptions)",
        "On-premises mail flow using SMTP connectors (not user-facing authentication)",
        "Tenants using Exchange Online with legacy auth disabled at transport level",
    ],
    "AZ_IDENTITY_GOVERNANCE": [
        "Users with last login outside 90-day window who are deliberately preserved as break-glass accounts",
        "Guest users with verified active external collaboration agreements",
        "Tenants using third-party governance tools (outside BHCE visibility)",
    ],
    "AZ_AUTH_METHODS_POLICY": [
        "Tenants using third-party MFA providers integrated via federation",
        "FIDO2 deployment in progress with documented rollout timeline",
        "Hardware token constraints for remote workforce",
    ],
    "AZ_LOGGING_AUDIT": [
        "Tenants using third-party SIEM connectors not visible in BHCE graph",
        "Log retention requirements satisfied via Azure Storage archival or Log Analytics workspace",
        "Tenants under 12-month audit exception period",
    ],
    # ── Heading 3: Security Architecture Simulation ─────────────
    "AZ_GRAPH_API_ABUSE": [
        "First-party Microsoft applications with delegated permissions (user-consented, not app-only)",
        "Applications with Graph permissions scoped to specific directory roles or administrative units",
        "Applications with permissions in 'disabled' or 'pending' state",
    ],
    "AZ_SYNC_ACCOUNT_COMPROMISE": [
        "On-premises sync accounts without Global Admin role assignment (cloud-only privileges)",
        "Tenants using PHS with pass-through authentication (no stored password hash)",
        "Hybrid identity accounts with MFA enforced via Conditional Access",
    ],
    "AZ_PRT_TOKEN_ABUSE": [
        "Devices not enrolled in Microsoft Intune or MDM",
        "Users without WHfB or PRT-capable device registration",
        "Browser-based tokens with short session lifetimes",
    ],
    "AZ_CA_BYPASS": [
        "Locations defined using IPv4 ranges (not trusted IPs) with MFA enforcement",
        "Compliant device exemptions for platform-managed kiosk devices",
        "MFA fatigue requires proof of compromise — listed as supplementary simulation data",
    ],
    "AZ_CROSS_TENANT_AUTH_CHAIN": [
        "Guest users with scoped access (not tenant-wide role assignments)",
        "Cross-tenant access with automatic redemption disabled",
        "Downstream tenants without inbound trust policies",
    ],
    "AZ_DEVICE_JOIN_ABUSE": [
        "Devices not registered in Entra ID or registered as Workplace Joined only",
        "Hybrid devices with BitLocker and conditional launch enabled",
        "VDI or ephemeral device sessions",
    ],
    "AZ_MI_TOKEN_THEFT": [
        "Managed identities with no role assignments (identity-only, no RBAC)",
        "System-assigned MIs (cannot be stolen outside compromised compute context)",
        "MI tokens with short expiry and Azure Key Vault access policy restrictions",
    ],
    "AZ_FUNCTION_KEY_ABUSE": [
        "Function apps with anonymous auth level (no key required at function level)",
        "Function keys stored in Key Vault with access restricted to managed identity",
        "APIM subscriptions revoked or with restricted product scope",
    ],
    "AZ_PAG_ESCALATION": [
        "Users who are members of device admin groups but lack interactive logon",
        "Groups with local admin scope limited to specific VMs (not any device)",
        "PAG membership via PIM-eligible role (requires activation, not permanent)",
    ],

    # ── Non-Human Identity Governance ──────────────────────────
    "AZ_SP_NO_OWNER": [
        "First-party Microsoft service principals (appownerorganizationid matches Microsoft)",
        "System-assigned managed identities (no owner by design)",
        "Service principals whose linked AZApplication already has an owner",
    ],
    "AZ_ORPHANED_APP": [
        "First-party Microsoft applications",
        "Apps already flagged by AZ_SP_NO_OWNER (deduplication)",
        "Apps with active re-ownership workflow in progress",
    ],
    "AZ_OVERCONSENTED_APP": [
        "First-party Microsoft applications with delegated (user-consented) permissions",
        "Applications with permissions scoped to specific directory roles or admin units",
        "Permissions in 'disabled' or 'pending' state",
    ],
    "AZ_SP_PRIVILEGED_NO_CA": [
        "Built-in Microsoft service principals",
        "Break-glass emergency access principals",
        "Workload identities documented as covered by CA policy exclusions",
    ],
    "AZ_USER_ASSIGNED_MI": [
        "User-assigned MIs with no role assignments",
        "System-assigned managed identities (single-attachment, lifecycle-bound)",
        "Documented shared-infrastructure patterns with justified multiple attachment",
    ],
    "AZ_STALE_SERVICE_PRINCIPAL": [
        "First-party Microsoft service principals",
        "System-assigned managed identities (lifecycle-bound to a resource)",
        "SPs with recent sign-in activity in enrichment data",
    ],
}

SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 5,
    "MEDIUM": 3,
    "LOW": 1,
}

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#2563eb",
}
