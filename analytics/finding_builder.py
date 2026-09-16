class FindingBuilder:

    FINDINGS = [
        # ── Group: AD Core ───────────────────────────────────────
        ("TIER0_PATHS", "Tier 0 Attack Paths Detected", "tier0_paths", "Active Directory", "ad_core"),
        ("ENTERPRISE_ADMIN_PATHS", "Enterprise Admin Paths Detected", "enterprise_admin_paths", "Active Directory", "ad_core"),
        ("KERBEROAST", "Kerberoastable Accounts Detected", "kerberoast", "Active Directory", "ad_core"),
        ("ASREP_ROAST", "AS-REP Roastable Accounts Detected", "asrep_roast", "Active Directory", "ad_core"),
        ("DELEGATION", "Unconstrained Delegation Detected", "delegation", "Active Directory", "ad_core"),
        ("ADMIN_TO", "Local Admin Relationships Detected", "admin_to", "Active Directory", "ad_core"),
        ("DACL_ABUSE", "Excessive Permissions Detected", "dacl_abuse", "Active Directory", "ad_core"),
        ("GPO_CONTROL", "GPO Modification Rights Detected", "gpo_control", "Active Directory", "ad_core"),
        ("SID_HISTORY", "SID History Abuse Potential", "sid_history", "Active Directory", "ad_core"),
        ("DCSYNC", "DCSync Rights Granted", "dcsync", "Active Directory", "ad_core"),
        ("CONSTRAINED_DELEGATION", "Constrained Delegation Misconfiguration", "constrained_delegation", "Active Directory", "ad_core"),
        ("RBCD", "Resource-Based Constrained Delegation Abuse", "rbcd", "Active Directory", "ad_core"),
        ("PASSWORD_NOT_REQUIRED", "Accounts Without Password Requirement", "password_not_required", "Active Directory", "ad_core"),
        ("REVERSIBLE_ENCRYPTION", "Accounts With Reversible Encryption", "reversible_encryption", "Active Directory", "ad_core"),
        ("ACCOUNT_OPERATORS", "Privileged Built-in Group Memberships", "account_operators", "Active Directory", "ad_core"),
        ("CROSS_FOREST", "Cross-Forest Trust Relationships", "cross_forest", "Active Directory", "ad_core"),
        ("PRIVILEGED_GROUPS", "Non-Tier-0 Administrative Groups", "privileged_groups", "Active Directory", "ad_core"),
        ("DISABLED_PRIVILEGED", "Disabled Accounts in Privileged Groups", "disabled_privileged", "Active Directory", "ad_core"),
        # ── Group: AD Attack Paths ───────────────────────────────
        ("CERT_ABUSE_ESC1", "AD-CS ESC1 — Certificate Template Abuse (Domain Escalation)", "cert_abuse_esc1", "Active Directory", "ad_attack"),
        ("CERT_ABUSE_ESC3", "AD-CS ESC3 — Certificate Agent Enrollment Abuse", "cert_abuse_esc3", "Active Directory", "ad_attack"),
        ("SHADOW_CREDENTIALS", "Shadow Credentials — Key Credential Link Abuse", "shadow_credentials", "Active Directory", "ad_attack"),
        ("DANGEROUS_COMPUTER_ACLS", "Dangerous Object ACLs — User/Group/OU Takeover", "dangerous_object_acls", "Active Directory", "ad_attack"),
        ("NTLM_RELAY_PATHS", "NTLM Relay — Web Server to Domain Controller Paths", "ntlm_relay_paths", "Active Directory", "ad_attack"),
        ("LAPS_GAPS", "LAPS Deployment Gaps — Weak Local Admin Password Protection", "laps_gaps", "Active Directory", "ad_attack"),
        ("SQL_LINKED_SERVERS", "MS-SQL Linked Server — Lateral Movement Risk", "sql_linked_servers", "Active Directory", "ad_attack"),
        ("DOMAIN_TRUST_ESCALATION", "Domain Trust Escalation — SID Filtering Disabled / TGT Delegation", "domain_trust_escalation", "Active Directory", "ad_attack"),
        # ── Group: Azure Core ────────────────────────────────────
        ("AZ_GLOBAL_ADMIN", "Global Administrator Assignment", "az_global_admin", "Azure", "az_core"),
        ("AZ_PRIVILEGED_ROLE_ADMIN", "Privileged Role Administrator Assignment", "az_privileged_role_admin", "Azure", "az_core"),
        ("AZ_HYBRID_IDENTITY_ADMIN", "Hybrid Identity Administrator Assignment", "az_hybrid_identity_admin", "Azure", "az_core"),
        ("AZ_APPLICATION_ADMIN", "Application Administrator Assignment", "az_application_admin", "Azure", "az_core"),
        ("AZ_CLOUD_APP_ADMIN", "Cloud Application Administrator Assignment", "az_cloud_app_admin", "Azure", "az_core"),
        ("AZ_CONDITIONAL_ACCESS_ADMIN", "Conditional Access Administrator Assignment", "az_conditional_access_admin", "Azure", "az_core"),
        ("AZ_PRIVILEGED_AUTH_ADMIN", "Privileged Authentication Administrator Assignment", "az_privileged_auth_admin", "Azure", "az_core"),
        ("AZ_SECURITY_ADMIN", "Security Administrator Assignment", "az_security_admin", "Azure", "az_core"),
        ("AZ_USER_ACCESS_ADMIN", "User Access Administrator Assignment", "az_user_access_admin", "Azure", "az_core"),
        ("AZ_ADD_SECRET", "Application Credential Abuse", "az_add_secret", "Azure", "az_core"),
        ("AZ_ADD_OWNER", "Application Owner Abuse", "az_add_owner", "Azure", "az_core"),
        ("AZ_ADD_TO_GROUP", "Group Membership Abuse", "az_add_to_group", "Azure", "az_core"),
        ("AZ_CONTRIBUTOR", "Azure Contributor Role Assignments", "az_contributor", "Azure", "az_core"),
        ("AZ_OWNER", "Azure Owner Role Assignments", "az_owner", "Azure", "az_core"),
        ("AZ_KEY_VAULT_ABUSE", "Key Vault Access Abuse", "az_key_vault_contributor", "Azure", "az_core"),
        ("AZ_MANAGED_IDENTITY", "Managed Identity Privileges", "az_managed_identity_roles", "Azure", "az_core"),
        ("AZ_EXTERNAL_USER", "External User Access", "az_external_users", "Azure", "az_core"),
        ("AZ_EXECUTE_COMMAND", "Remote Command Execution Risk", "az_execute_command", "Azure", "az_core"),
        ("AZ_RESET_PASSWORD", "Password Reset Privilege Abuse", "az_reset_password", "Azure", "az_core"),
        ("AZ_ROLE_ESCALATION", "Azure Role Escalation Paths", "az_role_escalation", "Azure", "az_core"),
        # ── Group: Zero Trust Review ─────────────────────────────
        ("AZ_MFA_GAP", "MFA Registration Gap — Users Without MFA", "az_mfa_gap", "Azure", "az_zt_review"),
        ("AZ_CA_POLICY_GAPS", "Conditional Access Policy Gaps — Disabled or Report-Only", "az_ca_policy_gaps", "Azure", "az_zt_review"),
        ("AZ_PIM_AUDIT", "PIM Activation Audit — Permanently Active Privileged Roles", "az_pim_audit", "Azure", "az_zt_review"),
        ("AZ_SP_OVERSIGHT", "Service Principal Oversight — Overprivileged Application Principals", "az_sp_oversight", "Azure", "az_zt_review"),
        ("AZ_CROSS_TENANT_ACCESS", "Unrestricted Cross-Tenant Collaboration", "az_cross_tenant_access", "Azure", "az_zt_review"),
        ("AZ_CUSTOM_ROLES", "Custom RBAC Role Definitions — Audit Required", "az_custom_roles", "Azure", "az_zt_review"),
        ("AZ_PASSWORD_PROTECTION", "Password Protection Policy — Not Configured", "az_password_protection", "Azure", "az_zt_review"),
        ("AZ_LEGACY_AUTH", "Legacy Authentication Flows — POP/IMAP/SMTP Auth Enabled", "az_legacy_auth", "Azure", "az_zt_review"),
        ("AZ_IDENTITY_GOVERNANCE", "Identity Governance Gaps — No Access Reviews, Stale Entitlements", "az_identity_governance", "Azure", "az_zt_review"),
        ("AZ_AUTH_METHODS_POLICY", "Authentication Methods Policy — SMS/Voice Allowed, Passwordless Absent", "az_auth_methods_policy", "Azure", "az_zt_review"),
        ("AZ_LOGGING_AUDIT", "Entra ID Logging — Diagnostic Settings Not Streaming to SIEM", "az_logging_audit", "Azure", "az_zt_review"),
        # ── Group: Architecture Simulation ───────────────────────
        ("AZ_GRAPH_API_ABUSE", "Graph API App Permission Abuse — Password Reset / Role Assignment via API", "az_graph_api_abuse", "Azure", "az_arch_sim"),
        ("AZ_SYNC_ACCOUNT_COMPROMISE", "Entra Connect Sync Account Compromise — PHS Decryption / USN Rollback", "az_sync_account_compromise", "Azure", "az_arch_sim"),
        ("AZ_PRT_TOKEN_ABUSE", "PRT / Session Token Abuse — Persistent Token Access & Device Claim Bypass", "az_prt_token_abuse", "Azure", "az_arch_sim"),
        ("AZ_CA_BYPASS", "Conditional Access Bypass Simulation — Trusted IPs / Compliant Device / MFA Fatigue", "az_ca_bypass", "Azure", "az_arch_sim"),
        ("AZ_CROSS_TENANT_AUTH_CHAIN", "Cross-Tenant Authentication Chain — Lateral Movement Across Tenants", "az_cross_tenant_auth_chain", "Azure", "az_arch_sim"),
        ("AZ_DEVICE_JOIN_ABUSE", "Hybrid Azure AD Join Abuse — Device Auth Relay & WPAD + AD CS", "az_device_join_abuse", "Azure", "az_arch_sim"),
        ("AZ_MI_TOKEN_THEFT", "Managed Identity Token Theft — Downstream Resource Access via Stolen MI Token", "az_mi_token_theft", "Azure", "az_arch_sim"),
        ("AZ_FUNCTION_KEY_ABUSE", "Azure Function / APIM Key Abuse — Leaked Keys to Key Vault Access", "az_function_key_abuse", "Azure", "az_arch_sim"),
        ("AZ_PAG_ESCALATION", "Privileged Access Group Escalation — Device Local Admin to Lateral Path", "az_pag_escalation", "Azure", "az_arch_sim"),
        # ── Group: Non-Human Identity Governance ────────────────
        ("AZ_SP_NO_OWNER", "Application Identity Without Owner — Ungoverned Service Principal", "az_sp_no_owner", "Azure", "nhi_governance"),
        ("AZ_ORPHANED_APP", "Orphaned Application — All Owners Disabled or Deleted", "az_orphaned_app", "Azure", "nhi_governance"),
        ("AZ_OVERCONSENTED_APP", "Over-Consented Service Principal — Broad Microsoft Graph Permissions", "az_overconsented_app", "Azure", "nhi_governance"),
        ("AZ_SP_PRIVILEGED_NO_CA", "Privileged Service Principal — Outside Conditional Access Scope", "az_sp_privileged_no_ca", "Azure", "nhi_governance"),
        ("AZ_USER_ASSIGNED_MI", "User-Assigned Managed Identities — Portable Workload Credentials", "az_user_assigned_mi", "Azure", "nhi_governance"),
        ("AZ_STALE_SERVICE_PRINCIPAL", "Stale Service Principals — Dormant Identity Governance Gap", "az_stale_service_principal", "Azure", "nhi_governance"),
        ("AZ_SP_DISABLED_PRIVILEGED", "Disabled Service Principal Retaining Privileges — Decommission Gap", "az_sp_disabled_privileged", "Azure", "nhi_governance"),
        ("AZ_SP_SINGLE_OWNER", "Single-Owner Service Principal — No Dual Control", "az_sp_single_owner", "Azure", "nhi_governance"),
        ("AZ_SP_OWNER_DISABLED", "Service Principal With No Active Owner — All Owners Disabled", "az_sp_owner_disabled", "Azure", "nhi_governance"),
        ("AZ_STALE_MANAGED_IDENTITY", "Stale Managed Identity — Dormant Workload Credential", "az_stale_managed_identity", "Azure", "nhi_governance"),
        ("AZ_STALE_DEVICE", "Stale Registered Device — Idle Enrollment 90+ Days", "az_stale_device", "Azure", "nhi_governance"),
        ("AZ_SP_COMBINED_PRIVILEGES", "Service Principal With Combined Directory + Azure Roles", "az_sp_combined_privileges", "Azure", "nhi_governance"),
        ("AZ_SP_OWNER_GROUP", "Service Principal Owned by Azure Group — Diffuse Accountability", "az_sp_owner_group", "Azure", "nhi_governance"),
        ("AZ_SP_LEGACY_TYPE", "Legacy / Unknown Service Principal Type — Hygiene Risk", "az_sp_legacy_type", "Azure", "nhi_governance"),
    ]

    def build(self, raw, selected_groups=None):
        findings = []

        for fid, title, key, source, group in self.FINDINGS:
            if selected_groups is not None and group not in selected_groups:
                continue
            evidence = raw.get(key, [])

            findings.append({
                "id": fid,
                "title": title,
                "severity": "LOW",
                "source": source,
                "group": group,
                "impact": "",
                "remediation": [],
                "detection": [],
                "mitre": {},
                "ad_objects": {
                    "users": [],
                    "groups": [],
                    "computers": [],
                    "gpos": [],
                    "organizational_units": [],
                    "relationships": [],
                },
                "evidence": evidence,
                "has_evidence": len(evidence) > 0,
            })

        return findings
