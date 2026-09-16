GROUPS = {
    "ad_core": {
        "name": "Active Directory Core Assessment",
        "heading": "",
        "report_title": "Active Directory Core Security Assessment Report",
    },
    "ad_attack": {
        "name": "Identity Attack Path Assessment",
        "heading": "1",
        "report_title": "Identity Attack Path Assessment Report",
    },
    "az_core": {
        "name": "Azure/Entra ID Core Assessment",
        "heading": "",
        "report_title": "Azure/Entra ID Core Security Assessment Report",
    },
    "az_zt_review": {
        "name": "Zero Trust Identity Hardening Review",
        "heading": "2",
        "report_title": "Zero Trust Identity Hardening Review Report",
    },
    "az_arch_sim": {
        "name": "Security Architecture Simulation",
        "heading": "3",
        "report_title": "Security Architecture Simulation Report",
    },
    "nhi_governance": {
        "name": "Non-Human Identity Governance",
        "heading": "4",
        "report_title": "Non-Human Identity Governance Assessment Report",
    },
}

GROUP_ORDER = ["ad_core", "ad_attack", "az_core", "az_zt_review", "az_arch_sim", "nhi_governance"]

GROUP_QUERY_KEYS = {
    "ad_core": {
        "tier0_paths", "enterprise_admin_paths", "kerberoast", "asrep_roast",
        "delegation", "admin_to", "dacl_abuse", "gpo_control", "sid_history",
        "dcsync", "constrained_delegation", "rbcd", "password_not_required",
        "reversible_encryption", "account_operators", "privileged_groups",
        "disabled_privileged", "cross_forest",
    },
    "ad_attack": {
        "cert_abuse_esc1", "cert_abuse_esc3", "shadow_credentials",
        "dangerous_object_acls", "ntlm_relay_paths", "laps_gaps",
        "sql_linked_servers", "domain_trust_escalation",
    },
    "az_core": {
        "az_global_admin", "az_privileged_role_admin", "az_privileged_auth_admin",
        "az_hybrid_identity_admin", "az_application_admin", "az_cloud_app_admin",
        "az_conditional_access_admin", "az_user_access_admin", "az_security_admin",
        "az_contributor", "az_owner", "az_add_secret", "az_add_owner",
        "az_add_to_group", "az_key_vault_contributor", "az_managed_identity",
        "az_managed_identity_roles", "az_external_users", "az_execute_command",
        "az_reset_password", "az_role_escalation",
    },
    "az_zt_review": {
        "az_mfa_gap", "az_ca_policy_gaps", "az_pim_audit", "az_sp_oversight",
        "az_cross_tenant_access", "az_custom_roles", "az_password_protection",
        "az_legacy_auth", "az_identity_governance", "az_auth_methods_policy",
        "az_logging_audit",
    },
    "az_arch_sim": {
        "az_graph_api_abuse", "az_sync_account_compromise", "az_prt_token_abuse",
        "az_ca_bypass", "az_cross_tenant_auth_chain", "az_device_join_abuse",
        "az_mi_token_theft", "az_function_key_abuse", "az_pag_escalation",
    },
    "nhi_governance": {
        "az_sp_no_owner", "az_orphaned_app", "az_overconsented_app",
        "az_sp_privileged_no_ca", "az_user_assigned_mi", "az_stale_service_principal",
    },
}

ALL_QUERY_KEYS = set()
for keys in GROUP_QUERY_KEYS.values():
    ALL_QUERY_KEYS.update(keys)
