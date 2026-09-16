AZURE_QUERIES = {
    # ── Entra ID Role Assignments (via AZHasRole) ───────────────
    "az_global_admin": """
        MATCH (n)-[:AZHasRole]->(r:AZRoleDefinition)
        WHERE r.displayname = 'Global Administrator'
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType
        LIMIT 15000
    """,
    "az_privileged_role_admin": """
        MATCH (n)-[:AZHasRole]->(r:AZRoleDefinition)
        WHERE r.displayname = 'Privileged Role Administrator'
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType
        LIMIT 15000
    """,
    "az_privileged_auth_admin": """
        MATCH (n)-[:AZHasRole]->(r:AZRoleDefinition)
        WHERE r.displayname = 'Privileged Authentication Administrator'
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType
        LIMIT 15000
    """,
    "az_hybrid_identity_admin": """
        MATCH (n)-[:AZHasRole]->(r:AZRoleDefinition)
        WHERE r.displayname = 'Hybrid Identity Administrator'
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType
        LIMIT 15000
    """,
    "az_application_admin": """
        MATCH (n)-[:AZHasRole]->(r:AZRoleDefinition)
        WHERE r.displayname = 'Application Administrator'
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType
        LIMIT 15000
    """,
    "az_cloud_app_admin": """
        MATCH (n)-[:AZHasRole]->(r:AZRoleDefinition)
        WHERE r.displayname = 'Cloud Application Administrator'
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType
        LIMIT 15000
    """,
    "az_conditional_access_admin": """
        MATCH (n)-[:AZHasRole]->(r:AZRoleDefinition)
        WHERE r.displayname = 'Conditional Access Administrator'
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType
        LIMIT 15000
    """,

    # ── Azure RBAC Role Assignments (native edges) ──────────────
    "az_user_access_admin": """
        MATCH (n)-[r:AZUserAccessAdmin]->(t:AZTenant)
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType, t.name AS Tenant
        LIMIT 15000
    """,
    "az_security_admin": """
        MATCH (n)-[r:AZSecurityAdmin]->(t:AZTenant)
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType, t.name AS Tenant
        LIMIT 15000
    """,
    "az_contributor": """
        MATCH (n)-[r:AZContributor]->(scope)
        WHERE ANY(lbl IN LABELS(scope) WHERE lbl IN ['AZSubscription', 'AZResourceGroup', 'AZManagementGroup'])
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType,
               type(r) AS Role, scope.name AS Scope, LABELS(scope) AS ScopeType
        LIMIT 15000
    """,
    "az_owner": """
        MATCH (n)-[r:AZOwner]->(scope)
        WHERE ANY(lbl IN LABELS(scope) WHERE lbl IN ['AZSubscription', 'AZResourceGroup', 'AZManagementGroup'])
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType,
               type(r) AS Role, scope.name AS Scope, LABELS(scope) AS ScopeType
        LIMIT 15000
    """,

    # ── Application / Service Principal Abuse ──────────────────
    "az_add_secret": """
        MATCH (n)-[r:AZAddSecret]->(app:AZApplication)
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType, app.name AS Application
        LIMIT 15000
    """,
    "az_add_owner": """
        MATCH (n)-[r:AZAddOwner]->(app:AZApplication)
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType, app.name AS Application
        LIMIT 15000
    """,
    "az_add_to_group": """
        MATCH (n)-[r:AZAddToGroup]->(g:AZGroup)
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType, g.name AS TargetGroup
        LIMIT 15000
    """,

    # ── Key Vault Access ───────────────────────────────────────
    "az_key_vault_contributor": """
        MATCH (n)-[r:AZKeyVaultContributor]->(kv:AZKeyVault)
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType, kv.name AS KeyVault
        LIMIT 15000
    """,

    # ── Managed Identity ──────────────────────────────────────
    "az_managed_identity": """
        MATCH (mi:AZManagedIdentity)
        RETURN mi.name AS Identity, mi.objectid AS ObjectId
        LIMIT 15000
    """,
    "az_managed_identity_roles": """
        MATCH (mi:AZManagedIdentity)-[r]->(scope)
        WHERE r:AZContributor OR r:AZOwner OR r:AZKeyVaultContributor
           OR r:AZUserAccessAdmin OR r:AZSecurityAdmin
        RETURN mi.name AS Identity, type(r) AS Role, scope.name AS Scope, LABELS(scope) AS ScopeType
        LIMIT 15000
    """,

    # ── External / Guest Users ─────────────────────────────────
    "az_external_users": """
        MATCH (u:AZUser)
        WHERE u.userprincipalname CONTAINS '#EXT#'
           OR COALESCE(u.onpremisessamaccountname, '') = ''
        RETURN u.name AS User, u.userprincipalname AS UPN
        LIMIT 15000
    """,

    # ── Execute Command (VM access) ────────────────────────────
    "az_execute_command": """
        MATCH (n)-[r:AZExecuteCommand]->(vm:AZVM)
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType, vm.name AS VirtualMachine
        LIMIT 15000
    """,
    "az_reset_password": """
        MATCH (n)-[r:AZResetPassword]->(target)
        WHERE target:AZUser OR target:AZVM
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType,
               target.name AS Target, LABELS(target) AS TargetType
        LIMIT 15000
    """,

    # ── Privileged role escalation via group membership ────────
    "az_role_escalation": """
        MATCH (a)-[:AZMemberOf]->(g:AZGroup)
        MATCH (g)-[:AZHasRole]->(r:AZRoleDefinition)
        WHERE r.displayname IN ['Global Administrator', 'Privileged Role Administrator',
               'Hybrid Identity Administrator', 'Application Administrator',
               'Cloud Application Administrator']
        RETURN a.name AS Principal, LABELS(a) AS PrincipalType,
               g.name AS Group, r.displayname AS Role
        LIMIT 15000
    """,

    # ── Heading 2: Zero Trust Identity Hardening Review ─────────

    # MFA registration gaps
    "az_mfa_gap": """
        MATCH (u:AZUser)
        WHERE u.mfaenabled = false
           OR u.mfaenabled IS NULL
        RETURN u.name AS User, u.userprincipalname AS UPN
        LIMIT 15000
    """,

    # Conditional Access policies in disabled or report-only state
    "az_ca_policy_gaps": """
        MATCH (p:AZConditionalAccessPolicy)
        WHERE p.state = 'disabled'
           OR p.state IN ['reportOnly', 'disabled']
        RETURN p.displayname AS Policy, p.state AS State
        LIMIT 15000
    """,

    # Permanently active privileged role assignments (not PIM-eligible)
    "az_pim_audit": """
        MATCH (n)-[ass:AZHasRole]->(r:AZRoleDefinition)
        WHERE r.displayname IN ['Global Administrator', 'Privileged Role Administrator',
               'Hybrid Identity Administrator', 'Application Administrator',
               'Cloud Application Administrator', 'Conditional Access Administrator',
               'Privileged Authentication Administrator', 'Security Administrator',
               'User Access Administrator']
          AND (ass.permanent = true OR ass.permanent IS NULL)
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType,
               r.displayname AS Role
        LIMIT 15000
    """,

    # Overprivileged service principals with tenant-wide roles
    "az_sp_oversight": """
        MATCH (sp:AZServicePrincipal)-[:AZHasRole]->(r:AZRoleDefinition)
        WHERE r.displayname IN ['Global Administrator', 'Privileged Role Administrator',
               'Hybrid Identity Administrator', 'Application Administrator',
               'Cloud Application Administrator', 'Conditional Access Administrator']
        RETURN sp.name AS Principal, r.displayname AS Role
        LIMIT 15000
    """,

    # Unrestricted cross-tenant access collaboration
    "az_cross_tenant_access": """
        MATCH (t:AZTenant)-[r:AZCrossTenantAccess]->(et:AZTenant)
        WHERE COALESCE(r.automaticredeem, r.automaticRedeem, false) = false
           OR COALESCE(r.automaticredeem, r.automaticRedeem, 'false') = 'false'
           OR COALESCE(r.userconsent, r.userConsent, false) = true
           OR COALESCE(r.userconsent, r.userConsent, 'true') = 'true'
           OR COALESCE(r.inboundtrust, r.inboundTrust) IS NULL
        RETURN t.name AS Tenant, et.name AS ExternalTenant,
               COALESCE(r.automaticredeem, r.automaticRedeem) AS AutoRedeem,
               COALESCE(r.userconsent, r.userConsent) AS UserConsent,
               COALESCE(r.inboundtrust, r.inboundTrust) AS InboundTrust
        LIMIT 15000
    """,
    "az_custom_roles": """
        MATCH (rd:AZRoleDefinition)
        WHERE COALESCE(rd.isbuiltin, rd.isBuiltIn) = false
        RETURN rd.displayname AS RoleName, rd.description AS Description,
               rd.actions AS Actions, rd.notactions AS NotActions
        LIMIT 15000
    """,

    # Password protection policy evaluation
    "az_password_protection": """
        MATCH (t:AZTenant)
        WHERE (t.passwordprotection = false OR t.passwordprotection = 'false')
           OR t.passwordprotection IS NULL
        RETURN t.name AS Tenant, t.displayname AS TenantName,
               t.passwordprotection AS PasswordProtection
        LIMIT 15000
    """,

    # Legacy authentication flows enabled
    "az_legacy_auth": """
        MATCH (u:AZUser)
        WHERE u.legacyauthenabled = true
           OR u.legacyauthenabled IS NULL
        RETURN u.name AS User, u.userprincipalname AS UPN,
               u.legacyauthenabled AS LegacyAuthEnabled
        LIMIT 15000
    """,

    # Identity governance gaps (stale accounts > 90 days)
    "az_identity_governance": """
        MATCH (u:AZUser)
        WHERE u.lastsignin IS NULL
           OR TOINTEGER(u.lastsignin) < (timestamp() - 7776000000)
        RETURN u.name AS User, u.userprincipalname AS UPN,
               u.lastsignin AS LastSignIn
        LIMIT 15000
    """,

    # Authentication methods policy
    "az_auth_methods_policy": """
        MATCH (t:AZTenant)
        WHERE (t.authenticationmethods = '[]' OR t.authenticationmethods = [])
           OR t.authenticationmethods IS NULL
           OR t.fido2enabled = false
        RETURN t.name AS Tenant, t.displayname AS TenantName,
               t.authenticationmethods AS AuthMethods,
               t.fido2enabled AS FIDO2Enabled
        LIMIT 15000
    """,

    # Entra ID diagnostic settings — not streaming to SIEM
    "az_logging_audit": """
        MATCH (t:AZTenant)
        WHERE t.diagnosticsiem = false
           OR t.diagnosticsiem IS NULL
           OR t.logretentiondays < 30
        RETURN t.name AS Tenant, t.displayname AS TenantName,
               t.diagnosticsiem AS DiagnosticSIEM,
               t.logretentiondays AS LogRetentionDays
        LIMIT 15000
    """,

    # ── Heading 3: Security Architecture Simulation ─────────────

    # Graph API apps with sensitive permissions
    "az_graph_api_abuse": """
        MATCH (sp:AZServicePrincipal)-[:AZAppRoleAssignment]->(r:AZRoleDefinition)
        WHERE r.displayname IN ['UserAuthenticationMethod.ReadWrite.All', 'RoleManagement.ReadWrite.Directory']
        RETURN sp.name AS Principal, sp.appid AS AppId,
               r.displayname AS GraphPermission
        LIMIT 15000
    """,

    # Entra Connect sync accounts — high-privilege sync principals
    "az_sync_account_compromise": """
        MATCH (u:AZUser)-[:AZHasRole]->(r:AZRoleDefinition)
        WHERE r.displayname = 'Global Administrator'
          AND (u.userprincipalname CONTAINS 'sync' OR u.userprincipalname CONTAINS 'aadconnect'
               OR u.displayname =~ '(?i).*sync.*')
        RETURN u.name AS User, u.userprincipalname AS UPN,
               u.displayname AS DisplayName
        LIMIT 15000
    """,

    # PRT / session token abuse surface
    "az_prt_token_abuse": """
        MATCH (u:AZUser)-[:AZHasRole]->(r:AZRoleDefinition)
        WHERE u.onpremisessyncenabled = true
        RETURN u.name AS User, u.userprincipalname AS UPN,
               u.onpremisessyncenabled AS SyncEnabled
        LIMIT 15000
    """,

    # CA bypass simulation — trusted IPs / compliant device / MFA fatigue indicators
    "az_ca_bypass": """
        MATCH (p:AZConditionalAccessPolicy)
        WHERE p.state = 'enabled'
          AND (ANY(loc IN COALESCE(p.locations, []) WHERE loc IN ['AllTrusted', 'AllCompliant'])
               OR p.grantcontrols CONTAINS 'MfaRegistration')
        RETURN p.displayname AS Policy, p.state AS State,
               p.locations AS Locations, p.grantcontrols AS GrantControls
        LIMIT 15000
    """,

    # Cross-tenant auth chains — guest users with privileged Entra ID roles
    "az_cross_tenant_auth_chain": """
        MATCH (u:AZUser)-[:AZHasRole]->(r:AZRoleDefinition)
        WHERE u.userprincipalname CONTAINS '#EXT#'
          AND r.displayname IN ['Global Administrator', 'Privileged Role Administrator',
                 'Hybrid Identity Administrator', 'Application Administrator',
                 'Cloud Application Administrator', 'Conditional Access Administrator']
        RETURN u.name AS User, u.userprincipalname AS UPN,
               r.displayname AS Role
        LIMIT 15000
    """,

    # Device join abuse — Hybrid Azure AD joined devices
    "az_device_join_abuse": """
        MATCH (d:AZDevice)
        WHERE d.iscomanaged = true
           OR d.trusttype = 'ServerAd'
        RETURN d.name AS DeviceName, d.displayname AS DisplayName,
               d.trusttype AS TrustType, d.iscomanaged AS CoManaged
        LIMIT 15000
    """,

    # Managed identity token theft — downstream resource access
    "az_mi_token_theft": """
        MATCH (mi:AZManagedIdentity)-[r]->(scope)
        WHERE r:AZContributor OR r:AZOwner OR r:AZKeyVaultContributor
           OR r:AZUserAccessAdmin OR r:AZSecurityAdmin
        RETURN mi.name AS Identity, type(r) AS Role,
               scope.name AS Scope, LABELS(scope) AS ScopeType
        LIMIT 15000
    """,

    # Function / APIM key abuse — leaked keys to Key Vault
    "az_function_key_abuse": """
        MATCH (f:AZWebApp)-[r]->(kv:AZKeyVault)
        WHERE r:AZKeyVaultContributor OR r:AZKeyVaultSecretUser
        RETURN f.name AS FunctionApp, type(r) AS Permission,
               kv.name AS KeyVault
        LIMIT 15000
    """,

    # Privileged Access Group escalation — device local admin paths
    "az_pag_escalation": """
        MATCH (u:AZUser)-[:AZMemberOf]->(g:AZGroup)-[:AZMemberOf*1..]->(admin:AZGroup)
        WHERE g.name =~ '(?i).*local admin.*'
           OR g.name =~ '(?i).*privileged.*access.*'
           OR g.name =~ '(?i).*device.*admin.*'
        RETURN u.name AS User, g.name AS SourceGroup, admin.name AS AdminGroup
        LIMIT 15000
    """,

    # ── Heading 4: Non-Human Identity Governance ─────────────────

    # Service principals / app registrations without an owner
    "az_sp_no_owner": """
        MATCH (sp:AZServicePrincipal)
        WHERE NOT (sp)<-[:AZOwns]-()
          AND COALESCE(sp.serviceprincipaltype, '') <> 'ManagedIdentity'
        RETURN sp.name AS Principal, sp.objectid AS ObjectId, sp.appid AS AppId,
               sp.serviceprincipaltype AS ServicePrincipalType, LABELS(sp) AS PrincipalType
        UNION ALL
        MATCH (app:AZApplication)
        WHERE NOT (app)<-[:AZOwns]-()
        RETURN app.name AS Principal, app.objectid AS ObjectId, app.appid AS AppId,
               NULL AS ServicePrincipalType, LABELS(app) AS PrincipalType
        LIMIT 15000
    """,

    # Applications whose owners are all disabled or deleted
    "az_orphaned_app": """
        MATCH (app:AZApplication)
        OPTIONAL MATCH (owner)-[:AZOwns]->(app)
        WITH app, collect(DISTINCT owner) AS owners
        WHERE SIZE(owners) = 0
           OR ALL(o IN owners WHERE o IS NULL
                  OR (o:AZUser AND COALESCE(o.enabled, false) = false))
        RETURN app.name AS Application, app.objectid AS ObjectId,
               app.appid AS AppId,
               SIZE([o IN owners WHERE o IS NOT NULL]) AS OwnerCount,
               [o IN owners WHERE o:AZUser | o.name] AS DisabledOwnerAccounts
        LIMIT 15000
    """,

    # Service principals with broad tenant-wide Graph API permissions
    "az_overconsented_app": """
        MATCH (sp:AZServicePrincipal)-[:AZAppRoleAssignment]->(r:AZRoleDefinition)
        WHERE r.displayname IN ['Application.ReadWrite.All', 'Directory.ReadWrite.All',
               'Group.ReadWrite.All', 'User.ReadWrite.All', 'Mail.ReadWrite',
               'Files.ReadWrite.All', 'RoleManagement.ReadWrite.Directory',
               'UserAuthenticationMethod.ReadWrite.All']
        RETURN sp.name AS Principal, sp.appid AS AppId,
               sp.appdisplayname AS AppDisplayName,
               r.displayname AS GraphPermission, LABELS(sp) AS PrincipalType
        LIMIT 15000
    """,

    # Privileged service principals not subject to Conditional Access
    "az_sp_privileged_no_ca": """
        MATCH (sp:AZServicePrincipal)-[:AZHasRole]->(r:AZRoleDefinition)
        WHERE r.displayname IN ['Global Administrator', 'Privileged Role Administrator',
               'Application Administrator', 'Cloud Application Administrator']
        RETURN sp.name AS Principal, sp.appid AS AppId,
               LABELS(sp) AS PrincipalType,
               sp.serviceprincipaltype AS ServicePrincipalType,
               r.displayname AS Role, sp.tenantid AS TenantId
        LIMIT 15000
    """,

    # User-assigned managed identities (portable workload credentials)
    "az_user_assigned_mi": """
        MATCH (mi:AZServicePrincipal)
        WHERE COALESCE(mi.serviceprincipaltype, '') = 'ManagedIdentity'
        OPTIONAL MATCH (res)-[:AZManagedIdentity]->(mi)
        WITH mi, count(res) AS AttachedResourceCount,
             collect(DISTINCT res.name) AS AttachedTo
        WHERE AttachedResourceCount <> 1
        RETURN mi.name AS Identity, mi.objectid AS ObjectId, mi.appid AS AppId,
               AttachedResourceCount, AttachedTo
        LIMIT 15000
    """,

    # Stale service principals — not collected for 90+ days
    "az_stale_service_principal": """
        MATCH (sp:AZServicePrincipal)
        WHERE COALESCE(sp.serviceprincipaltype, '') <> 'ManagedIdentity'
          AND (sp.lastcollected IS NULL
               OR TOINTEGER(sp.lastcollected) < (timestamp() - 7776000000))
        RETURN sp.name AS Principal, sp.objectid AS ObjectId, sp.appid AS AppId,
               sp.serviceprincipaltype AS ServicePrincipalType,
               sp.lastcollected AS LastCollected, LABELS(sp) AS PrincipalType
        LIMIT 15000
    """,
}
