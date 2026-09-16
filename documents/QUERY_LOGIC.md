# GraphShield Hybrid Identity Assessment — Query Logic & Approach

**Targets**: BloodHound CE 5.x–6.x | SharpHound v2.x–3.x | AzureHound CE

This document describes each finding, what we query, why it matters, the Cypher logic, and the target BloodHound CE schema version. Clients can review our methodology and request custom logic if needed.

All Neo4j Cypher queries are hardened against BH CE schema drift:
- `COALESCE(prop, default)` for NULL-safe property access
- `ANY(lbl IN LABELS(n) WHERE ...)` for multi-label matching
- `TOINTEGER(prop)` for cross-version numeric type safety
- `ANY(x IN COALESCE(list_prop, []) WHERE ...)` for list-type property iteration
- `CamelCase` vs `snake_case` property fallback via `COALESCE(prop1, prop2)`
- `LIMIT 15000` on all queries preventing OOM on large datasets (aligned with 15K batch size)
- `MAX_FETCH = 100000` Python-side safety net in `neo4j_collector.py`

A **schema probe** runs at Neo4j connect time (`collectors/schema_probe.py`) — validates expected labels, property keys, and list-types exist before query execution; warnings surface in app UI. The probe only checks labels/properties relevant to the selected assessment scope to avoid misleading messages.

---

## Active Directory Findings (26)

### Group: AD Core (18 findings)

| ID | Finding | Sev | What We Check & Why | Query Key |
|---|---|---|---|---|
| AD-001 | Tier 0 Attack Paths | CRITICAL | Shortest attack paths to Tier-0 groups (Domain Admins RID-512, Administrators RID-544, Schema Admins RID-518, Key Admins RID-526/527). Excludes built-in accounts (RID < 1000). | `tier0_paths` |
| AD-002 | Enterprise Admin Paths | CRITICAL | Attack paths to Enterprise Admins (RID-519). Forest-wide scope. Excludes built-in Administrator (RID-500). | `enterprise_admin_paths` |
| AD-003 | Kerberoastable Accounts | HIGH | Users with SPNs enabled (excludes krbtgt RID-502). TGS tickets can be requested and cracked offline. | `kerberoast` |
| AD-004 | AS-REP Roastable Accounts | HIGH | Users with pre-auth disabled (`dontreqpreauth`). AS-REP response can be cracked offline. | `asrep_roast` |
| AD-005 | Unconstrained Delegation | HIGH | Computers with unconstrained delegation. Attacker captures TGTs of authenticating users. | `delegation` |
| AD-006 | Local Admin Relationships | HIGH | Users with `AdminTo` on computers. Lateral movement surface. | `admin_to` |
| AD-007 | Excessive Permissions | HIGH | Objects with GenericAll/GenericWrite/WriteDacl/WriteOwner over other objects. Filters system groups. | `dacl_abuse` |
| AD-008 | GPO Modification Rights | MEDIUM | Principals with write access to GPOs. Can deploy malware or disable security controls domain-wide. | `gpo_control` |
| AD-009 | SID History Abuse | HIGH | Users with SID History set. Cross-domain persistence after migration. | `sid_history` |
| AD-010 | DCSync Rights | CRITICAL | Principals with GetChanges/GetChangesAll. Can replicate all domain credentials. | `dcsync` |
| AD-011 | Constrained Delegation | HIGH | Computers with `allowedtodelegate`. Impersonation to specific services. | `constrained_delegation` |
| AD-012 | RBCD Abuse | HIGH | Principals with write access to computer objects. Can configure RBCD for user impersonation. | `rbcd` |
| AD-013 | No Password Required | MEDIUM | Enabled users with `PASSWD_NOTREQD`. Trivial compromise vector. | `password_not_required` |
| AD-014 | Reversible Encryption | HIGH | Users with reversible encryption. Passwords recoverable by anyone with AD read access. | `reversible_encryption` |
| AD-015 | Privileged Built-in Group Members | HIGH | Users in Account/Backup/Print/Server Operators. AD abuse capabilities. | `account_operators` |
| AD-016 | Non-Tier-0 Admin Groups | MEDIUM | Users in groups containing "ADMINISTRATORS" excluding well-known RIDs. Informational. | `privileged_groups` |
| AD-017 | Disabled Privileged Accounts | LOW | Disabled accounts still in privileged groups. Cleanup risk. | `disabled_privileged` |
| AD-018 | Cross-Forest Trusts | MEDIUM | Trust relationships to other domains. Expanded attack surface. | `cross_forest` |

### Group: AD Attack Paths (8 findings)

| ID | Finding | Sev | What We Check & Why | Query Key |
|---|---|---|---|---|
| AD-019 | AD-CS ESC1 — Certificate Template Abuse | CRITICAL | CertTemplate with enrollee-supplies-subject + client auth + write rights. Domain escalation via certificate. | `cert_abuse_esc1` |
| AD-020 | AD-CS ESC3 — Certificate Agent Enrollment Abuse | HIGH | Same principal enrolls in both an agent template (client auth, fixed subject) and a subject template (supplies subject). Agent-on-behalf-of enrollment bypass. | `cert_abuse_esc3` |
| AD-021 | Shadow Credentials — Key Credential Link Abuse | HIGH | Principals with `AddKeyCredentialLink` on targets. Kerberos PKINIT authentication via device-registered credentials. | `shadow_credentials` |
| AD-022 | Dangerous Object ACLs — User/Group/OU Takeover | HIGH | Non-computer object ACL abuse (User, Group, OU) via GenericAll/Write/WriteDacl/WriteOwner. Gap not covered by AD-012 (RBCD targets only computers). | `dangerous_object_acls` |
| AD-023 | NTLM Relay Paths | HIGH | Computers with `AdminTo` on a Domain Controller. NTLM relay from web server to DC enables credential relay. | `ntlm_relay_paths` |
| AD-024 | LAPS Deployment Gaps | MEDIUM | Computers missing LAPS or running legacy OS. No local admin password rotation risks lateral movement. | `laps_gaps` |
| AD-025 | MS-SQL Linked Server Abuse | HIGH | SQL Admin rights to SQL servers. Linked server abuse for lateral movement and privilege escalation. | `sql_linked_servers` |
| AD-026 | Intra-Forest Trust Escalation | HIGH | Trusts with SID filtering disabled or TGT delegation enabled. SID history injection across domains. | `domain_trust_escalation` |

---

## Azure / Entra ID Findings (46)

### Group: Azure Core (20 findings)

| ID | Finding | Sev | What We Check & Why | Query Key |
|---|---|---|---|---|
| AZ-001 | Global Administrator | CRITICAL | `AZHasRole` → `AZRoleDefinition` where `displayname = 'Global Administrator'`. Full tenant control. | `az_global_admin` |
| AZ-002 | Privileged Role Administrator | CRITICAL | Role management rights — effectively equivalent to GA. | `az_privileged_role_admin` |
| AZ-003 | Privileged Authentication Admin | CRITICAL | Manages auth methods, agents, credential policies. Auth pipeline backdoor. | `az_privileged_auth_admin` |
| AZ-004 | Hybrid Identity Administrator | CRITICAL | AD Connect sync, federation, password hash sync. On-prem/cloud bridge. | `az_hybrid_identity_admin` |
| AZ-005 | Application Administrator | HIGH | App registration, secrets, certificates. Backdoor app access to tenant data. | `az_application_admin` |
| AZ-006 | Cloud Application Administrator | HIGH | Microsoft cloud app management. M365 data access. | `az_cloud_app_admin` |
| AZ-007 | Conditional Access Administrator | HIGH | CA policy create/modify/delete. MFA bypass, security control weakening. | `az_conditional_access_admin` |
| AZ-008 | User Access Administrator | HIGH | Azure RBAC role assignment at any scope. Subscription/resource access grants. | `az_user_access_admin` |
| AZ-009 | Security Administrator | HIGH | Security settings, alerts, Defender policies. Monitoring bypass. | `az_security_admin` |
| AZ-010 | Azure Contributor Role Assignments | HIGH | Contributor at subscription/resource-group/management-group. Full resource management. | `az_contributor` |
| AZ-011 | Azure Owner Role Assignments | CRITICAL | Owner at any scope. Full control including role assignment. | `az_owner` |
| AZ-012 | Application Credential Abuse | HIGH | `AZAddSecret` on apps. Persistent backdoor secrets bypassing MFA. | `az_add_secret` |
| AZ-013 | Application Owner Abuse | HIGH | `AZAddOwner` on apps. Group control escalation. | `az_add_owner` |
| AZ-014 | Group Membership Abuse | HIGH | `AZAddToGroup` on Azure groups. Privilege escalation via group nesting. | `az_add_to_group` |
| AZ-015 | Key Vault Access Abuse | CRITICAL | `AZKeyVaultContributor`. Secrets, keys, certificate extraction. | `az_key_vault_contributor` |
| AZ-016 | Managed Identity Privileges | HIGH | Managed Identities with Contributor/Owner/KeyVault roles. Downstream compromise. | `az_managed_identity_roles` |
| AZ-017 | External User Access | MEDIUM | Guest users (`#EXT#`) or users without on-prem SAM account name. Unmanaged IDP risk. | `az_external_users` |
| AZ-018 | Remote Command Execution | HIGH | `AZExecuteCommand` on VMs. Script execution without network access. | `az_execute_command` |
| AZ-019 | Password Reset Abuse | MEDIUM | `AZResetPassword` on users or VMs. Account takeover via credential reset. | `az_reset_password` |
| AZ-020 | Azure Role Escalation Paths | CRITICAL | Transitive role assignments through group nesting → tenant-wide admin roles. | `az_role_escalation` |

### Group: Zero Trust Identity Hardening Review (11 findings)

| ID | Finding | Sev | What We Check & Why | Query Key |
|---|---|---|---|---|
| AZ-021 | MFA Registration Gaps | HIGH | Users with `mfaenabled = false`. No second factor for authentication. | `az_mfa_gap` |
| AZ-022 | CA Policy Gaps | MEDIUM | Disabled or report-only CA policies. Policy not enforced. | `az_ca_policy_gaps` |
| AZ-023 | PIM Audit — Permanent Role Assignments | HIGH | Permanently active (non-PIM-eligible) privileged role assignments. No JIT elevation. | `az_pim_audit` |
| AZ-024 | Overprivileged Service Principals | HIGH | SPs with tenant-wide admin roles. Broad blast radius. | `az_sp_oversight` |
| AZ-025 | Unrestricted Cross-Tenant Access | MEDIUM | B2B collaboration without automatic redeem, user consent enabled, or inbound trust unconfigured. | `az_cross_tenant_access` |
| AZ-026 | Custom Azure RBAC Roles | MEDIUM | Non-built-in role definitions. May lack proper permission scoping. | `az_custom_roles` |
| AZ-027 | Password Protection Disabled | MEDIUM | Tenant-level password protection not enforced. Weak password risk. | `az_password_protection` |
| AZ-028 | Legacy Authentication Flows | HIGH | Users with legacy auth enabled. MFA bypass via legacy protocols. | `az_legacy_auth` |
| AZ-029 | Identity Governance — Stale Accounts | MEDIUM | Users inactive > 90 days or never signed in. Orphaned accounts. | `az_identity_governance` |
| AZ-030 | Authentication Methods Policy | MEDIUM | Weak auth methods or FIDO2 disabled. Reduced credential security. | `az_auth_methods_policy` |
| AZ-031 | Entra ID Logging Gaps | MEDIUM | Diagnostic settings not streaming to SIEM or retention < 30 days. | `az_logging_audit` |

### Group: Security Architecture Simulation (9 findings)

| ID | Finding | Sev | What We Check & Why | Query Key |
|---|---|---|---|---|
| AZ-032 | Graph API Permission Abuse | HIGH | SPs with Graph API permissions for user auth method or role management RW. Token theft escalation. | `az_graph_api_abuse` |
| AZ-033 | Entra Connect Sync Account Compromise | CRITICAL | Global Admin sync accounts with naming patterns. Supply-chain attack on identity bridge. | `az_sync_account_compromise` |
| AZ-034 | PRT / Session Token Abuse Surface | HIGH | Synced users with privileged roles. PRT theft enables persistent access. | `az_prt_token_abuse` |
| AZ-035 | CA Bypass Simulation | HIGH | Enabled CA policies with trusted IPs/locations or MFA registration grants. Bypass surface. | `az_ca_bypass` |
| AZ-036 | Cross-Tenant Auth Chain | HIGH | Guest users with privileged Entra ID roles. Resource compromise via tenant trust chain. | `az_cross_tenant_auth_chain` |
| AZ-037 | Device Join Abuse | HIGH | Hybrid Azure AD joined or co-managed devices. On-prem device compromise extends to cloud. | `az_device_join_abuse` |
| AZ-038 | Managed Identity Token Theft | HIGH | Managed Identities with high-privilege roles. Token theft from compromised resource. | `az_mi_token_theft` |
| AZ-039 | Function/APIM Key Abuse | MEDIUM | Web apps/function apps with KV contributor access. Downstream key/data theft. | `az_function_key_abuse` |
| AZ-040 | Privileged Access Group Escalation | HIGH | Users in groups nested into PAG groups. Local admin on devices via group membership. | `az_pag_escalation` |

### Group: Non-Human Identity Governance (6 findings)

| ID | Finding | Sev | What We Check & Why | Query Key |
|---|---|---|---|---|
| AZ-041 | Unowned Service Principals | HIGH | `AZServicePrincipal` with no `AZOwns` incoming edge. No accountable owner blocks credential rotation, CA assignment, and lifecycle management. | `az_sp_no_owner` |
| AZ-042 | Orphaned Applications | HIGH | `AZApplication` with no incoming `AZOwns` edge. No owner means no authorized party to revoke credentials or modify consent grants. | `az_orphaned_app` |
| AZ-043 | Over-Consented Applications | HIGH | `AZServicePrincipal` with `AZAppRoleAssignment` to `AZRoleDefinition` where permission type is `Role` (application, not delegated). Broad Graph API app permissions bypass user-context controls. | `az_overconsented_app` |
| AZ-044 | Privileged SPs Without Conditional Access | CRITICAL | `AZServicePrincipal` with `AZHasRole` to `AZRoleDefinition` matching directory-role names AND no `CAApplicationCondition` linking to a CA policy. SPs with directory roles bypass conditional access. | `az_sp_privileged_no_ca` |
| AZ-045 | User-Assigned Managed Identity Proliferation | MEDIUM | `AZServicePrincipal` with `AZManagedIdentity` incoming edge (user-assigned MI). Attachment count != 1 indicates identity sprawl or resource attachment drift. | `az_user_assigned_mi` |
| AZ-046 | Stale Service Principals | MEDIUM | `AZServicePrincipal` where `TOINTEGER(lastcollected)` < 7776000000 (90 days). Decommissioned SPs retaining active credentials — lateral movement surface. | `az_stale_service_principal` |

---

## Assessment Groups

All queries are organized into 5 groups (`analytics/groups.py`). Group selection via single-select radio in the sidebar determines which queries execute:

| Group | Queries | Findings |
|---|---|---|
| AD Core | 18 | AD-001 → AD-018 |
| AD Attack Paths | 8 | AD-019 → AD-026 |
| Azure Core | 21 | AZ-001 → AZ-020 |
| Zero Trust Review | 11 | AZ-021 → AZ-031 |
| Architecture Simulation | 9 | AZ-032 → AZ-040 |
| NHI Governance | 6 | AZ-041 → AZ-046 |

**Note**: `az_managed_identity` query (Azure Core group) collects environment data but has no finding mapping — reserved for future use.

---

## Key Methodology Notes

1. **Tier-0 identification** follows Microsoft's well-known RID methodology (512, 519, 544, 518, 526, 527).
2. **Built-in / default account filtering** — excludes RID < 1000 and well-known group SIDs across all AD queries.
3. **Entra ID role queries** use `[:AZHasRole]->(r:AZRoleDefinition) WHERE r.displayname = '...'` pattern — matches AzureHound CE schema. RBAC edges (`AZContributor`, `AZOwner`, etc.) use native edge types.
4. **Azure property naming** — all lowercased per BH CE convention (`displayname`, `userprincipalname`, `lastsignin`). CamelCase fallback via `COALESCE` where BH historically uses mixed case (e.g., `automaticRedeem` / `automaticredeem`).
5. **Severity tiers**: CRITICAL (immediate domain/tenant compromise), HIGH (privilege escalation / credential theft), MEDIUM (expanded attack surface / compliance), LOW (cleanup / informational).
6. **All queries run against BloodHound CE** (Neo4j 5.x) populated by SharpHound (AD) and AzureHound (Entra ID) collectors. No direct LDAP or Graph API queries.
7. **Schema probe** validates all expected labels and properties at Neo4j connect time. Warnings are surfaced in app UI and logged.
8. **Per-query caching not supported** — all queries re-execute on "Reload from Neo4j". Data is cached per version as `raw_bloodhound.json` with `_assessment_group` scope metadata.

---

## Cypher Files

- `collectors/bloodhound_queries.py` — 26 AD queries (all with `LIMIT 15000`)
- `collectors/azure_queries.py` — 47 Azure queries (all with `LIMIT 15000`)
- `collectors/schema_probe.py` — Runtime schema validation against expected labels and properties (per-group scope-aware)
- `collectors/query_registry.py` — Query version management and S3 update pipeline

---

## Query Registry

All queries are baked into the source and resolved at runtime by `collectors/query_registry.py`:

```
get_queries():
  return BUILTIN_QUERIES from bloodhound_queries.py + azure_queries.py
```

To add or modify a query, edit `collectors/bloodhound_queries.py` (AD) or
`collectors/azure_queries.py` (Azure/Entra ID) — changes take effect on next app start.

