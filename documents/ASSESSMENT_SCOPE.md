# GraphShield Hybrid Identity Security Assessment — Complete Scope of Coverage

**Total: 80 findings** across 6 assessment groups (26 Active Directory + 54 Azure/Entra ID)

---

## Group 1 — Active Directory Core Assessment (AD-001 to AD-018, 18 findings)

Foundational BloodHound CE attack path analysis covering Tier 0 privilege, credential exposure, delegation abuse, and cross-forest risks.

| ID | Finding | Severity | What We Detect |
|----|---------|----------|----------------|
| AD-001 | Tier 0 Attack Paths Detected | CRITICAL | Direct attack paths from non-privileged principals to Tier 0 assets (Domain Admins, DCs, GPOs) via nested group memberships and privilege relationships |
| AD-002 | Enterprise Admin Paths Detected | CRITICAL | Forest-wide privilege escalation paths to Enterprise Admin groups enabling complete multi-domain compromise |
| AD-003 | Kerberoastable Accounts Detected | HIGH | Service accounts with SPNs whose encrypted TGS tickets can be requested and cracked offline for credential recovery |
| AD-004 | AS-REP Roastable Accounts Detected | HIGH | Accounts without Kerberos pre-authentication enabled exposing password hashes for offline cracking |
| AD-005 | Unconstrained Delegation Detected | HIGH | Computers/servers with unconstrained delegation where attackers can capture Kerberos tickets of connecting privileged users |
| AD-006 | Local Admin Relationships Detected | HIGH | Excessive AdminTo relationships creating lateral movement paths between computers via local admin rights |
| AD-007 | Excessive Permissions Detected (DACL) | HIGH | Dangerous ACL entries (GenericAll, WriteDacl, WriteOwner) on AD objects enabling privilege escalation and persistence |
| AD-008 | GPO Modification Rights Detected | MEDIUM | Principals with write access to Group Policy Objects enabling domain-wide malware deployment or security control bypass |
| AD-009 | SID History Abuse Potential | HIGH | Accounts with SID history entries enabling cross-domain privilege escalation without proper authentication |
| AD-010 | DCSync Rights Granted | CRITICAL | Accounts with Replicating Directory Changes permissions able to extract all domain password hashes via DCSync |
| AD-011 | Constrained Delegation Misconfiguration | HIGH | Constrained delegation entries allowing impersonation of users to specific services with risk of service ticket abuse |
| AD-012 | RBCD Abuse Potential | HIGH | Write permissions on computer objects enabling Resource-Based Constrained Delegation configuration for authentication relay |
| AD-013 | Accounts Without Password Requirement | MEDIUM | User accounts with PASSWD_NOTREQD flag allowing access without valid passwords |
| AD-014 | Accounts With Reversible Encryption | HIGH | Accounts with reversible encryption enabled exposing plaintext passwords to anyone with AD read access |
| AD-015 | Privileged Built-in Group Memberships | HIGH | Non-admin users in privileged groups (Account Operators, Backup Operators, Print Operators, Server Operators) enabling privilege escalation |
| AD-016 | Cross-Forest Trust Relationships | MEDIUM | Forest trusts expanding attack surface for lateral movement across organizational boundaries |
| AD-017 | Non-Tier-0 Administrative Groups | MEDIUM | Administrative group memberships outside standard Tier-0 (DHCP Admins, DNS Admins) granting delegated elevated privileges |
| AD-018 | Disabled Accounts in Privileged Groups | LOW | Disabled accounts retaining privileged group membership — cleanup and compliance risk if re-enabled |

---

## Group 2 — Identity Attack Path Assessment (AD-019 to AD-026, 8 findings)

Advanced AD attack path analysis covering certificate services (AD CS), credential abuse, relay attacks, and trust exploitation.

| ID | Finding | Severity | What We Detect |
|----|---------|----------|----------------|
| AD-019 | AD-CS ESC1 — Certificate Template Abuse | CRITICAL | Certificate templates with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT and no issuance requirements allowing domain escalation via forged certificate requests |
| AD-020 | AD-CS ESC3 — Certificate Agent Enrollment Abuse | HIGH | Enrollment agent templates chained with subject templates enabling arbitrary user certificate enrollment and impersonation |
| AD-021 | Shadow Credentials — Key Credential Link Abuse | HIGH | Principals with AddKeyCredentialLink write access enabling rogue key credential registration for PKINIT-based authentication bypass |
| AD-022 | Dangerous Object ACLs — User/Group/OU Takeover | HIGH | GenericAll/GenericWrite/WriteDacl/WriteOwner on User/Group/OU objects enabling unauthorized object takeover, group membership escalation, or attribute modification |
| AD-023 | NTLM Relay — Web Server to DC Paths | HIGH | HTTP/HTTPS servers with local admin access to DCs enabling NTLM credential relay to LDAPS for rogue domain admin creation |
| AD-024 | LAPS Deployment Gaps | MEDIUM | Computers without LAPS deployed relying on shared/identical local admin passwords enabling lateral movement |
| AD-025 | MS-SQL Linked Server — Lateral Movement | HIGH | SQL Server linked server trusts allowing cross-database and cross-system lateral movement via SQLAdmin rights and xp_cmdshell |
| AD-026 | Domain Trust Escalation — SID Filter/TGT Delegation | HIGH | Inter-domain trusts with SID filtering disabled or TGT delegation enabled enabling cross-domain privilege escalation |

---

## Group 3 — Azure/Entra ID Core Assessment (AZ-001 to AZ-020, 20 findings)

Entra ID privileged role assignments, Azure RBAC abuse paths, application/service principal backdoors, and external user risks.

| ID | Finding | Severity | What We Detect |
|----|---------|----------|----------------|
| AZ-001 | Global Administrator Assignment | CRITICAL | Users/groups/SPs with Global Admin role — full tenant-wide control including password resets, app registration, and data access |
| AZ-002 | Privileged Role Administrator Assignment | CRITICAL | Principals who can manage all role assignments including elevating to Global Admin — effectively equivalent to tenant-wide admin |
| AZ-003 | Privileged Authentication Administrator Assignment | CRITICAL | Admins who can register PTA agents, manage authentication methods, reset passwords for privileged users — authentication pipeline backdoor |
| AZ-004 | Hybrid Identity Administrator Assignment | CRITICAL | Sync admins who can modify PHS, federation, and provisioning settings — bridge between on-prem AD and cloud compromise |
| AZ-005 | Application Administrator Assignment | HIGH | Principals who can register apps, manage secrets/certificates, and grant permissions — backdoor application creation risk |
| AZ-006 | Cloud Application Administrator Assignment | HIGH | Similar to App Admin but restricted to Microsoft cloud apps (Exchange, SharePoint, Teams) — M365 data access |
| AZ-007 | Conditional Access Administrator Assignment | HIGH | Principals who can create, modify, or delete CA policies — can disable MFA, create IP allow-lists, exempt users from security controls |
| AZ-008 | User Access Administrator Assignment | HIGH | Principals who can manage RBAC assignments at all scopes — can grant themselves access to any Azure resource |
| AZ-009 | Security Administrator Assignment | HIGH | Principals who can manage security policies, alerts, and Defender settings — can bypass security monitoring |
| AZ-010 | Azure Contributor Role Assignments | HIGH | Contributors with full resource management access at subscription/resource group/management group scope |
| AZ-011 | Azure Owner Role Assignments | CRITICAL | Owners with full resource management AND role assignment access — can elevate any principal at their scope |
| AZ-012 | Application Credential Abuse (Add Secret) | HIGH | Principals with Add Secret permissions who can create persistent backdoor credentials for applications bypassing MFA |
| AZ-013 | Application Owner Abuse (Add Owner) | HIGH | Principals with Add Owner permissions who can grant control of applications to other principals for privilege escalation |
| AZ-014 | Group Membership Abuse (Add to Group) | HIGH | Principals with Add Member permissions who can add themselves/others to privileged groups for escalation |
| AZ-015 | Key Vault Access Abuse | CRITICAL | Key Vault Contributors/Readers who can read secrets, keys, and certificates enabling broad data access and lateral movement |
| AZ-016 | Managed Identity Privileges | HIGH | Managed identities with high-privilege RBAC where compromise of the hosting resource inherits identity's full permissions |
| AZ-017 | External User Access | MEDIUM | Guest users with privileged role assignments — managed by external IdPs with unknown security posture |
| AZ-018 | Remote Command Execution Risk | HIGH | Principals with Run Command on Azure VMs enabling script execution, credential harvesting, and lateral movement into VM environments |
| AZ-019 | Password Reset Privilege Abuse | MEDIUM | Principals with password reset permissions enabling account takeover and persistence through credential modification |
| AZ-020 | Azure Role Escalation Paths | CRITICAL | Nested group memberships and transitive role assignments enabling privilege escalation to tenant-wide admin roles |

---

## Group 4 — Zero Trust Identity Hardening Review (AZ-021 to AZ-031, 11 findings)

Entra ID tenant configuration against Zero Trust principles — authentication posture, governance, logging, and collaboration controls.

| ID | Finding | Severity | What We Detect |
|----|---------|----------|----------------|
| AZ-021 | MFA Registration Gap | HIGH | Users without MFA registered or using SMS/voice (least secure); number matching not enforced — core Zero Trust control |
| AZ-022 | CA Policy Gaps | MEDIUM | CA policies in disabled or report-only state; no session controls; device compliance requirements absent |
| AZ-023 | PIM Activation Audit | HIGH | Permanently active privileged role assignments instead of PIM-eligible; no approval workflow or justification logging |
| AZ-024 | Service Principal Oversight | HIGH | SPs with app roles exceeding intended scope; credentials never rotated; no owner assigned; orphaned SPs |
| AZ-025 | Unrestricted Cross-Tenant Collaboration | MEDIUM | No inbound/outbound access policies; tenant restrictions not applied; external collaboration ungoverned |
| AZ-026 | Custom RBAC Role Definitions | MEDIUM | Custom roles with wildcard actions or permissions exceeding stated scope (e.g., "Reader" with credential write) |
| AZ-027 | Password Protection Policy | MEDIUM | Password writeback not enabled; custom banned passwords not deployed; SSPR unconfigured |
| AZ-028 | Legacy Authentication Flows | HIGH | Users/apps using POP3/IMAP4/SMTP Auth that bypass all Conditional Access policies and MFA enforcement |
| AZ-029 | Identity Governance Gaps | MEDIUM | No access reviews; orphaned entitlements; stale guest accounts; no provisioning/deprovisioning automation |
| AZ-030 | Authentication Methods Policy | MEDIUM | FIDO2/WHfB adoption absent; SMS still allowed as primary MFA; no passwordless authentication for admins |
| AZ-031 | Entra ID Logging Gaps | MEDIUM | Diagnostic settings not streaming to SIEM; log retention under 30 days for sign-in/audit logs |

---

## Group 5 — Security Architecture Simulation (AZ-032 to AZ-040, 9 findings)

Simulated attacker techniques against Entra ID to identify architectural weaknesses that bypass or subvert controls.

| ID | Finding | Severity | What We Simulate |
|----|---------|----------|------------------|
| AZ-032 | Graph API App Permission Abuse | CRITICAL | SPs with UserAuthenticationMethod.ReadWrite.All (reset any user's MFA) or RoleManagement.ReadWrite.Directory (assign admin roles via API) — app-only permissions bypass MFA and CA |
| AZ-033 | Entra Connect Sync Account Compromise | CRITICAL | Sync accounts with PHS decryption capability, USN rollback potential, on-prem-to-cloud impersonation paths |
| AZ-034 | PRT / Session Token Abuse | HIGH | Devices/users capable of PRT theft and replay — persistent access beyond password changes, device claim bypass, cross-tenant token replay |
| AZ-035 | Conditional Access Bypass Simulation | HIGH | Trusted IP range exemptions, compliant device bypass paths, MFA fatigue susceptibility indicators |
| AZ-036 | Cross-Tenant Authentication Chain | HIGH | Guest users with privileged role assignments creating lateral movement paths across tenants (A → B → C) |
| AZ-037 | Hybrid Azure AD Join Abuse | HIGH | Hybrid joined devices under attacker control can relay device authentication to cloud resources via WPAD + AD CS |
| AZ-038 | Managed Identity Token Theft | HIGH | MI tokens from compromised compute (VM, Function, AKS) exposing downstream Key Vaults, storage, databases |
| AZ-039 | Azure Function / APIM Key Abuse | MEDIUM | Leaked function/API keys unlocking downstream RBAC context and Key Vault access |
| AZ-040 | Privileged Access Group Escalation | HIGH | Device local admin groups and PAG memberships enabling lateral movement across thousands of endpoints |

---

## Group 6 — Non-Human Identity Governance (AZ-041 to AZ-054, 14 findings)

Workload identity lifecycle governance — service principal ownership, application consent, managed identity proliferation, and privilege hygiene.

| ID | Finding | Severity | What We Detect |
|----|---------|----------|----------------|
| AZ-041 | Unowned Service Principals | HIGH | Azure AD service principals with no assigned owner — impossible to determine accountability; blocks credential rotation, CA policy assignment, and lifecycle management |
| AZ-042 | Orphaned Applications | HIGH | Applications where all registered owners are disabled, deleted, or ineligible — no qualified owner exists; risk of forgotten app credentials and unrevoked consent grants |
| AZ-043 | Over-Consented Applications | HIGH | Service principals with Graph API permissions exceeding their intended scope — excessive consent grants enable data exfiltration or privilege escalation beyond the application's purpose |
| AZ-044 | Privileged SPs Without Conditional Access | CRITICAL | Service principals holding directory-roles (Global Admin, Application Admin, etc.) with no conditional access scoping — any compromised credential inherits full role privileges without identity controls |
| AZ-045 | User-Assigned Managed Identity Proliferation | MEDIUM | User-assigned managed identities attached to non-standard resource counts (0 or >1) — indicates identity sprawl or resource attachment drift from intended baseline |
| AZ-046 | Stale Service Principals | MEDIUM | Service principals not collected in the last 90 days — likely decommissioned but retaining active credentials and role assignments; lateral movement surface if still enabled |
| AZ-047 | Disabled Service Principals Retaining Privileges | HIGH | Disabled/decommissioned SPs that still hold Entra directory roles — reactivation or cached credentials silently restore privileged access, bypassing standard stale-privilege review |
| AZ-048 | Single-Owner Service Principals (No Dual Control) | MEDIUM | SPs with exactly one owner — no independent accountability checkpoint for credential, consent, or role changes |
| AZ-049 | Service Principals With No Active Owner | HIGH | SPs whose only owners are disabled or deleted — appear 'owned' but have no accountable human; role assignments and credentials remain live |
| AZ-050 | Stale Managed Identities | MEDIUM | User-assigned managed identities idle 90+ days — decommissioned MIs remain assignable and may still carry Azure RBAC |
| AZ-051 | Stale Registered Devices | MEDIUM | Entra ID-registered devices idle 90+ days — dormant enrollments retain trust state, PRTs, and CA exclusions |
| AZ-052 | Service Principals With Combined Privileges | CRITICAL | SPs holding BOTH an Entra directory role AND Azure ARM Owner/Contributor/UserAccessAdmin — two privilege planes rarely reviewed together |
| AZ-053 | Service Principals Owned by Azure Groups | MEDIUM | SPs owned by groups — diffuse accountability with no named individual reviewing credentials or consent |
| AZ-054 | Legacy / Unknown Service Principal Types | LOW | SPs with 'Legacy' or 'Unknown' service principal type — typically pre-Graph-era, undocumented, and outside modern lifecycle tooling |

#### Optional NHI Lifecycle Findings (feed-gated — AZ-055 → AZ-062)

The eight lifecycle findings below are **emitted only when an Entra lifecycle feed is supplied** (`GRAPH_SHIELD_LIFECYCLE_FEED` env → JSON path / glob / in-memory dict). Without a feed they do **not** run, so the 80-finding baseline is unchanged. Each carries an `OWASP NHI` compliance mapping and Entra sign-in/audit evidence.

| AZ ID | Finding | Severity | Rationale / Source Evidence |
|--------|---------|----------|----------------------------|
| AZ-055 | Active Orphaned Workload Identity | HIGH | Workload identity actively signing in with no accountable owner — no rotation/CA/lifecycle control; NHI lifecycle-feed signal `orphan`. |
| AZ-056 | Dormant High-Privilege Identity Reactivation | HIGH | Privileged NHI that went dormant then reactivated — dormant account takeover surface; signal `dormant` / `disabled`. |
| AZ-057 | Credential-Expired Identity Still Alive | HIGH | Client-secret/credential-expired NHI still authenticating — credential lifecycle breach; signal `credential expired`. |
| AZ-058 | Sign-In Anomaly (NHI) | MEDIUM | Anomalous/nonstandard workload sign-in (impossible travel, unfamiliar client) — NHI compromise indicator; signal `sign-in anomaly`. |
| AZ-059 | Consent Granted After Review | LOW | Consent/permission granted following post-review activity — drift after attestation; signal `consent after review`. |
| AZ-060 | Workload Attestation Overdue | HIGH | Active NHI whose attestation window has lapsed — no re-attestation inside the policy window, drifting out of the governance baseline; signal `attestation overdue`. |
| AZ-061 | Credential Rotation Overdue (Still Alive) | HIGH | NHI credential past its rotation-policy window while the identity keeps authenticating — standing rotation-lifecycle enforcement gap; signal `rotation overdue`. |
| AZ-062 | New Active Workload Without Owner | MEDIUM | Workload identity created inside the onboarding window that is already authenticating with no owner on record — ungoverned from day one; signal `no owner on record`. |

---

## Summary

| Group | Focus | Scope | Severity Range |
|-------|-------|-------|----------------|
| 1 | Active Directory Core Assessment | 18 AD (AD-001–AD-018) | CRITICAL–LOW |
| 2 | Identity Attack Path Assessment | 8 AD (AD-019–AD-026) | CRITICAL–MEDIUM |
| 3 | Azure/Entra ID Core Assessment | 20 Azure (AZ-001–AZ-020) | CRITICAL–MEDIUM |
| 4 | Zero Trust Identity Hardening Review | 11 Azure (AZ-021–AZ-031) | HIGH–MEDIUM |
| 5 | Security Architecture Simulation | 9 Azure (AZ-032–AZ-040) | CRITICAL–MEDIUM |
| 6 | Non-Human Identity Governance | 14 Azure (AZ-041–AZ-054) | CRITICAL–LOW |
| **Total (baseline)** | | **26 AD + 54 Azure = 80** | |

A lifecycle feed (AZ-055 → AZ-062, above) is **optional and gated** — when supplied the total reaches **88**, otherwise the 80-finding baseline is unchanged. The findings tables in scope are version-stamped (ADR-021 | Findings | 80 baseline findings: 26 AD + 54 Azure (feed-gated lifecycle adds AZ-055 → AZ-062) |).

When a lifecycle feed is supplied, the app also renders a **per-identity NHI Lifecycle Dashboard** (`lifecycle_dashboard_rows()` → feed-gated `st.dataframe`): workload identity, last sign-in, sign-in count, activity period, credential type, lifecycle stages, attestation / rotation / onboarding / cross-source status. With no feed the dashboard renders nothing and the 80-finding baseline is untouched.

### NHI two-source correlation (graph + logs)

The 14 NHI governance findings (AZ-041 → AZ-054) are **graph-derived** — they come from AzureHound Cypher in `collectors/azure_queries.py` and prove structural posture: ownership, consent, privilege, managed-identity sprawl, stale/legacy identities. The graph contains **no sign-in or audit data at all**.

The 8 NHI lifecycle findings (AZ-055 → AZ-062) are **log-derived** — they come from the optional Entra sign-in/audit feed and prove temporal/behavioral lifecycle: is the identity still authenticating, when did it lose its owner, is its attestation or rotation overdue, is the sign-in anomalous.

The two sets are **complementary, not redundant** — neither source is sufficient alone, and the union is the complete NHI assessment. When a feed is supplied, `correlate_nhi_sources()` binds them **per workload identity** (Entra `AppId` / object id / display name) and attaches a `nhi_correlation` block to both sides:

```
nhi_correlation = { identity, app_id, graph_findings[], lifecycle_findings[], both_sources }
```

So an identity that is unowned *in the graph* and attestation-overdue *in the logs* is reported as one correlated identity rather than two unrelated findings. Identities present in only one source are never given a fabricated match, and with no feed the graph findings are returned untouched.

**Scope: NHI assessment only.** Correlation is applied strictly to the `nhi_governance` group (AZ-041 → AZ-054) plus the `AZ_LC_*` lifecycle findings. The AD Core, AD Attack Paths, Azure/Entra ID Core, Zero Trust Review and Security Architecture Simulation assessments are never correlated and are unaffected. A non-NHI finding that happens to reference the same workload `AppId` is deliberately left uncorrelated.

The exported reports carry this as a final `Corroboration (NHI)` column (CSV and the Excel *Findings Register*), left empty for every finding outside the NHI assessment. It is appended last so the documented `R`-`U` worksheet columns (Status, Owner, Due Date, Notes) keep their positions.

The AI outputs are scoped identically. `ai/analyst.py` adds a `NON-HUMAN IDENTITY - GRAPH + LOG CORROBORATION` prompt block and a section 6 **only** when corroborated identities exist, and the per-finding `nhi_corroboration` key is omitted for every non-NHI finding, so the prompt without a feed is byte-identical to the pre-correlation behaviour. `reporting/ai_pdf_export.py` renders a *Graph + Log Corroboration* table inside the Non-Human Identity Governance section only.

Data source: BloodHound CE (Active Directory) + AzureHound (Entra ID) via Neo4j graph database. All findings are evidence-based using actual graph relationships and attack paths, not theoretical configuration checks.

Compliance mappings available: CIS Controls, NIST Cybersecurity Framework, ISO 27001, SA 315 (ICAI), DPDP Act 2023, OWASP NHI Top 10 (applied to workload-identity findings).
