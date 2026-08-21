def _extract_domain(name):
    if not name:
        return None
    name = str(name).strip()
    if "@" in name:
        return name.split("@", 1)[1]
    parts = name.split(".")
    if len(parts) >= 2:
        return ".".join(parts[1:])
    return None


def _clean(name):
    if not name:
        return None
    name = str(name).strip()
    if not name or name.upper() == "NONE":
        return None
    if name.startswith("S-1-5-21"):
        return None
    return name


def _classify(name, labels=None):
    name = _clean(name)
    if not name:
        return None, None
    if labels:
        label_set = set(labels)
        # Azure node labels
        if "AZUser" in label_set:
            return "users", name
        if "AZGroup" in label_set:
            return "groups", name
        if "AZServicePrincipal" in label_set:
            return "service_principals", name
        if "AZManagedIdentity" in label_set:
            return "managed_identities", name
        if "AZApplication" in label_set:
            return "applications", name
        if "AZVM" in label_set:
            return "computers", name
        if "AZKeyVault" in label_set:
            return "key_vaults", name
        if "AZTenant" in label_set:
            return "tenants", name
        if "AZSubscription" in label_set:
            return "subscriptions", name
        if "AZResourceGroup" in label_set:
            return "resource_groups", name
        if "AZManagementGroup" in label_set:
            return "management_groups", name
        # AD node labels
        if "Computer" in label_set:
            return "computers", name
        if "GPO" in label_set:
            return "gpos", name
        if "OU" in label_set:
            return "organizational_units", name
        if "User" in label_set:
            return "users", name
        if "Group" in label_set:
            return "groups", name
        if "Domain" in label_set:
            return None, name
    upper = name.upper()
    if upper.endswith("$") or "$@" in upper:
        return "computers", name
    if "OU=" in upper:
        return "organizational_units", name
    return "groups", name


def _azure_bucket(labels):
    """Map Azure node labels to bucket keys."""
    if not labels:
        return None
    s = set(labels)
    if "AZUser" in s: return "users"
    if "AZGroup" in s: return "groups"
    if "AZServicePrincipal" in s: return "service_principals"
    if "AZManagedIdentity" in s: return "managed_identities"
    if "AZApplication" in s: return "applications"
    if "AZKeyVault" in s: return "key_vaults"
    if "AZVM" in s: return "computers"
    if "AZTenant" in s: return "tenants"
    if "AZSubscription" in s: return "subscriptions"
    if "AZResourceGroup" in s: return "resource_groups"
    if "AZManagementGroup" in s: return "management_groups"
    return None


def _process_azure_evidence(category, evidence, buckets, relationship_records):
    role_assignment_categories = (
        "AZ_GLOBAL_ADMIN", "AZ_PRIVILEGED_ROLE_ADMIN", "AZ_HYBRID_IDENTITY_ADMIN",
        "AZ_APPLICATION_ADMIN", "AZ_CLOUD_APP_ADMIN", "AZ_CONDITIONAL_ACCESS_ADMIN",
        "AZ_USER_ACCESS_ADMIN", "AZ_PRIVILEGED_AUTH_ADMIN", "AZ_SECURITY_ADMIN",
    )
    app_abuse_categories = ("AZ_ADD_SECRET", "AZ_ADD_OWNER")

    if category in role_assignment_categories:
        for item in evidence:
            bucket, principal = _classify(item.get("Principal"), item.get("PrincipalType"))
            tenant = _clean(item.get("Tenant"))
            if principal:
                if bucket:
                    buckets[bucket].add(principal)
                else:
                    buckets["users"].add(principal)
            if tenant:
                buckets["tenants"].add(tenant)
            if principal and tenant:
                ent = _empty_buckets()
                ent[bucket or "users"].add(principal)
                ent["tenants"].add(tenant)
                role_name = category.replace("AZ_", "").replace("_", " ").title()
                relationship_records.append({
                    "text": f"{principal} -[{role_name}]-> {tenant}",
                    "entities": ent,
                })

    elif category == "AZ_ADD_TO_GROUP":
        for item in evidence:
            bucket, principal = _classify(item.get("Principal"), item.get("PrincipalType"))
            group = _clean(item.get("TargetGroup"))
            if principal:
                buckets[bucket or "users"].add(principal)
            if group:
                buckets["groups"].add(group)
            if principal and group:
                ent = _empty_buckets()
                ent[bucket or "users"].add(principal)
                ent["groups"].add(group)
                relationship_records.append({
                    "text": f"{principal} -[AddToGroup]-> {group}",
                    "entities": ent,
                })

    elif category in app_abuse_categories:
        for item in evidence:
            bucket, principal = _classify(item.get("Principal"), item.get("PrincipalType"))
            app = _clean(item.get("Application"))
            if principal:
                buckets[bucket or "users"].add(principal)
            if app:
                buckets["applications"].add(app)
            if principal and app:
                ent = _empty_buckets()
                ent[bucket or "users"].add(principal)
                ent["applications"].add(app)
                action = "AddSecret" if category == "AZ_ADD_SECRET" else "AddOwner"
                relationship_records.append({
                    "text": f"{principal} -[{action}]-> {app}",
                    "entities": ent,
                })

    elif category == "AZ_KEY_VAULT_ABUSE":
        for item in evidence:
            bucket, principal = _classify(item.get("Principal"), item.get("PrincipalType"))
            kv = _clean(item.get("KeyVault"))
            if principal:
                buckets[bucket or "users"].add(principal)
            if kv:
                buckets["key_vaults"].add(kv)
            if principal and kv:
                ent = _empty_buckets()
                ent[bucket or "users"].add(principal)
                ent["key_vaults"].add(kv)
                relationship_records.append({
                    "text": f"{principal} -[KeyVaultContributor]-> {kv}",
                    "entities": ent,
                })

    elif category in ("AZ_CONTRIBUTOR", "AZ_OWNER"):
        for item in evidence:
            bucket, principal = _classify(item.get("Principal"), item.get("PrincipalType"))
            role = item.get("Role", "")
            scope = _clean(item.get("Scope"))
            scope_type = item.get("ScopeType", "")
            if principal:
                buckets[bucket or "users"].add(principal)
            if scope:
                if "Subscription" in (scope_type or ""):
                    buckets["subscriptions"].add(scope)
                elif "ResourceGroup" in (scope_type or ""):
                    buckets["resource_groups"].add(scope)
                elif "ManagementGroup" in (scope_type or ""):
                    buckets["management_groups"].add(scope)
            if principal and scope:
                ent = _empty_buckets()
                ent[bucket or "users"].add(principal)
                rel = f"{principal} -[{role}]-> {scope}"
                relationship_records.append({"text": rel, "entities": ent})

    elif category == "AZ_MANAGED_IDENTITY":
        for item in evidence:
            identity = _clean(item.get("Identity"))
            role = item.get("Role", "")
            scope = _clean(item.get("Scope"))
            if identity:
                buckets["managed_identities"].add(identity)
            if identity and role and scope:
                ent = _empty_buckets()
                ent["managed_identities"].add(identity)
                rel = f"{identity} -[{role}]-> {scope}"
                relationship_records.append({"text": rel, "entities": ent})

    elif category == "AZ_EXTERNAL_USER":
        for item in evidence:
            user = _clean(item.get("User"))
            upn = item.get("UPN", "")
            if user:
                buckets["users"].add(user)
                ent = _empty_buckets()
                ent["users"].add(user)
                display = f"{user} ({upn})" if upn else user
                relationship_records.append({
                    "text": f"External user: {display}",
                    "entities": ent,
                })

    elif category == "AZ_EXECUTE_COMMAND":
        for item in evidence:
            bucket, principal = _classify(item.get("Principal"), item.get("PrincipalType"))
            vm = _clean(item.get("VirtualMachine"))
            if principal:
                buckets[bucket or "users"].add(principal)
            if vm:
                buckets["computers"].add(vm)
            if principal and vm:
                ent = _empty_buckets()
                ent[bucket or "users"].add(principal)
                ent["computers"].add(vm)
                relationship_records.append({
                    "text": f"{principal} -[ExecuteCommand]-> {vm}",
                    "entities": ent,
                })

    elif category == "AZ_RESET_PASSWORD":
        for item in evidence:
            bucket, principal = _classify(item.get("Principal"), item.get("PrincipalType"))
            target = _clean(item.get("Target"))
            tgt_labels = item.get("TargetType")
            tgt_bucket = _azure_bucket(tgt_labels) if tgt_labels else None
            if principal:
                buckets[bucket or "users"].add(principal)
            if target:
                buckets[tgt_bucket or "users"].add(target)
            if principal and target:
                ent = _empty_buckets()
                ent[bucket or "users"].add(principal)
                ent[tgt_bucket or "users"].add(target)
                relationship_records.append({
                    "text": f"{principal} -[ResetPassword]-> {target}",
                    "entities": ent,
                })

    elif category == "AZ_ROLE_ESCALATION":
        for item in evidence:
            bucket, principal = _classify(item.get("Principal"), item.get("PrincipalType"))
            group = _clean(item.get("Group"))
            role_name = item.get("Role", "")
            if principal:
                buckets[bucket or "users"].add(principal)
            if group:
                buckets["groups"].add(group)
            if principal and group:
                ent = _empty_buckets()
                ent[bucket or "users"].add(principal)
                ent["groups"].add(group)
                role_str = f" ({role_name})" if role_name else ""
                rel = f"{principal} -[MemberOf]-> {group} -[{role_name}]"
                relationship_records.append({"text": rel, "entities": ent})

    # ── Heading 2: Zero Trust Identity Hardening Review ──────────
    elif category in ("AZ_MFA_GAP", "AZ_PASSWORD_PROTECTION"):
        for item in evidence:
            user = _clean(item.get("User") or item.get("TenantName") or item.get("Tenant"))
            upn = item.get("UPN", "")
            if user:
                buckets["users"].add(user)
                ent = _empty_buckets()
                ent["users"].add(user)
                display = f"{user} ({upn})" if upn else user
                label = "No MFA registered" if category == "AZ_MFA_GAP" else "No password protection"
                relationship_records.append({"text": f"{display} - {label}", "entities": ent})

    elif category in ("AZ_CA_POLICY_GAPS", "AZ_CUSTOM_ROLES", "AZ_SP_OVERSIGHT"):
        for item in evidence:
            name = _clean(item.get("Policy") or item.get("RoleName") or item.get("Principal"))
            state_or_desc = item.get("State") or item.get("Description") or item.get("Role", "")
            if name:
                buckets["tenants"].add(name)
                ent = _empty_buckets()
                ent["tenants"].add(name)
                rel = f"{name}" + (f" - [{state_or_desc}]" if state_or_desc else "")
                relationship_records.append({"text": rel, "entities": ent})

    elif category == "AZ_PIM_AUDIT":
        for item in evidence:
            bucket, principal = _classify(item.get("Principal"), item.get("PrincipalType"))
            role = item.get("Role", "")
            if principal:
                buckets[bucket or "users"].add(principal)
                ent = _empty_buckets()
                ent[bucket or "users"].add(principal)
                rel = f"{principal} -[{role}] (permanent)"
                relationship_records.append({"text": rel, "entities": ent})

    elif category == "AZ_CROSS_TENANT_ACCESS":
        for item in evidence:
            tenant = _clean(item.get("Tenant"))
            external = _clean(item.get("ExternalTenant"))
            auto_redeem = item.get("AutoRedeem")
            user_consent = item.get("UserConsent")
            if tenant:
                buckets["tenants"].add(tenant)
            if external:
                buckets["tenants"].add(external)
            if tenant and external:
                ent = _empty_buckets()
                ent["tenants"].add(tenant)
                ent["tenants"].add(external)
                flags = []
                if auto_redeem: flags.append(f"AutoRedeem={auto_redeem}")
                if user_consent: flags.append(f"UserConsent={user_consent}")
                flag_str = f" ({', '.join(flags)})" if flags else ""
                relationship_records.append({"text": f"{tenant} -[CrossTenantAccess]-> {external}{flag_str}", "entities": ent})

    elif category == "AZ_LEGACY_AUTH":
        for item in evidence:
            user = _clean(item.get("User"))
            upn = item.get("UPN", "")
            legacy = item.get("LegacyAuthEnabled")
            if user:
                buckets["users"].add(user)
                ent = _empty_buckets()
                ent["users"].add(user)
                display = f"{user} ({upn})" if upn else user
                flags = f" LegacyAuth={legacy}" if legacy is not None else ""
                relationship_records.append({"text": f"{display} - legacy auth enabled{flags}", "entities": ent})

    elif category == "AZ_IDENTITY_GOVERNANCE":
        for item in evidence:
            user = _clean(item.get("User"))
            upn = item.get("UPN", "")
            last_login = item.get("LastSignIn")
            if user:
                buckets["users"].add(user)
                ent = _empty_buckets()
                ent["users"].add(user)
                display = f"{user} ({upn})" if upn else user
                since = f" LastLogin={last_login}" if last_login else ""
                relationship_records.append({"text": f"{display} - stale/no recent login{since}", "entities": ent})

    elif category == "AZ_AUTH_METHODS_POLICY":
        for item in evidence:
            tenant = _clean(item.get("Tenant") or item.get("TenantName"))
            auth = item.get("AuthMethods", "")
            fido = item.get("FIDO2Enabled")
            if tenant:
                buckets["tenants"].add(tenant)
                ent = _empty_buckets()
                ent["tenants"].add(tenant)
                details = []
                if auth: details.append(f"Methods={auth}")
                if fido is not None: details.append(f"FIDO2={fido}")
                detail_str = f" ({', '.join(details)})" if details else ""
                relationship_records.append({"text": f"{tenant} - weak auth methods{detail_str}", "entities": ent})

    elif category == "AZ_LOGGING_AUDIT":
        for item in evidence:
            tenant = _clean(item.get("Tenant") or item.get("TenantName"))
            siem = item.get("DiagnosticSIEM")
            retention = item.get("LogRetentionDays")
            if tenant:
                buckets["tenants"].add(tenant)
                ent = _empty_buckets()
                ent["tenants"].add(tenant)
                details = []
                if siem is not None: details.append(f"SIEM={siem}")
                if retention is not None: details.append(f"Retention={retention}d")
                detail_str = f" ({', '.join(details)})" if details else ""
                relationship_records.append({"text": f"{tenant} - logging gaps{detail_str}", "entities": ent})

    # ── Heading 3: Security Architecture Simulation ──────────────
    elif category == "AZ_GRAPH_API_ABUSE":
        for item in evidence:
            principal = _clean(item.get("Principal"))
            app_id = item.get("AppId", "")
            perm = item.get("GraphPermission", "")
            if principal:
                buckets["applications"].add(principal)
                ent = _empty_buckets()
                ent["applications"].add(principal)
                perm_str = f" -[{perm}]->" if perm else ""
                rel = f"{principal}{perm_str} Graph API ({app_id})" if app_id else f"{principal}{perm_str} Graph API"
                relationship_records.append({"text": rel, "entities": ent})

    elif category == "AZ_SYNC_ACCOUNT_COMPROMISE":
        for item in evidence:
            user = _clean(item.get("User"))
            upn = item.get("UPN", "")
            if user:
                buckets["users"].add(user)
                ent = _empty_buckets()
                ent["users"].add(user)
                display = f"{user} ({upn})" if upn else user
                rel = f"{display} - sync account with privileged access"
                relationship_records.append({"text": rel, "entities": ent})

    elif category in ("AZ_PRT_TOKEN_ABUSE", "AZ_DEVICE_JOIN_ABUSE"):
        label = "PRT-capable" if category == "AZ_PRT_TOKEN_ABUSE" else "Hybrid joined"
        for item in evidence:
            name = _clean(item.get("User") or item.get("DeviceName") or item.get("DisplayName"))
            upn = item.get("UPN", "")
            if name:
                buckets["users" if category == "AZ_PRT_TOKEN_ABUSE" else "computers"].add(name)
                ent = _empty_buckets()
                ent["users" if category == "AZ_PRT_TOKEN_ABUSE" else "computers"].add(name)
                display = f"{name} ({upn})" if upn else name
                relationship_records.append({"text": f"{display} - {label}", "entities": ent})

    elif category == "AZ_CA_BYPASS":
        for item in evidence:
            name = _clean(item.get("Policy"))
            state = item.get("State", "")
            loc = item.get("Locations", "")
            grants = item.get("GrantControls", "")
            if name:
                buckets["tenants"].add(name)
                ent = _empty_buckets()
                ent["tenants"].add(name)
                details = []
                if loc: details.append(f"Loc={loc}")
                if grants: details.append(f"Grants={grants}")
                detail_str = f" ({', '.join(details)})" if details else ""
                relationship_records.append({"text": f"{name} - CA bypass potential{detail_str}", "entities": ent})

    elif category == "AZ_CROSS_TENANT_AUTH_CHAIN":
        for item in evidence:
            user = _clean(item.get("User"))
            upn = item.get("UPN", "")
            role = item.get("Role", "")
            if user:
                buckets["users"].add(user)
                ent = _empty_buckets()
                ent["users"].add(user)
                role_str = f" -[{role}]" if role else ""
                rel = f"{user} ({upn}){role_str} (guest+privileged)" if upn else f"{user}{role_str} (guest+privileged)"
                relationship_records.append({"text": rel, "entities": ent})
                relationship_records.append({"text": rel, "entities": ent})

    elif category == "AZ_MI_TOKEN_THEFT":
        for item in evidence:
            identity = _clean(item.get("Identity"))
            role = item.get("Role", "")
            scope = _clean(item.get("Scope"))
            if identity:
                buckets["managed_identities"].add(identity)
            if identity and scope:
                ent = _empty_buckets()
                ent["managed_identities"].add(identity)
                rel = f"{identity} -[{role}]-> {scope}" if role else f"{identity} -> {scope}"
                relationship_records.append({"text": rel, "entities": ent})

    elif category == "AZ_FUNCTION_KEY_ABUSE":
        for item in evidence:
            func = _clean(item.get("FunctionApp"))
            perm = item.get("Permission", "")
            kv = _clean(item.get("KeyVault"))
            if func:
                buckets["applications"].add(func)
            if kv:
                buckets["key_vaults"].add(kv)
            if func and kv:
                ent = _empty_buckets()
                ent["applications"].add(func)
                ent["key_vaults"].add(kv)
                rel = f"{func} -[{perm}]-> {kv}" if perm else f"{func} -> {kv}"
                relationship_records.append({"text": rel, "entities": ent})

    elif category == "AZ_PAG_ESCALATION":
        for item in evidence:
            user = _clean(item.get("User"))
            src = _clean(item.get("SourceGroup"))
            tgt = _clean(item.get("AdminGroup"))
            if user:
                buckets["users"].add(user)
            if src:
                buckets["groups"].add(src)
            if tgt:
                buckets["groups"].add(tgt)
            if user and tgt:
                ent = _empty_buckets()
                ent["users"].add(user)
                ent["groups"].add(tgt)
                rel = f"{user} -[MemberOf]-> {src} -[MemberOf*]-> {tgt}" if src else f"{user} -> {tgt}"
                relationship_records.append({"text": rel, "entities": ent})


def _empty_buckets():
    return {
        "users": set(), "groups": set(), "computers": set(),
        "gpos": set(), "organizational_units": set(), "domains": set(),
        "service_principals": set(), "managed_identities": set(),
        "applications": set(), "key_vaults": set(),
        "tenants": set(), "subscriptions": set(),
        "resource_groups": set(), "management_groups": set(),
    }


def _buckets_to_lists(buckets):
    return {k: sorted(v) for k, v in buckets.items()}


def _dedupe_path_records(records):
    sequences = [r["text"].split(" → ") for r in records]
    keep = []
    for i, seq in enumerate(sequences):
        if not any(
            j != i and len(other) > len(seq) and other[: len(seq)] == seq
            for j, other in enumerate(sequences)
        ):
            keep.append(records[i])
    return keep


from analytics.constants import COMPLIANCE_MAP, EXCLUSIONS_MAP

METADATA = {
    "TIER0_PATHS": {
        "severity": "CRITICAL",
        "mitre": {"id": "T1078", "tactic": "Privilege Escalation", "technique": "Valid Accounts"},
        "impact": """
Tier-0 exposure creates a direct path to full Active Directory compromise.
An attacker exploiting these paths may:
- Obtain Domain Administrator privileges
- Deploy ransomware enterprise-wide
- Disable security tooling
- Manipulate Group Policy
- Access sensitive business systems
- Cause widespread operational disruption
""",
        "remediation": [
            "Remove unnecessary Tier-0 memberships",
            "Review nested privileged groups",
            "Implement privileged access workstations",
            "Enforce MFA for privileged identities",
            "Deploy Just-In-Time administration",
            "Review BloodHound attack paths regularly",
        ],
        "detection": [
            "Event ID 4624 - Privileged logon",
            "Event ID 4728 - Added to privileged groups",
            "Event ID 4732 - Local admin changes",
            "BloodHound attack path monitoring",
        ],
    },
    "ENTERPRISE_ADMIN_PATHS": {
        "severity": "CRITICAL",
        "mitre": {"id": "T1098", "tactic": "Persistence", "technique": "Account Manipulation"},
        "impact": """
Enterprise Admin compromise enables complete forest-wide control.
Attackers can:
- Compromise every domain in the forest
- Create persistent privileged accounts
- Modify trust relationships
- Access sensitive authentication systems
- Establish long-term persistence
""",
        "remediation": [
            "Reduce Enterprise Admin membership",
            "Use dedicated EA accounts",
            "Implement privileged identity governance",
            "Perform quarterly EA reviews",
            "Enable privileged access monitoring",
        ],
        "detection": [
            "Enterprise Admin membership changes",
            "Privileged account creation",
            "Suspicious administrative logons",
        ],
    },
    "KERBEROAST": {
        "severity": "HIGH",
        "mitre": {"id": "T1558.003", "tactic": "Credential Access", "technique": "Kerberoasting"},
        "impact": """
Kerberoastable service accounts expose encrypted service tickets.
Successful attacks may lead to:
- Offline password cracking
- Service account compromise
- Privilege escalation
- Lateral movement
- Domain compromise
""",
        "remediation": [
            "Migrate service accounts to gMSA",
            "Rotate service account passwords",
            "Use long random passwords",
            "Remove unnecessary SPNs",
            "Limit service account privileges",
        ],
        "detection": [
            "Event ID 4769 monitoring",
            "Unusual TGS requests",
            "High-volume Kerberos ticket requests",
        ],
    },
    "ASREP_ROAST": {
        "severity": "HIGH",
        "mitre": {"id": "T1558", "tactic": "Credential Access", "technique": "AS-REP Roasting"},
        "impact": """
Accounts configured without Kerberos pre-authentication
can expose password hashes for offline cracking.
This can result in:
- Credential theft
- Account compromise
- Privilege escalation
- Persistence opportunities
""",
        "remediation": [
            "Enable Kerberos pre-authentication",
            "Review legacy account settings",
            "Rotate affected account passwords",
        ],
        "detection": [
            "Monitor unusual AS-REQ activity",
            "Review Event ID 4768",
        ],
    },
    "DELEGATION": {
        "severity": "HIGH",
        "mitre": {"id": "T1552", "tactic": "Credential Access", "technique": "Unsecured Credentials"},
        "impact": """
Unconstrained delegation allows attackers to impersonate
highly privileged users authenticating to vulnerable systems.
Potential outcomes include:
- Credential theft
- Domain Administrator compromise
- Lateral movement
- Full domain takeover
""",
        "remediation": [
            "Disable unconstrained delegation",
            "Use constrained delegation",
            "Mark privileged users as sensitive",
            "Restrict delegation permissions",
        ],
        "detection": [
            "Monitor delegation configuration changes",
            "Review delegated systems regularly",
        ],
    },
    "ADMIN_TO": {
        "severity": "HIGH",
        "mitre": {"id": "T1021", "tactic": "Lateral Movement", "technique": "Remote Services"},
        "impact": """
Excessive administrative relationships create opportunities
for attacker movement between systems.
Compromise may result in:
- Lateral movement
- Credential harvesting
- Privilege escalation
- Increased attack surface
""",
        "remediation": [
            "Reduce local administrator rights",
            "Implement tiered administration",
            "Use LAPS",
            "Review privileged access paths",
        ],
        "detection": [
            "Monitor remote logons",
            "Review administrator group membership",
        ],
    },
    "DACL_ABUSE": {
        "severity": "HIGH",
        "mitre": {"id": "T1098", "tactic": "Persistence", "technique": "ACL Abuse"},
        "impact": """
Excessive directory permissions may allow attackers to
modify privileged objects and gain unauthorized access.
This can lead to:
- Privilege escalation
- Persistence
- Hidden administrative control
""",
        "remediation": [
            "Remove GenericAll permissions",
            "Remove WriteDACL permissions",
            "Audit delegated rights",
            "Review ACL inheritance",
        ],
        "detection": [
            "Monitor ACL changes",
            "Review AD object permissions regularly",
        ],
    },
    "GPO_CONTROL": {
        "severity": "MEDIUM",
        "mitre": {"id": "T1484.001", "tactic": "Privilege Escalation", "technique": "Group Policy Modification"},
        "impact": """
Unauthorized GPO control may enable domain-wide
execution of attacker-controlled settings.
Potential impact includes:
- Malware deployment
- Security control bypass
- Persistence
- Privilege escalation
""",
        "remediation": [
            "Restrict GPO editing rights",
            "Review GPO ownership",
            "Implement change approval processes",
        ],
        "detection": [
            "Monitor GPO modifications",
            "Review Event ID 5136",
        ],
    },
    "SID_HISTORY": {
        "severity": "HIGH",
        "mitre": {"id": "T1134.005", "tactic": "Defense Evasion", "technique": "SID History Injection"},
        "impact": """
SID History allows users to maintain access across domains
after migration. Attackers can abuse this for privilege escalation.
Potential outcomes include:
- Cross-domain privilege escalation
- Persistent unauthorized access
- Forest-wide compromise
""",
        "remediation": [
            "Remove unnecessary SID history entries",
            "Limit SID history to migration periods",
            "Audit SID history changes regularly",
        ],
        "detection": [
            "Monitor Event ID 4765 - SID History added",
            "Review accounts with SID history",
        ],
    },
    "DCSYNC": {
        "severity": "CRITICAL",
        "mitre": {"id": "T1003.006", "tactic": "Credential Access", "technique": "DCSync"},
        "impact": """
Accounts with DCSync rights can replicate directory
data and extract all domain credentials.
This can result in:
- Complete domain compromise
- Golden ticket creation
- Kerberos key extraction
- Persistent backdoor access
""",
        "remediation": [
            "Remove Replicating Directory Changes permissions",
            "Restrict DCSync to domain controllers",
            "Monitor for unauthorized replication",
            "Implement honeytoken accounts",
        ],
        "detection": [
            "Event ID 4662 - Directory Service Access",
            "Monitor GetNCChanges replication requests",
        ],
    },
    "CONSTRAINED_DELEGATION": {
        "severity": "HIGH",
        "mitre": {"id": "T1552", "tactic": "Credential Access", "technique": "Unsecured Credentials"},
        "impact": """
Constrained delegation allows impersonation of users
to specific services. Misconfiguration may enable:
- Privilege escalation to critical services
- Lateral movement to sensitive systems
- Service ticket abuse
""",
        "remediation": [
            "Review constrained delegation configurations",
            "Use resource-based delegation where possible",
            "Restrict delegation to least-privilege services",
            "Mark sensitive accounts as 'Account is sensitive'",
        ],
        "detection": [
            "Review delegation settings regularly",
            "Monitor privileged account usage",
        ],
    },
    "RBCD": {
        "severity": "HIGH",
        "mitre": {"id": "T1552", "tactic": "Credential Access", "technique": "Unsecured Credentials"},
        "impact": """
Resource-Based Constrained Delegation (RBCD) allows
computer objects to control delegation to themselves.
Attackers with write access to a computer object
may gain the ability to authenticate as any user.
This can lead to:
- Privilege escalation
- Lateral movement
- Service compromise
""",
        "remediation": [
            "Restrict write permissions on computer objects",
            "Audit RBCD configurations regularly",
            "Remove unnecessary RBCD rights",
        ],
        "detection": [
            "Monitor msDS-AllowedToActOnBehalfOfOtherIdentity changes",
            "Review computer object ACLs",
        ],
    },
    "PASSWORD_NOT_REQUIRED": {
        "severity": "MEDIUM",
        "mitre": {"id": "T1078", "tactic": "Initial Access", "technique": "Valid Accounts"},
        "impact": """
Accounts that do not require passwords present a
significant security risk. These accounts can be
compromised without authentication.
Potential impact includes:
- Easy account compromise
- Lateral movement vector
- Persistence opportunity
""",
        "remediation": [
            "Enable password requirement on all accounts",
            "Audit accounts with passwordnotreq flag",
            "Implement password policy enforcement",
        ],
        "detection": [
            "Review userAccountControl flags",
            "Audit accounts with PASSWD_NOTREQD flag",
        ],
    },
    "REVERSIBLE_ENCRYPTION": {
        "severity": "HIGH",
        "mitre": {"id": "T1552", "tactic": "Credential Access", "technique": "Unsecured Credentials"},
        "impact": """
Reversible encryption stores passwords in a
reversibly encrypted format, allowing anyone
with AD read access to decrypt them.
This can result in:
- Credential theft
- Account compromise
- Privilege escalation
""",
        "remediation": [
            "Disable reversible encryption on all accounts",
            "Rotate affected account passwords",
            "Audit GPO password settings",
        ],
        "detection": [
            "Review account encryption flags",
            "Audit GPO password policy",
        ],
    },
    "ACCOUNT_OPERATORS": {
        "severity": "HIGH",
        "mitre": {"id": "T1098", "tactic": "Persistence", "technique": "Account Manipulation"},
        "impact": """
Membership in privileged built-in groups (Account Operators,
Backup Operators, Print Operators, Server Operators)
grants significant AD privileges that can be abused.
Potential impact includes:
- Privilege escalation
- Domain compromise
- Sensitive data access
- Ransomware deployment
""",
        "remediation": [
            "Remove unnecessary group memberships",
            "Audit built-in group memberships regularly",
            "Implement tiered administration model",
            "Restrict interactive logons for service accounts",
        ],
        "detection": [
            "Monitor privileged group membership changes",
            "Event ID 4728 - Security group member added",
            "Event ID 4732 - Local group member added",
        ],
    },
    "CROSS_FOREST": {
        "severity": "MEDIUM",
        "mitre": {"id": "T1482", "tactic": "Discovery", "technique": "Domain Trust Discovery"},
        "impact": """
Cross-forest trust relationships expand the attack
surface beyond the current domain. Attackers may
leverage trusts to move laterally across forests.
This can lead to:
- Cross-forest compromise
- Lateral movement
- Sensitive data access
""",
        "remediation": [
            "Review trust relationships regularly",
            "Implement selective authentication",
            "Restrict SID filtering for external trusts",
            "Monitor cross-forest authentication attempts",
        ],
        "detection": [
            "Monitor trust relationship changes",
            "Event ID 4624 - Account logon with trusted domain",
        ],
    },
    "PRIVILEGED_GROUPS": {
        "severity": "MEDIUM",
        "mitre": {"id": "T1078", "tactic": "Privilege Escalation", "technique": "Valid Accounts"},
        "impact": """
Membership in administrative groups outside the standard
Tier-0 set (e.g. DHCP Administrators, DNS Administrators)
grants elevated privileges. While often intentionally delegated,
these memberships should be reviewed to ensure least privilege.
Potential impact includes:
- Unnecessary administrative access
- Lateral movement opportunity
- Privilege escalation if combined with other vulnerabilities
""",
        "remediation": [
            "Review membership in custom administrative groups",
            "Audit administrative group memberships regularly",
            "Ensure delegated permissions follow least privilege",
            "Remove unused admin group memberships",
        ],
        "detection": [
            "Monitor administrative group membership changes",
            "Review privileged group membership reports",
        ],
    },
    "DISABLED_PRIVILEGED": {
        "severity": "LOW",
        "mitre": {"id": "T1078", "tactic": "Persistence", "technique": "Valid Accounts"},
        "impact": """
Disabled accounts that remain members of privileged groups
pose a cleanup and compliance risk. While not immediately
exploitable, these accounts should be removed from privileged
groups or deleted to reduce the attack surface.
Potential impact includes:
- Compliance violations
- Stale privileged access
- Risk if accounts are re-enabled
""",
        "remediation": [
            "Remove disabled accounts from privileged groups",
            "Either delete or disable privileged group membership",
            "Implement account lifecycle management",
            "Review privileged group memberships quarterly",
        ],
        "detection": [
            "Regular review of disabled accounts in privileged groups",
            "Identity governance recertification campaigns",
        ],
    },
    # ── Heading 1: Identity Attack Path Assessment ──────────────
    "CERT_ABUSE_ESC1": {
        "severity": "CRITICAL",
        "mitre": {"id": "T1649", "tactic": "Privilege Escalation", "technique": "Steal or Forge Kerberos Tickets"},
        "impact": """
AD-CS ESC1 abuse allows any principal with Enroll + Write rights
on a vulnerable certificate template to request a certificate for
any user (including Domain Admin) and authenticate as that user.
An attacker exploiting ESC1 may:
- Escalate from standard user to Domain Admin
- Forge authentication for any domain user
- Persist via forged certificates
- Bypass MFA with certificate-based authentication
- Compromise the entire domain
""",
        "remediation": [
            "Disable 'Supply Subject Name' on certificate templates that also allow Client Authentication",
            "Require CA Manager Approval on all certificate templates",
            "Audit and remove excessive Write permissions (GenericAll/GenericWrite/WriteDacl) on CertTemplate objects",
            "Implement certificate template lifecycle management",
            "Enable CA auditing and monitor for unusual certificate requests",
            "Deploy CA ACL monitoring",
        ],
        "detection": [
            "Event ID 4886 - Certificate Services approved a certificate request",
            "Event ID 4887 - Certificate Services denied a certificate request",
            "Event ID 4693 - Certificate Services received a request to reenroll",
            "Windows Event Log: CertificateServices-Operational",
        ],
    },
    "CERT_ABUSE_ESC3": {
        "severity": "HIGH",
        "mitre": {"id": "T1649", "tactic": "Privilege Escalation", "technique": "Steal or Forge Kerberos Tickets"},
        "impact": """
ESC3 chains an enrollment agent template (agent certificate)
with a subject template to request arbitrary user certificates.
An attacker exploiting ESC3 may:
- Authenticate as any domain user
- Escalate privileges across the domain
- Persist access via stolen certificates
""",
        "remediation": [
            "Disable Subject Name supply on enrollment agent templates",
            "Set Manager Approval Required on enrollment agent templates",
            "Separate enrollment agent and client authentication templates",
            "Restrict enrollment agent certificates to specific security groups",
        ],
        "detection": [
            "Event ID 4886/4887 - Certificate Services operations",
            "Event ID 4693 - Certificate reenrollment requests",
        ],
    },
    "SHADOW_CREDENTIALS": {
        "severity": "HIGH",
        "mitre": {"id": "T1556", "tactic": "Credential Access", "technique": "Modify Authentication Process"},
        "impact": """
Shadow Credentials abuse uses the AddKeyCredentialLink edge
to add a rogue key credential to a target object (user or
computer). The attacker can then authenticate as that target
using PKINIT, bypassing password-based authentication.
An attacker exploiting Shadow Credentials may:
- Impersonate any target object
- Bypass MFA and password changes
- Persist access even after password rotation
- Escalate privileges via computer account takeover
""",
        "remediation": [
            "Audit and restrict AddKeyCredentialLink permissions",
            "Enable Key Credential auditing on Active Directory",
            "Monitor for rogue certificate authority (CA) enrollment",
            "Restrict registration of key credentials to authorized systems",
            "Use Windows Defender for Identity to detect Shadow Credential attacks",
        ],
        "detection": [
            "Event ID 4768 – Kerberos authentication with PKINIT",
            "Event ID 5136 – LDAP modify of msDS-KeyCredentialLink attribute",
            "Azure ATP: Suspicious certificate enrollment alerts",
        ],
    },
    "DANGEROUS_COMPUTER_ACLS": {
        "severity": "HIGH",
        "mitre": {"id": "T1098", "tactic": "Persistence", "technique": "Account Manipulation"},
        "impact": """
Excessive ACL permissions on User, Group, or OU objects allow
unauthorized principals to modify, impersonate, or take over
those objects. An attacker exploiting these ACLs may:
- Add themselves or others to privileged groups
- Modify user attributes (password reset, SPN set, etc.)
- Take ownership of OUs to control subordinate objects
- Escalate privileges across the domain via group membership
""",
        "remediation": [
            "Remove excessive GenericAll/GenericWrite/WriteDacl on User/Group/OU objects",
            "Implement least-privilege delegation for object management",
            "Audit all write-permission ACLs on sensitive groups (Domain Admins, etc.)",
            "Restrict WriteOwner/WriteDacl on OUs containing high-value objects",
        ],
        "detection": [
            "Event ID 5136 – LDAP write to user/group/OU attributes",
            "Event ID 4738 – User account modified (password reset, SPN change)",
            "Event ID 4728/4732 – Member added to security group",
        ],
    },
    "NTLM_RELAY_PATHS": {
        "severity": "HIGH",
        "mitre": {"id": "T1557", "tactic": "Credential Access", "technique": "Adversary-in-the-Middle"},
        "impact": """
Computers with local admin access to Domain Controllers create
potential NTLM relay paths. An attacker who gains control of such
a computer can coerce authentication from a privileged account and
relay the NTLM challenge to LDAPS on the DC, resulting in
credential relay and privilege escalation regardless of the
service running on the relay server.
An attacker exploiting NTLM relay may:
- Relay credentials to LDAPS and create a rogue domain admin
- Compromise Domain Controller access
- Persist via credential theft
""",
        "remediation": [
            "Enable SMB signing on Domain Controllers (required to block NTLM relay)",
            "Enable LDAP signing and channel binding on Domain Controllers",
            "Minimize computers with AdminTo privilege on Domain Controllers",
            "Deploy EPA (Extended Protection for Authentication)",
            "Apply KB5005413 mitigation for AD CS NTLM relay",
        ],
        "detection": [
            "Event ID 4624 – Logon with NTLM authentication",
            "Event ID 4776 – NTLM authentication to DC",
            "Network monitoring: NTLM authentication flows to unverified servers",
        ],
    },
    "LAPS_GAPS": {
        "severity": "MEDIUM",
        "mitre": {"id": "T1078", "tactic": "Persistence", "technique": "Valid Accounts"},
        "impact": """
Computers without LAPS deployed rely on shared local admin
passwords (often identical across machines). This allows lateral
movement using tools like PsExec, WMI, and WinRM once a single
machine's local admin password is compromised.
An attacker exploiting LAPS gaps may:
- Move laterally across systems with shared passwords
- Escalate from standard user to local admin on multiple systems
- Use pass-the-hash attacks with identical local admin credentials
""",
        "remediation": [
            "Deploy Microsoft LAPS or Windows LAPS on all domain-joined computers",
            "Rotate legacy local admin passwords immediately",
            "Enforce complex unique passwords for local administrator accounts",
            "Monitor LAPS-managed password usage via audit logs",
        ],
        "detection": [
            "Event ID 4662 – An operation was performed on LAPS ms-Mcs-AdmPwd attribute",
            "LAPS reporting via PowerShell Get-LapsADPassword",
        ],
    },
    "SQL_LINKED_SERVERS": {
        "severity": "HIGH",
        "mitre": {"id": "T1550.002", "tactic": "Lateral Movement", "technique": "Exploitation of Trust"},
        "impact": """
MS-SQL Linked Server abuse allows attackers with SQLAdmin rights
to traverse linked server trusts, enabling cross-database and
cross-system lateral movement. Attackers can execute commands
on remote SQL Servers, escalate to OS-level access via xp_cmdshell,
and reach systems that are not directly accessible.
An attacker exploiting SQL Linked Servers may:
- Move laterally across the environment
- Execute commands on remote SQL Servers
- Escalate from SQL Server to OS-level compromise
- Access sensitive databases across linked trust chains
""",
        "remediation": [
            "Restrict SQLAdmin permissions to only authorized principals",
            "Audit and remove unnecessary SQL Server linked server configurations",
            "Disable xp_cmdshell on SQL Servers where not required",
            "Implement least-privilege for SQL Server service accounts",
            "Enable SQL Server audit logging",
        ],
        "detection": [
            "SQL Server audit log: xp_cmdshell execution",
            "Event ID 18454 – SQL Server linked server access",
            "Network monitoring: SQL Server connections across trust boundaries",
        ],
    },
    "DOMAIN_TRUST_ESCALATION": {
        "severity": "HIGH",
        "mitre": {"id": "T1484", "tactic": "Privilege Escalation", "technique": "Domain Policy Modification"},
        "impact": """
Intra-forest and cross-domain trusts with SID filtering disabled
or TGT delegation enabled allow attackers to perform SID history
abuse (Golden Ticket-style attacks) and forge privilege across
domain boundaries. Attackers can escalate from a compromised
domain to other domains in the forest or across the trust.
An attacker exploiting trust misconfigurations may:
- Escalate from standard user to Enterprise Admin
- Access resources in trusting domains
- Forge SID history for privilege escalation
- Persist across domain boundaries
""",
        "remediation": [
            "Verify SID filtering is enabled on all intra-forest trusts",
            "Disable TGT delegation where not required",
            "Restrict trust authentication to specific security groups",
            "Implement selective authentication for high-value trusts",
            "Monitor trust relationship modifications",
        ],
        "detection": [
            "Event ID 4769 – Kerberos service ticket request (inter-domain)",
            "Event ID 4662 – Trusted Domain Information access",
            "Event ID 5127 – Trust relationship modified",
        ],
    },
    # ── Azure / Entra ID Metadata ──────────────────────────────
    "AZ_GLOBAL_ADMIN": {
        "severity": "CRITICAL",
        "mitre": {"id": "T1078.004", "tactic": "Privilege Escalation", "technique": "Cloud Roles"},
        "impact": """
Global Administrator is the highest privileged role in Entra ID.
Any user, group, or service principal with this role can:
- Access all Azure resources and settings
- Modify tenant-wide configuration
- Reset any user's password
- Register and manage applications
- Access all data via privileged access
- Compromise the entire tenant
""",
        "remediation": [
            "Reduce Global Administrator count to absolute minimum (4-6 break-glass accounts)",
            "Enforce Privileged Identity Management (PIM) for activation",
            "Require Azure MFA and phishing-resistant authentication",
            "Use dedicated break-glass accounts with long complex passwords",
            "Monitor and alert on Global Administrator activation",
            "Implement Privileged Access Groups for delegating admin roles",
        ],
        "detection": [
            "Azure AD Audit Log: Add member to Global Administrator role",
            "Microsoft 365 Defender: Elevated role activation alerts",
            "Azure Sentinel: Global Admin activity monitoring workbook",
        ],
    },
    "AZ_PRIVILEGED_ROLE_ADMIN": {
        "severity": "CRITICAL",
        "mitre": {"id": "T1078.004", "tactic": "Privilege Escalation", "technique": "Cloud Roles"},
        "impact": """
Privileged Role Administrator can manage role assignments in
Entra ID, including elevating any user to Global Administrator.
This role is effectively equivalent to Global Administrator.
Compromise may lead to:
- Complete tenant takeover
- Permanent backdoor access
- Data exfiltration
""",
        "remediation": [
            "Restrict Privileged Role Administrator to dedicated admin accounts",
            "Enable PIM with approval workflow for role activation",
            "Require MFA and conditional access policies",
            "Audit all role assignment changes in real-time",
        ],
        "detection": [
            "Monitor Azure AD PIM activation requests",
            "Alert on Privileged Role Administrator assignments",
            "Review privileged role activation justifications",
        ],
    },
    "AZ_HYBRID_IDENTITY_ADMIN": {
        "severity": "CRITICAL",
        "mitre": {"id": "T1078.004", "tactic": "Privilege Escalation", "technique": "Cloud Roles"},
        "impact": """
Hybrid Identity Administrator manages cloud provisioning and
identity synchronization between on-prem AD and Entra ID.
This role can:
- Modify password hash sync configuration
- Manage federation settings (AD FS)
- Provision cloud users from on-prem AD
- Deploy and manage Pass-through Authentication agents
Compromise enables on-prem to cloud lateral movement.
""",
        "remediation": [
            "Restrict Hybrid Identity Administrator to dedicated sync accounts",
            "Secure AD FS infrastructure (if federated)",
            "Monitor synchronization configuration changes",
            "Implement break-glass accounts for sync emergencies",
        ],
        "detection": [
            "Azure AD Connect configuration change audit logs",
            "Federation setting modification alerts",
            "Sync account credential changes",
        ],
    },
    "AZ_APPLICATION_ADMIN": {
        "severity": "HIGH",
        "mitre": {"id": "T1098.003", "tactic": "Persistence", "technique": "Additional Cloud Roles"},
        "impact": """
Application Administrator can register and manage applications,
including creating and managing application secrets and certificates.
This role can:
- Add credentials to existing applications
- Create new application registrations
- Grant application permissions
- Modify application authentication configuration
Attackers can create backdoor application access to tenant data.
""",
        "remediation": [
            "Restrict Application Administrator to dedicated admin accounts",
            "Implement application registration approval workflows",
            "Monitor and audit application credential changes",
            "Review consented application permissions regularly",
        ],
        "detection": [
            "Azure AD Audit Log: Add application credential",
            "Microsoft Defender for Cloud Apps: OAuth app alerts",
            "Monitor application permission grant activity",
        ],
    },
    "AZ_CLOUD_APP_ADMIN": {
        "severity": "HIGH",
        "mitre": {"id": "T1098.003", "tactic": "Persistence", "technique": "Additional Cloud Roles"},
        "impact": """
Cloud Application Administrator has the same capabilities as
Application Administrator but only for Microsoft cloud applications
(Exchange Online, SharePoint, Teams, etc.). Compromise may enable
persistent access to Microsoft 365 data and services.
""",
        "remediation": [
            "Restrict Cloud Application Administrator to dedicated accounts",
            "Review and limit app consent policies",
            "Implement conditional access for app management",
            "Audit Microsoft 365 application assignments regularly",
        ],
        "detection": [
            "Monitor admin role assignments in Microsoft 365",
            "Audit application consent grant activity",
            "Review OAuth application permissions quarterly",
        ],
    },
    "AZ_CONDITIONAL_ACCESS_ADMIN": {
        "severity": "HIGH",
        "mitre": {"id": "T1098.003", "tactic": "Defense Evasion", "technique": "Conditional Access Policies"},
        "impact": """
Conditional Access Administrator can create, modify, and delete
conditional access policies. This role can:
- Disable or bypass MFA requirements
- Create allow-lists for specific IP ranges
- Exempt specific users or applications from security policies
- Weaken or remove device compliance requirements
Compromise enables bypassing core security controls.
""",
        "remediation": [
            "Restrict Conditional Access Administrator to dedicated accounts",
            "Implement break-glass accounts exempt from CA policies",
            "Monitor all CA policy changes",
            "Set up policy change notification workflows",
            "Maintain offline backup of CA policy configuration",
        ],
        "detection": [
            "Azure AD Audit Log: Conditional Access policy changes",
            "Alert on CA policy deletion or disabling",
            "Monitor policy exemption additions",
        ],
    },
    "AZ_USER_ACCESS_ADMIN": {
        "severity": "HIGH",
        "mitre": {"id": "T1078.004", "tactic": "Privilege Escalation", "technique": "Cloud Roles"},
        "impact": """
User Access Administrator can manage user assignments to Azure
resources at all scopes. This role can grant itself or others
access to any Azure subscription, resource group, or resource.
Compromise may lead to broad Azure resource access and data exposure.
""",
        "remediation": [
            "Restrict User Access Administrator assignments",
            "Review role assignments at management group scope",
            "Implement Azure Privileged Identity Management",
            "Audit role assignments regularly across all subscriptions",
        ],
        "detection": [
            "Azure Monitor: Role assignment change alerts",
            "Azure Activity Log: Create role assignment",
            "Microsoft Defender for Cloud: RBAC monitoring",
        ],
    },
    "AZ_PRIVILEGED_AUTH_ADMIN": {
        "severity": "CRITICAL",
        "mitre": {"id": "T1078.004", "tactic": "Privilege Escalation", "technique": "Cloud Roles"},
        "impact": """
Privileged Authentication Administrator can manage authentication
policies and credentials for all users, including:
- Register and manage Pass Through Authentication agents
- Deploy and manage Azure AD Application Proxy
- Manage authentication methods and policies
- Reset passwords for privileged users
Compromise enables persistent backdoor access to authentication
pipeline and credential compromise.
""",
        "remediation": [
            "Restrict Privileged Authentication Administrator to dedicated admin accounts",
            "Enable PIM with approval workflow for role activation",
            "Monitor authentication agent registration changes",
            "Secure Pass Through Authentication agent hosts",
            "Audit authentication method policy changes",
        ],
        "detection": [
            "Azure AD Audit Log: Authentication agent registration",
            "Monitor Pass Through Authentication connector changes",
            "Alert on authentication policy modifications",
        ],
    },
    "AZ_SECURITY_ADMIN": {
        "severity": "HIGH",
        "mitre": {"id": "T1078.004", "tactic": "Privilege Escalation", "technique": "Cloud Roles"},
        "impact": """
Security Administrator can manage security-related settings in
Entra ID and Microsoft 365, including:
- Read and manage security policies and alerts
- Manage conditional access policies (read-only)
- View audit logs and sign-in reports
- Manage Microsoft Defender for Cloud settings
- Manage Identity Protection and Privileged Identity Management
Compromise enables bypassing security monitoring and controls.
""",
        "remediation": [
            "Restrict Security Administrator to dedicated security operations accounts",
            "Implement PIM for security role activation",
            "Monitor security administrator activity",
            "Enforce MFA and conditional access for security admins",
        ],
        "detection": [
            "Azure AD Audit Log: Security Administrator role assignments",
            "Microsoft 365 Defender: Security admin activity alerts",
            "Monitor security policy modification events",
        ],
    },
    "AZ_CONTRIBUTOR": {
        "severity": "HIGH",
        "mitre": {"id": "T1078.004", "tactic": "Privilege Escalation", "technique": "Cloud Roles"},
        "impact": """
Contributor role grants full access to manage all resources within
the assigned scope (subscription, resource group, or management
group) but cannot manage role assignments. This role can:
- Create, modify, and delete Azure resources
- Deploy virtual machines and storage accounts
- Modify network security group rules
- Access and modify configuration of existing resources
Compromise enables significant lateral movement within Azure.
""",
        "remediation": [
            "Replace Contributor with more specific RBAC roles where possible",
            "Use management group scoped assignments only when necessary",
            "Implement Azure PIM for just-in-time Contributor access",
            "Review Contributor assignments quarterly",
            "Use Azure Policy to restrict resource types contributors can manage",
        ],
        "detection": [
            "Azure Activity Log: Resource creation/modification events",
            "Microsoft Defender for Cloud: Excessive RBAC monitoring",
            "Azure Policy compliance alerts on resource configuration",
        ],
    },
    "AZ_OWNER": {
        "severity": "CRITICAL",
        "mitre": {"id": "T1078.004", "tactic": "Privilege Escalation", "technique": "Cloud Roles"},
        "impact": """
Owner role grants full access to manage all resources and role
assignments within the assigned scope (subscription, resource group,
or management group). This role can:
- Do everything Contributor can
- Grant any RBAC role to any principal
- Elevate access to any scope below the assigned level
- Delete all resources including access control
Compromise enables complete takeover of the Azure subscription.
""",
        "remediation": [
            "Replace Owner with Contributor + separate Privileged Role Administrator where possible",
            "Use Azure PIM for just-in-time Owner activation",
            "Implement break-glass accounts with Owner role",
            "Audit and alert on Owner role assignments",
            "Limit Owner assignments to management group scope only",
        ],
        "detection": [
            "Azure Activity Log: Role assignment creation events",
            "Microsoft Defender for Cloud: Owner role monitoring",
            "Azure Monitor: Alert on new Owner assignments",
        ],
    },
    "AZ_ADD_SECRET": {
        "severity": "HIGH",
        "mitre": {"id": "T1098.002", "tactic": "Persistence", "technique": "Additional Cloud Credentials"},
        "impact": """
Principals with permission to add secrets to applications can
create new credentials (passwords or certificates) for existing
application registrations. This allows:
- Persistent backdoor access to application resources
- Authentication as the application to access tenant data
- Bypassing user-based MFA and conditional access
Attackers can maintain long-term persistent access.
""",
        "remediation": [
            "Audit all principals with Add Secret permissions",
            "Restrict application credential management to admins",
            "Implement certificate-based authentication for critical apps",
            "Set short credential expiry periods",
            "Monitor and alert on new application credentials",
        ],
        "detection": [
            "Azure AD Audit Log: Add application credential",
            "Alert on new application secrets outside change window",
            "Review application credential age and rotation",
        ],
    },
    "AZ_ADD_OWNER": {
        "severity": "HIGH",
        "mitre": {"id": "T1098.002", "tactic": "Persistence", "technique": "Additional Cloud Roles"},
        "impact": """
Principals with permission to add owners to applications can
grant other principals control over the application. This enables:
- Privilege escalation through application ownership
- Lateral movement across application permissions
- Persistent access through owned applications
""",
        "remediation": [
            "Restrict Add Owner permissions to authorized admins",
            "Review application owner lists regularly",
            "Implement application ownership approval workflows",
            "Remove unused applications and their permissions",
        ],
        "detection": [
            "Azure AD Audit Log: Add owner to application",
            "Review application ownership changes",
            "Alert on sensitive application owner additions",
        ],
    },
    "AZ_ADD_TO_GROUP": {
        "severity": "HIGH",
        "mitre": {"id": "T1098.001", "tactic": "Persistence", "technique": "Account Manipulation"},
        "impact": """
Principals with permission to add members to Azure groups can
elevate their own or others' privileges by adding accounts to
privileged groups. This can lead to:
- Privilege escalation through group membership
- Lateral movement across the tenant
- Persistent access via group nesting
""",
        "remediation": [
            "Restrict group membership management to authorized admins",
            "Review group membership changes regularly",
            "Implement approval workflows for privileged group changes",
            "Use Entra ID PIM for privileged group membership",
        ],
        "detection": [
            "Azure AD Audit Log: Add group member",
            "Alert on additions to privileged groups",
            "Monitor group nesting depth for escalation paths",
        ],
    },
    "AZ_KEY_VAULT_ABUSE": {
        "severity": "CRITICAL",
        "mitre": {"id": "T1552.005", "tactic": "Credential Access", "technique": "Cloud Instance Metadata API"},
        "impact": """
Key Vault Contributor access or equivalent permissions allow
reading secrets, keys, and certificates stored in Azure Key Vault.
This can expose:
- Application credentials and connection strings
- Storage account keys and database passwords
- Certificate private keys
- Cryptographic keys for data encryption
Compromise enables broad data access and lateral movement.
""",
        "remediation": [
            "Restrict Key Vault access to least privilege using RBAC",
            "Enable Key Vault firewall and service endpoints",
            "Use managed identities instead of connection strings",
            "Enable Key Vault soft-delete and purge protection",
            "Rotate secrets regularly and audit access",
            "Enable Key Vault logging and monitoring",
        ],
        "detection": [
            "Azure Monitor: Key Vault secret access logs",
            "Azure Sentinel: Key Vault access anomaly detection",
            "Alert on bulk secret read operations",
            "Monitor Key Vault RBAC assignment changes",
        ],
    },
    "AZ_MANAGED_IDENTITY": {
        "severity": "HIGH",
        "mitre": {"id": "T1525.001", "tactic": "Persistence", "technique": "Implant Internal Image"},
        "impact": """
Managed identities with high-privilege role assignments (Contributor,
Owner, Key Vault access) present an abuse vector. If a managed
identity's hosting resource (VM, Function App, Container Instance)
is compromised, the attacker inherits the identity's privileges.
This can lead to:
- Lateral movement across Azure resources
- Data access via Key Vault secrets
- Privilege escalation within subscriptions
""",
        "remediation": [
            "Review managed identity role assignments for least privilege",
            "Use separate managed identities per resource type",
            "Restrict which resources can use managed identities",
            "Monitor managed identity authentication activity",
            "Implement network isolation for resources with managed identities",
        ],
        "detection": [
            "Azure Activity Log: Managed identity token requests",
            "Azure AD Sign-in Logs: Managed identity authentication",
            "Microsoft Defender for Cloud: Identity recommendations",
        ],
    },
    "AZ_EXTERNAL_USER": {
        "severity": "MEDIUM",
        "mitre": {"id": "T1098.003", "tactic": "Persistence", "technique": "Additional Cloud Roles"},
        "impact": """
External (guest) users with privileged role assignments in the
tenant present a risk of unauthorized access. Guest user accounts:
- Are managed by external identity providers
- May have unknown security postures
- Can retain access after external provider compromise
- Are frequently over-provisioned with unnecessary privileges
""",
        "remediation": [
            "Review guest user role assignments regularly",
            "Implement Entra ID entitlement management",
            "Set guest user access review campaigns",
            "Restrict guest user permissions to minimum required",
            "Use cross-tenant access policies for external collaboration",
        ],
        "detection": [
            "Azure AD Audit Log: Guest user role assignment",
            "Identity Governance: Access review reminders",
            "Microsoft 365 Defender: Guest user activity alerts",
        ],
    },
    "AZ_EXECUTE_COMMAND": {
        "severity": "HIGH",
        "mitre": {"id": "T1059.009", "tactic": "Execution", "technique": "Cloud Shell"},
        "impact": """
Principals with Run Command permissions on Azure VMs can execute
scripts and commands directly on virtual machines. This enables:
- Code execution on target VMs without network access
- Credential harvesting from VM memory and disk
- Lateral movement into VM environments
- Privilege escalation within the VM's identity context
""",
        "remediation": [
            "Restrict Run Command permissions to authorized admins",
            "Disable Run Command if not required",
            "Use Azure Bastion for VM access instead of Run Command",
            "Monitor and audit all Run Command executions",
            "Implement just-in-time VM access",
        ],
        "detection": [
            "Azure Activity Log: Run Command execution events",
            "Azure Monitor: VM extension activity alerts",
            "Alert on Run Command from non-admin principals",
        ],
    },
    "AZ_RESET_PASSWORD": {
        "severity": "MEDIUM",
        "mitre": {"id": "T1098", "tactic": "Persistence", "technique": "Account Manipulation"},
        "impact": """
Principals with password reset permissions can modify credentials
for user accounts or local VM accounts. This enables:
- Account takeover through credential reset
- Persistence via new password knowledge
- Lateral movement through compromised credentials
""",
        "remediation": [
            "Restrict password reset permissions to authorized helpdesk/admin accounts",
            "Enable self-service password reset with MFA",
            "Audit all password reset operations",
            "Implement approval workflows for privileged account resets",
            "Notify users on password reset events",
        ],
        "detection": [
            "Azure AD Audit Log: Password reset events",
            "Alert on bulk password reset operations",
            "Monitor helpdesk admin password reset activity",
        ],
    },
    "AZ_ROLE_ESCALATION": {
        "severity": "CRITICAL",
        "mitre": {"id": "T1078.004", "tactic": "Privilege Escalation", "technique": "Cloud Roles"},
        "impact": """
Azure role escalation paths exist where a principal can leverage
group memberships and role assignments to gain higher privileges.
These paths represent direct escalation to tenant-wide admin roles
via nested group memberships and transitive role assignments.
Compromise of any principal on these paths can lead to:
- Complete tenant compromise
- Permanent backdoor access
- Broad data exfiltration capabilities
""",
        "remediation": [
            "Review group nesting for privileged role access paths",
            "Implement just-in-time group membership with PIM",
            "Restrict Azure AD group creation to admins",
            "Audit transitive role assignments",
            "Break escalation paths by removing unnecessary group memberships",
        ],
        "detection": [
            "Azure AD Audit Log: Privileged group membership changes",
            "Identity Protection: Risky user alerts for privileged users",
            "Microsoft Defender for Identity: Privileged role alerts",
        ],
    },
    # ── Heading 2: Zero Trust Identity Hardening Review ──────────
    "AZ_MFA_GAP": {
        "severity": "HIGH",
        "mitre": {"id": "T1078", "tactic": "Privilege Escalation", "technique": "Valid Accounts"},
        "impact": """
Users without MFA registered are vulnerable to credential theft,
password spray, and phishing attacks. MFA is the single most
effective control for preventing account compromise in Entra ID.
Without MFA enforcement, any compromised password grants the
attacker full access to the user's applications and data.
An attacker exploiting MFA gaps may:
- Access sensitive cloud applications with stolen credentials
- Perform lateral movement using compromised identities
- Persist via password-based authentication
""",
        "remediation": [
            "Enable Conditional Access to require MFA for all users",
            "Implement security defaults for tenants without P2 licensing",
            "Enforce number matching for push notifications",
            "Migrate users from SMS/voice to authenticator app or FIDO2",
            "Run MFA registration campaigns via Entra ID Identity Protection",
        ],
        "detection": [
            "Entra ID Sign-in logs: Authentication method used",
            "Identity Protection: Risky sign-in events",
            "MFA registration audit via Entra ID Admin Center",
        ],
    },
    "AZ_CA_POLICY_GAPS": {
        "severity": "HIGH",
        "mitre": {"id": "T1078", "tactic": "Defense Evasion", "technique": "Valid Accounts"},
        "impact": """
Conditional Access policies in disabled or report-only state do
not enforce security controls. Attackers can bypass intended
authentication protections while admins may have a false sense
of security from policies that are not actually blocking threats.
An attacker exploiting CA policy gaps may:
- Bypass MFA requirements
- Access tenant resources from untrusted locations
- Use legacy authentication flows
""",
        "remediation": [
            "Enable all Conditional Access policies with 'Block' or 'Grant' controls",
            "Move report-only policies to enforcement within 90 days",
            "Target policies at All Users + All Cloud Apps with exclude scope for break-glass",
            "Implement phased rollout for high-impact policy changes",
        ],
        "detection": [
            "Entra ID Audit Log: Conditional Access policy status changes",
            "Sign-in logs: Report-only policy results",
            "Microsoft 365 Defender: CA policy alerts",
        ],
    },
    "AZ_PIM_AUDIT": {
        "severity": "MEDIUM",
        "mitre": {"id": "T1078.004", "tactic": "Persistence", "technique": "Cloud Roles"},
        "impact": """
Permanently active privileged role assignments bypass the security
benefits of Privileged Identity Management. Without PIM activation
requirements, any compromise of a permanently assigned user grants
immediate elevated access without approvals, time limits, or audit.
An attacker exploiting permanently active roles may:
- Immediately access tenant-wide admin capabilities
- Create additional privileged accounts
- Establish long-term persistence
""",
        "remediation": [
            "Convert permanent role assignments to PIM-eligible with activation approval",
            "Set maximum activation duration to 4-8 hours based on role criticality",
            "Require Azure MFA for PIM activation",
            "Enable PIM alerting for privileged role activations",
            "Implement privileged access groups for continuous access management",
        ],
        "detection": [
            "Entra ID Audit Log: PIM activation events",
            "Microsoft 365 Defender: Elevated role usage alerts",
            "PIM alerts for suspicious activation patterns",
        ],
    },
    "AZ_SP_OVERSIGHT": {
        "severity": "HIGH",
        "mitre": {"id": "T1098", "tactic": "Persistence", "technique": "Account Manipulation"},
        "impact": """
Service principals with privileged directory roles represent a
significant security risk. These application identities operate
without user oversight and are often forgotten after deployment.
Compromised SP credentials grant attackers automated, persistent
access to tenant admin capabilities without triggering user-based
detections.
An attacker exploiting overprivileged SPs may:
- Access tenant admin capabilities without MFA
- Create and manage applications and service principals
- Persist access long after incident response clears user accounts
- Automate credential access across the tenant
""",
        "remediation": [
            "Audit all service principals with privileged directory roles",
            "Replace permanent role assignments with PIM for service principals",
            "Rotate SP credentials regularly and enforce certificate-based auth",
            "Remove unused or orphaned service principals",
            "Implement application governance policies",
        ],
        "detection": [
            "Entra ID Audit Log: SP credential addition",
            "Microsoft 365 Defender: Suspicious application consent alerts",
            "Identity Protection: Service principal sign-in anomalies",
        ],
    },
    "AZ_CROSS_TENANT_ACCESS": {
        "severity": "MEDIUM",
        "mitre": {"id": "T1528", "tactic": "Credential Access", "technique": "Steal Application Access Token"},
        "impact": """
Unrestricted cross-tenant collaboration settings allow external
users to access tenant resources without governance controls.
Attackers can use cross-tenant trusts to move laterally between
compromised tenants, exfiltrate data via guest access, or
establish persistence through unmanaged external identities.
An attacker exploiting cross-tenant access may:
- Move laterally across trusted tenants
- Exfiltrate sensitive data via guest user access
- Establish unauthorized external collaboration
""",
        "remediation": [
            "Configure cross-tenant access policies for inbound and outbound access",
            "Disable automatic redemption for external users",
            "Enable Entitlement Management for governed guest access",
            "Restrict external collaboration to specific approved domains",
            "Review and audit guest user access reviews quarterly",
        ],
        "detection": [
            "Entra ID Audit Log: Guest user invitation",
            "Microsoft 365 Defender: Cross-tenant sign-in activity",
            "Identity Protection: Cross-tenant access anomalies",
        ],
    },
    "AZ_CUSTOM_ROLES": {
        "severity": "MEDIUM",
        "mitre": {"id": "T1078.004", "tactic": "Persistence", "technique": "Cloud Roles"},
        "impact": """
Custom Azure RBAC role definitions can grant permissions that
exceed their intended scope. Roles with wildcard actions ('*')
or broad permissions like 'Microsoft.Authorization/*' allow
role holders to elevate privileges, create additional roles,
or bypass intended access controls.
An attacker exploiting custom roles may:
- Create additional privileged role assignments
- Modify or delete RBAC role definitions
- Escalate from custom role to owner/contributor
""",
        "remediation": [
            "Audit all custom role definitions for excessive permissions",
            "Remove wildcard actions from custom roles where possible",
            "Implement least privilege using specific action permissions",
            "Review custom role assignments to verify least privilege",
            "Use built-in roles wherever possible",
        ],
        "detection": [
            "Entra ID Audit Log: Role definition creation or modification",
            "Azure Policy: Monitor custom role creation",
            "Microsoft Defender for Cloud: Custom role usage alerts",
        ],
    },
    "AZ_PASSWORD_PROTECTION": {
        "severity": "MEDIUM",
        "mitre": {"id": "T1110", "tactic": "Credential Access", "technique": "Brute Force"},
        "impact": """
Password protection policies reduce the risk of password spray and
brute force attacks by blocking common passwords and enforcing
complexity. Without these policies, users can set weak passwords
that are vulnerable to dictionary attacks, password spray, and
credential stuffing — the most common initial attack vectors.
An attacker exploiting weak password policies may:
- Gain initial access via password spray attacks
- Compromise multiple accounts with common passwords
- Establish foothold for lateral movement
""",
        "remediation": [
            "Enable Entra ID Password Protection for cloud and on-premises",
            "Deploy custom banned password lists for industry-specific terms",
            "Enforce password writeback for hybrid environments",
            "Enable SSPR (Self-Service Password Reset) with MFA registration",
            "Implement phishing-resistant authentication methods",
        ],
        "detection": [
            "Entra ID Audit Log: Password change and reset events",
            "Identity Protection: Leaked credentials reports",
            "Microsoft 365 Defender: Password spray attack alerts",
        ],
    },
    "AZ_LEGACY_AUTH": {
        "severity": "HIGH",
        "mitre": {"id": "T1078", "tactic": "Defense Evasion", "technique": "Valid Accounts"},
        "impact": """
Legacy authentication protocols (POP3, IMAP4, SMTP Auth) bypass
Conditional Access and MFA enforcement. Attackers regularly use
legacy auth to authenticate without MFA, perform password spray,
and maintain persistence after modern authentication controls
are enabled.
An attacker exploiting legacy auth may:
- Bypass MFA and Conditional Access policies
- Perform password spray attacks without triggering MFA challenges
- Persist access using stolen credentials on legacy protocols
""",
        "remediation": [
            "Block legacy authentication in Conditional Access policies",
            "Disable legacy protocols on mailboxes via Exchange Online authentication policies",
            "Enable security defaults for tenants without P2 licensing",
            "Monitor legacy authentication traffic via Entra ID Sign-in logs",
            "Migrate POP/IMAP users to modern clients (Outlook, Outlook Mobile)",
        ],
        "detection": [
            "Entra ID Sign-in logs: Filter ClientApp for legacy auth protocols",
            "Microsoft 365 Defender: Legacy protocol authentication alerts",
            "Identity Protection: Legacy auth sign-in anomalies",
        ],
    },
    "AZ_IDENTITY_GOVERNANCE": {
        "severity": "MEDIUM",
        "mitre": {"id": "T1098", "tactic": "Persistence", "technique": "Account Manipulation"},
        "impact": """
Identity governance gaps such as missing access reviews, orphaned
entitlements, stale guest accounts, and lack of provisioning
automation increase the risk of privilege creep and undetected
attacker persistence. Without regular attestation, dormant
accounts and excessive permissions accumulate over time.
An attacker exploiting governance gaps may:
- Use dormant privileged accounts for persistence
- Leverage orphaned guest accounts for cross-tenant access
- Inherit excessive permissions from stale group memberships
""",
        "remediation": [
            "Enable Entra ID Entitlement Management for automated access reviews",
            "Configure periodic access reviews for privileged roles and guest users",
            "Automate guest user lifecycle (invite expiration, deprovisioning)",
            "Implement just-in-time provisioning with PIM",
            "Define attestation cadence (quarterly for privileged, annually for standard)",
        ],
        "detection": [
            "Entra ID Audit Log: Access review results",
            "Identity Protection: Stale account anomalies",
            "Microsoft 365 Defender: Orphaned account alerts",
        ],
    },
    "AZ_AUTH_METHODS_POLICY": {
        "severity": "HIGH",
        "mitre": {"id": "T1078", "tactic": "Credential Access", "technique": "Valid Accounts"},
        "impact": """
Authentication methods policy that allows SMS or voice as primary
MFA methods exposes users to SIM-swapping, phishing, and number
porting attacks. Absence of passwordless methods (FIDO2, Windows
Hello for Business, passkeys) means admins remain vulnerable to
credential theft.
An attacker exploiting weak auth methods may:
- Intercept SMS-based MFA codes via SIM swap
- Bypass MFA using voice call social engineering
- Phish OTP codes from users on less secure methods
""",
        "remediation": [
            "Enable FIDO2 security keys and Windows Hello for Business for all users",
            "Ban SMS and voice as primary authentication methods",
            "Implement number matching for authenticator app push notifications",
            "Migrate to passwordless credentials for administrative roles first",
            "Configure authentication strengths in Conditional Access",
        ],
        "detection": [
            "Entra ID Audit Log: Authentication method registration changes",
            "Identity Protection: MFA method registration anomalies",
            "Microsoft 365 Defender: Suspicious MFA registration alerts",
        ],
    },
    "AZ_LOGGING_AUDIT": {
        "severity": "MEDIUM",
        "mitre": {"id": "T1562", "tactic": "Defense Evasion", "technique": "Impair Defenses"},
        "impact": """
Entra ID diagnostic settings not streaming to a SIEM or log
analytics workspace severely impair incident detection and
forensic investigation. Without adequate retention (minimum
30 days for sign-in logs), security teams cannot investigate
historical attacks, correlate cross-tenant activity, or
comply with audit and regulatory requirements.
An attacker operating without SIEM coverage may:
- Operate undetected without logging to security teams
- Destroy or alter evidence before retention expires
- Move laterally without triggering SIEM detection rules
""",
        "remediation": [
            "Configure diagnostic settings to stream sign-in and audit logs to Log Analytics",
            "Set log retention to at least 30 days (365 recommended) for sign-in logs",
            "Integrate Log Analytics with Sentinel or existing SIEM",
            "Enable Microsoft  Defender for Cloud Apps log collection",
            "Test SIEM ingestion pipeline quarterly",
        ],
        "detection": [
            "Entra ID Audit Log: Diagnostic settings changes",
            "Microsoft 365 Defender: Log ingestion health alerts",
            "Azure Monitor: Workspace data ingestion anomalies",
        ],
    },
    # ── Heading 3: Security Architecture Simulation ─────────────
    "AZ_GRAPH_API_ABUSE": {
        "severity": "CRITICAL",
        "mitre": {"id": "T1098", "tactic": "Credential Access", "technique": "Account Manipulation"},
        "impact": """
Graph API application permissions UserAuthenticationMethod.ReadWrite.All
and RoleManagement.ReadWrite.Directory grant app-level capability to
reset any user's MFA methods or assign administrative roles without
user interaction. Unlike delegated permissions, these app-only
permissions bypass MFA and Conditional Access, operating with the
application's identity.
An attacker exploiting Graph API app permissions may:
- Reset any user's authentication methods (password, MFA)
- Assign Global Admin or other privileged roles to controlled accounts
- Establish application-level persistence outside user accounts
""",
        "remediation": [
            "Audit all service principals with UserAuthenticationMethod.ReadWrite.All or RoleManagement.ReadWrite.Directory",
            "Restrict Graph API app permissions to the minimum required scope",
            "Use Privileged Identity Management (PIM) for app role assignments",
            "Monitor Microsoft Graph activity logs for suspicious API calls",
            "Implement application access policies for high-privilege apps",
        ],
        "detection": [
            "Microsoft Graph API audit logs: Role update and authentication method events",
            "Microsoft 365 Defender: Suspicious Graph API call patterns",
            "Entra ID Audit Log: Application role assignment changes",
        ],
    },
    "AZ_SYNC_ACCOUNT_COMPROMISE": {
        "severity": "CRITICAL",
        "mitre": {"id": "T1098", "tactic": "Persistence", "technique": "Account Manipulation"},
        "impact": """
Compromise of an Entra Connect sync account grants an attacker
the ability to decrypt Password Hash Sync (PHS) hashes, perform
USN rollback to resurrect disabled accounts, and impersonate
on-premises identities in the cloud. These accounts typically
hold Global Administrator privileges and are often not monitored.
An attacker exploiting sync account compromise may:
- Decrypt on-premises password hashes for offline cracking
- Roll back USN values to re-enable disabled accounts
- Create or modify sync rules for persistent cloud access
""",
        "remediation": [
            "Restrict sync accounts to least privilege — remove Global Admin if not required",
            "Enable PIM for sync account role assignments",
            "Monitor Entra Connect Health for unauthorized configuration changes",
            "Use pass-through authentication instead of PHS where feasible",
            "Implement break-glass account procedures for sync account emergencies",
        ],
        "detection": [
            "Entra ID Audit Log: Entra Connect configuration changes",
            "Microsoft 365 Defender: Suspicious sync activity alerts",
            "Identity Protection: Sync account sign-in anomalies",
        ],
    },
    "AZ_PRT_TOKEN_ABUSE": {
        "severity": "HIGH",
        "mitre": {"id": "T1528", "tactic": "Credential Access", "technique": "Steal Application Access Token"},
        "impact": """
A stolen Primary Refresh Token (PRT) provides persistent access
equivalent to the user's full privilege set, bypassing device
compliance checks and location-based Conditional Access controls.
PRTs are long-lived (up to 90 days) and can be replayed across
trusted devices, enabling token theft attacks like token replay.
An attacker with a stolen PRT may:
- Access cloud resources without MFA challenges
- Bypass device compliance and trusted location policies
- Maintain persistent access even after password changes
""",
        "remediation": [
            "Enable token protection (token binding) for PRTs",
            "Implement device compliance policies with BitLocker",
            "Shorten PRT lifetime via Conditional Access session controls",
            "Monitor for anomalous token usage patterns in sign-in logs",
            "Enable Microsoft Defender for Identity token theft detections",
        ],
        "detection": [
            "Entra ID Sign-in logs: Token replay indicators",
            "Microsoft 365 Defender: Anomalous token usage alerts",
            "Identity Protection: Suspicious PRT activity",
        ],
    },
    "AZ_CA_BYPASS": {
        "severity": "HIGH",
        "mitre": {"id": "T1550", "tactic": "Defense Evasion", "technique": "Use Alternate Authentication Material"},
        "impact": """
Conditional Access policies can be bypassed through trusted IP
ranges (attackers operating from corporate network), compliant
device exemptions (compromised but compliant devices), or MFA
fatigue (users approving repeated push notifications). These
bypass paths allow attackers to evade intended security controls.
An attacker exploiting CA bypass paths may:
- Access applications from trusted IPs without MFA
- Use compromised compliant devices for persistent access
- Fatigue users into approving MFA for unauthorized access
""",
        "remediation": [
            "Remove trusted IP exclusions from CA policies where possible",
            "Require MFA for all access regardless of network location",
            "Implement number matching for MFA push notifications",
            "Apply session controls to limit token lifetime for compliant devices",
            "Monitor for MFA fatigue patterns in sign-in logs",
        ],
        "detection": [
            "Entra ID Sign-in logs: MFA approval counts per user",
            "Microsoft 365 Defender: MFA fatigue attack alerts",
            "Identity Protection: Risky sign-in patterns from trusted IPs",
        ],
    },
    "AZ_CROSS_TENANT_AUTH_CHAIN": {
        "severity": "HIGH",
        "mitre": {"id": "T1528", "tactic": "Credential Access", "technique": "Steal Application Access Token"},
        "impact": """
Cross-tenant authentication chains occur when a guest user from
Tenant A holds a privileged role in Tenant B, which in turn has
trust relationships with Tenant C. An attacker compromising the
guest account can traverse all three tenants, escalating access
at each step through inherited trust relationships.
An attacker exploiting cross-tenant auth chains may:
- Move laterally from low-privilege tenant to high-value target
- Escalate through inherited B2B trust relationships
- Maintain access across organizational boundaries
""",
        "remediation": [
            "Audit guest users with privileged directory role assignments",
            "Apply cross-tenant access policies restricting inbound trusts",
            "Restrict guest user permissions using Entitlement Management",
            "Implement automated guest user access reviews",
            "Disable automatic redemption for external users",
        ],
        "detection": [
            "Entra ID Audit Log: Guest user role assignment events",
            "Microsoft 365 Defender: Cross-tenant lateral movement patterns",
            "Identity Protection: Cross-tenant sign-in anomalies",
        ],
    },
    "AZ_DEVICE_JOIN_ABUSE": {
        "severity": "HIGH",
        "mitre": {"id": "T1550", "tactic": "Defense Evasion", "technique": "Use Alternate Authentication Material"},
        "impact": """
Hybrid Azure AD joined devices under attacker control can
authenticate to cloud resources using device credentials. Combined
with WPAD (Web Proxy Auto-Discovery) and AD CS relay techniques,
an attacker can relay device authentication to obtain cloud access
tokens, impersonating the device identity at scale.
An attacker exploiting device join abuse may:
- Authenticate to cloud resources as a trusted device
- Relay device authentication tokens for privilege escalation
- Bypass user-focused Conditional Access policies
""",
        "remediation": [
            "Restrict device registration to authorized users and groups",
            "Disable WPAD in DHCP and DNS configurations",
            "Implement SChannel certificate authentication hardening",
            "Monitor device authentication patterns for anomalies",
            "Enable Microsoft Defender for Identity device alerts",
        ],
        "detection": [
            "Entra ID Sign-in logs: Device authentication from anomalous IPs",
            "Microsoft 365 Defender: Suspicious device registration alerts",
            "Windows Event Logs: Device authentication failures",
        ],
    },
    "AZ_MI_TOKEN_THEFT": {
        "severity": "HIGH",
        "mitre": {"id": "T1528", "tactic": "Credential Access", "technique": "Steal Application Access Token"},
        "impact": """
Managed identity tokens stolen from a compromised compute instance
(Azure VM, Function App, AKS pod) can be used to access downstream
resources including Key Vaults, storage accounts, and databases.
Each MI token exposes the full RBAC scope of the identity, which
often exceeds the requirements of the hosting workload.
An attacker with a stolen MI token may:
- Read secrets from Key Vaults accessible to the identity
- Access storage accounts and databases with MI permissions
- Move laterally to other resources the MI can reach
""",
        "remediation": [
            "Scope managed identity RBAC assignments to the minimum required resources",
            "Use Azure AD Pod Identity / Workload Identity for AKS workloads",
            "Implement network restrictions on token endpoints (IMDS)",
            "Rotate managed identity certificates regularly",
            "Monitor IMDS endpoint access in VM logs",
        ],
        "detection": [
            "Azure VM logs: IMDS endpoint call patterns",
            "Microsoft 365 Defender: Anomalous token usage from identities",
            "Azure Monitor: Managed identity access pattern anomalies",
        ],
    },
    "AZ_FUNCTION_KEY_ABUSE": {
        "severity": "MEDIUM",
        "mitre": {"id": "T1528", "tactic": "Credential Access", "technique": "Steal Application Access Token"},
        "impact": """
Leaked Azure Function or APIM (API Management) keys grant
unauthenticated HTTP access to function endpoints. Combined with
function-level RBAC assignments, an attacker can use the function
identity to access Key Vault, storage, or other downstream
resources without proper authentication.
An attacker exploiting leaked function keys may:
- Access Key Vault secrets via the function's managed identity
- Invoke function endpoints to trigger business logic abuse
- Escalate to downstream resources accessible to the function app
""",
        "remediation": [
            "Use Azure AD authentication for function apps instead of function/API keys",
            "Restrict function app managed identity RBAC to minimal permissions",
            "Enable Key Vault references for function app configuration secrets",
            "Rotate function host keys and application keys regularly",
            "Implement API Management subscription key lifecycle management",
        ],
        "detection": [
            "Function App logs: Authentication method and call patterns",
            "API Management: Subscription key usage anomalies",
            "Key Vault audit: Secret access from compute identities",
        ],
    },
    "AZ_PAG_ESCALATION": {
        "severity": "HIGH",
        "mitre": {"id": "T1078.004", "tactic": "Privilege Escalation", "technique": "Cloud Roles"},
        "impact": """
Privileged Access Groups (PAGs) that include device local
administrators or broad scope groups create lateral movement
paths. Members of these groups inherit the group's permissions
across all joined devices, potentially escalating from standard
user to local administrator on thousands of endpoints.
An attacker exploiting PAG escalation may:
- Gain local administrator access on all joined devices
- Move laterally across endpoints using inherited credentials
- Escalate from standard user to device-level privileged role
""",
        "remediation": [
            "Audit Privileged Access Group memberships for excessive scope",
            "Restrict device local admin groups to specific devices or OUs",
            "Use PIM for privileged access group activation",
            "Implement just-in-time local admin via Microsoft LAPS",
            "Monitor group membership changes for suspicious additions",
        ],
        "detection": [
            "Entra ID Audit Log: Group membership changes for PAGs",
            "Windows Event Logs: Local group membership modifications",
            "Microsoft 365 Defender: Lateral movement path detections",
        ],
    },
}


def enrich_finding(finding, raw):
    category = finding.get("id", "")
    evidence = finding.get("evidence", []) or []

    buckets = _empty_buckets()
    relationship_records = []

    if category in ("TIER0_PATHS", "ENTERPRISE_ADMIN_PATHS"):
        for item in evidence:
            path = item.get("Path", [])
            path_types = item.get("PathTypes", [])
            if isinstance(path, str):
                path = [p.strip() for p in path.split("->") if p.strip()]

            cleaned = []
            path_entities = _empty_buckets()
            for i, raw_name in enumerate(path):
                labels = path_types[i] if i < len(path_types) else None
                bucket, name = _classify(raw_name, labels)
                if not name:
                    continue
                cleaned.append(name)
                if bucket:
                    buckets[bucket].add(name)
                    path_entities[bucket].add(name)

            if len(cleaned) > 1:
                text = " → ".join(cleaned)
                relationship_records.append({"text": text, "entities": path_entities})

        relationship_records = _dedupe_path_records(relationship_records)

    elif category in ("KERBEROAST", "ASREP_ROAST"):
        for item in evidence:
            _, name = _classify(item.get("User"))
            if name:
                buckets["users"].add(name)

    elif category == "DELEGATION":
        for item in evidence:
            _, name = _classify(item.get("Computer"))
            if name:
                buckets["computers"].add(name)

    elif category == "ADMIN_TO":
        for item in evidence:
            user = _clean(item.get("User"))
            comp = _clean(item.get("Computer"))
            if user:
                buckets["users"].add(user)
            if comp:
                buckets["computers"].add(comp)
            if user and comp:
                ent = _empty_buckets()
                ent["users"].add(user)
                ent["computers"].add(comp)
                relationship_records.append({"text": f"{user} -[AdminTo]-> {comp}", "entities": ent})

    elif category == "DACL_ABUSE":
        grouped = {}
        src_bucket_map = {}
        for item in evidence:
            src_bucket, src = _classify(item.get("Source"), item.get("SourceType"))
            tgt_bucket, tgt = _classify(item.get("Target"), item.get("TargetType"))
            perm = item.get("Permission", "")
            if not src or not tgt:
                continue
            if src_bucket:
                buckets[src_bucket].add(src)
            if tgt_bucket:
                buckets[tgt_bucket].add(tgt)
            src_bucket_map[src] = src_bucket
            grouped.setdefault((src, perm), []).append((tgt, tgt_bucket))

        for (src, perm), target_pairs in grouped.items():
            unique_targets = sorted(set(target_pairs))
            target_names = [t for t, _ in unique_targets]
            if len(target_names) <= 3:
                target_str = ", ".join(target_names)
            else:
                target_str = f"{', '.join(target_names[:3])}, +{len(target_names) - 3} more"
            count = len(target_names)
            obj_word = "object" if count == 1 else "objects"
            text = f"{src} -[{perm}]-> {target_str} ({count} {obj_word})"

            ent = _empty_buckets()
            sb = src_bucket_map.get(src)
            if sb:
                ent[sb].add(src)
            for t, tb in unique_targets:
                if tb:
                    ent[tb].add(t)

            relationship_records.append({"text": text, "entities": ent})

    elif category == "GPO_CONTROL":
        for item in evidence:
            p_bucket, principal = _classify(item.get("Principal"), item.get("PrincipalType"))
            gpo = _clean(item.get("GPO"))
            perm = item.get("Permission", "")
            if gpo:
                buckets["gpos"].add(gpo)
            if principal and p_bucket:
                buckets[p_bucket].add(principal)
            if gpo and principal:
                ent = _empty_buckets()
                ent["gpos"].add(gpo)
                if p_bucket:
                    ent[p_bucket].add(principal)
                relationship_records.append({"text": f"{principal} -[{perm}]-> {gpo} (GPO Control)", "entities": ent})

    elif category == "SID_HISTORY":
        for item in evidence:
            _, name = _classify(item.get("User"))
            sid_raw = item.get("SidHistory")
            sid = str(sid_raw).strip() if sid_raw else None
            if name:
                buckets["users"].add(name)
            if name and sid and sid.upper() != "NONE":
                ent = _empty_buckets()
                ent["users"].add(name)
                relationship_records.append({"text": f"{name} has SID History: {sid}", "entities": ent})

    elif category == "DCSYNC":
        for item in evidence:
            bucket, name = _classify(item.get("Principal"), item.get("PrincipalType"))
            perm = item.get("Permission", "")
            if name:
                # Domain-typed principals fall back to groups (not computers)
                if bucket:
                    buckets[bucket].add(name)
                elif "Domain" in (item.get("PrincipalType") or []):
                    buckets["groups"].add(name)
                else:
                    buckets["users"].add(name)
            if name and perm:
                ent = _empty_buckets()
                if bucket:
                    ent[bucket].add(name)
                elif "Domain" in (item.get("PrincipalType") or []):
                    ent["groups"].add(name)
                else:
                    ent["users"].add(name)
                relationship_records.append({"text": f"{name} has {perm} rights (DCSync)", "entities": ent})

    elif category == "CONSTRAINED_DELEGATION":
        for item in evidence:
            _, name = _classify(item.get("Computer"))
            delegates = item.get("AllowedDelegates", "")
            if name:
                buckets["computers"].add(name)
            if name and delegates:
                ent = _empty_buckets()
                ent["computers"].add(name)
                rel_text = f"{name} can delegate to: {delegates}"
                if len(rel_text) > 200:
                    rel_text = rel_text[:200] + "..."
                relationship_records.append({"text": rel_text, "entities": ent})

    elif category == "RBCD":
        for item in evidence:
            p_bucket, principal = _classify(item.get("Principal"), item.get("PrincipalType"))
            _, computer = _classify(item.get("Computer"))
            perm = item.get("Permission", "")
            if principal:
                if p_bucket:
                    buckets[p_bucket].add(principal)
                else:
                    buckets["users"].add(principal)
            if computer:
                buckets["computers"].add(computer)
            if principal and computer:
                ent = _empty_buckets()
                if p_bucket:
                    ent[p_bucket].add(principal)
                ent["computers"].add(computer)
                relationship_records.append({"text": f"{principal} -[{perm}]-> {computer} (RBCD)", "entities": ent})

    elif category in ("PASSWORD_NOT_REQUIRED", "REVERSIBLE_ENCRYPTION"):
        label = "passwordnotreq" if category == "PASSWORD_NOT_REQUIRED" else "reversible encryption"
        for item in evidence:
            _, name = _classify(item.get("User"))
            if name:
                buckets["users"].add(name)
                ent = _empty_buckets()
                ent["users"].add(name)
                relationship_records.append({"text": f"{name} has {label} flag set", "entities": ent})

    elif category == "ACCOUNT_OPERATORS":
        for item in evidence:
            _, user = _classify(item.get("User"))
            _, group = _classify(item.get("Group"))
            if user:
                buckets["users"].add(user)
            if group:
                buckets["groups"].add(group)
            if user and group:
                ent = _empty_buckets()
                ent["users"].add(user)
                ent["groups"].add(group)
                relationship_records.append({"text": f"{user} is member of {group}", "entities": ent})

    elif category in ("PRIVILEGED_GROUPS", "DISABLED_PRIVILEGED"):
        for item in evidence:
            _, user = _classify(item.get("User"))
            _, group = _classify(item.get("Group"))
            if user:
                buckets["users"].add(user)
            if group:
                buckets["groups"].add(group)
            if user and group:
                ent = _empty_buckets()
                ent["users"].add(user)
                ent["groups"].add(group)
                rel = f"{user} is member of {group}"
                if category == "DISABLED_PRIVILEGED":
                    rel += " [DISABLED]"
                relationship_records.append({"text": rel, "entities": ent})

    elif category == "CROSS_FOREST":
        for item in evidence:
            src = _clean(item.get("SourceDomain"))
            tgt = _clean(item.get("TargetDomain"))
            trust = item.get("TrustTypes", "trusted")
            if isinstance(trust, list):
                trust_str = ", ".join(trust)
            else:
                trust_str = str(trust) if trust else "trusted"
            transitive = item.get("IsTransitive", "")
            if transitive:
                trust_str += f" (Transitive: {transitive})"
            sid_filtering = item.get("SIDFiltering", "")
            direction = item.get("TrustDirection", "")
            if direction:
                trust_str += f" [{direction}]"
            if sid_filtering:
                trust_str += f" | SIDFilter: {sid_filtering}"
            if src:
                buckets["domains"].add(src)
            if tgt:
                buckets["domains"].add(tgt)
            if src and tgt:
                ent = _empty_buckets()
                ent["domains"].add(src)
                ent["domains"].add(tgt)
                relationship_records.append({"text": f"{src} -[{trust_str}]-> {tgt}", "entities": ent})

    # ── Heading 1: Identity Attack Path Assessment ──────────────
    elif category in ("CERT_ABUSE_ESC1", "CERT_ABUSE_ESC3", "SHADOW_CREDENTIALS",
                       "DANGEROUS_COMPUTER_ACLS", "NTLM_RELAY_PATHS",
                       "LAPS_GAPS", "SQL_LINKED_SERVERS", "DOMAIN_TRUST_ESCALATION"):

        for item in evidence:
            src = _clean(item.get("Principal") or item.get("Source") or item.get("SourcePrincipal") or item.get("SourceDomain"))
            tgt = _clean(item.get("CertTemplate") or item.get("Target") or item.get("Computer") or item.get("RelayTarget") or item.get("SQLServer") or item.get("TargetDomain"))
            perm = item.get("Permission", "")
            if src:
                buckets["users"].add(src)
            if tgt:
                if category in ("DOMAIN_TRUST_ESCALATION",):
                    buckets["domains"].add(tgt)
                elif category in ("CERT_ABUSE_ESC1", "CERT_ABUSE_ESC3"):
                    buckets["organizational_units"].add(tgt)
                else:
                    buckets["computers"].add(tgt)
            if src and tgt:
                ent = _empty_buckets()
                ent["users"].add(src)
                if category in ("DOMAIN_TRUST_ESCALATION",):
                    ent["domains"].add(tgt)
                else:
                    ent["computers"].add(tgt)
                label = category.lower().replace("_", " ")
                rel = f"{src} -[{perm or label}]-> {tgt}"
                if category == "DOMAIN_TRUST_ESCALATION":
                    direction = item.get("Direction", "")
                    sid_filter = item.get("SIDFiltering", "")
                    if direction:
                        rel += f" [{direction}]"
                    if sid_filter is not None:
                        rel += f" SIDFilter={sid_filter}"
                relationship_records.append({"text": rel, "entities": ent})

    # ── Azure / Entra ID Evidence Processing ────────────────────
    elif category.startswith("AZ_"):
        _process_azure_evidence(category, evidence, buckets, relationship_records)

    finding["ad_objects"] = _buckets_to_lists(buckets)
    finding["ad_objects"]["relationships"] = [r["text"] for r in relationship_records]
    finding["relationship_records"] = [
        {"text": r["text"], "entities": _buckets_to_lists(r["entities"])} for r in relationship_records
    ]
    if category.startswith("AZ_"):
        finding["azure_objects"] = finding["ad_objects"]

    meta = METADATA.get(category)
    if meta:
        finding["severity"] = meta["severity"]
        finding["mitre"] = meta["mitre"]
        finding["impact"] = meta["impact"]
        finding["remediation"] = meta["remediation"]
        finding["detection"] = meta["detection"]
    else:
        finding.setdefault("mitre", {})
        finding.setdefault("impact", "No enrichment data available for this finding type.")

    finding["compliance"] = COMPLIANCE_MAP.get(category, {})
    finding["exclusions"] = EXCLUSIONS_MAP.get(category, [])
    finding["source"] = finding.get("source", "Active Directory")

    # Truncation note: flag if evidence count hits query-level LIMIT thresholds
    ev_count = len(evidence)
    if ev_count >= 10000:
        finding["truncated"] = True
        note = (
            "\n\nNote: Over 10,000 instances found — showing top results. "
            "Actual count may be higher. Remediation should address all affected objects."
        )
        if note not in finding.get("impact", ""):
            finding["impact"] = (finding.get("impact", "") + note)
    elif ev_count >= 5000:
        finding["truncated"] = True
        note = (
            "\n\nNote: Over 5,000 instances found — showing top results. "
            "Actual count may be higher. Address critical items first."
        )
        if note not in finding.get("impact", ""):
            finding["impact"] = (finding.get("impact", "") + note)
    else:
        finding["truncated"] = False

    # Confidence label (Mandiant methodology: Confirmed vs Informational)
    if not finding.get("has_evidence", False):
        finding["confidence"] = "No Data"
    elif category in ("PRIVILEGED_GROUPS", "DISABLED_PRIVILEGED"):
        finding["confidence"] = "Informational"
    else:
        finding["confidence"] = "Confirmed"
    return finding
