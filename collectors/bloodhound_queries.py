QUERIES = {
    # Tier-0 groups matched by well-known RID suffix (Microsoft methodology)
    # RIDs: 512=Domain Admins, 519=Enterprise Admins, 544=Built-in Administrators,
    #       518=Schema Admins, 526=Key Admins, 527=Enterprise Key Admins
    "tier0_paths": """
        MATCH (g:Group)
        WHERE g.objectid ENDS WITH '-512'
           OR g.objectid ENDS WITH '-544'
           OR g.objectid ENDS WITH '-518'
           OR g.objectid ENDS WITH '-526'
           OR g.objectid ENDS WITH '-527'
        MATCH p = shortestPath(
          (n)-[:MemberOf|AdminTo|GenericAll|GenericWrite|WriteOwner|WriteDacl|AllExtendedRights*1..8]->(g)
        )
        WHERE n <> g
          AND NOT n.name = g.name
          AND NOT COALESCE(n.isgroup, false) = true
          AND NOT 'Group' IN labels(n)
          AND TOINTEGER(LAST(SPLIT(n.objectid, '-'))) >= 1000
        RETURN
          [x IN nodes(p) | x.name] AS Path,
          [x IN nodes(p) | LABELS(x)] AS PathTypes,
          length(p) AS Distance
        LIMIT 15000
    """,

    # Enterprise Admin paths (RID -519) — forest-wide scope
    "enterprise_admin_paths": """
        MATCH p = shortestPath(
          (n)-[:MemberOf|AdminTo|GenericAll|GenericWrite|WriteOwner|WriteDacl|AllExtendedRights*1..8]->(g:Group)
        )
        WHERE n <> g
          AND g.objectid ENDS WITH '-519'
          AND NOT n.objectid ENDS WITH '-500'
          AND NOT n.name STARTS WITH 'ADMINISTRATOR@'
          AND NOT COALESCE(n.isgroup, false) = true
          AND NOT 'Group' IN labels(n)
          AND TOINTEGER(LAST(SPLIT(n.objectid, '-'))) >= 1000
        RETURN
          [x IN nodes(p) | x.name] AS Path,
          [x IN nodes(p) | LABELS(x)] AS PathTypes,
          length(p) AS Distance
        LIMIT 15000
    """,

    "kerberoast": """
        MATCH (u:User)
        WHERE COALESCE(u.hasspn, false) = true
          AND u.enabled = true
          AND NOT u.objectid ENDS WITH '-502'
        RETURN u.name AS User
        LIMIT 15000
    """,

    "asrep_roast": """
        MATCH (u:User)
        WHERE u.dontreqpreauth = true
        RETURN u.name AS User
        LIMIT 15000
    """,

    "delegation": """
        MATCH (c:Computer)
        WHERE c.unconstraineddelegation = true
        RETURN c.name AS Computer
        LIMIT 15000
    """,

    "admin_to": """
        MATCH (u:User)-[:AdminTo]->(c:Computer)
        RETURN u.name AS User, c.name AS Computer
        LIMIT 15000
    """,

    "dacl_abuse": """
    MATCH (a)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|AllExtendedRights]->(b)
    WHERE NOT a.name STARTS WITH 'ADMINISTRATORS@'
      AND NOT a.name STARTS WITH 'DOMAIN ADMINS@'
      AND NOT a.name STARTS WITH 'ENTERPRISE ADMINS@'
      AND NOT a.name STARTS WITH 'SYSTEM@'
      AND NOT a.objectid ENDS WITH '-512'
      AND NOT a.objectid ENDS WITH '-519'
      AND NOT a.objectid ENDS WITH '-544'
    RETURN
      a.name AS Source,
      LABELS(a) AS SourceType,
      type(r) AS Permission,
      b.name AS Target,
      LABELS(b) AS TargetType
    LIMIT 15000
    """,

    "gpo_control": """
        MATCH (g:GPO)<-[r]-(a)
        WHERE type(r) IN ['GenericAll','GenericWrite','WriteDacl','WriteOwner']
        RETURN
          a.name AS Principal,
          LABELS(a) AS PrincipalType,
          type(r) AS Permission,
          g.name AS GPO
        LIMIT 15000
    """,

    "sid_history": """
        MATCH (u:User)
        WHERE u.sidhistory IS NOT NULL
        RETURN u.name AS User, u.sidhistory AS SidHistory
        LIMIT 15000
    """,

    "dcsync": """
        MATCH (n)-[r:GetChanges|GetChangesAll]->(:Domain)
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType, type(r) AS Permission
        LIMIT 15000
    """,

    "constrained_delegation": """
        MATCH (c:Computer)
        WHERE c.allowedtodelegate IS NOT NULL
        RETURN c.name AS Computer, c.allowedtodelegate AS AllowedDelegates
        LIMIT 15000
    """,

    "rbcd": """
        MATCH (c:Computer)<-[r:WriteOwner|WriteDacl|GenericAll|GenericWrite|AllExtendedRights]-(n)
        RETURN n.name AS Principal, LABELS(n) AS PrincipalType, c.name AS Computer, type(r) AS Permission
        LIMIT 15000
    """,

    "password_not_required": """
        MATCH (u:User)
        WHERE u.passwordnotreq = true AND u.enabled = true
        RETURN u.name AS User
        LIMIT 15000
    """,

    "reversible_encryption": """
        MATCH (u:User)
        WHERE u.reversibleencryption = true AND u.enabled = true
        RETURN u.name AS User
        LIMIT 15000
    """,

    "account_operators": """
        MATCH (u:User)-[:MemberOf]->(g:Group)
        WHERE u.enabled = true
          AND (g.name CONTAINS 'ACCOUNT OPERATORS'
            OR g.name CONTAINS 'BACKUP OPERATORS'
            OR g.name CONTAINS 'PRINT OPERATORS'
            OR g.name CONTAINS 'SERVER OPERATORS')
        RETURN u.name AS User, g.name AS Group
        LIMIT 15000
    """,

    # Non-Tier-0 admin groups (name contains ADMIN but not a well-known privileged group)
    # MEDIUM severity — clients may argue these are intentionally delegated
    "privileged_groups": """
        MATCH (g:Group)
        WHERE g.name CONTAINS 'ADMINISTRATORS'
          AND NOT g.objectid ENDS WITH '-544'
          AND NOT g.objectid ENDS WITH '-512'
          AND NOT g.objectid ENDS WITH '-519'
          AND NOT g.objectid ENDS WITH '-518'
        MATCH (u:User)-[:MemberOf]->(g)
        WHERE u.enabled = true
        RETURN u.name AS User, g.name AS Group
        LIMIT 15000
    """,

    # Disabled users in privileged groups (separate from active findings)
    "disabled_privileged": """
        MATCH (u:User)-[:MemberOf]->(g:Group)
        WHERE u.enabled = false
          AND (g.objectid ENDS WITH '-512'
            OR g.objectid ENDS WITH '-519'
            OR g.objectid ENDS WITH '-544'
            OR g.objectid ENDS WITH '-518'
            OR g.objectid ENDS WITH '-526'
            OR g.objectid ENDS WITH '-527'
            OR g.name CONTAINS 'ACCOUNT OPERATORS'
            OR g.name CONTAINS 'BACKUP OPERATORS'
            OR g.name CONTAINS 'PRINT OPERATORS'
            OR g.name CONTAINS 'SERVER OPERATORS')
        RETURN u.name AS User, g.name AS Group
        LIMIT 15000
    """,

    "cross_forest": """
        MATCH (d:Domain)-[r:CrossForestTrust]->(t:Domain)
        WHERE NOT t.name ENDS WITH d.name
        RETURN d.name AS SourceDomain, t.name AS TargetDomain,
               r.trusttype AS TrustTypes,
               r.transitive AS IsTransitive,
               r.tgtdelegation AS TGTDelegation,
               r.sidfiltering AS SIDFiltering,
               r.trustdirection AS TrustDirection
        LIMIT 15000
    """,

    # ── Heading 1: Identity Attack Path Assessment ──────────────

    # AD-CS ESC1: Enrollee supplies subject + client auth + write rights on template
    "cert_abuse_esc1": """
        MATCH (ct:CertTemplate)
        WHERE ct.enrolleesuppliessubject = true
          AND (ct.requiresclientauth = true
               OR ct.ekus IS NULL OR ct.ekus = ''
               OR ct.ekus CONTAINS '2.5.29.37.0'
               OR ct.ekus CONTAINS '1.3.6.1.4.1.311.21.8')
        MATCH (n)-[:Enroll]->(ct)
        MATCH (n)-[:GenericAll|GenericWrite|WriteOwner|WriteDacl]->(ct)
        WHERE NOT 'Group' IN labels(n)
        RETURN DISTINCT n.name AS Principal, ct.name AS CertTemplate
        LIMIT 15000
    """,

    # AD-CS ESC3: Certificate agent enrollment abuse
    "cert_abuse_esc3": """
        MATCH (n)-[:Enroll]->(ct1:CertTemplate)
        WHERE ct1.enrolleesuppliessubject = false
          AND ct1.requiresclientauth = true
        MATCH (n)-[:Enroll]->(ct2:CertTemplate)
        WHERE ct2.enrolleesuppliessubject = true
          AND ct2.requiresclientauth = false
          AND ct2.ismanagerapprovalrequired = false
          AND NOT 'Group' IN labels(n)
        RETURN DISTINCT n.name AS SourcePrincipal,
                        ct1.name AS Esc1AgentTemplate,
                        ct2.name AS Esc1SubjectTemplate
        LIMIT 15000
    """,

    # Shadow Credentials: AddKeyCredentialLink abuse
    "shadow_credentials": """
        MATCH (n)-[r:AddKeyCredentialLink]->(m)
        WHERE NOT 'Group' IN labels(n)
        RETURN n.name AS Source, m.name AS Target
        LIMIT 15000
    """,

    # Dangerous Computer ACLs
    "dangerous_object_acls": """
        MATCH (n)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner]->(c)
        WHERE ANY(lbl IN LABELS(c) WHERE lbl IN ['User', 'Group', 'OU'])
          AND NOT 'Group' IN labels(n)
          AND NOT n.objectid ENDS WITH '-512'
          AND NOT n.objectid ENDS WITH '-519'
          AND NOT n.objectid ENDS WITH '-544'
        RETURN n.name AS Principal, c.name AS TargetObject,
               type(r) AS Permission, labels(c) AS TargetType
        LIMIT 15000
    """,

    # NTLM relay: all computers with AdminTo on a DC (any service)
    "ntlm_relay_paths": """
        MATCH (c:Computer)-[:AdminTo]->(dc:Computer)-[:DCFor]->(:Domain)
        RETURN c.name AS RelayTarget, dc.name AS DomainController
        LIMIT 15000
    """,

    # LAPS deployment gaps
    "laps_gaps": """
        MATCH (c:Computer)
        WHERE (c.haslaps = false OR c.haslaps IS NULL)
          AND NOT COALESCE(c.operatingsystem, '') CONTAINS '2003'
        RETURN c.name AS Computer, c.operatingsystem AS OS
        LIMIT 15000
    """,

    # MS-SQL linked server abuse
    "sql_linked_servers": """
        MATCH (n)-[:SQLAdmin]->(s:Computer)
        WHERE NOT 'Group' IN labels(n)
        RETURN n.name AS Principal, s.name AS SQLServer
        LIMIT 15000
    """,

    # Intra-forest trust escalation (SID filtering disabled / TGT delegation)
    "domain_trust_escalation": """
        MATCH (d:Domain)-[r:TrustedBy]->(t:Domain)
        WHERE NOT d.name = t.name
          AND (r.sidfiltering = false OR r.tgtdelegation = true)
        RETURN d.name AS SourceDomain, t.name AS TargetDomain,
               r.trustdirection AS Direction,
               r.transitive AS Transitive,
               r.sidfiltering AS SIDFiltering,
               r.tgtdelegation AS TGTDelegation
        LIMIT 15000
    """,
}
