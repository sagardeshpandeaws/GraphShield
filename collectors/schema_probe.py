import logging

logger = logging.getLogger(__name__)

# Labels to check per group, derived from actual typed MATCH patterns in each group's queries
# Only labels that appear in at least one query for that group are listed.
GROUP_LABELS = {
    "ad_core": {"User", "Computer", "Group", "Domain", "GPO"},
    "ad_attack": {"CertTemplate", "Computer", "Domain"},
    "az_core": {
        "AZTenant", "AZUser", "AZGroup", "AZApplication",
        "AZKeyVault", "AZManagedIdentity", "AZVM", "AZWebApp",
        "AZRoleDefinition",
    },
    "az_zt_review": {
        "AZTenant", "AZUser", "AZConditionalAccessPolicy",
        "AZRoleDefinition", "AZServicePrincipal",
    },
    "az_arch_sim": {
        "AZUser", "AZRoleDefinition", "AZServicePrincipal",
        "AZConditionalAccessPolicy", "AZDevice", "AZManagedIdentity",
        "AZWebApp", "AZKeyVault", "AZGroup",
    },
}

# Properties to verify on specific labels (only checked when label is in active group's set)
CHECK_PROPERTIES = {
    "User": ["displayname", "hasspn"],
    "Computer": ["operatingsystem", "haslaps"],
    "AZUser": ["mfaenabled", "lastsignin", "userprincipalname"],
    "AZConditionalAccessPolicy": ["state", "locations", "grantcontrols"],
    "AZRoleDefinition": ["displayname", "isbuiltin"],
    "AZTenant": ["passwordprotection", "authenticationmethods"],
    "AZWebApp": None,
    "AZKeyVault": None,
    "AZDevice": None,
}


class ProbeResult:
    def __init__(self):
        self.labels = set()
        self.labels_props = {}  # label -> set(property_name)
        self.list_props = set()  # (label, property_name) that are lists
        self.warnings = []
        self.errors = []


def _probe_label_props(session, label):
    try:
        q = f"MATCH (n:`{label}`) RETURN keys(n) AS k LIMIT 1"
        row = list(session.run(q))
        if row and row[0]["k"]:
            return set(row[0]["k"])
        return set()
    except Exception:
        return set()


def _is_list_property(session, label, prop):
    try:
        q = f"MATCH (n:`{label}`) WHERE n.`{prop}` IS NOT NULL RETURN n.`{prop}` AS v LIMIT 1"
        rows = list(session.run(q))
        if rows:
            return isinstance(rows[0]["v"], (list, tuple))
        return False
    except Exception:
        return False


def probe(driver, selected_groups=None) -> ProbeResult:
    result = ProbeResult()
    if selected_groups:
        expected_labels = set()
        for g in selected_groups:
            expected_labels.update(GROUP_LABELS.get(g, set()))
    else:
        expected_labels = set().union(*GROUP_LABELS.values())
    try:
        with driver.session() as session:
            try:
                rows = list(session.run("CALL db.labels()"))
                result.labels = {r["label"] for r in rows}
            except Exception as e:
                result.errors.append(f"db.labels() failed: {e}")

            for label in sorted(expected_labels):
                if label not in result.labels:
                    result.warnings.append(f"Label '{label}' not found in database")
                else:
                    props = _probe_label_props(session, label)
                    result.labels_props[label] = props
                    check = CHECK_PROPERTIES.get(label)
                    if check is None:
                        continue
                    for prop in check:
                        if prop not in props:
                            result.warnings.append(
                                f"Property '{prop}' missing on '{label}' nodes"
                            )

            for label, props in result.labels_props.items():
                for prop in props:
                    if _is_list_property(session, label, prop):
                        result.list_props.add((label, prop))

    except Exception as e:
        result.errors.append(f"Schema probe failed: {e}")

    for w in result.warnings:
        logger.warning("Schema: %s", w)
    for e in result.errors:
        logger.error("Schema: %s", e)

    logger.info(
        "Schema probe: %d labels, %d warnings, %d errors",
        len(result.labels), len(result.warnings), len(result.errors),
    )
    return result
