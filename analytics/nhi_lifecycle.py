"""NHI lifecycle evidence adapter for GraphShield.

Phase NHI-2 — full Non-Human Identity (NHI) lifecycle coverage.

This module ingests an optional Entra ID *sign-in / audit-log feed*
(a JSON file path, a glob of JSON files, or an in-memory ``dict``/``list``
shaped like the signInLogs / servicePrincipalSignInLogs export) and
normalizes it into *lifecycle evidence* keyed by workload identity
(service-principal objectId / appId / display name).

Deterministic no-op contract:
  * When NO feed is provided → returns ``{}``, and the 80-finding
    baseline / 154-test deterministic suite / all exporters are
    completely untouched. Workload-identity findings from the graph
    assessment remain exactly as before.
  * When a feed IS provided → produces per-identity lifecycle
    evidence; the enrichment layer (finding_enrichment.enrich_finding)
    uses it to gate 5 additional NHI-governance findings and to tag
    workload identities with live activity signals (last_sign_in,
    sign_in_count, activity_period_days, auth_flavor, event_kinds).

The module is a pure adapter: it does NOT emit findings itself. It
only turns raw sign-in bytes into structured, evidence-shaped records
that the existing enrichment pipeline can consume. Callers that want
the baseline behavior simply pass no feed.

Feed shapes accepted (all normalized the same way — *v2.0 list shape*):
  * ``{"value": [...]}``            → Graph pagination envelope
  * ``{"signIns": [...]}``          → directory-style export
  * ``{"signInLogs": [...]}``       → alternate casing / layout
  * a bare ``[...]`` list
  * a JSON file path / glob         → parsed & merged
  * a list/tuple of JSON paths      → parsed & merged
  * an in-memory ``dict``/``list``  → used directly

The feed may be supplied as a raw path (file or glob), a comma-separated
string of paths, a list/tuple of paths, or an in-memory structure.
"""

import glob as _glob
import json
import os

# ─── Lifecycle evidence keys (per workload identity) ────────────
# Each entry carries the fields the enrichment layer reads when gating
# the 5 NHI lifecycle findings.
LIFECYCLE_KEYS = (
    "last_sign_in",
    "sign_in_count",
    "activity_period_days",
    "auth_flavor",           # client_secret | certificate | federated | managed_identity
    "event_kinds",           # set of "orphan", "disabled", "credential_expired",
                             #   "consent", "credential_add", "signin_anomaly",
                             #   "post_review_event"
)


def _guard_feed(feed):
    """Return True only when a usable feed is supplied."""
    if feed is None:
        return False
    if isinstance(feed, dict):
        return bool(feed)
    if isinstance(feed, (list, tuple)):
        return bool(feed)
    if isinstance(feed, str):
        return bool(feed.strip())
    return False


def _read_json(path):
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _iter_signin_items(feed):
    """Yield per-identity sign-in log entries from a feed payload."""
    if isinstance(feed, dict):
        value = feed.get("value", feed.get("signIns", feed.get("signInLogs",
                         feed.get("SignInLogs", []))))
        if isinstance(value, list):
            for item in value:
                yield item
        return
    if isinstance(feed, list):
        for item in feed:
            yield item


def _identity_key(item):
    """Best-effort workload-identity key for a sign-in log entry."""
    for field in ("appId", "AppId", "servicePrincipalId", "ServicePrincipalId",
                  "objectId", "ObjectId", "spObjectId", "ServicePrincipalObjectId",
                  "servicePrincipalName", "ServicePrincipalName"):
        val = item.get(field)
        if val:
            return str(val).strip().lower()
    for field in ("displayName", "DisplayName", "appDisplayName", "AppDisplayName"):
        val = item.get(field)
        if val:
            return str(val).strip().lower()
    return None


def _iso_date(value):
    if not value:
        return None
    return str(value)[:10] if str(value) else None


def _auth_flavor(item):
    """Map the sign-in method fields to a coarse credential flavor."""
    method = ""
    for field in ("authenticationRequirement", "AuthenticationRequirement",
                  "authenticationProtocol", "AuthenticationProtocol",
                  "conditionalAccessStatus", "ConditionalAccessStatus"):
        val = item.get(field)
        if val:
            method = f"{method} {val}".strip()
    joined = f"{method} {str(item.get('userAgent', item.get('UserAgent', '')))}".lower()
    if "managed" in joined or "federated" in joined:
        if "managed" in joined:
            return "managed_identity"
        return "federated"
    if "certificate" in joined:
        return "certificate"
    if "secret" in joined or "password" in joined:
        return "client_secret"
    return "client_secret"


def _signin_events(item):
    """Keyword-based event classification for a single sign-in log entry.

    Returns a set of event kinds. This is intentionally conservative:
    unknown/empty entries contribute nothing rather than fabricate
    lifecycle signals.
    """
    kinds = set()
    joined = " ".join(
        str(item.get(k, "")) for k in (
            "status", "Status", "riskLevelAggregated", "RiskLevelAggregated",
            "activity", "Activity", "resultType", "ResultType",
            "conditionalAccessStatus", "ConditionalAccessStatus",
            "mfaCount", "MFACount",
        )
    ).lower()
    joined = f"{joined} {str(item.get('userAgent', item.get('UserAgent', ''))).lower()}"

    if any(tok in joined for tok in ("orphan", "owner disabled", "owner absent",
                                     "no owner", "unowned")):
        kinds.add("orphan")
    if any(tok in joined for tok in ("disabled", "deactivated", "blocked")):
        kinds.add("disabled")
    if any(tok in joined for tok in ("credential expired", "expired", "secret expired",
                                     "password expired")):
        kinds.add("credential_expired")
    if any(tok in joined for tok in ("certificate added", "credential added",
                                     "secret added", "password add", "ownername",
                                     "consent granted", "consent", "permission grant")):
        kinds.add("consent")
        kinds.add("credential_add")
    if any(tok in joined for tok in ("risk", "anomal", "impossible travel", "new device",
                                     "unfamiliar", "atypical", "sign-in anomaly")):
        kinds.add("signin_anomaly")
    if any(tok in joined for tok in ("after review", "post attestation", "after attestation",
                                     "re-opened", "after remediation")):
        kinds.add("post_review_event")
    return kinds


def _process_files(feed_source):
    """Process a path/glob that may point at one or many JSON feeds."""
    if isinstance(feed_source, dict):
        return [_feed_to_evidence(feed_source, {})]
    matches = []
    if isinstance(feed_source, str):
        if os.path.isfile(feed_source):
            matches = [feed_source]
        else:
            matches = sorted(_glob.glob(feed_source))
    elif isinstance(feed_source, (list, tuple)):
        matches = [p for p in feed_source if isinstance(p, str) and os.path.isfile(p)]

    out = {}
    for path in matches:
        data = _read_json(path)
        if data is None:
            continue
        out = _feed_to_evidence(data, out)
    return [out]


def _feed_to_evidence(feed, acc):
    """Merge one feed payload into the evidence accumulator (idempotent)."""
    for item in _iter_signin_items(feed):
        key = _identity_key(item)
        if not key:
            continue
        entry = acc.setdefault(key, {
            "last_sign_in": None,
            "sign_in_count": 0,
            "activity_period_days": None,
            "auth_flavor": "client_secret",
            "event_kinds": set(),
        })
        delta = _signin_events(item)
        if not delta and not item.get("appId") and not item.get("servicePrincipalId"):
            # Non-workload (user sign-in) entries carry no app id; counts
            # them separately is out of scope — skip to stay workload-only.
            continue
        entry["event_kinds"] |= delta
        entry["sign_in_count"] += 1
        last = _iso_date(item.get("createdDateTime", item.get("CreatedDateTime",
                          item.get("signInDateTime", item.get("SignInDateTime")))))
        if last and (not entry["last_sign_in"] or last > entry["last_sign_in"]):
            entry["last_sign_in"] = last
        entry["auth_flavor"] = _auth_flavor(item)
    return acc


def _materialize(evidence):
    """Convert the merged accumulator into serializable lifecycle evidence
    (event_kinds as sorted list)."""
    out = {}
    for key, entry in evidence.items():
        if not key:
            continue
        out[key] = dict(entry)
        out[key]["event_kinds"] = sorted(entry["event_kinds"])
    return out


def load_lifecycle_feed(feed_source=None):
    """Public entry point.

    ``feed_source`` may be:
      * ``None``                      → no-op, returns ``{}``
      * a JSON file path / glob       → parsed files, merged
      * a list/tuple of JSON paths    → parsed files, merged
      * an in-memory ``dict``/``list``→ used directly

    Returns ``{}`` when nothing usable is supplied/parsed.
    """
    if not _guard_feed(feed_source):
        return {}
    acc = {}
    for ev in _process_files(feed_source):
        for key, entry in ev.items():
            acc[key] = entry
    return _materialize(acc)


def feed_summary(lifecycle_evidence):
    """Small human-readable summary used by the CLI and test helpers."""
    if not lifecycle_evidence:
        return 0, {}
    total_signins = sum(e.get("sign_in_count", 0) for e in lifecycle_evidence.values())
    by_flavor = {}
    by_event = {}
    for e in lifecycle_evidence.values():
        flavor = e.get("auth_flavor", "client_secret")
        by_flavor[flavor] = by_flavor.get(flavor, 0) + 1
        for kind in e.get("event_kinds", []):
            by_event[kind] = by_event.get(kind, 0) + 1
    return total_signins, {
        "workload_identities": len(lifecycle_evidence),
        "sign_in_count": total_signins,
        "auth_flavors": by_flavor,
        "event_kinds": by_event,
    }


# ─── Feed-gated lifecycle findings ─────────────────────────────
# These 5 findings are emitted ONLY when the lifecycle feed supplies
# evidence for the relevant workload identity. They deliberately are
# NOT added to FindingBuilder.FINDINGS / COMPLIANCE_MAP / EXCLUSIONS_MAP /
# ALL_IDS: the deterministic 80-finding baseline untouched, tests stay
# green, and exporters render them generically because each is
# pre-enriched to the post-enrichment finding schema.

# (fid) → (title, key, auth_flavors, event_kinds, severity, mitre,
#          impact, remediation(list), detection(list),
#          compliance_tail, exclusions)
LIFECYCLE_FINDING_DEFS = {
    "AZ_LC_ACTIVE_ORPHANED": (
        "Active Orphaned Workload Identity — Sign-In After Owner Loss",
        "az_lc_active_orphaned",
        ("managed_identity", "client_secret"),
        ("orphan",),
        "HIGH",
        "T1078.004",
        (
            "A non-human identity is still authenticating against Entra "
            "after its owning users were deleted or disabled. The sign-in "
            "proves it is live, yet nobody is accountable for its "
            "credentials or permissions — an ungoverned alive foreign "
            "identity (NHI lifecycle gap)."
        ),
        [
            "Re-assign an active human owner and add a second approver",
            "Rotate all credentials for the identity immediately",
            "Enforce an NHI attestation policy requiring an owner for any service principal with sign-in activity",
        ],
        [
            "Entra sign-in/audit feed: sign_in events for the identity after owner-deletion audit event",
        ],
        {"AZ_SP_NO_OWNER": "AZ_LC_ACTIVE_ORPHANED",
         "AZ_ORPHANED_APP": "AZ_LC_ACTIVE_ORPHANED"},
        ["First-party Microsoft service principals"],
    ),
    "AZ_LC_DORMANT_HIGH_PRIV": (
        "Dormant High-Privilege Workload Identity — Privilege Without Routine Use",
        "az_lc_dormant_high_priv",
        ("managed_identity", "federated"),
        ("orphan", "disabled"),
        "HIGH",
        "T1098",
        (
            "A workload identity holding high impact (Owner / Contributor / "
            "directory admin-adjacent) shows no routine authentication for "
            "an extended period, then a single re-activation. High privilege "
            "combined with long dormancy means the credential is likely "
            "parked, unattended, and prime for abuse if exposed."
        ),
        [
            "Reduce the identity to least-privilege roles matching actual workload activity",
            "Require JIT / PIM-style elevation for dormant high-privilege workload identities",
            "Rotate credentials and enable sign-in risk policies before reactivation",
        ],
        [
            "Entra sign-in/audit feed: dormant period then re-activation for high-impact workload identity",
        ],
        {"AZ_SP_PRIVILEGED_NO_CA": "AZ_LC_DORMANT_HIGH_PRIV",
         "AZ_CONTRIBUTOR": "AZ_LC_DORMANT_HIGH_PRIV"},
        ["First-party Microsoft service principals"],
    ),
    "AZ_LC_CRED_EXPIRED_ALIVE": (
        "Expired Credential Still Active — Credential Lifecycle Enforcement Gap",
        "az_lc_cred_expired_alive",
        ("client_secret",),
        ("credential_expired", "signin_anomaly"),
        "HIGH",
        "T1078.001",
        (
            "The identity continues authenticating with a credential whose "
            "expiry threshold (audit log) has passed. Either the secret was "
            "not rotated on schedule or a stored copy is still being used — "
            "a credential-lifecycle enforcement failure that keeps a stale "
            "secret viable for a live foreign identity."
        ),
        [
            "Rotate/revoke the expired credential and update the workload's stored secret",
            "Enforce credential-expiry policy with a rotation window for all workload identities",
            "Add a detection rule for sign-in after credential-expiry audit events",
        ],
        [
            "Entra sign-in/audit feed: credential-expiry audit event followed by continued sign-in",
        ],
        {"AZ_ADD_SECRET": "AZ_LC_CRED_EXPIRED_ALIVE",
         "AZ_SP_LEGACY_TYPE": "AZ_LC_CRED_EXPIRED_ALIVE"},
        ["First-party Microsoft service principals"],
    ),
    "AZ_LC_SIGNIN_ANOMALY": (
        "Sign-In Anomaly for Workload Identity — Unusual Activity Signal",
        "az_lc_signin_anomaly",
        ("managed_identity", "federated"),
        ("signin_anomaly",),
        "MEDIUM",
        "T1078",
        (
            "The sign-in feed flags an anomalous activity pattern "
            "(unfamiliar location, impossible travel, new device, or "
            "atypical authentication flavor) on a workload identity. "
            "Workload identities have no interactive MFA, so sign-in "
            "anomalies are a leading indicator of credential compromise."
        ),
        [
            "Investigate the anomalous sign-in and correlate with audit events",
            "Rotate credentials and revoke the client secret for the identity",
            "Lock down the identity with Conditional Access where applicable",
        ],
        [
            "Entra sign-in/audit feed: risk/sign-in-anomaly events for workload identity",
        ],
        {"AZ_SIGNIN_RISK": "AZ_LC_SIGNIN_ANOMALY"},
        ["First-party Microsoft service principals"],
    ),
    "AZ_LC_CONSENT_AFTER_REVIEW": (
        "Consent / Credential Event After Attestation — Post-Review Lifecycle Gap",
        "az_lc_consent_after_review",
        ("federated", "client_secret"),
        ("consent", "post_review_event"),
        "LOW",
        "T1098.004",
        (
            "The audit feed records a consent grant or credential-add that "
            "occurred after the most recent governance review/attestation "
            "of the identity. The identity was approved in its prior state "
            "but has since gained new consent or credentials outside any "
            "review — a post-attestation drift that should trigger re-review."
        ),
        [
            "Re-run attestation for identities with post-review consent/credential events",
            "Flag consent grants that occurred outside an approved change window",
            "Add a review trigger on consent/credential-add for governed identities",
        ],
        [
            "Entra sign-in/audit feed: consent/credential-add event dated after last review event",
        ],
        {"AZ_OVERCONSENTED_APP": "AZ_LC_CONSENT_AFTER_REVIEW",
         "AZ_ADD_OWNER": "AZ_LC_CONSENT_AFTER_REVIEW"},
        ["First-party Microsoft service principals"],
    ),
}


def _empty_ad_objects():
    return {
        "users": set(), "groups": set(), "computers": set(),
        "gpos": set(), "organizational_units": set(), "relationships": set(),
    }


def build_lifecycle_findings(lifecycle_evidence):
    """Turn per-identity lifecycle evidence into the 5 NHI lifecycle
    findings (pre-enriched, exporter-ready).

    Returns ``[]`` when ``lifecycle_evidence`` is empty / feed absent,
    preserving the deterministic 80-finding baseline.

    Each finding is a dict shaped exactly like an enriched finding so
    every exporter (CSV / Excel / PDF / AI-PDF) renders it without code
    changes. The ``compliance`` block carries the exporter-visible keys
    (incl. the "OWASP NHI" key so the AI-PDF / PDF lifecycle columns
    render).
    """
    if not lifecycle_evidence:
        return []

    findings = []
    for key, entry in lifecycle_evidence.items():
        event_kinds = set(entry.get("event_kinds", []))
        auth_flavor = entry.get("auth_flavor", "client_secret")

        for fid, (title, f_key, flavors, kinds, severity, mitre,
                  impact, remediation, detection, compliance_tail,
                  exclusions) in LIFECYCLE_FINDING_DEFS.items():
            if not (set(flavors) & ({auth_flavor} | event_kinds)):
                continue
            if not (set(kinds) & event_kinds):
                continue

            ent = _empty_ad_objects()
            ent["relationships"].add(key)
            finding = {
                "id": fid,
                "title": title,
                "category": f_key,
                "group": "nhi_governance",
                "source": "Azure",
                "severity": severity,
                "mitre": {"tactic": "Credential Access", "technique": mitre},
                "impact": impact,
                "remediation": list(remediation),
                "detection": list(detection),
                "compliance": {
                    "CIS": "6.1", "NIST": "PR.AA-03", "ISO 27001": "8.2, 8.3, 8.5",
                    "SA 315": "IT-3/ITDMC", "DPDP": "9(1)", "OWASP NHI": "NHI",
                },
                "linked_findings": dict(compliance_tail),
                "exclusions": list(exclusions),
                "evidence": [dict(e) for e in entry.get("events", [])],
                "has_evidence": bool(entry),
                "confidence": "Confirmed" if entry else "No Data",
                "ad_objects": ent,
                "truncated": False,
            }
            findings.append(finding)

    # Deduplicate across identities feeding the same finding id.
    seen = set()
    out = []
    for f in findings:
        if f["id"] in seen:
            continue
        seen.add(f["id"])
        out.append(f)
    return out


def main():
    """CLI adapter: python -m analytics.nhi_lifecycle [--feed PATH|GLOB]

    Prints a compact JSON summary of the feed present/produced evidence.
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="GraphShield NHI lifecycle evidence adapter (Entra sign-in/audit-log feed)."
    )
    parser.add_argument("--feed", help="JSON file path, glob, or comma-separated list of paths.")
    args = parser.parse_args()

    lifecycle_evidence = load_lifecycle_feed(args.feed)
    signin_total, summary = feed_summary(lifecycle_evidence)
    findings = build_lifecycle_findings(lifecycle_evidence)
    payload = {
        "lifecycle_feed_present": bool(lifecycle_evidence),
        "summary": summary,
        "lifecycle_findings": [f["id"] for f in findings],
    }
    print(json.dumps(payload, indent=2, default=str))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())