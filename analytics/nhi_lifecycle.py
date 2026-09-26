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
# the NHI lifecycle findings.
LIFECYCLE_KEYS = (
    "last_sign_in",
    "sign_in_count",
    "activity_period_days",
    "auth_flavor",           # client_secret | certificate | federated | managed_identity
    "event_kinds",           # set of "orphan", "disabled", "credential_expired",
                             #   "consent", "credential_add", "signin_anomaly",
                             #   "post_review_event", "attestation_overdue",
                             #   "rotation_overdue", "onboarding_gap"
    "attestation",           # {last_attested_date, attestation_window_days,
                             #   attestation_status}
    "rotation",              # {last_rotation_date, rotation_policy_max_age_days,
                             #   rotation_overdue_days, rotation_status}
    "onboarding",            # {created_date, onboarding_window_days,
                             #   onboarding_status, has_owner_ever}
    "cross_source",          # {feed_sources, merged_at, feeds_merged}
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
    if any(tok in joined for tok in ("dormant", "inactive", "idle account",
                                     "dormant high privilege", "reactivation")):
        kinds.add("dormant")
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
    if any(tok in joined for tok in ("attestation overdue", "attestation window lapsed",
                                     "attestation expired", "no attestation",
                                     "attestation gap", "missed attestation",
                                     "attestation_outdated", "attestation alarm",
                                     "attestation overdue warning")):
        kinds.add("attestation_overdue")
    if any(tok in joined for tok in ("rotation overdue", "rotation window exceeded",
                                     "rotation policy exceeded", "rotation expired",
                                     "rotation overdue warning", "credential rotation overdue",
                                     "rotation_gap", "missed rotation")):
        kinds.add("rotation_overdue")
    if any(tok in joined for tok in ("onboarding gap", "never onboarded",
                                     "no onboarding record", "missing onboarding",
                                     "onboarding_gap", "no owner on record",
                                     "unowned new", "newly created without owner",
                                     "onboarding pending")):
        kinds.add("onboarding_gap")
    return kinds


def _first(item, *names):
    """Return the first present, non-empty value among ``names``."""
    for n in names:
        v = item.get(n)
        if v not in (None, ""):
            return v
    return None


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _structured_lifecycle(item):
    """Extract the optional structured lifecycle blocks an Entra attestation /
    rotation / onboarding feed may carry.

    Returns a dict with only the blocks the feed actually supplied, so feeds
    that omit them stay fully backward compatible (no fabricated values).
    """
    out = {}

    att = {}
    last_attested = _iso_date(_first(item, "lastAttestedDate", "last_attested_date",
                                     "lastAttestationDate", "last_attestation_date"))
    if last_attested:
        att["last_attested_date"] = last_attested
    window = _int_or_none(_first(item, "attestationWindowDays", "attestation_window_days"))
    if window is not None:
        att["attestation_window_days"] = window
    att_status = _first(item, "attestationStatus", "attestation_status")
    if att_status:
        att["attestation_status"] = str(att_status)
    if att:
        out["attestation"] = att

    rot = {}
    last_rot = _iso_date(_first(item, "lastRotationDate", "last_rotation_date",
                                "lastCredentialRotationDate", "last_credential_rotation_date"))
    if last_rot:
        rot["last_rotation_date"] = last_rot
    max_age = _int_or_none(_first(item, "rotationPolicyMaxAgeDays", "rotation_policy_max_age_days"))
    if max_age is not None:
        rot["rotation_policy_max_age_days"] = max_age
    overdue = _int_or_none(_first(item, "rotationOverdueDays", "rotation_overdue_days"))
    if overdue is not None:
        rot["rotation_overdue_days"] = overdue
    rot_status = _first(item, "rotationStatus", "rotation_status")
    if rot_status:
        rot["rotation_status"] = str(rot_status)
    if rot:
        out["rotation"] = rot

    # The onboarding block is only emitted when the feed actually carries
    # onboarding context - never inferred from a bare createdDateTime, which
    # every sign-in record has. Nothing is fabricated.
    onb = {}
    owin = _int_or_none(_first(item, "onboardingWindowDays", "onboarding_window_days"))
    if owin is not None:
        onb["onboarding_window_days"] = owin
    ostatus = _first(item, "onboardingStatus", "onboarding_status")
    if ostatus:
        onb["onboarding_status"] = str(ostatus)
    owner = _first(item, "hasOwnerEver", "has_owner_ever")
    if owner is not None:
        onb["has_owner_ever"] = bool(owner) if isinstance(owner, bool) else \
            str(owner).strip().lower() in ("1", "true", "yes")
    created = _iso_date(_first(item, "createdDate", "created_date", "createdDateTime"))
    if created and onb:
        # created_date only carries onboarding meaning alongside explicit
        # onboarding context.
        onb["created_date"] = created
    if onb:
        out["onboarding"] = onb

    return out


def _process_files(feed_source):
    """Process a path/glob that may point at one or many JSON feeds."""
    if isinstance(feed_source, dict):
        return [_feed_to_evidence(feed_source, {}, "in-memory")]
    matches = []
    inline = []
    if isinstance(feed_source, str):
        if os.path.isfile(feed_source):
            matches = [feed_source]
        else:
            matches = sorted(_glob.glob(feed_source))
    elif isinstance(feed_source, (list, tuple)):
        for part in feed_source:
            if isinstance(part, dict):
                # in-memory payload (e.g. the per-client cache restore path)
                inline.append(part)
            elif isinstance(part, str) and os.path.isfile(part):
                matches.append(part)

    out = {}
    for payload in inline:
        out = _feed_to_evidence(payload, out, "in-memory")
    for path in sorted(matches):
        data = _read_json(path)
        if data is None:
            continue
        out = _feed_to_evidence(data, out, os.path.basename(path))
    return [out]


def _feed_to_evidence(feed, acc, source_label="in-memory"):
    """Merge one feed payload into the evidence accumulator (idempotent).

    Per identity it accumulates:
      * ``event_kinds``   - classified lifecycle signal kinds (set)
      * ``sign_in_count`` - number of workload sign-in records
      * ``last_sign_in``  - most recent sign-in date
      * ``auth_flavor``   - coarse credential type
      * ``events``        - the source records behind the signal, so findings
                            can cite real Entra evidence instead of an empty list
      * ``attestation`` / ``rotation`` / ``onboarding`` - structured blocks,
                            only when the feed actually supplies them
      * ``cross_source``  - which feed(s) contributed this identity
    """
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
            "events": [],
        })
        delta = _signin_events(item)
        if not delta and not item.get("appId") and not item.get("servicePrincipalId"):
            # Non-workload (user sign-in) entries carry no app id; counts
            # them separately is out of scope - skip to stay workload-only.
            continue
        entry["event_kinds"] |= delta
        entry["sign_in_count"] += 1
        last = _iso_date(item.get("createdDateTime", item.get("CreatedDateTime",
                          item.get("signInDateTime", item.get("SignInDateTime")))))
        if last and (not entry["last_sign_in"] or last > entry["last_sign_in"]):
            entry["last_sign_in"] = last
        entry["auth_flavor"] = _auth_flavor(item)

        # Source evidence record (bounded, deterministic) so findings can cite it.
        entry["events"].append({
            "timestamp": last,
            "event_kinds": sorted(delta),
            "auth_flavor": entry["auth_flavor"],
            "user_agent": _first(item, "userAgent", "UserAgent"),
            "activity": _first(item, "activity", "Activity"),
            "status": _first(item, "status", "Status"),
            "conditional_access_status": _first(item, "conditionalAccessStatus",
                                                 "ConditionalAccessStatus"),
            "source": source_label,
        })

        for block, values in _structured_lifecycle(item).items():
            entry.setdefault(block, {}).update(values)

        # Joinable identity attributes: the graph side keys NHI objects by
        # AppId / display name (see finding_enrichment AZ_SP_NO_OWNER etc.),
        # so keep the raw values to let the two sources be correlated.
        ident = entry.setdefault("identity", {})
        for attr, fields in (
            ("app_id", ("appId", "AppId", "applicationId", "ApplicationId")),
            ("object_id", ("objectId", "ObjectId", "servicePrincipalId",
                           "ServicePrincipalId", "spObjectId",
                           "ServicePrincipalObjectId")),
            ("display_name", ("displayName", "DisplayName", "appDisplayName",
                              "AppDisplayName")),
            ("service_principal_name", ("servicePrincipalName",
                                       "ServicePrincipalName")),
        ):
            val = _first(item, *fields)
            if val and not ident.get(attr):
                ident[attr] = str(val).strip()

        xs = entry.setdefault("cross_source", {"feed_sources": set(), "feeds_merged": 0})
        xs["feed_sources"].add(source_label)
        xs["feeds_merged"] = len(xs["feed_sources"])
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
        out[key]["events"] = list(entry.get("events", []))
        out[key]["identity"] = dict(entry.get("identity") or {})
        xs = entry.get("cross_source") or {}
        sources = xs.get("feed_sources") or set()
        # merged_at is derived from the data (not wall-clock) so the evidence
        # stays byte-deterministic across reruns.
        out[key]["cross_source"] = {
            "feed_sources": sorted(sources),
            "feeds_merged": len(sources),
            "merged_at": entry.get("last_sign_in"),
        }
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
        # every credential flavor: orphaning is an ownership problem, not a
        # credential-type problem, so a federated/certificate orphan must not
        # be mislabeled as a dormancy finding.
        ("managed_identity", "client_secret", "federated", "certificate"),
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
        ("managed_identity", "federated", "client_secret", "certificate"),
        # dormancy only — previously included "orphan", which made any
        # federated orphan double-report as a dormancy finding.
        ("dormant", "disabled"),
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
    # ─── NHI lifecycle assessment (feed-gated, deterministic) ────
    # Three recommended lifecycle-time governance findings emitted ONLY
    # when the feed's classifier marks the workload identity with the
    # matching NHI attestation/rotation/onboarding lifecycle event kind.
    # No feed / no matching kind → no-op → the deterministic 80-finding
    # baseline and every exporter stay untouched.
    "AZ_LC_ATTESTATION_OVERDUE": (
        "Workload Attestation Overdue — NHI Attestation Lifecycle Gap",
        "az_lc_attestation_overdue",
        ("managed_identity", "federated", "client_secret"),
        ("attestation_overdue",),
        "HIGH",
        "T1098",
        (
            "The lifecycle feed shows the workload identity's attestation "
            "window has lapsed — last attestation is older than the "
            "attestation_window_days period on record, yet the identity "
            "remains active. An NHI that nobody has re-attested in the "
            "policy window is drifting out of the governance baseline "
            "without triggering re-onboarding."
        ),
        [
            "Re-run the attestation process and record a new attestation date",
            "Shorten attestation windows for high-privilege workload identities",
            "Flag identities whose attestation window lapsed with no re-attestation",
        ],
        [
            "Entra attestation/audit feed: last_attested_date older than attestation_window_days",
        ],
        {"AZ_ATTESTATION": "AZ_LC_ATTESTATION_OVERDUE",
         "AZ_SP_ATTESTATION": "AZ_LC_ATTESTATION_OVERDUE"},
        ["First-party Microsoft service principals"],
    ),
    "AZ_LC_ROTATION_OVERDUE_ALIVE": (
        "Workload Credential Rotation Overdue — NHI Rotation Lifecycle Gap",
        "az_lc_rotation_overdue_alive",
        ("client_secret", "managed_identity"),
        ("rotation_overdue",),
        "HIGH",
        "T1098",
        (
            "The lifecycle feed records a credential whose rotation is "
            "overdue — last rotation predates the rotation_policy_max_age_days "
            "period on record — while the workload identity is still "
            "alive and authenticating. An NHI credential past its rotation "
            "policy is a standing rotation-lifecycle enforcement gap."
        ),
        [
            "Rotate the credential to conform to the rotation policy window",
            "Set up automated rotation with a standing credential-add pipeline",
            "Detect workload identities past their rotation policy window",
        ],
        [
            "Entra credential/audit feed: rotation_policy_max_age_days exceeded by credential age",
        ],
        {"AZ_ROTATION_OVERDUE": "AZ_LC_ROTATION_OVERDUE_ALIVE",
         "AZ_SP_ROTATION": "AZ_LC_ROTATION_OVERDUE_ALIVE"},
        ["First-party Microsoft service principals"],
    ),
    "AZ_LC_NEW_UNOWNED_ACTIVE": (
        "New Active Workload Without Owner — NHI Onboarding Governance Gap",
        "az_lc_new_unowned_active",
        ("client_secret", "managed_identity"),
        ("onboarding_gap",),
        "MEDIUM",
        "T1098",
        (
            "The lifecycle feed shows a workload identity created within "
            "the onboarding_window_days period that is already authenticating "
            "yet carries no owner attestation on record. A brand-new NHI "
            "that goes live without being onboarded to the ownership "
            "baseline is ungoverned from day one."
        ),
        [
            "Assign an owner and complete onboarding attestation before granting access",
            "Enforce an owner-required policy for all newly created workload identities",
            "Gate live sign-in on completed NHI onboarding for new identities",
        ],
        [
            "Entra onboarding/audit feed: created within onboarding_window_days, no owner, active sign-in",
        ],
        {"AZ_NEW_UNOWNED": "AZ_LC_NEW_UNOWNED_ACTIVE",
         "AZ_SP_NEW_UNOWNED": "AZ_LC_NEW_UNOWNED_ACTIVE"},
        ["First-party Microsoft service principals"],
    ),
}


# Bucket schema mirrors analytics.finding_enrichment._empty_buckets() so
# lifecycle findings carry the same ad_objects shape as graph-derived
# findings and every exporter (CSV/Excel/PDF/AI-PDF) renders the Azure
# sections for them instead of empty lists.
_AD_BUCKETS = (
    "users", "groups", "computers", "gpos", "organizational_units", "domains",
    "service_principals", "managed_identities", "applications", "key_vaults",
    "tenants", "subscriptions", "resource_groups", "management_groups",
)


def _empty_ad_objects():
    out = {k: set() for k in _AD_BUCKETS}
    out["relationships"] = set()
    return out


def _identity_display(entry):
    """Human label for a lifecycle identity, matching the baseline NHI
    convention ``"<Principal> (<AppId>)"`` used by enrich_finding."""
    ident = entry.get("identity") or {}
    name = (ident.get("display_name") or ident.get("service_principal_name")
            or entry.get("auth_flavor") or "workload identity")
    app_id = ident.get("app_id")
    return f"{name} ({app_id})" if app_id else name


def _ad_objects_for(entry):
    """Build baseline-convention ad_objects for one lifecycle identity."""
    ent = _empty_ad_objects()
    ident = entry.get("identity") or {}
    label = _identity_display(entry)
    flavor = entry.get("auth_flavor", "client_secret")
    if flavor == "managed_identity":
        ent["managed_identities"].add(label)
    else:
        ent["service_principals"].add(label)
    if ident.get("display_name"):
        ent["applications"].add(ident["display_name"])
    ent["relationships"].add(label)
    return ent


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

            ent = _ad_objects_for(entry)
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
                "has_evidence": bool(entry.get("events")),
                "confidence": "Confirmed" if entry else "No Data",
                "ad_objects": ent,
                "truncated": False,
                # correlation handle: which feed identity produced this
                "nhi_identity_key": key,
            }
            findings.append(finding)

    # Deduplicate across identities feeding the same finding id, merging the
    # cited source evidence and the identities behind each finding.
    merged = {}
    order = []
    for f in findings:
        cur = merged.get(f["id"])
        if cur is None:
            merged[f["id"]] = dict(f)
            merged[f["id"]]["evidence"] = list(f["evidence"])
            order.append(f["id"])
            continue
        known = {e.get("source") for e in cur["evidence"]}
        for ev in f["evidence"]:
            if ev not in cur["evidence"]:
                cur["evidence"].append(ev)
        rel = cur["ad_objects"].get("relationships")
        if rel is not None and f["ad_objects"].get("relationships"):
            rel |= f["ad_objects"]["relationships"]
    return [merged[fid] for fid in order]


def lifecycle_dashboard_rows(lifecycle_evidence):
    """Per-identity NHI lifecycle dashboard rows (feed-gated, deterministic).

    Returns ``[]`` when ``lifecycle_evidence`` is empty / no feed supplied,
    so the dashboard renders nothing and the deterministic baseline is
    untouched. One row per workload identity, sorted by identity key for
    stable ordering across reruns.

    Columns are derived only from the lifecycle evidence the module already
    collects (see ``LIFECYCLE_KEYS``) - no new data sources, no heuristics:
      identity, last_sign_in, sign_in_count, activity_period_days,
      auth_flavor, lifecycle_stages, attestation, rotation, onboarding,
      cross_source
    """
    if not lifecycle_evidence:
        return []
    rows = []
    for key in sorted(lifecycle_evidence):
        e = lifecycle_evidence[key] or {}
        stages = e.get("event_kinds") or []
        if isinstance(stages, (set, frozenset)):
            stages = sorted(stages)
        att = e.get("attestation") or {}
        rot = e.get("rotation") or {}
        onb = e.get("onboarding") or {}
        xsrc = e.get("cross_source") or {}
        rows.append({
            "identity": key,
            "last_sign_in": e.get("last_sign_in"),
            "sign_in_count": e.get("sign_in_count", 0),
            "activity_period_days": e.get("activity_period_days"),
            "auth_flavor": e.get("auth_flavor", "client_secret"),
            "lifecycle_stages": ", ".join(stages) if stages else "-",
            "attestation": att.get("attestation_status") or "-",
            "rotation": rot.get("rotation_status") or "-",
            "onboarding": onb.get("onboarding_status") or "-",
            "cross_source": xsrc.get("merged_at") or "-",
        })
    return rows


def correlate_nhi_sources(findings, lifecycle_evidence):
    """Correlate graph-derived NHI findings with feed-derived lifecycle
    findings **per workload identity**.

    The two assessment sources are complementary and, without correlation,
    an identity orphaned in the graph (AZ-041) and attestation-overdue in the
    logs (AZ-060) would surface as two unrelated findings. This joins them on
    the identifiers both sides actually carry: the Entra application /
    service-principal object id and the display name.

    Mutates each finding in place by adding a ``nhi_correlation`` block and
    returns the list of findings for convenience. Deterministic: identity
    keys and finding ids are sorted, and nothing is invented when either
    source is absent (a no-feed run simply yields no correlated identities).

    ``nhi_correlation`` = {
        "identity": "<display label>",
        "app_id": "<appId or null>",
        "graph_findings": [...],       # NHI governance ids from Neo4j
        "lifecycle_findings": [...],   # lifecycle ids from the feed
        "both_sources": True,          # appears in both sources
    }
    """
    if not findings:
        return findings
    if not lifecycle_evidence:
        return findings

    # index lifecycle identities by every identifier we can join on
    life_index = {}
    for key, entry in (lifecycle_evidence or {}).items():
        ident = entry.get("identity") or {}
        labels = {key}
        for attr in ("app_id", "object_id", "service_principal_name",
                     "display_name"):
            v = ident.get(attr)
            if v:
                labels.add(str(v).strip().lower())
        for lbl in labels:
            life_index.setdefault(lbl, key)

    # index graph findings: NHI governance ids only
    nhi_graph = [
        f for f in findings
        if str(f.get("id", "")).startswith(("AZ_",)) and not str(f.get("id", "")).startswith("AZ_LC_")
    ]
    nhi_life = [f for f in findings if str(f.get("id", "")).startswith("AZ_LC_")]

    graph_hits = {}
    for f in nhi_graph:
        for ev in (f.get("evidence") or []):
            if not isinstance(ev, dict):
                continue
            for field in ("AppId", "appId", "ApplicationId", "ObjectId",
                          "objectId", "ServicePrincipalObjectId", "Principal",
                          "Application", "AppDisplayName", "DisplayName",
                          "ServicePrincipalName"):
                v = ev.get(field)
                if not v or not isinstance(v, str):
                    continue
                hit = life_index.get(v.strip().lower())
                if hit:
                    graph_hits.setdefault(hit, set()).add(f["id"])

    life_hits = {}
    for f in nhi_life:
        key = f.get("nhi_identity_key")
        if key and key in graph_hits:
            life_hits.setdefault(key, set())

    for key in sorted(set(graph_hits) | set(life_hits)):
        entry = lifecycle_evidence.get(key) or {}
        ident = entry.get("identity") or {}
        graph_ids = sorted(graph_hits.get(key, set()))
        life_ids = sorted({
            f["id"] for f in nhi_life if f.get("nhi_identity_key") == key
        })
        block = {
            "identity": _identity_display(entry),
            "app_id": ident.get("app_id"),
            "graph_findings": graph_ids,
            "lifecycle_findings": life_ids,
            "both_sources": bool(graph_ids and life_ids),
        }
        for f in findings:
            if f.get("nhi_identity_key") == key or (
                f in nhi_graph and f["id"] in graph_ids
            ):
                f["nhi_correlation"] = dict(block)

    # consume the internal correlation handle so exporters only ever see the
    # documented finding keys
    for f in findings:
        f.pop("nhi_identity_key", None)
    return findings


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