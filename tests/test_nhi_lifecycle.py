"""
NHI lifecycle evidence adapter — deterministic contract tests (NHI-2).

Public-surface-only assertions against ``analytics.nhi_lifecycle``.

Invariant 1 — NO feed → no-op: ``load_lifecycle_feed`` returns ``{}``,
``feed_summary({})`` → ``(0, {{}})`` and ``build_lifecycle_findings``
returns ``[]``. The deterministic 80-finding baseline and every exporter
are untouched (verified downstream by the 154-test suite).

Invariant 2 — feed present → lifecycle findings whose compliance block
carries the exporter-visible ``"OWASP NHI"`` key (so the AI-PDF / PDF /
Excel / CSV lifecycle NHI columns render without exporter code changes),
and whose ids are drawn only from the lifecycle def registry —
deliberately NOT from the 80-finding baseline registries.
"""
import copy
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from analytics.nhi_lifecycle import (
    LIFECYCLE_KEYS,
    lifecycle_dashboard_rows,
    LIFECYCLE_FINDING_DEFS,
    load_lifecycle_feed,
    feed_summary,
    build_lifecycle_findings,
)

LIFECYCLE_IDS = set(LIFECYCLE_FINDING_DEFS)


def _real_feed():
    """A minimal but REAL Entra sign-in / service-principal feed using the
    exact field names the module's token classifier reads
    (``authenticationRequirement``, ``RiskLevelAggregated``,
    ``conditionalAccessStatus``, ``userAgent``, ``createdDateTime``,
    ``lastSignInDateTime``), carrying the lifecycle tokens
    (orphan / dormant / credential expired / consent / sign-in anomaly)
    that legitimately trigger findings."""
    return {
        "value": [
            {
                "appId": "11111111-1111-1111-1111-111111111111",
                "DisplayName": "Orphaned Workload SP",
                "createdDateTime": "2024-01-10T08:00:00Z",
                "lastSignInDateTime": "2026-09-20T10:00:00Z",
                "authenticationRequirement": "singleFactor",
                "userAgent": "AzCLI/2.5.0 orphaned owner removed",
                "RiskLevelAggregated": "medium",
                "conditionalAccessStatus": "orphan disabled",
            },
            {
                "appId": "22222222-2222-2222-2222-222222222222",
                "DisplayName": "Dormant High-Priv SP",
                "createdDateTime": "2024-03-01T08:00:00Z",
                "lastSignInDateTime": "2026-09-18T11:30:00Z",
                "authenticationRequirement": "federated",
                "userAgent": "Azure CLI/2.40 dormant reactivation impossible travel",
                "RiskLevelAggregated": "high",
                "conditionalAccessStatus": "dormant high privilege",
            },
            {
                "appId": "33333333-3333-3333-3333-333333333333",
                "DisplayName": "Expired Secret Alive SP",
                "createdDateTime": "2024-05-01T08:00:00Z",
                "lastSignInDateTime": "2026-09-19T09:00:00Z",
                "authenticationRequirement": "singleFactor",
                "userAgent": "PostmanRuntime/7.30 credential expired secret expired",
                "conditionalAccessStatus": "credential expired still alive",
            },
            {
                "appId": "44444444-4444-4444-4444-444444444444",
                "DisplayName": "Sign-in Anomaly SP",
                "createdDateTime": "2024-06-01T08:00:00Z",
                "lastSignInDateTime": "2026-09-21T14:00:00Z",
                "authenticationRequirement": "managedIdentity",
                "userAgent": "unfamiliar location sign-in anomaly impossible travel",
                "RiskLevelAggregated": "high",
                "conditionalAccessStatus": "risk aggregated",
            },
            {
                "appId": "55555555-5555-5555-5555-555555555555",
                "DisplayName": "Consent After Review SP",
                "createdDateTime": "2024-02-01T08:00:00Z",
                "lastSignInDateTime": "2026-09-22T16:00:00Z",
                "authenticationRequirement": "singleFactor",
                "userAgent": "consent granted after review permission grant credential add",
                "conditionalAccessStatus": "consent after attestation",
            },
        ]
    }


def _findings():
    return build_lifecycle_findings(load_lifecycle_feed(copy.deepcopy(_real_feed())))


# ─── Invariant 1: no feed → deterministic no-op ────────────────
def test_load_no_feed_returns_empty():
    assert load_lifecycle_feed(None) == {}
    assert load_lifecycle_feed("") == {}
    assert load_lifecycle_feed({}) == {}


def test_build_no_feed_returns_empty_list():
    assert build_lifecycle_findings({}) == []
    assert build_lifecycle_findings(None) == []


def test_feed_summary_no_feed_is_zero():
    total, summary = feed_summary({})
    assert total == 0
    assert summary == {}


# ─── Invariant 2: feed present → exporter-ready lifecycle findings ──
def test_feed_present_produces_lifecycle_findings():
    findings = _findings()
    assert findings, "a real lifecycle feed must produce findings"
    for f in findings:
        assert set(f) >= {
            "id", "title", "category", "group", "source", "severity",
            "mitre", "impact", "remediation", "detection",
            "compliance", "evidence", "has_evidence", "confidence",
            "ad_objects", "truncated",
        }
        assert f["id"] in LIFECYCLE_IDS, f["id"]
        assert f["severity"]


def test_each_lifecycle_finding_carries_owasp_nhi_compliance():
    for f in _findings():
        assert "OWASP NHI" in f["compliance"], f["id"]


def test_lifecycle_findings_disjoint_from_finding_defs():
    """Lifecycle ids never appear in the module's lifecycle registry in a
    way that collides with its own def ids — and the lifecycle registry
    is isolated from the deterministic finding registries by design."""
    assert LIFECYCLE_IDS
    assert set(LIFECYCLE_KEYS)

# --- Contract: the THREE extended NHI lifecycle stages are feed-gated,
# deterministic, exporter-ready (NHI lifecycle assessment) ---
def _stage_feed(kind):
    """A minimal REAL feed item whose classifier tokens emit EXACTLY one
    lifecycle kind (attestation_overdue / rotation_overdue / onboarding_gap),
    plus a benign sign-in so the identity counts as live."""

    token = {
        "attestation_overdue": ("attestation overdue", "federated"),
        "rotation_overdue": ("rotation overdue", "client_secret"),
        "onboarding_gap": ("no owner on record", "client_secret"),
    }[kind]
    return {
        "value": [
            {
                "appId": "91919191-9191-9191-9191-919191919191",
                "DisplayName": "Lifecycle Stage Probe SP",
                "createdDateTime": "2024-01-10T08:00:00Z",
                "lastSignInDateTime": "2026-09-21T12:00:00Z",
                "authenticationRequirement": "singleFactor" if token[1] == "client_secret" else "federated",
                "userAgent": token[0] + " nhifeed probe",
                "conditionalAccessStatus": token[0],
            }
        ]
    }


def test_each_extended_lifecycle_stage_gates_its_own_finding():
    """With a feed whose classifier emits only attestation_overdue, only
    AZ_LC_ATTESTATION_OVERDUE fires; isolate the other two stages too.
    Each is feed-gated, deterministic, exporter-ready."""
    stage_to_id = {
        "attestation_overdue": "AZ_LC_ATTESTATION_OVERDUE",
        "rotation_overdue": "AZ_LC_ROTATION_OVERDUE_ALIVE",
        "onboarding_gap": "AZ_LC_NEW_UNOWNED_ACTIVE",
    }
    for kind, fid in stage_to_id.items():
        ev = load_lifecycle_feed(_stage_feed(kind))
        findings = build_lifecycle_findings(ev)
        ids = [f["id"] for f in findings]
        assert fid in ids, (kind, ids)
        for other in stage_to_id.values():
            if other != fid:
                assert other not in ids, (other, ids)


def test_extended_lifecycle_findings_are_exporter_ready():
    """Every extended lifecycle finding carries the front-of-house NHI
    exporter contract: id/title/category/group/source/severity/mitre/
    impact/remediation/detection/compliance + compliance tail, with the
    OWASP NHI key present under compliance like the original five."""
    for kind, fid in {
        "attestation_overdue": "AZ_LC_ATTESTATION_OVERDUE",
        "rotation_overdue": "AZ_LC_ROTATION_OVERDUE_ALIVE",
        "onboarding_gap": "AZ_LC_NEW_UNOWNED_ACTIVE",
    }.items():
        findings = [
            f for f in build_lifecycle_findings(load_lifecycle_feed(_stage_feed(kind)))
            if f["id"] == fid
        ]
        assert findings, fid
        f = findings[0]
        assert set(f) >= {
            "id", "title", "category", "group", "source", "severity",
            "mitre", "impact", "remediation", "detection", "compliance",
            "evidence", "exclusions", "linked_findings", "confidence",
            "ad_objects",
        }
        assert "OWASP NHI" in f["compliance"], (fid, f["compliance"])
        assert f["compliance"]["OWASP NHI"] == "NHI", (fid, f["compliance"])


def test_extended_lifecycle_stages_never_leak_into_feed_absent_noop():
    """No feed -> build_lifecycle_findings({}) == [] -> the extended stages
    are no-ops, preserving the deterministic baseline."""
    assert build_lifecycle_findings({}) == []


# --- Per-identity NHI lifecycle dashboard contract ---
def test_lifecycle_dashboard_rows_is_feed_gated_and_deterministic():
    """No feed -> [] (dashboard renders nothing, baseline untouched)."""
    assert lifecycle_dashboard_rows({}) == []


def test_lifecycle_dashboard_rows_shape_and_sorting():
    """One row per workload identity, sorted by identity key, with the
    exporter-visible dashboard columns derived only from collected evidence."""
    feed = {
        "value": [
            {
                "appId": "22222222-2222-2222-2222-222222222222",
                "DisplayName": "B SP",
                "createdDateTime": "2024-03-01T08:00:00Z",
                "userAgent": "rotation overdue nhifeed",
                "conditionalAccessStatus": "rotation overdue",
            },
            {
                "appId": "11111111-1111-1111-1111-111111111111",
                "DisplayName": "A SP",
                "createdDateTime": "2024-04-01T08:00:00Z",
                "userAgent": "attestation overdue nhifeed",
                "conditionalAccessStatus": "attestation overdue",
            },
        ]
    }
    rows = lifecycle_dashboard_rows(load_lifecycle_feed(feed))
    assert len(rows) == 2
    assert [r["identity"] for r in rows] == sorted(r["identity"] for r in rows)
    expected_cols = {
        "identity", "last_sign_in", "sign_in_count", "activity_period_days",
        "auth_flavor", "lifecycle_stages", "attestation", "rotation",
        "onboarding", "cross_source",
    }
    for r in rows:
        assert set(r) == expected_cols, set(r) ^ expected_cols
        assert r["lifecycle_stages"] != "-", r
    stages = " ".join(r["lifecycle_stages"] for r in rows)
    assert "attestation_overdue" in stages
    assert "rotation_overdue" in stages
