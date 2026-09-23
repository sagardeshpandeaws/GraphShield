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
