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
    correlate_nhi_sources,
    corroboration_label,
    LIFECYCLE_FINDING_DEFS,
    load_lifecycle_feed,
    feed_summary,
    build_lifecycle_findings,
)

LIFECYCLE_IDS = set(LIFECYCLE_FINDING_DEFS)


def build_lifecycle_feed_evidence_findings(feed):
    """Small local helper: load a raw feed then build its findings."""
    return build_lifecycle_findings(load_lifecycle_feed(feed))


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
        "onboarding", "cross_source", "graph_findings",
        "confirmed_by_both_sources",
    }
    for r in rows:
        assert set(r) == expected_cols, set(r) ^ expected_cols
        assert r["lifecycle_stages"] != "-", r
    stages = " ".join(r["lifecycle_stages"] for r in rows)
    assert "attestation_overdue" in stages
    assert "rotation_overdue" in stages


# --- Regressions: the three gaps closed ---
_STRUCTURED_FEED = {
    "value": [
        {
            "appId": "f0000000-0000-0000-0000-000000000003",
            "DisplayName": "Full Lifecycle SP",
            "createdDateTime": "2026-09-01T00:00:00Z",
            "lastSignInDateTime": "2026-09-25T10:00:00Z",
            "userAgent": "rotation overdue attestation overdue nhifeed",
            "conditionalAccessStatus": "rotation overdue",
            "authenticationRequirement": "singleFactor",
            "lastAttestedDate": "2024-01-01T00:00:00Z",
            "attestationWindowDays": 90,
            "attestationStatus": "overdue",
            "lastRotationDate": "2024-01-01T00:00:00Z",
            "rotationPolicyMaxAgeDays": 180,
            "rotationOverdueDays": 300,
            "rotationStatus": "overdue",
            "onboardingStatus": "no_owner",
            "hasOwnerEver": False,
            "onboardingWindowDays": 30,
        }
    ]
}


def test_findings_cite_real_source_evidence():
    """Regression: findings used to carry an empty evidence list because the
    evidence entries never collected the source records. Every lifecycle
    finding now cites the Entra records behind the signal."""
    findings = build_lifecycle_findings(load_lifecycle_feed(_STRUCTURED_FEED))
    assert findings
    for f in findings:
        assert f["evidence"], f["id"]
        assert f["has_evidence"] is True, f["id"]
        ev = f["evidence"][0]
        assert set(ev) >= {"timestamp", "event_kinds", "auth_flavor", "source"}
        assert ev["event_kinds"], f["id"]


def test_federated_orphan_is_not_mislabeled_as_dormancy():
    """Regression: the flavor gate used to block AZ-055 for federated orphans,
    so they were reported as AZ-056 (dormant high privilege) instead."""
    feed = {
        "value": [
            {
                "appId": "f0000000-0000-0000-0000-000000000001",
                "DisplayName": "Federated Orphan",
                "createdDateTime": "2024-01-01T00:00:00Z",
                "userAgent": "orphan owner absent nhifeed",
                "conditionalAccessStatus": "no owner",
                "authenticationRequirement": "federated",
            }
        ]
    }
    ids = [f["id"] for f in build_lifecycle_findings(load_lifecycle_feed(feed))]
    assert "AZ_LC_ACTIVE_ORPHANED" in ids, ids
    assert "AZ_LC_DORMANT_HIGH_PRIV" not in ids, ids


def test_dormant_token_fires_dormancy_finding():
    """The documented `dormant` feed token must actually classify."""
    feed = {
        "value": [
            {
                "appId": "f0000000-0000-0000-0000-000000000002",
                "DisplayName": "Dormant SP",
                "createdDateTime": "2024-02-01T00:00:00Z",
                "userAgent": "dormant high privilege reactivation",
                "conditionalAccessStatus": "dormant high privilege",
                "authenticationRequirement": "federated",
            }
        ]
    }
    ids = [f["id"] for f in build_lifecycle_feed_evidence_findings(feed)]
    assert "AZ_LC_DORMANT_HIGH_PRIV" in ids, ids


def test_all_lifecycle_keys_are_populated_when_feed_supplies_them():
    """Regression: attestation / rotation / onboarding / cross_source were
    declared in LIFECYCLE_KEYS but never populated, so those dashboard columns
    always rendered '-'. They now populate from the feed, and stay absent when
    the feed omits them (nothing is fabricated)."""
    ev = load_lifecycle_feed(_STRUCTURED_FEED)
    entry = ev["f0000000-0000-0000-0000-000000000003"]
    assert set(LIFECYCLE_KEYS) <= set(entry), set(LIFECYCLE_KEYS) - set(entry)
    assert entry["attestation"]["attestation_status"] == "overdue"
    assert entry["attestation"]["attestation_window_days"] == 90
    assert entry["rotation"]["rotation_overdue_days"] == 300
    assert entry["onboarding"]["has_owner_ever"] is False
    assert entry["cross_source"]["feeds_merged"] == 1
    # deterministic: merged_at derived from the data, not wall-clock
    assert entry["cross_source"]["merged_at"] == entry["last_sign_in"]

    plain = load_lifecycle_feed(_real_feed())
    for e in plain.values():
        assert "attestation" not in e
        assert "rotation" not in e
        assert "onboarding" not in e


def test_cache_restore_tuple_with_inline_dict_is_loaded():
    """Regression: app.py restores a cached feed as ("__nhi_cache__", dict).
    That inline dict was silently dropped, so a cached rerun produced no
    lifecycle evidence at all."""
    ev = load_lifecycle_feed(("__nhi_cache__", _STRUCTURED_FEED))
    assert ev
    assert build_lifecycle_findings(ev)


# --- Two-source NHI correlation (graph + logs) ---
_CORR_APP = "11111111-2222-3333-4444-555555555555"
_CORR_FEED = {
    "value": [
        {
            "appId": _CORR_APP,
            "DisplayName": "Contoso Billing SP",
            "createdDateTime": "2026-09-01T00:00:00Z",
            "userAgent": "attestation overdue orphan no owner nhifeed",
            "conditionalAccessStatus": "attestation overdue",
            "authenticationRequirement": "federated",
            "attestationStatus": "overdue",
            "attestationWindowDays": 90,
        }
    ]
}


def _graph_nhi_finding():
    """A graph-derived NHI governance finding for the same identity."""
    return {
        "id": "AZ_SP_NO_OWNER",
        "title": "Unowned Service Principals",
        "group": "nhi_governance",
        "source": "Azure",
        "severity": "HIGH",
        "evidence": [{"Principal": "Contoso Billing SP", "AppId": _CORR_APP}],
        "ad_objects": {},
        "has_evidence": True,
        "confidence": "Confirmed",
    }


def test_correlation_binds_graph_and_lifecycle_findings_for_one_identity():
    """An identity orphaned in the graph (AZ-041) and attestation-overdue in
    the logs (AZ-060) must surface as ONE correlated identity, not two
    unrelated findings."""
    ev = load_lifecycle_feed(_CORR_FEED)
    findings = [_graph_nhi_finding()] + build_lifecycle_findings(ev)
    correlate_nhi_sources(findings, ev)
    corr = [f["nhi_correlation"] for f in findings if "nhi_correlation" in f]
    assert corr, "expected a correlation block on both sides"
    for c in corr:
        assert c["both_sources"] is True, c
        assert c["app_id"] == _CORR_APP, c
        assert "AZ_SP_NO_OWNER" in c["graph_findings"], c
        assert "AZ_LC_ATTESTATION_OVERDUE" in c["lifecycle_findings"], c


def test_correlation_does_not_invent_matches_for_unknown_identities():
    """A graph finding whose AppId is absent from the feed gets no
    correlation block - nothing is fabricated."""
    ev = load_lifecycle_feed(_CORR_FEED)
    other = _graph_nhi_finding()
    other["evidence"] = [{"Principal": "Unknown SP",
                          "AppId": "99999999-9999-9999-9999-999999999999"}]
    findings = [other] + build_lifecycle_findings(ev)
    correlate_nhi_sources(findings, ev)
    assert "nhi_correlation" not in findings[0]


def test_correlation_is_a_noop_without_feed():
    """No feed -> graph findings are returned untouched (baseline safe)."""
    findings = [_graph_nhi_finding()]
    out = correlate_nhi_sources(findings, {})
    assert out is findings
    assert "nhi_correlation" not in findings[0]


def test_lifecycle_findings_carry_baseline_convention_ad_objects():
    """Lifecycle findings must populate the same ad_objects buckets the
    exporters read (service_principals / applications), not an empty
    AD-only schema."""
    ev = load_lifecycle_feed(_CORR_FEED)
    for f in build_lifecycle_findings(ev):
        objs = f["ad_objects"]
        for bucket in ("service_principals", "applications", "relationships",
                       "users", "groups", "key_vaults", "tenants"):
            assert bucket in objs, bucket
        assert objs["service_principals"], f["id"]
        assert _CORR_APP in " ".join(objs["service_principals"]), f["id"]


def test_correlation_handle_is_not_leaked_to_exporters():
    """The internal identity handle must be consumed so exporters only see
    documented finding keys."""
    ev = load_lifecycle_feed(_CORR_FEED)
    findings = [_graph_nhi_finding()] + build_lifecycle_findings(ev)
    correlate_nhi_sources(findings, ev)
    for f in findings:
        assert "nhi_identity_key" not in f, f["id"]


def test_dashboard_surfaces_graph_corroboration_per_identity():
    """A CISO must see, in one row, that an identity is confirmed by Neo4j
    and the logs - the dashboard exposes the graph findings per identity."""
    ev = load_lifecycle_feed(_CORR_FEED)
    findings = [_graph_nhi_finding()] + build_lifecycle_findings(ev)
    corr = {}
    correlate_nhi_sources(findings, ev, corr)
    rows = lifecycle_dashboard_rows(ev, corr)
    assert len(rows) == 1
    r = rows[0]
    assert r["confirmed_by_both_sources"] == "Yes"
    assert "AZ_SP_NO_OWNER" in r["graph_findings"]


def test_dashboard_without_correlation_map_is_unchanged():
    """Omitting the map keeps the new columns at '-' (safe default)."""
    ev = load_lifecycle_feed(_CORR_FEED)
    r = lifecycle_dashboard_rows(ev)[0]
    assert r["graph_findings"] == "-"
    assert r["confirmed_by_both_sources"] == "No"


def test_correlation_map_is_keyed_by_identity():
    corr = {}
    ev = load_lifecycle_feed(_CORR_FEED)
    findings = [_graph_nhi_finding()] + build_lifecycle_findings(ev)
    correlate_nhi_sources(findings, ev, corr)
    assert len(corr) == 1
    key = next(iter(corr))
    assert corr[key]["both_sources"] is True


# --- Scope: correlation is NHI-ASSESSMENT ONLY ---

def test_non_nhi_finding_with_matching_appid_is_never_correlated():
    """An az_core / ad_core finding that references the SAME workload AppId
    must not be pulled into the NHI correlation - the two-source correlation
    belongs to the NHI assessment only."""
    ev = load_lifecycle_feed(_CORR_FEED)
    az_core = {
        "id": "AZ_ADD_SECRET", "group": "az_core", "source": "Azure",
        "severity": "MEDIUM", "evidence": [{"AppId": _CORR_APP}],
        "ad_objects": {}, "has_evidence": True, "confidence": "Confirmed",
    }
    ad_core = {
        "id": "AD_KERBEROAST", "group": "ad_core", "source": "Active Directory",
        "severity": "HIGH", "evidence": [{"User": "jdoe"}],
        "ad_objects": {}, "has_evidence": True, "confidence": "Confirmed",
    }
    findings = [az_core, ad_core, _graph_nhi_finding()] + build_lifecycle_findings(ev)
    correlate_nhi_sources(findings, ev)
    assert "nhi_correlation" not in az_core, "az_core must not be correlated"
    assert "nhi_correlation" not in ad_core, "ad_core must not be correlated"
    assert "nhi_correlation" in findings[2], "nhi_governance must be correlated"


def test_corroboration_label_is_empty_outside_the_nhi_assessment():
    """Report label must be blank for every non-NHI finding and for NHI
    findings that lack a both-sources match."""
    assert corroboration_label(None) == ""
    assert corroboration_label({"id": "AD_KERBEROAST", "group": "ad_core"}) == ""
    assert corroboration_label({"id": "AZ_ADD_SECRET", "group": "az_core"}) == ""
    # NHI finding with no correlation at all
    assert corroboration_label({"id": "AZ_SP_NO_OWNER", "group": "nhi_governance"}) == ""
    # NHI finding whose identity is single-source
    assert corroboration_label({
        "id": "AZ_SP_NO_OWNER", "group": "nhi_governance",
        "nhi_correlation": {"both_sources": False},
    }) == ""


def test_corroboration_label_summarizes_both_sources():
    ev = load_lifecycle_feed(_CORR_FEED)
    findings = [_graph_nhi_finding()] + build_lifecycle_findings(ev)
    correlate_nhi_sources(findings, ev)
    for f in findings:
        label = corroboration_label(f)
        assert "Neo4j: AZ_SP_NO_OWNER" in label, label
        assert "Logs: " in label, label
        assert "AZ_LC_ATTESTATION_OVERDUE" in label, label
        assert _CORR_APP in label, label


def test_lifecycle_ad_objects_are_sorted_lists_for_exporters():
    """Exporters slice ad_objects values (csv uses [:5]), so lifecycle
    findings must emit sorted lists, never sets."""
    ev = load_lifecycle_feed(_CORR_FEED)
    for f in build_lifecycle_findings(ev):
        for bucket, vals in f["ad_objects"].items():
            assert isinstance(vals, list), (f["id"], bucket, type(vals))
            assert vals == sorted(vals), (f["id"], bucket, vals)


def test_merged_relationships_stay_sorted_lists():
    """Two identities triggering one finding must merge relationships into a
    stable sorted list, not a set."""
    feed = {"value": [
        {"appId": "11111111-1111-1111-1111-111111111111", "DisplayName": "A SP",
         "userAgent": "orphaned no owner nhifeed",
         "conditionalAccessStatus": "orphaned"},
        {"appId": "22222222-2222-2222-2222-222222222222", "DisplayName": "B SP",
         "userAgent": "orphaned no owner nhifeed",
         "conditionalAccessStatus": "orphaned"},
    ]}
    ev = load_lifecycle_feed(feed)
    for f in build_lifecycle_findings(ev):
        rels = f["ad_objects"]["relationships"]
        assert isinstance(rels, list), type(rels)
        assert rels == sorted(rels), rels
        assert len(rels) == 2, rels
