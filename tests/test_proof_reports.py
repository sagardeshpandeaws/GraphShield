import csv
import io
import json
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analytics.finding_enrichment import enrich_finding
from analytics.groups import GROUP_ORDER
from scripts import generate_proof_reports as gpr

NHI = "nhi_governance"
NON_NHI = [g for g in GROUP_ORDER if g != NHI]
ARTIFACT_KINDS = ("Assessment_Report", "Engineering", "Findings",
                  "Evidence", "Attack_Graph", "Executive_Brief", "Package")


@pytest.fixture(scope="module")
def raw():
    return gpr.build_dummy_raw()


@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    out = tmp_path_factory.mktemp("proof")
    summary, out_root = gpr.generate(client_name="1st_Client",
                                     out_root=str(out), verbose=False)
    return summary, out_root


# ── synthetic input ────────────────────────────────────────────────

def test_dummy_raw_supports_every_declared_query_key():
    """Every query key the builder declares must have synthetic rows, so all
    finding types can be proven without a live Neo4j."""
    query_keys = {spec[2] for spec in gpr.FindingBuilder.FINDINGS}
    raw = gpr.build_dummy_raw()
    missing = sorted(k for k in query_keys if not raw.get(k))
    assert not missing, "no synthetic rows for: %s" % missing


def test_dummy_raw_covers_every_declared_finding_type():
    raw = gpr.build_dummy_raw()
    declared = {spec[0] for spec in gpr.FindingBuilder.FINDINGS}
    seen = set()
    for group in GROUP_ORDER:
        for f in gpr.FindingBuilder().build(raw, selected_groups=[group]):
            seen.add(f["id"])
    assert declared - seen == set(), "findings never built: %s" % (declared - seen)
    assert len(declared) == 80, "baseline contract is 80 finding types"


def test_lifecycle_feed_correlates_with_graph_entities():
    """The inline feed must share object ids with the graph data, which is how
    the two sources are matched."""
    feed = gpr.load_lifecycle_feed(gpr.DUMMY_LIFECYCLE_FEED)
    assert feed, "inline dummy lifecycle feed must load"
    raw = gpr.build_dummy_raw()
    graph = [enrich_finding(f, raw) for f in
             gpr.FindingBuilder().build(raw, selected_groups=[NHI])]
    blob = " ".join(
        str(v) for f in graph
        for values in (f.get("ad_objects") or {}).values()
        for v in (values if isinstance(values, list) else [values]))
    matched = [app_id for app_id in feed if app_id in blob]
    assert len(matched) >= 2, "expected the feed to share ids with the graph data"
    # The remainder are deliberately log-only: they prove the feed surfaces
    # identities Neo4j posture data never contained.
    assert len(matched) < len(feed), \
        "sample data should also prove the log-only (uncorrelated) path"


def test_log_only_identity_is_still_reported_with_its_identity(raw):
    findings, chains, risk, ev, corr = gpr.build_findings_for_group(raw, NHI)
    log_only = [f for f in findings
                if str(f.get("id", "")).startswith("AZ_LC_")
                and not (f.get("nhi_correlation") or {}).get("graph_findings")]
    assert log_only, "no log-only lifecycle finding was produced"
    for f in log_only:
        named = [v for values in (f.get("ad_objects") or {}).values()
                 for v in (values if isinstance(values, list) else [values])]
        assert named, "a log-only finding must still name its identity"



# ── pipeline ───────────────────────────────────────────────────────

@pytest.mark.parametrize("group", GROUP_ORDER)
def test_group_findings_all_have_evidence(raw, group):
    findings, chains, risk, ev, corr = gpr.build_findings_for_group(raw, group)
    assert findings, "%s produced no findings" % group
    inactive = [f["id"] for f in findings if not f.get("has_evidence")]
    assert not inactive, "%s inactive findings: %s" % (group, inactive)
    assert risk.get("total_score") is not None
    assert risk.get("rating")


@pytest.mark.parametrize("group", GROUP_ORDER)
def test_lifecycle_and_correlation_are_nhi_only(raw, group):
    findings, chains, risk, ev, corr = gpr.build_findings_for_group(raw, group)
    lifecycle = [f for f in findings if str(f.get("id", "")).startswith("AZ_LC_")]
    if group == NHI:
        assert ev, "NHI should load the lifecycle feed"
        assert lifecycle, "NHI should include lifecycle findings"
        assert corr, "NHI should correlate the two sources"
    else:
        assert not lifecycle, "%s leaked lifecycle findings" % group
        assert not ev, "%s loaded a lifecycle feed" % group
        assert not corr, "%s produced correlation" % group
        assert all("nhi_correlation" not in f for f in findings)


def test_nhi_correlation_is_bidirectional(raw):
    findings, chains, risk, ev, corr = gpr.build_findings_for_group(raw, NHI)
    matched_graph, matched_life, log_only = set(), set(), set()
    for f in findings:
        c = f.get("nhi_correlation")
        if not c:
            continue
        if str(f.get("id", "")).startswith("AZ_LC_"):
            if c.get("graph_findings"):
                matched_life.add(f["id"])
            else:
                log_only.add(f["id"])
        else:
            matched_graph.add(f["id"])
    assert matched_graph and matched_life, \
        "correlations must exist on both sides for matched identities"
    assert log_only, "a log-only identity must still be reported"
    # every correlation entry describes a real identity from the feed
    assert set(corr) == set(ev), (set(corr), set(ev))
    for key, block in corr.items():
        assert block["both_sources"] is bool(block["graph_findings"]
                                            and block["lifecycle_findings"]), block
        assert block["lifecycle_findings"], block


# ── artifacts ──────────────────────────────────────────────────────

def test_generates_every_artifact_for_every_group(generated):
    summary, out_root = generated
    assert set(summary) == set(GROUP_ORDER)
    for group, s in summary.items():
        assert len(s["artifacts"]) == len(ARTIFACT_KINDS), group
        for name in s["artifacts"]:
            p = os.path.join(out_root, group, name)
            assert os.path.getsize(p) > 1000, name
        assert s["with_evidence"] == s["findings"]
        assert s["ai_source"].startswith("deterministic")


def test_manifest_records_integrity_hashes(generated):
    import hashlib
    summary, out_root = generated
    man = json.load(io.open(os.path.join(out_root, "proof_manifest.json"),
                            encoding="utf-8"))
    assert man["client"] == "1st_Client"
    assert man["generated_from"] == "synthetic sample data"
    assert man["report_date"] == gpr.FIXED_DATE
    for group, s in summary.items():
        integrity = man["groups"][group]["artifact_integrity"]
        assert set(integrity) == set(s["artifacts"])
        for name, rec in integrity.items():
            p = os.path.join(out_root, group, name)
            data = open(p, "rb").read()
            assert rec["bytes"] == len(data)
            assert rec["sha256"] == hashlib.sha256(data).hexdigest()


def test_zip_packages_contain_the_six_reports(generated):
    summary, out_root = generated
    for group in GROUP_ORDER:
        zpath = [os.path.join(out_root, group, n) for n in summary[group]["artifacts"]
                 if n.endswith(".zip")][0]
        with zipfile.ZipFile(zpath) as z:
            assert z.testzip() is None
            assert len(z.namelist()) == 6


def test_csv_corroboration_populated_only_in_nhi(generated):
    summary, out_root = generated
    for group in GROUP_ORDER:
        name = [n for n in summary[group]["artifacts"] if n.endswith(".csv")][0]
        rows = list(csv.reader(io.open(os.path.join(out_root, group, name),
                                       encoding="utf-8-sig")))
        header = rows[2]
        assert "Corroboration (NHI)" in header
        col = header.index("Corroboration (NHI)")
        idcol = header.index("Finding ID")
        for r in rows[3:]:
            if not r or not r[idcol].strip():
                continue
            value = r[col].strip() if len(r) > col else ""
            if group == NHI:
                continue  # NHI may corroborate any row
            assert not value, "%s row %s has corroboration: %s" % (group, r[idcol], value)
            assert not r[idcol].startswith("AZ_LC_")


def test_excel_findings_register_keeps_status_and_adds_corroboration(generated):
    openpyxl = pytest.importorskip("openpyxl")
    summary, out_root = generated
    for group in GROUP_ORDER:
        name = [n for n in summary[group]["artifacts"] if n.endswith(".xlsx")][0]
        ws = openpyxl.load_workbook(
            os.path.join(out_root, group, name))["Findings Register"]
        header = [c.value for c in ws[3]]
        assert "Status" in header
        assert header.index("Status") + 1 == 19, "Status must stay in column R"
        assert "Corroboration (NHI)" in header
        assert header.index("Corroboration (NHI)") + 1 == len(header)
        if group != NHI:
            col = header.index("Corroboration (NHI)") + 1
            for row in ws.iter_rows(min_row=4, min_col=col, max_col=col):
                assert not (row[0].value or "").strip()


def test_evidence_json_carries_correlation_only_for_nhi(generated):
    summary, out_root = generated
    for group in GROUP_ORDER:
        name = [n for n in summary[group]["artifacts"] if n.endswith(".json")][0]
        doc = json.load(io.open(os.path.join(out_root, group, name),
                                encoding="utf-8"))
        assert doc["findings"]
        corr = [f for f in doc["findings"] if "nhi_correlation" in f]
        life = [f for f in doc["findings"]
                if str(f.get("id", "")).startswith("AZ_LC_")]
        if group == NHI:
            assert corr and life
        else:
            assert not corr, "%s leaked correlation" % group
            assert not life, "%s leaked lifecycle findings" % group


def test_exports_are_repeatable(generated, tmp_path):
    """Regeneration must overwrite in place, which is where Windows AV locks
    used to raise PermissionError."""
    _, out_root = generated
    before = {g: sorted(os.listdir(os.path.join(out_root, g))) for g in GROUP_ORDER}
    gpr.generate(client_name="1st_Client", out_root=out_root, verbose=False)
    after = {g: sorted(os.listdir(os.path.join(out_root, g))) for g in GROUP_ORDER}
    assert before == after
    assert not [f for g in GROUP_ORDER
                for f in os.listdir(os.path.join(out_root, g))
                if ".part" in f], "temp files left behind"


def test_atomic_export_preserves_extension_and_cleans_up(tmp_path):
    target = str(tmp_path / "graph.html")
    gpr._atomic_export(lambda p: io.open(p, "w").write("<html/>"), target)
    assert io.open(target).read() == "<html/>"
    assert os.listdir(tmp_path) == ["graph.html"]


def test_atomic_export_retries_transient_permission_errors(tmp_path, monkeypatch):
    target = str(tmp_path / "report.pdf")
    state = {"n": 0}

    def flaky(path):
        state["n"] += 1
        if state["n"] < 3:
            raise PermissionError(13, "simulated AV lock")
        io.open(path, "wb").write(b"%PDF-1.4 ok")

    monkeypatch.setattr(gpr.time, "sleep", lambda s: None)
    gpr._atomic_export(flaky, target)
    assert state["n"] == 3
    assert io.open(target, "rb").read() == b"%PDF-1.4 ok"
    assert os.listdir(tmp_path) == ["report.pdf"]


def test_atomic_export_raises_after_exhausting_retries(tmp_path, monkeypatch):
    monkeypatch.setattr(gpr.time, "sleep", lambda s: None)
    with pytest.raises(PermissionError):
        gpr._atomic_export(
            lambda p: (_ for _ in ()).throw(PermissionError(13, "locked")),
            str(tmp_path / "never.pdf"))
    assert not os.path.exists(str(tmp_path / "never.pdf"))
    assert not os.path.exists(str(tmp_path / "never.part.pdf"))


def test_excel_export_receives_filepath_kwarg(generated):
    """export_excel names its destination filepath, which is why
    _atomic_export must detect the keyword rather than pass positionally."""
    import inspect
    from reporting.excel_export import export_excel
    assert "filepath" in inspect.signature(export_excel).parameters
    assert not gpr._takes_filepath(gpr.export_csv)
