import streamlit as st
import json
import os
import glob
import hashlib
import plotly.graph_objects as go
import streamlit.components.v1 as components
from datetime import datetime

from analytics.risk_engine import RiskEngine
from analytics.attack_chain import AttackChainBuilder
from analytics.finding_enrichment import enrich_finding
from analytics.graph_builder import create_attack_graph
from analytics.identity_normalizer import IdentityNormalizer
from analytics.hybrid_attack_chain import HybridAttackChain
from analytics.finding_builder import FindingBuilder
from analytics.groups import GROUPS, GROUP_ORDER
from ai.analyst import ask_ollama
from reporting.pdf_export import export_pdf
from reporting.excel_export import export_excel
from reporting.csv_export import export_csv
from reporting.json_export import export_json
from reporting.zip_package import create_zip
from reporting.ai_pdf_export import export_ai_pdf
from reporting.evidence_manager import init_evidence, add_evidence
from config import (
    DEFAULT_CLIENT_NAME, DEFAULT_ENGAGEMENT_ID, DEFAULT_ASSESSOR,
    DEFAULT_DATA_VERSION, BASE_OUTPUT_DIR,
    CLIENT_PROFILES_DIR,
    list_client_profiles, load_client_profile, save_client_profile,
    build_client_config,
    get_output_paths, list_client_output_dirs,
    save_raw_cache, load_raw_cache, find_cache_for_version, ensure_client_dirs,
)
from config import compute_env_stats, LOGO_PATH, load_source_integrity, setup_logging

setup_logging()
import logging
_log = logging.getLogger(__name__)

# ─── PAGE CONFIG ─────────────────────────────────────────────
st.set_page_config(page_title="GraphShield Hybrid Identity Security", layout="wide", page_icon="")

init_evidence()

# ─── SESSION STATE ───────────────────────────────────────────
if "findings" not in st.session_state:
    st.session_state.findings = None
    st.session_state.chains = None
    st.session_state.risk = None
    st.session_state.client_config = None
    st.session_state.data_loaded = False
    st.session_state.ai_report = None

# Track last loaded version for auto-cache detection
if "_last_data_version" not in st.session_state:
    st.session_state._last_data_version = None

# ─── SIDEBAR: Client Selection ───────────────────────────────
st.sidebar.title("Engagement")

profiles = list_client_profiles()
profile_options = ["[Manual Entry]"] + profiles
selected_profile = st.sidebar.selectbox("Client Profile", profile_options, index=0)

if selected_profile == "[Manual Entry]":
    default_name = DEFAULT_CLIENT_NAME
    default_eid = DEFAULT_ENGAGEMENT_ID
    default_ver = DEFAULT_DATA_VERSION
else:
    profile_data = load_client_profile(selected_profile)
    default_name = profile_data.get("client_name", DEFAULT_CLIENT_NAME)
    default_eid = profile_data.get("engagement_id", DEFAULT_ENGAGEMENT_ID)
    default_ver = profile_data.get("data_version", DEFAULT_DATA_VERSION)

client_name = st.sidebar.text_input("Client Name", default_name)
engagement_id = st.sidebar.text_input("Engagement ID", default_eid)
data_version = st.sidebar.text_input("Data Version", default_ver)
assessor = st.sidebar.text_input("Assessor", DEFAULT_ASSESSOR)

client_config = build_client_config(client_name, engagement_id, data_version, assessor)

# Warn if version already has report outputs
vp = get_output_paths(client_name, data_version)
reports_exist_for_version = os.path.exists(vp["report_pdf"])

if reports_exist_for_version:
    st.sidebar.warning(f"v{data_version} already has reports — saving will overwrite on next generation.")
    confirm_overwrite = st.sidebar.checkbox("I understand, overwrite existing reports", value=False,
                                            key="ver_overwrite_confirm")
else:
    confirm_overwrite = True

# Save profile button
profile_save_label = "Update Profile" if selected_profile != "[Manual Entry]" else "Save as Profile"
save_disabled = bool(reports_exist_for_version and not confirm_overwrite)
if st.sidebar.button(profile_save_label, disabled=save_disabled):
    saved = save_client_profile(client_name, engagement_id, data_version, assessor)
    if saved:
        st.sidebar.success(f"Saved: `{os.path.basename(saved)}`")
        st.rerun()
    else:
        st.sidebar.error("Failed to save profile")

st.sidebar.divider()
st.sidebar.caption(f"Active Client: **{client_config['client_name']}**")
st.sidebar.caption(f"Data Version: v{client_config['data_version']}")
st.sidebar.caption(f"Date: {datetime.now().strftime('%Y-%m-%d')}")
if LOGO_PATH and os.path.exists(LOGO_PATH):
    st.sidebar.image(LOGO_PATH, width=150)

client_dir = os.path.join(BASE_OUTPUT_DIR, client_config["client_name"])
st.sidebar.caption(f"Output: `{client_dir}`")

# Data source selection (checks main cache + backups for this version)
cached_data = find_cache_for_version(client_config["client_name"], client_config["data_version"])
raw_cache = cached_data
cached_version = cached_data.get("_data_version", "") if cached_data else ""
has_cache = cached_version == client_config["data_version"]

# Version change detection — auto-load cache when switching to a version with cache
last_ver = st.session_state._last_data_version
current_ver = client_config["data_version"]
version_changed = last_ver is not None and last_ver != current_ver
st.session_state._last_data_version = current_ver
if version_changed:
    # Clear stale session state when version changes
    st.session_state.pop("_cache_assessment_group", None)
    if has_cache:
        st.session_state.use_cache = True
    else:
        st.session_state.use_cache = False

use_cache = st.sidebar.checkbox("Use cached data", value=has_cache, key="use_cache",
                                help=f"Load from {client_config['client_name']}/raw_bloodhound.json")

# ─── Assessment Group Selector (single select) ────────────────
st.sidebar.divider()
st.sidebar.markdown("**Assessment Scope**")
if "_selected_group" not in st.session_state:
    st.session_state._selected_group = "ad_core"
_cache_group = st.session_state.get("_cache_assessment_group")
# When cache is in use and has a saved assessment group, lock scope + auto-select
if has_cache and cached_data and use_cache:
    _cached_val = cached_data.get("_assessment_group")
    if _cached_val and _cached_val in GROUP_ORDER:
        _cache_group = _cached_val
        st.session_state._selected_group = _cached_val
        st.session_state._cache_assessment_group = _cached_val
    elif _cache_group is None:
        _cache_group = "_locked"
        st.session_state._cache_assessment_group = "_locked"
_scope_disabled = bool(_cache_group) and use_cache
if _scope_disabled and _cache_group != "_locked":
    st.sidebar.caption(f"Scope locked from cache: {GROUPS[_cache_group]['name']}")
elif _scope_disabled:
    st.sidebar.caption("Scope locked — loaded from cache")
selected_group = st.sidebar.radio(
    "Select assessment scope:",
    options=GROUP_ORDER,
    format_func=lambda g: GROUPS[g]["name"],
    key="_selected_group",
    disabled=_scope_disabled,
)
# Reload from Neo4j — hidden when scope is locked (cache mode)
if not _scope_disabled:
    confirm_reload = st.session_state.get("_confirm_reload", False)
    reload_btn = st.session_state.pop("_reload_trigger", False)
    if confirm_reload:
        st.sidebar.warning("Reload from Neo4j will overwrite any cached data. Proceed?")
        c1, c2 = st.sidebar.columns(2)
        if c1.button("Yes, Reload"):
            st.session_state._confirm_reload = False
            st.session_state._reload_trigger = True
            st.rerun()
        if c2.button("Cancel"):
            st.session_state._confirm_reload = False
            st.rerun()
    elif st.sidebar.button("Reload from Neo4j"):
        if has_cache:
            st.session_state._confirm_reload = True
            st.rerun()
        else:
            st.session_state._reload_trigger = True
            st.rerun()
else:
    reload_btn = False
    st.session_state.pop("_reload_trigger", None)
    st.session_state.pop("_confirm_reload", None)

if st.sidebar.button("Change Neo4j Config"):
    from config import _get_neo4j_cred_path
    path = _get_neo4j_cred_path()
    if os.path.exists(path):
        os.remove(path)
        st.info("Cleared saved Neo4j config")
    st.rerun()

# ─── Data Source Integrity (File Upload) ──────────────────────

# Initialize session state for file metadata
if "file_metadata" not in st.session_state:
    st.session_state.file_metadata = {
        "sh_sha256": None, "sh_method": None, "sh_timestamp": None,
        "ah_sha256": None, "ah_method": None, "ah_timestamp": None,
    }


using_cache = bool(use_cache and has_cache) or (version_changed and has_cache)

if using_cache:
    # Cache mode — no upload needed; integrity restored from cache in data pipeline
    st.sidebar.markdown("**Data Source Integrity**")
    cached_si = st.session_state.file_metadata
    if cached_si.get("sh_sha256") or cached_si.get("ah_sha256"):
        st.sidebar.caption("Using cached source integrity")
        items = []
        if cached_si["sh_sha256"]:
            items.append(f"SH: {cached_si['sh_sha256'][:12]}...")
        if cached_si["ah_sha256"]:
            items.append(f"AH: {cached_si['ah_sha256'][:12]}...")
        st.sidebar.caption(" | ".join(items))
    else:
        st.sidebar.caption("No source integrity in cache — "
                           "reload from Neo4j without cache to upload files")
else:
    # Fresh mode — require file upload
    st.sidebar.markdown("**Data Source Integrity**")
    st.sidebar.caption("Upload original OG Files to capture SHA-256 + collection method in the report")

    from config import process_sharphound_zip, process_azurehound_zip

    sh_zip = st.sidebar.file_uploader("SharpHound ZIP/JSON", type=["zip", "json"],
                                      help="Original SharpHound output ZIP or extracted metadata JSON")
    ah_zip = st.sidebar.file_uploader("AzureHound ZIP/JSON", type=["zip", "json"],
                                      help="Original AzureHound output file (computes SHA-256)")
    lf_feed = st.sidebar.file_uploader("NHI Lifecycle Feed (JSON)", type=["json"],
                                       help="Optional Entra NHI sign-in/audit-log feed JSON. "
                                            "no feed → no lifecycle findings")

    # When version changed to a cacheless version, ignore stale uploads
    # (file_uploaders persist across reruns within the same browser session)
    _stale_upload = version_changed and not has_cache
    if _stale_upload:
        for k in st.session_state.file_metadata:
            st.session_state.file_metadata[k] = None
    else:
        if sh_zip is None and ah_zip is None:
            for k in st.session_state.file_metadata:
                st.session_state.file_metadata[k] = None

        if sh_zip is not None:
            sh_bytes = sh_zip.getvalue()
            sh_sha256, sh_method, sh_ts = process_sharphound_zip(sh_bytes, filename=sh_zip.name)
            st.session_state.file_metadata["sh_sha256"] = sh_sha256
            st.session_state.file_metadata["sh_method"] = sh_method
            st.session_state.file_metadata["sh_timestamp"] = sh_ts
            client_config["sharphound_sha256"] = sh_sha256
            if sh_method:
                client_config["sharphound_collection_method"] = sh_method
            if sh_ts:
                client_config["sharphound_timestamp"] = sh_ts
                client_config["collection_timestamp"] = sh_ts
            parts = [f"SHA-256: {sh_sha256[:12]}..."]
            if sh_method:
                parts.append(f"method: {sh_method}")
            if sh_ts:
                parts.append(f"collected: {sh_ts[:10]}")
            st.sidebar.success("SharpHound: " + " | ".join(parts))

        if ah_zip is not None:
            ah_bytes = ah_zip.getvalue()
            ah_sha256, ah_method, ah_ts = process_azurehound_zip(ah_bytes)
            st.session_state.file_metadata["ah_sha256"] = ah_sha256
            st.session_state.file_metadata["ah_method"] = ah_method
            st.session_state.file_metadata["ah_timestamp"] = ah_ts
            client_config["azurehound_sha256"] = ah_sha256
            if ah_method:
                client_config["azurehound_collection_method"] = ah_method
            if ah_ts:
                client_config["azurehound_timestamp"] = ah_ts
                if not client_config.get("collection_timestamp"):
                    client_config["collection_timestamp"] = ah_ts
            parts = [f"SHA-256: {ah_sha256[:12]}..."]
            if ah_method:
                parts.append(f"method: {ah_method}")
            if ah_ts:
                parts.append(f"collected: {ah_ts[:10]}")
            st.sidebar.success("AzureHound: " + " | ".join(parts))

        # NHI lifecycle feed — persist like reloaded Neo4j data (SHA-256 +
        # method + timestamp in the client/version cache, restored on rerun).
        # No upload -> lifecycle_feed stays unset -> deterministic no-op.
        if lf_feed is not None:
            lf_bytes = lf_feed.getvalue()
            try:
                lf_evidence_raw = json.loads(lf_bytes.decode("utf-8"))
            except Exception:
                lf_evidence_raw = None
                st.sidebar.error("Lifecycle feed: not valid JSON")
            if lf_evidence_raw is not None:
                from analytics.nhi_lifecycle import load_lifecycle_feed
                from config import save_lifecycle_feed_cache
                lf_sha256 = hashlib.sha256(lf_bytes).hexdigest()
                lf_ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                lf_evidence = load_lifecycle_feed(lf_evidence_raw)
                save_lifecycle_feed_cache(
                    client_config["client_name"], client_config["data_version"],
                    lf_evidence,
                    metadata={
                        "nhil_sha256": lf_sha256,
                        "nhil_method": lf_feed.name,
                        "nhil_timestamp": lf_ts,
                    },
                )
                st.session_state.file_metadata["nhil_sha256"] = lf_sha256
                st.session_state.file_metadata["nhil_method"] = lf_feed.name
                st.session_state.file_metadata["nhil_timestamp"] = lf_ts
                client_config["nhil_sha256"] = lf_sha256
                client_config["nhil_collection_method"] = lf_feed.name
                client_config["nhil_timestamp"] = lf_ts
                st.sidebar.success("Lifecycle feed: " + " | ".join([
                    f"SHA-256: {lf_sha256[:12]}...",
                    f"method: {lf_feed.name[:20]}",
                ]))

        # Persist file metadata to disk per version
        from config import save_source_integrity
        if sh_zip is not None or ah_zip is not None:
            save_source_integrity(
                client_config["client_name"],
                client_config["data_version"],
                {
                    "sh_sha256": st.session_state.file_metadata.get("sh_sha256"),
                    "sh_method": st.session_state.file_metadata.get("sh_method"),
                    "sh_timestamp": st.session_state.file_metadata.get("sh_timestamp"),
                    "ah_sha256": st.session_state.file_metadata.get("ah_sha256"),
                    "ah_method": st.session_state.file_metadata.get("ah_method"),
                    "ah_timestamp": st.session_state.file_metadata.get("ah_timestamp"),
                }
            )



# ─── MAIN ─────────────────────────────────────────────────────
st.title(f"{client_config['assessor']}")
st.caption(f"Engagement: {client_config['client_name']} | ID: {client_config['engagement_id']} | Data v{client_config['data_version']}")
st.caption("GraphShield Hybrid Identity Security Assessment Platform")

# ─── DATA LOADING ────────────────────────────────────────────
if st.session_state.findings is None or reload_btn or version_changed:
    st.session_state.data_loaded = False
    st.session_state.findings = None
    st.session_state.chains = None
    st.session_state.risk = None

    raw = {}

    # Try per-client cache first
    should_use_cache = use_cache or (version_changed and has_cache)
    if should_use_cache and has_cache:
        st.info(f"Auto-loaded cached data for v{current_ver}")
        _log.info("Loading cache client=%s version=%s", client_config["client_name"], client_config["data_version"])
        with st.spinner(f"Loading cached data for {client_config['client_name']}..."):
            raw = cached_data or load_raw_cache(client_config["client_name"])
        if raw:
            cached_ver = raw.get("_data_version", "?")
            cached_group = raw.get("_assessment_group")
            if cached_group and cached_group in GROUP_ORDER:
                st.session_state._cache_assessment_group = cached_group
                _log.info("Assessment scope restored from cache: %s", cached_group)
            elif not st.session_state.get("_cache_assessment_group"):
                st.session_state._cache_assessment_group = "_locked"
            st.success(f"Loaded cached data ({sum(len(v) for v in raw.values() if isinstance(v, (list, dict))) if isinstance(raw, dict) else 0} records)")
            _log.info("Cache loaded client=%s cached_version=%s", client_config["client_name"], cached_ver)
        # Restore source integrity metadata from disk (versioned)
        si = load_source_integrity(client_config["client_name"], client_config["data_version"])
        if si.get("sh_sha256"):
            st.session_state.file_metadata["sh_sha256"] = si["sh_sha256"]
            st.session_state.file_metadata["sh_method"] = si.get("sh_method")
            st.session_state.file_metadata["sh_timestamp"] = si.get("sh_timestamp")
            client_config["sharphound_sha256"] = si["sh_sha256"]
            if si.get("sh_method"):
                client_config["sharphound_collection_method"] = si["sh_method"]
            if si.get("sh_timestamp"):
                client_config["sharphound_timestamp"] = si["sh_timestamp"]
        else:
            # Version mismatch or no integrity — clear stale file_metadata from previous version
            st.session_state.file_metadata["sh_sha256"] = None
            st.session_state.file_metadata["sh_method"] = None
            st.session_state.file_metadata["sh_timestamp"] = None
        if si.get("ah_sha256"):
            st.session_state.file_metadata["ah_sha256"] = si["ah_sha256"]
            st.session_state.file_metadata["ah_method"] = si.get("ah_method")
            st.session_state.file_metadata["ah_timestamp"] = si.get("ah_timestamp")
            client_config["azurehound_sha256"] = si["ah_sha256"]
            if si.get("ah_method"):
                client_config["azurehound_collection_method"] = si["ah_method"]
            if si.get("ah_timestamp"):
                client_config["azurehound_timestamp"] = si["ah_timestamp"]
        else:
            st.session_state.file_metadata["ah_sha256"] = None
            st.session_state.file_metadata["ah_method"] = None
            st.session_state.file_metadata["ah_timestamp"] = None

    # Only connect to Neo4j on explicit "Reload from Neo4j" click
    if reload_btn:
        st.session_state.pop("_cache_assessment_group", None)
        import neo4j.exceptions
        from collectors.neo4j_collector import BloodHoundCollector, test_connection
        from config import get_neo4j_config, save_neo4j_credentials

        neo4j_uri, neo4j_user, neo4j_pass = get_neo4j_config()
        ok, err = test_connection(neo4j_uri, neo4j_user, neo4j_pass)

        if not ok:
            st.error(f"Neo4j connection failed: {err}")
            with st.expander("Configure Neo4j Connection", expanded=True):
                with st.form("neo4j_config"):
                    c1, c2 = st.columns(2)
                    with c1:
                        uri = st.text_input("Neo4j URI", value=neo4j_uri)
                        password = st.text_input("Password", type="password")
                    with c2:
                        user = st.text_input("Username", value=neo4j_user)
                    if st.form_submit_button("Connect"):
                        ok2, err2 = test_connection(uri, user, password)
                        if ok2:
                            save_neo4j_credentials(uri, user, password)
                            st.success("Connected! Reloading...")
                            st.rerun()
                        else:
                            st.error(f"Failed: {err2}")

            fallback = find_cache_for_version(client_config["client_name"], client_config["data_version"])
            if fallback:
                raw = fallback
                fb_group = raw.get("_assessment_group")
                if fb_group and fb_group in GROUP_ORDER:
                    st.session_state._cache_assessment_group = fb_group
                else:
                    st.session_state._cache_assessment_group = "_locked"
                st.warning("Falling back to cached data")
            else:
                st.info("No cached data. Enter Neo4j credentials above to connect.")
                st.stop()
        else:
            collector = BloodHoundCollector(neo4j_uri, neo4j_user, neo4j_pass)
            _log.info("Neo4j collection starting client=%s version=%s group=%s", client_config["client_name"], client_config["data_version"], selected_group)
            with st.spinner("Collecting BloodHound data..."):
                try:
                    raw = collector.collect(selected_groups=[selected_group])
                    # Inject uploaded file integrity directly into fresh data
                    fm = st.session_state.file_metadata
                    if fm.get("sh_sha256") or fm.get("ah_sha256"):
                        raw["_source_integrity"] = {
                            "sh_sha256": fm.get("sh_sha256"),
                            "sh_method": fm.get("sh_method"),
                            "sh_timestamp": fm.get("sh_timestamp"),
                            "ah_sha256": fm.get("ah_sha256"),
                            "ah_method": fm.get("ah_method"),
                            "ah_timestamp": fm.get("ah_timestamp"),
                        }
                    if collector.errors:
                        _log.warning("Neo4j query errors: %d", len(collector.errors))
                        with st.expander(f"Query Errors ({len(collector.errors)})", expanded=False):
                            for err in collector.errors:
                                st.caption(err)
                    save_raw_cache(client_config["client_name"], client_config["data_version"], raw, assessment_group=selected_group)
                    raw = find_cache_for_version(client_config["client_name"], client_config["data_version"]) or raw
                    _log.info("Neo4j collection complete client=%s", client_config["client_name"])
                    st.success(f"Collected fresh data ({sum(len(v) for v in raw.values() if isinstance(v, (list, dict))) if isinstance(raw, dict) else 0} records)")
                except neo4j.exceptions.ServiceUnavailable as e:
                    _log.error("Neo4j unavailable: %s", e)
                    st.error(f"Neo4j server unavailable: {e}")
                    fallback = find_cache_for_version(client_config["client_name"], client_config["data_version"])
                    if fallback:
                        raw = fallback
                        fb_group = raw.get("_assessment_group")
                        if fb_group and fb_group in GROUP_ORDER:
                            st.session_state._cache_assessment_group = fb_group
                        else:
                            st.session_state._cache_assessment_group = "_locked"
                        st.warning("Falling back to cached data")
                    else:
                        st.stop()
                except neo4j.exceptions.AuthError as e:
                    _log.error("Neo4j auth failed: %s", e)
                    st.error(f"Neo4j authentication failed: {e}")
                    st.stop()
                except Exception as e:
                    _log.error("Neo4j collection failed: %s", e)
                    st.error(f"Collection failed: {e}")
                    fallback = find_cache_for_version(client_config["client_name"], client_config["data_version"])
                    if fallback:
                        raw = fallback
                        fb_group = raw.get("_assessment_group")
                        if fb_group and fb_group in GROUP_ORDER:
                            st.session_state._cache_assessment_group = fb_group
                        else:
                            st.session_state._cache_assessment_group = "_locked"
                        st.warning("Falling back to cached data")
                    else:
                        st.stop()
                finally:
                    try:
                        collector.close()
                    except Exception:
                        pass

    if not raw:
        st.info("Click **Reload from Neo4j** in the sidebar to fetch data.")
        st.stop()

    # ─── Analysis Pipeline ────────────────────────────────────
    builder = FindingBuilder()
    findings = builder.build(raw, selected_groups=[selected_group])
    findings = [enrich_finding(f, raw) for f in findings]
    findings = IdentityNormalizer().normalize(findings)

    # ─── NHI lifecycle feed (phase NHI-2, deterministic no-op) ────
    # Optional ENTRA_DIR sign-in/audit feed (env GRAPH_SHIELD_LIFECYCLE_FEED
    # → path/glob/JSON). When absent → load_lifecycle_feed returns {} →
    # build_lifecycle_findings returns [] → the 80-finding baseline, the
    # 154-test deterministic suite, and all exporters are untouched.
    # When present → appends the feed-gated NHI lifecycle findings
    # (pre-enriched, exporter-ready) to the normalized set.
    # NHI lifecycle block: env env var → path/glob/JSON. Deterministic no-op:
    # GRAPH_SHIELD_LIFECYCLE_FEED absent (or empty/bad) → load_lifecycle_feed
    # returns {} → build_lifecycle_findings([]) → [] → the 80-finding
    # baseline is untouched. When present → appends the feed-gated NHI
    # lifecycle governance findings (NHI-2, exporter-ready).
    lifecycle_evidence = {}
    nhi_correlation = {}
    lifecycle_feed = os.environ.get("GRAPH_SHIELD_LIFECYCLE_FEED", "").strip()
    if not lifecycle_feed:
        # Rerun restore: rehydrate the feed from the per-client cache
        # (persisted by save_lifecycle_feed_cache) — mirrors how reloaded
        # Neo4j data is restored on a cached rerun.
        from config import load_lifecycle_feed_cache as _lf_restore
        _feed = _lf_restore(client_config["client_name"])
        if _feed:
            lifecycle_feed = ("__nhi_cache__", _feed)
    if lifecycle_feed:
        try:
            from analytics.nhi_lifecycle import (
                load_lifecycle_feed, build_lifecycle_findings,
            )
            lifecycle_evidence = load_lifecycle_feed(lifecycle_feed)
            if lifecycle_evidence:
                # Graph-derived NHI governance findings (AZ-041->AZ-054) and
                # feed-derived lifecycle findings (AZ-055->AZ-062) are
                # complementary: the graph proves ownership/privilege posture,
                # the logs prove temporal/behavioral lifecycle. Concatenating
                # them would show one identity as unrelated findings, so bind
                # them per workload identity (AppId / display name) before the
                # risk + chain stages see the combined set.
                from analytics.nhi_lifecycle import (
                    correlate_nhi_sources as _correlate_nhi,
                )
                _nhi_feed_findings = build_lifecycle_findings(lifecycle_evidence)
                findings = findings + _nhi_feed_findings
                _correlate_nhi(findings, lifecycle_evidence, nhi_correlation)
        except Exception:
            pass  # deterministic no-op on any feed/adapter failure

    for f in findings:
        f["ad_objects"] = f.get("ad_objects", {
            "users": [], "groups": [], "computers": [],
            "gpos": [], "organizational_units": [], "relationships": []
        })

    # Sort findings by ID for deterministic ordering
    id_order = {
        "TIER0_PATHS": 0, "ENTERPRISE_ADMIN_PATHS": 1,
        "KERBEROAST": 2, "ASREP_ROAST": 3,
        "DELEGATION": 4, "ADMIN_TO": 5,
        "DACL_ABUSE": 6, "GPO_CONTROL": 7,
        "SID_HISTORY": 8, "DCSYNC": 9,
        "CONSTRAINED_DELEGATION": 10, "RBCD": 11,
        "PASSWORD_NOT_REQUIRED": 12, "REVERSIBLE_ENCRYPTION": 13,
        "ACCOUNT_OPERATORS": 14, "CROSS_FOREST": 15,
        "PRIVILEGED_GROUPS": 16, "DISABLED_PRIVILEGED": 17,
        # Azure findings (sorted after AD)
        "AZ_GLOBAL_ADMIN": 18, "AZ_PRIVILEGED_ROLE_ADMIN": 19,
        "AZ_HYBRID_IDENTITY_ADMIN": 20, "AZ_APPLICATION_ADMIN": 21,
        "AZ_CLOUD_APP_ADMIN": 22, "AZ_CONDITIONAL_ACCESS_ADMIN": 23,
        "AZ_PRIVILEGED_AUTH_ADMIN": 24, "AZ_SECURITY_ADMIN": 25,
        "AZ_USER_ACCESS_ADMIN": 26, "AZ_ADD_SECRET": 27,
        "AZ_ADD_OWNER": 28, "AZ_ADD_TO_GROUP": 29,
        "AZ_CONTRIBUTOR": 30, "AZ_OWNER": 31,
        "AZ_KEY_VAULT_ABUSE": 32, "AZ_MANAGED_IDENTITY": 33,
        "AZ_EXTERNAL_USER": 34, "AZ_EXECUTE_COMMAND": 35,
        "AZ_RESET_PASSWORD": 36, "AZ_ROLE_ESCALATION": 37,
    }
    findings.sort(key=lambda f: (id_order.get(f.get("id", ""), 99), f.get("source", "")))

    # ─── Report title from selected group ──────────────────────
    report_title = GROUPS[selected_group]["report_title"]
    client_config["report_title"] = report_title

    # Risk & Attack Chains
    active_evidence = [f for f in findings if f.get("has_evidence", False)]
    risk = RiskEngine().calculate(active_evidence)

    ad_chains = AttackChainBuilder(findings).build()
    hybrid_chains = HybridAttackChain().analyze(findings)
    chains = ad_chains + hybrid_chains

    for c in chains:
        c["ad_objects"] = c.get("ad_objects", {
            "users": [], "groups": [], "computers": [],
            "gpos": [], "organizational_units": [], "relationships": []
        })
        c["mitre"] = c.get("mitre", {}) or {}

    # Ensure client output directories exist
    ensure_client_dirs(client_config["client_name"], client_config["data_version"])

    # Enrich client_config with data source metadata
    # Use actual file collection timestamp when available; fallback to now
    if not client_config.get("collection_timestamp"):
        file_ts = client_config.get("sharphound_timestamp") or client_config.get("azurehound_timestamp")
        client_config["collection_timestamp"] = file_ts or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    if use_cache and has_cache:
        client_config["data_source_type"] = "Cached JSON"
    else:
        client_config["data_source_type"] = "Neo4j Graph Database"
    # Collection method comes ONLY from uploaded file metadata, never inferred.
    # If no files uploaded, report will show "Not applicable (Neo4j direct connection)".

    # Store in session state
    st.session_state.findings = findings
    st.session_state.chains = chains
    st.session_state.risk = risk
    st.session_state.client_config = client_config
    st.session_state.raw = raw
    st.session_state.data_loaded = True

# Read from session state
findings = st.session_state.findings
chains = st.session_state.chains
risk = st.session_state.risk
client_config = st.session_state.client_config

if not findings:
    st.warning("No data loaded. Configure client in sidebar and ensure Neo4j is accessible.")
    st.stop()

# Rebuild output_paths in case they changed
output_paths = get_output_paths(client_config["client_name"], client_config["data_version"])
ensure_client_dirs(client_config["client_name"], client_config["data_version"])

# ─── DEDUPLICATE FINDINGS ─────────────────────────────────────
seen_ids = set()
deduped = []
for f in findings:
    fid = f.get("id", "")
    if fid not in seen_ids:
        seen_ids.add(fid)
        deduped.append(f)
    else:
        has_ev = f.get("has_evidence", False)
        existing_ev = any(x.get("has_evidence", False) for x in deduped if x.get("id") == fid)
        if has_ev and not existing_ev:
            for i, x in enumerate(deduped):
                if x.get("id") == fid:
                    deduped[i] = f
                    break
findings = deduped

# ─── DEDUPLICATE CHAINS ──────────────────────────────────────
seen_chain_paths = set()
deduped_chains = []
for c in chains:
    path = c.get("attack_path", "")
    if path not in seen_chain_paths:
        seen_chain_paths.add(path)
        deduped_chains.append(c)
chains = deduped_chains

# ─── METRICS ─────────────────────────────────────────────────
active_findings = [f for f in findings if f.get("has_evidence", False)]
critical = sum(1 for x in active_findings if x["severity"] == "CRITICAL")
high = sum(1 for x in active_findings if x["severity"] == "HIGH")
medium = sum(1 for x in active_findings if x["severity"] == "MEDIUM")

raw_data = st.session_state.get("raw", {})
env_stats = compute_env_stats(findings, chains, risk, raw=raw_data)

col1, col2, col3, col4, col5, col6 = st.columns(6)
col1.metric("Critical", env_stats["critical_findings"])
col2.metric("High", env_stats["high_findings"])
col3.metric("Attack Paths", env_stats["attack_paths"])
col4.metric("Affected Accounts", env_stats["affected_accounts"])
col5.metric("Tier-0 Exposure", env_stats["tier0_exposure"])
col6.metric("DCSync Exposure", env_stats["dcsync_exposure"])

risk_score = min(risk.get("total_score", 0), 100)

fig = go.Figure(go.Indicator(
    mode="gauge+number",
    value=risk_score,
    title={"text": "Risk Score"},
    gauge={
        "axis": {"range": [0, 100]},
        "steps": [
            {"range": [0, 30], "color": "green"},
            {"range": [30, 70], "color": "orange"},
            {"range": [70, 100], "color": "red"}
        ]
    }
))
st.plotly_chart(fig, use_container_width=True)

# ─── Per-identity NHI lifecycle dashboard (feed-gated) ──────────
# Renders only when a lifecycle feed supplied evidence; no feed -> nothing
# rendered here, baseline untouched. Rows come from the module's
# lifecycle_dashboard_rows() (deterministic, sorted by identity).
try:
    from analytics.nhi_lifecycle import lifecycle_dashboard_rows
    _nhi_rows = lifecycle_dashboard_rows(
        lifecycle_evidence, nhi_correlation)
except Exception:
    _nhi_rows = []
if _nhi_rows:
    _nhi_total_signins = sum(int(r.get("sign_in_count") or 0) for r in _nhi_rows)
    _nhi_staged = [r for r in _nhi_rows if r.get("lifecycle_stages") not in (None, "", "-")]
    st.divider()
    st.header("NHI Lifecycle Dashboard")
    _nhi_both = [r for r in _nhi_rows
                 if r.get("confirmed_by_both_sources") == "Yes"]
    st.caption(
        f"{len(_nhi_rows)} workload identities | {_nhi_total_signins} sign-in events | "
        f"{len(_nhi_staged)} with lifecycle-stage signals | "
        f"{len(_nhi_both)} confirmed by both Neo4j and logs"
    )
    st.dataframe(
        _nhi_rows,
        use_container_width=True,
        hide_index=True,
        column_config={
            "identity": "Workload Identity",
            "last_sign_in": "Last Sign-In",
            "sign_in_count": "Sign-Ins",
            "activity_period_days": "Activity (days)",
            "auth_flavor": "Credential Type",
            "lifecycle_stages": "Lifecycle Stages",
            "attestation": "Attestation",
            "rotation": "Rotation",
            "onboarding": "Onboarding",
            "cross_source": "Cross-Source",
            "graph_findings": "Graph NHI Findings",
            "confirmed_by_both_sources": "Both Sources",
        },
    )

# ─── AI EXECUTIVE SUMMARY ────────────────────────────────────
st.divider()
col1, col2 = st.columns([3, 1])
with col1:
    st.header("AI Executive Assessment")
with col2:
    st.caption(f"v{client_config['data_version']} | {datetime.now().strftime('%Y-%m-%d')}")

if st.button("Generate CISO Summary"):
    with st.spinner("AI analysing findings..."):
        ai_report = ask_ollama(findings, chains, risk)
        st.session_state.ai_report = ai_report
        export_ai_pdf(ai_report, output_paths["ai_report_pdf"],
                      findings=findings, chains=chains, risk=risk, env_stats=env_stats,
                      client_config=client_config, report_title=client_config.get("report_title", ""))
        st.success(f"AI Executive PDF created: {os.path.basename(output_paths['ai_report_pdf'])}")

if st.session_state.get("ai_report"):
    st.write(st.session_state.ai_report)

# ─── FINDINGS DISPLAY ───────────────────────────────────────
def render_html_box(title, items, icon, color):
    with st.expander(f"{icon} {title} ({len(items)})", expanded=True):
        if len(items) < 15:
            for item in items:
                st.markdown(f"* `{item}`")
        else:
            li = "".join([f"<li style='margin-bottom:6px;font-family:monospace;font-size:13px;color:{color};'>{x}</li>" for x in items])
            st.markdown(
                f'<div style="max-height:280px;overflow-y:auto;border:1px solid #4A4A4A;padding:15px;border-radius:6px;background-color:#111111;"><ul style="margin:0;padding-left:20px;">{li}</ul></div>',
                unsafe_allow_html=True
            )

st.divider()
st.header("Detailed Security Findings")

has_any = any(f.get("has_evidence", False) for f in findings)
if not has_any:
    st.warning("No active findings with evidence. Reference-only findings shown below. Connect to Neo4j to populate with real data.")

ad_i = 0
az_i = 0
for f in findings:
    has_ev = f.get("has_evidence", False)
    sev_icon = {"CRITICAL": "", "HIGH": "", "MEDIUM": "", "LOW": ""}.get(f["severity"], "")
    mitre = f.get("mitre") or {}
    if f.get("source") == "Azure":
        az_i += 1
        fid = f"AZ-{az_i:03d}"
    else:
        ad_i += 1
        fid = f"AD-{ad_i:03d}"

    display_title = f["title"].split("|")[-1].strip().upper().replace("_", " ")
    label = f"{sev_icon} {fid} | {f['severity']} | {display_title}"
    if not has_ev:
        label += " [NO DATA]"
    st.subheader(label)

    confidence = f.get("confidence", "No Data")
    conf_color = {"Confirmed": "green", "Informational": "orange", "No Data": "gray"}.get(confidence, "gray")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("MITRE Technique", mitre.get("id", "-"), mitre.get("technique", "-"))
    m2.metric("Tactical Phase", mitre.get("tactic", "-"))
    m3.metric("Scope", f.get("source", "Active Directory"))
    m4.markdown(f"**Confidence**<br/><span style='color:{conf_color};font-weight:bold'>{confidence}</span>", unsafe_allow_html=True)
    truncated = f.get("truncated", False)
    if truncated:
        st.caption("⚠️ Over 5,000 results — showing top findings. See impact note for details.")

    tabs = st.tabs(["Business Impact", "Remediation", "Compliance", "Targeted Assets"])

    with tabs[0]:
        st.markdown("### Risk & Impact Analysis")
        st.info(f.get("impact", "No impact information."))
        if not has_ev:
            st.caption("No evidence detected. Apply remediation proactively.")
        if f.get("detection"):
            st.markdown("#### Detection Strategies")
            for d in f["detection"]:
                st.markdown(f"* `{d}`")

    with tabs[1]:
        st.markdown("### Remediation Steps")
        rem = f.get("remediation", [])
        if rem:
            for r in rem:
                st.success(f"  {r}")
        else:
            st.caption("No remediation plan for this finding.")

    with tabs[2]:
        st.markdown("### Compliance Mapping")
        comp = f.get("compliance", {})
        if comp:
            for fw, ctrl in comp.items():
                st.markdown(f"* **{fw}**: `{ctrl}`")
        else:
            st.caption("No compliance mapping available.")

    with tabs[3]:
        st.markdown("### Targeted Assets")
        ad_obj = f.get("ad_objects", {})
        has_el = any(len(ad_obj.get(k, [])) > 0 for k in ["users", "groups", "computers", "gpos", "organizational_units", "service_principals", "managed_identities", "applications", "key_vaults", "tenants", "relationships"])
        if not has_el:
            st.warning("No assets mapped.")
        else:
            for cat, label_text, icon_text in [
                ("users", "Exposed Users", ""),
                ("groups", "Vulnerable Groups", ""),
                ("service_principals", "Service Principals", ""),
                ("managed_identities", "Managed Identities", ""),
                ("applications", "Applications", ""),
                ("key_vaults", "Key Vaults", ""),
                ("tenants", "Tenants", ""),
                ("computers", "Compromised Hosts", ""),
                ("gpos", "Affected GPOs", ""),
                ("organizational_units", "Affected OUs", ""),
            ]:
                items = ad_obj.get(cat, [])
                if items:
                    cleaned = [f"Object ID ({x.split(' ')[-1]})" if cat == "computers" and "S-1-5-21" in x else x for x in items]
                    render_html_box(label_text, cleaned, icon_text, "#E0E0E0")
            rels = ad_obj.get("relationships", [])
            if rels:
                st.markdown("#### Attack Paths")
                st.code("\n".join(rels))

    st.markdown("#### Evidence Upload")
    uploaded = st.file_uploader("Attach screenshot / log", key=f"ev_{fid}")
    if uploaded:
        saved = add_evidence(fid, uploaded)
        st.success(saved)
    st.write("---")

# ─── ATTACK GRAPH ────────────────────────────────────────────
st.divider()
st.header("Attack Path Visualization")

if chains:
    os.makedirs(os.path.dirname(output_paths["attack_graph_html"]), exist_ok=True)
    create_attack_graph(chains, output_paths["attack_graph_html"])
    if os.path.exists(output_paths["attack_graph_html"]):
        with open(output_paths["attack_graph_html"], encoding="utf-8") as f:
            components.html(f.read(), height=750, scrolling=True)

# ─── ATTACK CHAINS ───────────────────────────────────────────
st.header("Evaluated Attack Chains")

for c in chains:
    c = dict(c)
    st.error(f" {c['severity']} Risk Matrix | {c['risk']}")
    st.code(c["attack_path"])

    ad_obj = c.get("ad_objects", {})
    has_assets = any(len(ad_obj.get(k, [])) > 0 for k in ["users", "groups", "computers", "gpos", "organizational_units", "service_principals", "managed_identities", "applications", "key_vaults", "tenants"])
    if has_assets:
        with st.expander("View Assets in this Chain", expanded=False):
            ca, cb, cc, cd, ce = st.columns(5)
            for col, cat, label in [
                (ca, "users", "Users"),
                (cb, "groups", "Groups"),
                (cc, "service_principals", "SPs"),
                (cd, "managed_identities", "MIs"),
                (ce, "tenants", "Tenants"),
            ]:
                items = ad_obj.get(cat, [])
                if items:
                    if len(items) < 10:
                        col.markdown(f"**{label}:**\n" + "\n".join([f"* `{x}`" for x in items]))
                    else:
                        tags = "".join([f"<li style='margin-bottom:4px;font-family:monospace;font-size:12px;color:#E0E0E0;'>{x}</li>" for x in items])
                        col.markdown(
                            f"**{label} ({len(items)}):**\n<div style='max-height:200px;overflow-y:auto;border:1px solid #4A4A4A;padding:10px;border-radius:4px;background-color:#111111;'><ul style='margin:0;padding-left:15px;'>{tags}</ul></div>",
                            unsafe_allow_html=True
                        )
    st.write("---")

st.subheader("Risk Assessment")
_has_ad_risk = any(f.get("source") != "Azure" for f in findings)
_has_az_risk = any(f.get("source") == "Azure" for f in findings)
_risk_cols = [_has_ad_risk, _has_az_risk].count(True) + 1
_cols = st.columns(_risk_cols)
_col_idx = 0
if _has_ad_risk:
    _cols[_col_idx].metric("AD Risk", risk.get("ad_score", 0))
    _col_idx += 1
if _has_az_risk:
    _cols[_col_idx].metric("Entra Risk", risk.get("cloud_score", 0))
    _col_idx += 1
_cols[_col_idx].metric("Overall", risk.get("rating", "MEDIUM"))

# ─── Reports Section (MUST be after data loading so findings_ready is accurate) ──
with st.sidebar:
    st.divider()
    st.markdown("**Reports**")

    findings_ready = st.session_state.get("findings") is not None
    if findings_ready:
        findings = st.session_state.findings
        chains = st.session_state.chains
        risk = st.session_state.risk
        p = get_output_paths(client_config["client_name"], client_config["data_version"])

        # Restore source integrity from disk (version-checked via load_source_integrity)
        si = load_source_integrity(client_config["client_name"], client_config["data_version"])
        if si.get("sh_sha256"):
            client_config["sharphound_sha256"] = si["sh_sha256"]
        if si.get("sh_method"):
            client_config["sharphound_collection_method"] = si["sh_method"]
        if si.get("sh_timestamp"):
            client_config["sharphound_timestamp"] = si["sh_timestamp"]
        if si.get("ah_sha256"):
            client_config["azurehound_sha256"] = si["ah_sha256"]
        if si.get("ah_method"):
            client_config["azurehound_collection_method"] = si["ah_method"]
        if si.get("ah_timestamp"):
            client_config["azurehound_timestamp"] = si["ah_timestamp"]

        # ── File integrity + overwrite gating ──────────────────────
        sh_uploaded = st.session_state.file_metadata.get("sh_sha256") is not None
        ah_uploaded = st.session_state.file_metadata.get("ah_sha256") is not None
        has_upload = sh_uploaded or ah_uploaded

        # Check if integrity exists in cached raw data on disk
        si_cached = load_source_integrity(client_config["client_name"], client_config["data_version"]) if using_cache else {}
        integrity_in_cache = bool(si_cached.get("sh_sha256") or si_cached.get("ah_sha256"))

        # Check if any report files already exist for this version
        reports_exist = any(os.path.exists(p.get(k, ""))
                            for k in ("report_pdf", "engineering_xlsx", "evidence_json"))

        can_generate = False

        if using_cache:
            # ── Cached data path ──
            if reports_exist:
                st.warning(f"Reports already exist for v{client_config['data_version']} — "
                           "regenerating will overwrite them.")
                overwrite_ok = st.checkbox("I understand, overwrite existing reports", value=False)
            else:
                overwrite_ok = True

            if integrity_in_cache or has_upload:
                can_generate = overwrite_ok
                if not can_generate and reports_exist:
                    st.info("Check the overwrite box above to proceed")
            else:
                skip_integrity = st.checkbox(
                    "No original ZIPs — proceed without file hash",
                    value=False,
                    help="SHA-256 fields in the report will show 'Not applicable'."
                )
                can_generate = skip_integrity and overwrite_ok

        else:
            # ── Fresh Neo4j (no cache) — MUST upload at least one file ──
            if not has_upload:
                st.warning("Upload at least one SharpHound or AzureHound ZIP to generate reports",
                           icon="\u26a0\ufe0f")
            else:
                can_generate = True

        # Show partial upload info
        if has_upload:
            missing = []
            if not sh_uploaded:
                missing.append("SharpHound")
            if not ah_uploaded:
                missing.append("AzureHound")
            if missing:
                st.info(f"Generating without {' & '.join(missing)} — "
                        f"report will show 'Not applicable' for missing file hashes.")

        if st.button("Generate All Reports", use_container_width=True, disabled=not can_generate):
            _log.info("Report generation starting client=%s version=%s",
                      client_config["client_name"], client_config["data_version"])
            with st.spinner("Generating reports..."):
                ensure_client_dirs(client_config["client_name"], client_config["data_version"])
                env_stats = compute_env_stats(findings, chains, risk, raw=st.session_state.get("raw", {}))
                export_pdf(findings, chains, p["report_pdf"], client_config=client_config, risk=risk, env_stats=env_stats, report_title=client_config.get("report_title", ""))
                export_excel(findings, chains, filepath=p["engineering_xlsx"], client_config=client_config, risk=risk, env_stats=env_stats, report_title=client_config.get("report_title", ""))
                export_csv(findings, p["findings_csv"], client_config=client_config, report_title=client_config.get("report_title", ""))
                export_json(findings, chains, risk, p["evidence_json"], client_config=client_config)

            create_zip(
                [p["report_pdf"], p["engineering_xlsx"], p["findings_csv"],
                 p["evidence_json"], p["attack_graph_html"], p["ai_report_pdf"]],
                p["zip_package"]
            )
            st.success("All reports generated!")
            st.rerun()

        # Show generated file status + download
        for label, path in [
            ("PDF Report", p["report_pdf"]),
            ("Excel Audit Workbook", p["engineering_xlsx"]),
            ("CSV Findings", p["findings_csv"]),
            ("JSON Evidence", p["evidence_json"]),
            ("Attack Graph", p["attack_graph_html"]),
            ("ZIP Package", p["zip_package"]),
        ]:
            exists = os.path.exists(path)
            icon = "\u2705" if exists else "\u274c"
            st.caption(f"{icon} {label}")

        if os.path.exists(p["zip_package"]):
            st.divider()
            with open(p["zip_package"], "rb") as f:
                st.download_button(
                    "Download Assessment ZIP",
                    f,
                    file_name=os.path.basename(p["zip_package"]),
                    use_container_width=True,
                )
    else:
        st.caption("Load data first to generate reports.")

# ─── Previous Outputs Browser ─────────────────────────────────
st.sidebar.divider()
prev_clients = list_client_output_dirs()
if prev_clients:
    with st.sidebar.expander("Previous Assessments", expanded=False):
        for cname in prev_clients:
            cpath = os.path.join(BASE_OUTPUT_DIR, cname)
            versions = sorted([
                d for d in os.listdir(cpath)
                if os.path.isdir(os.path.join(cpath, d)) and d.startswith("v")
            ], reverse=True)
            st.caption(f"**{cname}**")
            for v in versions:
                vpath = os.path.join(cpath, v)
                files = [f for f in os.listdir(vpath) if f.endswith((".pdf", ".xlsx", ".csv", ".json", ".html", ".zip"))]
                for f in files[:3]:
                    st.caption(f"  `{f}`")
                if len(files) > 3:
                    st.caption(f"  … +{len(files)-3} more")

# ─── Sidebar footer ───────────────────────────────────────────
st.sidebar.divider()
st.sidebar.markdown(
    "<div style='text-align:center;color:#94a3b8;font-size:11px;'>"
    "GraphShield Hybrid Identity Security Platform<br>"
    "Open Source (MIT)"
    "</div>",
    unsafe_allow_html=True
)
