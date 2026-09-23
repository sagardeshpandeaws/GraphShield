import os
import sys
import json
import re
import shutil
import glob
import base64
import hashlib
import io
import secrets
import zipfile
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from cryptography.fernet import Fernet

# ─── Logging Setup (file only — never stderr/stdout to avoid Streamlit conflicts) ──
_LOG_INITIALIZED = False


def _get_app_base_dir():
    """Return the EXE's directory for persistent data (onefile-safe)."""
    env_base = os.environ.get("GS_APP_BASE")
    if env_base:
        return env_base
    if getattr(sys, 'frozen', False):
        return os.path.dirname(os.path.abspath(sys.argv[0]))
    return os.getcwd()


def setup_logging():
    global _LOG_INITIALIZED
    if _LOG_INITIALIZED:
        return
    log_dir = os.path.join(_get_app_base_dir(), "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "app.log")
    handler = RotatingFileHandler(log_path, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    ))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    _LOG_INITIALIZED = True
    logging.getLogger(__name__).info("Logging initialized — log file: %s", log_path)

# ─── Neo4j / BloodHound ──────────────────────────────────────
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "bloodhoundcommunityedition")

def _get_neo4j_cred_path():
    return os.path.join(_get_app_base_dir(), "neo4j_credentials.enc")

def _get_secret_key_path():
    return os.path.join(_get_app_base_dir(), ".gs_secret")

def _cred_fernet():
    """Fernet cipher keyed by a locally-generated random secret file."""
    path = _get_secret_key_path()
    if not os.path.exists(path):
        key = Fernet.generate_key()
        with open(path, "wb") as f:
            f.write(key)
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(path, 2)  # hidden
        except Exception:
            pass
    else:
        with open(path, "rb") as f:
            key = f.read().strip()
        if not key:
            key = Fernet.generate_key()
            with open(path, "wb") as f:
                f.write(key)
    return Fernet(key)

def save_neo4j_credentials(uri, user, password):
    data = json.dumps({"uri": uri, "user": user, "password": password}).encode()
    encrypted = _cred_fernet().encrypt(data)
    with open(_get_neo4j_cred_path(), "wb") as f:
        f.write(encrypted)
    global NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
    NEO4J_URI = uri
    NEO4J_USER = user
    NEO4J_PASSWORD = password

def load_neo4j_credentials():
    path = _get_neo4j_cred_path()
    if not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as f:
            decrypted = _cred_fernet().decrypt(f.read())
        return json.loads(decrypted.decode())
    except:
        return None

def get_neo4j_config():
    saved = load_neo4j_credentials()
    if saved:
        return saved["uri"], saved["user"], saved["password"]
    return NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

# ─── Ollama AI ────────────────────────────────────────────────
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:latest")

# ─── Branding (locked per licensed build) ─────────────────────
def _get_logo_path():
    """Return path to bundled logo.png, or None if not present."""
    if getattr(sys, 'frozen', False):
        base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(sys.argv[0])))
        for candidate in [
            os.path.join(base, "logo.png"),
            os.path.join(base, "_internal", "logo.png"),
        ]:
            if os.path.exists(candidate):
                return candidate
    else:
        # Dev mode: check brand_logo/ or project root
        for candidate in [
            os.path.join(os.path.dirname(__file__), "brand_logo", "logo.png"),
            os.path.join(os.path.dirname(__file__), "logo.png"),
        ]:
            if os.path.exists(candidate):
                return candidate
    return None

LOGO_PATH = _get_logo_path()


# ─── Base directories ─────────────────────────────────────────
_APP_BASE = _get_app_base_dir()
BASE_OUTPUT_DIR = os.getenv("BASE_OUTPUT_DIR", os.path.join(_APP_BASE, "outputs"))
CLIENT_PROFILES_DIR = os.getenv("CLIENT_PROFILES_DIR", os.path.join(_APP_BASE, "client_profiles"))

# (AzureHound config path removed - Azure data now sourced via Neo4j/BloodHound CE)

# ─── Client defaults (overridden by profile or UI) ───────────
DEFAULT_CLIENT_NAME = os.getenv("CLIENT_NAME", "Default_Client")
DEFAULT_ENGAGEMENT_ID = os.getenv("ENGAGEMENT_ID", "AD-YYYY-001")
DEFAULT_ASSESSOR = os.getenv("ASSESSOR", "Security Assessment Team")
DEFAULT_DATA_VERSION = os.getenv("DATA_VERSION", "1.0")


def _safe_filename(s):
    """Remove /\\:*?\"<>| and trim spaces for safe filenames."""
    return re.sub(r'[\\/*?:\"<>|]', '_', s).strip().replace(' ', '_')


def _client_dir(client_name):
    """Client-specific output directory: outputs/<Client>/"""
    safe = _safe_filename(client_name)
    return os.path.join(BASE_OUTPUT_DIR, safe)


def save_lifecycle_feed_cache(client_name, data_version, feed_data, metadata=None):
    """Persist an uploaded Entra NHI lifecycle feed exactly like reloaded
    Neo4j data: versioned JSON in the client dir plus a SHA-256/method/
    timestamp integrity block that is rehydrated on the next run.

    feed_data is the JSON-serializable lifecycle feed (dict/list). metadata
    may carry nhil_sha256 / nhil_method / nhil_timestamp. Returns bool.
    """
    log = logging.getLogger(__name__)
    cdir = _client_dir(client_name)
    os.makedirs(cdir, exist_ok=True)
    feed_path = os.path.join(cdir, "nhi_lifecycle_feed.json")
    try:
        existing = {}
        if os.path.exists(feed_path):
            with open(feed_path, encoding="utf-8") as f:
                existing = json.load(f)
        existing_integrity = existing.get("_source_integrity") if isinstance(existing, dict) else None
    except Exception:
        existing_integrity = None

    payload = feed_data if isinstance(feed_data, dict) else {"value": feed_data}
    if isinstance(payload, dict):
        payload["_data_version"] = data_version
        payload["_client"] = client_name
        payload["_saved_at"] = datetime.utcnow().isoformat()
        if existing_integrity:
            payload["_source_integrity"] = existing_integrity
        if metadata:
            payload["_source_integrity"] = {
                "nhil_sha256": metadata.get("nhil_sha256"),
                "nhil_method": metadata.get("nhil_method"),
                "nhil_timestamp": metadata.get("nhil_timestamp"),
                "nhil_name": metadata.get("nhil_name"),
            }
    with open(feed_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    log.info("Lifecycle feed cache saved client=%s version=%s path=%s",
             client_name, data_version, os.path.basename(feed_path))
    return True


def load_lifecycle_feed_cache(client_name):
    """Load the persisted NHI lifecycle feed for a client (mirrors
    load_raw_cache). Returns dict/list or None. Never raises."""
    log = logging.getLogger(__name__)
    feed_path = os.path.join(_client_dir(client_name), "nhi_lifecycle_feed.json")
    if not os.path.exists(feed_path):
        return None
    try:
        with open(feed_path, encoding="utf-8") as f:
            data = json.load(f)
        log.debug("Lifecycle feed cache loaded client=%s", client_name)
        return data.get("value", data) if isinstance(data, dict) else data
    except Exception as e:
        log.warning("Failed to load lifecycle feed cache %s: %s", feed_path, e)
        return None


def _version_dir(client_name, data_version):
    """Version-specific output directory: outputs/<Client>/v<version>/"""
    return os.path.join(_client_dir(client_name), f"v{data_version}")


def get_report_filename(client_name, report_type, ext="pdf"):
    """Generate client- and date-stamped filenames.
    
    Returns just the filename (no path), e.g. "Acme_Corp_GraphShield_Assessment_Report_2026-06-19.pdf"
    """
    safe = _safe_filename(client_name)
    date = datetime.now().strftime("%Y-%m-%d")
    return f"{safe}_{report_type}_{date}.{ext}"


def get_output_paths(client_name, data_version="1.0"):
    """Return dict of all output file paths for a given client.
    
    Files land in: outputs/<Client>/v<version>/
    """
    vdir = _version_dir(client_name, data_version)
    return {
        "report_pdf": os.path.join(vdir, get_report_filename(client_name, "GraphShield_Assessment_Report", "pdf")),
        "engineering_xlsx": os.path.join(vdir, get_report_filename(client_name, "GraphShield_Engineering", "xlsx")),
        "findings_csv": os.path.join(vdir, get_report_filename(client_name, "GraphShield_Findings", "csv")),
        "evidence_json": os.path.join(vdir, get_report_filename(client_name, "GraphShield_Evidence", "json")),
        "attack_graph_html": os.path.join(vdir, get_report_filename(client_name, "GraphShield_Attack_Graph", "html")),
        "ai_report_pdf": os.path.join(vdir, get_report_filename(client_name, "GraphShield_Executive_Security_Brief", "pdf")),
        "zip_package": os.path.join(vdir, get_report_filename(client_name, "GraphShield_Package", "zip")),
        "raw_cache": os.path.join(_client_dir(client_name), "raw_bloodhound.json"),
    }


def ensure_client_dirs(client_name, data_version="1.0"):
    """Create all needed directories for a client."""
    paths = get_output_paths(client_name, data_version)
    for key, path in paths.items():
        if key != "raw_cache":
            os.makedirs(os.path.dirname(path), exist_ok=True)
    os.makedirs(os.path.dirname(paths["raw_cache"]), exist_ok=True)


def save_raw_cache(client_name, data_version, raw_data, assessment_group=None):
    """Save raw data to client cache, with versioned backup on data version change."""
    log = logging.getLogger(__name__)
    cdir = _client_dir(client_name)
    os.makedirs(cdir, exist_ok=True)

    cache_path = os.path.join(cdir, "raw_bloodhound.json")
    date_str = datetime.now().strftime("%Y-%m-%d")

    existing_integrity = None
    backed_up = None
    if os.path.exists(cache_path):
        try:
            with open(cache_path, encoding="utf-8") as f:
                existing = json.load(f)
            existing_integrity = existing.get("_source_integrity")
            existing_version = existing.get("_data_version", "")
            if existing_version and existing_version != data_version:
                backup_name = f"raw_bloodhound_v{existing_version}_{date_str}.json"
                backup_path = os.path.join(cdir, backup_name)
                shutil.copy2(cache_path, backup_path)
                backed_up = backup_name
                log.info("Cache backed up client=%s from=v%s to=%s", client_name, existing_version, backup_name)
        except Exception as e:
            log.warning("Cache backup failed client=%s: %s", client_name, e)

    # Add metadata to the raw data
    raw_data["_client"] = client_name
    raw_data["_data_version"] = data_version
    raw_data["_saved_at"] = datetime.utcnow().isoformat()
    if assessment_group:
        raw_data["_assessment_group"] = assessment_group

    # Preserve source integrity if incoming data doesn't have it
    if existing_integrity and "_source_integrity" not in raw_data:
        raw_data["_source_integrity"] = existing_integrity

    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(raw_data, f, indent=2, default=str)


def load_raw_cache(client_name):
    """Load cached raw data for a client. Returns dict or None."""
    log = logging.getLogger(__name__)
    cache_path = os.path.join(_client_dir(client_name), "raw_bloodhound.json")
    if not os.path.exists(cache_path):
        log.debug("No cache file found client=%s", client_name)
        return None
    with open(cache_path, encoding="utf-8") as f:
        data = json.load(f)
    cached_ver = data.get("_data_version", "unknown")
    log.debug("Cache loaded client=%s version=%s size=%d keys",
              client_name, cached_ver, len(data))
    return data


def find_cache_for_version(client_name, data_version):
    """Find cached data for a specific version. Checks main cache first, then backups."""
    log = logging.getLogger(__name__)
    raw = load_raw_cache(client_name)
    if raw and raw.get("_data_version") == data_version:
        log.debug("Cache found in main file client=%s version=%s", client_name, data_version)
        return raw
    cdir = _client_dir(client_name)
    pattern = f"raw_bloodhound_v{data_version}_*.json"
    if os.path.exists(cdir):
        matches = sorted(glob.glob(os.path.join(cdir, pattern)), reverse=True)
        if matches:
            backup_path = matches[0]
            try:
                with open(backup_path, encoding="utf-8") as f:
                    data = json.load(f)
                log.info("Cache found in backup client=%s version=%s file=%s",
                         client_name, data_version, os.path.basename(backup_path))
                return data
            except Exception as e:
                log.warning("Failed to load backup %s: %s", backup_path, e)
    log.debug("No cache found for client=%s version=%s", client_name, data_version)
    return None


# ─── Source Integrity (SHA-256 + Collection Method) ──────────────

def save_source_integrity(client_name, data_version, metadata, raw_data=None):
    """Embed SharpHound/AzureHound SHA-256, collection methods + timestamps into raw cache."""
    log = logging.getLogger(__name__)
    if not client_name:
        log.warning("save_source_integrity: no client_name provided")
        return False
    if raw_data is None:
        raw_data = load_raw_cache(client_name) or {}
    has_sh = bool(metadata.get("sh_sha256"))
    has_ah = bool(metadata.get("ah_sha256"))
    raw_data["_source_integrity"] = {
        "sh_sha256": metadata.get("sh_sha256"),
        "sh_method": metadata.get("sh_method"),
        "sh_timestamp": metadata.get("sh_timestamp"),
        "ah_sha256": metadata.get("ah_sha256"),
        "ah_method": metadata.get("ah_method"),
        "ah_timestamp": metadata.get("ah_timestamp"),
        "_saved_at": datetime.utcnow().isoformat(),
        "_data_version": data_version,
    }
    save_raw_cache(client_name, data_version, raw_data)
    log.info("Source integrity saved client=%s version=%s sh=%s ah=%s",
             client_name, data_version, has_sh, has_ah)
    return True


def _load_si_from_raw(raw):
    """Extract source integrity dict from a raw cache dict."""
    if not raw:
        return {}
    si = raw.get("_source_integrity", {})
    return {
        "sh_sha256": si.get("sh_sha256"),
        "sh_method": si.get("sh_method"),
        "sh_timestamp": si.get("sh_timestamp"),
        "ah_sha256": si.get("ah_sha256"),
        "ah_method": si.get("ah_method"),
        "ah_timestamp": si.get("ah_timestamp"),
    }


def load_source_integrity(client_name, data_version="1.0"):
    """Load source integrity for a specific data version."""
    log = logging.getLogger(__name__)
    source = "none"
    raw = load_raw_cache(client_name)
    if raw:
        cached_ver = raw.get("_data_version", "")
        if cached_ver == data_version:
            source = "main_cache"
            log.info("Source integrity loaded from main cache client=%s version=%s", client_name, data_version)
            return _load_si_from_raw(raw)
        log.info("Source integrity version mismatch client=%s requested=%s cached=%s — searching backups",
                 client_name, data_version, cached_ver)

    # Version mismatch or no main cache — search backup files
    cdir = _client_dir(client_name)
    pattern = f"raw_bloodhound_v{data_version}_*.json"
    backup_path = None
    if os.path.exists(cdir):
        matches = sorted(glob.glob(os.path.join(cdir, pattern)), reverse=True)
        if matches:
            backup_path = matches[0]
    if backup_path:
        try:
            with open(backup_path, encoding="utf-8") as f:
                backup_raw = json.load(f)
            log.info("Source integrity loaded from backup client=%s version=%s file=%s",
                     client_name, data_version, os.path.basename(backup_path))
            return _load_si_from_raw(backup_raw)
        except Exception as e:
            log.warning("Failed to load backup file %s: %s", backup_path, e)

    log.warning("Source integrity fallback (no version match) client=%s requested=%s", client_name, data_version)
    return _load_si_from_raw(raw)


# ─── Client Profile Loading ──────────────────────────────────

def list_client_profiles():
    """Return list of available profile names (without .json extension)."""
    if not os.path.isdir(CLIENT_PROFILES_DIR):
        return []
    return sorted([
        f[:-5] for f in os.listdir(CLIENT_PROFILES_DIR)
        if f.endswith(".json")
    ])


def list_client_output_dirs():
    """Return list of client directories that have been run before (have outputs)."""
    if not os.path.isdir(BASE_OUTPUT_DIR):
        return []
    return sorted([
        d for d in os.listdir(BASE_OUTPUT_DIR)
        if os.path.isdir(os.path.join(BASE_OUTPUT_DIR, d))
        and not d.startswith("__")
    ])


def load_client_profile(profile_name=None):
    """Load a client profile dict.

    profile_name can be:
    - Full path to a .json file
    - Just the name (looks in CLIENT_PROFILES_DIR, adds .json if needed)
    - None: checks CLIENT_PROFILE env var
    Returns dict or {} if not found.
    """
    if profile_name is None:
        profile_name = os.getenv("CLIENT_PROFILE", "")
    if not profile_name:
        return {}
    path = profile_name if os.path.exists(profile_name) else \
        os.path.join(CLIENT_PROFILES_DIR, profile_name)
    if not os.path.exists(path):
        path2 = path + ".json"
        if os.path.exists(path2):
            path = path2
        else:
            return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_client_profile(client_name, engagement_id, data_version, assessor,
                         filename=None):
    """Save a client profile to CLIENT_PROFILES_DIR.
    
    Args:
        client_name, engagement_id, data_version, assessor: profile fields
        filename: optional custom filename (auto-generated from client_name if None)
    Returns:
        full path to saved file, or None on failure
    """
    os.makedirs(CLIENT_PROFILES_DIR, exist_ok=True)
    safe = _safe_filename(client_name)
    filename = filename or f"{safe.lower()}.json"
    path = filename if os.path.isabs(filename) else \
        os.path.join(CLIENT_PROFILES_DIR, filename)
    data = {
        "client_name": client_name,
        "engagement_id": engagement_id,
        "data_version": data_version,
        "assessor": assessor,
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return path
    except Exception:
        return None


def build_client_config(client_name=None, engagement_id=None,
                         data_version=None, assessor=None, collection_date=None,
                         data_source_type=None,
                         sharphound_sha256=None, sharphound_collection_method=None,
                         sharphound_timestamp=None,
                         azurehound_sha256=None, azurehound_collection_method=None,
                         azurehound_timestamp=None,
                         collection_timestamp=None):
    """Build a complete client config dict, merging env, profile, and passed args.
    
    Returns dict with keys:
      client_name, engagement_id, data_version, assessor, collection_date,
      data_source_type,
      sharphound_sha256, sharphound_collection_method, sharphound_timestamp,
      azhound_sha256, azurehound_collection_method, azurehound_timestamp,
      collection_timestamp,
      client_dir, version_dir (computed paths)
    """
    cfg = {
        "client_name": DEFAULT_CLIENT_NAME,
        "engagement_id": DEFAULT_ENGAGEMENT_ID,
        "data_version": DEFAULT_DATA_VERSION,
        "assessor": assessor or DEFAULT_ASSESSOR,
        "collection_date": datetime.now().strftime("%Y-%m-%d"),
        "data_source_type": data_source_type or "Neo4j Graph Database (live)",
        "sharphound_sha256": sharphound_sha256 or None,
        "sharphound_collection_method": sharphound_collection_method or None,
        "sharphound_timestamp": sharphound_timestamp or None,
        "azurehound_sha256": azurehound_sha256 or None,
        "azurehound_collection_method": azurehound_collection_method or None,
        "azurehound_timestamp": azurehound_timestamp or None,
        "collection_timestamp": collection_timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    profile = load_client_profile()
    cfg.update(profile)
    if client_name:
        cfg["client_name"] = client_name
    if engagement_id:
        cfg["engagement_id"] = engagement_id
    if data_version:
        cfg["data_version"] = data_version
    # Explicit assessor argument wins over profile value
    if assessor:
        cfg["assessor"] = assessor
    if collection_date:
        cfg["collection_date"] = collection_date
    if data_source_type:
        cfg["data_source_type"] = data_source_type
    if sharphound_sha256:
        cfg["sharphound_sha256"] = sharphound_sha256
    if sharphound_collection_method:
        cfg["sharphound_collection_method"] = sharphound_collection_method
    if sharphound_timestamp:
        cfg["sharphound_timestamp"] = sharphound_timestamp
    if azurehound_sha256:
        cfg["azurehound_sha256"] = azurehound_sha256
    if azurehound_collection_method:
        cfg["azurehound_collection_method"] = azurehound_collection_method
    if azurehound_timestamp:
        cfg["azurehound_timestamp"] = azurehound_timestamp

    # Add computed paths
    cfg["client_dir"] = _client_dir(cfg["client_name"])
    cfg["version_dir"] = _version_dir(cfg["client_name"], cfg["data_version"])
    return cfg


# ─── Data Source Metadata ────────────────────────────────────────

import hashlib
import io
import zipfile
import re
def _compute_sha256_from_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _recursive_find(meta, targets, _likes=None):
    """Search dict (and nested dicts/lists) for the first value matching one of target keys.
    
    Tries exact match → case-insensitive match → LIKE substring match.
    """
    if _likes is None:
        _likes = {t.lower() for t in targets}
    if isinstance(meta, dict):
        for k, v in meta.items():
            if k in targets and v is not None and isinstance(v, (str, int, float)):
                return str(v)
            result = _recursive_find(v, targets, _likes)
            if result:
                return result
        # Case-insensitive fallback: first key whose lowercase matches a target
        if not any(k in targets for k in meta):
            for k, v in meta.items():
                if k.lower() in _likes and v is not None and isinstance(v, (str, int, float)):
                    return str(v)
            # LIKE fallback: key contains a relevant substring
            like_terms = {"method", "collector", "type", "collect", "timestamp", "collected", "collection", "start"}
            for k, v in meta.items():
                kl = k.lower()
                if any(t in kl for t in like_terms) and v is not None and isinstance(v, (str, int, float)):
                    return str(v)
    elif isinstance(meta, list):
        for item in meta:
            result = _recursive_find(item, targets, _likes)
            if result:
                return result
    return None


_METHOD_KEYS = {"method", "collection_method", "collectortype", "collector_type",
                "collectionmethod", "collectionmethods",
                "CollectionMethod", "CollectionMethods", "CollectionMethodName",
                "collection_method_name", "collector_type_name"}
_TIMESTAMP_KEYS = {"collected", "collection_time", "collected_at", "timestamp", "collected_date",
                   "collectiontimestamp", "collection_timestamp",
                   "CollectedAt", "collectedat", "collected_at_local", "collection_time_utc"}

# SharpHound v2.x collection method bitfield values
_COLLECTION_BITFIELD = {
    0: "Base", 1: "Group", 2: "LocalAdmin", 4: "Session",
    8: "LoggedOn", 16: "Trusts", 32: "ACL", 64: "RDP",
    128: "WinRM", 256: "DCOM", 512: "PSRemote",
    1024: "UserRights", 2048: "CertServices", 4096: "DCOnly",
}

def _scan_for_method_value(meta, known_methods):
    """Scan nested JSON for string values matching known collection method names."""
    if isinstance(meta, dict):
        for k, v in meta.items():
            if isinstance(v, str) and v.lower() in known_methods:
                return v
            result = _scan_for_method_value(v, known_methods)
            if result:
                return result
    elif isinstance(meta, list):
        for item in meta:
            result = _scan_for_method_value(item, known_methods)
            if result:
                return result
    return None


def _epoch_timestamp_to_str(val):
    """Convert a Unix epoch timestamp (seconds as int/str) to readable date string.
    If the value isn't an epoch timestamp, returns it unchanged."""
    if val is None:
        return None
    s = str(val).strip()
    if s.isdigit() and len(s) in (8, 9, 10):
        try:
            return datetime.utcfromtimestamp(int(s)).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OSError, ValueError, OverflowError):
            pass
    return s


def _decode_sharphound_bitfield(value):
    """Decode a SharpHound collection method bitfield integer to human-readable string."""
    if isinstance(value, str):
        try:
            value = int(value)
        except ValueError:
            return value
    if not isinstance(value, int):
        return str(value)
    if value == 0:
        return "Base"
    methods = [name for bit, name in sorted(_COLLECTION_BITFIELD.items()) if bit != 0 and value & bit]
    if not methods:
        return "Unknown"
    return "+".join(methods)


def _try_zip_filename_timestamp(filename):
    """Extract timestamp from SharpHound output ZIP filename (YYYYMMDDHHmmss_ prefix)."""
    base = filename.rsplit("/", 1)[-1]  # handle paths inside ZIP
    m = re.match(r"(\d{14})_", base)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y%m%d%H%M%S").strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            pass
    return None


def _search_all_json_for_metadata(zf):
    """Scan every JSON file in a ZIP for collection method + timestamp."""
    method = None
    timestamp = None
    for name in zf.namelist():
        if not name.endswith(".json"):
            continue
        try:
            with zf.open(name) as f:
                content = json.load(f)
        except Exception:
            continue
        raw_m = _recursive_find(content, _METHOD_KEYS)
        raw_t = _recursive_find(content, _TIMESTAMP_KEYS)
        if raw_m and not method:
            method = _decode_sharphound_bitfield(raw_m)
        if raw_t and not timestamp:
            timestamp = raw_t
        if method and timestamp:
            break
            # v2.x sometimes has method only in metadata.json; also try data.props/Properties sub-structure
        if not method or not timestamp:
            meta_block = content.get("data") if isinstance(content, dict) else None
            if isinstance(meta_block, dict):
                props = meta_block.get("props") or meta_block.get("Properties") or meta_block
                raw_m = _recursive_find(props, _METHOD_KEYS)
                raw_t = _recursive_find(props, _TIMESTAMP_KEYS)
                if raw_m and not method:
                    method = _decode_sharphound_bitfield(raw_m)
                if raw_t and not timestamp:
                    timestamp = raw_t
            # Look for BH CE format: [{Type: "CollectionMethod", Properties: {...}}]
            if isinstance(meta_block, list):
                for entry in meta_block:
                    if isinstance(entry, dict) and entry.get("Type") == "CollectionMethod":
                        props = entry.get("Properties") or entry.get("props") or entry
                        raw_m = _recursive_find(props, _METHOD_KEYS)
                        raw_t = _recursive_find(props, _TIMESTAMP_KEYS)
                        if raw_m and not method:
                            method = _decode_sharphound_bitfield(raw_m)
                        if raw_t and not timestamp:
                            timestamp = raw_t
    # Last resort: scan all JSON files for string values matching known method names
    if not method:
        known = {"dconly", "group", "session", "localadmin", "loggedon",
                 "trusts", "acl", "rdp", "winrm", "dcom", "psremote",
                 "userrights", "certservices", "base"}
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                with zf.open(name) as f:
                    content = json.load(f)
                val = _scan_for_method_value(content, known)
                if val:
                    method = val
                    break
            except Exception:
                continue
    return method, timestamp


def process_sharphound_zip(file_bytes, filename=None):
    """Process an uploaded SharpHound output: compute SHA-256, extract collection method + timestamp.
    
    Robust strategy chain:
      1. Metadata JSON inside ZIP (any *metadata*.json file)
      2. Filename timestamp from ZIP name (YYYYMMDDHHmmss_ prefix)
      3. All JSON files in ZIP scanned for matching keys
      4. ZIP entry modification time as last resort
    
    Returns (sha256, collection_method_or_None, collection_timestamp_or_None).
    """
    sha256 = _compute_sha256_from_bytes(file_bytes)
    method = None
    timestamp = None

    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            names = zf.namelist()

            # Strategy 1: dedicated metadata JSON file(s)
            meta_candidates = sorted(
                n for n in names if "metadata" in n.lower() and n.endswith(".json")
            ) or sorted(
                n for n in names if "metadata" in n.lower()
            )
            for meta_name in meta_candidates:
                try:
                    with zf.open(meta_name) as f:
                        meta = json.load(f)
                except Exception:
                    continue
                raw_m = _recursive_find(meta, _METHOD_KEYS)
                raw_t = _recursive_find(meta, _TIMESTAMP_KEYS)
                if raw_m and not method:
                    method = _decode_sharphound_bitfield(raw_m)
                if raw_t and not timestamp:
                    timestamp = raw_t
                if method and timestamp:
                    break

            # Strategy 2: filename timestamp from ZIP name (most reliable)
            if not timestamp and filename:
                candidate = _try_zip_filename_timestamp(filename)
                if candidate:
                    timestamp = candidate

            # Strategy 3: scan all JSON files
            if not method or not timestamp:
                m2, t2 = _search_all_json_for_metadata(zf)
                if not method and m2:
                    method = m2
                if not timestamp and t2:
                    timestamp = t2

            # Strategy 4: ZIP entry modification time (last resort)
            if not timestamp and names:
                try:
                    info = zf.getinfo(names[0])
                    dt = datetime(*info.date_time)
                    timestamp = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                except Exception:
                    pass

    except zipfile.BadZipFile:
        # Not a ZIP — might be a raw JSON file uploaded through the ZIP uploader
        try:
            content = json.loads(file_bytes.decode("utf-8"))
            if isinstance(content, dict) or isinstance(content, list):
                raw_m = _recursive_find(content, _METHOD_KEYS)
                raw_t = _recursive_find(content, _TIMESTAMP_KEYS)
                if raw_m:
                    method = _decode_sharphound_bitfield(raw_m)
                if raw_t:
                    timestamp = raw_t
        except Exception:
            pass
    except Exception:
        pass

    return sha256, method, timestamp


def _search_azurehound_content(content):
    """Extract method + timestamp from parsed AzureHound JSON (dict or list)."""
    method = None
    timestamp = None
    raw_m = _recursive_find(content, _METHOD_KEYS)
    raw_t = _recursive_find(content, _TIMESTAMP_KEYS)
    if raw_m:
        method = _decode_sharphound_bitfield(raw_m)
    if raw_t:
        timestamp = _epoch_timestamp_to_str(raw_t)
    if not method or not timestamp:
        data = content.get("data") if isinstance(content, dict) else None
        if data:
            raw_m = _recursive_find(data, _METHOD_KEYS)
            raw_t = _recursive_find(data, _TIMESTAMP_KEYS)
            if raw_m and not method:
                method = _decode_sharphound_bitfield(raw_m)
            if raw_t and not timestamp:
                timestamp = _epoch_timestamp_to_str(raw_t)
    return method, timestamp


def process_azurehound_zip(file_bytes, filename=None):
    """Process an uploaded AzureHound ZIP/JSON: compute SHA-256, extract collection method + timestamp.
    
    Robust strategy chain:
      1. All JSON files inside ZIP scanned for matching keys
      2. Raw JSON file (not a ZIP)
      3. Recursive key search across known naming variants
    
    Returns (sha256, collection_method_or_None, collection_timestamp_or_None).
    """
    sha256 = _compute_sha256_from_bytes(file_bytes)
    method = None
    timestamp = None

    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            json_files = [n for n in zf.namelist() if n.endswith(".json")]
            if json_files:
                for jf_name in json_files:
                    try:
                        with zf.open(jf_name) as f:
                            content = json.load(f)
                    except Exception:
                        continue
                    m2, t2 = _search_azurehound_content(content)
                    if m2 and not method:
                        method = m2
                    if t2 and not timestamp:
                        timestamp = t2
                    if method and timestamp:
                        break
                # Fallback: ZIP entry timestamp
                if not timestamp:
                    try:
                        info = zf.getinfo(json_files[0])
                        dt = datetime(*info.date_time)
                        timestamp = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                    except Exception:
                        pass
    except zipfile.BadZipFile:
        try:
            content = json.loads(file_bytes.decode("utf-8"))
            if isinstance(content, (dict, list)):
                method, timestamp = _search_azurehound_content(content)
        except Exception:
            pass
    except Exception:
        pass

    return sha256, method, timestamp


# ─── Environment Statistics ────────────────────────────────────

def compute_env_stats(findings, chains, risk=None, raw=None):
    """Compute environment and risk statistics.
    
    Uses real Neo4j counts (from raw._env_stats) for AD Environment Overview
    and computes dashboard metrics from findings.
    
    Returns dict with all metrics for Executive Dashboard and AD Environment Overview.
    """
    active = [f for f in findings if f.get("has_evidence", False)]
    
    # Collect unique objects across all active findings
    all_users = set()
    all_groups = set()
    all_computers = set()
    all_gpos = set()
    all_ous = set()
    
    for f in active:
        ad = f.get("ad_objects", {})
        all_users.update(ad.get("users", []))
        all_groups.update(ad.get("groups", []))
        all_computers.update(ad.get("computers", []))
        all_gpos.update(ad.get("gpos", []))
        all_ous.update(ad.get("organizational_units", []))
    
    # Real environment data from Neo4j (preferred)
    env_raw = (raw or {}).get("_env_stats", {})
    
    # Find specific findings for exposure flags
    finding_map = {f.get("id"): f for f in active}
    tier0 = finding_map.get("TIER0_PATHS", {})
    dcsync = finding_map.get("DCSYNC", {})
    cross_forest = finding_map.get("CROSS_FOREST", {})
    
    tier0_exposure = tier0.get("has_evidence", False)
    tier0_accounts = len(tier0.get("ad_objects", {}).get("users", []))
    dcsync_exposure = dcsync.get("has_evidence", False)
    
    # Attack path count (unique relationships)
    attack_path_count = 0
    for f in active:
        attack_path_count += len(f.get("ad_objects", {}).get("relationships", []))
    
    risk_score = min(risk.get("total_score", 0), 100) if risk else 0
    risk_label = "LOW"
    if risk_score >= 70: risk_label = "CRITICAL"
    elif risk_score >= 30: risk_label = "HIGH"
    elif risk_score >= 15: risk_label = "MEDIUM"

    return {
        # Dashboard metrics (from findings)
        "critical_findings": sum(1 for f in active if f["severity"] == "CRITICAL"),
        "high_findings": sum(1 for f in active if f["severity"] == "HIGH"),
        "medium_findings": sum(1 for f in active if f["severity"] == "MEDIUM"),
        "low_findings": sum(1 for f in active if f["severity"] == "LOW"),
        "total_active": len(active),
        "attack_chains": len(chains),
        "attack_paths": attack_path_count,
        "affected_accounts": len(all_users),
        "tier0_exposure": "YES" if tier0_exposure else "NO",
        "tier0_accounts": tier0_accounts or env_raw.get("tier0_accounts", 0),
        "dcsync_exposure": "YES" if dcsync_exposure else "NO",
        "risk_score": risk_score,
        "risk_label": risk_label,
        # Environment overview — global Neo4j counts are ground truth
        "total_users": env_raw.get("total_users", len(all_users)),
        "total_computers": env_raw.get("total_computers", len(all_computers)),
        "servers": env_raw.get("servers", 0),
        "domain_controllers": env_raw.get("domain_controllers", 0),
        "total_groups": env_raw.get("total_groups", len(all_groups)),
        "total_gpos": env_raw.get("total_gpos", len(all_gpos)),
        "domains": env_raw.get("domains", []),
        "service_accounts": env_raw.get("service_accounts", 0),
        "trusts": env_raw.get("trusts", 0),
        "forests": env_raw.get("forests", []),
        # Azure / Entra ID environment
        "azure_tenants": env_raw.get("azure_tenants", []),
        "azure_users": env_raw.get("azure_users", 0),
        "azure_groups": env_raw.get("azure_groups", 0),
        "azure_service_principals": env_raw.get("azure_service_principals", 0),
        "azure_managed_identities": env_raw.get("azure_managed_identities", 0),
        "azure_applications": env_raw.get("azure_applications", 0),
        "azure_key_vaults": env_raw.get("azure_key_vaults", 0),
        "azure_vms": env_raw.get("azure_vms", 0),
        "azure_subscriptions": env_raw.get("azure_subscriptions", 0),
        "azure_tenants_detail": env_raw.get("azure_tenants_detail", []),
    }
