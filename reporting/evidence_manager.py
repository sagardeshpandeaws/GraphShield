import os

EVIDENCE_DIR = os.getenv("EVIDENCE_DIR", "evidence")


def init_evidence(base_dir=None):
    """Create the evidence directory.
    
    Args:
        base_dir: Client-specific output directory. If None, uses EVIDENCE_DIR.
    """
    path = base_dir or EVIDENCE_DIR
    os.makedirs(path, exist_ok=True)


def add_evidence(finding_id, file, base_dir=None):
    """Save uploaded evidence to disk.
    
    Args:
        finding_id: e.g. "AD-001"
        file: uploaded Streamlit file object (must have .name and .getbuffer())
        base_dir: Client-specific evidence directory (optional)
    Returns:
        saved file path
    """
    path = os.path.join(base_dir or EVIDENCE_DIR, finding_id)
    os.makedirs(path, exist_ok=True)
    destination = os.path.join(path, file.name)
    with open(destination, "wb") as f:
        f.write(file.getbuffer())
    return destination
