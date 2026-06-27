"""Shared helpers for normalizers."""
import re

CWE_ID_RE = re.compile(r"^CWE-\d+$")
CAPEC_ID_RE = re.compile(r"^CAPEC-\d+$")
ATTACK_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
ATLAS_ID_RE = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")
D3FEND_ID_RE = re.compile(r"^D3-[A-Z][A-Z0-9-]*$")


def safe_text(v) -> str:
    """Coerce STIX/JSON values to a clean text string."""
    if v is None:
        return ""
    if isinstance(v, str):
        return v.strip()
    if isinstance(v, list):
        return " ".join(safe_text(x) for x in v).strip()
    return str(v)


def first_external_id(refs: list, source_name: str) -> str | None:
    """Pull the first external_references entry whose source_name matches."""
    for r in refs or []:
        if r.get("source_name") == source_name and r.get("external_id"):
            return r["external_id"]
    return None
