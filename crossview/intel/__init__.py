"""Intel layer — the Intellio ↔ Crossview mindmeld.

Intellio generates rich, LLM-authored cyber-intelligence *reports* (threat-intel,
vulnerability, red/blue-team tool, engineering) but persists nothing and grounds
nothing in a local knowledge base. Crossview is the opposite: a persistent,
cross-referenced MITRE graph (CWE/CAPEC/ATT&CK/ATLAS/D3FEND/UKC) + CVE/KEV
enrichment, with no narrative layer.

This module fuses them: it ingests an Intellio report, extracts every canonical
entity it references (ATT&CK techniques, CWE/CAPEC/CVE/CPE/D3FEND…), *grounds*
those against Crossview's silo, and persists the report as a first-class node
cross-referenced into the graph. The result is a "multispectrum" knowledge tool:
structured taxonomy + live CVE/KEV + scan findings + narrative intel, all linked.

Storage is a dedicated `intel.db` next to the reference/enrichment DBs, so the
reference silo stays a clean, rebuildable source of truth.
"""
from __future__ import annotations

import json
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from crossview.data.paths import DATA_DIR

INTEL_DB_PATH = DATA_DIR / "intel.db"

# Canonical-ID patterns Crossview understands. CVE/CPE are resolved against the
# enrichment DB; the rest against the reference silo.
_ID_PATTERNS = {
    "attack": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    "atlas": re.compile(r"\bAML\.T\d{4}(?:\.\d{3})?\b"),
    "cwe": re.compile(r"\bCWE-\d+\b"),
    "capec": re.compile(r"\bCAPEC-\d+\b"),
    "d3fend": re.compile(r"\bD3F:[A-Za-z0-9_]+\b"),
    "ukc": re.compile(r"\bUKC-\d+\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b"),
    "cpe": re.compile(r"cpe:2\.3:[aoh][^\s\"']+"),
}


# ── store ────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS intel_reports (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    subject        TEXT NOT NULL,
    report_type    TEXT NOT NULL,
    canonical_name TEXT,
    summary        TEXT,
    payload_json   TEXT NOT NULL,
    origin         TEXT NOT NULL DEFAULT 'intellio',
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(subject, report_type)
);
CREATE TABLE IF NOT EXISTS intel_refs (
    report_id     INTEGER NOT NULL REFERENCES intel_reports(id) ON DELETE CASCADE,
    entity_id     TEXT NOT NULL,
    entity_source TEXT,
    resolved      INTEGER NOT NULL DEFAULT 0,
    name          TEXT,
    PRIMARY KEY (report_id, entity_id)
);
CREATE INDEX IF NOT EXISTS idx_intel_refs_entity ON intel_refs(entity_id);
CREATE INDEX IF NOT EXISTS idx_intel_reports_type ON intel_reports(report_type);
"""


def connect(path: Path | None = None) -> sqlite3.Connection:
    p = path or INTEL_DB_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(_SCHEMA)
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


# ── grounding ────────────────────────────────────────────────────────────

def extract_entity_ids(report: dict) -> dict[str, str]:
    """Scan a report for every canonical ID it mentions. Returns {id: source}."""
    blob = json.dumps(report, default=str)
    found: dict[str, str] = {}
    for source, pat in _ID_PATTERNS.items():
        for m in pat.findall(blob):
            # ATT&CK pattern also greedily matches the ATLAS suffix; skip overlaps
            if source == "attack" and m.startswith("AML"):
                continue
            found.setdefault(m, source)
    return found


def ground(ids: dict[str, str], ref_conn: sqlite3.Connection,
           enr_conn: sqlite3.Connection | None = None) -> list[dict]:
    """Resolve candidate IDs against Crossview's silo + enrichment.

    Returns one row per id: {entity_id, entity_source, resolved, name}.
    """
    rows: list[dict] = []
    for eid, guessed in sorted(ids.items()):
        name, src, resolved = None, guessed, False
        if guessed in ("cve", "cpe"):
            if enr_conn is not None and guessed == "cve":
                r = enr_conn.execute(
                    "SELECT cve_id, description FROM cves WHERE cve_id = ?", (eid,)
                ).fetchone()
                if r:
                    name = (r["description"] or "")[:80]
                    resolved = True
        else:
            r = ref_conn.execute(
                "SELECT id, name, source FROM entities WHERE id = ?", (eid,)
            ).fetchone()
            if r:
                name, src, resolved = r["name"], r["source"], True
        rows.append({"entity_id": eid, "entity_source": src,
                     "resolved": resolved, "name": name})
    return rows


# ── ingest ───────────────────────────────────────────────────────────────

def _summary_of(report: dict) -> str:
    sb = report.get("strategicBrief")
    if isinstance(sb, dict):
        return sb.get("summary", "")
    return report.get("description") or report.get("ttpEvolution") or ""


def ingest_report(report: dict, intel_conn: sqlite3.Connection,
                  ref_conn: sqlite3.Connection,
                  enr_conn: sqlite3.Connection | None = None,
                  origin: str = "intellio") -> dict:
    """Persist an Intellio report + its grounded cross-references. Idempotent on
    (subject, report_type). Returns a summary dict."""
    subject = report.get("subjectName") or report.get("subject") or "(unknown)"
    rtype = report.get("reportType", "unknown")
    ids = extract_entity_ids(report)
    refs = ground(ids, ref_conn, enr_conn)

    with transaction(intel_conn):
        intel_conn.execute(
            "DELETE FROM intel_reports WHERE subject = ? AND report_type = ?",
            (subject, rtype),
        )
        cur = intel_conn.execute(
            """INSERT INTO intel_reports
                 (subject, report_type, canonical_name, summary, payload_json, origin)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (subject, rtype, report.get("canonicalName") or subject,
             _summary_of(report)[:2000], json.dumps(report, default=str), origin),
        )
        rid = cur.lastrowid
        for ref in refs:
            intel_conn.execute(
                """INSERT OR REPLACE INTO intel_refs
                     (report_id, entity_id, entity_source, resolved, name)
                   VALUES (?, ?, ?, ?, ?)""",
                (rid, ref["entity_id"], ref["entity_source"],
                 int(ref["resolved"]), ref["name"]),
            )
    resolved = [r for r in refs if r["resolved"]]
    return {
        "report_id": rid, "subject": subject, "report_type": rtype,
        "refs_total": len(refs), "refs_resolved": len(resolved),
        "resolved": resolved,
        "unresolved": [r for r in refs if not r["resolved"]],
    }


# ── queries ──────────────────────────────────────────────────────────────

def list_reports(intel_conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return intel_conn.execute(
        """SELECT r.id, r.subject, r.report_type, r.created_at,
                  COUNT(f.entity_id) AS refs,
                  SUM(f.resolved) AS grounded
           FROM intel_reports r
           LEFT JOIN intel_refs f ON f.report_id = r.id
           GROUP BY r.id ORDER BY r.created_at DESC"""
    ).fetchall()


def get_report(intel_conn: sqlite3.Connection, subject: str) -> sqlite3.Row | None:
    return intel_conn.execute(
        "SELECT * FROM intel_reports WHERE subject = ? COLLATE NOCASE "
        "ORDER BY created_at DESC LIMIT 1", (subject,)
    ).fetchone()


def report_refs(intel_conn: sqlite3.Connection, report_id: int) -> list[sqlite3.Row]:
    return intel_conn.execute(
        "SELECT * FROM intel_refs WHERE report_id = ? ORDER BY resolved DESC, entity_source, entity_id",
        (report_id,),
    ).fetchall()


def reports_citing(intel_conn: sqlite3.Connection, entity_id: str) -> list[sqlite3.Row]:
    """Reverse link: which intel reports cite this canonical entity — the
    cross-spectrum query that makes the silo 'multispectrum'."""
    return intel_conn.execute(
        """SELECT r.subject, r.report_type, r.created_at, f.entity_source
           FROM intel_refs f JOIN intel_reports r ON r.id = f.report_id
           WHERE f.entity_id = ? COLLATE NOCASE ORDER BY r.created_at DESC""",
        (entity_id,),
    ).fetchall()
