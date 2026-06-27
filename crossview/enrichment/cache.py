"""Enrichment SQLite cache.

Lifecycle: append-mostly with TTL. Distinct from crossview.db (rebuildable
canonical) and cohort.db (per-project investigation). Write through enrichers,
read through the orchestrator.
"""
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from crossview.enrichment.paths import ENRICHMENT_DB_PATH

ENRICHMENT_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- Generic per-entity enrichment cache. One row per (entity_id, enricher).
CREATE TABLE IF NOT EXISTS enrichments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id       TEXT NOT NULL,
    enricher        TEXT NOT NULL,
    payload_json    TEXT NOT NULL,
    fetched_at      TEXT NOT NULL DEFAULT (datetime('now')),
    ttl_seconds     INTEGER,
    fingerprint     TEXT,
    UNIQUE (entity_id, enricher)
);
CREATE INDEX IF NOT EXISTS idx_enrichments_entity ON enrichments(entity_id);
CREATE INDEX IF NOT EXISTS idx_enrichments_enricher ON enrichments(enricher);

-- CVE master table. Populated by cve_nvd enricher (Wave 2).
CREATE TABLE IF NOT EXISTS cves (
    cve_id          TEXT PRIMARY KEY,
    description     TEXT,
    cvss_v3_score   REAL,
    cvss_v3_severity TEXT,
    published_at    TEXT,
    modified_at     TEXT,
    raw_json        TEXT,
    fetched_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(cvss_v3_severity);
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_at);

-- CWE → CVE many-to-many. Joins crossview.db.entities (CWE) ↔ enrichment.db.cves.
CREATE TABLE IF NOT EXISTS cwe_cves (
    cwe_id          TEXT NOT NULL,
    cve_id          TEXT NOT NULL,
    PRIMARY KEY (cwe_id, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_cwe_cves_cve ON cwe_cves(cve_id);

-- CPE dictionary (Common Platform Enumeration). Affected products per CVE.
CREATE TABLE IF NOT EXISTS cpes (
    cpe_uri         TEXT PRIMARY KEY,
    part            TEXT,         -- a (application) | o (os) | h (hardware)
    vendor          TEXT,
    product         TEXT,
    version         TEXT,
    raw_json        TEXT
);
CREATE INDEX IF NOT EXISTS idx_cpes_vendor_product ON cpes(vendor, product);

CREATE TABLE IF NOT EXISTS cve_cpes (
    cve_id          TEXT NOT NULL,
    cpe_uri         TEXT NOT NULL,
    vulnerable      INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (cve_id, cpe_uri)
);
CREATE INDEX IF NOT EXISTS idx_cve_cpes_cpe ON cve_cpes(cpe_uri);

-- CISA Known Exploited Vulnerabilities catalog.
CREATE TABLE IF NOT EXISTS kev (
    cve_id              TEXT PRIMARY KEY,
    vendor_project      TEXT,
    product             TEXT,
    vulnerability_name  TEXT,
    date_added          TEXT,
    short_description   TEXT,
    required_action     TEXT,
    due_date            TEXT,
    known_ransomware_use TEXT,
    notes               TEXT,
    cwe_ids_json        TEXT,
    fetched_at          TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_kev_date_added ON kev(date_added);

-- Resumable sweep state (so a Ctrl-C'd bulk pull picks up where it stopped).
CREATE TABLE IF NOT EXISTS sweep_state (
    sweep_name      TEXT PRIMARY KEY,
    last_index      INTEGER NOT NULL DEFAULT 0,
    total_expected  INTEGER,
    pages_done      INTEGER NOT NULL DEFAULT 0,
    started_at      TEXT,
    last_progress_at TEXT,
    status          TEXT NOT NULL DEFAULT 'idle'  -- idle | running | complete | error
);
"""


def connect(path: Path | None = None) -> sqlite3.Connection:
    db = path or ENRICHMENT_DB_PATH
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    conn.executescript(ENRICHMENT_SCHEMA)
    conn.commit()
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def upsert_enrichment(
    conn: sqlite3.Connection,
    entity_id: str,
    enricher: str,
    payload: dict,
    ttl_seconds: int | None = None,
    fingerprint: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO enrichments (entity_id, enricher, payload_json, ttl_seconds, fingerprint)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(entity_id, enricher) DO UPDATE SET
            payload_json = excluded.payload_json,
            fetched_at   = datetime('now'),
            ttl_seconds  = excluded.ttl_seconds,
            fingerprint  = excluded.fingerprint
        """,
        (entity_id, enricher, json.dumps(payload, default=str), ttl_seconds, fingerprint),
    )


def get_enrichment(
    conn: sqlite3.Connection, entity_id: str, enricher: str
) -> dict | None:
    row = conn.execute(
        """
        SELECT payload_json, fetched_at, ttl_seconds, fingerprint
        FROM enrichments
        WHERE entity_id = ? AND enricher = ?
        """,
        (entity_id, enricher),
    ).fetchone()
    if not row:
        return None
    return {
        "payload": json.loads(row["payload_json"]),
        "fetched_at": row["fetched_at"],
        "ttl_seconds": row["ttl_seconds"],
        "fingerprint": row["fingerprint"],
    }


def is_stale(record: dict | None) -> bool:
    if not record:
        return True
    ttl = record.get("ttl_seconds")
    if ttl is None:
        return False
    import datetime as dt

    fetched = dt.datetime.fromisoformat(record["fetched_at"])
    age = (dt.datetime.utcnow() - fetched).total_seconds()
    return age > ttl


def load_sweep_state(conn: sqlite3.Connection, name: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM sweep_state WHERE sweep_name = ?", (name,)
    ).fetchone()
    return dict(row) if row else None


def save_sweep_state(
    conn: sqlite3.Connection,
    name: str,
    last_index: int,
    pages_done: int,
    total_expected: int | None,
    status: str = "running",
) -> None:
    conn.execute(
        """
        INSERT INTO sweep_state (sweep_name, last_index, pages_done, total_expected,
                                  started_at, last_progress_at, status)
        VALUES (?, ?, ?, ?, datetime('now'), datetime('now'), ?)
        ON CONFLICT(sweep_name) DO UPDATE SET
            last_index = excluded.last_index,
            pages_done = excluded.pages_done,
            total_expected = COALESCE(excluded.total_expected, sweep_state.total_expected),
            last_progress_at = datetime('now'),
            status = excluded.status
        """,
        (name, last_index, pages_done, total_expected, status),
    )
    conn.commit()


def stats(conn: sqlite3.Connection) -> dict:
    out: dict = {}
    out["enrichments_total"] = conn.execute(
        "SELECT COUNT(*) AS n FROM enrichments"
    ).fetchone()["n"]
    out["by_enricher"] = {
        r["enricher"]: r["n"]
        for r in conn.execute(
            "SELECT enricher, COUNT(*) AS n FROM enrichments GROUP BY enricher"
        )
    }
    out["cves"] = conn.execute("SELECT COUNT(*) AS n FROM cves").fetchone()["n"]
    out["cwe_cves"] = conn.execute("SELECT COUNT(*) AS n FROM cwe_cves").fetchone()["n"]
    out["cpes"] = conn.execute("SELECT COUNT(*) AS n FROM cpes").fetchone()["n"]
    out["cve_cpes"] = conn.execute("SELECT COUNT(*) AS n FROM cve_cpes").fetchone()["n"]
    out["kev"] = conn.execute("SELECT COUNT(*) AS n FROM kev").fetchone()["n"]
    return out
