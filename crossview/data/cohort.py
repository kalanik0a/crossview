"""Cohort SQLite database — per-project investigation workspace.

Lives at <project>/.crossview/cohort.db. Never auto-dropped: this is mutable user
data (or, more accurately, *my* analysis state). The reference DB is read-only
from this side.
"""
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

COHORT_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS investigations (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    project_path        TEXT NOT NULL,
    file_path           TEXT,
    line_start          INTEGER,
    line_end            INTEGER,
    summary             TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'open',
    scanner_finding_id  INTEGER,
    opened_at           TEXT NOT NULL DEFAULT (datetime('now')),
    closed_at           TEXT
);
CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status);
CREATE INDEX IF NOT EXISTS idx_investigations_file ON investigations(file_path);

CREATE TABLE IF NOT EXISTS hypotheses (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id    INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    parent_id           INTEGER REFERENCES hypotheses(id),
    statement           TEXT NOT NULL,
    confidence          REAL NOT NULL DEFAULT 0.5,
    suspected_cwe       TEXT,
    suspected_capec     TEXT,
    suspected_attack    TEXT,
    suspected_atlas     TEXT,
    status              TEXT NOT NULL DEFAULT 'active',
    superseded_by       INTEGER REFERENCES hypotheses(id),
    posted_at           TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_hypotheses_inv    ON hypotheses(investigation_id);
CREATE INDEX IF NOT EXISTS idx_hypotheses_parent ON hypotheses(parent_id);
CREATE INDEX IF NOT EXISTS idx_hypotheses_status ON hypotheses(status);

CREATE TABLE IF NOT EXISTS evidence (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hypothesis_id   INTEGER NOT NULL REFERENCES hypotheses(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,
    content         TEXT NOT NULL,
    file_path       TEXT,
    line            INTEGER,
    ref_url         TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_evidence_hyp ON evidence(hypothesis_id);

CREATE TABLE IF NOT EXISTS validations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hypothesis_id   INTEGER NOT NULL REFERENCES hypotheses(id) ON DELETE CASCADE,
    entity_type     TEXT NOT NULL,
    entity_id       TEXT NOT NULL,
    match           TEXT NOT NULL,
    notes           TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_validations_hyp ON validations(hypothesis_id);

CREATE TABLE IF NOT EXISTS mitigations (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id    INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    d3fend_id           TEXT,
    description         TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'proposed',
    applied_at          TEXT,
    verified_at         TEXT
);

CREATE TABLE IF NOT EXISTS scan_results (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    project_path        TEXT NOT NULL,
    file_path           TEXT NOT NULL,
    line_start          INTEGER,
    line_end            INTEGER,
    rule_id             TEXT NOT NULL,
    rule_source         TEXT NOT NULL,
    severity            TEXT,
    message             TEXT NOT NULL,
    cwe_id              TEXT,
    raw_finding_json    TEXT,
    scanned_at          TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scan_cwe  ON scan_results(cwe_id);
CREATE INDEX IF NOT EXISTS idx_scan_file ON scan_results(file_path);

CREATE TABLE IF NOT EXISTS notes (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id    INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    content             TEXT NOT NULL,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Stage 1 (Survey) output: structural map of the project being scanned.
CREATE TABLE IF NOT EXISTS project_map (
    project_path        TEXT PRIMARY KEY,
    surveyed_at         TEXT NOT NULL DEFAULT (datetime('now')),
    languages_json      TEXT,
    frameworks_json     TEXT,
    files_count         INTEGER,
    entrypoints_count   INTEGER,
    sinks_count         INTEGER,
    notes               TEXT
);

CREATE TABLE IF NOT EXISTS entrypoints (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    project_path        TEXT NOT NULL,
    file_path           TEXT NOT NULL,
    line                INTEGER NOT NULL,
    kind                TEXT NOT NULL,        -- http_route|cli_command|websocket|page|scheduled|...
    framework           TEXT,
    method              TEXT,                 -- GET / POST / ANY / WS / null
    path                TEXT,                 -- /api/foo/{id}
    handler_name        TEXT,
    parameters_json     TEXT,
    surveyed_at         TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (project_path, file_path, line, kind)
);
CREATE INDEX IF NOT EXISTS idx_entrypoints_project ON entrypoints(project_path);
CREATE INDEX IF NOT EXISTS idx_entrypoints_kind ON entrypoints(kind);

CREATE TABLE IF NOT EXISTS sinks (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    project_path        TEXT NOT NULL,
    file_path           TEXT NOT NULL,
    line                INTEGER NOT NULL,
    kind                TEXT NOT NULL,        -- sql_exec | shell_exec | code_eval | ...
    callee              TEXT,
    risk_cwe_json       TEXT,                 -- ["CWE-89", "CWE-78"]
    snippet             TEXT,
    surveyed_at         TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (project_path, file_path, line, callee)
);
CREATE INDEX IF NOT EXISTS idx_sinks_project ON sinks(project_path);
CREATE INDEX IF NOT EXISTS idx_sinks_kind ON sinks(kind);
CREATE INDEX IF NOT EXISTS idx_sinks_file ON sinks(file_path);
"""


def cohort_path(project_root: Path) -> Path:
    return project_root / ".crossview" / "cohort.db"


def connect(project_root: Path) -> sqlite3.Connection:
    """Open (or create) the cohort DB for a project. Idempotent — never destructive."""
    db = cohort_path(project_root)
    # [CWE-59] Refuse to follow symlinks for .crossview directory
    if db.parent.is_symlink():
        raise RuntimeError(
            f"Security: {db.parent} is a symlink. Refusing to write cohort.db through symlinks."
        )
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    conn.executescript(COHORT_SCHEMA)
    conn.commit()
    return conn


def attach_reference(conn: sqlite3.Connection, reference_db: Path, alias: str = "ref") -> None:
    """ATTACH the reference DB so cohort queries can JOIN against canonical entities."""
    # [CWE-89] Validate alias is a safe SQL identifier
    import re
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", alias):
        raise ValueError(f"Invalid SQL alias: {alias!r}")
    conn.execute(f"ATTACH DATABASE ? AS {alias}", (str(reference_db),))


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
