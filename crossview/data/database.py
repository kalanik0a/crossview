"""Reference SQLite database: canonical MITRE silo. Rebuildable from data/raw/."""
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator

from crossview.data.paths import DB_PATH
from crossview.domain import Entity, Xref

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS xrefs;
DROP TABLE IF EXISTS entities_fts;
DROP TABLE IF EXISTS entities;

CREATE TABLE entities (
    id            TEXT PRIMARY KEY,
    source        TEXT NOT NULL,
    subtype       TEXT NOT NULL,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    framework     TEXT,
    abstraction   TEXT,
    stix_id       TEXT,
    created_at    TEXT,
    modified_at   TEXT,
    raw_json      TEXT
);
CREATE INDEX idx_entities_source     ON entities(source);
CREATE INDEX idx_entities_subtype    ON entities(subtype);
CREATE INDEX idx_entities_framework  ON entities(framework);
CREATE INDEX idx_entities_stix_id    ON entities(stix_id);

CREATE TABLE xrefs (
    src_id        TEXT NOT NULL,
    dst_id        TEXT NOT NULL,
    relation      TEXT NOT NULL,
    source        TEXT NOT NULL,
    metadata_json TEXT,
    PRIMARY KEY (src_id, dst_id, relation)
);
CREATE INDEX idx_xrefs_src_rel ON xrefs(src_id, relation);
CREATE INDEX idx_xrefs_dst_rel ON xrefs(dst_id, relation);

CREATE VIRTUAL TABLE entities_fts USING fts5(
    id UNINDEXED,
    name,
    description,
    tokenize='porter unicode61'
);
"""


def connect(path: Path | None = None) -> sqlite3.Connection:
    db = path or DB_PATH
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_schema(conn: sqlite3.Connection) -> None:
    """Drop and recreate the reference schema. Destroys all entity/xref data."""
    conn.executescript(SCHEMA)
    conn.commit()


def insert_entities(conn: sqlite3.Connection, entities: Iterable[Entity]) -> int:
    rows = [
        (
            e.id, e.source, e.subtype, e.name, e.description,
            e.framework, e.abstraction, e.stix_id,
            e.created_at, e.modified_at,
            json.dumps(e.raw, default=str) if e.raw else None,
        )
        for e in entities
    ]
    conn.executemany(
        """
        INSERT OR REPLACE INTO entities
            (id, source, subtype, name, description, framework, abstraction,
             stix_id, created_at, modified_at, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    return len(rows)


def insert_xrefs(conn: sqlite3.Connection, xrefs: Iterable[Xref]) -> int:
    rows = [
        (
            x.src_id, x.dst_id, x.relation, x.source,
            json.dumps(x.metadata, default=str) if x.metadata else None,
        )
        for x in xrefs
    ]
    conn.executemany(
        """
        INSERT OR IGNORE INTO xrefs
            (src_id, dst_id, relation, source, metadata_json)
        VALUES (?, ?, ?, ?, ?)
        """,
        rows,
    )
    return len(rows)


def rebuild_fts(conn: sqlite3.Connection) -> None:
    """Repopulate the FTS5 mirror after a load. Cheap on our entity volume."""
    conn.execute("DELETE FROM entities_fts")
    conn.execute(
        """
        INSERT INTO entities_fts (rowid, id, name, description)
        SELECT rowid, id, name, description FROM entities
        """
    )
    conn.commit()


def stats(conn: sqlite3.Connection) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in conn.execute("SELECT source, subtype, COUNT(*) AS n FROM entities GROUP BY source, subtype"):
        out[f"{row['source']}.{row['subtype']}"] = row["n"]
    out["xrefs"] = conn.execute("SELECT COUNT(*) AS n FROM xrefs").fetchone()["n"]
    out["xrefs_by_relation"] = {
        r["relation"]: r["n"]
        for r in conn.execute("SELECT relation, COUNT(*) AS n FROM xrefs GROUP BY relation")
    }
    return out
