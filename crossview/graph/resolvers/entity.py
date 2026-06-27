"""Entity-domain resolvers."""
from __future__ import annotations

from crossview.data.database import connect as ref_connect
from crossview.graph.types import Entity, Xref


def _row_to_entity(row) -> Entity:
    return Entity(
        id=row["id"],
        source=row["source"],
        subtype=row["subtype"],
        name=row["name"],
        description=row["description"] or "",
        framework=row["framework"],
        abstraction=row["abstraction"],
        stix_id=row["stix_id"],
    )


def resolve_entity(id: str) -> Entity | None:
    conn = ref_connect()
    row = conn.execute("SELECT * FROM entities WHERE id = ?", (id,)).fetchone()
    return _row_to_entity(row) if row else None


def resolve_search(query: str, limit: int = 20) -> list[Entity]:
    conn = ref_connect()
    rows = conn.execute(
        """
        SELECT e.*
        FROM entities_fts f
        JOIN entities e ON e.rowid = f.rowid
        WHERE entities_fts MATCH ?
        ORDER BY rank
        LIMIT ?
        """,
        (query, limit),
    ).fetchall()
    return [_row_to_entity(r) for r in rows]


def resolve_xrefs_outbound(entity_id: str) -> list[Xref]:
    conn = ref_connect()
    rows = conn.execute(
        "SELECT * FROM xrefs WHERE src_id = ?", (entity_id,)
    ).fetchall()
    return [
        Xref(
            src_id=r["src_id"], dst_id=r["dst_id"],
            relation=r["relation"], source=r["source"],
        )
        for r in rows
    ]


def resolve_xrefs_inbound(entity_id: str) -> list[Xref]:
    conn = ref_connect()
    rows = conn.execute(
        "SELECT * FROM xrefs WHERE dst_id = ?", (entity_id,)
    ).fetchall()
    return [
        Xref(
            src_id=r["src_id"], dst_id=r["dst_id"],
            relation=r["relation"], source=r["source"],
        )
        for r in rows
    ]


def resolve_entities_by_source(source: str, subtype: str | None = None, limit: int = 100) -> list[Entity]:
    conn = ref_connect()
    if subtype:
        rows = conn.execute(
            "SELECT * FROM entities WHERE source = ? AND subtype = ? LIMIT ?",
            (source, subtype, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM entities WHERE source = ? LIMIT ?",
            (source, limit),
        ).fetchall()
    return [_row_to_entity(r) for r in rows]
