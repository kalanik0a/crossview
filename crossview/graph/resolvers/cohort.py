"""Cohort-domain resolvers (per-project investigations + hypothesis forest)."""
from __future__ import annotations

from pathlib import Path

from crossview.data import cohort as cohort_db
from crossview.graph.types import Evidence, Hypothesis, Investigation, Validation


def _row_to_investigation(r) -> Investigation:
    return Investigation(
        id=r["id"],
        project_path=r["project_path"],
        file_path=r["file_path"],
        line_start=r["line_start"],
        line_end=r["line_end"],
        summary=r["summary"],
        status=r["status"],
        opened_at=r["opened_at"],
    )


def _row_to_hypothesis(r) -> Hypothesis:
    return Hypothesis(
        id=r["id"],
        investigation_id=r["investigation_id"],
        parent_id=r["parent_id"],
        statement=r["statement"],
        confidence=r["confidence"] or 0.0,
        suspected_cwe=r["suspected_cwe"],
        suspected_capec=r["suspected_capec"],
        suspected_attack=r["suspected_attack"],
        suspected_atlas=r["suspected_atlas"],
        status=r["status"],
        posted_at=r["posted_at"],
    )


def _validate_project_path(project_path: str) -> Path:
    """[CWE-22] Validate project_path is a real, existing directory — never create arbitrary dirs."""
    p = Path(project_path).resolve()
    if not p.is_dir():
        raise ValueError(f"Project path does not exist: {project_path}")
    if ".." in Path(project_path).parts:
        raise ValueError(f"Path traversal rejected: {project_path}")
    return p


def resolve_investigations(project_path: str, status: str | None = None, limit: int = 100) -> list[Investigation]:
    conn = cohort_db.connect(_validate_project_path(project_path))
    sql = "SELECT * FROM investigations WHERE project_path = ?"
    params: list = [project_path]
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    return [_row_to_investigation(r) for r in conn.execute(sql, params).fetchall()]


def resolve_investigation(investigation_id: int, project_path: str) -> Investigation | None:
    conn = cohort_db.connect(_validate_project_path(project_path))
    r = conn.execute(
        "SELECT * FROM investigations WHERE id = ?", (investigation_id,)
    ).fetchone()
    return _row_to_investigation(r) if r else None


def resolve_hypotheses(investigation_id: int, project_path: str) -> list[Hypothesis]:
    conn = cohort_db.connect(_validate_project_path(project_path))
    rows = conn.execute(
        "SELECT * FROM hypotheses WHERE investigation_id = ? ORDER BY id",
        (investigation_id,),
    ).fetchall()
    return [_row_to_hypothesis(r) for r in rows]


def resolve_evidence(hypothesis_id: int, project_path: str) -> list[Evidence]:
    conn = cohort_db.connect(_validate_project_path(project_path))
    rows = conn.execute(
        "SELECT * FROM evidence WHERE hypothesis_id = ? ORDER BY id",
        (hypothesis_id,),
    ).fetchall()
    return [
        Evidence(
            id=r["id"], hypothesis_id=r["hypothesis_id"],
            kind=r["kind"], content=r["content"],
            file_path=r["file_path"], line=r["line"],
            ref_url=r["ref_url"], created_at=r["created_at"],
        )
        for r in rows
    ]


def resolve_validations(hypothesis_id: int, project_path: str) -> list[Validation]:
    conn = cohort_db.connect(_validate_project_path(project_path))
    rows = conn.execute(
        "SELECT * FROM validations WHERE hypothesis_id = ? ORDER BY id",
        (hypothesis_id,),
    ).fetchall()
    return [
        Validation(
            id=r["id"], hypothesis_id=r["hypothesis_id"],
            entity_type=r["entity_type"], entity_id=r["entity_id"],
            match=r["match"], notes=r["notes"],
            created_at=r["created_at"],
        )
        for r in rows
    ]
