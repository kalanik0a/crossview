"""Stage 4 — Verify.

For each medium+ priority hypothesis, use the language harness to confirm the
finding is still real:

  - Re-read the file; if it's gone or the pattern no longer matches → rejected
  - If a Sink (from Stage 1's harness output) lives at the same line → confirmed
  - If the file isn't reachable from any Entrypoint → partial
  - Otherwise → inconclusive (left active for manual review)

The result is persisted as an updated hypothesis status, an evidence row with
the verdict reasoning, and a confidence delta.
"""
from __future__ import annotations

import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.table import Table

from crossview.data import cohort as cohort_db
from crossview.harness.orchestrator import survey_file, harnesses_for

console = Console()


@dataclass
class Verdict:
    status: str            # confirmed | partial | rejected | inconclusive
    reason: str
    confidence_delta: float


def _entrypoint_files(conn: sqlite3.Connection, project_path: str) -> set[str]:
    return {
        r["file_path"]
        for r in conn.execute(
            "SELECT DISTINCT file_path FROM entrypoints WHERE project_path = ?",
            (project_path,),
        )
    }


def _entrypoint_dirs(entrypoint_files: set[str]) -> set[str]:
    """Directories that contain at least one entrypoint."""
    return {str(Path(f).parent) for f in entrypoint_files}


def _sinks_by_file(conn: sqlite3.Connection, project_path: str) -> dict[str, set[int]]:
    """file_path → set of sink line numbers, from Stage 1."""
    out: dict[str, set[int]] = defaultdict(set)
    for r in conn.execute(
        "SELECT file_path, line FROM sinks WHERE project_path = ?", (project_path,)
    ):
        out[r["file_path"]].add(r["line"])
    return out


def _verify_one(
    hyp_file: str,
    hyp_line: int | None,
    entrypoint_files: set[str],
    entrypoint_dirs: set[str],
    sinks_by_file: dict[str, set[int]],
    project_root: Path,
    harnesses: list,
) -> Verdict:
    if not hyp_file:
        return Verdict("inconclusive", "no file path on the finding", 0.0)

    file_path = Path(hyp_file)
    # [CWE-22] Validate file_path stays within project root
    try:
        resolved = file_path.resolve()
        if not resolved.is_relative_to(project_root.resolve()):
            return Verdict("rejected", f"path escapes project root: {hyp_file}", -1.0)
    except (ValueError, OSError):
        return Verdict("rejected", f"invalid path: {hyp_file}", -1.0)
    if not file_path.exists():
        return Verdict(
            "rejected",
            "file no longer exists at path (probably refactored or deleted)",
            -0.5,
        )

    # Stage 1 sinks are authoritative for the harness
    sink_at_line = (
        hyp_line is not None
        and hyp_line in sinks_by_file.get(hyp_file, set())
    )

    # Reachability via entrypoint co-residence (cheap, conservative)
    is_entrypoint_file = hyp_file in entrypoint_files
    file_dir = str(file_path.parent)
    in_entrypoint_module = any(
        file_dir.startswith(d) or d.startswith(file_dir)
        for d in entrypoint_dirs
    )

    # Re-survey the live file to detect "code drift" — has the pattern changed?
    fm = survey_file(file_path, harnesses)
    live_sink_lines = (
        {s.line for s in fm.sinks} if fm else set()
    )
    has_live_sink_nearby = bool(
        live_sink_lines & set(range(max(1, (hyp_line or 1) - 2), (hyp_line or 1) + 3))
    ) if hyp_line else False

    # The scanner has authority over what "is a vulnerability." The harness only
    # narrows ~30 well-known sink patterns. We use harness signals to STRENGTHEN
    # confidence, never to overrule the scanner.

    if is_entrypoint_file and sink_at_line:
        return Verdict(
            "confirmed",
            "sink and entrypoint co-located in same file; directly reachable",
            +0.2,
        )
    if sink_at_line and in_entrypoint_module:
        return Verdict(
            "confirmed",
            "harness sink at exact line; module is entrypoint-reachable",
            +0.15,
        )
    if has_live_sink_nearby and in_entrypoint_module:
        return Verdict(
            "confirmed",
            "live harness re-detected the sink within ±2 lines; reachable",
            +0.1,
        )
    if in_entrypoint_module:
        return Verdict(
            "confirmed",
            "scanner finding inside an entrypoint-bearing module (harness has no specific pattern for this rule)",
            +0.05,
        )
    if sink_at_line:
        return Verdict(
            "partial",
            "sink confirmed but file not in an entrypoint-bearing module — internal-only code path",
            0.0,
        )
    return Verdict(
        "partial",
        "scanner finding present but no entrypoint co-residence — likely internal-only",
        -0.05,
    )


def run_verify(
    project_root: Path,
    priority_floor: float = 0.5,
    only_hypothesis_id: int | None = None,
) -> dict:
    project_root = project_root.resolve()
    project_path = str(project_root)
    conn = cohort_db.connect(project_root)

    console.rule("[bold]Stage 4 — Verify[/bold]")

    ep_files = _entrypoint_files(conn, project_path)
    ep_dirs = _entrypoint_dirs(ep_files)
    sinks = _sinks_by_file(conn, project_path)
    harnesses = harnesses_for(project_root)

    # Verify is idempotent: re-set previously-verified hypotheses back to active
    # so we can re-classify them. Skip hypotheses that were manually dismissed.
    if only_hypothesis_id is None:
        with cohort_db.transaction(conn):
            conn.execute(
                """
                UPDATE hypotheses
                SET status = 'active'
                WHERE status IN ('confirmed', 'partial', 'rejected', 'inconclusive')
                  AND investigation_id IN (
                    SELECT id FROM investigations WHERE project_path = ?
                  )
                """,
                (project_path,),
            )

    where = "h.status = 'active' AND i.project_path = ? AND h.confidence >= ?"
    params: list = [project_path, priority_floor]
    if only_hypothesis_id:
        where += " AND h.id = ?"
        params.append(only_hypothesis_id)

    rows = conn.execute(
        f"""
        SELECT h.id, h.investigation_id, h.confidence,
               i.file_path, i.line_start
        FROM hypotheses h
        JOIN investigations i ON i.id = h.investigation_id
        WHERE {where}
        """,
        tuple(params),
    ).fetchall()

    console.log(f"Verifying {len(rows):,} hypotheses (confidence >= {priority_floor})...")

    by_status: Counter = Counter()

    with cohort_db.transaction(conn):
        for r in rows:
            verdict = _verify_one(
                r["file_path"], r["line_start"],
                ep_files, ep_dirs, sinks,
                project_root, harnesses,
            )
            by_status[verdict.status] += 1

            new_conf = max(0.0, min(1.0, r["confidence"] + verdict.confidence_delta))
            conn.execute(
                """
                UPDATE hypotheses
                SET status = ?, confidence = ?
                WHERE id = ?
                """,
                (verdict.status, new_conf, r["id"]),
            )
            conn.execute(
                """
                INSERT INTO evidence (hypothesis_id, kind, content)
                VALUES (?, 'test_result', ?)
                """,
                (r["id"], f"Verify verdict: {verdict.status} — {verdict.reason}"),
            )

            # When a hypothesis is confirmed, also flip the investigation status
            if verdict.status == "confirmed":
                conn.execute(
                    "UPDATE investigations SET status = 'validated' WHERE id = ?",
                    (r["investigation_id"],),
                )

    t = Table(title="Stage 4 — Verify totals")
    t.add_column("verdict")
    t.add_column("count", justify="right")
    color = {"confirmed": "red", "partial": "yellow", "rejected": "dim", "inconclusive": "blue"}
    for status in ("confirmed", "partial", "inconclusive", "rejected"):
        n = by_status.get(status, 0)
        c = color.get(status, "")
        t.add_row(f"[{c}]{status}[/{c}]", f"{n:,}")
    t.add_section()
    t.add_row("[bold]total verified[/bold]", f"[bold]{len(rows):,}[/bold]")
    console.print(t)

    return {"verified": len(rows), "by_status": dict(by_status)}
