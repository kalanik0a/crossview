"""Stage 1 — Survey.

Walks the project tree, runs language harnesses, persists the structural map
(entrypoints + sinks + framework signals) to <project>/.crossview/cohort.db.

The survey is the agent's structural read of the codebase. Stage 2 (Prematch)
and beyond consume this map.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.table import Table

from crossview.data import cohort as cohort_db
from crossview.harness.base import FileMap
from crossview.harness.orchestrator import survey_tree

console = Console()


def _persist(conn, project_root: Path, results: list[FileMap]) -> dict:
    project_path = str(project_root.resolve())

    languages = Counter(r.language for r in results)
    frameworks: set[str] = set()
    for r in results:
        frameworks.update(r.frameworks_detected)

    ep_rows = []
    sink_rows = []
    for r in results:
        for ep in r.entrypoints:
            ep_rows.append((
                project_path, ep.file, ep.line, ep.kind,
                ep.framework, ep.method, ep.path, ep.handler_name,
                json.dumps(ep.parameters) if ep.parameters else None,
            ))
        for s in r.sinks:
            sink_rows.append((
                project_path, s.file, s.line, s.kind, s.callee,
                json.dumps(s.risk_cwe), s.snippet,
            ))

    with cohort_db.transaction(conn):
        # Replace prior survey data for this project
        conn.execute("DELETE FROM entrypoints WHERE project_path = ?", (project_path,))
        conn.execute("DELETE FROM sinks WHERE project_path = ?", (project_path,))
        conn.executemany(
            """
            INSERT INTO entrypoints
                (project_path, file_path, line, kind, framework, method, path,
                 handler_name, parameters_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_path, file_path, line, kind) DO NOTHING
            """,
            ep_rows,
        )
        conn.executemany(
            """
            INSERT INTO sinks
                (project_path, file_path, line, kind, callee, risk_cwe_json, snippet)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_path, file_path, line, callee) DO NOTHING
            """,
            sink_rows,
        )

        conn.execute(
            """
            INSERT INTO project_map
                (project_path, languages_json, frameworks_json,
                 files_count, entrypoints_count, sinks_count)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_path) DO UPDATE SET
                surveyed_at = datetime('now'),
                languages_json = excluded.languages_json,
                frameworks_json = excluded.frameworks_json,
                files_count = excluded.files_count,
                entrypoints_count = excluded.entrypoints_count,
                sinks_count = excluded.sinks_count
            """,
            (
                project_path,
                json.dumps(dict(languages)),
                json.dumps(sorted(frameworks)),
                len(results),
                len(ep_rows),
                len(sink_rows),
            ),
        )

    return {
        "files": len(results),
        "languages": dict(languages),
        "frameworks": sorted(frameworks),
        "entrypoints": len(ep_rows),
        "sinks": len(sink_rows),
    }


def _print_summary(project_root: Path, summary: dict, results: list[FileMap]) -> None:
    console.rule(f"[bold]Survey: {project_root}[/bold]")

    overview = Table(show_header=False, box=None)
    overview.add_column("k", style="dim")
    overview.add_column("v")
    overview.add_row("Files surveyed", f"{summary['files']:,}")
    overview.add_row("Languages", ", ".join(f"{k}({v})" for k, v in summary["languages"].items()))
    overview.add_row("Frameworks", ", ".join(summary["frameworks"]) or "(none detected)")
    overview.add_row("Entrypoints", f"{summary['entrypoints']:,}")
    overview.add_row("Sinks", f"{summary['sinks']:,}")
    console.print(overview)

    sink_kinds = Counter(s.kind for r in results for s in r.sinks)
    if sink_kinds:
        st = Table(title="Sinks by kind", show_lines=False)
        st.add_column("kind")
        st.add_column("count", justify="right")
        for k, n in sink_kinds.most_common():
            st.add_row(k, f"{n:,}")
        console.print(st)

    ep_kinds = Counter(ep.kind for r in results for ep in r.entrypoints)
    if ep_kinds:
        et = Table(title="Entrypoints by kind", show_lines=False)
        et.add_column("kind")
        et.add_column("count", justify="right")
        for k, n in ep_kinds.most_common():
            et.add_row(k, f"{n:,}")
        console.print(et)


def run_survey(project_root: Path) -> dict:
    project_root = project_root.resolve()
    console.log(f"Surveying {project_root}...")

    results = survey_tree(project_root)
    conn = cohort_db.connect(project_root)
    summary = _persist(conn, project_root, results)
    _print_summary(project_root, summary, results)
    return summary
