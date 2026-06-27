"""Stage 2a — Code SAST prematch via Bandit + Semgrep, normalized through SARIF.

For each finding emitted by either tool:
  1. Insert into cohort.db scan_results
  2. Open an investigation linked to that scan_result
  3. Seed a root hypothesis with the candidate CWE
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from rich.console import Console
from rich.table import Table

from crossview.data import cohort as cohort_db
from crossview.scanner.bandit_ingest import parse_bandit_json
from crossview.scanner.preset_selector import filter_existing_paths, select
from crossview.scanner.sarif_ingest import Finding, parse_sarif
from crossview.scanner.tooling import resolve_tool

console = Console()


# ---- Tool runners ------------------------------------------------------------

BANDIT_EXCLUDE_PATHS = (
    "*/.venv/*", "*/venv/*", "*/node_modules/*", "*/.next/*",
    "*/__pycache__/*", "*/.pytest_cache/*", "*/.mypy_cache/*",
    "*/build/*", "*/dist/*", "*/.git/*", "*/htmlcov/*",
    "*/migrations/*", "*/alembic/versions/*", "*/.tox/*",
    "*/coverage/*", "*/data/*", "*/tests/*", "*/test_*",
)


def _run_bandit(project_root: Path, json_out: Path, config: str | None) -> bool:
    """Run Bandit with JSON output (it doesn't ship SARIF natively)."""
    bandit = resolve_tool("bandit")
    cmd = [
        bandit, "-r", str(project_root),
        "-f", "json",
        "-o", str(json_out),
        "-q",
        "--exclude", ",".join(BANDIT_EXCLUDE_PATHS),
    ]
    if config:
        cfg_path = Path(config)
        if not cfg_path.is_absolute():
            cfg_path = Path(__file__).resolve().parents[2] / cfg_path
        if cfg_path.exists():
            cmd.extend(["-c", str(cfg_path)])
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return json_out.exists()
    except subprocess.TimeoutExpired:
        console.log("[red]bandit timed out[/red]")
        return False
    except FileNotFoundError:
        console.log("[red]bandit not on PATH[/red]")
        return False


SEMGREP_EXCLUDES = (
    "node_modules", ".venv", "venv", "__pycache__", ".next", "build",
    "dist", ".git", "htmlcov", ".pytest_cache", ".mypy_cache", "data/raw",
    "alembic/versions", ".tox",
)


def _run_semgrep(project_root: Path, sarif_out: Path, configs: list[str]) -> bool:
    if not configs:
        console.log("[dim]no semgrep configs selected; skipping[/dim]")
        return False

    semgrep = resolve_tool("semgrep")

    cmd = [
        semgrep, "scan",
        "--sarif", "--output", str(sarif_out),
        "--quiet",
        "--no-git-ignore",  # don't auto-skip files because of git state
        "--metrics=off",
    ]
    for c in configs:
        cmd.extend(["--config", c])
    for ex in SEMGREP_EXCLUDES:
        cmd.extend(["--exclude", ex])
    cmd.append(str(project_root))

    console.log(f"[dim]semgrep configs ({len(configs)}): {', '.join(configs)}[/dim]")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
        if result.returncode != 0 and not sarif_out.exists():
            stderr_tail = "\n".join(result.stderr.splitlines()[-20:])
            console.log(f"[red]semgrep returncode={result.returncode}[/red]")
            console.log(f"[dim]stderr tail:\n{stderr_tail}[/dim]")
        elif result.returncode != 0:
            stderr_tail = "\n".join(result.stderr.splitlines()[-5:])
            console.log(f"[yellow]semgrep returncode={result.returncode} (SARIF still produced)[/yellow]")
            if stderr_tail.strip():
                console.log(f"[dim]stderr tail: {stderr_tail}[/dim]")
        return sarif_out.exists()
    except subprocess.TimeoutExpired:
        console.log("[red]semgrep timed out (20 min)[/red]")
        return False
    except FileNotFoundError:
        console.log("[red]semgrep not on PATH[/red]")
        return False


# ---- Persistence -------------------------------------------------------------

def _persist_findings(conn, project_root: Path, findings: list[Finding]) -> dict:
    project_path = str(project_root.resolve())
    inserted_results = 0
    inserted_invs = 0
    inserted_hypotheses = 0

    with cohort_db.transaction(conn):
        # Clear prior prematch findings for this project. Cascades drop dependent
        # hypotheses + evidence + validations + mitigations.
        conn.execute(
            "DELETE FROM investigations WHERE project_path = ? AND scanner_finding_id IS NOT NULL",
            (project_path,),
        )
        conn.execute("DELETE FROM scan_results WHERE project_path = ?", (project_path,))

        for f in findings:
            # 1. scan_results
            cursor = conn.execute(
                """
                INSERT INTO scan_results
                    (project_path, file_path, line_start, line_end, rule_id,
                     rule_source, severity, message, cwe_id, raw_finding_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    project_path,
                    f.file_path,
                    f.line_start,
                    f.line_end,
                    f.rule_id,
                    f.rule_source,
                    f.severity,
                    f.message[:2000],
                    f.cwe_ids[0] if f.cwe_ids else None,
                    json.dumps(f.raw, default=str)[:50000],
                ),
            )
            scan_id = cursor.lastrowid
            inserted_results += 1

            # 2. investigation
            cursor = conn.execute(
                """
                INSERT INTO investigations
                    (project_path, file_path, line_start, line_end,
                     summary, status, scanner_finding_id)
                VALUES (?, ?, ?, ?, ?, 'open', ?)
                """,
                (
                    project_path,
                    f.file_path,
                    f.line_start,
                    f.line_end,
                    f.message[:500],
                    scan_id,
                ),
            )
            inv_id = cursor.lastrowid
            inserted_invs += 1

            # 3. seed root hypothesis (one per distinct CWE; if no CWE, one generic)
            cwes_to_seed = f.cwe_ids or [None]
            for cwe in cwes_to_seed:
                statement = (
                    f"Pattern matched by {f.rule_source}/{f.rule_id}: {f.message[:200]}"
                )
                conn.execute(
                    """
                    INSERT INTO hypotheses
                        (investigation_id, parent_id, statement, confidence,
                         suspected_cwe, status)
                    VALUES (?, NULL, ?, 0.5, ?, 'active')
                    """,
                    (inv_id, statement, cwe),
                )
                inserted_hypotheses += 1

    return {
        "scan_results": inserted_results,
        "investigations": inserted_invs,
        "hypotheses": inserted_hypotheses,
    }


# ---- Top-level ---------------------------------------------------------------

def _read_project_context(conn, project_root: Path) -> tuple[set[str], set[str]]:
    """Pull languages + frameworks from project_map (Stage 1 must have run)."""
    project_path = str(project_root.resolve())
    row = conn.execute(
        "SELECT languages_json, frameworks_json FROM project_map WHERE project_path = ?",
        (project_path,),
    ).fetchone()
    if not row:
        raise RuntimeError(
            f"No project_map for {project_root}. Run `crossview survey` first."
        )
    langs = set(json.loads(row["languages_json"] or "{}").keys())
    frameworks = set(json.loads(row["frameworks_json"] or "[]"))
    return langs, frameworks


def run_prematch_code(project_root: Path, skip_semgrep: bool = False) -> dict:
    project_root = project_root.resolve()
    conn = cohort_db.connect(project_root)

    languages, frameworks = _read_project_context(conn, project_root)
    chosen = select(languages, frameworks)
    semgrep_cfgs = filter_existing_paths(chosen.get("semgrep", []), project_root)
    bandit_cfg = chosen.get("bandit", [None])[0] if chosen.get("bandit") else None

    console.rule("[bold]Stage 2a — Code prematch[/bold]")
    console.print(f"languages: {sorted(languages)}")
    console.print(f"frameworks: {sorted(frameworks)}")

    findings: list[Finding] = []
    with tempfile.TemporaryDirectory(prefix="crossview-prematch-") as tmpdir:
        tmp = Path(tmpdir)

        # Bandit (Python only — JSON output, native parser)
        if "python" in languages:
            bandit_json = tmp / "bandit.json"
            console.log("Running bandit...")
            if _run_bandit(project_root, bandit_json, bandit_cfg):
                bandit_findings = parse_bandit_json(bandit_json)
                findings.extend(bandit_findings)
                console.log(f"[green]bandit: {len(bandit_findings)} findings[/green]")

        # Semgrep (multi-language)
        if not skip_semgrep and semgrep_cfgs:
            semgrep_sarif = tmp / "semgrep.sarif"
            console.log("Running semgrep...")
            if _run_semgrep(project_root, semgrep_sarif, semgrep_cfgs):
                sg_findings = parse_sarif(semgrep_sarif, "semgrep")
                findings.extend(sg_findings)
                console.log(f"[green]semgrep: {len(sg_findings)} findings[/green]")

    # Persist
    summary = _persist_findings(conn, project_root, findings)

    # Print summary
    t = Table(title=f"Stage 2a totals — {project_root.name}")
    t.add_column("metric")
    t.add_column("count", justify="right")
    t.add_row("findings ingested", f"{len(findings):,}")
    t.add_row("scan_results rows", f"{summary['scan_results']:,}")
    t.add_row("investigations opened", f"{summary['investigations']:,}")
    t.add_row("hypotheses seeded", f"{summary['hypotheses']:,}")
    console.print(t)

    # Top CWEs
    from collections import Counter
    cwe_counter = Counter(f.cwe_ids[0] for f in findings if f.cwe_ids)
    if cwe_counter:
        ct = Table(title="Top CWEs found")
        ct.add_column("CWE")
        ct.add_column("count", justify="right")
        for cwe, n in cwe_counter.most_common(10):
            ct.add_row(cwe, f"{n:,}")
        console.print(ct)

    return {"findings": len(findings), **summary}
