"""Stage 2c — IaC / container prematch.

  - Trivy: container images, IaC (Dockerfile, Compose, K8s, Terraform), filesystem
  - Hadolint: focused Dockerfile lint

Both emit SARIF natively. Graceful skip when binaries are absent.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.table import Table

from crossview.data import cohort as cohort_db
from crossview.scanner.sarif_ingest import Finding, parse_sarif

console = Console()

IAC_RULE_SOURCES = {"trivy", "hadolint"}


def _run_trivy(project_root: Path, sarif_out: Path) -> bool:
    binary = shutil.which("trivy")
    if not binary:
        console.log(
            "[yellow]trivy not on PATH. Install: "
            "https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
            "[/yellow]"
        )
        return False
    cmd = [
        binary, "fs",
        "--format", "sarif",
        "--output", str(sarif_out),
        "--scanners", "vuln,misconfig,secret",
        "--skip-dirs", "node_modules,.venv,venv,__pycache__,.next,build,dist,.git,htmlcov,data/raw",
        "--quiet",
        str(project_root),
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        return sarif_out.exists()
    except subprocess.TimeoutExpired:
        console.log("[red]trivy timed out (15 min)[/red]")
        return False


def _run_hadolint(project_root: Path) -> list[Finding]:
    binary = shutil.which("hadolint")
    if not binary:
        console.log(
            "[yellow]hadolint not on PATH. Install: "
            "https://github.com/hadolint/hadolint#install[/yellow]"
        )
        return []

    dockerfiles = list(project_root.rglob("Dockerfile"))
    dockerfiles += list(project_root.rglob("Dockerfile.*"))
    # Filter out vendored / nested dependencies
    dockerfiles = [
        d for d in dockerfiles
        if not any(
            p in {"node_modules", ".venv", "venv", ".git", "build", "dist"}
            for p in d.parts
        )
    ]
    if not dockerfiles:
        console.log("[dim]no Dockerfiles found, skipping hadolint[/dim]")
        return []

    findings: list[Finding] = []
    for df in dockerfiles:
        try:
            result = subprocess.run(
                [binary, "--format", "sarif", str(df)],
                capture_output=True, text=True, timeout=60,
            )
        except subprocess.TimeoutExpired:
            console.log(f"[yellow]hadolint timed out for {df}[/yellow]")
            continue
        if not result.stdout.strip():
            continue
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
            f.write(result.stdout)
            tmp_path = Path(f.name)
        try:
            findings.extend(parse_sarif(tmp_path, "hadolint"))
        finally:
            tmp_path.unlink(missing_ok=True)

    return findings


def _persist_findings(conn, project_root: Path, findings: list[Finding]) -> dict:
    project_path = str(project_root.resolve())
    inserted_results = inserted_invs = inserted_hyps = 0

    with cohort_db.transaction(conn):
        conn.execute(
            """
            DELETE FROM investigations
            WHERE project_path = ? AND scanner_finding_id IN (
                SELECT id FROM scan_results
                WHERE project_path = ? AND rule_source IN ('trivy', 'hadolint')
            )
            """,
            (project_path, project_path),
        )
        conn.execute(
            "DELETE FROM scan_results WHERE project_path = ? AND rule_source IN ('trivy', 'hadolint')",
            (project_path,),
        )

        for f in findings:
            cur = conn.execute(
                """
                INSERT INTO scan_results
                    (project_path, file_path, line_start, line_end, rule_id,
                     rule_source, severity, message, cwe_id, raw_finding_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    project_path, f.file_path, f.line_start, f.line_end,
                    f.rule_id, f.rule_source, f.severity, f.message[:2000],
                    f.cwe_ids[0] if f.cwe_ids else None,
                    json.dumps(f.raw, default=str)[:50000],
                ),
            )
            scan_id = cur.lastrowid
            inserted_results += 1

            cur = conn.execute(
                """
                INSERT INTO investigations
                    (project_path, file_path, line_start, line_end, summary,
                     status, scanner_finding_id)
                VALUES (?, ?, ?, ?, ?, 'open', ?)
                """,
                (project_path, f.file_path, f.line_start, f.line_end,
                 f.message[:500], scan_id),
            )
            inv_id = cur.lastrowid
            inserted_invs += 1

            for cwe in f.cwe_ids or [None]:
                conn.execute(
                    """
                    INSERT INTO hypotheses
                        (investigation_id, parent_id, statement, confidence,
                         suspected_cwe, status)
                    VALUES (?, NULL, ?, 0.6, ?, 'active')
                    """,
                    (inv_id, f"IaC/container finding: {f.message[:200]}", cwe),
                )
                inserted_hyps += 1

    return {"scan_results": inserted_results, "investigations": inserted_invs, "hypotheses": inserted_hyps}


def run_prematch_iac(project_root: Path) -> dict:
    project_root = project_root.resolve()
    conn = cohort_db.connect(project_root)

    console.rule("[bold]Stage 2c — IaC / container prematch[/bold]")
    findings: list[Finding] = []

    with tempfile.TemporaryDirectory(prefix="crossview-iac-") as tmpdir:
        tmp = Path(tmpdir)

        console.log("Running trivy...")
        trivy_sarif = tmp / "trivy.sarif"
        if _run_trivy(project_root, trivy_sarif):
            tv_findings = parse_sarif(trivy_sarif, "trivy")
            console.log(f"[green]trivy: {len(tv_findings)} findings[/green]")
            findings.extend(tv_findings)
        else:
            console.log("[dim]trivy: skipped[/dim]")

    console.log("Running hadolint...")
    hl_findings = _run_hadolint(project_root)
    console.log(f"[green]hadolint: {len(hl_findings)} findings[/green]")
    findings.extend(hl_findings)

    summary = _persist_findings(conn, project_root, findings)

    t = Table(title="Stage 2c — IaC totals")
    t.add_column("metric")
    t.add_column("count", justify="right")
    t.add_row("findings ingested", f"{len(findings):,}")
    t.add_row("scan_results rows", f"{summary['scan_results']:,}")
    t.add_row("investigations opened", f"{summary['investigations']:,}")
    t.add_row("hypotheses seeded", f"{summary['hypotheses']:,}")
    console.print(t)

    if findings:
        by_source = Counter(f.rule_source for f in findings)
        st = Table(title="By source")
        st.add_column("source")
        st.add_column("count", justify="right")
        for k, n in by_source.most_common():
            st.add_row(k, f"{n:,}")
        console.print(st)

    return {"findings": len(findings), **summary}
