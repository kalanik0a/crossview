"""Stage 2d — Dependency CVE prematch via OSV-Scanner.

OSV-Scanner reads lockfiles (requirements.txt, package-lock.json, go.mod, etc.)
and emits SARIF with CVE IDs. We auto-join those CVEs to our local enrichment.db
to enrich each finding with CVSS, CWE, and CISA-KEV "actively exploited" status.
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
from crossview.enrichment.cache import connect as enr_connect
from crossview.scanner.sarif_ingest import Finding

console = Console()

DEP_RULE_SOURCES = {"osv-scanner"}


def _run_osv_scanner(project_root: Path, json_out: Path) -> bool:
    """OSV-Scanner doesn't emit SARIF in stable releases yet — use JSON.
    Output structure:
      {"results": [{"source":..., "packages": [{"package":..., "vulnerabilities":[...]}]}]}
    """
    binary = shutil.which("osv-scanner")
    if not binary:
        console.log(
            "[yellow]osv-scanner not on PATH. Install: "
            "https://google.github.io/osv-scanner/installation/[/yellow]"
        )
        return False
    cmd = [
        binary, "scan",
        "--format", "json",
        "--output", str(json_out),
        "-r", str(project_root),
    ]
    try:
        # OSV-Scanner returns nonzero when issues are found; treat as success.
        subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return json_out.exists()
    except subprocess.TimeoutExpired:
        console.log("[red]osv-scanner timed out (10 min)[/red]")
        return False


def _parse_osv_json(path: Path) -> list[Finding]:
    if not path.exists():
        return []
    try:
        doc = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []

    findings: list[Finding] = []
    for result in doc.get("results", []) or []:
        source = (result.get("source") or {}).get("path") or ""
        for pkg in result.get("packages", []) or []:
            pkg_info = pkg.get("package") or {}
            pkg_name = pkg_info.get("name") or ""
            pkg_version = pkg_info.get("version") or ""
            ecosystem = pkg_info.get("ecosystem") or ""
            for vuln in pkg.get("vulnerabilities", []) or []:
                vid = vuln.get("id") or ""
                summary = vuln.get("summary") or ""
                # Aliases often include the CVE id when the OSV id is something else
                cve_ids = [
                    a for a in (vuln.get("aliases", []) or [])
                    if a.startswith("CVE-")
                ]
                if vid.startswith("CVE-"):
                    cve_ids.insert(0, vid)
                # Severity (CVSS) — OSV puts it under .severity[].score
                severity_label = "warning"
                for sev in vuln.get("severity", []) or []:
                    if sev.get("type", "").startswith("CVSS"):
                        severity_label = "error"
                        break
                findings.append(
                    Finding(
                        rule_id=vid,
                        rule_source="osv-scanner",
                        severity=severity_label,
                        message=f"{pkg_name}@{pkg_version} ({ecosystem}): {summary}",
                        file_path=source,
                        line_start=None,
                        line_end=None,
                        cwe_ids=[],  # filled in by enrichment join below
                        raw={
                            "vuln_id": vid,
                            "cve_ids": cve_ids,
                            "package": pkg_name,
                            "version": pkg_version,
                            "ecosystem": ecosystem,
                        },
                    )
                )
    return findings


def _enrich_with_cwe_and_kev(findings: list[Finding]) -> list[Finding]:
    """Join OSV findings against enrichment.db: pull CWEs and KEV status per CVE."""
    if not findings:
        return findings
    enr = enr_connect()
    for f in findings:
        cve_ids = f.raw.get("cve_ids", [])
        if not cve_ids:
            continue
        cwes: list[str] = []
        in_kev = False
        for cve in cve_ids:
            for r in enr.execute(
                "SELECT cwe_id FROM cwe_cves WHERE cve_id = ?", (cve,)
            ):
                cwes.append(r["cwe_id"])
            kev_row = enr.execute(
                "SELECT 1 FROM kev WHERE cve_id = ?", (cve,)
            ).fetchone()
            if kev_row:
                in_kev = True
        # de-dup
        seen, uniq = set(), []
        for c in cwes:
            if c not in seen:
                seen.add(c)
                uniq.append(c)
        f.cwe_ids.extend(uniq)
        if in_kev:
            f.severity = "error"
            f.message = f.message + "  [⚠ in CISA KEV — exploited in the wild]"
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
                WHERE project_path = ? AND rule_source = 'osv-scanner'
            )
            """,
            (project_path, project_path),
        )
        conn.execute(
            "DELETE FROM scan_results WHERE project_path = ? AND rule_source = 'osv-scanner'",
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
                    VALUES (?, NULL, ?, 0.8, ?, 'active')
                    """,
                    (inv_id, f"Vulnerable dependency: {f.message[:200]}", cwe),
                )
                inserted_hyps += 1

    return {"scan_results": inserted_results, "investigations": inserted_invs, "hypotheses": inserted_hyps}


def run_prematch_deps(project_root: Path) -> dict:
    project_root = project_root.resolve()
    conn = cohort_db.connect(project_root)

    console.rule("[bold]Stage 2d — Dependency CVE prematch[/bold]")

    findings: list[Finding] = []
    with tempfile.TemporaryDirectory(prefix="crossview-deps-") as tmpdir:
        json_out = Path(tmpdir) / "osv.json"
        console.log("Running osv-scanner...")
        if _run_osv_scanner(project_root, json_out):
            findings = _parse_osv_json(json_out)
            console.log(f"[green]osv-scanner: {len(findings)} findings[/green]")
        else:
            console.log("[dim]osv-scanner: skipped[/dim]")

    findings = _enrich_with_cwe_and_kev(findings)
    summary = _persist_findings(conn, project_root, findings)

    t = Table(title="Stage 2d — deps totals")
    t.add_column("metric")
    t.add_column("count", justify="right")
    t.add_row("findings ingested", f"{len(findings):,}")
    t.add_row("scan_results rows", f"{summary['scan_results']:,}")
    t.add_row("investigations opened", f"{summary['investigations']:,}")
    t.add_row("hypotheses seeded", f"{summary['hypotheses']:,}")
    console.print(t)

    if findings:
        kev_count = sum(1 for f in findings if "in CISA KEV" in f.message)
        if kev_count:
            console.print(f"[bold red]⚠ {kev_count} of these are in CISA KEV (actively exploited)[/bold red]")
        eco = Counter(f.raw.get("ecosystem", "") for f in findings)
        if eco:
            et = Table(title="By ecosystem")
            et.add_column("ecosystem")
            et.add_column("count", justify="right")
            for k, n in eco.most_common():
                et.add_row(k or "?", f"{n:,}")
            console.print(et)

    return {"findings": len(findings), **summary}
