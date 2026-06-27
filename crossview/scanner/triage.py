"""Production-exploit triage.

Filters confirmed findings down to those that are reachable in *production* —
ignoring test files, dev tooling, migrations, build artifacts, and config
templates. Then re-runs TruffleHog with --results=verified to flag any
credential that is still live on its home API (the highest-urgency category).

Output is a focused report ranked by exploit urgency:
  1. Verified-live credentials in production paths
  2. Production-path findings whose CWE has CISA KEV intersect
  3. Production-path LLM-input vulnerabilities (ATLAS AML.T0051)
  4. Other production-path confirmed findings
"""
from __future__ import annotations

import json
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.table import Table

from crossview.data import cohort as cohort_db
from crossview.enrichment.cache import connect as enr_connect
from crossview.scanner.prematch_secrets import _SECRET_VALUE_KEYS

console = Console()

# ─────────────────────── File-path classification ────────────────────────────

PathClass = str  # "production" | "test" | "dev" | "build" | "config_template" | "unknown"

TEST_DIR_NAMES = {"tests", "__tests__", "test", "spec", "__test__", "e2e", "fixtures"}
DEV_DIR_NAMES = {"scripts", "tools", "bin", "dev", "devops"}
BUILD_DIR_NAMES = {
    ".next", "build", "dist", "node_modules", ".venv", "venv",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "alembic", "migrations", "htmlcov", ".tox",
}

TEST_FILE_TOKENS = ("test_", "_test.", ".test.", ".spec.", "conftest.py", ".cy.ts", ".cy.js")
DEV_FILE_TOKENS = (
    "seed_", "seed-", "migrate_", "fix_feeds", "reclassify_", "update_competitor",
    "test_podcast_pipeline", "_baseline.json", ".secrets.baseline",
)


def classify(path: str) -> PathClass:
    parts = path.replace("\\", "/").split("/")
    parts_set = set(parts)
    name = parts[-1] if parts else ""
    name_l = name.lower()

    if parts_set & BUILD_DIR_NAMES:
        return "build"
    if parts_set & TEST_DIR_NAMES:
        return "test"
    if parts_set & DEV_DIR_NAMES:
        return "dev"
    if any(t in name_l for t in TEST_FILE_TOKENS):
        return "test"
    if any(t in name_l for t in DEV_FILE_TOKENS):
        return "dev"
    if name.endswith(".example") or name.endswith(".template") or name == ".env.example":
        return "config_template"
    if name.endswith(".md") or name.endswith(".rst") or name.endswith(".txt"):
        return "doc"
    return "production"


# ─────────────────────── Verified secrets re-run ─────────────────────────────

@dataclass
class LiveSecret:
    cve_or_rule: str
    detector: str
    file_path: str
    line: int | None
    raw: dict


def run_trufflehog_verified(project_root: Path) -> list[LiveSecret]:
    """Run trufflehog with --results=verified to confirm credentials are live."""
    binary = shutil.which("trufflehog")
    if not binary:
        console.log("[yellow]trufflehog not on PATH; skipping live verification[/yellow]")
        return []

    # Exclude crossview's own cohort.db — its raw_finding_json column
    # captures secret values during scan_results inserts and would otherwise
    # re-fire as live findings (own-goal). Trufflehog wants exclude paths in
    # a file (one regex per line).
    exclude_dir = project_root / ".crossview"
    # [CWE-59] Refuse to follow symlinks
    if exclude_dir.is_symlink():
        raise RuntimeError(f"Security: {exclude_dir} is a symlink. Refusing to write through symlinks.")
    exclude_dir.mkdir(parents=True, exist_ok=True)
    exclude_file = exclude_dir / "trufflehog-excludes.txt"
    exclude_file.write_text(
        "\n".join([
            r"\.crossview/",
            r"node_modules/",
            r"\.venv/",
            r"\.next/",
            r"build/",
            r"dist/",
        ]) + "\n",
        encoding="utf-8",
    )

    cmd = [
        binary, "filesystem",
        "--json",
        "--no-update",
        "--results=verified",
        "--exclude-paths", str(exclude_file),
        str(project_root),
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        console.log("[red]trufflehog verification timed out[/red]")
        return []

    out: list[LiveSecret] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not obj.get("Verified"):
            continue
        detector = obj.get("DetectorName", "unknown")
        source = (obj.get("SourceMetadata") or {}).get("Data", {}).get("Filesystem", {})
        out.append(
            LiveSecret(
                cve_or_rule=f"trufflehog/{detector}/verified",
                detector=detector,
                file_path=source.get("file") or "",
                line=source.get("line"),
                # [CWE-312] Strip secret values before storage
                # [CWE-312] Reuse shared constant for secret key stripping
                raw={k: ("[REDACTED]" if k in _SECRET_VALUE_KEYS else v)
                     for k, v in obj.items()},
            )
        )
    return out


# ─────────────────────── Triage assembly ─────────────────────────────────────

@dataclass
class TriageRow:
    rank_bucket: str            # live_secret | kev_intersect | atlas_llm | production_other
    file_path: str
    line: int | None
    cwe_id: str | None
    rule_source: str
    rule_id: str
    severity: str
    message: str
    in_kev: bool = False
    is_atlas: bool = False
    classification: str = "production"
    investigation_id: int | None = None


def _kev_cwes(enr_conn) -> set[str]:
    """All CWE IDs that any KEV row references."""
    out: set[str] = set()
    for r in enr_conn.execute("SELECT cwe_ids_json FROM kev"):
        try:
            for c in json.loads(r["cwe_ids_json"] or "[]"):
                out.add(c)
        except json.JSONDecodeError:
            continue
    return out


def assemble_triage(project_root: Path) -> tuple[list[TriageRow], dict]:
    project_path = str(project_root.resolve())
    cohort_conn = cohort_db.connect(project_root)
    enr_conn = enr_connect()

    kev_cwe_set = _kev_cwes(enr_conn)

    rows = cohort_conn.execute(
        """
        SELECT i.id AS investigation_id,
               i.file_path, i.line_start,
               sr.rule_id, sr.rule_source, sr.severity, sr.message, sr.cwe_id,
               h.suspected_cwe, h.confidence, h.status
        FROM investigations i
        JOIN hypotheses h ON h.investigation_id = i.id
        LEFT JOIN scan_results sr ON sr.id = i.scanner_finding_id
        WHERE i.project_path = ?
          AND h.status = 'confirmed'
        """,
        (project_path,),
    ).fetchall()

    out: list[TriageRow] = []
    for r in rows:
        cls = classify(r["file_path"] or "")
        cwe = r["suspected_cwe"] or r["cwe_id"]
        is_kev = cwe in kev_cwe_set if cwe else False
        is_atlas = (cwe == "CWE-1426") or ("AML.T" in (r["message"] or ""))

        if cls != "production":
            continue  # Skip non-production by design

        bucket = "production_other"
        if is_kev and (r["severity"] == "error" or r["rule_source"] in {"trufflehog", "detect-secrets"}):
            bucket = "kev_intersect"
        elif is_atlas:
            bucket = "atlas_llm"

        out.append(TriageRow(
            rank_bucket=bucket,
            file_path=r["file_path"] or "",
            line=r["line_start"],
            cwe_id=cwe,
            rule_source=r["rule_source"] or "",
            rule_id=r["rule_id"] or "",
            severity=r["severity"] or "warning",
            message=r["message"] or "",
            in_kev=is_kev,
            is_atlas=is_atlas,
            classification=cls,
            investigation_id=r["investigation_id"],
        ))

    summary = {
        "total_confirmed_in_cohort": len(rows),
        "production_only": len(out),
        "by_classification": dict(Counter(classify(r["file_path"] or "") for r in rows)),
        "by_rank_bucket": dict(Counter(t.rank_bucket for t in out)),
    }
    return out, summary


# ─────────────────────── Top-level driver ────────────────────────────────────

def run_triage(
    project_root: Path,
    verify_live_secrets: bool = True,
    out_path: Path | None = None,
) -> dict:
    project_root = project_root.resolve()
    console.rule("[bold red]Production Exploit Triage[/bold red]")

    triage_rows, summary = assemble_triage(project_root)

    # Print bucket overview
    cls_table = Table(title="Findings by file-path classification (across all confirmed)")
    cls_table.add_column("classification")
    cls_table.add_column("count", justify="right")
    for k, n in sorted(summary["by_classification"].items(), key=lambda kv: -kv[1]):
        marker = " [bold green]← production[/bold green]" if k == "production" else ""
        cls_table.add_row(f"{k}{marker}", f"{n:,}")
    console.print(cls_table)

    bucket_table = Table(title="Production findings by exploit-urgency bucket")
    bucket_table.add_column("bucket")
    bucket_table.add_column("count", justify="right")
    for b in ("kev_intersect", "atlas_llm", "production_other"):
        n = summary["by_rank_bucket"].get(b, 0)
        color = {"kev_intersect": "red", "atlas_llm": "yellow", "production_other": "blue"}[b]
        bucket_table.add_row(f"[{color}]{b}[/{color}]", f"{n:,}")
    console.print(bucket_table)

    # Live secrets (TruffleHog verified)
    live_secrets: list[LiveSecret] = []
    if verify_live_secrets:
        console.log("Re-running trufflehog with [bold red]--results=verified[/bold red] (live API checks)...")
        all_live = run_trufflehog_verified(project_root)
        # Restrict to production-path files
        live_secrets = [s for s in all_live if classify(s.file_path) == "production"]

        if all_live:
            t = Table(title=f"Verified-live credentials in production ({len(live_secrets)} of {len(all_live)} total)")
            t.add_column("detector")
            t.add_column("file:line")
            for s in live_secrets:
                t.add_row(s.detector, f"{Path(s.file_path).name}:{s.line or '?'}")
            console.print(t)
        else:
            console.print("[green]No verified-live credentials found.[/green]")

    # The triage output report
    out_path = out_path or (project_root / "CROSSVIEW-TRIAGE.md")
    md = render_markdown(project_root, triage_rows, live_secrets, summary)
    out_path.write_text(md, encoding="utf-8")
    console.print(f"\n[green]wrote[/green] {out_path}")

    return {
        "production_findings": len(triage_rows),
        "live_secrets_in_production": len(live_secrets),
        "by_bucket": summary["by_rank_bucket"],
        "by_classification": summary["by_classification"],
        "report_path": str(out_path),
    }


def render_markdown(
    project_root: Path,
    rows: list[TriageRow],
    live_secrets: list[LiveSecret],
    summary: dict,
) -> str:
    import datetime as dt

    bucket_order = {"kev_intersect": 0, "atlas_llm": 1, "production_other": 2}
    rows_sorted = sorted(rows, key=lambda r: (bucket_order.get(r.rank_bucket, 99), r.file_path, r.line or 0))

    lines: list[str] = []
    lines.append("# Crossview Production Exploit Triage")
    lines.append("")
    lines.append(f"**Project:** `{project_root}`")
    lines.append(f"**Generated:** {dt.datetime.utcnow().isoformat(timespec='seconds')}Z")
    lines.append("")
    lines.append("Filtered to production paths only. Test files, dev tooling, migrations, build artifacts, and config templates are excluded.")
    lines.append("")

    lines.append("## File-path classification (all confirmed findings)")
    lines.append("")
    lines.append("| classification | count |")
    lines.append("|---|---|")
    for k, n in sorted(summary["by_classification"].items(), key=lambda kv: -kv[1]):
        lines.append(f"| {k} | {n} |")
    lines.append("")

    # ── Live credentials (top of report) ────────────────────────────────────
    lines.append("## ⚠ Verified-live credentials in production")
    lines.append("")
    if live_secrets:
        lines.append("These are credentials TruffleHog confirmed are still valid against their home APIs **right now**. Patch first.")
        lines.append("")
        lines.append("| Detector | File | Line |")
        lines.append("|---|---|---|")
        for s in live_secrets:
            lines.append(f"| {s.detector} | `{s.file_path}` | {s.line or '?'} |")
    else:
        lines.append("_No verified-live credentials in production paths. Either credentials are placeholders / dev-only, or TruffleHog wasn't run with --results=verified._")
    lines.append("")

    # ── KEV intersect bucket ────────────────────────────────────────────────
    kev_rows = [r for r in rows_sorted if r.rank_bucket == "kev_intersect"]
    lines.append(f"## KEV intersect (production paths) — {len(kev_rows)} findings")
    lines.append("")
    lines.append("Confirmed scanner findings whose CWE has at least one CVE in the CISA Known Exploited Vulnerabilities catalog. These map to attack patterns in active use.")
    lines.append("")
    if kev_rows:
        lines.append("| File:Line | CWE | Scanner | Severity | Message |")
        lines.append("|---|---|---|---|---|")
        for r in kev_rows[:200]:
            short_msg = r.message.replace("|", "\\|").replace("\n", " ")[:120]
            lines.append(
                f"| `{r.file_path.split('/')[-1]}:{r.line or '?'}` | {r.cwe_id or '—'} | {r.rule_source}/{r.rule_id} | {r.severity} | {short_msg} |"
            )
    else:
        lines.append("_(none)_")
    lines.append("")

    # ── ATLAS LLM bucket ────────────────────────────────────────────────────
    atlas_rows = [r for r in rows_sorted if r.rank_bucket == "atlas_llm"]
    lines.append(f"## ATLAS LLM input flow (production paths) — {len(atlas_rows)} findings")
    lines.append("")
    lines.append("LLM call sites where untrusted input could reach `messages.create()` or `chat.completions.create()`. Maps to AML.T0051 (LLM Prompt Injection).")
    lines.append("")
    if atlas_rows:
        lines.append("| File:Line | Scanner | Message |")
        lines.append("|---|---|---|")
        for r in atlas_rows[:50]:
            short_msg = r.message.replace("|", "\\|").replace("\n", " ")[:120]
            lines.append(
                f"| `{r.file_path.split('/')[-1]}:{r.line or '?'}` | {r.rule_source}/{r.rule_id} | {short_msg} |"
            )
    else:
        lines.append("_(none)_")
    lines.append("")

    # ── Other production findings ───────────────────────────────────────────
    other_rows = [r for r in rows_sorted if r.rank_bucket == "production_other"]
    lines.append(f"## Other production findings — {len(other_rows)} findings")
    lines.append("")
    if other_rows:
        lines.append("| File:Line | CWE | Scanner | Message |")
        lines.append("|---|---|---|---|")
        for r in other_rows[:200]:
            short_msg = r.message.replace("|", "\\|").replace("\n", " ")[:120]
            lines.append(
                f"| `{r.file_path.split('/')[-1]}:{r.line or '?'}` | {r.cwe_id or '—'} | {r.rule_source}/{r.rule_id} | {short_msg} |"
            )
        if len(other_rows) > 200:
            lines.append(f"| _...and {len(other_rows) - 200} more_ | | | |")
    else:
        lines.append("_(none)_")
    lines.append("")

    lines.append("## Methodology")
    lines.append("")
    lines.append("- **Classification.** Each confirmed finding's file path is classified production / test / dev / build / config_template / doc using directory and file-name heuristics.")
    lines.append("- **Live credential check.** TruffleHog re-run with `--results=verified` to confirm credentials are valid against their home APIs at scan time.")
    lines.append("- **KEV intersect bucket.** Findings whose CWE has any CVE in the CISA Known Exploited Vulnerabilities catalog AND severity=error / scanner is a credential detector.")
    lines.append("- **ATLAS LLM bucket.** Findings tagged CWE-1426 or referencing an AML.T-id — i.e. user input flowing into an LLM API.")
    lines.append("")

    return "\n".join(lines)
