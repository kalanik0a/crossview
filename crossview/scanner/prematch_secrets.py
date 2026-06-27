"""Stage 2b — Secrets prematch.

Three tools, three different strengths:
  - detect-secrets (Yelp): plugin-based, Python API, baseline workflow
  - TruffleHog (Trufflesecurity): live verification — confirms a credential is still valid
  - Gitleaks: git history sweep
Each finding maps to CWE-798 (Hardcoded Credentials).

TruffleHog and Gitleaks are external Go binaries. If absent, we log a one-line
install hint and skip; detect-secrets always runs.
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
from crossview.scanner.sarif_ingest import Finding

console = Console()

CWE_HARDCODED = "CWE-798"

# Keys in TruffleHog/Gitleaks JSON that contain actual secret values.
# These MUST be stripped before storing in cohort.db. [CWE-312]
_SECRET_VALUE_KEYS = {"Raw", "RawV2", "Secret", "Match", "secret_value", "Fingerprint"}


def _strip_secret_values(obj: dict) -> dict:
    """Return a copy of a TruffleHog/Gitleaks JSON object with secret values removed."""
    return {k: ("[REDACTED]" if k in _SECRET_VALUE_KEYS else v) for k, v in obj.items()}

SECRETS_EXCLUDES = {
    ".venv", "venv", "node_modules", "__pycache__", ".next", "build",
    "dist", ".git", "htmlcov", ".pytest_cache", ".mypy_cache",
    "data/raw", ".tox", "coverage", ".secrets.baseline",
    ".crossview",  # crossview's own cohort.db captures secret values; never re-scan
}


# ---- detect-secrets ----------------------------------------------------------

# detect-secrets plugin types we trust as high-signal. The two High-Entropy
# detectors (HexHighEntropyString, Base64HighEntropyString) are dropped because
# they fire on file hashes, commit SHAs, lockfile digests, etc., burying real
# findings under noise. KeywordDetector + the named-API detectors give us the
# coverage that actually matters.
DETECT_SECRETS_HIGH_SIGNAL_TYPES = {
    "AWS Access Key",
    "Azure Storage Key",
    "Basic Auth Credentials",
    "Cloudant Credentials",
    "Discord Bot Token",
    "GitHub Token",
    "GitLab Token",
    "IBM Cloud IAM Key",
    "IBM COS HMAC Credentials",
    "JSON Web Token",
    "Mailchimp Access Key",
    "NPM tokens",
    "OpenAI Token",
    "Private Key",
    "SendGrid API Key",
    "Slack Token",
    "SoftLayer Credentials",
    "Square OAuth Secret",
    "Stripe Access Key",
    "Telegram Bot Token",
    "Twilio API Key",
    "Secret Keyword",  # KeywordDetector — name-based, useful even with FPs
}


def _run_detect_secrets(project_root: Path) -> list[Finding]:
    from detect_secrets.core.scan import scan_file
    from detect_secrets.settings import default_settings

    out: list[Finding] = []
    with default_settings():
        for path in project_root.rglob("*"):
            if path.is_symlink():  # [CWE-59] Don't follow symlinks outside project
                continue
            if not path.is_file():
                continue
            if any(part in SECRETS_EXCLUDES for part in path.parts):
                continue
            try:
                secrets = list(scan_file(str(path)))
            except (UnicodeDecodeError, OSError):
                continue
            for s in secrets:
                if s.type not in DETECT_SECRETS_HIGH_SIGNAL_TYPES:
                    continue  # drop the noisy entropy plugins
                out.append(
                    Finding(
                        rule_id=f"detect-secrets/{s.type}",
                        rule_source="detect-secrets",
                        severity="error",
                        message=f"Possible {s.type} detected",
                        file_path=str(path),
                        line_start=s.line_number,
                        line_end=s.line_number,
                        cwe_ids=[CWE_HARDCODED],
                        raw={
                            "type": s.type,
                            "filename": s.filename,
                            "line_number": s.line_number,
                            # [CWE-312] Never store secret values — even truncated
                        },
                    )
                )
    return out


# ---- TruffleHog --------------------------------------------------------------

def _run_trufflehog(project_root: Path) -> list[Finding]:
    binary = shutil.which("trufflehog")
    if not binary:
        console.log(
            "[yellow]trufflehog not on PATH. Install: "
            "https://github.com/trufflesecurity/trufflehog#install[/yellow]"
        )
        return []
    cmd = [binary, "filesystem", "--json", "--no-update", str(project_root)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        console.log("[red]trufflehog timed out[/red]")
        return []

    out: list[Finding] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        # TruffleHog JSON: {"DetectorName":"AWS","Verified":true,"SourceMetadata":...}
        verified = obj.get("Verified", False)
        detector = obj.get("DetectorName", "unknown")
        source = obj.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        file_path = source.get("file") or ""
        line_no = source.get("line")
        out.append(
            Finding(
                rule_id=f"trufflehog/{detector}",
                rule_source="trufflehog",
                severity="error" if verified else "warning",
                message=(
                    f"{detector} secret detected"
                    + (" (VERIFIED — credential is currently valid)" if verified else "")
                ),
                file_path=file_path,
                line_start=line_no,
                line_end=line_no,
                cwe_ids=[CWE_HARDCODED],
                # [CWE-312] Strip secret values from raw JSON before storage
                raw=_strip_secret_values(obj),
            )
        )
    return out


# ---- Gitleaks ----------------------------------------------------------------

def _run_gitleaks(project_root: Path) -> list[Finding]:
    binary = shutil.which("gitleaks")
    if not binary:
        console.log(
            "[yellow]gitleaks not on PATH. Install: "
            "https://github.com/gitleaks/gitleaks#installing[/yellow]"
        )
        return []

    if not (project_root / ".git").exists():
        console.log("[dim]gitleaks: project is not a git repo, skipping history scan[/dim]")
        return []

    with tempfile.TemporaryDirectory(prefix="crossview-gitleaks-") as tmpdir:
        sarif_out = Path(tmpdir) / "gitleaks.sarif"
        cmd = [
            binary, "detect",
            "--source", str(project_root),
            "--report-format", "sarif",
            "--report-path", str(sarif_out),
            "--no-banner",
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            console.log("[red]gitleaks timed out[/red]")
            return []

        from crossview.scanner.sarif_ingest import parse_sarif
        findings = parse_sarif(sarif_out, "gitleaks")
        for f in findings:
            if CWE_HARDCODED not in f.cwe_ids:
                f.cwe_ids.insert(0, CWE_HARDCODED)
        return findings


# ---- Persistence (shared with prematch_code via cohort.db.scan_results) -----

def _persist_findings(conn, project_root: Path, findings: list[Finding]) -> dict:
    project_path = str(project_root.resolve())
    inserted_results = inserted_invs = inserted_hyps = 0

    with cohort_db.transaction(conn):
        # Wipe prior secrets-only findings for this project before re-inserting.
        # Identified by rule_source IN (...) so we don't touch prematch_code rows.
        conn.execute(
            """
            DELETE FROM investigations
            WHERE project_path = ? AND scanner_finding_id IN (
                SELECT id FROM scan_results
                WHERE project_path = ?
                  AND rule_source IN ('detect-secrets', 'trufflehog', 'gitleaks')
            )
            """,
            (project_path, project_path),
        )
        conn.execute(
            """
            DELETE FROM scan_results
            WHERE project_path = ?
              AND rule_source IN ('detect-secrets', 'trufflehog', 'gitleaks')
            """,
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
                    VALUES (?, NULL, ?, 0.7, ?, 'active')
                    """,
                    (inv_id, f"Possible hardcoded secret: {f.message[:200]}", cwe),
                )
                inserted_hyps += 1

    return {"scan_results": inserted_results, "investigations": inserted_invs, "hypotheses": inserted_hyps}


# ---- Top-level ---------------------------------------------------------------

def run_prematch_secrets(project_root: Path) -> dict:
    project_root = project_root.resolve()
    conn = cohort_db.connect(project_root)

    console.rule("[bold]Stage 2b — Secrets prematch[/bold]")

    findings: list[Finding] = []

    console.log("Running detect-secrets...")
    ds_findings = _run_detect_secrets(project_root)
    console.log(f"[green]detect-secrets: {len(ds_findings)} findings[/green]")
    findings.extend(ds_findings)

    console.log("Running trufflehog...")
    th_findings = _run_trufflehog(project_root)
    console.log(f"[green]trufflehog: {len(th_findings)} findings[/green]")
    findings.extend(th_findings)

    console.log("Running gitleaks...")
    gl_findings = _run_gitleaks(project_root)
    console.log(f"[green]gitleaks: {len(gl_findings)} findings[/green]")
    findings.extend(gl_findings)

    summary = _persist_findings(conn, project_root, findings)

    by_source = Counter(f.rule_source for f in findings)
    by_type = Counter(f.rule_id for f in findings)

    t = Table(title="Stage 2b — secrets totals")
    t.add_column("metric")
    t.add_column("count", justify="right")
    t.add_row("findings ingested", f"{len(findings):,}")
    t.add_row("scan_results rows", f"{summary['scan_results']:,}")
    t.add_row("investigations opened", f"{summary['investigations']:,}")
    t.add_row("hypotheses seeded", f"{summary['hypotheses']:,}")
    console.print(t)

    if by_source:
        st = Table(title="By source")
        st.add_column("source")
        st.add_column("count", justify="right")
        for k, n in by_source.most_common():
            st.add_row(k, f"{n:,}")
        console.print(st)

    if by_type:
        rt = Table(title="Top secret types")
        rt.add_column("rule_id")
        rt.add_column("count", justify="right")
        for k, n in by_type.most_common(10):
            rt.add_row(k, f"{n:,}")
        console.print(rt)

    return {"findings": len(findings), **summary}
