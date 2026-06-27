"""Stage 5 — Report.

Three output formats, all from the same cohort.db state:
  - Markdown (CROSSVIEW-REPORT.md): the human-facing deliverable.
  - SARIF 2.1.0 (CROSSVIEW.sarif): OASIS standard for IDE/CI integration.
  - STIX 2.1 (CROSSVIEW.stix.json): threat-intel-friendly export of confirmed findings.
"""
from __future__ import annotations

import datetime as dt
import json
import sqlite3
import uuid
from pathlib import Path

from rich.console import Console

from crossview.data import cohort as cohort_db
from crossview.data.database import connect as ref_connect

console = Console()


# ─────────────────────────── Data assembly ───────────────────────────────────

def _assemble_findings(conn: sqlite3.Connection, project_path: str) -> list[dict]:
    """Build a list of fully-enriched finding records for the report."""
    rows = conn.execute(
        """
        SELECT i.id AS investigation_id,
               i.file_path, i.line_start, i.line_end, i.summary, i.status AS inv_status,
               h.id AS hypothesis_id, h.suspected_cwe, h.confidence, h.status AS hyp_status,
               sr.rule_id, sr.rule_source, sr.severity, sr.message, sr.cwe_id
        FROM investigations i
        JOIN hypotheses h ON h.investigation_id = i.id
        LEFT JOIN scan_results sr ON sr.id = i.scanner_finding_id
        WHERE i.project_path = ?
          AND h.status IN ('confirmed', 'partial')
        ORDER BY
          CASE h.status WHEN 'confirmed' THEN 0 ELSE 1 END,
          h.confidence DESC,
          sr.severity DESC
        """,
        (project_path,),
    ).fetchall()

    findings = []
    for r in rows:
        validations = conn.execute(
            "SELECT entity_type, entity_id FROM validations WHERE hypothesis_id = ?",
            (r["hypothesis_id"],),
        ).fetchall()

        evidence = conn.execute(
            "SELECT kind, content FROM evidence WHERE hypothesis_id = ? ORDER BY id",
            (r["hypothesis_id"],),
        ).fetchall()

        capecs = sorted({v["entity_id"] for v in validations if v["entity_type"] == "capec"})
        attacks = sorted({v["entity_id"] for v in validations if v["entity_type"] == "attack"})
        atlas = sorted({v["entity_id"] for v in validations if v["entity_type"] == "atlas"})
        d3fends = sorted({v["entity_id"] for v in validations if v["entity_type"] == "d3fend"})
        ukcs = sorted({v["entity_id"] for v in validations if v["entity_type"] == "ukc"})

        evidence_dict = {ev["kind"]: ev["content"] for ev in evidence}

        findings.append({
            "investigation_id": r["investigation_id"],
            "hypothesis_id": r["hypothesis_id"],
            "status": r["hyp_status"],
            "confidence": r["confidence"] or 0.0,
            "file_path": r["file_path"] or "",
            "line": r["line_start"],
            "summary": (r["summary"] or "")[:300],
            "rule_id": r["rule_id"] or "",
            "rule_source": r["rule_source"] or "",
            "severity": r["severity"] or "warning",
            "message": r["message"] or "",
            "suspected_cwe": r["suspected_cwe"] or r["cwe_id"] or "",
            "capecs": capecs,
            "attacks": attacks,
            "atlas": atlas,
            "d3fends": d3fends,
            "ukcs": ukcs,
            "evidence": evidence_dict,
        })

    return findings


def _entity_names(ref_conn: sqlite3.Connection, ids: list[str]) -> dict[str, str]:
    if not ids:
        return {}
    placeholders = ",".join("?" * len(ids))
    rows = ref_conn.execute(
        f"SELECT id, name FROM entities WHERE id IN ({placeholders})", ids
    ).fetchall()
    return {r["id"]: r["name"] for r in rows}


# ─────────────────────────── Markdown report ─────────────────────────────────

MARKDOWN_TEMPLATE = """# Crossview Security Report

**Project:** `{project_path}`
**Generated:** {generated_at}
**Crossview version:** {crossview_version}

## Summary

| status | count |
|---|---|
| confirmed | {confirmed_count} |
| partial   | {partial_count}   |

{summary_note}

---

## Confirmed Vulnerabilities

{confirmed_section}

---

## Partial Findings

{partial_section}

---

## Methodology

This report is composed by the Crossview pipeline:

1. **Survey** — language harnesses enumerate entrypoints + sinks.
2. **Prematch** — Bandit, Semgrep, detect-secrets, TruffleHog, Gitleaks, Trivy, Hadolint, OSV-Scanner emit findings normalized through SARIF.
3. **Investigate** — each finding is walked across the canonical MITRE silo
   (CWE → CAPEC → ATT&CK → ATLAS → D3FEND → UKC) and joined to the local CVE / CISA-KEV cache.
4. **Verify** — the language harness re-checks the live code; status is set to confirmed / partial / rejected based on entrypoint reachability.
5. **Report** — this document.

Sources: MITRE CAPEC, CWE, ATT&CK Enterprise/Mobile/ICS, ATLAS, D3FEND, NVD CVE, CISA KEV.
"""


FINDING_BLOCK = """### {n}. `{file_path}`:{line} — {short}

| field | value |
|---|---|
| Status | **{status_upper}** |
| Confidence | {confidence:.2f} |
| Severity | {severity} |
| Scanner | `{rule_source}` / `{rule_id}` |
| CWE | {cwe_link} |

**Finding:** {message}

**Cross-source chain (canonical):**

{chain_table}

**Real-world signal:**

{external_signal}

**Suggested mitigations (D3FEND):**

{d3fend_block}

---
"""


def _format_chain_table(f: dict, names: dict[str, str]) -> str:
    rows = []
    if f["capecs"]:
        rows.append(f"| CAPEC | {', '.join(f['capecs'][:8])} |")
    if f["attacks"]:
        rows.append(f"| ATT&CK | {', '.join(f['attacks'][:8])} |")
    if f["atlas"]:
        rows.append(f"| ATLAS  | {', '.join(f['atlas'])} |")
    if f["ukcs"]:
        ukc_labels = [f"{u} ({names.get(u, '?')})" for u in f["ukcs"]]
        rows.append(f"| UKC    | {', '.join(ukc_labels)} |")
    if not rows:
        return "_(no canonical chain — likely no CWE on the original finding)_"
    return "| domain | entities |\n|---|---|\n" + "\n".join(rows)


def _format_d3fend_block(f: dict, names: dict[str, str]) -> str:
    if not f["d3fends"]:
        return "_(no D3FEND mitigations linked from this CWE)_"
    items = []
    for d in f["d3fends"][:10]:
        nm = names.get(d, d)
        items.append(f"- **{d}** — {nm}")
    if len(f["d3fends"]) > 10:
        items.append(f"- _...and {len(f['d3fends']) - 10} more_")
    return "\n".join(items)


def _format_external_signal(f: dict) -> str:
    chunks = []
    for kind, content in f["evidence"].items():
        if kind == "external_ref":
            chunks.append(content)
    return "\n\n".join(chunks) if chunks else "_(no external signal collected)_"


def _short_label(f: dict, names: dict[str, str]) -> str:
    cwe = f["suspected_cwe"]
    if cwe and cwe in names:
        return f"{cwe} {names[cwe]}"
    return f["rule_id"] or "finding"


def render_markdown(
    project_path: str,
    findings: list[dict],
    names: dict[str, str],
) -> str:
    confirmed = [f for f in findings if f["status"] == "confirmed"]
    partial = [f for f in findings if f["status"] == "partial"]

    def render_section(items: list[dict]) -> str:
        if not items:
            return "_(none)_\n"
        out = []
        for i, f in enumerate(items, 1):
            cwe = f["suspected_cwe"]
            cwe_link = (
                f"[{cwe}](https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html)"
                if cwe and cwe.startswith("CWE-") else (cwe or "—")
            )
            block = FINDING_BLOCK.format(
                n=i,
                file_path=f["file_path"],
                line=f["line"] or "?",
                short=_short_label(f, names),
                status_upper=f["status"].upper(),
                confidence=f["confidence"],
                severity=f["severity"],
                rule_source=f["rule_source"],
                rule_id=f["rule_id"],
                cwe_link=cwe_link,
                message=f["message"][:600],
                chain_table=_format_chain_table(f, names),
                external_signal=_format_external_signal(f),
                d3fend_block=_format_d3fend_block(f, names),
            )
            out.append(block)
        return "\n".join(out)

    summary_note = ""
    if confirmed:
        summary_note = (
            f"Of the {len(confirmed)} confirmed findings, "
            f"prioritize those linked to CISA KEV (actively exploited in the wild)."
        )

    return MARKDOWN_TEMPLATE.format(
        project_path=project_path,
        generated_at=dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        crossview_version="0.1.0",
        confirmed_count=len(confirmed),
        partial_count=len(partial),
        summary_note=summary_note,
        confirmed_section=render_section(confirmed),
        partial_section=render_section(partial),
    )


# ─────────────────────────── SARIF 2.1.0 export ──────────────────────────────

def render_sarif(project_path: str, findings: list[dict]) -> dict:
    """OASIS SARIF 2.1.0 representation of findings. One run, multiple results."""
    results = []
    rules: dict[str, dict] = {}
    for f in findings:
        rid = f["rule_id"] or "crossview/finding"
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f["message"][:200] or rid},
                "properties": {
                    "tags": [
                        f["rule_source"],
                        f["status"],
                    ] + [c for c in [f["suspected_cwe"]] if c],
                },
            }
        results.append({
            "ruleId": rid,
            "level": {
                "error": "error", "warning": "warning", "note": "note",
                "confirmed": "error", "partial": "warning",
            }.get(f["status"], "warning"),
            "message": {"text": f["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file_path"]},
                    "region": {"startLine": f["line"] or 1},
                }
            }],
            "properties": {
                "crossview": {
                    "status": f["status"],
                    "confidence": f["confidence"],
                    "capecs": f["capecs"],
                    "attacks": f["attacks"],
                    "atlas": f["atlas"],
                    "d3fends": f["d3fends"],
                    "ukcs": f["ukcs"],
                    "investigation_id": f["investigation_id"],
                },
            },
        })

    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "crossview",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/crossview/crossview",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "properties": {"projectPath": project_path},
        }],
    }


# ─────────────────────────── STIX 2.1 export ─────────────────────────────────

def render_stix(project_path: str, findings: list[dict]) -> dict:
    """Each confirmed finding emits a STIX 'vulnerability' SDO with relationships
    to canonical 'attack-pattern' (CAPEC) and 'course-of-action' (D3FEND).
    """
    confirmed = [f for f in findings if f["status"] == "confirmed"]
    objects: list[dict] = []

    bundle_id = f"bundle--{uuid.uuid4()}"
    now = dt.datetime.utcnow().isoformat(timespec="seconds") + "Z"

    for f in confirmed:
        vuln_id = f"vulnerability--{uuid.uuid4()}"
        external_refs = []
        if f["suspected_cwe"]:
            cwe_num = f["suspected_cwe"].split("-")[-1]
            external_refs.append({
                "source_name": "cwe",
                "external_id": f["suspected_cwe"],
                "url": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
            })

        objects.append({
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": vuln_id,
            "created": now,
            "modified": now,
            "name": f["suspected_cwe"] or f["rule_id"] or "crossview-finding",
            "description": (
                f"{f['message']} | location: {f['file_path']}:{f['line']} "
                f"| confidence: {f['confidence']:.2f}"
            ),
            "external_references": external_refs,
            "x_crossview_status": f["status"],
            "x_crossview_confidence": f["confidence"],
        })

        for capec in f["capecs"]:
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "relationship_type": "exploited-using",
                "source_ref": vuln_id,
                "target_ref": f"attack-pattern--{capec.lower()}",  # symbolic — consumer can resolve
                "x_crossview_target_external_id": capec,
            })

        for d3 in f["d3fends"][:5]:
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "relationship_type": "mitigated-by",
                "source_ref": vuln_id,
                "target_ref": f"course-of-action--{d3.replace(':', '-').lower()}",
                "x_crossview_target_external_id": d3,
            })

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects,
    }


# ─────────────────────────── Top-level ───────────────────────────────────────

def run_report(project_root: Path, out_dir: Path | None = None) -> dict:
    project_root = project_root.resolve()
    project_path = str(project_root)
    out_dir = (out_dir or project_root).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    cohort_conn = cohort_db.connect(project_root)
    ref_conn = ref_connect()

    console.rule("[bold]Stage 5 — Report[/bold]")

    findings = _assemble_findings(cohort_conn, project_path)
    if not findings:
        console.log("[yellow]No confirmed or partial findings to report. Run survey + prematch + investigate + verify first.[/yellow]")
        return {"findings": 0}

    # Pull canonical names for entities referenced in findings
    all_ids = set()
    for f in findings:
        for k in ("capecs", "attacks", "atlas", "d3fends", "ukcs"):
            all_ids.update(f[k])
        if f["suspected_cwe"]:
            all_ids.add(f["suspected_cwe"])
    names = _entity_names(ref_conn, sorted(all_ids))

    md = render_markdown(project_path, findings, names)
    sarif = render_sarif(project_path, findings)
    stix = render_stix(project_path, findings)

    md_path = out_dir / "CROSSVIEW-REPORT.md"
    sarif_path = out_dir / "CROSSVIEW.sarif"
    stix_path = out_dir / "CROSSVIEW.stix.json"

    md_path.write_text(md, encoding="utf-8")
    sarif_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    stix_path.write_text(json.dumps(stix, indent=2), encoding="utf-8")

    # Client-grade HTML (always) + PDF (when a renderer is available)
    from crossview.reporting import html_to_pdf, render_html
    html = render_html(project_path, findings, names)
    html_path = out_dir / "CROSSVIEW-REPORT.html"
    html_path.write_text(html, encoding="utf-8")
    pdf_path = out_dir / "CROSSVIEW-REPORT.pdf"
    pdf_engine = html_to_pdf(html, pdf_path)

    confirmed = sum(1 for f in findings if f["status"] == "confirmed")
    partial = sum(1 for f in findings if f["status"] == "partial")

    console.print(f"[green]wrote[/green] {md_path}")
    console.print(f"[green]wrote[/green] {sarif_path}")
    console.print(f"[green]wrote[/green] {stix_path}")
    console.print(f"[green]wrote[/green] {html_path}")
    if pdf_engine:
        console.print(f"[green]wrote[/green] {pdf_path} [dim](via {pdf_engine})[/dim]")
    else:
        console.print("[dim]PDF skipped — install 'weasyprint' or a Playwright Chromium for PDF output.[/dim]")
    console.print(f"\n  confirmed: {confirmed}    partial: {partial}    total: {len(findings)}")

    result = {
        "findings": len(findings),
        "confirmed": confirmed,
        "partial": partial,
        "markdown": str(md_path),
        "sarif": str(sarif_path),
        "stix": str(stix_path),
        "html": str(html_path),
    }
    if pdf_engine:
        result["pdf"] = str(pdf_path)
    return result
