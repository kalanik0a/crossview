"""Parse Bandit's native JSON output into our normalized Finding dataclass.

Bandit doesn't ship SARIF natively in the version pinned in pyproject; rather
than add a fragile bandit-sarif-formatter dep we map the JSON directly.
"""
from __future__ import annotations

import json
from pathlib import Path

from crossview.scanner.sarif_ingest import Finding


def parse_bandit_json(path: Path) -> list[Finding]:
    if not path.exists():
        return []
    try:
        doc = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []

    findings: list[Finding] = []
    for r in doc.get("results", []) or []:
        cwe_field = r.get("issue_cwe") or {}
        cwe_id = None
        if isinstance(cwe_field, dict) and cwe_field.get("id") is not None:
            cwe_id = f"CWE-{cwe_field['id']}"
        cwes = [cwe_id] if cwe_id else []

        severity_map = {
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
        }
        severity = severity_map.get(
            (r.get("issue_severity") or "").upper(), "warning"
        )

        line = r.get("line_number")
        line_range = r.get("line_range") or [line, line]
        line_start = line_range[0] if line_range else line
        line_end = line_range[-1] if line_range else line

        findings.append(
            Finding(
                rule_id=r.get("test_id", ""),
                rule_source="bandit",
                severity=severity,
                message=r.get("issue_text", "") or "",
                file_path=r.get("filename", "") or "",
                line_start=line_start,
                line_end=line_end,
                cwe_ids=cwes,
                raw=r,
            )
        )

    return findings
