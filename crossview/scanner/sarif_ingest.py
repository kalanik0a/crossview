"""Parse SARIF 2.1.0 (OASIS Standard) output from any tool into normalized findings.

We keep this format-loyal: tools that emit SARIF properly (Bandit, Semgrep,
Trivy, etc.) all flow through this single ingest path.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

CWE_RE = re.compile(r"CWE-\d+")


@dataclass
class Finding:
    rule_id: str
    rule_source: str        # bandit | semgrep | njsscan | trufflehog | trivy | osv-scanner
    severity: str           # error | warning | note
    message: str
    file_path: str
    line_start: int | None
    line_end: int | None
    cwe_ids: list[str]
    raw: dict


def _extract_cwe_codes(s: str) -> list[str]:
    """Pull every CWE-N substring out of a string. Tolerates labels like
    'CWE-532: INSERTION OF SENSITIVE...' by matching only the canonical prefix."""
    return [m.upper() for m in CWE_RE.findall(s)]


def _find_cwes(rule: dict, result: dict) -> list[str]:
    """SARIF stores CWE in many places. Probe each."""
    cwes: list[str] = []

    # taxa references on the rule (often {"target": {"id": "CWE-89"}} or
    # {"target": {"id": "CWE-532: ..."}})
    for relation in rule.get("relationships", []) or []:
        target = (relation.get("target") or {}).get("id") or ""
        cwes.extend(_extract_cwe_codes(target))

    # rule.properties
    props = rule.get("properties", {}) or {}
    for tag in props.get("tags", []) or []:
        if isinstance(tag, str):
            cwes.extend(_extract_cwe_codes(tag))
    for cwe in props.get("cwe", []) or []:
        if isinstance(cwe, str):
            cwes.extend(_extract_cwe_codes(cwe))
        elif isinstance(cwe, dict) and cwe.get("id"):
            cwes.extend(_extract_cwe_codes(str(cwe["id"])))
    issue_id = props.get("issue_cwe_id")
    if isinstance(issue_id, (str, int)):
        cwes.append(f"CWE-{issue_id}")

    # result.properties
    rprops = result.get("properties", {}) or {}
    for tag in rprops.get("tags", []) or []:
        if isinstance(tag, str):
            cwes.extend(_extract_cwe_codes(tag))

    # de-dupe preserve order
    seen, out = set(), []
    for c in cwes:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _result_location(result: dict) -> tuple[str, int | None, int | None]:
    locs = result.get("locations") or []
    if not locs:
        return "", None, None
    phys = (locs[0].get("physicalLocation") or {})
    artifact = (phys.get("artifactLocation") or {})
    region = (phys.get("region") or {})
    return (
        artifact.get("uri", "") or "",
        region.get("startLine"),
        region.get("endLine") or region.get("startLine"),
    )


def parse_sarif(path: Path, rule_source_default: str) -> list[Finding]:
    if not path.exists():
        return []
    try:
        doc = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []

    findings: list[Finding] = []
    for run in doc.get("runs", []) or []:
        tool = ((run.get("tool") or {}).get("driver") or {})
        rule_source = tool.get("name", rule_source_default).lower()
        rules_by_id = {r.get("id"): r for r in tool.get("rules", []) or []}

        for result in run.get("results", []) or []:
            rule_id = result.get("ruleId") or ""
            rule = rules_by_id.get(rule_id, {})
            file_path, line_start, line_end = _result_location(result)
            cwes = _find_cwes(rule, result)
            findings.append(
                Finding(
                    rule_id=rule_id,
                    rule_source=rule_source,
                    severity=result.get("level") or "warning",
                    message=(result.get("message") or {}).get("text", "") or "",
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    cwe_ids=cwes,
                    raw=result,
                )
            )

    return findings
