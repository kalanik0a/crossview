"""Stage 3 — Investigate.

For each active hypothesis in cohort.db:
  1. Walk the canonical graph: CWE → CAPEC → ATT&CK → D3FEND → UKC.
  2. Check enrichment.db for related CVEs and KEV exploit-in-the-wild status.
  3. Score priority (KEV+CVSS-driven) so we only spend research bandwidth on hypotheses worth it.
  4. Persist evidence and validations to cohort.db, anchoring every finding to canonical entity IDs.
  5. (Opt-in) Run crawl4ai web_research for high-priority hypotheses.
"""
from __future__ import annotations

import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.table import Table

from crossview.data import cohort as cohort_db
from crossview.data.database import connect as ref_connect
from crossview.enrichment.cache import connect as enr_connect

console = Console()


@dataclass
class CrossSourceChain:
    cwe_id: str
    capecs: list[str] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)
    atlas_techniques: list[str] = field(default_factory=list)
    d3fend_techniques: list[str] = field(default_factory=list)
    ukc_phases: list[str] = field(default_factory=list)
    parent_cwes: list[str] = field(default_factory=list)


@dataclass
class CVEEnrichment:
    top_cves: list[dict] = field(default_factory=list)  # ranked by CVSS
    kev_count: int = 0
    kev_with_ransomware: int = 0
    max_cvss: float | None = None


@dataclass
class Priority:
    score: float
    reasons: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        if self.score >= 0.8:
            return "high"
        if self.score >= 0.5:
            return "medium"
        return "low"


# ─────────────────────────── Graph walk ───────────────────────────────────────

def walk_chain(ref_conn: sqlite3.Connection, cwe_id: str) -> CrossSourceChain:
    chain = CrossSourceChain(cwe_id=cwe_id)

    # CWE parent hierarchy
    chain.parent_cwes = [
        r["dst_id"] for r in ref_conn.execute(
            "SELECT dst_id FROM xrefs WHERE src_id = ? AND relation = 'child_of'",
            (cwe_id,),
        )
    ]

    # CWE → CAPEC (via 'targets' relation: weakness "is targeted by" attack pattern)
    chain.capecs = sorted({
        r["dst_id"] for r in ref_conn.execute(
            "SELECT dst_id FROM xrefs WHERE src_id = ? AND relation = 'targets'",
            (cwe_id,),
        )
    })
    # Inbound: CAPEC → CWE (uses_weakness)
    inbound_capecs = {
        r["src_id"] for r in ref_conn.execute(
            "SELECT src_id FROM xrefs WHERE dst_id = ? AND relation = 'uses_weakness'",
            (cwe_id,),
        )
    }
    chain.capecs = sorted(set(chain.capecs) | inbound_capecs)

    # CAPEC → ATT&CK techniques (via 'related' relation in CAPEC's external refs)
    if chain.capecs:
        placeholders = ",".join("?" * len(chain.capecs))
        for r in ref_conn.execute(
            f"""
            SELECT DISTINCT dst_id FROM xrefs
            WHERE src_id IN ({placeholders}) AND relation = 'related'
            """,
            chain.capecs,
        ):
            dst = r["dst_id"]
            if dst.startswith("T") and dst[1:5].isdigit():
                chain.attack_techniques.append(dst)
            elif dst.startswith("AML.T"):
                chain.atlas_techniques.append(dst)

    chain.attack_techniques = sorted(set(chain.attack_techniques))
    chain.atlas_techniques = sorted(set(chain.atlas_techniques))

    # ATT&CK → UKC phases
    techniques = chain.attack_techniques + chain.atlas_techniques
    if techniques:
        ph = ",".join("?" * len(techniques))
        chain.ukc_phases = sorted({
            r["dst_id"] for r in ref_conn.execute(
                f"SELECT DISTINCT dst_id FROM xrefs WHERE src_id IN ({ph}) AND relation = 'kill_chain_phase' AND dst_id LIKE 'UKC-%'",
                techniques,
            )
        })

        # ATT&CK → D3FEND (D3FEND counters ATT&CK)
        chain.d3fend_techniques = sorted({
            r["src_id"] for r in ref_conn.execute(
                f"SELECT DISTINCT src_id FROM xrefs WHERE dst_id IN ({ph}) AND relation = 'counters'",
                techniques,
            )
        })

    return chain


# ─────────────────────── Enrichment: CVEs + KEV ───────────────────────────────

def cve_enrichment(enr_conn: sqlite3.Connection, cwe_id: str, top_n: int = 5) -> CVEEnrichment:
    e = CVEEnrichment()
    rows = enr_conn.execute(
        """
        SELECT c.cve_id, c.cvss_v3_score, c.cvss_v3_severity, c.published_at,
               EXISTS (SELECT 1 FROM kev k WHERE k.cve_id = c.cve_id) AS in_kev
        FROM cwe_cves cc
        JOIN cves c ON c.cve_id = cc.cve_id
        WHERE cc.cwe_id = ?
        ORDER BY c.cvss_v3_score DESC NULLS LAST, c.published_at DESC
        LIMIT ?
        """,
        (cwe_id, top_n),
    ).fetchall()
    e.top_cves = [
        {
            "cve_id": r["cve_id"],
            "cvss_v3_score": r["cvss_v3_score"],
            "cvss_v3_severity": r["cvss_v3_severity"],
            "published_at": r["published_at"],
            "in_kev": bool(r["in_kev"]),
        }
        for r in rows
    ]
    if e.top_cves:
        e.max_cvss = max(
            (c["cvss_v3_score"] for c in e.top_cves if c["cvss_v3_score"] is not None),
            default=None,
        )
        e.kev_count = sum(1 for c in e.top_cves if c["in_kev"])

    # CISA KEV linked to this CWE (full count, not just top 5)
    kev_pattern = f'%"{cwe_id}"%'
    kev_rows = enr_conn.execute(
        "SELECT known_ransomware_use FROM kev WHERE cwe_ids_json LIKE ?",
        (kev_pattern,),
    ).fetchall()
    e.kev_count = max(e.kev_count, len(kev_rows))
    e.kev_with_ransomware = sum(
        1 for r in kev_rows if (r["known_ransomware_use"] or "").lower() == "known"
    )

    return e


# ─────────────────────────── Priority scoring ────────────────────────────────

def score_priority(chain: CrossSourceChain, cve: CVEEnrichment, severity: str) -> Priority:
    score = 0.0
    reasons: list[str] = []

    if severity == "error":
        score += 0.3
        reasons.append("scanner severity=error")
    if cve.kev_count > 0:
        score += 0.4
        reasons.append(f"{cve.kev_count} KEV CVEs (exploited in the wild)")
    if cve.kev_with_ransomware > 0:
        score += 0.2
        reasons.append(f"{cve.kev_with_ransomware} KEV with known ransomware use")
    if cve.max_cvss and cve.max_cvss >= 9.0:
        score += 0.2
        reasons.append(f"top related CVE CVSS ≥ 9.0 (max {cve.max_cvss:.1f})")
    elif cve.max_cvss and cve.max_cvss >= 7.0:
        score += 0.1
        reasons.append(f"top related CVE CVSS ≥ 7.0 (max {cve.max_cvss:.1f})")
    if chain.d3fend_techniques:
        score += 0.05
        reasons.append(f"{len(chain.d3fend_techniques)} D3FEND mitigations available")

    return Priority(score=min(1.0, score), reasons=reasons)


# ─────────────────────────── Persistence ─────────────────────────────────────

def _write_evidence_rows(
    conn: sqlite3.Connection,
    hypothesis_id: int,
    chain: CrossSourceChain,
    cve: CVEEnrichment,
    priority: Priority,
) -> int:
    """Write one row per major canonical link found, plus enrichment summary."""
    n = 0

    def _add(kind: str, content: str, ref_url: str | None = None) -> None:
        nonlocal n
        conn.execute(
            """
            INSERT INTO evidence (hypothesis_id, kind, content, ref_url)
            VALUES (?, ?, ?, ?)
            """,
            (hypothesis_id, kind, content[:2000], ref_url),
        )
        n += 1

    if chain.capecs:
        _add("mitre_xref", f"CAPEC: {', '.join(chain.capecs[:8])}")
    if chain.attack_techniques:
        _add("mitre_xref", f"ATT&CK: {', '.join(chain.attack_techniques[:8])}")
    if chain.atlas_techniques:
        _add("mitre_xref", f"ATLAS: {', '.join(chain.atlas_techniques)}")
    if chain.d3fend_techniques:
        _add("mitre_xref", f"D3FEND mitigations: {', '.join(chain.d3fend_techniques[:8])}")
    if chain.ukc_phases:
        _add("mitre_xref", f"UKC phases: {', '.join(chain.ukc_phases)}")

    if cve.top_cves:
        cve_lines = [
            f"- {c['cve_id']} CVSS={c['cvss_v3_score'] or '?'} ({c['cvss_v3_severity'] or '?'})"
            f"{' [KEV]' if c['in_kev'] else ''}"
            for c in cve.top_cves
        ]
        _add("external_ref", "Top related CVEs:\n" + "\n".join(cve_lines))
    if cve.kev_count:
        _add(
            "external_ref",
            f"CISA KEV: {cve.kev_count} actively-exploited CVE(s) tagged with this CWE; "
            f"{cve.kev_with_ransomware} with known ransomware use",
        )

    _add(
        "test_result",
        f"Priority: {priority.label} ({priority.score:.2f}). Reasons: {'; '.join(priority.reasons) or 'none'}",
    )
    return n


def _write_validation_rows(conn, hypothesis_id: int, chain: CrossSourceChain) -> int:
    """One validation row per canonical entity the chain links to."""
    n = 0
    rows: list[tuple[str, str]] = []

    rows.append(("cwe", chain.cwe_id))
    for cwe in chain.parent_cwes:
        rows.append(("cwe", cwe))
    for capec in chain.capecs:
        rows.append(("capec", capec))
    for t in chain.attack_techniques:
        rows.append(("attack", t))
    for t in chain.atlas_techniques:
        rows.append(("atlas", t))
    for d in chain.d3fend_techniques:
        rows.append(("d3fend", d))
    for u in chain.ukc_phases:
        rows.append(("ukc", u))

    for entity_type, entity_id in rows:
        conn.execute(
            """
            INSERT INTO validations
                (hypothesis_id, entity_type, entity_id, match, notes)
            VALUES (?, ?, ?, 'yes', 'asserted by canonical MITRE data')
            """,
            (hypothesis_id, entity_type, entity_id),
        )
        n += 1
    return n


# ─────────────────────────── Top-level driver ────────────────────────────────

def _wipe_prior_investigation_data(conn: sqlite3.Connection, project_path: str) -> None:
    """Stage 3 is rerunnable. Wipe prior evidence/validations for this project's hypotheses."""
    conn.execute(
        """
        DELETE FROM evidence
        WHERE hypothesis_id IN (
            SELECT h.id FROM hypotheses h
            JOIN investigations i ON i.id = h.investigation_id
            WHERE i.project_path = ?
        )
        """,
        (project_path,),
    )
    conn.execute(
        """
        DELETE FROM validations
        WHERE hypothesis_id IN (
            SELECT h.id FROM hypotheses h
            JOIN investigations i ON i.id = h.investigation_id
            WHERE i.project_path = ?
        )
        """,
        (project_path,),
    )


def run_investigate(
    project_root: Path,
    only_hypothesis_id: int | None = None,
    web_research_threshold: float = 0.8,
    max_web_research: int = 0,
) -> dict:
    """Investigate every active hypothesis. Optional limited web research for top-priority ones."""
    project_root = project_root.resolve()
    project_path = str(project_root)

    cohort_conn = cohort_db.connect(project_root)
    ref_conn = ref_connect()
    enr_conn = enr_connect()

    console.rule("[bold]Stage 3 — Investigate[/bold]")

    if only_hypothesis_id is None:
        with cohort_db.transaction(cohort_conn):
            _wipe_prior_investigation_data(cohort_conn, project_path)

    where = "h.status = 'active' AND i.project_path = ?"
    params: list = [project_path]
    if only_hypothesis_id:
        where += " AND h.id = ?"
        params.append(only_hypothesis_id)

    rows = cohort_conn.execute(
        f"""
        SELECT h.id, h.investigation_id, h.suspected_cwe, h.statement,
               i.file_path, sr.severity
        FROM hypotheses h
        JOIN investigations i ON i.id = h.investigation_id
        LEFT JOIN scan_results sr ON sr.id = i.scanner_finding_id
        WHERE {where}
        """,
        tuple(params),
    ).fetchall()

    console.log(f"Investigating {len(rows):,} active hypotheses...")

    by_priority: Counter = Counter()
    evidence_total = 0
    validation_total = 0
    web_research_done = 0

    high_priority_for_research: list[tuple[int, str]] = []  # (hyp_id, suspected_cwe)

    with cohort_db.transaction(cohort_conn):
        for r in rows:
            cwe = r["suspected_cwe"]
            if not cwe:
                continue

            chain = walk_chain(ref_conn, cwe)
            cve = cve_enrichment(enr_conn, cwe)
            priority = score_priority(chain, cve, r["severity"] or "warning")
            by_priority[priority.label] += 1

            evidence_total += _write_evidence_rows(
                cohort_conn, r["id"], chain, cve, priority
            )
            validation_total += _write_validation_rows(cohort_conn, r["id"], chain)

            # Update hypothesis confidence + priority note
            cohort_conn.execute(
                """
                UPDATE hypotheses
                SET confidence = ?,
                    statement = statement || ' [priority=' || ? || ']'
                WHERE id = ? AND statement NOT LIKE '%[priority=%'
                """,
                (priority.score, priority.label, r["id"]),
            )

            if priority.score >= web_research_threshold:
                high_priority_for_research.append((r["id"], cwe))

    # Optional web research for top-priority hypotheses
    if max_web_research > 0 and high_priority_for_research:
        from crossview.enrichment.orchestrator import run_enricher_sync

        # De-duplicate by CWE so we don't research the same entity 50 times
        seen_cwes: set[str] = set()
        unique = []
        for hid, cwe in high_priority_for_research:
            if cwe in seen_cwes:
                continue
            seen_cwes.add(cwe)
            unique.append((hid, cwe))
            if len(unique) >= max_web_research:
                break

        console.log(f"Running web_research for {len(unique)} high-priority CWEs...")
        for hid, cwe in unique:
            try:
                run_enricher_sync("web_research", entity_id=cwe, force=False)
                web_research_done += 1
            except Exception as e:
                console.log(f"[yellow]web_research failed for {cwe}: {e}[/yellow]")

    # Summary
    t = Table(title="Stage 3 — Investigate totals")
    t.add_column("metric")
    t.add_column("count", justify="right")
    t.add_row("hypotheses investigated", f"{len(rows):,}")
    t.add_row("evidence rows written", f"{evidence_total:,}")
    t.add_row("validation rows written", f"{validation_total:,}")
    t.add_row("web_research runs", f"{web_research_done:,}")
    console.print(t)

    if by_priority:
        pt = Table(title="By priority")
        pt.add_column("level")
        pt.add_column("count", justify="right")
        for level in ("high", "medium", "low"):
            n = by_priority.get(level, 0)
            color = {"high": "red", "medium": "yellow", "low": "dim"}[level]
            pt.add_row(f"[{color}]{level}[/{color}]", f"{n:,}")
        console.print(pt)

    return {
        "investigated": len(rows),
        "evidence": evidence_total,
        "validations": validation_total,
        "web_research": web_research_done,
        "by_priority": dict(by_priority),
    }
