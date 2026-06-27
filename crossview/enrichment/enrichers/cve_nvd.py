"""NVD CVE/CPE bulk enricher.

Pulls the entire NVD 2.0 CVE feed paginated. Extracts CPEs embedded in each
CVE's `configurations` block. Resumable via the `sweep_state` table.

Rate limits (NVD policy without API key):
  5 requests / 30 seconds → 6 second minimum interval.
We sleep 8s between pages to stay well under and survive transient slowdowns.
"""
from __future__ import annotations

import asyncio
import os
import random
from typing import Any

import httpx
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from crossview.enrichment.cache import (
    connect,
    load_sweep_state,
    save_sweep_state,
    transaction,
)
from crossview.enrichment.enrichers.base import EnrichmentResult

console = Console()

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "crossview/0.1.0 (security research tool)"

PAGE_SIZE = 2000        # NVD max
SLEEP_JITTER = 0.5      # add 0-0.5s of jitter
BACKOFF_INITIAL = 30.0  # 429/503 → wait 30s, then 60s, 120s, max 300s
BACKOFF_MAX = 300.0
SWEEP_NAME = "cve_nvd_bulk"


def _rate() -> tuple[str | None, float]:
    """NVD rate policy: ~5 requests / 30s anonymous (≈6 s/page), ~50 requests / 30s
    with an API key (≈0.6 s/page). Setting ``NVD_API_KEY`` unlocks the higher tier —
    the real way to de-throttle the full sweep (minutes vs. ~30-60 min). ``NVD_SLEEP``
    overrides the per-page delay; too low invites HTTP 429 (absorbed by backoff, but
    it wastes time), so it's floored at 0.5 s."""
    key = os.environ.get("NVD_API_KEY") or None
    default = 0.8 if key else 6.0          # was a flat 8.0 — flexed toward NVD's actual limits
    try:
        sleep = float(os.environ.get("NVD_SLEEP", default))
    except ValueError:
        sleep = default
    return key, max(sleep, 0.5)


# ---- Extraction helpers ------------------------------------------------------

def _en_description(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return (d.get("value") or "")[:5000]
    return ""


def _cvss_v3(cve: dict) -> tuple[float | None, str | None]:
    metrics = cve.get("metrics", {}) or {}
    # Prefer v3.1, fall back to v3.0
    for key in ("cvssMetricV31", "cvssMetricV30"):
        items = metrics.get(key) or []
        if items:
            data = items[0].get("cvssData") or {}
            return data.get("baseScore"), data.get("baseSeverity")
    return None, None


def _cwes(cve: dict) -> list[str]:
    out: set[str] = set()
    for w in cve.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            v = (d.get("value") or "").strip()
            if v.startswith("CWE-"):
                out.add(v)
    return sorted(out)


def _cpe_parts(uri: str) -> tuple[str, str, str, str]:
    """cpe:2.3:<part>:<vendor>:<product>:<version>:..."""
    parts = uri.split(":")
    if len(parts) < 6:
        return "", "", "", ""
    return parts[2], parts[3], parts[4], parts[5]


def _cpes_from_configurations(cve: dict) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                criteria = match.get("criteria")
                if not criteria:
                    continue
                vulnerable = 1 if match.get("vulnerable") else 0
                out.append((criteria, vulnerable))
    return out


# ---- Persistence -------------------------------------------------------------

def _persist_page(conn, vulnerabilities: list[dict]) -> dict[str, int]:
    cve_rows = []
    cwe_cve_rows = []
    cpe_rows = []
    cve_cpe_rows = []

    for item in vulnerabilities:
        cve = item.get("cve")
        if not cve:
            continue
        cve_id = cve.get("id")
        if not cve_id:
            continue

        score, severity = _cvss_v3(cve)
        cve_rows.append((
            cve_id,
            _en_description(cve),
            score,
            severity,
            cve.get("published"),
            cve.get("lastModified"),
            None,  # raw_json — we drop it; the descriptive fields are enough
        ))

        for cwe in _cwes(cve):
            cwe_cve_rows.append((cwe, cve_id))

        seen_cpes: set[str] = set()
        for criteria, vulnerable in _cpes_from_configurations(cve):
            if criteria in seen_cpes:
                # multiple cpeMatch entries can repeat the same URI; dedupe
                continue
            seen_cpes.add(criteria)
            cve_cpe_rows.append((cve_id, criteria, vulnerable))
            part, vendor, product, version = _cpe_parts(criteria)
            cpe_rows.append((criteria, part, vendor, product, version))

    with transaction(conn):
        conn.executemany(
            """
            INSERT OR REPLACE INTO cves
                (cve_id, description, cvss_v3_score, cvss_v3_severity,
                 published_at, modified_at, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            cve_rows,
        )
        conn.executemany(
            "INSERT OR IGNORE INTO cwe_cves (cwe_id, cve_id) VALUES (?, ?)",
            cwe_cve_rows,
        )
        conn.executemany(
            """
            INSERT OR IGNORE INTO cpes (cpe_uri, part, vendor, product, version)
            VALUES (?, ?, ?, ?, ?)
            """,
            cpe_rows,
        )
        conn.executemany(
            """
            INSERT OR IGNORE INTO cve_cpes (cve_id, cpe_uri, vulnerable)
            VALUES (?, ?, ?)
            """,
            cve_cpe_rows,
        )

    return {
        "cves": len(cve_rows),
        "cwe_links": len(cwe_cve_rows),
        "cpes": len(set(c[0] for c in cpe_rows)),
        "cve_cpe_links": len(cve_cpe_rows),
    }


# ---- HTTP fetch --------------------------------------------------------------

async def _fetch_page(client: httpx.AsyncClient, start_index: int) -> dict[str, Any]:
    """Fetch one page, retrying with exponential backoff on rate-limit responses."""
    backoff = BACKOFF_INITIAL
    attempt = 0
    while True:
        attempt += 1
        try:
            resp = await client.get(
                NVD_CVE_URL,
                params={"startIndex": start_index, "resultsPerPage": PAGE_SIZE},
            )
            if resp.status_code in (429, 503):
                wait = min(backoff, BACKOFF_MAX)
                console.log(
                    f"[yellow]NVD {resp.status_code} (rate-limited). "
                    f"Backing off {wait:.0f}s (attempt {attempt}).[/yellow]"
                )
                await asyncio.sleep(wait)
                backoff *= 2
                continue
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            if attempt >= 6:
                raise
            wait = min(backoff, BACKOFF_MAX)
            console.log(f"[yellow]NVD HTTP error: {e!s}. Retry in {wait:.0f}s.[/yellow]")
            await asyncio.sleep(wait)
            backoff *= 2
        except httpx.TransportError as e:
            # Covers NetworkError, ProtocolError (incl. RemoteProtocolError),
            # TimeoutException, ProxyError. NVD has a habit of closing chunked
            # responses mid-stream — surface as transient and retry.
            if attempt >= 8:
                raise
            wait = min(backoff, BACKOFF_MAX)
            console.log(f"[yellow]NVD transport: {type(e).__name__}: {e!s}. Retry in {wait:.0f}s.[/yellow]")
            await asyncio.sleep(wait)
            backoff *= 2


# ---- Enricher ----------------------------------------------------------------

class BulkCVENVDEnricher:
    name = "cve_nvd_bulk"
    default_ttl_seconds = 7 * 24 * 3600  # 1 week — but the sweep is incremental anyway

    async def enrich(self, entity_id: str | None = None) -> EnrichmentResult:
        conn = connect()
        state = load_sweep_state(conn, SWEEP_NAME) or {}
        start_index = int(state.get("last_index", 0))
        pages_done = int(state.get("pages_done", 0))
        total_expected = state.get("total_expected")
        save_sweep_state(conn, SWEEP_NAME, start_index, pages_done, total_expected, "running")

        api_key, sleep_between = _rate()
        timeout = httpx.Timeout(connect=30.0, read=120.0, write=30.0, pool=30.0)
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if api_key:
            headers["apiKey"] = api_key   # NVD's higher-rate tier
        console.log(
            f"[dim]NVD sweep — {'keyed (50/30s)' if api_key else 'anonymous (5/30s)'}, "
            f"{sleep_between:.2g}s/page[/dim]"
        )

        totals = {"cves": 0, "cwe_links": 0, "cpes": 0, "cve_cpe_links": 0}

        progress_cols = (
            TextColumn("[bold cyan]NVD CVE sweep"),
            BarColumn(),
            TextColumn("{task.completed:,} / {task.total:,} CVEs"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
        )

        async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
            with Progress(*progress_cols, console=console) as progress:
                task = progress.add_task("nvd", total=total_expected or 1, completed=start_index)

                while True:
                    page = await _fetch_page(client, start_index)
                    vulns = page.get("vulnerabilities") or []
                    page_total = int(page.get("totalResults") or 0)

                    if total_expected != page_total:
                        total_expected = page_total
                        progress.update(task, total=total_expected)

                    if not vulns:
                        break

                    counts = _persist_page(conn, vulns)
                    for k, v in counts.items():
                        totals[k] = totals.get(k, 0) + v

                    start_index += len(vulns)
                    pages_done += 1
                    progress.update(task, completed=start_index)
                    save_sweep_state(conn, SWEEP_NAME, start_index, pages_done, total_expected, "running")

                    if start_index >= total_expected:
                        break

                    # Polite sleep between requests
                    await asyncio.sleep(sleep_between + random.random() * SLEEP_JITTER)

        save_sweep_state(conn, SWEEP_NAME, start_index, pages_done, total_expected, "complete")

        return EnrichmentResult(
            enricher=self.name,
            payload={
                "pages_done": pages_done,
                "cves_seen": start_index,
                "total_expected": total_expected,
                **totals,
            },
            notes=[
                f"completed {pages_done} pages, {start_index:,} CVEs, "
                f"{totals['cwe_links']:,} CWE links, {totals['cpes']:,} unique CPEs"
            ],
            side_effects={"sweep": SWEEP_NAME, **totals},
        )


# ---- Per-CWE query (for `crossview enrich CWE-89` after sweep) ---------------

def cves_for_cwe(conn, cwe_id: str, limit: int = 25) -> list[dict]:
    rows = conn.execute(
        """
        SELECT c.cve_id, c.description, c.cvss_v3_score, c.cvss_v3_severity,
               c.published_at, c.modified_at,
               EXISTS (SELECT 1 FROM kev WHERE kev.cve_id = c.cve_id) AS in_kev
        FROM cwe_cves cc
        JOIN cves c ON c.cve_id = cc.cve_id
        WHERE cc.cwe_id = ?
        ORDER BY c.cvss_v3_score DESC NULLS LAST, c.published_at DESC
        LIMIT ?
        """,
        (cwe_id, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def cpes_for_cve(conn, cve_id: str) -> list[dict]:
    rows = conn.execute(
        """
        SELECT cp.cpe_uri, cp.vendor, cp.product, cp.version, cc.vulnerable
        FROM cve_cpes cc
        JOIN cpes cp ON cp.cpe_uri = cc.cpe_uri
        WHERE cc.cve_id = ?
        ORDER BY cp.vendor, cp.product, cp.version
        """,
        (cve_id,),
    ).fetchall()
    return [dict(r) for r in rows]
