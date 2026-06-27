"""CISA Known Exploited Vulnerabilities catalog.

Single JSON feed refreshed by CISA daily. Pulled wholesale; insert into the
`kev` table. Each KEV row is keyed by CVE-ID and carries the CWE-IDs MITRE
has associated with it.
"""
import json

import httpx

from crossview.enrichment.cache import connect, transaction
from crossview.enrichment.enrichers.base import EnrichmentResult

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_TTL = 24 * 3600  # 1 day


class CISAKEVEnricher:
    name = "cisa_kev"
    default_ttl_seconds = DEFAULT_TTL

    async def fetch(self) -> dict:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=15.0, read=120.0, write=30.0, pool=15.0),
            headers={"User-Agent": "crossview/0.1.0"},
        ) as client:
            resp = await client.get(KEV_FEED_URL)
            resp.raise_for_status()
            return resp.json()

    async def enrich(self, entity_id: str | None = None) -> EnrichmentResult:
        feed = await self.fetch()
        catalog = feed.get("vulnerabilities", []) or []

        rows = []
        for v in catalog:
            cwes = v.get("cwes") or []
            rows.append((
                v.get("cveID"),
                v.get("vendorProject"),
                v.get("product"),
                v.get("vulnerabilityName"),
                v.get("dateAdded"),
                v.get("shortDescription"),
                v.get("requiredAction"),
                v.get("dueDate"),
                v.get("knownRansomwareCampaignUse"),
                v.get("notes"),
                json.dumps(cwes),
            ))

        conn = connect()
        with transaction(conn):
            conn.execute("DELETE FROM kev")  # KEV is small (<2k rows); replace wholesale
            conn.executemany(
                """
                INSERT INTO kev (cve_id, vendor_project, product, vulnerability_name,
                                 date_added, short_description, required_action,
                                 due_date, known_ransomware_use, notes, cwe_ids_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

        return EnrichmentResult(
            enricher=self.name,
            payload={
                "catalog_version": feed.get("catalogVersion"),
                "date_released": feed.get("dateReleased"),
                "row_count": len(rows),
            },
            notes=[f"loaded {len(rows)} KEV rows"],
            side_effects={"kev_rows": len(rows)},
        )


def kev_for_cwe(conn, cwe_id: str) -> list[dict]:
    """Return KEV rows whose cwe_ids_json contains this CWE."""
    pattern = f'%"{cwe_id}"%'
    rows = conn.execute(
        """
        SELECT cve_id, vendor_project, product, vulnerability_name,
               date_added, short_description, known_ransomware_use
        FROM kev
        WHERE cwe_ids_json LIKE ?
        ORDER BY date_added DESC
        """,
        (pattern,),
    ).fetchall()
    return [dict(r) for r in rows]


def kev_count_by_cwe(conn) -> dict[str, int]:
    """Sweep the KEV table once and return CWE → number of exploited-in-wild CVEs."""
    counts: dict[str, int] = {}
    for r in conn.execute("SELECT cwe_ids_json FROM kev"):
        try:
            cwes = json.loads(r["cwe_ids_json"] or "[]")
        except json.JSONDecodeError:
            continue
        for cwe in cwes:
            counts[cwe] = counts.get(cwe, 0) + 1
    return counts
