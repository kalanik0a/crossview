"""Enrichment orchestrator: picks enrichers for an entity, manages cache freshness."""
import asyncio

from rich.console import Console

from crossview.enrichment.cache import connect, get_enrichment, is_stale, transaction, upsert_enrichment
from crossview.enrichment.enrichers.base import Enricher, EnrichmentResult
from crossview.enrichment.enrichers.cisa_kev import CISAKEVEnricher
from crossview.enrichment.enrichers.cve_nvd import BulkCVENVDEnricher
from crossview.enrichment.enrichers.web_research import WebResearchEnricher

console = Console()


# Full registry across waves 1-3.
ALL_ENRICHERS: dict[str, type] = {
    "cisa_kev": CISAKEVEnricher,
    "cve_nvd_bulk": BulkCVENVDEnricher,
    "web_research": WebResearchEnricher,
}

# Global enrichers run without an entity_id; per-entity enrichers need one.
GLOBAL_ENRICHERS = {"cisa_kev", "cve_nvd_bulk"}
PER_ENTITY_ENRICHERS = {"web_research"}


def _instantiate(name: str) -> Enricher:
    cls = ALL_ENRICHERS.get(name)
    if not cls:
        raise ValueError(f"Unknown enricher: {name}")
    return cls()


async def run_enricher(name: str, entity_id: str | None = None, force: bool = False) -> EnrichmentResult:
    enricher = _instantiate(name)
    cache_id = entity_id or "_global_"

    if not force:
        conn = connect()
        cached = get_enrichment(conn, cache_id, name)
        if cached and not is_stale(cached):
            console.log(f"[dim]{name}: cache hit ({cache_id})[/dim]")
            return EnrichmentResult(enricher=name, payload=cached["payload"], notes=["cache hit"])

    result = await enricher.enrich(entity_id)

    conn = connect()
    with transaction(conn):
        upsert_enrichment(
            conn,
            entity_id=cache_id,
            enricher=name,
            payload=result.payload,
            ttl_seconds=enricher.default_ttl_seconds,
        )
    return result


async def run_all_global(force: bool = False) -> list[EnrichmentResult]:
    """Run every global enricher once. Useful for `crossview enrich --all`."""
    results = []
    for name in GLOBAL_ENRICHERS:
        results.append(await run_enricher(name, force=force))
    return results


def run_all_global_sync(force: bool = False) -> list[EnrichmentResult]:
    return asyncio.run(run_all_global(force))


def run_enricher_sync(name: str, entity_id: str | None = None, force: bool = False) -> EnrichmentResult:
    return asyncio.run(run_enricher(name, entity_id, force))
