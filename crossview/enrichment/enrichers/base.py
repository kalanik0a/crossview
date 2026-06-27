"""Enricher protocol and shared types."""
from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class EnrichmentResult:
    """What an enricher returns. Caller decides how to persist."""

    enricher: str                 # short name: "cisa_kev", "cve_nvd", "web_research", ...
    entity_id: str | None = None  # nullable for global enrichers (e.g. KEV catalog refresh)
    payload: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    side_effects: dict = field(default_factory=dict)  # e.g. row counts written to dedicated tables


class Enricher(Protocol):
    """Anything that pulls fresh context for one or more canonical entities."""

    name: str
    default_ttl_seconds: int

    async def enrich(self, entity_id: str | None = None) -> EnrichmentResult: ...
