"""Web research enricher (crawl4ai-backed).

Targeted, schema-bound enrichment of a canonical entity by fetching and
distilling its authoritative web sources (MITRE pages, NVD detail pages,
OWASP cheatsheets, etc.). Result is JSON cached in enrichment.db keyed
by entity_id; repeat queries are free.

This is NOT a replacement for the hoover-maneuver skill, which handles
narrative, multi-URL, exploratory research. web_research is the opposite:
deterministic, per-entity, cache-forever enrichment.

Token-burn discipline: only distilled JSON enters our context, never raw HTML.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass

from crossview.enrichment.enrichers.base import EnrichmentResult


@dataclass(frozen=True)
class ResearchSource:
    url: str
    label: str


def url_templates_for(entity_id: str) -> list[ResearchSource]:
    """Return canonical research URLs for an entity ID."""
    if entity_id.startswith("CWE-"):
        num = entity_id.split("-", 1)[1]
        return [
            ResearchSource(
                url=f"https://cwe.mitre.org/data/definitions/{num}.html",
                label="MITRE canonical CWE definition",
            )
        ]

    if entity_id.startswith("CAPEC-"):
        num = entity_id.split("-", 1)[1]
        return [
            ResearchSource(
                url=f"https://capec.mitre.org/data/definitions/{num}.html",
                label="MITRE canonical CAPEC definition",
            )
        ]

    if re.match(r"^T\d{4}", entity_id):
        # ATT&CK: T1059 → /T1059/, T1059.001 → /T1059/001/
        if "." in entity_id:
            base, sub = entity_id.split(".", 1)
            path = f"{base}/{sub}"
        else:
            path = entity_id
        return [
            ResearchSource(
                url=f"https://attack.mitre.org/techniques/{path}/",
                label="MITRE ATT&CK technique page",
            )
        ]

    if entity_id.startswith("AML.T"):
        return [
            ResearchSource(
                url=f"https://atlas.mitre.org/techniques/{entity_id}",
                label="MITRE ATLAS technique page",
            )
        ]

    if entity_id.startswith("CVE-"):
        return [
            ResearchSource(
                url=f"https://nvd.nist.gov/vuln/detail/{entity_id}",
                label="NVD CVE detail page",
            ),
            ResearchSource(
                url=f"https://github.com/advisories?query={entity_id}",
                label="GitHub Advisory Database search",
            ),
        ]

    if entity_id.startswith("D3F:"):
        # D3FEND techniques
        slug = entity_id.split(":", 1)[1]
        return [
            ResearchSource(
                url=f"https://d3fend.mitre.org/technique/d3f:{slug}",
                label="MITRE D3FEND technique page",
            )
        ]

    return []


def _distill(markdown: str, max_chars: int = 4000) -> dict:
    """Squeeze a fetched page into a token-cheap JSON record.

    Strips images, link URLs, nav-like noise. Preserves up to 10 bullets
    and 5 code blocks. Truncates plain text at max_chars.
    """
    if not markdown:
        return {"summary": "", "bullets": [], "code_blocks": []}

    text = markdown
    # 1. Drop image markdown entirely (the biggest source of nav-link bloat)
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", text)
    # 2. Convert link markdown to bare visible text
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    # 3. Drop horizontal rules and HTML comments
    text = re.sub(r"^[-=]{3,}\s*$", "", text, flags=re.MULTILINE)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    # 4. Strip lines that are only repeated whitespace, pipes, or emoji
    cleaned_lines = []
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            cleaned_lines.append("")
            continue
        if re.fullmatch(r"[\|\s\-:]+", stripped):
            continue
        cleaned_lines.append(line)
    text = "\n".join(cleaned_lines)

    code_blocks = re.findall(r"```[a-z]*\n(.*?)```", text, re.DOTALL)
    bullets = [
        m.strip()
        for m in re.findall(r"^\s*[-*]\s+(.+?)$", text, re.MULTILINE)
        if len(m.strip()) > 8  # skip nav-bullet stubs
    ][:10]

    summary = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    summary = re.sub(r"\n{3,}", "\n\n", summary).strip()[:max_chars]

    return {
        "summary": summary,
        "bullets": bullets,
        "code_blocks": [c.strip()[:600] for c in code_blocks[:5]],
    }


class WebResearchEnricher:
    name = "web_research"
    default_ttl_seconds = 14 * 24 * 3600  # two weeks

    async def enrich(self, entity_id: str | None = None) -> EnrichmentResult:
        if not entity_id:
            return EnrichmentResult(
                enricher=self.name,
                notes=["web_research requires an entity_id; skipping"],
            )

        sources = url_templates_for(entity_id)
        if not sources:
            return EnrichmentResult(
                enricher=self.name,
                entity_id=entity_id,
                notes=[f"no URL templates known for {entity_id}"],
            )

        # Lazy-import crawl4ai so the rest of crossview works without
        # playwright browsers installed.
        from crawl4ai import AsyncWebCrawler

        results: list[dict] = []
        try:
            async with AsyncWebCrawler(verbose=False) as crawler:
                for source in sources:
                    try:
                        result = await crawler.arun(url=source.url)
                        md = getattr(result, "markdown", None) or ""
                        if isinstance(md, object) and hasattr(md, "raw_markdown"):
                            md = md.raw_markdown
                        distilled = _distill(str(md))
                        results.append(
                            {
                                "url": source.url,
                                "label": source.label,
                                "ok": bool(distilled["summary"]),
                                **distilled,
                            }
                        )
                    except Exception as e:
                        results.append(
                            {
                                "url": source.url,
                                "label": source.label,
                                "ok": False,
                                "error": f"{type(e).__name__}: {e!s}"[:200],
                            }
                        )
        except Exception as e:
            return EnrichmentResult(
                enricher=self.name,
                entity_id=entity_id,
                notes=[
                    f"crawl4ai failed to start: {type(e).__name__}: {e!s}",
                    f"Run: {sys.executable} -m playwright install chromium",
                ],
            )

        ok_count = sum(1 for r in results if r.get("ok"))
        return EnrichmentResult(
            enricher=self.name,
            entity_id=entity_id,
            payload={"sources": results},  # full payload — orchestrator persists
            notes=[f"fetched {ok_count}/{len(results)} sources for {entity_id}"],
        )


def get_research(conn, entity_id: str) -> dict | None:
    """Read cached research for an entity. Returns the payload dict or None."""
    row = conn.execute(
        """
        SELECT payload_json, fetched_at, ttl_seconds
        FROM enrichments
        WHERE entity_id = ? AND enricher = 'web_research'
        """,
        (entity_id,),
    ).fetchone()
    if not row:
        return None
    import json
    return json.loads(row["payload_json"])
