"""HEAD-check every MITRE source URL."""
import asyncio

import httpx
from rich.console import Console
from rich.table import Table

from crossview.data.downloader import USER_AGENT
from crossview.data.sources import SOURCES

console = Console()


async def _head(client: httpx.AsyncClient, url: str) -> tuple[int, str]:
    try:
        resp = await client.head(url, follow_redirects=True, timeout=15.0)
        return resp.status_code, resp.headers.get("content-type", "?")
    except httpx.HTTPError as e:
        return -1, f"error: {e!s}"


async def verify_all() -> int:
    headers = {"User-Agent": USER_AGENT}
    table = Table(title="MITRE source URL status")
    table.add_column("Source")
    table.add_column("URL", overflow="fold")
    table.add_column("Status")
    table.add_column("Content-Type")

    failures = 0
    async with httpx.AsyncClient(headers=headers) as client:
        results = await asyncio.gather(
            *[_head(client, s.url) for s in SOURCES]
        )
        for src, (code, ctype) in zip(SOURCES, results, strict=True):
            ok = 200 <= code < 400
            status_color = "green" if ok else "red"
            table.add_row(
                src.key,
                src.url,
                f"[{status_color}]{code}[/{status_color}]",
                ctype,
            )
            if not ok:
                failures += 1

    console.print(table)
    return failures
