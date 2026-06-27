"""Concurrent async downloader for MITRE source files.

Streams to disk with atomic rename, caches by mtime, extracts CWE zip.
"""
import asyncio
import zipfile
from pathlib import Path

import httpx
from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TransferSpeedColumn,
)

from crossview.data.sources import SOURCES, Source

console = Console()
USER_AGENT = "crossview/0.1.0"


async def _stream_to_file(
    client: httpx.AsyncClient,
    url: str,
    dest: Path,
    progress: Progress,
    label: str,
) -> None:
    tmp = dest.with_suffix(dest.suffix + ".part")
    async with client.stream("GET", url) as resp:
        resp.raise_for_status()
        total = int(resp.headers.get("content-length") or 0) or None
        task = progress.add_task(label, total=total)
        with tmp.open("wb") as f:
            async for chunk in resp.aiter_bytes(chunk_size=64 * 1024):
                f.write(chunk)
                progress.update(task, advance=len(chunk))
    tmp.replace(dest)


def _extract_cwe_zip(zip_path: Path, raw_dir: Path) -> Path | None:
    """Extract the XML inside cwec_latest.xml.zip and rename to cwec.xml."""
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            if name.endswith(".xml"):
                # [CWE-22] Zip Slip prevention — validate extraction stays in raw_dir
                target_path = (raw_dir / name).resolve()
                if not target_path.is_relative_to(raw_dir.resolve()):
                    raise ValueError(f"Zip entry escapes target directory: {name}")
                zf.extract(name, raw_dir)
                target = raw_dir / "cwec.xml"
                (raw_dir / name).rename(target)
                return target
    return None


async def _download_one(
    client: httpx.AsyncClient,
    src: Source,
    raw_dir: Path,
    force: bool,
    progress: Progress,
) -> Path:
    out = raw_dir / src.filename
    if out.exists() and not force:
        progress.console.log(f"[dim]{src.key:<22}[/dim] cached")
        return out

    label = f"[cyan]{src.key:<22}[/cyan]"
    await _stream_to_file(client, src.url, out, progress, label)

    if src.fmt == "stix-zip-xml" and out.suffix == ".zip":
        extracted = _extract_cwe_zip(out, raw_dir)
        if extracted:
            progress.console.log(f"[green]extracted[/green] {extracted.name}")

    return out


async def download_all(
    raw_dir: Path,
    only: list[str] | None = None,
    force: bool = False,
) -> list[Path]:
    raw_dir.mkdir(parents=True, exist_ok=True)
    selected = [s for s in SOURCES if not only or s.key in only]
    if not selected:
        console.print(f"[red]No sources match: {only}[/red]")
        return []

    progress_cols = (
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(bar_width=30),
        DownloadColumn(),
        TransferSpeedColumn(),
    )
    timeout = httpx.Timeout(connect=30.0, read=600.0, write=60.0, pool=30.0)
    headers = {"User-Agent": USER_AGENT}

    with Progress(*progress_cols, console=console) as progress:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=True, headers=headers
        ) as client:
            tasks = [
                _download_one(client, s, raw_dir, force, progress) for s in selected
            ]
            return await asyncio.gather(*tasks)


def download_all_sync(
    raw_dir: Path, only: list[str] | None = None, force: bool = False
) -> list[Path]:
    return asyncio.run(download_all(raw_dir, only, force))
