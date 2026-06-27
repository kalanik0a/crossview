"""Quick structural inspection of downloaded files.

Knows STIX bundles, JSON-LD graphs, plain JSON, XML, and ZIP.
Goal: let me peek at any source file without dumping it into context.
"""
import json
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

console = Console()


def inspect(path: Path) -> None:
    suffix = path.suffix.lower()
    if suffix == ".zip":
        _inspect_zip(path)
    elif suffix == ".xml":
        _inspect_xml(path)
    elif suffix == ".json":
        _inspect_json(path)
    else:
        console.print(f"[red]Unknown file type: {path}[/red]")


def _size_label(path: Path) -> str:
    n = path.stat().st_size
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def _inspect_zip(path: Path) -> None:
    console.rule(f"ZIP {path.name} ({_size_label(path)})")
    with zipfile.ZipFile(path) as zf:
        table = Table()
        table.add_column("File")
        table.add_column("Size", justify="right")
        table.add_column("Compressed", justify="right")
        for info in zf.infolist():
            table.add_row(
                info.filename, f"{info.file_size:,}", f"{info.compress_size:,}"
            )
        console.print(table)


def _inspect_xml(path: Path) -> None:
    import xml.etree.ElementTree as ET

    console.rule(f"XML {path.name} ({_size_label(path)})")
    tree = ET.parse(path)
    root = tree.getroot()
    console.print(f"[bold]Root:[/bold] <{root.tag}>")
    if root.attrib:
        console.print(f"[bold]Root attrs:[/bold] {dict(root.attrib)}")

    direct_children = Counter(_strip_ns(child.tag) for child in root)
    table = Table(title="Direct children of root")
    table.add_column("Element")
    table.add_column("Count", justify="right")
    for tag, count in direct_children.most_common():
        table.add_row(tag, f"{count:,}")
    console.print(table)

    # One layer deeper for the most common child
    if direct_children:
        most_common_tag = direct_children.most_common(1)[0][0]
        sample_parent = next(
            (c for c in root if _strip_ns(c.tag) == most_common_tag), None
        )
        if sample_parent is not None:
            grandchildren = Counter(_strip_ns(g.tag) for g in sample_parent)
            if grandchildren:
                t2 = Table(title=f"Children of <{most_common_tag}> (sample)")
                t2.add_column("Element")
                t2.add_column("Count", justify="right")
                for tag, count in grandchildren.most_common(15):
                    t2.add_row(tag, f"{count:,}")
                console.print(t2)


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _inspect_json(path: Path) -> None:
    console.rule(f"JSON {path.name} ({_size_label(path)})")
    data = json.loads(path.read_text())

    if isinstance(data, list):
        console.print(f"Top-level: list of {len(data):,} items")
        if data and isinstance(data[0], dict):
            keys = Counter()
            for item in data[:1000]:
                keys.update(item.keys())
            _key_table("Common keys (first 1000 items)", keys)
        return

    if not isinstance(data, dict):
        console.print(f"Top-level: {type(data).__name__}")
        return

    # Top-level keys
    table = Table(title="Top-level keys")
    table.add_column("Key")
    table.add_column("Type")
    table.add_column("Detail")
    for k, v in data.items():
        if isinstance(v, list):
            detail = f"list[{len(v):,}]"
            if v:
                detail += f", first={type(v[0]).__name__}"
        elif isinstance(v, dict):
            detail = f"dict, {len(v)} keys"
        else:
            detail = repr(v)[:80]
        table.add_row(k, type(v).__name__, detail)
    console.print(table)

    # STIX bundle breakdown
    if "objects" in data and isinstance(data["objects"], list):
        types = Counter(obj.get("type", "?") for obj in data["objects"])
        _key_table("STIX object types", types)

    # JSON-LD breakdown
    graph_key = "@graph" if "@graph" in data else None
    if graph_key and isinstance(data[graph_key], list):
        types: Counter[str] = Counter()
        for obj in data[graph_key]:
            t = obj.get("@type", "?")
            if isinstance(t, list):
                t = "|".join(t)
            types[str(t)] += 1
        _key_table(f"JSON-LD {graph_key} @type breakdown", types, top=20)


def _key_table(title: str, counter: Counter, top: int | None = None) -> None:
    table = Table(title=title)
    table.add_column("Key/Type")
    table.add_column("Count", justify="right")
    items = counter.most_common(top) if top else counter.most_common()
    for k, count in items:
        table.add_row(str(k)[:80], f"{count:,}")
    console.print(table)


def _make_meta(data: Any) -> dict[str, Any]:
    """Future: return structured metadata for programmatic use."""
    return {"top_type": type(data).__name__}
