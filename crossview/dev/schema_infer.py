"""Infer field paths and types from a JSON file.

For STIX bundles and JSON-LD graphs, buckets by entity type first so
we get one schema per type instead of a soup.
"""
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

console = Console()
SAMPLE_LIMIT = 500


def _type_name(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "list"
    if isinstance(v, dict):
        return "dict"
    return type(v).__name__


def _walk(node: Any, path: str, depth: int, max_depth: int, paths: dict) -> None:
    if depth > max_depth:
        return
    paths[path][_type_name(node)] += 1
    if isinstance(node, dict):
        for k, v in node.items():
            _walk(v, f"{path}.{k}" if path else k, depth + 1, max_depth, paths)
    elif isinstance(node, list):
        for item in node[:50]:
            _walk(item, f"{path}[]", depth + 1, max_depth, paths)


def _infer_for(items: list, max_depth: int) -> dict[str, dict[str, int]]:
    paths: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for item in items[:SAMPLE_LIMIT]:
        _walk(item, "", 0, max_depth, paths)
    return paths


def _bucketize(data: Any) -> dict[str, list]:
    """Group heterogeneous arrays by entity type."""
    if isinstance(data, dict) and isinstance(data.get("objects"), list):
        buckets: dict[str, list] = defaultdict(list)
        for obj in data["objects"]:
            buckets[obj.get("type", "_unknown")].append(obj)
        return dict(buckets)

    if isinstance(data, dict) and isinstance(data.get("@graph"), list):
        buckets = defaultdict(list)
        for obj in data["@graph"]:
            t = obj.get("@type", "_unknown")
            if isinstance(t, list):
                t = "|".join(t)
            buckets[str(t)].append(obj)
        return dict(buckets)

    if isinstance(data, list):
        return {"<list>": data}

    return {"<root>": [data]}


def infer(path: Path, max_depth: int = 3) -> None:
    if path.suffix.lower() != ".json":
        console.print(f"[red]Schema inference is JSON-only; got {path}[/red]")
        return

    data = json.loads(path.read_text())
    buckets = _bucketize(data)

    console.rule(f"Inferred schemas: {path.name} ({len(buckets)} bucket(s))")

    # Sort buckets by population (most common first)
    sorted_buckets = sorted(buckets.items(), key=lambda kv: -len(kv[1]))

    for bucket_name, items in sorted_buckets:
        console.print(f"\n[bold cyan]{bucket_name}[/bold cyan] ({len(items):,} items)")
        paths = _infer_for(items, max_depth)
        if not paths:
            continue
        table = Table(show_header=True, header_style="dim")
        table.add_column("Path")
        table.add_column("Types")
        table.add_column("Count", justify="right")
        for p in sorted(paths.keys()):
            if not p:
                continue
            types = paths[p]
            type_str = ", ".join(
                f"{t}" for t, _ in sorted(types.items(), key=lambda x: -x[1])
            )
            total = sum(types.values())
            table.add_row(p, type_str, f"{total:,}")
        console.print(table)
