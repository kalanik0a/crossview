"""Pull representative samples out of a JSON file."""
import json
from collections import defaultdict
from pathlib import Path

from rich.console import Console

console = Console()


def sample(path: Path, count: int = 3) -> None:
    if path.suffix.lower() != ".json":
        console.print(f"[red]Sampling is JSON-only; got {path}[/red]")
        return

    data = json.loads(path.read_text())

    if isinstance(data, dict) and isinstance(data.get("objects"), list):
        _sample_buckets(data["objects"], "type", count)
        return

    if isinstance(data, dict) and isinstance(data.get("@graph"), list):
        _sample_buckets(data["@graph"], "@type", count)
        return

    if isinstance(data, list):
        _print_samples("<list>", data[:count])
        return

    console.print_json(json.dumps(data, default=str)[:5000])


def _sample_buckets(items: list, type_key: str, count: int) -> None:
    by_type: dict[str, list] = defaultdict(list)
    for obj in items:
        t = obj.get(type_key, "_unknown")
        if isinstance(t, list):
            t = "|".join(t)
        if len(by_type[str(t)]) < count:
            by_type[str(t)].append(obj)

    for t in sorted(by_type.keys()):
        _print_samples(t, by_type[t])


def _print_samples(label: str, items: list) -> None:
    console.rule(f"[bold]{label}[/bold] — {len(items)} sample(s)")
    for item in items:
        console.print_json(json.dumps(item, indent=2, default=str))
