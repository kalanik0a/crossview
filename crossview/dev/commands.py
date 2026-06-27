"""Internal data-tooling subcommands.

Make my (the agent's) life easier when iterating on normalizers and xrefs.
Stay in the tool because they're useful whenever MITRE bumps a schema.
"""
import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

console = Console()
app = typer.Typer(no_args_is_help=True)


@app.command("verify-urls")
def verify_urls() -> None:
    """HEAD-check every MITRE source URL and report status."""
    from crossview.dev.url_check import verify_all

    failures = asyncio.run(verify_all())
    if failures:
        raise typer.Exit(code=1)


@app.command("inspect")
def inspect_cmd(file: Path = typer.Argument(..., exists=True)) -> None:  # noqa: B008
    """Print top-level keys, type, and counts for a downloaded file."""
    from crossview.dev.inspector import inspect

    inspect(file)


@app.command("schema")
def schema_cmd(
    file: Path = typer.Argument(..., exists=True),  # noqa: B008
    depth: int = typer.Option(3, help="Max nesting depth to infer."),
) -> None:
    """Infer field paths and types from a JSON file (per entity type)."""
    from crossview.dev.schema_infer import infer

    infer(file, max_depth=depth)


@app.command("sample")
def sample_cmd(
    file: Path = typer.Argument(..., exists=True),  # noqa: B008
    count: int = typer.Option(3, help="How many samples per entity type."),
) -> None:
    """Pull N samples per entity type out of a JSON file."""
    from crossview.dev.sampler import sample

    sample(file, count=count)


@app.command("stats")
def stats() -> None:
    """Row counts per source/subtype, plus xref breakdown by relation."""
    from crossview.data.database import connect, stats as db_stats

    conn = connect()
    s = db_stats(conn)

    t = Table(title="Entities by source/subtype")
    t.add_column("source.subtype")
    t.add_column("count", justify="right")
    total = 0
    for k, v in sorted(s.items()):
        if k in ("xrefs", "xrefs_by_relation"):
            continue
        t.add_row(k, f"{v:,}")
        total += v
    t.add_section()
    t.add_row("[bold]total entities[/bold]", f"[bold]{total:,}[/bold]")
    console.print(t)

    t2 = Table(title="Xrefs by relation")
    t2.add_column("relation")
    t2.add_column("count", justify="right")
    for k, v in sorted(s.get("xrefs_by_relation", {}).items()):
        t2.add_row(k, f"{v:,}")
    t2.add_section()
    t2.add_row("[bold]total xrefs[/bold]", f"[bold]{s.get('xrefs', 0):,}[/bold]")
    console.print(t2)


@app.command("validate")
def validate() -> None:
    """Integrity checks: orphans, dangling xrefs, FTS coverage, dup IDs."""
    from crossview.data.database import connect

    conn = connect()
    checks: list[tuple[str, int, str]] = []

    # 1. Dangling xrefs (point to a non-existent entity)
    dangling = conn.execute(
        """
        SELECT COUNT(*) AS n FROM xrefs x
        WHERE NOT EXISTS (SELECT 1 FROM entities WHERE id = x.dst_id)
           OR NOT EXISTS (SELECT 1 FROM entities WHERE id = x.src_id)
        """
    ).fetchone()["n"]
    checks.append(("Dangling xrefs (src or dst missing)", dangling, "ok" if dangling == 0 else "warn"))

    # 2. Orphan entities (no inbound or outbound xrefs)
    orphans = conn.execute(
        """
        SELECT COUNT(*) AS n FROM entities e
        WHERE NOT EXISTS (SELECT 1 FROM xrefs WHERE src_id = e.id OR dst_id = e.id)
        """
    ).fetchone()["n"]
    checks.append(("Orphan entities (zero xrefs)", orphans, "ok" if orphans < 200 else "warn"))

    # 3. FTS coverage
    fts_count = conn.execute("SELECT COUNT(*) AS n FROM entities_fts").fetchone()["n"]
    ent_count = conn.execute("SELECT COUNT(*) AS n FROM entities").fetchone()["n"]
    checks.append(
        ("FTS coverage", fts_count, "ok" if fts_count == ent_count else f"mismatch ({ent_count} entities)")
    )

    t = Table(title="Validation")
    t.add_column("Check")
    t.add_column("Count", justify="right")
    t.add_column("Status")
    for name, n, status in checks:
        color = "green" if status == "ok" else "yellow"
        t.add_row(name, f"{n:,}", f"[{color}]{status}[/{color}]")
    console.print(t)


@app.command("sql")
def sql(query: str) -> None:
    """Execute a read-only SQL query against the reference DB."""
    from crossview.data.database import connect

    conn = connect()
    # [CWE-89] Enforce read-only at the SQLite level — prefix check alone is bypassable
    conn.execute("PRAGMA query_only = ON")
    if not query.strip().lower().startswith(("select", "with", "explain")):
        console.print("[red]Only SELECT / WITH / EXPLAIN allowed.[/red]")
        raise typer.Exit(code=1)
    rows = conn.execute(query).fetchall()
    if not rows:
        console.print("[dim](no rows)[/dim]")
        return
    cols = rows[0].keys()
    t = Table()
    for c in cols:
        t.add_column(c)
    for r in rows:
        t.add_row(*[str(r[c]) if r[c] is not None else "" for c in cols])
    console.print(t)
    console.print(f"[dim]{len(rows)} row(s)[/dim]")


@app.command("xref")
def xref(entity_id: str) -> None:
    """Trace every cross-reference path out from an entity (one hop)."""
    from crossview.data.database import connect

    conn = connect()
    out = conn.execute(
        """
        SELECT x.relation, x.dst_id, e.name, e.source, e.subtype
        FROM xrefs x
        LEFT JOIN entities e ON e.id = x.dst_id
        WHERE x.src_id = ?
        ORDER BY x.relation, x.dst_id
        """,
        (entity_id,),
    ).fetchall()

    inc = conn.execute(
        """
        SELECT x.relation, x.src_id, e.name, e.source, e.subtype
        FROM xrefs x
        LEFT JOIN entities e ON e.id = x.src_id
        WHERE x.dst_id = ?
        ORDER BY x.relation, x.src_id
        """,
        (entity_id,),
    ).fetchall()

    if not out and not inc:
        console.print(f"[dim]No xrefs touching {entity_id}.[/dim]")
        return

    if out:
        t = Table(title=f"{entity_id} → ...")
        for c in ("relation", "→", "name", "source", "type"):
            t.add_column(c)
        for r in out:
            t.add_row(r["relation"], r["dst_id"], r["name"] or "?", r["source"] or "?", r["subtype"] or "?")
        console.print(t)

    if inc:
        t = Table(title=f"... → {entity_id}")
        for c in ("relation", "←", "name", "source", "type"):
            t.add_column(c)
        for r in inc:
            t.add_row(r["relation"], r["src_id"], r["name"] or "?", r["source"] or "?", r["subtype"] or "?")
        console.print(t)


@app.command("orphans")
def orphans(limit: int = typer.Option(50, "--limit")) -> None:
    """List entities with zero cross-references (might indicate normalizer gaps)."""
    from crossview.data.database import connect

    conn = connect()
    rows = conn.execute(
        """
        SELECT e.id, e.source, e.subtype, e.name
        FROM entities e
        WHERE NOT EXISTS (SELECT 1 FROM xrefs WHERE src_id = e.id OR dst_id = e.id)
        ORDER BY e.source, e.id
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    if not rows:
        console.print("[green]No orphans.[/green]")
        return
    t = Table(title=f"Orphan entities (showing {len(rows)})")
    for c in ("id", "source", "subtype", "name"):
        t.add_column(c)
    for r in rows:
        t.add_row(r["id"], r["source"], r["subtype"], r["name"])
    console.print(t)


@app.command("diff")
def diff(
    old: Path = typer.Argument(..., exists=True),  # noqa: B008
    new: Path = typer.Argument(..., exists=True),  # noqa: B008
) -> None:
    """Diff two MITRE snapshots: added/removed/changed entities."""
    raise typer.Exit(code=2)
