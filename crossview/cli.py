"""Crossview CLI entry point.

Subcommand groups:
  - top-level: update / search / show / scan / tui
  - dev:       data tooling (verify-urls, inspect, schema, sample, validate, stats, sql)
"""
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from crossview.dev import commands as dev_commands
from crossview.intel import commands as intel_commands

console = Console()

app = typer.Typer(
    name="crossview",
    help="Cross-referenced MITRE CAPEC/CWE/ATT&CK/ATLAS/D3FEND silo + scanner.",
    no_args_is_help=True,
)
app.add_typer(dev_commands.app, name="dev", help="Internal data tooling.")
app.add_typer(intel_commands.app, name="intel",
              help="Intellio↔Crossview intel reports: ingest, ground, query.")


@app.command()
def update(
    only: list[str] = typer.Option(  # noqa: B008
        None, "--only", help="Only refresh these source keys (--only capec --only cwe ...)."
    ),
    force: bool = typer.Option(False, "--force", help="Re-download even if cached."),
    skip_download: bool = typer.Option(  # noqa: B008
        False, "--skip-download", help="Use already-cached files; just rebuild the DB."
    ),
) -> None:
    """Re-download MITRE data, normalize, and rebuild the SQLite reference DB."""
    from crossview.data.downloader import download_all_sync
    from crossview.data.loader import load_all
    from crossview.data.paths import RAW_DIR, ensure_dirs

    ensure_dirs()
    if not skip_download:
        download_all_sync(RAW_DIR, only=only or None, force=force)
    load_all()


@app.command()
def search(
    query: str,
    limit: int = typer.Option(20, "--limit", "-n"),
) -> None:
    """Full-text search across the silo."""
    from crossview.data.database import connect

    conn = connect()
    rows = conn.execute(
        """
        SELECT e.id, e.source, e.subtype, e.name,
               substr(e.description, 1, 120) AS snippet
        FROM entities_fts f
        JOIN entities e ON e.rowid = f.rowid
        WHERE entities_fts MATCH ?
        ORDER BY rank
        LIMIT ?
        """,
        (query, limit),
    ).fetchall()

    if not rows:
        console.print(f"[dim]No matches for {query!r}.[/dim]")
        raise typer.Exit(code=1)

    table = Table(title=f"{len(rows)} match(es) for {query!r}")
    table.add_column("ID")
    table.add_column("Source")
    table.add_column("Type")
    table.add_column("Name")
    table.add_column("Snippet", overflow="fold")
    for r in rows:
        table.add_row(r["id"], r["source"], r["subtype"], r["name"], r["snippet"] or "")
    console.print(table)


@app.command()
def show(entity_id: str) -> None:
    """Show one entity plus all its outbound and inbound xrefs."""
    from crossview.data.database import connect

    conn = connect()
    row = conn.execute(
        "SELECT * FROM entities WHERE id = ?", (entity_id,)
    ).fetchone()
    if not row:
        console.print(f"[red]No entity with id {entity_id!r}.[/red]")
        raise typer.Exit(code=1)

    console.rule(f"[bold]{row['id']}[/bold] · {row['name']}")
    console.print(f"[dim]source={row['source']}  type={row['subtype']}  framework={row['framework']}[/dim]")
    if row["abstraction"]:
        console.print(f"[dim]abstraction={row['abstraction']}[/dim]")
    if row["description"]:
        console.print()
        console.print(row["description"])

    out = conn.execute(
        "SELECT relation, dst_id FROM xrefs WHERE src_id = ? ORDER BY relation, dst_id",
        (entity_id,),
    ).fetchall()
    if out:
        t = Table(title="outbound xrefs")
        t.add_column("relation")
        t.add_column("→ target")
        for x in out:
            t.add_row(x["relation"], x["dst_id"])
        console.print(t)

    inc = conn.execute(
        "SELECT relation, src_id FROM xrefs WHERE dst_id = ? ORDER BY relation, src_id",
        (entity_id,),
    ).fetchall()
    if inc:
        t = Table(title="inbound xrefs")
        t.add_column("relation")
        t.add_column("← source")
        for x in inc:
            t.add_row(x["relation"], x["src_id"])
        console.print(t)


@app.command()
def enrich(
    entity_id: str = typer.Argument(  # noqa: B008
        None, help="Entity to enrich (CWE-89, CAPEC-66, etc). Omit for global enrichers."
    ),
    enricher: str = typer.Option(  # noqa: B008
        None, "--enricher", "-e", help="Specific enricher to run (cisa_kev, ...). Default: all."
    ),
    force: bool = typer.Option(False, "--force", help="Bypass TTL cache."),
) -> None:
    """Run enrichers and write distilled context into enrichment.db."""
    from crossview.enrichment.orchestrator import (
        ALL_ENRICHERS,
        GLOBAL_ENRICHERS,
        run_all_global_sync,
        run_enricher_sync,
    )

    if enricher and enricher not in ALL_ENRICHERS:
        console.print(f"[red]Unknown enricher: {enricher}. Available: {list(ALL_ENRICHERS)}[/red]")
        raise typer.Exit(code=1)

    if entity_id is None and enricher is None:
        results = run_all_global_sync(force=force)
    elif entity_id is None and enricher in GLOBAL_ENRICHERS:
        results = [run_enricher_sync(enricher, force=force)]
    elif entity_id and enricher:
        results = [run_enricher_sync(enricher, entity_id=entity_id, force=force)]
    elif entity_id and not enricher:
        # Per-entity sweep: in Wave 1 we only have global enrichers, so just do KEV lookup
        from crossview.enrichment.cache import connect as conn_enr
        from crossview.enrichment.enrichers.cisa_kev import kev_for_cwe

        if entity_id.startswith("CWE-"):
            from crossview.enrichment.enrichers.cve_nvd import cves_for_cwe

            conn_e = conn_enr()
            kev_rows = kev_for_cwe(conn_e, entity_id)
            cve_rows = cves_for_cwe(conn_e, entity_id, limit=15)

            if kev_rows:
                t = Table(title=f"CISA KEV entries linked to {entity_id}")
                for c in ("cve_id", "vendor_project", "product", "name", "added", "ransomware"):
                    t.add_column(c)
                for r in kev_rows:
                    t.add_row(
                        r["cve_id"], r["vendor_project"] or "", r["product"] or "",
                        r["vulnerability_name"] or "", r["date_added"] or "",
                        r["known_ransomware_use"] or "",
                    )
                console.print(t)

            if cve_rows:
                t = Table(title=f"NVD CVEs linked to {entity_id} (top {len(cve_rows)} by CVSS)")
                for c in ("cve_id", "score", "severity", "published", "in_kev", "description"):
                    t.add_column(c, overflow="fold")
                for r in cve_rows:
                    t.add_row(
                        r["cve_id"],
                        f"{r['cvss_v3_score']:.1f}" if r["cvss_v3_score"] is not None else "",
                        r["cvss_v3_severity"] or "",
                        (r["published_at"] or "")[:10],
                        "★" if r["in_kev"] else "",
                        (r["description"] or "")[:140],
                    )
                console.print(t)

            if not kev_rows and not cve_rows:
                console.print(
                    f"[dim]No KEV or NVD CVEs linked to {entity_id}. "
                    f"Run `crossview enrich --enricher cve_nvd_bulk` for the full sweep.[/dim]"
                )
            return
        else:
            console.print(f"[dim]Per-entity enrichers for {entity_id} land in a later wave.[/dim]")
            return
    else:
        console.print("[red]Invalid combination of arguments.[/red]")
        raise typer.Exit(code=1)

    for r in results:
        for note in r.notes:
            console.log(f"[green]{r.enricher}[/green]: {note}")


@app.command()
def research(entity_id: str, force: bool = typer.Option(False, "--force")) -> None:
    """Web-research one entity via crawl4ai. Cached in enrichment.db."""
    from crossview.enrichment.orchestrator import run_enricher_sync

    result = run_enricher_sync("web_research", entity_id=entity_id, force=force)
    for note in result.notes:
        console.log(note)
    if result.payload:
        console.print(result.payload)


@app.command()
def cve(cve_id: str) -> None:
    """Show one CVE plus its CWE links and affected CPE list."""
    from crossview.enrichment.cache import connect as conn_enr
    from crossview.enrichment.enrichers.cve_nvd import cpes_for_cve

    conn = conn_enr()
    row = conn.execute(
        "SELECT * FROM cves WHERE cve_id = ?", (cve_id,)
    ).fetchone()
    if not row:
        console.print(f"[red]No CVE {cve_id!r} in the cache. Run the bulk sweep first.[/red]")
        raise typer.Exit(code=1)

    console.rule(f"[bold]{row['cve_id']}[/bold]")
    if row["cvss_v3_score"] is not None:
        console.print(
            f"[bold]CVSS v3:[/bold] {row['cvss_v3_score']:.1f} "
            f"([yellow]{row['cvss_v3_severity']}[/yellow])"
        )
    if row["published_at"]:
        console.print(f"[dim]published: {row['published_at']}  modified: {row['modified_at']}[/dim]")
    if row["description"]:
        console.print()
        console.print(row["description"])

    in_kev = conn.execute("SELECT * FROM kev WHERE cve_id = ?", (cve_id,)).fetchone()
    if in_kev:
        console.print()
        console.print(f"[bold red]⚠ Listed in CISA KEV[/bold red] — added {in_kev['date_added']}")
        if in_kev["known_ransomware_use"]:
            console.print(f"  ransomware use: {in_kev['known_ransomware_use']}")

    cwes = conn.execute(
        "SELECT cwe_id FROM cwe_cves WHERE cve_id = ? ORDER BY cwe_id", (cve_id,)
    ).fetchall()
    if cwes:
        console.print()
        console.print(f"[bold]CWEs:[/bold] {', '.join(c['cwe_id'] for c in cwes)}")

    cpe_rows = cpes_for_cve(conn, cve_id)
    if cpe_rows:
        t = Table(title=f"Affected platforms ({len(cpe_rows)} CPE entries)")
        for c in ("vendor", "product", "version", "vulnerable", "cpe_uri"):
            t.add_column(c, overflow="fold")
        for r in cpe_rows[:50]:
            t.add_row(
                r["vendor"] or "", r["product"] or "", r["version"] or "",
                "yes" if r["vulnerable"] else "no",
                r["cpe_uri"],
            )
        console.print(t)
        if len(cpe_rows) > 50:
            console.print(f"[dim](showing first 50 of {len(cpe_rows)})[/dim]")


@app.command()
def survey(path: Path = typer.Argument(..., exists=True, file_okay=False)) -> None:  # noqa: B008
    """Stage 1 — walk the project, run language harnesses, persist structural map to cohort.db."""
    from crossview.scanner.survey import run_survey

    run_survey(path)


@app.command()
def prematch(
    path: Path = typer.Argument(..., exists=True, file_okay=False),  # noqa: B008
    skip_semgrep: bool = typer.Option(False, "--skip-semgrep"),
) -> None:
    """Stage 2a — run Bandit + Semgrep, persist findings, seed investigations + hypotheses."""
    from crossview.scanner.prematch_code import run_prematch_code

    run_prematch_code(path, skip_semgrep=skip_semgrep)


@app.command("prematch-secrets")
def prematch_secrets_cmd(
    path: Path = typer.Argument(..., exists=True, file_okay=False),  # noqa: B008
) -> None:
    """Stage 2b — run detect-secrets + TruffleHog + Gitleaks, persist findings + investigations."""
    from crossview.scanner.prematch_secrets import run_prematch_secrets

    run_prematch_secrets(path)


@app.command("prematch-iac")
def prematch_iac_cmd(
    path: Path = typer.Argument(..., exists=True, file_okay=False),  # noqa: B008
) -> None:
    """Stage 2c — run Trivy + Hadolint for IaC + container scanning."""
    from crossview.scanner.prematch_iac import run_prematch_iac

    run_prematch_iac(path)


@app.command("prematch-deps")
def prematch_deps_cmd(
    path: Path = typer.Argument(..., exists=True, file_okay=False),  # noqa: B008
) -> None:
    """Stage 2d — run OSV-Scanner against lockfiles, auto-enrich with our CVE database."""
    from crossview.scanner.prematch_deps import run_prematch_deps

    run_prematch_deps(path)


@app.command()
def investigate(
    path: Path = typer.Argument(..., exists=True, file_okay=False),  # noqa: B008
    web_research: int = typer.Option(  # noqa: B008
        0, "--web-research", "-W",
        help="Run crawl4ai web_research for the top N high-priority unique CWEs (default 0).",
    ),
    threshold: float = typer.Option(  # noqa: B008
        0.8, "--threshold", help="Priority score threshold for web research."
    ),
) -> None:
    """Stage 3 — walk CWE→CAPEC→ATT&CK→D3FEND→UKC for every open hypothesis, score priority, persist evidence."""
    from crossview.scanner.investigate import run_investigate

    run_investigate(
        path,
        web_research_threshold=threshold,
        max_web_research=web_research,
    )


@app.command()
def verify(
    path: Path = typer.Argument(..., exists=True, file_okay=False),  # noqa: B008
    priority_floor: float = typer.Option(  # noqa: B008
        0.5, "--floor", help="Skip hypotheses below this confidence."
    ),
) -> None:
    """Stage 4 — re-survey live code per hypothesis, classify confirmed/partial/rejected."""
    from crossview.scanner.verify import run_verify

    run_verify(path, priority_floor=priority_floor)


@app.command()
def report(
    path: Path = typer.Argument(..., exists=True, file_okay=False),  # noqa: B008
    out_dir: Path = typer.Option(  # noqa: B008
        None, "--out", help="Where to write reports. Defaults to <path>/."
    ),
) -> None:
    """Stage 5 — emit Markdown + SARIF + STIX reports of confirmed/partial findings."""
    from crossview.scanner.reporter import run_report

    run_report(path, out_dir=out_dir)


@app.command()
def triage(
    path: Path = typer.Argument(..., exists=True, file_okay=False),  # noqa: B008
    no_verify_secrets: bool = typer.Option(  # noqa: B008
        False, "--no-verify-secrets",
        help="Skip the live trufflehog --results=verified pass.",
    ),
    out: Path = typer.Option(  # noqa: B008
        None, "--out", help="Where to write the triage report. Default <path>/CROSSVIEW-TRIAGE.md"
    ),
) -> None:
    """Production-only exploit triage. Filters confirmed findings by file-path classification, re-runs TruffleHog with live verification, and emits a ranked report."""
    from crossview.scanner.triage import run_triage

    run_triage(path, verify_live_secrets=not no_verify_secrets, out_path=out)


@app.command()
def scan(
    path: Path = typer.Argument(..., exists=True, file_okay=False),  # noqa: B008
    out_dir: Path = typer.Option(  # noqa: B008
        None, "--out", help="Where to write reports. Defaults to <path>/."
    ),
    skip_semgrep: bool = typer.Option(False, "--skip-semgrep"),
    web_research: int = typer.Option(  # noqa: B008
        0, "--web-research", "-W", help="Run crawl4ai for top N high-priority CWEs."
    ),
    stop_after: str = typer.Option(  # noqa: B008
        None, "--stop-after",
        help="Stop after stage: survey | prematch | investigate | verify",
    ),
) -> None:
    """Run the full scan pipeline: survey → prematch (code/secrets/iac/deps) → investigate → verify → report."""
    from crossview.scanner.investigate import run_investigate
    from crossview.scanner.prematch_code import run_prematch_code
    from crossview.scanner.prematch_deps import run_prematch_deps
    from crossview.scanner.prematch_iac import run_prematch_iac
    from crossview.scanner.prematch_secrets import run_prematch_secrets
    from crossview.scanner.reporter import run_report
    from crossview.scanner.survey import run_survey
    from crossview.scanner.verify import run_verify

    stages = ["survey", "prematch", "investigate", "verify", "report"]
    if stop_after and stop_after not in stages:
        console.print(f"[red]Invalid --stop-after: {stop_after}. Valid: {stages}[/red]")
        raise typer.Exit(code=1)

    run_survey(path)
    if stop_after == "survey":
        return

    run_prematch_code(path, skip_semgrep=skip_semgrep)
    run_prematch_secrets(path)
    run_prematch_iac(path)
    run_prematch_deps(path)
    if stop_after == "prematch":
        return

    run_investigate(path, max_web_research=web_research)
    if stop_after == "investigate":
        return

    run_verify(path)
    if stop_after == "verify":
        return

    run_report(path, out_dir=out_dir)


@app.command()
def graphql(
    query: str = typer.Argument(..., help="GraphQL query string."),  # noqa: B008
    pretty: bool = typer.Option(True, "--pretty/--no-pretty"),
) -> None:
    """Run a GraphQL query in-process against the unified schema."""
    import json as _json

    from crossview.graph.schema import execute

    result = execute(query)
    if pretty:
        console.print_json(_json.dumps(result, default=str))
    else:
        console.print(_json.dumps(result, default=str))


@app.command()
def tui() -> None:
    """Launch the Textual TUI: tree views + search + detail panel."""
    from crossview.tui.app import run_tui

    run_tui()


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address."),  # noqa: B008
    port: int = typer.Option(8000, "--port", help="Port."),  # noqa: B008
) -> None:
    """Serve the GraphQL schema over HTTP (GraphiQL in the browser) — the seam any
    web or desktop front-end uses to drive Crossview without duplicating logic."""
    try:
        import uvicorn
        from strawberry.asgi import GraphQL
    except ImportError:
        console.print("[red]`serve` needs uvicorn + strawberry. Install: pip install 'crossview[serve]'[/red]")
        raise typer.Exit(1)
    from crossview.graph.schema import schema

    console.print(f"[green]Crossview GraphQL[/green] → http://{host}:{port}/graphql  "
                  "[dim](open in a browser for GraphiQL; Ctrl-C to stop)[/dim]")
    uvicorn.run(GraphQL(schema), host=host, port=port, log_level="info")


if __name__ == "__main__":
    app()
