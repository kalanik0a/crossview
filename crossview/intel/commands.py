"""`crossview intel` — ingest, ground, and query Intellio-style intelligence
reports as cross-referenced nodes in the Crossview silo."""
from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from crossview import intel
from crossview.data.database import connect as ref_connect

app = typer.Typer(help="Intellio↔Crossview intel reports: ingest, ground, query.")
console = Console()


def _enr_connect():
    try:
        from crossview.enrichment.cache import connect as enr_connect
        return enr_connect()
    except Exception:
        return None


def _print_ingest(res: dict) -> None:
    pct = (100 * res["refs_resolved"] // res["refs_total"]) if res["refs_total"] else 0
    console.print(
        f"[green]✓[/green] {res['subject']} [dim]({res['report_type']})[/dim] — "
        f"grounded {res['refs_resolved']}/{res['refs_total']} refs ({pct}%)"
    )
    if res["resolved"]:
        t = Table("entity", "source", "name", title="Grounded → Crossview silo")
        for r in res["resolved"]:
            t.add_row(r["entity_id"], r["entity_source"], (r["name"] or "")[:60])
        console.print(t)
    if res["unresolved"]:
        console.print("[yellow]unresolved:[/yellow] "
                      + ", ".join(r["entity_id"] for r in res["unresolved"]))


@app.command()
def ingest(
    path: Path = typer.Argument(..., exists=True, dir_okay=False,  # noqa: B008
                                help="Intellio report JSON (a single report or a list)."),
) -> None:
    """Persist an Intellio report and ground its entity references against the silo."""
    data = json.loads(path.read_text())
    reports = data if isinstance(data, list) else [data]
    ic, rc, ec = intel.connect(), ref_connect(), _enr_connect()
    for rep in reports:
        _print_ingest(intel.ingest_report(rep, ic, rc, ec))


@app.command()
def generate(
    subject: str = typer.Argument(..., help="What to research (malware, CVE, tool, framework…)."),
    type_: str = typer.Option(None, "--type", "-t", help="Force a class: threat-intel, vulnerability, red-team-tool, blue-team-tool, engineering."),
    model: str = typer.Option(None, "--model", help="Override the Gemini model."),
    no_store: bool = typer.Option(False, "--no-store", help="Print the report JSON; don't persist."),
) -> None:
    """Generate an intel report in-process (Intellio generators ported to Python,
    Gemini-grounded), then ground + persist it into the silo. Needs GEMINI_API_KEY."""
    from crossview.intel import generate as gen_mod
    cls = type_ or gen_mod.classify(subject)
    console.print(f"[dim]generating '{cls}' report for '{subject}' via Gemini grounding…[/dim]")
    report = gen_mod.generate(subject, classification=cls, model=model)
    if no_store:
        console.print_json(json.dumps(report))
        return
    ic, rc, ec = intel.connect(), ref_connect(), _enr_connect()
    _print_ingest(intel.ingest_report(report, ic, rc, ec, origin="intellio-port"))


@app.command(name="list")
def list_cmd() -> None:
    """List stored intel reports with their grounding coverage."""
    rows = intel.list_reports(intel.connect())
    if not rows:
        console.print("[dim]no intel reports ingested yet[/dim]")
        return
    t = Table("id", "subject", "type", "refs", "grounded", "ingested")
    for r in rows:
        t.add_row(str(r["id"]), r["subject"], r["report_type"],
                  str(r["refs"]), str(r["grounded"] or 0), r["created_at"])
    console.print(t)


@app.command()
def show(subject: str) -> None:
    """Show a stored report's summary and its grounded cross-references."""
    ic = intel.connect()
    rep = intel.get_report(ic, subject)
    if not rep:
        console.print(f"[red]no intel report for '{subject}'[/red]")
        raise typer.Exit(1)
    console.print(f"[bold]{rep['subject']}[/bold]  [dim]{rep['report_type']}[/dim]")
    if rep["summary"]:
        console.print(rep["summary"])
    refs = intel.report_refs(ic, rep["id"])
    t = Table("entity", "source", "grounded", "name", title="Cross-references")
    for r in refs:
        t.add_row(r["entity_id"], r["entity_source"] or "",
                  "✓" if r["resolved"] else "·", (r["name"] or "")[:60])
    console.print(t)


@app.command()
def report(
    subject: str = typer.Argument(..., help="Stored intel subject (e.g. WannaCry, CWE-89)."),
    out: Path = typer.Option(None, "--out", help="Output base path (default <subject>-intel)."),  # noqa: B008
) -> None:
    """Render a stored intel report to client-grade HTML (+ PDF) — the OSCTI deliverable."""
    from crossview.reporting import html_to_pdf, render_intel_html
    ic = intel.connect()
    rep = intel.get_report(ic, subject)
    if not rep:
        console.print(f"[red]no intel report for '{subject}' — generate or ingest it first[/red]")
        raise typer.Exit(1)
    refs = [{"entity_id": r["entity_id"], "entity_source": r["entity_source"],
             "resolved": r["resolved"], "name": r["name"]} for r in intel.report_refs(ic, rep["id"])]
    report_dict = {"subject": rep["subject"], "report_type": rep["report_type"],
                   "origin": rep["origin"], "summary": rep["summary"], "payload": rep["payload_json"]}
    html = render_intel_html(report_dict, refs)
    base = out or Path(f"{subject}-intel")
    html_path = base.with_suffix(".html")
    html_path.write_text(html, encoding="utf-8")
    pdf_path = base.with_suffix(".pdf")
    engine = html_to_pdf(html, pdf_path)
    console.print(f"[green]wrote[/green] {html_path}")
    if engine:
        console.print(f"[green]wrote[/green] {pdf_path} [dim](via {engine})[/dim]")
    else:
        console.print("[dim]PDF skipped — install 'weasyprint' or a Playwright Chromium.[/dim]")


@app.command()
def citing(entity_id: str) -> None:
    """Reverse link: which intel reports cite this canonical entity (e.g. T1059, CWE-89)."""
    rows = intel.reports_citing(intel.connect(), entity_id)
    if not rows:
        console.print(f"[dim]no intel reports cite {entity_id}[/dim]")
        return
    t = Table("subject", "report type", "via", "ingested",
              title=f"Intel reports citing {entity_id}")
    for r in rows:
        t.add_row(r["subject"], r["report_type"], r["entity_source"] or "", r["created_at"])
    console.print(t)
