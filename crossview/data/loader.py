"""Loader: reads raw files, runs normalizers, persists to the reference DB."""
import json

from rich.console import Console
from rich.table import Table

from crossview.data import database
from crossview.data.normalizers import cwe as cwe_norm
from crossview.data.normalizers import d3fend as d3fend_norm
from crossview.data.normalizers import stix as stix_norm
from crossview.data.normalizers import ukc as ukc_norm
from crossview.data.paths import RAW_DIR
from crossview.domain import NormalizerResult

console = Console()


# (raw_filename, normalize_fn) — order matters only for human readability of logs.
def _load_stix(filename: str, source: str, framework: str | None = None) -> NormalizerResult:
    raw = json.loads((RAW_DIR / filename).read_text())
    return stix_norm.normalize(raw, source=source, framework=framework)


def _load_cwe() -> NormalizerResult:
    return cwe_norm.normalize_file(RAW_DIR / "cwec.xml")


def _load_d3fend() -> NormalizerResult:
    out = d3fend_norm.normalize_ontology(RAW_DIR / "d3fend-ontology.json")
    out.extend(d3fend_norm.normalize_mappings(RAW_DIR / "d3fend-mappings.json"))
    return out


def load_all() -> dict[str, int]:
    """Run every normalizer and write into a freshly-rebuilt reference DB."""
    conn = database.connect()
    database.init_schema(conn)

    summary: list[tuple[str, int, int]] = []  # (label, entities, xrefs)

    def _persist(label: str, res: NormalizerResult) -> None:
        with database.transaction(conn):
            n_e = database.insert_entities(conn, res.entities)
            n_x = database.insert_xrefs(conn, res.xrefs)
        for note in res.notes:
            console.log(f"[dim]{label}: {note}[/dim]")
        summary.append((label, n_e, n_x))

    console.log("[bold]Loading sources...[/bold]")

    _persist("UKC",                ukc_norm.normalize())
    _persist("CWE",                _load_cwe())
    _persist("CAPEC",              _load_stix("capec.stix.json", "capec"))
    _persist("ATT&CK Enterprise",  _load_stix("attack-enterprise.json", "attack", "enterprise"))
    _persist("ATT&CK Mobile",      _load_stix("attack-mobile.json", "attack", "mobile"))
    _persist("ATT&CK ICS",         _load_stix("attack-ics.json", "attack", "ics"))
    _persist("ATLAS",              _load_stix("atlas.stix.json", "atlas", "atlas"))
    _persist("D3FEND",             _load_d3fend())

    database.rebuild_fts(conn)

    # Pretty summary
    table = Table(title="Load summary")
    table.add_column("Source")
    table.add_column("Entities", justify="right")
    table.add_column("Xrefs", justify="right")
    total_e = total_x = 0
    for label, e, x in summary:
        table.add_row(label, f"{e:,}", f"{x:,}")
        total_e += e
        total_x += x
    table.add_section()
    table.add_row("[bold]Total[/bold]", f"[bold]{total_e:,}[/bold]", f"[bold]{total_x:,}[/bold]")
    console.print(table)

    return {label: e for label, e, _ in summary}
