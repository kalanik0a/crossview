"""Crossview TUI — Textual app.

Layout:
  ┌─────────────────────────────────────────────────────────────────┐
  │  Search bar  (cwe-89, prompt injection, TA0009, ...)            │
  ├──────────────────────┬──────────────────────────────────────────┤
  │ Tree                 │ Detail panel                             │
  │  CWE                 │  Selected entity:                        │
  │   ├ child weakness   │   - name + description                   │
  │  CAPEC               │   - cross-source chain                   │
  │  ATT&CK              │   - top CVEs / KEV                       │
  │  ATLAS               │                                          │
  │  D3FEND              │                                          │
  │  UKC                 │                                          │
  └──────────────────────┴──────────────────────────────────────────┘

All data flows through the Phase 4 GraphQL schema, so the TUI never touches
SQLite directly.
"""
from __future__ import annotations

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input, Static, Tree

from crossview.graph.schema import execute


# Sources to surface as top-level tree branches and what subtype to show first
TREE_BRANCHES = [
    ("cwe", "weakness", "CWE — Weaknesses"),
    ("capec", "attack-pattern", "CAPEC — Attack Patterns"),
    ("attack", "technique", "ATT&CK — Techniques"),
    ("atlas", "technique", "ATLAS — AI/ML Adversarial"),
    ("d3fend", "technique", "D3FEND — Defenses"),
    ("ukc", "kill-chain-phase", "UKC — Kill Chain"),
]


def _gql_entity(eid: str) -> dict | None:
    # [CWE-943] Use GraphQL variables, not string concatenation
    res = execute(
        'query($id: String!) { entity(id: $id) { id source subtype name description framework abstraction } }',
        variables={"id": eid},
    )
    return (res.get("data") or {}).get("entity")


def _gql_chain(cwe_id: str) -> dict | None:
    res = execute(
        'query($id: String!) { exploitChain(cweId: $id) { capecs attackTechniques atlasTechniques d3fendTechniques ukcPhases parentCwes } }',
        variables={"id": cwe_id},
    )
    return (res.get("data") or {}).get("exploitChain")


def _gql_cves(cwe_id: str, limit: int = 10) -> list[dict]:
    res = execute(
        'query($id: String!, $lim: Int!) { cvesForCwe(cweId: $id, limit: $lim) { cveId cvssV3Score cvssV3Severity inKev publishedAt } }',
        variables={"id": cwe_id, "lim": limit},
    )
    return (res.get("data") or {}).get("cvesForCwe") or []


def _gql_kev(cwe_id: str) -> list[dict]:
    res = execute(
        'query($id: String!) { kevForCwe(cweId: $id) { cveId vendorProject product knownRansomwareUse dateAdded } }',
        variables={"id": cwe_id},
    )
    return (res.get("data") or {}).get("kevForCwe") or []


def _gql_search(query: str, limit: int = 30) -> list[dict]:
    res = execute(
        'query($q: String!, $lim: Int!) { search(query: $q, limit: $lim) { id source subtype name } }',
        variables={"q": query, "lim": limit},
    )
    return (res.get("data") or {}).get("search") or []


def _gql_entities_by_source(source: str, subtype: str, limit: int = 200) -> list[dict]:
    res = execute(
        'query($src: String!, $sub: String!, $lim: Int!) { entitiesBySource(source: $src, subtype: $sub, limit: $lim) { id name } }',
        variables={"src": source, "sub": subtype, "lim": limit},
    )
    return (res.get("data") or {}).get("entitiesBySource") or []


def _format_detail(entity: dict, chain: dict | None, cves: list[dict], kev: list[dict]) -> str:
    lines: list[str] = []
    lines.append(f"[bold]{entity['id']}[/bold]  [dim]({entity['source']}/{entity['subtype']})[/dim]")
    lines.append(f"[bold cyan]{entity['name']}[/bold cyan]")
    if entity.get("framework"):
        lines.append(f"[dim]framework: {entity['framework']}  abstraction: {entity.get('abstraction') or '-'}[/dim]")
    lines.append("")
    if entity.get("description"):
        lines.append(entity["description"][:1500])
        lines.append("")

    if chain:
        lines.append("[bold yellow]Cross-source chain[/bold yellow]")
        if chain.get("parentCwes"):
            lines.append(f"  parents: {', '.join(chain['parentCwes'])}")
        if chain.get("capecs"):
            lines.append(f"  CAPEC: {', '.join(chain['capecs'][:8])}")
        if chain.get("attackTechniques"):
            lines.append(f"  ATT&CK: {', '.join(chain['attackTechniques'][:8])}")
        if chain.get("atlasTechniques"):
            lines.append(f"  ATLAS: {', '.join(chain['atlasTechniques'])}")
        if chain.get("d3fendTechniques"):
            lines.append(f"  D3FEND: {', '.join(chain['d3fendTechniques'][:6])}")
        if chain.get("ukcPhases"):
            lines.append(f"  UKC: {', '.join(chain['ukcPhases'])}")
        lines.append("")

    if cves:
        lines.append(f"[bold red]Top NVD CVEs ({len(cves)})[/bold red]")
        for c in cves[:6]:
            kev_marker = " [KEV]" if c.get("inKev") else ""
            score = f"{c['cvssV3Score']:.1f}" if c.get("cvssV3Score") is not None else "?"
            lines.append(
                f"  {c['cveId']}  CVSS={score}  ({c.get('cvssV3Severity') or '?'}){kev_marker}"
            )
        lines.append("")

    if kev:
        lines.append(f"[bold red]CISA KEV ({len(kev)} actively exploited)[/bold red]")
        ransomware = sum(1 for k in kev if (k.get("knownRansomwareUse") or "").lower() == "known")
        if ransomware:
            lines.append(f"  [red]⚠ {ransomware} with known ransomware use[/red]")
        for k in kev[:5]:
            lines.append(
                f"  {k['cveId']}  {k.get('vendorProject') or '?'} / {k.get('product') or '?'}"
            )

    return "\n".join(lines)


class CrossviewTUI(App):
    CSS = """
    Tree { width: 50; }
    #search { dock: top; height: 3; }
    #detail { padding: 1 2; }
    """

    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit"),
        Binding("/", "focus_search", "Search"),
        Binding("escape", "focus_tree", "Tree"),
    ]

    TITLE = "crossview"

    def compose(self) -> ComposeResult:
        yield Header()
        yield Input(placeholder="Search... (CWE-89, prompt injection, T1059, AML.T0051)", id="search")
        with Horizontal():
            tree: Tree[dict] = Tree("MITRE Knowledge Silo", id="tree")
            tree.show_root = False
            for source, subtype, label in TREE_BRANCHES:
                tree.root.add(label, data={"source": source, "subtype": subtype, "kind": "branch"})
            yield tree
            with Vertical():
                yield Static("Select an entity in the tree, or type a query and press Enter.", id="detail")
        yield Footer()

    def on_mount(self) -> None:
        tree = self.query_one("#tree", Tree)
        tree.focus()

    def on_tree_node_expanded(self, event: Tree.NodeExpanded[dict]) -> None:
        data = event.node.data or {}
        if data.get("kind") != "branch":
            return
        # Lazy-load entities under this branch on first expand
        if event.node.children:
            return
        entities = _gql_entities_by_source(data["source"], data["subtype"], limit=300)
        for e in entities:
            label = f"{e['id']}  {e['name'][:60]}"
            event.node.add_leaf(label, data={"id": e["id"], "kind": "entity"})

    def on_tree_node_selected(self, event: Tree.NodeSelected[dict]) -> None:
        data = event.node.data or {}
        if data.get("kind") != "entity":
            return
        self._show_entity(data["id"])

    def on_input_submitted(self, event: Input.Submitted) -> None:
        query = event.value.strip()
        if not query:
            return
        # If the query looks like an entity ID, jump straight to it.
        if any(query.startswith(p) for p in ("CWE-", "CAPEC-", "T", "AML.T", "D3F:", "UKC-")):
            entity = _gql_entity(query)
            if entity:
                self._show_entity(query)
                return
        # Otherwise full-text search
        hits = _gql_search(query, limit=30)
        if not hits:
            self.query_one("#detail", Static).update(
                f"[dim]No matches for {query!r}.[/dim]"
            )
            return
        out = ["[bold]Search results[/bold]\n"]
        for h in hits:
            out.append(f"  [cyan]{h['id']}[/cyan]  ({h['source']})  {h['name']}")
        self.query_one("#detail", Static).update("\n".join(out))

    def _show_entity(self, eid: str) -> None:
        entity = _gql_entity(eid)
        if not entity:
            self.query_one("#detail", Static).update(f"[red]No entity {eid!r}[/red]")
            return
        chain = _gql_chain(eid) if eid.startswith("CWE-") else None
        cves = _gql_cves(eid) if eid.startswith("CWE-") else []
        kev = _gql_kev(eid) if eid.startswith("CWE-") else []
        self.query_one("#detail", Static).update(_format_detail(entity, chain, cves, kev))

    def action_focus_search(self) -> None:
        self.query_one("#search", Input).focus()

    def action_focus_tree(self) -> None:
        self.query_one("#tree", Tree).focus()


def run_tui() -> None:
    CrossviewTUI().run()
