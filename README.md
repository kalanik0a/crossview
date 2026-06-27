# Crossview

**Cross-referenced MITRE security knowledge silo + a 5-stage code scanner.**

Crossview fuses the canonical MITRE taxonomy — CAPEC, CWE, ATT&CK (Enterprise / Mobile / ICS), ATLAS, D3FEND, and the Unified Kill Chain — into a single navigable graph, then walks real codebase findings through that graph to produce enriched, exploit-prioritized security reports. It is SecGuru's big brother: where SecGuru reviews docs, Crossview scans live code against the full MITRE graph and intersects findings with actively-exploited CVEs (NVD + CISA KEV).

Everything is local. Three SQLite databases, one `crossview` CLI, an optional in-process GraphQL surface, and a Textual TUI.

> **Full documentation lives in [docs/](docs/README.md)** — intro, installation, user guide, CLI reference, API guide, architecture, scanner pipeline, data model, rules & presets, enrichment, the AI skill guide, the [Intel Mindmeld](docs/12-intel-mindmeld.md), and a worked [Case Study](docs/13-case-study.md) that takes a real vulnerable app from anonymous HTTP to RCE.
>
> See it in action: a ~70 s cinematic case-study video (in the internal media library, `~/Videos/visionlighter/crossview/case-study/`) and the full [engagement workspace](examples/vulpy-engagement/README.md) (notes, intel, PoC, report).

![Crossview case study — the exploit chain executing](examples/vulpy-engagement/assets/flow-graph.gif)

---

## What's inside

| Layer | Description |
|---|---|
| **Reference silo** | Canonical MITRE entities (CAPEC, CWE, ATT&CK ×3, ATLAS, D3FEND) plus cross-references, full-text searchable. |
| **Enrichment** | NVD CVEs + CISA KEV intersection per CWE, single-CVE → CWE → CPE lookups, and a `crawl4ai` per-entity web-research cache. |
| **Scanner** | A 5-stage SAST pipeline: survey → prematch → investigate → verify → report. Wraps Bandit, Semgrep (with custom ATLAS/LLM rules), detect-secrets, and — when installed — TruffleHog, Trivy, Hadolint, and OSV-Scanner. |
| **Graph** | A code-first GraphQL schema (Strawberry) over the reference silo + per-project cohort data. |
| **TUI** | A Textual app: tree views, search, and a detail panel for exploring the silo interactively. |
| **Reports** | `CROSSVIEW-REPORT.md`, a client-grade **HTML + PDF** report, OASIS **SARIF**, MITRE **STIX**, and CycloneDX **VEX** outputs. |

### Data sources

Downloaded and rebuilt by `crossview update`:

- **CAPEC** — STIX 2.1
- **CWE** — full XML (all views, incl. view 1000)
- **ATT&CK** — Enterprise, Mobile, and ICS (STIX 2.0)
- **D3FEND** — full mappings + ontology (JSON-LD)
- **ATLAS** — adversarial AI/ML techniques (STIX)
- **NVD / CISA KEV** — pulled on demand by the enrichment engine

### The three databases

| DB | Default path | Lifecycle |
|---|---|---|
| Reference (canonical MITRE) | `<data-dir>/crossview.db` | Rebuildable via `crossview update` |
| Enrichment (CVEs, KEV, web cache) | `<data-dir>/enrichment.db` | Mutable cache; rebuild with `crossview enrich --enricher cve_nvd_bulk --force` |
| Cohort (per-project investigation) | `<project>/.crossview/cohort.db` | Per project, never auto-deleted |

`<data-dir>` resolves portably:

1. `$CROSSVIEW_DATA_DIR` if set;
2. else `<repo>/data/` when running from a source checkout (writable repo with `pyproject.toml`);
3. else `$XDG_DATA_HOME/crossview` (fallback `~/.local/share/crossview`) for installed packages — so a read-only nix-store install still has a writable place to build the silo.

---

## Install

### With Nix (recommended on NixOS)

The flake provides the `crossview` CLI on `PATH` and a dev shell with all native build deps (tree-sitter C extensions, etc.):

```bash
nix develop          # drop into a shell with crossview available
# or run directly:
nix run .# -- --help
```

### With a venv

```bash
make install          # python3 -m venv .venv && pip install -e ".[dev]"
# crossview lands at .venv/bin/crossview
```

> **Note:** `crossview graphql` requires `strawberry-graphql`, which is imported by the
> graph layer but not yet pinned in `pyproject.toml`. Install it (`pip install strawberry-graphql`)
> if you intend to use the GraphQL command.

### Submodules (Semgrep rule packs)

Crossview vendors external Semgrep rule packs as git submodules under `rules/external/`:

```bash
git submodule update --init --recursive
```

This pulls [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules),
[elttam/semgrep-rules](https://github.com/elttam/semgrep-rules), and
[trailofbits/semgrep-rules](https://github.com/trailofbits/semgrep-rules). Custom
ATLAS/LLM rules (prompt injection, system-prompt leak, tool-use validation, output
rendering) live under `rules/custom/`. Preset composition is driven by `rules/presets.yaml`.

### Build the silo

```bash
crossview update      # download all MITRE sources and (re)build crossview.db
```

---

## Quickstart

```bash
# Look up any entity and its cross-references
crossview show CWE-89          # also: CAPEC-66, T1059, AML.T0051, D3F:Token_Binding, UKC-7

# Full-text search the whole silo
crossview search "sql injection"

# What's actively exploited that maps to this weakness? (NVD ∩ CISA KEV)
crossview enrich CWE-78

# Scan a codebase end-to-end → CROSSVIEW-REPORT.md (+ .sarif + .stix.json)
crossview scan /path/to/project

# Explore interactively
crossview tui
```

---

## CLI reference

### Knowledge queries (no setup needed once the silo is built)

| Command | What it does |
|---|---|
| `crossview show <id>` | Show one entity + all its xrefs |
| `crossview search "<query>"` | Full-text search the silo |
| `crossview enrich <CWE-ID>` | Active CVEs for a CWE (NVD + KEV intersect) |
| `crossview cve <CVE-ID>` | One CVE + its CWEs + affected CPEs |
| `crossview research <id>` | Web-research one entity (crawl4ai), cached |

### The 5-stage scan pipeline

| Stage | Command | What it does |
|---|---|---|
| Full pipeline | `crossview scan <path>` | Runs all five stages back to back |
| 1. Survey | `crossview survey <path>` | Enumerate entrypoints + sinks → `<project>/.crossview/cohort.db` |
| 2a. Code SAST | `crossview prematch <path>` | Bandit + Semgrep (ATLAS rules), SARIF-normalized |
| 2b. Secrets | `crossview prematch-secrets <path>` | detect-secrets (+ trufflehog/gitleaks if installed) |
| 2c. IaC + container | `crossview prematch-iac <path>` | Trivy + Hadolint (graceful skip if missing) |
| 2d. Dependency CVEs | `crossview prematch-deps <path>` | OSV-Scanner, auto-joined to enrichment.db |
| 3. Investigate | `crossview investigate <path>` | Walk CWE → CAPEC → ATT&CK → D3FEND → UKC; score priority |
| 4. Verify | `crossview verify <path>` | Re-survey live code; confirmed / partial / rejected |
| 5. Report | `crossview report <path>` | Emit `CROSSVIEW-REPORT.md`, `CROSSVIEW.sarif`, `CROSSVIEW.stix.json` |
| Triage | `crossview triage <path>` | Production-only exploit triage: filter confirmed findings by file-path class, re-run TruffleHog with live verification, emit a ranked report |

`crossview scan` flags: `--out <dir>`, `--skip-semgrep`, `--web-research/-W <N>`
(crawl4ai for top N high-priority CWEs), `--stop-after survey|prematch|investigate|verify`.

### Graph + TUI

| Command | What it does |
|---|---|
| `crossview graphql "<query>"` | Run a GraphQL query in-process against the unified schema |
| `crossview tui` | Launch the Textual TUI (tree views + search + detail panel) |

### Internal data tooling — `crossview dev <subcommand>`

For inspecting the silo itself: `verify-urls`, `stats`, `validate`, `sql "<query>"`,
`xref <id>`, `orphans`, and `inspect` / `schema` / `sample` for peeking at raw
downloaded JSON.

---

## Makefile shortcuts

```bash
make install          # venv + editable install with dev extras
make update           # rebuild the MITRE silo
make tui              # launch the TUI
make scan PATH_=<dir> # scan a project
make test             # pytest
make lint / make fmt  # ruff
make dev-stats        # DB row counts
make dev-sql QUERY='SELECT ...'
```

---

## Reports & formats

A full scan writes, alongside the human-readable `CROSSVIEW-REPORT.md`:

- **HTML + PDF** (`CROSSVIEW-REPORT.html` / `.pdf`) — a branded, client-grade report (severity badges, the MITRE cross-reference chain, KEV signal, D3FEND mitigations). HTML is always produced (pure Jinja2); PDF when a renderer is available (`pip install crossview[pdf]` for WeasyPrint, or any Playwright Chromium).
- **SARIF** (`CROSSVIEW.sarif`) — OASIS Static Analysis Results Interchange Format, for CI/IDE ingestion.
- **STIX** (`CROSSVIEW.stix.json`) — for threat-intel pipelines.
- **CycloneDX VEX** — vulnerability exploitability exchange for dependency findings.

---

## Gotchas

- **`scan` runs in cwd** — `cd` into the project first, or pass an absolute path.
- **Semgrep parse errors** — a rule pack with a bad pattern can make a run return `rc=7` with empty results. Trim configs in `rules/presets.yaml`, or pin a known-good submodule SHA. (`tsx` is not a Semgrep language — use `typescript` in custom rules.)
- **Idempotent statuses** — re-running `verify` resets and re-classifies; re-running `investigate` wipes and rewrites evidence/validation for that project.
- **Bandit SARIF** — the pinned Bandit doesn't emit SARIF natively; Crossview parses its JSON. Don't pass `--format sarif` to Bandit.
- **Optional scanners** — TruffleHog, Gitleaks, Trivy, Hadolint, and OSV-Scanner each add material coverage and are skipped gracefully when absent. Install them when convenient.

---

## Project layout

```text
crossview/
├── cli.py                 # Typer CLI — every command lives here
├── data/                  # downloader, loader, normalizers, sources, DB + cohort
├── enrichment/            # NVD / CISA KEV / web-research enrichers + orchestrator
├── scanner/               # survey → prematch{code,secrets,iac,deps} → investigate → verify → report → triage
├── harness/               # language harnesses (python, typescript) for live re-survey
├── graph/                 # Strawberry GraphQL schema, types, resolvers
├── tui/                   # Textual TUI app
└── dev/                   # internal data tooling (inspect, schema, sample, url-check)
rules/                     # bandit.yaml, presets.yaml, custom/ (ATLAS-LLM), external/ (submodules)
```

---

## License

Internal-only.
