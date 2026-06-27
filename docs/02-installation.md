# 02 · Installation & Setup

Crossview targets **Python ≥ 3.11**. It bundles several optional external scanners; the core silo and the Python/Bandit/Semgrep scan path work without them, and missing tools are skipped gracefully.

## Option A — Nix (recommended on NixOS)

The flake provides the `crossview` CLI on `PATH`, the right Python, native build deps (the tree-sitter C extension needs a compiler), and every external scanner.

```bash
# Drop into a dev shell with crossview + all scanner tools available
nix develop

# …or run the CLI directly without entering a shell
nix run .# -- --help
```

The flake is **multi-platform** — it evaluates for `x86_64-linux`, `aarch64-linux`, `x86_64-darwin`, and `aarch64-darwin`. The dev shell puts `trufflehog`, `gitleaks`, `trivy`, `hadolint`, `osv-scanner`, and `semgrep` on `PATH`, plus `sqlite`, `jq`, and `git`.

> The shell sets `SEMGREP_SKIP_UPDATE=1` so Semgrep uses its Nix-managed binary instead of trying to self-update.

## Option B — Python venv

```bash
make install        # python3 -m venv .venv && pip install -e ".[dev]"
```

For **PDF report output**, also install the optional extra (HTML reports work without it):

```bash
pip install -e ".[pdf]"   # WeasyPrint; or rely on a Playwright Chromium
```

This creates `.venv/` and installs Crossview editable with its dev extras (`pytest`, `ruff`). The console script lands at `.venv/bin/crossview`.

Activate it, or call the binary by path:

```bash
source .venv/bin/activate     # then: crossview --help
# or
.venv/bin/crossview --help
```

> **Heads-up on copied/moved checkouts:** a venv's console scripts hardcode an absolute shebang to the interpreter. If you move or copy the repo, `.venv/bin/crossview` will point at the old path and fail with `bad interpreter`. Rebuild the venv (`make clean && make install`) or run via the interpreter: `python -c "from crossview.cli import app; app()" --help`.

## Submodules — Semgrep rule packs

Crossview vendors external Semgrep rules as git submodules under `rules/external/`. Pull them before scanning:

```bash
git submodule update --init --recursive
```

This fetches:

- [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules)
- [elttam/semgrep-rules](https://github.com/elttam/semgrep-rules)
- [trailofbits/semgrep-rules](https://github.com/trailofbits/semgrep-rules)

Custom ATLAS/LLM rules (prompt injection, system-prompt leak, tool-use validation, output rendering) live in-tree under `rules/custom/`. Preset composition is driven by `rules/presets.yaml` — see the [Rules & Presets guide](09-rules-and-presets.md).

## External scanners (optional but recommended)

Beyond Bandit + Semgrep (always available via the Python install), each of these adds material coverage and is skipped with a log line if absent:

| Tool | Stage | Adds |
|---|---|---|
| `trufflehog` | 2b secrets / triage | Live credential verification |
| `gitleaks` | 2b secrets | Git-history secret scanning |
| `trivy` | 2c IaC | CVE + IaC misconfig + SBOM |
| `hadolint` | 2c IaC | Dockerfile linting |
| `osv-scanner` | 2d deps | Lockfile → CVE matching |

The Nix dev shell provides all of them. With the venv path, install whichever you need via your OS package manager.

`crawl4ai` (web-research enrichment) and `tree-sitter` / `ast-grep` (harness parsing) install via pip from `pyproject.toml`. crawl4ai additionally needs a Playwright browser the first time:

```bash
python -m playwright install chromium
```

## Build the silo

Nothing queries until the reference DB exists. Download all MITRE sources and build it:

```bash
crossview update
```

Useful flags:

- `--only <key>` (repeatable) — refresh just some sources, e.g. `--only capec --only cwe`.
- `--force` — re-download even if a cached copy exists.
- `--skip-download` — rebuild the DB from already-cached raw files.

Verify it landed:

```bash
crossview dev stats        # entity + xref counts per source/subtype
crossview show CWE-89      # should print the entity and its xrefs
```

## Data directory

Crossview resolves `<data-dir>` **portably**, in this order:

1. `$CROSSVIEW_DATA_DIR` if set — explicit override, always wins.
2. `<repo>/data/` when running from a writable source checkout (detected by a `pyproject.toml` at the repo root).
3. `$XDG_DATA_HOME/crossview` (fallback `~/.local/share/crossview`) for installed packages — so a read-only install (e.g. the nix store) still has a writable place to build the silo.

Both `crossview.db` and `enrichment.db` live in `<data-dir>`; raw downloads go to `<data-dir>/raw/`. To pin a location regardless of how you installed:

```bash
export CROSSVIEW_DATA_DIR=/var/lib/crossview
crossview update
```

The per-project cohort DB is independent of `<data-dir>` — it always lives at `<project>/.crossview/cohort.db`.

## Enable enrichment (optional)

To intersect findings with real CVEs and CISA's exploited-in-the-wild catalog:

```bash
crossview enrich --enricher cisa_kev          # quick: pull the KEV catalog
crossview enrich CWE-89                        # on-demand CVEs for one CWE
```

A full NVD bulk import is large and resumable — see the [Enrichment guide](10-enrichment.md).

## Verify your install

```bash
crossview --help                                       # full command surface
crossview dev stats                                    # silo populated?
crossview show CWE-89                                  # xref walk works?
crossview graphql '{ entity(id: "CWE-89") { id name } }'   # GraphQL path works?
```

If `crossview graphql` raises `ModuleNotFoundError: strawberry`, your environment predates the `strawberry-graphql` dependency — reinstall (`pip install -e .` or `nix develop` again).

## Makefile shortcuts

```bash
make install            # venv + editable install (dev extras)
make update             # rebuild the MITRE silo
make tui                # launch the TUI
make scan PATH_=<dir>   # scan a project
make test               # pytest
make lint / make fmt    # ruff check / format
make dev-stats          # DB row counts
make dev-sql QUERY='SELECT ...'
```

Next: the [User Guide](03-user-guide.md).
