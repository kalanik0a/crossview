---
name: crossview
description: Cross-referenced MITRE security knowledge silo (CAPEC, CWE, ATT&CK, ATLAS, D3FEND, UKC, NVD CVEs, CISA KEV) plus a 5-stage code scanner. Use whenever you need to query canonical MITRE entities, look up actively-exploited CVEs by CWE, or perform structured vulnerability analysis on a code project.
---

# Crossview

A tool that fuses the MITRE knowledge graph with a code scanner. Three SQLite databases under the hood, one CLI surface.

## When to use

- The user asks about a CWE, CAPEC, ATT&CK technique, ATLAS technique, or D3FEND mitigation by ID or name.
- The user asks "is X vulnerability actively exploited?" or "what CVEs apply to Y?"
- The user wants to scan a codebase for vulnerabilities with cross-source enrichment.
- The user mentions prompt injection, jailbreaks, or other LLM-specific threats and you need ATLAS context.
- The user wants to produce a security report (markdown / SARIF / STIX) on a project.

## When NOT to use

- General questions about software architecture or non-security code review — Crossview is security-specific.
- Web research that isn't anchored to a specific entity ID — use the `hoover-maneuver` skill instead. Crossview's `web_research` enricher is for *targeted* per-entity caching, not exploratory.

## CLI surface

The tool is callable via `crossview` (installed at `.venv/bin/crossview` within the project root).

### Knowledge queries (always work, no setup needed)

| What you want | Command |
|---|---|
| Show one entity + all its xrefs | `crossview show <id>` (e.g. `CWE-89`, `CAPEC-66`, `T1059`, `AML.T0051`, `D3F:Token_Binding`, `UKC-7`) |
| Full-text search the silo | `crossview search "<query>"` |
| Active CVEs for a CWE (NVD + KEV intersect) | `crossview enrich <CWE-ID>` |
| One CVE + its CWEs + affected CPEs | `crossview cve <CVE-ID>` |
| Web-research one entity (crawl4ai) | `crossview research <id>` |

### Scanning a project (the 5-stage pipeline)

| Stage | Command | What it does |
|---|---|---|
| Full pipeline | `crossview scan <path>` | Runs all five stages back to back |
| 1. Survey | `crossview survey <path>` | Enumerate entrypoints + sinks, persist to `<project>/.crossview/cohort.db` |
| 2a. Code SAST | `crossview prematch <path>` | Bandit + Semgrep with ATLAS rules; SARIF-normalized |
| 2b. Secrets | `crossview prematch-secrets <path>` | detect-secrets (+ trufflehog/gitleaks if installed) |
| 2c. IaC + container | `crossview prematch-iac <path>` | Trivy + Hadolint (graceful skip if missing) |
| 2d. Dep CVEs | `crossview prematch-deps <path>` | OSV-Scanner, auto-joined to NVD enrichment.db |
| 3. Investigate | `crossview investigate <path>` | Walk CWE → CAPEC → ATT&CK → D3FEND → UKC; score priority |
| 4. Verify | `crossview verify <path>` | Re-survey live code; confirmed / partial / rejected |
| 5. Report | `crossview report <path>` | Emit `CROSSVIEW-REPORT.md`, `CROSSVIEW.sarif`, `CROSSVIEW.stix.json` |
| Triage | `crossview triage <path>` | Production-only exploit triage: filter confirmed findings by file-path class, re-run TruffleHog with live verification (`--no-verify-secrets` to skip), emit a ranked report (`--out`) |

`crossview scan` also accepts `--out <dir>`, `--skip-semgrep`, `--web-research/-W <N>` (crawl4ai for top N high-priority CWEs), and `--stop-after survey|prematch|investigate|verify`.

### Graph + TUI

| What you want | Command |
|---|---|
| Run a GraphQL query against the unified schema (in-process) | `crossview graphql "<query>"` |
| Launch the interactive Textual explorer (trees + search + detail) | `crossview tui` |

> `crossview graphql` needs `strawberry-graphql`, which the graph layer imports but `pyproject.toml` does not yet pin — `pip install strawberry-graphql` if it's missing.

### Intel reports (Intellio mindmeld)

`crossview intel <subcommand>` — persist LLM-authored intelligence reports (Intellio's threat-intel / vulnerability / tool / engineering shapes) as grounded, cross-referenced nodes in the silo. See [docs/12-intel-mindmeld.md](../../../docs/12-intel-mindmeld.md).

| What you want | Command |
|---|---|
| Generate a grounded report in-process (Gemini; needs `GEMINI_API_KEY`) | `crossview intel generate "<subject>"` |
| Ingest + ground an existing Intellio report JSON | `crossview intel ingest <file>` |
| List stored reports + grounding coverage | `crossview intel list` |
| Show a report + its cross-references | `crossview intel show <subject>` |
| Which intel reports cite a canonical entity? | `crossview intel citing <ID>` (e.g. `T1486`, `CWE-89`) |

### Internal data tooling

`crossview dev <subcommand>` — for inspecting the silo itself:
- `dev verify-urls` — HEAD-check every MITRE source URL
- `dev stats` — entity + xref counts
- `dev validate` — integrity checks
- `dev sql "<query>"` — raw read-only SQL against `crossview.db`
- `dev xref <id>` — trace one-hop cross-references
- `dev orphans` — entities with zero xrefs
- `dev inspect <file>` / `dev schema <file>` / `dev sample <file>` — peek at raw downloaded JSON

## Three databases

| DB | Default path | Lifecycle |
|---|---|---|
| Reference (canonical MITRE) | `<data-dir>/crossview.db` | Rebuildable via `crossview update` |
| Enrichment (CVEs, KEV, web research cache) | `<data-dir>/enrichment.db` | Mutable, cache; rebuild with `crossview enrich --enricher cve_nvd_bulk --force` |
| Cohort (per-project investigation) | `<project>/.crossview/cohort.db` | Per project, never auto-deleted |

`<data-dir>` resolves portably: `$CROSSVIEW_DATA_DIR` if set → else `<repo>/data/` from a writable source checkout → else `$XDG_DATA_HOME/crossview` (`~/.local/share/crossview`) for read-only installs (e.g. nix store).

## Typical workflows

### "Tell me about CWE-89"
```
crossview show CWE-89
crossview enrich CWE-89   # gets active KEV + ranked NVD CVEs
```

### "Scan this codebase"
```
crossview scan /path/to/project
# Outputs land at /path/to/project/CROSSVIEW-REPORT.md (+ .sarif + .stix.json)
```

### "What's actively being exploited that maps to CWE-78?"
```
crossview enrich CWE-78
```

### "What ATT&CK technique is this CAPEC tied to?"
```
crossview show CAPEC-66
# Look at outbound xrefs with relation=related → T-IDs are listed
```

### "Show me LLM prompt injection (ATLAS)"
```
crossview show AML.T0051
crossview research AML.T0051   # if you want the MITRE page distilled into JSON
```

## Composition with hoover-maneuver

Crossview's `research` command does *targeted* per-entity caching — it fetches the canonical MITRE page for a known entity ID. For *exploratory* multi-URL research ("find me everything about prompt injection in production AI systems"), use the `hoover-maneuver` skill instead. They serve different needs.

## Important gotchas

- **`scan` runs in cwd**: cd into the project first, or pass an absolute path.
- **Stage 2a Semgrep config issues**: if a rule pack has a parse error, the run can return rc=7 with empty results. Trim configs in `rules/presets.yaml` if this happens.
- **`tsx` not a semgrep language**: use `typescript` in custom rules.
- **Scanner-finding statuses are idempotent**: re-running `verify` resets and re-classifies; re-running `investigate` wipes and re-writes evidence/validation rows for that project.
- **bandit doesn't ship SARIF natively** in our pinned version — we parse its JSON output. Don't be surprised if `--format sarif` to bandit fails.
- **TruffleHog / Gitleaks / Trivy / Hadolint / OSV-Scanner are optional** but each adds material coverage. Install them when convenient.
