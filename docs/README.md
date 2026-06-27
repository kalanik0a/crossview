# Crossview Documentation

The complete guide set for Crossview — the cross-referenced MITRE knowledge silo and 5-stage code scanner. Start with the introduction, then jump to the guide that matches what you're doing.

## Guides

| # | Guide | Read it when you want to… |
|---|---|---|
| 01 | [Introduction](01-introduction.md) | Understand what Crossview is, the mental model, and why it exists |
| 02 | [Installation & Setup](02-installation.md) | Install via Nix or venv, pull submodules, build the silo, set the data dir |
| 03 | [User Guide](03-user-guide.md) | Do real work: query the silo, scan a project, read the reports |
| 04 | [CLI Reference](04-cli-reference.md) | Look up every command, argument, and flag |
| 05 | [API Guide](05-api-guide.md) | Drive Crossview programmatically — GraphQL + the Python API |
| 06 | [Architecture](06-architecture.md) | See how the three databases and the pipeline fit together |
| 07 | [Scanner Pipeline](07-scanner-pipeline.md) | Understand each of the five scan stages in depth |
| 08 | [Data Model](08-data-model.md) | Reference the table schemas of all three databases |
| 09 | [Rules & Presets](09-rules-and-presets.md) | Manage Semgrep packs, custom ATLAS rules, and preset selection |
| 10 | [Enrichment](10-enrichment.md) | Pull live CVE / CISA KEV / web-research context |
| 11 | [AI Skill Guide](11-ai-skill-guide.md) | Use Crossview from an AI agent (the `crossview` Claude skill) |
| 12 | [Intel Mindmeld](12-intel-mindmeld.md) | Fuse Intellio's LLM reports into the silo as grounded, cross-referenced nodes |
| 13 | [Case Study — vulpy](13-case-study.md) | A full engagement: scan a real vulnerable app → find an exploit chain → report + video |
| 14 | [Vision](14-vision.md) | The roadmap — lenses on one spine, report-per-use-case, `serve`, and the console |
| 15 | [UI Screens](15-ui-screens.md) | A gallery of the current interactive surfaces — TUI, web (serve), and reports |

## The 30-second version

Crossview fuses the canonical MITRE taxonomy — **CWE, CAPEC, ATT&CK (Enterprise/Mobile/ICS), ATLAS, D3FEND, and the Unified Kill Chain** — into one navigable graph (~3,700 entities), then walks real code findings through that graph and intersects them with actively-exploited CVEs (NVD + CISA KEV) to produce exploit-prioritized reports.

Two faces, one tool:

- **The silo** — a queryable, offline knowledge base of the MITRE graph.
- **The scanner** — a five-stage SAST pipeline (survey → prematch → investigate → verify → report) that anchors every finding to that graph.

```text
       ┌────────────────────── the silo ──────────────────────┐
       │  CWE ──targets──▶ CAPEC ──related──▶ ATT&CK / ATLAS   │
       │   │                                      │            │
       │   └──child_of──▶ CWE          D3FEND ──counters──┘     │
       │                                  │                     │
       │                                UKC phases              │
       └───────────────────────┬───────────────────────────────┘
                                │  the scanner walks findings through it
   survey ─▶ prematch ─▶ investigate ─▶ verify ─▶ report / triage
```

## Demo videos

Two fully tool-driven videos (Gemini music bed + OpenAI narration). The rendered
videos live in the **internal media library** (`~/Videos/visionlighter/crossview/`,
not committed); the docs preview them with the GIFs/posters here, and the build
scripts regenerate them on demand.

- **Product demo** — [docs/demo/](demo/README.md): a ~83 s narrated tour over the real screenshots. `python3 scripts/build_demo.py` → `…/product-demo/crossview-demo.mp4`.
- **Cinematic case study** — [vulpy engagement](13-case-study.md): a ~70 s animated walkthrough — code-scan beam, 15-finding matrix, exploit-chain flow graph, and a CISA-KEV ticker. `python3 examples/vulpy-engagement/assets/build_cinematic.py` → `…/case-study/case-study.mp4`.

![exploit chain executing](../examples/vulpy-engagement/assets/flow-graph.gif)

## Screenshots

The images in these guides live in [docs/assets/](assets/) and are **generated deterministically** from the real application — no hand-captured screenshots that drift. Regenerate them all with:

```bash
make screenshots                 # all surfaces
make screenshots SURFACES=cli    # just the terminal shots
```

The generator ([scripts/gen_screenshots.py](../scripts/gen_screenshots.py)) covers four surfaces: **cli** (real `crossview` output → SVG via Rich), **tui** (the Textual explorer, headless → SVG), and **web** (a temporary GraphiQL playground → PNG via Playwright). SVGs are the source of truth; PNGs are rasterized alongside for renderers that don't display SVG. It needs a built silo (`crossview update`); the web surface needs Playwright browsers (provided by Nix on NixOS — the script auto-discovers them).

## Conventions used in these docs

- `crossview <cmd>` is the installed CLI. In a source checkout without the console script, the equivalent is `python -c "from crossview.cli import app; app()" <cmd>`.
- `<data-dir>` is the resolved data directory — see [Installation](02-installation.md#data-directory).
- `<project>` is a codebase you are scanning; its per-scan state lives in `<project>/.crossview/cohort.db`.
