# 11 · AI Skill Guide

Crossview ships as a Claude Code **skill** (and plugin) so an AI agent can drive it directly. This guide is for two audiences: people configuring the skill, and agents (or prompt authors) deciding *when* and *how* to invoke it.

The skill definition lives at `.claude-plugin/skills/crossview/SKILL.md`; the plugin manifest is `.claude-plugin/plugin.json`.

---

## What the skill is

A thin, declarative wrapper that tells an agent:

- **what Crossview is** — a MITRE knowledge silo + 5-stage code scanner;
- **when to reach for it** vs. when not to;
- **the command surface** to call (the same `crossview` CLI documented in the [CLI Reference](04-cli-reference.md)).

The agent does the work by invoking the CLI; the skill is the discipline for using it correctly. There is no separate API — the skill *is* the CLI plus guidance.

## Installing the skill / plugin

The plugin manifest (`.claude-plugin/plugin.json`) registers the skill under `skills/crossview`. In a Claude Code environment that loads this repo's plugins, the skill becomes invokable as `crossview`. The agent must also be able to run the `crossview` CLI — i.e. the package is installed (`make install` or `nix develop`) and the silo is built (`crossview update`).

---

## When an agent should invoke Crossview

**Invoke it when the task is:**

- Looking up a CWE / CAPEC / ATT&CK / ATLAS / D3FEND / UKC entity by ID or name.
- Asking whether a weakness is actively exploited, or which CVEs apply to it.
- Scanning a codebase for vulnerabilities with cross-source enrichment.
- Reasoning about LLM-specific threats (prompt injection, jailbreaks) where ATLAS context helps.
- Producing a security report (Markdown / SARIF / STIX) for a project.

**Do not invoke it for:**

- General architecture or non-security code review — Crossview is security-specific.
- Exploratory web research not anchored to an entity ID — its `research` command is a *targeted* per-entity cache, not a crawler.

This mirrors the "When to use / When NOT to use" section in `SKILL.md` — keep the two in sync if you edit either.

---

## Playbooks for agents

These are the high-value command sequences. Prefer **knowledge queries** (no setup, fast, deterministic) before anything that scans or hits the network.

### "Tell me about CWE-89"

```bash
crossview show CWE-89          # entity + cross-references
crossview enrich CWE-89        # live CVEs + CISA KEV intersection
```

### "Is this actively exploited?"

```bash
crossview enrich CWE-78        # non-empty KEV intersection = exploited in the wild
```

### "Scan this codebase"

```bash
crossview scan /abs/path/to/project
# reads CROSSVIEW-REPORT.md / .sarif / .stix.json from the project root afterwards
```

For production-only exploit ranking, follow with `crossview triage /abs/path`.

### "What ATT&CK technique does this attack pattern map to?"

```bash
crossview show CAPEC-66        # read the outbound 'related' xrefs → T-IDs
```

### "Show me LLM prompt injection (ATLAS)"

```bash
crossview show AML.T0051
crossview research AML.T0051   # distill the MITRE page into JSON if needed
```

### Structured output for downstream reasoning

When the agent needs machine-readable results rather than rendered tables, use GraphQL:

```bash
crossview graphql '{ exploitChain(cweId: "CWE-89") {
  capecs attackTechniques atlasTechniques d3fendTechniques ukcPhases } }'
```

The JSON result is ideal for an agent to parse and reason over. See the [API Guide](05-api-guide.md).

---

## Gotchas an agent must know

- **`scan` is path-sensitive.** Always pass an absolute path (or `cd` first). Survey and verify re-read files relative to that path.
- **Statuses are idempotent.** Re-running `verify` resets and re-classifies; re-running `investigate` rewrites that project's evidence/validation rows. Safe to repeat; don't assume append-only.
- **Optional tools degrade gracefully.** If TruffleHog / Trivy / Hadolint / OSV-Scanner aren't installed, those sub-stages skip with a log line — the agent should not treat their absence as failure.
- **Semgrep config can fail a run.** A bad rule pattern yields rc=7 + empty SARIF; the fix is trimming `rules/presets.yaml`, not retrying verbatim.
- **`crossview research` ≠ web search.** It caches one known entity's MITRE page. For exploratory research, the agent should use a different tool.
- **Silo must exist.** If queries error out, the agent should run `crossview update` (and, for exploitation signal, `crossview enrich --enricher cisa_kev`) first.

---

## Composition with other skills

- **Targeted vs. exploratory research.** Crossview's `research` is per-entity caching. Pair it with a general research/crawl skill for breadth, then feed specific entity IDs back into Crossview for depth.
- **Reporting.** Crossview emits SARIF/STIX/VEX; hand those to a CI code-scanning view or a threat-intel platform rather than re-deriving them.
- **Knowledge graphs.** The GraphQL `exploitChain` output (CWE→CAPEC→ATT&CK→ATLAS→D3FEND→UKC) maps cleanly onto a node/edge visualizer if the agent is building a graph artifact.

---

## Keeping the skill accurate

The skill's command tables must track the real CLI. After changing commands or flags, update **both**:

- `.claude-plugin/skills/crossview/SKILL.md` (the agent-facing surface)
- the [CLI Reference](04-cli-reference.md) (the human-facing surface)

A quick consistency check: `crossview --help` should list exactly the commands the skill mentions. The plugin's `tags` and `description` in `plugin.json` should likewise reflect the current source/scanner coverage.
