# 09 · Rules & Presets

How Crossview decides *which* SAST rules to run against *which* code. The system has three parts: vendored Semgrep rule packs (git submodules), in-tree custom rules (the ATLAS/LLM pack and a Bandit profile), and a preset map that composes them by detected language and framework.

```text
rules/
├── presets.yaml              # the composition map
├── bandit.yaml               # Bandit plugin profile
├── custom/
│   ├── atlas-llm/            # in-tree ATLAS/LLM Semgrep rules
│   │   ├── prompt-injection.yaml
│   │   ├── system-prompt-leak.yaml
│   │   ├── tool-use-validation.yaml
│   │   └── output-rendering.yaml
│   └── crossview-conventions/
└── external/                 # git submodules
    ├── semgrep-rules/        # semgrep/semgrep-rules
    ├── elttam-rules/         # elttam/semgrep-rules
    └── trailofbits-rules/    # trailofbits/semgrep-rules
```

Pull the submodules before scanning: `git submodule update --init --recursive`.

---

## Preset composition (`rules/presets.yaml`)

A **preset** is a named bundle of rule sources. `scanner/preset_selector.select(languages, frameworks)` reads the languages/frameworks that Stage 1 (survey) detected and assembles the active Semgrep configs and Bandit profile. The composition logic:

```text
per language          → include {lang}_base            (python_base, typescript_base)
per detected framework → include the matching preset    (python_fastapi, react, …)
if an LLM SDK detected → include 'llm'                   (the ATLAS pack)
cross-cutting          → secrets, iac_container (if Dockerfile), deps
```

### Available presets

| Preset | Sources |
|---|---|
| `python_base` | `semgrep-rules/python`, `trailofbits-rules/python`, Bandit (`rules/bandit.yaml`) |
| `python_fastapi` / `python_flask` / `python_django` | currently empty — subsumed by `python_base` |
| `typescript_base` | `semgrep-rules/typescript`, `semgrep-rules/javascript` |
| `react` / `nextjs` | currently empty — subsumed by `typescript_base` |
| `llm` | `rules/custom/atlas-llm` — activates when anthropic/openai/langchain/llama_index calls are detected |
| `secrets` | trufflehog, gitleaks, detect-secrets |
| `iac_container` | trivy, hadolint |
| `deps` | osv-scanner |

> **Why the framework presets are empty.** Framework-specific subdirectories (e.g. `python/fastapi`, `javascript/react`) and the full elttam pack contain rules whose patterns the pinned Semgrep version rejects, and a single bad pattern contaminates a combined run (rc=7, empty SARIF). The base packs are the proven, parse-clean subset. Re-enable the framework subdirs once the upstream parse issue is fixed or by pinning a known-good submodule SHA — just add the paths back to the matching preset.

---

## The ATLAS / LLM pack (`rules/custom/atlas-llm/`)

The headline custom contribution: Semgrep rules that flag AI/ML-specific weaknesses, each tagged with both a **CWE** and a **MITRE ATLAS technique** so findings thread straight into the investigate stage's graph walk.

| File | Catches |
|---|---|
| `prompt-injection.yaml` | Untrusted input flowing into an LLM call (`AML.T0051`, `CWE-1426`) |
| `system-prompt-leak.yaml` | Patterns that can exfiltrate the system prompt |
| `tool-use-validation.yaml` | Unvalidated tool/function-call arguments from model output |
| `output-rendering.yaml` | Unsafe rendering of model output (insecure output handling) |

Each rule carries `metadata.cwe` and `metadata.atlas`, which `sarif_ingest.parse_sarif()` extracts into the finding's `cwe_ids`. Example (abridged):

```yaml
rules:
  - id: atlas-llm-prompt-injection-anthropic
    languages: [python]
    severity: WARNING
    message: |
      Untrusted input flows directly into an Anthropic LLM messages.create() call.
      MITRE ATLAS classifies this as AML.T0051 (LLM Prompt Injection)…
    metadata:
      cwe:  ["CWE-1426"]
      atlas: ["AML.T0051"]
    pattern-either:
      - pattern: $CLIENT.messages.create(...)
      - pattern: await $CLIENT.messages.create(...)
```

This is what lets Crossview turn "an LLM call on untrusted input" into a finding that links to `AML.T0051`, walks to related ATT&CK/D3FEND, and shows up in triage's `atlas_llm` bucket.

---

## The Bandit profile (`rules/bandit.yaml`)

Bandit runs with **all** default plugins enabled (B101–B703) — the philosophy is to over-detect at Stage 2 and let the hypothesis lifecycle in `cohort.db` cull false positives (set a hypothesis `status='rejected'` with a note). It also excludes the usual non-source directories (`.venv`, `node_modules`, `build`, `migrations`, `alembic/versions`, …).

---

## Authoring your own rules

### Add a custom Semgrep rule

1. Drop a `.yaml` under `rules/custom/<your-pack>/`.
2. Tag it with `metadata.cwe` (and `metadata.atlas` if applicable) so the finding anchors to the graph.
3. Reference the pack from a preset in `presets.yaml` (e.g. add `rules/custom/<your-pack>` to `python_base.semgrep` or a new preset).

### Re-enable a vendored framework pack

Add the submodule subdirectory back to the relevant preset's `semgrep` list. First confirm it parses cleanly with your Semgrep version:

```bash
semgrep --validate --config rules/external/semgrep-rules/python/fastapi
```

### Gotchas

- **`tsx` is not a Semgrep language.** Use `typescript` in custom rules; `.tsx` files are covered by the `typescript`/`javascript` configs.
- **One bad pattern fails the whole run.** If a Semgrep run returns rc=7 with empty results, a config has a parse error — bisect by trimming entries in `presets.yaml`.
- **Bandit doesn't emit SARIF** in the pinned version — Crossview parses its JSON. Don't pass `--format sarif` to Bandit.
- External tools are resolved portably (`scanner/tooling.resolve_tool`), so Semgrep/Bandit are found whether you're in a venv, the nix store, or a system install.
