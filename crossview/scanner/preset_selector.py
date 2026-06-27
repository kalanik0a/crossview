"""Choose Semgrep + Bandit configs based on detected languages and frameworks.

Reads rules/presets.yaml as the single source of truth for which rule packs
attach to which (language × framework × signal) tuples.
"""
from __future__ import annotations

import yaml
from pathlib import Path

# Located at repo root; presets.yaml is canonical
PRESETS_FILE = Path(__file__).resolve().parents[2] / "rules" / "presets.yaml"


def load_presets() -> dict:
    if not PRESETS_FILE.exists():
        return {"presets": {}}
    return yaml.safe_load(PRESETS_FILE.read_text()) or {"presets": {}}


def select(languages: set[str], frameworks: set[str]) -> dict[str, list[str]]:
    """Return {tool_name: [config_paths_or_ids]} for the given context.

    tool_name is "semgrep" | "bandit" | "trufflehog" | "gitleaks" | ... so that
    each Stage 2 sub-stage only consumes its own keys.
    """
    cfg = load_presets()
    presets = cfg.get("presets", {})
    chosen: dict[str, list[str]] = {"semgrep": [], "bandit": []}

    def _add(preset_key: str) -> None:
        p = presets.get(preset_key)
        if not p:
            return
        for k in ("semgrep", "bandit"):
            if k in p:
                v = p[k]
                if isinstance(v, list):
                    chosen.setdefault(k, []).extend(v)
                elif isinstance(v, dict) and "config" in v:
                    chosen.setdefault(k, []).append(v["config"])

    if "python" in languages:
        _add("python_base")
        if "fastapi" in frameworks:
            _add("python_fastapi")
        if "flask" in frameworks:
            _add("python_flask")
        if "django" in frameworks:
            _add("python_django")

    if languages & {"typescript", "javascript", "tsx"}:
        _add("typescript_base")
        if "react" in frameworks:
            _add("react")
        if "nextjs" in frameworks:
            _add("nextjs")

    if frameworks & {"anthropic", "openai", "langchain", "llama_index"}:
        _add("llm")

    # De-dupe preserving order
    for k, vs in chosen.items():
        seen, out = set(), []
        for v in vs:
            if v in seen:
                continue
            seen.add(v)
            out.append(v)
        chosen[k] = out

    return chosen


def filter_existing_paths(configs: list[str], project_root: Path) -> list[str]:
    """Resolve config paths against the crossview repo, drop missing local paths,
    and (for v1) drop p/ registry shortcuts.

    Registry shortcuts pull from semgrep.dev which can fail with returncode 7
    when one preset is unavailable, killing the entire combined run. The local
    submodules cover the same content deterministically.
    """
    out: list[str] = []
    crossview_root = Path(__file__).resolve().parents[2]
    for cfg in configs:
        if cfg.startswith("p/"):
            # Skip registry shortcuts — local submodules subsume them.
            continue
        candidate = crossview_root / cfg
        if not candidate.exists():
            continue
        if candidate.is_file():
            out.append(str(candidate))
            continue
        # Directory: only include if it has YAML rules inside.
        if any(candidate.rglob("*.yaml")) or any(candidate.rglob("*.yml")):
            out.append(str(candidate))
    return out
