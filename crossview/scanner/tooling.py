"""Portable resolution of external CLI tools.

Works the same across editable venvs, read-only nix-store installs, pipx, and
system installs. Resolution order:

  1. A console script sitting next to the *running* interpreter
     (``sys.executable``). This is where ``bandit`` / ``semgrep`` land in a
     venv or a nix python env even when crossview was invoked by absolute path
     and that bin dir is not on ``PATH``.
  2. Anywhere on ``PATH`` (``shutil.which``).
  3. The bare name — so ``subprocess`` raises a clear ``FileNotFoundError``
     that callers already handle.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path


def resolve_tool(name: str) -> str:
    """Return the best path to the CLI ``name`` for the current environment."""
    candidate = Path(sys.executable).parent / name
    if candidate.exists():
        return str(candidate)
    on_path = shutil.which(name)
    if on_path:
        return on_path
    return name
