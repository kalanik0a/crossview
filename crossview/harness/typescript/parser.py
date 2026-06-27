"""ast-grep wrapper for TypeScript / TSX."""
from __future__ import annotations

from pathlib import Path

try:
    from ast_grep_py import SgRoot
except ImportError:
    SgRoot = None  # Graceful degradation — TS harness disabled without ast-grep

# File extension → ast-grep language label
LANG_FOR_EXT = {
    ".ts": "typescript",
    ".tsx": "tsx",
    ".js": "javascript",
    ".jsx": "tsx",  # ast-grep treats jsx as tsx
    ".mjs": "javascript",
    ".cjs": "javascript",
}


def detect_lang(file: Path) -> str | None:
    return LANG_FOR_EXT.get(file.suffix.lower())


def parse(source: str, lang: str) -> SgRoot | None:
    if SgRoot is None:
        return None
    return SgRoot(source, lang)
