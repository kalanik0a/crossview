"""TypeScriptHarness — TS/JS/TSX file analysis."""
from __future__ import annotations

from pathlib import Path

from crossview.harness.base import FileMap
from crossview.harness.typescript.parser import LANG_FOR_EXT, detect_lang
from crossview.harness.typescript.routes import (
    find_express_hono_routes,
    find_next_entrypoints,
)
from crossview.harness.typescript.sinks import find_sinks


# Imports that signal a framework
FRAMEWORK_IMPORT_HINTS = {
    "next": "nextjs",
    "next/server": "nextjs",
    "express": "express",
    "hono": "hono",
    "fastify": "fastify",
    "@nestjs/common": "nestjs",
    "@anthropic-ai/sdk": "anthropic",
    "openai": "openai",
    "langchain": "langchain",
    "@langchain/core": "langchain",
    "react": "react",
}


def _detect_imports(source: str) -> dict[str, str]:
    """Cheap regex-based import detection; we don't need full TS parsing for this."""
    import re

    imports: dict[str, str] = {}
    # ES: import ... from 'pkg'
    for m in re.finditer(
        r"""import\s+(?:[\w*{}\s,]+)\s+from\s+['"]([^'"]+)['"]""",
        source,
    ):
        pkg = m.group(1)
        imports[pkg] = pkg
    # CJS: require('pkg')
    for m in re.finditer(r"""require\(\s*['"]([^'"]+)['"]\s*\)""", source):
        pkg = m.group(1)
        imports[pkg] = pkg
    return imports


class TypeScriptHarness:
    languages = ("typescript", "javascript", "tsx")
    extensions = set(LANG_FOR_EXT.keys())

    def __init__(self, project_root: Path | None = None):
        self.project_root = project_root

    def can_handle(self, file: Path) -> bool:
        return file.suffix.lower() in self.extensions

    def survey(self, file: Path) -> FileMap:
        lang = detect_lang(file) or "typescript"
        result = FileMap(file=str(file), language=lang)

        try:
            source = file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError) as e:
            result.notes.append(f"could not read: {e}")
            return result

        result.imports = _detect_imports(source)
        for pkg in result.imports:
            for prefix, label in FRAMEWORK_IMPORT_HINTS.items():
                if pkg == prefix or pkg.startswith(prefix + "/"):
                    result.frameworks_detected.add(label)
                    break

        # Routes — both file-path heuristics (Next.js) and AST patterns (Express/Hono)
        if self.project_root:
            try:
                result.entrypoints.extend(
                    find_next_entrypoints(file, self.project_root, source, lang)
                )
            except (ValueError, OSError) as e:
                result.notes.append(f"next-route detect failed: {e}")

        # Only run Express/Hono detection when one of those frameworks is
        # actually imported. Otherwise $APP.get($$$) matches every
        # searchParams.get() / headers.get() / context.get() call in a Next.js
        # app and the route list balloons with false positives.
        server_frameworks = {"express", "hono", "fastify", "nestjs"}
        if result.frameworks_detected & server_frameworks:
            try:
                result.entrypoints.extend(find_express_hono_routes(source, lang, file))
            except Exception as e:
                result.notes.append(f"express/hono detect failed: {type(e).__name__}: {e}")

        # Sinks
        try:
            result.sinks = find_sinks(file, source, lang)
        except Exception as e:
            result.notes.append(f"sink detect failed: {type(e).__name__}: {e}")

        return result
