"""PythonHarness — top-level Python file analysis."""
from pathlib import Path

from crossview.harness.base import FileMap
from crossview.harness.python.ast_walker import get_imports, parse_file
from crossview.harness.python.routes import find_entrypoints
from crossview.harness.python.sinks import find_sinks


# Imported names that signal a framework is in use, for survey-level signaling.
FRAMEWORK_SIGNALS = {
    "fastapi": "fastapi",
    "starlette": "starlette",
    "flask": "flask",
    "django": "django",
    "typer": "typer",
    "click": "click",
    "celery": "celery",
    "apscheduler": "apscheduler",
    "anthropic": "anthropic",  # → triggers ATLAS rule preset
    "openai": "openai",
    "langchain": "langchain",
    "langchain_core": "langchain",
    "llama_index": "llama_index",
}


class PythonHarness:
    languages = ("python",)
    extensions = {".py"}

    def can_handle(self, file: Path) -> bool:
        return file.suffix in self.extensions

    def survey(self, file: Path) -> FileMap:
        result = FileMap(file=str(file), language="python")

        try:
            source = file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError) as e:
            result.notes.append(f"could not read: {e}")
            return result

        tree = parse_file(file)
        if not tree:
            result.notes.append("python parse error")
            return result

        result.imports = get_imports(tree)

        # Detect frameworks by import name prefix
        for local, full in result.imports.items():
            for prefix, label in FRAMEWORK_SIGNALS.items():
                if full == prefix or full.startswith(prefix + "."):
                    result.frameworks_detected.add(label)
                    break

        source_lines = source.split("\n")
        fastapi_in_use = (
            "fastapi" in result.frameworks_detected
            or "starlette" in result.frameworks_detected
        )
        result.entrypoints = find_entrypoints(file, tree, fastapi_in_use=fastapi_in_use)
        result.sinks = find_sinks(file, tree, source_lines)

        return result
