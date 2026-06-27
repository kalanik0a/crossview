"""Detect language and dispatch to the right harness. Used by Stage 1 (Survey)."""
from pathlib import Path

from crossview.harness.base import CodeHarness, FileMap
from crossview.harness.python.harness import PythonHarness
from crossview.harness.typescript.harness import TypeScriptHarness

DEFAULT_IGNORE = {
    ".venv", "venv", "node_modules", "__pycache__", ".next",
    "build", "dist", ".git", ".pytest_cache", ".mypy_cache",
    "migrations", "alembic", ".tox", ".ruff_cache", "htmlcov",
    "coverage", "data",
}


def harnesses_for(project_root: Path) -> list[CodeHarness]:
    """Build a fresh harness set for a project. project_root lets the TS harness
    convert file paths to Next.js routes."""
    return [
        PythonHarness(),
        TypeScriptHarness(project_root=project_root),
    ]


def survey_file(file: Path, harnesses: list[CodeHarness]) -> FileMap | None:
    for harness in harnesses:
        if harness.can_handle(file):
            return harness.survey(file)
    return None


def survey_tree(root: Path, ignore: set[str] | None = None) -> list[FileMap]:
    """Walk a directory tree and survey every supported file."""
    ignore = ignore if ignore is not None else DEFAULT_IGNORE
    harnesses = harnesses_for(root)

    results: list[FileMap] = []
    for path in root.rglob("*"):
        if any(part in ignore for part in path.parts):
            continue
        if not path.is_file():
            continue
        result = survey_file(path, harnesses)
        if result:
            results.append(result)
    return results
