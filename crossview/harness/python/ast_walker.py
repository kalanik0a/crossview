"""Reusable AST helpers for Python harness modules."""
import ast
from pathlib import Path


def parse_file(path: Path) -> ast.Module | None:
    """Parse a Python file. Returns None if parse fails or file unreadable."""
    try:
        source = path.read_text(encoding="utf-8")
        return ast.parse(source, filename=str(path))
    except (SyntaxError, UnicodeDecodeError, OSError):
        return None


def call_name(call: ast.Call) -> str:
    """Extract the dotted name of what's being called.

    foo()             → 'foo'
    foo.bar()         → 'foo.bar'
    foo.bar.baz()     → 'foo.bar.baz'
    x.foo()           → 'x.foo' (variable name not resolved)
    """
    func = call.func
    parts: list[str] = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    elif isinstance(func, ast.Call):
        parts.append("<call>")
    return ".".join(reversed(parts))


def decorator_name(dec: ast.expr) -> str:
    """Extract dotted name from a decorator AST node."""
    if isinstance(dec, ast.Call):
        return call_name(dec)
    if isinstance(dec, ast.Attribute):
        parts: list[str] = []
        cur: ast.expr = dec
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    if isinstance(dec, ast.Name):
        return dec.id
    return ""


def kwarg_value(call: ast.Call, name: str) -> ast.expr | None:
    """Get the value AST node of a keyword arg by name."""
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def is_string_literal(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def get_imports(tree: ast.Module) -> dict[str, str]:
    """Map local name → fully-qualified name.

    import subprocess               → {'subprocess': 'subprocess'}
    from fastapi import APIRouter   → {'APIRouter': 'fastapi.APIRouter'}
    from fastapi import APIRouter as AR → {'AR': 'fastapi.APIRouter'}
    """
    imports: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                imports[alias.asname or alias.name] = f"{module}.{alias.name}"
    return imports


def line_snippet(source_lines: list[str], lineno: int, span: int = 1) -> str:
    """Return ±span lines around lineno (1-indexed). Capped to 200 chars."""
    if not source_lines or lineno < 1:
        return ""
    start = max(0, lineno - 1 - span)
    end = min(len(source_lines), lineno + span)
    return "\n".join(source_lines[start:end])[:200]
