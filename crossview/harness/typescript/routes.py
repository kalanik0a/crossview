"""Discover entrypoints in TypeScript / JavaScript projects.

Two strategies:
  1. **File-path heuristics** for Next.js (pages router + app router).
     `pages/api/foo.ts` → /api/foo;  `app/api/foo/route.ts` → /api/foo.
  2. **AST patterns** for Express, Hono, Fastify, NestJS controllers, tRPC.
"""
from __future__ import annotations

from pathlib import Path

from crossview.harness.base import Entrypoint
from crossview.harness.typescript.parser import parse


# ─────────────────────────── Next.js path heuristics ──────────────────────────

def _trim_to_router_root(rel_path: str, marker: str) -> list[str] | None:
    """Find the first occurrence of `marker` in the path components and return
    the components from there onward. Lets us locate Next.js inside arbitrary
    nesting (frontend/, src/, etc.) without forcing project_root == Next root.

    _trim_to_router_root("frontend/src/app/api/news/route.ts", "app")
        → ["app", "api", "news", "route.ts"]
    """
    parts = rel_path.replace("\\", "/").split("/")
    try:
        idx = parts.index(marker)
    except ValueError:
        return None
    return parts[idx:]


def _next_pages_route_path(rel_path: str) -> str | None:
    """Convert a Next.js pages-router file path to its URL.

    pages/api/foo.ts          → /api/foo
    pages/api/users/[id].ts   → /api/users/{id}
    pages/index.tsx           → /
    """
    parts = _trim_to_router_root(rel_path, "pages")
    if not parts:
        return None
    inner = parts[1:]
    if not inner:
        return None
    # _app, _document, _error, _middleware are Next.js framework files
    if inner[-1].rsplit(".", 1)[0].startswith("_"):
        return None
    inner[-1] = inner[-1].rsplit(".", 1)[0]
    if inner[-1] == "index":
        inner = inner[:-1]

    inner = [
        ("{" + p[1:-1] + "}") if p.startswith("[") and p.endswith("]") else p
        for p in inner
    ]
    return "/" + "/".join(inner) if inner else "/"


def _next_app_route_path(rel_path: str) -> str | None:
    """Convert Next.js app-router file paths to URL.

    app/api/foo/route.ts     → /api/foo
    app/users/[id]/page.tsx  → /users/{id}
    app/page.tsx             → /
    """
    parts = _trim_to_router_root(rel_path, "app")
    if not parts:
        return None
    if parts[-1].rsplit(".", 1)[0] not in ("route", "page"):
        return None

    inner = parts[1:-1]
    inner = [
        ("{" + p[1:-1] + "}") if p.startswith("[") and p.endswith("]") else p
        for p in inner
    ]
    # Drop route groups (folder names wrapped in parens)
    inner = [p for p in inner if not (p.startswith("(") and p.endswith(")"))]
    return "/" + "/".join(inner) if inner else "/"


def _find_next_route_methods(source: str, lang: str) -> list[str]:
    """In an app-router route.ts, look for exported HTTP method handlers.

    export async function GET(...) {...}   → GET
    export const POST = ...                 → POST
    """
    from crossview.harness.typescript.parser import parse as _parse

    methods: list[str] = []
    root = _parse(source, lang).root()
    valid = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

    for pattern in (
        "export async function $NAME($$$)",
        "export function $NAME($$$)",
        "export const $NAME = $$$",
    ):
        for m in root.find_all(pattern=pattern):
            captured = m.get_match("NAME")
            if captured and captured.text() in valid:
                methods.append(captured.text())
    return methods


def find_next_entrypoints(file: Path, project_root: Path, source: str, lang: str) -> list[Entrypoint]:
    rel = str(file.relative_to(project_root)) if project_root in file.parents or file == project_root else str(file)

    # Strip optional src/ prefix
    if rel.startswith("src/"):
        rel = rel[4:]

    out: list[Entrypoint] = []

    pages_path = _next_pages_route_path(rel)
    if pages_path is not None:
        # In pages router, default export is the handler. We don't need to
        # parse to know it's an entrypoint.
        # API routes are explicitly under pages/api/. Treat /pages/api/* as
        # http_route; everything else is a page render.
        kind = "http_route" if rel.startswith("pages/api/") else "page"
        out.append(
            Entrypoint(
                file=str(file), line=1,
                kind=kind, framework="nextjs-pages",
                method="ANY" if kind == "http_route" else None,
                path=pages_path,
                handler_name="default",
            )
        )
        return out

    app_path = _next_app_route_path(rel)
    if app_path is not None:
        if rel.endswith("/route.ts") or rel.endswith("/route.tsx") or rel.endswith("/route.js"):
            methods = _find_next_route_methods(source, lang) or ["ANY"]
            for m in methods:
                out.append(
                    Entrypoint(
                        file=str(file), line=1,
                        kind="http_route", framework="nextjs-app",
                        method=m, path=app_path,
                        handler_name=m,
                    )
                )
        else:
            out.append(
                Entrypoint(
                    file=str(file), line=1,
                    kind="page", framework="nextjs-app",
                    path=app_path, handler_name="default",
                )
            )

    return out


# ─────────────────────────── AST-based detection ──────────────────────────────

EXPRESS_HONO_METHODS = ("get", "post", "put", "delete", "patch", "options", "head", "all")


def find_express_hono_routes(source: str, lang: str, file: Path) -> list[Entrypoint]:
    """Detect $APP.<method>('/path', handler) patterns. Catches Express, Hono, Fastify-style."""
    out: list[Entrypoint] = []
    root = parse(source, lang).root()

    for method in EXPRESS_HONO_METHODS:
        # Pattern: app.get('/path', handler)
        for match in root.find_all(pattern=f"$APP.{method}($$$ARGS)"):
            args = match.get_multiple_matches("ARGS")
            path = None
            if args:
                first = args[0].text().strip()
                if (first.startswith("'") and first.endswith("'")) or (
                    first.startswith('"') and first.endswith('"')
                ):
                    path = first[1:-1]
            line = match.range().start.line + 1
            out.append(
                Entrypoint(
                    file=str(file), line=line,
                    kind="http_route", framework="express-or-hono",
                    method=method.upper(), path=path,
                )
            )

    return out
