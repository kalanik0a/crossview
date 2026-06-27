"""Discover HTTP / CLI / event entrypoints across Python frameworks."""
import ast
from pathlib import Path

from crossview.harness.base import Entrypoint
from crossview.harness.python.ast_walker import (
    call_name,
    is_string_literal,
    kwarg_value,
)

# HTTP method suffixes recognized when the receiver is a FastAPI/Starlette router.
# This handles named routers like `auth_router.post(...)`, `admin_router.get(...)`.
HTTP_METHOD_SUFFIXES = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "delete": "DELETE",
    "patch": "PATCH",
    "head": "HEAD",
    "options": "OPTIONS",
    "api_route": "ANY",
    "websocket": "WS",
}

FLASK_DECORATORS = {"app.route", "blueprint.route", "bp.route"}

# CLI frameworks
CLI_DECORATORS = {
    "app.command": "typer",
    "typer.Typer.command": "typer",
    "click.command": "click",
    "click.group": "click",
}

# Scheduler / event decorators
SCHEDULER_DECORATORS = {
    "scheduler.scheduled_job": "apscheduler",
    "app.task": "celery",
    "celery.task": "celery",
}


def find_entrypoints(
    file: Path,
    tree: ast.Module,
    fastapi_in_use: bool = False,
) -> list[Entrypoint]:
    """Walk function defs looking for known framework decorators.

    Pass fastapi_in_use=True (set by the harness when fastapi/starlette is
    imported) so we can recognize named router decorators like
    auth_router.post() and admin_router.get().
    """
    out: list[Entrypoint] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        for dec in node.decorator_list:
            ep = _decorator_to_entrypoint(file, node, dec, fastapi_in_use)
            if ep:
                out.append(ep)

    # Django: routes are URL patterns, not decorators. Detect path()/url()/re_path() calls.
    out.extend(_find_django_urls(file, tree))

    return out


def _first_string_arg(call: ast.Call) -> str | None:
    if call.args and is_string_literal(call.args[0]):
        return call.args[0].value
    return None


def _decorator_to_entrypoint(
    file: Path,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    dec: ast.expr,
    fastapi_in_use: bool = False,
) -> Entrypoint | None:
    if not isinstance(dec, ast.Call):
        return None

    name = call_name(dec)
    path = _first_string_arg(dec)

    # FastAPI / Starlette: any <X>.<http_method>(...) when fastapi is imported.
    # Catches @app.get, @router.post, @auth_router.delete, @admin_router.patch, etc.
    if fastapi_in_use and "." in name:
        suffix = name.rsplit(".", 1)[-1]
        if suffix in HTTP_METHOD_SUFFIXES:
            method = HTTP_METHOD_SUFFIXES[suffix]
            return Entrypoint(
                file=str(file),
                line=func.lineno,
                kind="websocket" if method == "WS" else "http_route",
                framework="fastapi",
                method=method,
                path=path,
                handler_name=func.name,
            )

    # Flask
    if name in FLASK_DECORATORS:
        methods_kw = kwarg_value(dec, "methods")
        method = "GET"
        if isinstance(methods_kw, ast.List):
            ms = [
                m.value
                for m in methods_kw.elts
                if isinstance(m, ast.Constant) and isinstance(m.value, str)
            ]
            method = ",".join(ms) if ms else "GET"
        return Entrypoint(
            file=str(file),
            line=func.lineno,
            kind="http_route",
            framework="flask",
            method=method,
            path=path,
            handler_name=func.name,
        )

    # CLI
    if name in CLI_DECORATORS:
        return Entrypoint(
            file=str(file),
            line=func.lineno,
            kind="cli_command",
            framework=CLI_DECORATORS[name],
            handler_name=func.name,
        )

    # Schedulers
    if name in SCHEDULER_DECORATORS:
        return Entrypoint(
            file=str(file),
            line=func.lineno,
            kind="scheduled",
            framework=SCHEDULER_DECORATORS[name],
            handler_name=func.name,
        )

    return None


def _find_django_urls(file: Path, tree: ast.Module) -> list[Entrypoint]:
    """Detect path('admin/', admin.site.urls) and similar URL declarations."""
    out: list[Entrypoint] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = call_name(node)
        if name not in ("path", "url", "re_path", "django.urls.path", "django.urls.re_path"):
            continue

        url_pattern = _first_string_arg(node)
        handler = None
        if len(node.args) >= 2:
            second = node.args[1]
            if isinstance(second, ast.Name):
                handler = second.id
            elif isinstance(second, ast.Attribute):
                handler = call_name(ast.Call(func=second, args=[], keywords=[]))

        out.append(
            Entrypoint(
                file=str(file),
                line=node.lineno,
                kind="http_route",
                framework="django",
                method="ANY",
                path=url_pattern,
                handler_name=handler,
            )
        )

    return out
