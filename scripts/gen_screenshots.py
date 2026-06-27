#!/usr/bin/env python3
"""Regenerate every documentation screenshot deterministically.

Four surfaces, each independently runnable and gracefully skipped if its
dependencies are missing:

  cli   real `crossview <cmd>` output → SVG (Rich) → PNG (rsvg/ImageMagick)
  tui   the Textual explorer, headless → SVG → PNG
  web   a TEMPORARY GraphiQL playground (uvicorn + strawberry.asgi) → PNG (Playwright)
  png   rasterize any SVG produced above

Assets land in docs/assets/. SVG is the source of truth (crisp, version-controlled,
renders inline on GitHub + IDEs); PNG is rasterized for renderers that don't show SVG.

Usage:
    python scripts/gen_screenshots.py [cli] [tui] [web]      # default: all
    make screenshots

This is a dev/docs tool — it is NOT imported by the crossview package.
"""
from __future__ import annotations

import glob
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))  # import crossview from a source checkout
ASSETS = ROOT / "docs" / "assets"
PY = sys.executable
WIDTH = 100  # terminal columns for CLI captures


# ─────────────────────────────────────────────────────────── helpers ──

def _run_cli_to_svg(name: str, args: list[str], title: str, width: int = WIDTH) -> Path | None:
    """Run `crossview <args>` with color forced, render its ANSI output to SVG."""
    from rich.console import Console
    from rich.text import Text

    env = {**os.environ, "FORCE_COLOR": "1", "COLUMNS": str(width), "NO_COLOR": ""}
    proc = subprocess.run(
        [PY, "-c", "from crossview.cli import app; app()", *args],
        cwd=ROOT, env=env, capture_output=True, text=True,
    )
    out = proc.stdout or proc.stderr
    if not out.strip():
        print(f"  ! {name}: no output (rc={proc.returncode}) — skipped")
        return None
    console = Console(record=True, width=width)
    console.print(Text.from_ansi(out.rstrip("\n")))
    svg = ASSETS / f"{name}.svg"
    console.save_svg(str(svg), title=title)
    print(f"  ✓ {name}.svg")
    return svg


def _rasterize(svg: Path) -> Path | None:
    """SVG → PNG via rsvg-convert if present, else ImageMagick (librsvg delegate)."""
    png = svg.with_suffix(".png")
    if shutil.which("rsvg-convert"):
        cmd = ["rsvg-convert", "--dpi-x", "144", "--dpi-y", "144",
               "-b", "white", "-o", str(png), str(svg)]
    elif shutil.which("magick"):
        cmd = ["magick", "-density", "144", "-background", "white", str(svg), str(png)]
    elif shutil.which("convert"):
        cmd = ["convert", "-density", "144", "-background", "white", str(svg), str(png)]
    else:
        print(f"  ! no SVG rasterizer (rsvg-convert/magick/convert) — {svg.name} PNG skipped")
        return None
    r = subprocess.run(cmd, capture_output=True, text=True)
    if png.exists():
        print(f"  ✓ {png.name}")
        return png
    print(f"  ! rasterize failed for {svg.name}: {r.stderr[:160]}")
    return None


def _maybe_reexec_for_web(requested: list[str]) -> None:
    """On NixOS, Playwright needs nix-provided browsers + libstdc++ on the
    dynamic-linker path. LD_LIBRARY_PATH is read at process start, so mutating
    os.environ is too late — instead re-exec ourselves once with it set.
    No-op off NixOS or when the env is already configured.
    """
    if "web" not in requested or os.environ.get("_CV_SHOT_REEXEC"):
        return
    changed = False
    if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
        hits = sorted(glob.glob("/nix/store/*-playwright-browsers"))
        if hits:
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = hits[-1]
            changed = True
    if "libstdc++" not in os.environ.get("LD_LIBRARY_PATH", ""):
        libs = sorted(glob.glob("/nix/store/*gcc*-lib/lib/libstdc++.so.6"))
        if libs:
            libdir = str(Path(libs[-1]).parent)
            os.environ["LD_LIBRARY_PATH"] = (
                f"{libdir}:{os.environ.get('LD_LIBRARY_PATH', '')}".rstrip(":")
            )
            changed = True
    if changed:
        os.environ["_CV_SHOT_REEXEC"] = "1"
        os.execve(sys.executable, [sys.executable, *sys.argv], os.environ)


def _browser_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


# ─────────────────────────────────────────────────────────── surfaces ──

CLI_SHOTS = [
    ("help",        ["--help"],                                  "crossview --help"),
    ("show-cwe-89", ["show", "CWE-89"],                          "crossview show CWE-89"),
    ("search",      ["search", "prompt injection", "-n", "6"],   "crossview search 'prompt injection'"),
    ("dev-stats",   ["dev", "stats"],                            "crossview dev stats"),
    ("graphql",     ["graphql", '{ exploitChain(cweId: "CWE-89") '
                                 "{ capecs attackTechniques d3fendTechniques } }"],
                                                                 "crossview graphql (exploit chain)"),
]


def gen_cli() -> None:
    print("[cli] terminal screenshots")
    for name, args, title in CLI_SHOTS:
        svg = _run_cli_to_svg(name, args, title)
        if svg:
            _rasterize(svg)


def gen_tui() -> None:
    print("[tui] Textual explorer screenshot")
    import asyncio
    import inspect

    from textual.app import App

    from crossview.tui import app as tapp

    app_cls = next(
        o for _, o in inspect.getmembers(tapp)
        if inspect.isclass(o) and issubclass(o, App) and o is not App
    )

    async def shoot():
        app = app_cls()
        async with app.run_test(size=(110, 34)) as pilot:
            await pilot.pause()
            # land on a populated detail view if the search box is wired up
            try:
                await pilot.press(*list("CWE-89"))
                await pilot.press("enter")
                await pilot.pause()
            except Exception:
                pass
            app.save_screenshot(str(ASSETS / "tui-explorer.svg"))

    asyncio.run(shoot())
    print("  ✓ tui-explorer.svg")
    _rasterize(ASSETS / "tui-explorer.svg")


def gen_web() -> None:
    print("[web] GraphiQL playground screenshot (temporary local server)")
    if not _browser_available():
        print("  ! playwright not importable — web shot skipped")
        return
    import threading
    import time

    import uvicorn
    from strawberry.asgi import GraphQL

    from crossview.graph.schema import schema

    port = 8799
    server = uvicorn.Server(uvicorn.Config(
        GraphQL(schema), host="127.0.0.1", port=port, log_level="warning",
    ))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    # wait for the server to come up
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)

    query = ('{\n  exploitChain(cweId: "CWE-89") {\n    parentCwes\n    capecs\n'
             "    attackTechniques\n    atlasTechniques\n    d3fendTechniques\n"
             "    ukcPhases\n  }\n}")
    base = f"http://127.0.0.1:{port}/graphql"
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1280, "height": 800})
            # Load the IDE once so it initializes, then prefill the editor via
            # localStorage (typing into CodeMirror auto-closes brackets) and reload.
            # Start from a clean slate so GraphiQL doesn't restore old tabs.
            page.goto(base, wait_until="load")
            page.evaluate("() => localStorage.clear()")
            page.goto(base, wait_until="load")
            page.wait_for_timeout(1200)
            # Focus the query editor and replace its contents. A single
            # insert_text() bypasses CodeMirror's per-keystroke bracket
            # auto-close (which would corrupt a typed-out query).
            editor = page.query_selector(".graphiql-query-editor .CodeMirror") \
                or page.query_selector(".graphiql-query-editor")
            editor.click()
            page.keyboard.press("Control+A")
            page.keyboard.press("Delete")
            page.keyboard.insert_text(query)
            page.wait_for_timeout(400)
            # Run it (Ctrl-Enter is the version-stable shortcut).
            page.keyboard.press("Control+Enter")
            page.wait_for_timeout(1800)  # let results render
            png = ASSETS / "graphiql.png"
            page.screenshot(path=str(png))
            browser.close()
        print(f"  ✓ {png.name}")
    except Exception as e:
        print(f"  ! web shot failed: {type(e).__name__}: {str(e)[:200]}")
    finally:
        server.should_exit = True


# ─────────────────────────────────────────────────────────── main ──

SURFACES = {"cli": gen_cli, "tui": gen_tui, "web": gen_web}


def main(argv: list[str]) -> int:
    requested = [a for a in argv if a in SURFACES] or list(SURFACES)
    _maybe_reexec_for_web(requested)  # may re-exec; nothing below runs twice
    ASSETS.mkdir(parents=True, exist_ok=True)
    print(f"Generating screenshots → {ASSETS.relative_to(ROOT)}  ({', '.join(requested)})\n")
    for key in requested:
        try:
            SURFACES[key]()
        except Exception as e:
            print(f"  ! [{key}] aborted: {type(e).__name__}: {str(e)[:200]}")
        print()
    print("Done. SVGs are the source of truth; PNGs are rasterized alongside.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
