#!/usr/bin/env python3
"""Capture Crossview's current UI screens for the docs gallery.

Surfaces (all real, shipped UI today):
  tui     — the Textual terminal app: silo tree, a populated detail view, search
  web     — the `crossview serve` GraphQL UI (GraphiQL), with a query run
  report  — the HTML security report and the OSCTI intel report

Output → docs/assets/ui/*.png. Browser captures auto-discover the nix-provided
Playwright browsers (re-exec once with the right env on NixOS).

NOTE: there is no Electron app yet — the desktop console is roadmap (docs/14).
When it exists, Playwright's _electron driver + DevTools is how it gets captured.
"""
from __future__ import annotations

import glob
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
OUT = REPO / "docs" / "assets" / "ui"
OUT.mkdir(parents=True, exist_ok=True)


def _rasterize(svg: Path, png: Path) -> None:
    for cmd in (["rsvg-convert", "-b", "#0b0f14", "-o", str(png), str(svg)],
                ["magick", "-background", "#0b0f14", str(svg), str(png)],
                ["convert", "-background", "#0b0f14", str(svg), str(png)]):
        try:
            if subprocess.run(cmd, capture_output=True).returncode == 0 and png.exists():
                return
        except FileNotFoundError:
            continue


# ── TUI (Textual headless) ────────────────────────────────────────────────

def capture_tui() -> None:
    import asyncio
    import inspect

    from textual.app import App
    from textual.widgets import Input

    from crossview.tui import app as tapp
    app_cls = next(o for _, o in inspect.getmembers(tapp)
                   if inspect.isclass(o) and issubclass(o, App) and o is not App)

    async def shot(name: str, query: str | None):
        app = app_cls()
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            if query:
                inp = app.query_one("#search", Input)
                inp.focus()
                inp.value = query
                await pilot.press("enter")
                await pilot.pause()
                await pilot.pause()
            svg = OUT / f"tui-{name}.svg"
            app.save_screenshot(str(svg))
            _rasterize(svg, OUT / f"tui-{name}.png")
            print(f"  ✓ tui-{name}")

    asyncio.run(shot("overview", None))
    asyncio.run(shot("detail", "CWE-89"))
    asyncio.run(shot("search", "injection"))


# ── browser captures (GraphiQL + reports) ─────────────────────────────────

def _maybe_reexec() -> None:
    if os.environ.get("_CV_UI_REEXEC"):
        return
    changed = False
    if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
        hits = sorted(glob.glob("/nix/store/*-playwright-browsers"))
        if hits:
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = hits[-1]; changed = True
    if "libstdc++" not in os.environ.get("LD_LIBRARY_PATH", ""):
        libs = sorted(glob.glob("/nix/store/*gcc*-lib/lib/libstdc++.so.6"))
        if libs:
            os.environ["LD_LIBRARY_PATH"] = (
                f"{Path(libs[-1]).parent}:{os.environ.get('LD_LIBRARY_PATH', '')}".rstrip(":"))
            changed = True
    if changed:
        os.environ["_CV_UI_REEXEC"] = "1"
        os.execve(sys.executable, [sys.executable, *sys.argv], os.environ)


def capture_web() -> None:
    try:
        import uvicorn
        from strawberry.asgi import GraphQL

        from crossview.graph.schema import schema
        from playwright.sync_api import sync_playwright
    except Exception as e:
        print(f"  ! web skipped: {type(e).__name__}: {e}")
        return
    port = 8791
    server = uvicorn.Server(uvicorn.Config(GraphQL(schema), host="127.0.0.1", port=port, log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)
    query = ('{\n  exploitChain(cweId: "CWE-89") {\n    parentCwes\n    capecs\n'
             "    attackTechniques\n    d3fendTechniques\n  }\n}")
    try:
        with sync_playwright() as p:
            b = p.chromium.launch()
            pg = b.new_page(viewport={"width": 1280, "height": 800})
            pg.goto(f"http://127.0.0.1:{port}/graphql", wait_until="load")
            pg.evaluate("() => localStorage.clear()")
            pg.goto(f"http://127.0.0.1:{port}/graphql", wait_until="load")
            pg.wait_for_timeout(1200)
            ed = pg.query_selector(".graphiql-query-editor .CodeMirror") or pg.query_selector(".graphiql-query-editor")
            if ed:
                ed.click(); pg.keyboard.press("Control+A"); pg.keyboard.press("Delete")
                pg.keyboard.insert_text(query); pg.wait_for_timeout(300)
                pg.keyboard.press("Control+Enter"); pg.wait_for_timeout(1500)
            pg.screenshot(path=str(OUT / "web-graphiql.png"))
            b.close()
        print("  ✓ web-graphiql")
    except Exception as e:
        print(f"  ! web-graphiql failed: {type(e).__name__}: {e}")
    finally:
        server.should_exit = True


def capture_reports() -> None:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        print(f"  ! reports skipped: {e}")
        return
    targets = {
        "report-security": REPO / ".scratch" / "targets" / "vulpy" / "bad" / "CROSSVIEW-REPORT.html",
        "report-intel": REPO / ".scratch" / "wannacry.html",
    }
    have = {k: v for k, v in targets.items() if v.exists()}
    if not have:
        print("  ! reports skipped (generate them first: crossview report … / crossview intel report …)")
        return
    with sync_playwright() as p:
        b = p.chromium.launch()
        for name, path in have.items():
            pg = b.new_page(viewport={"width": 900, "height": 1160})
            pg.set_content(path.read_text(), wait_until="load")
            pg.wait_for_timeout(300)
            pg.screenshot(path=str(OUT / f"{name}.png"), full_page=True)
            pg.close()
            print(f"  ✓ {name}")
        b.close()


def main() -> None:
    surfaces = [a for a in sys.argv[1:] if a in ("tui", "web", "report")] or ["tui", "web", "report"]
    if "web" in surfaces or "report" in surfaces:
        _maybe_reexec()
    if "tui" in surfaces:
        print("[tui]"); capture_tui()
    if "web" in surfaces:
        print("[web]"); capture_web()
    if "report" in surfaces:
        print("[report]"); capture_reports()
    print("Done →", OUT.relative_to(REPO))


if __name__ == "__main__":
    main()
