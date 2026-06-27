#!/usr/bin/env python3
"""Assemble the Crossview demo video — a "defense-intelligence platform" HUD:
dark grid, classification banners, a live telemetry status bar, corner reticles,
framed screenshots, a subtle Ken-Burns push per slide, a sweeping scanline, and a
waveform band — over a Gemini music bed with ducked narration.

Music bed + VO and the rendered video live in the media library (kept out of the
repo), resolved via CROSSVIEW_MEDIA_DIR. Rebuild: python3 scripts/build_demo.py
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO = Path(__file__).resolve().parents[1]
SHOTS = REPO / "docs" / "assets"                       # product screenshots (in repo)
MANIFEST = REPO / "docs" / "demo" / "assets" / "manifest.json"  # build config (in repo)
MEDIA = Path(os.environ.get(
    "CROSSVIEW_MEDIA_DIR",
    os.path.expanduser("~/Videos/visionlighter/crossview"))) / "product-demo"
ASSETS = MEDIA / "build-assets"                        # music bed + VO (out of repo)
WORK = MEDIA / "_work"                                 # scratch
SLIDES = WORK / "slides"
SLIDES.mkdir(parents=True, exist_ok=True)

W, H = 1920, 1080
WAVE_H = 110                 # visualizer band at the very bottom
TAIL = 0.6                   # hold each slide past its narration
BANNER_H = 58
STATUS_H = 46

# Defense-HUD palette (near-black, cyan + amber, muted steel)
BG = (7, 9, 13)              # #07090d
GRID = (15, 32, 42)          # faint cyan grid
CHROME = (10, 18, 26)        # banner / status fills
PANEL = (12, 20, 28)
BORDER = (32, 60, 76)
CY = (88, 200, 255)          # cyan accent
AM = (240, 179, 90)          # amber
GR = (110, 231, 160)         # online green
INK = (232, 242, 246)
MUTE = (111, 134, 148)


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    path = subprocess.check_output(["fc-match", "-f", "%{file}", name], text=True).strip()
    return ImageFont.truetype(path, size)


F_TITLE = font("DejaVu Sans:bold", 128)
F_SUB = font("DejaVu Sans Mono", 44)
F_WORD = font("DejaVu Sans Mono:bold", 30)
F_BANNER = font("DejaVu Sans Mono", 24)
F_CAP = font("DejaVu Sans Mono:bold", 44)
F_LABEL = font("DejaVu Sans Mono", 26)
F_TAG = font("DejaVu Sans Mono", 34)
F_TINY = font("DejaVu Sans Mono", 22)


def _ffprobe_dur(p: Path) -> float:
    return float(subprocess.check_output(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration",
         "-of", "csv=p=0", str(p)], text=True).strip())


def _text_w(d: ImageDraw.ImageDraw, s: str, f) -> int:
    b = d.textbbox((0, 0), s, font=f)
    return b[2] - b[0]


def _spaced(s: str) -> str:
    return " ".join(s)


def _corner_ticks(d, x0, y0, x1, y1, n=26, col=CY, wdt=2):
    for (cx, cy, dx, dy) in ((x0, y0, 1, 1), (x1, y0, -1, 1),
                             (x0, y1, 1, -1), (x1, y1, -1, -1)):
        d.line([(cx, cy), (cx + dx * n, cy)], fill=col, width=wdt)
        d.line([(cx, cy), (cx, cy + dy * n)], fill=col, width=wdt)


def _chrome(d: ImageDraw.ImageDraw, scene: str | None) -> None:
    # grid
    for x in range(0, W, 64):
        d.line([(x, BANNER_H), (x, H - STATUS_H - WAVE_H)], fill=GRID, width=1)
    for y in range(BANNER_H, H - STATUS_H - WAVE_H, 64):
        d.line([(0, y), (W, y)], fill=GRID, width=1)
    # top classification banner
    d.rectangle([0, 0, W, BANNER_H], fill=CHROME)
    d.line([(0, BANNER_H), (W, BANNER_H)], fill=BORDER, width=2)
    d.polygon([(28, 18), (28, 40), (40, 29)], fill=CY)
    d.text((50, 16), "CROSSVIEW", font=F_WORD, fill=CY)
    center = _spaced("OPEN-SOURCE DEFENSE INTELLIGENCE PLATFORM")
    d.text(((W - _text_w(d, center, F_BANNER)) // 2, 18), center, font=F_BANNER, fill=MUTE)
    rt = "// UNCLASSIFIED // OSINT"
    d.text((W - _text_w(d, rt, F_BANNER) - 28, 18), rt, font=F_BANNER, fill=AM)
    # bottom status / telemetry bar (above the waveform band)
    sy = H - STATUS_H - WAVE_H
    d.rectangle([0, sy, W, sy + STATUS_H], fill=CHROME)
    d.line([(0, sy), (W, sy)], fill=BORDER, width=2)
    tele = "MITRE GRAPH  3,716 ENTITIES   14,200 XREFS   CWE·CAPEC·ATT&CK·ATLAS·D3FEND·UKC   NVD/KEV LINKED"
    d.text((50, sy + 11), tele, font=F_TINY, fill=MUTE)
    d.ellipse([W - 150, sy + 16, W - 136, sy + 30], fill=GR)
    d.text((W - 126, sy + 11), "LIVE", font=F_TINY, fill=GR)
    # scene index
    if scene:
        d.text((W - _text_w(d, scene, F_TINY) - 28, BANNER_H + 14), scene, font=F_TINY, fill=MUTE)
    # content-area corner reticles
    _corner_ticks(d, 40, BANNER_H + 40, W - 40, H - STATUS_H - WAVE_H - 40)


def title_card(path: Path, title: str, subtitle: str, scene: str) -> None:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    _chrome(d, scene)
    cy = H // 2 - 40
    tb = d.textbbox((0, 0), title, font=F_TITLE)
    d.text(((W - (tb[2] - tb[0])) // 2, cy - 150), title, font=F_TITLE, fill=INK)
    # cyan rule under the title
    rule_w = 520
    d.rectangle([(W - rule_w) // 2, cy + 6, (W + rule_w) // 2, cy + 9], fill=CY)
    sub = subtitle.upper()
    d.text(((W - _text_w(d, sub, F_SUB)) // 2, cy + 34), sub, font=F_SUB, fill=CY)
    tag = "// SYSTEM ONLINE  ·  KNOWLEDGE GRAPH LOADED  ·  AWAITING QUERY"
    d.text(((W - _text_w(d, tag, F_LABEL)) // 2, cy + 110), tag, font=F_LABEL, fill=MUTE)
    img.save(path)


def outro_card(path: Path, line: str, scene: str) -> None:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    _chrome(d, scene)
    cy = H // 2 - 30
    tb = d.textbbox((0, 0), "CROSSVIEW", font=F_TITLE)
    d.text(((W - (tb[2] - tb[0])) // 2, cy - 140), "CROSSVIEW", font=F_TITLE, fill=INK)
    d.rectangle([(W - 520) // 2, cy + 6, (W + 520) // 2, cy + 9], fill=CY)
    ln = line.upper()
    d.text(((W - _text_w(d, ln, F_TAG)) // 2, cy + 34), ln, font=F_TAG, fill=CY)
    foot = "MITRE SILO · 5-STAGE SCANNER · SARIF · STIX · VEX · GRAPHQL · INTEL FUSION"
    d.text(((W - _text_w(d, foot, F_LABEL)) // 2, cy + 104), foot, font=F_LABEL, fill=AM)
    img.save(path)


def shot_slide(path: Path, shot: Path, caption: str, scene: str) -> None:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    _chrome(d, scene)
    # command caption with a cyan prompt glyph
    d.text((54, BANNER_H + 28), "❯", font=F_CAP, fill=CY)
    d.text((92, BANNER_H + 28), caption, font=F_CAP, fill=INK)
    # framed screenshot panel
    top, bottom, side = BANNER_H + 110, H - STATUS_H - WAVE_H - 70, 120
    area_w, area_h = W - 2 * side, bottom - top
    s = Image.open(shot).convert("RGB")
    scale = min(area_w / s.width, area_h / s.height)
    nw, nh = int(s.width * scale), int(s.height * scale)
    s = s.resize((nw, nh), Image.LANCZOS)
    x, y = (W - nw) // 2, top + (area_h - nh) // 2
    d.rectangle([x - 16, y - 16, x + nw + 16, y + nh + 16], fill=PANEL, outline=BORDER, width=2)
    img.paste(s, (x, y))
    _corner_ticks(d, x - 16, y - 16, x + nw + 16, y + nh + 16, n=18, col=CY, wdt=2)
    d.text((x - 16, y - 46), f"FIG.{scene.split('/')[0].strip()}", font=F_TINY, fill=MUTE)
    img.save(path)


def main() -> None:
    m = json.loads(MANIFEST.read_text())
    segs = m["segments"]
    n = len(segs)

    timeline = []
    for i, seg in enumerate(segs):
        sp = SLIDES / f"{seg['id']}.png"
        scene = f"{i+1:02d} / {n:02d}"
        if seg["slide"] == "__title__":
            title_card(sp, m["title"], m["subtitle"], scene)
        elif seg["slide"] == "__outro__":
            outro_card(sp, seg["text"].split(".")[-2].strip() + ".", scene)
        else:
            shot_slide(sp, SHOTS / seg["slide"], seg["caption"], scene)
        dur = _ffprobe_dur(ASSETS / "vo" / f"{seg['id']}.mp3") + TAIL
        timeline.append({"slide": sp, "vo": ASSETS / "vo" / f"{seg['id']}.mp3", "dur": dur})
    total = sum(t["dur"] for t in timeline)
    print(f"segments={n} total={total:.1f}s")

    # ── audio: padded VO concat ducked under the music bed (unchanged) ──
    vo_parts = []
    for i, t in enumerate(timeline):
        out = WORK / f"_vo_{i}.wav"
        subprocess.run(["ffmpeg", "-y", "-i", str(t["vo"]),
                        "-af", f"adelay=250|250,apad,atrim=0:{t['dur']:.3f},aresample=48000",
                        "-ac", "2", str(out)], check=True, capture_output=True)
        vo_parts.append(out)
    (WORK / "vo_concat.txt").write_text("".join(f"file '{p}'\n" for p in vo_parts))
    vo_track = WORK / "vo_track.wav"
    subprocess.run(["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(WORK / "vo_concat.txt"),
                    "-c", "copy", str(vo_track)], check=True, capture_output=True)
    bed = ASSETS / "crossview-bed.mp3"
    mix = WORK / "mix.wav"
    duck = (
        f"[0:a]atrim=0:{total:.3f},afade=t=in:st=0:d=1.2,"
        f"afade=t=out:st={total-1.6:.3f}:d=1.6,volume=0.55,aresample=48000[bed];"
        "[1:a]aresample=48000,asplit=2[vo1][vo2];"
        "[bed][vo1]sidechaincompress=threshold=0.025:ratio=7:attack=5:release=320[bd];"
        "[bd][vo2]amix=inputs=2:normalize=0,alimiter=limit=0.95[mx]"
    )
    subprocess.run(["ffmpeg", "-y", "-i", str(bed), "-i", str(vo_track),
                    "-filter_complex", duck, "-map", "[mx]",
                    "-c:a", "pcm_s16le", str(mix)], check=True, capture_output=True)

    # ── video: per-slide Ken-Burns push (single still → zoompan) ──
    clips = []
    for i, t in enumerate(timeline):
        out = WORK / f"_clip_{i}.mp4"
        frames = max(int(round(t["dur"] * 30)), 1)
        zexpr = f"min(1+0.035*on/{max(frames-1,1)},1.035)"
        vf = (f"scale={2*W}:{2*H},setsar=1,"
              f"zoompan=z='{zexpr}':x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)'"
              f":d={frames}:s={W}x{H}:fps=30,format=yuv420p")
        subprocess.run(["ffmpeg", "-y", "-i", str(t["slide"]),
                        "-vf", vf, "-t", f"{t['dur']:.3f}", "-r", "30",
                        "-c:v", "libx264", "-preset", "medium", "-crf", "20", str(out)],
                       check=True, capture_output=True)
        clips.append(out)
    (WORK / "v_concat.txt").write_text("".join(f"file '{p}'\n" for p in clips))
    slides_mp4 = WORK / "slides.mp4"
    subprocess.run(["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(WORK / "v_concat.txt"),
                    "-c", "copy", str(slides_mp4)], check=True, capture_output=True)

    # ── final: sweeping scanline + cyan waveform band + fades, mux audio ──
    final = MEDIA / "crossview-demo.mp4"
    band_y = H - WAVE_H
    fc = (
        # faint cyan scanline sweeping top→bottom
        "color=c=0x58c8ff@0.07:s=1920x4:r=30[scan];"
        f"[0:v][scan]overlay=0:y='mod(t*150\\,{H})'[v1];"
        # waveform visualizer band
        f"[1:a]showwaves=s={W}x{WAVE_H}:mode=cline:colors=0x58c8ff|0xf0b35a:"
        "scale=sqrt,format=rgba,colorchannelmixer=aa=0.9[wave];"
        f"[v1][wave]overlay=0:{band_y}[v2];"
        f"[v2]fade=t=in:st=0:d=0.6,fade=t=out:st={total-0.8:.3f}:d=0.8[vout]"
    )
    subprocess.run(["ffmpeg", "-y", "-i", str(slides_mp4), "-i", str(mix),
                    "-filter_complex", fc, "-map", "[vout]", "-map", "1:a",
                    "-c:v", "libx264", "-preset", "medium", "-crf", "20",
                    "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "192k",
                    "-movflags", "+faststart", "-shortest", str(final)],
                   check=True, capture_output=True)
    print("FINAL:", final, f"{_ffprobe_dur(final):.1f}s")


if __name__ == "__main__":
    main()
