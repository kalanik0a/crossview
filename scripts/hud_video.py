#!/usr/bin/env python3
"""Reusable "defense-intelligence platform" HUD video builder.

Given a spec (title/outro cards + captioned screenshot slides, a music bed, and
per-segment narration), renders a 1080p HUD video: dark grid, classification
banner, telemetry status bar, corner reticles, framed screenshots, a per-slide
Ken-Burns push, a sweeping scanline, and a waveform band — with narration ducked
under the bed. Used by scripts/build_demo.py and the vulpy case-study video.

This is a docs/media tool; not imported by the crossview package.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1920, 1080
WAVE_H, BANNER_H, STATUS_H = 110, 58, 46
BG = (7, 9, 13); GRID = (15, 32, 42); CHROME = (10, 18, 26)
PANEL = (12, 20, 28); BORDER = (32, 60, 76)
CY = (88, 200, 255); AM = (240, 179, 90); GR = (110, 231, 160)
INK = (232, 242, 246); MUTE = (111, 134, 148)


def _font(name: str, size: int) -> ImageFont.FreeTypeFont:
    p = subprocess.check_output(["fc-match", "-f", "%{file}", name], text=True).strip()
    return ImageFont.truetype(p, size)


F_TITLE = _font("DejaVu Sans:bold", 124)
F_SUB = _font("DejaVu Sans Mono", 42)
F_WORD = _font("DejaVu Sans Mono:bold", 30)
F_BANNER = _font("DejaVu Sans Mono", 24)
F_CAP = _font("DejaVu Sans Mono:bold", 42)
F_LABEL = _font("DejaVu Sans Mono", 26)
F_TINY = _font("DejaVu Sans Mono", 22)


def _dur(p: Path) -> float:
    return float(subprocess.check_output(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration",
         "-of", "csv=p=0", str(p)], text=True).strip())


def _tw(d, s, f):
    b = d.textbbox((0, 0), s, font=f); return b[2] - b[0]


def _spaced(s): return " ".join(s)


def _ticks(d, x0, y0, x1, y1, n=24, col=CY, w=2):
    for cx, cy, dx, dy in ((x0, y0, 1, 1), (x1, y0, -1, 1), (x0, y1, 1, -1), (x1, y1, -1, -1)):
        d.line([(cx, cy), (cx + dx * n, cy)], fill=col, width=w)
        d.line([(cx, cy), (cx, cy + dy * n)], fill=col, width=w)


def _chrome(d, spec, scene):
    for x in range(0, W, 64):
        d.line([(x, BANNER_H), (x, H - STATUS_H - WAVE_H)], fill=GRID, width=1)
    for y in range(BANNER_H, H - STATUS_H - WAVE_H, 64):
        d.line([(0, y), (W, y)], fill=GRID, width=1)
    d.rectangle([0, 0, W, BANNER_H], fill=CHROME)
    d.line([(0, BANNER_H), (W, BANNER_H)], fill=BORDER, width=2)
    d.polygon([(28, 18), (28, 40), (40, 29)], fill=CY)
    d.text((50, 16), spec.get("wordmark", "CROSSVIEW"), font=F_WORD, fill=CY)
    center = _spaced(spec.get("banner_center", "OPEN-SOURCE DEFENSE INTELLIGENCE PLATFORM"))
    d.text(((W - _tw(d, center, F_BANNER)) // 2, 18), center, font=F_BANNER, fill=MUTE)
    rt = spec.get("banner_right", "// UNCLASSIFIED // OSINT")
    d.text((W - _tw(d, rt, F_BANNER) - 28, 18), rt, font=F_BANNER, fill=AM)
    sy = H - STATUS_H - WAVE_H
    d.rectangle([0, sy, W, sy + STATUS_H], fill=CHROME)
    d.line([(0, sy), (W, sy)], fill=BORDER, width=2)
    d.text((50, sy + 11), spec.get("telemetry", ""), font=F_TINY, fill=MUTE)
    d.ellipse([W - 150, sy + 16, W - 136, sy + 30], fill=GR)
    d.text((W - 126, sy + 11), "LIVE", font=F_TINY, fill=GR)
    if scene:
        d.text((W - _tw(d, scene, F_TINY) - 28, BANNER_H + 14), scene, font=F_TINY, fill=MUTE)
    _ticks(d, 40, BANNER_H + 40, W - 40, H - STATUS_H - WAVE_H - 40)


def _title_card(path, spec, scene, title, subtitle, tagline):
    img = Image.new("RGB", (W, H), BG); d = ImageDraw.Draw(img)
    _chrome(d, spec, scene)
    cy = H // 2 - 40
    tb = d.textbbox((0, 0), title, font=F_TITLE)
    d.text(((W - (tb[2] - tb[0])) // 2, cy - 150), title, font=F_TITLE, fill=INK)
    d.rectangle([(W - 520) // 2, cy + 6, (W + 520) // 2, cy + 9], fill=CY)
    s = subtitle.upper()
    d.text(((W - _tw(d, s, F_SUB)) // 2, cy + 34), s, font=F_SUB, fill=CY)
    if tagline:
        d.text(((W - _tw(d, tagline, F_LABEL)) // 2, cy + 110), tagline, font=F_LABEL, fill=MUTE)
    img.save(path)


def _shot_slide(path, spec, scene, shot, caption):
    img = Image.new("RGB", (W, H), BG); d = ImageDraw.Draw(img)
    _chrome(d, spec, scene)
    d.text((54, BANNER_H + 28), "❯", font=F_CAP, fill=CY)
    d.text((92, BANNER_H + 28), caption, font=F_CAP, fill=INK)
    top, bottom, side = BANNER_H + 110, H - STATUS_H - WAVE_H - 70, 120
    aw, ah = W - 2 * side, bottom - top
    s = Image.open(shot).convert("RGB")
    sc = min(aw / s.width, ah / s.height)
    nw, nh = int(s.width * sc), int(s.height * sc)
    s = s.resize((nw, nh), Image.LANCZOS)
    x, y = (W - nw) // 2, top + (ah - nh) // 2
    d.rectangle([x - 16, y - 16, x + nw + 16, y + nh + 16], fill=PANEL, outline=BORDER, width=2)
    img.paste(s, (x, y))
    _ticks(d, x - 16, y - 16, x + nw + 16, y + nh + 16, n=18)
    d.text((x - 16, y - 46), f"FIG.{scene.split('/')[0].strip()}", font=F_TINY, fill=MUTE)
    img.save(path)


def render(spec: dict) -> str:
    """spec: {out, music, telemetry?, wordmark?, banner_center?, banner_right?,
             segments:[{kind:title|outro|shot, vo?, duration?, ...}]}"""
    out = Path(spec["out"]); out.parent.mkdir(parents=True, exist_ok=True)
    work = out.parent / "_hud_work"; work.mkdir(exist_ok=True)
    segs = spec["segments"]; n = len(segs)
    tl = []
    for i, seg in enumerate(segs):
        sp = work / f"s{i}.png"; scene = f"{i+1:02d} / {n:02d}"
        if seg["kind"] == "title":
            _title_card(sp, spec, scene, seg["title"], seg["subtitle"], seg.get("tagline", ""))
        elif seg["kind"] == "outro":
            _title_card(sp, spec, scene, seg.get("title", "CROSSVIEW"),
                        seg["subtitle"], seg.get("tagline", ""))
        else:
            _shot_slide(sp, spec, scene, seg["shot"], seg.get("caption", ""))
        vo = seg.get("vo")
        dur = float(seg["duration"]) if seg.get("duration") else (_dur(Path(vo)) + 0.6)
        tl.append({"slide": sp, "vo": vo, "dur": dur})
    total = sum(t["dur"] for t in tl)

    # audio: padded VO concat ducked under bed
    parts = []
    for i, t in enumerate(tl):
        a = work / f"a{i}.wav"
        if t["vo"]:
            subprocess.run(["ffmpeg", "-y", "-i", str(t["vo"]),
                            "-af", f"adelay=250|250,apad,atrim=0:{t['dur']:.3f},aresample=48000",
                            "-ac", "2", str(a)], check=True, capture_output=True)
        else:
            subprocess.run(["ffmpeg", "-y", "-f", "lavfi", "-t", f"{t['dur']:.3f}",
                            "-i", "anullsrc=r=48000:cl=stereo", str(a)], check=True, capture_output=True)
        parts.append(a)
    (work / "vo.txt").write_text("".join(f"file '{p}'\n" for p in parts))
    vot = work / "vo.wav"
    subprocess.run(["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(work / "vo.txt"),
                    "-c", "copy", str(vot)], check=True, capture_output=True)
    mix = work / "mix.wav"
    duck = (f"[0:a]aloop=loop=-1:size=2e9,atrim=0:{total:.3f},afade=t=in:st=0:d=1.2,"
            f"afade=t=out:st={total-1.6:.3f}:d=1.6,volume=0.55,aresample=48000[bed];"
            "[1:a]aresample=48000,asplit=2[v1][v2];"
            "[bed][v1]sidechaincompress=threshold=0.025:ratio=7:attack=5:release=320[bd];"
            "[bd][v2]amix=inputs=2:normalize=0,alimiter=limit=0.95[mx]")
    subprocess.run(["ffmpeg", "-y", "-i", str(spec["music"]), "-i", str(vot),
                    "-filter_complex", duck, "-map", "[mx]", "-c:a", "pcm_s16le", str(mix)],
                   check=True, capture_output=True)

    # video: per-slide Ken-Burns push
    clips = []
    for i, t in enumerate(tl):
        c = work / f"c{i}.mp4"; frames = max(int(round(t["dur"] * 30)), 1)
        z = f"min(1+0.035*on/{max(frames-1,1)},1.035)"
        vf = (f"scale={2*W}:{2*H},setsar=1,zoompan=z='{z}':x='iw/2-(iw/zoom/2)':"
              f"y='ih/2-(ih/zoom/2)':d={frames}:s={W}x{H}:fps=30,format=yuv420p")
        subprocess.run(["ffmpeg", "-y", "-i", str(t["slide"]), "-vf", vf,
                        "-t", f"{t['dur']:.3f}", "-r", "30", "-c:v", "libx264",
                        "-preset", "medium", "-crf", "20", str(c)], check=True, capture_output=True)
        clips.append(c)
    (work / "v.txt").write_text("".join(f"file '{c}'\n" for c in clips))
    slides = work / "slides.mp4"
    subprocess.run(["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(work / "v.txt"),
                    "-c", "copy", str(slides)], check=True, capture_output=True)

    fc = ("color=c=0x58c8ff@0.07:s=1920x4:r=30[scan];"
          f"[0:v][scan]overlay=0:y='mod(t*150\\,{H})'[v1];"
          f"[1:a]showwaves=s={W}x{WAVE_H}:mode=cline:colors=0x58c8ff|0xf0b35a:scale=sqrt,"
          "format=rgba,colorchannelmixer=aa=0.9[wave];"
          f"[v1][wave]overlay=0:{H-WAVE_H}[v2];"
          f"[v2]fade=t=in:st=0:d=0.6,fade=t=out:st={total-0.8:.3f}:d=0.8[vout]")
    subprocess.run(["ffmpeg", "-y", "-i", str(slides), "-i", str(mix),
                    "-filter_complex", fc, "-map", "[vout]", "-map", "1:a",
                    "-c:v", "libx264", "-preset", "medium", "-crf", "20", "-pix_fmt", "yuv420p",
                    "-c:a", "aac", "-b:a", "192k", "-movflags", "+faststart", "-shortest", str(out)],
                   check=True, capture_output=True)
    return str(out)
