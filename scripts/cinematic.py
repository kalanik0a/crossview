#!/usr/bin/env python3
"""Cinematic, motion-driven HUD video engine — frame-by-frame (Pillow → ffmpeg).

Built for a "defense-contractor" production feel: animated reveals, flowing data
particles along graph edges, a code-scan beam that tags sink lines, an animated
findings matrix with live counters, and a scrolling KEV exploitation ticker.

Driven by a spec of timed scenes + real data. Renders frames, encodes per-scene
clips, concatenates, then overlays a waveform band + sweeping scanline and muxes
narration ducked under a music bed. Docs/media tool; not imported by the package.
"""
from __future__ import annotations

import math
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H, FPS = 1920, 1080, 24
BANNER_H, STATUS_H, WAVE_H = 58, 46, 110
BG = (7, 9, 13); GRID = (15, 32, 42); CHROME = (10, 18, 26)
PANEL = (12, 20, 28); BORDER = (32, 60, 76)
CY = (88, 200, 255); AM = (240, 179, 90); GR = (110, 231, 160); RD = (255, 96, 96)
INK = (232, 242, 246); MUTE = (111, 134, 148)


def _font(name, size):
    p = subprocess.check_output(["fc-match", "-f", "%{file}", name], text=True).strip()
    return ImageFont.truetype(p, size)


@dataclass
class Ctx:
    data: dict
    spec: dict
    fonts: dict = field(default_factory=dict)


def clamp(x, a=0.0, b=1.0): return max(a, min(b, x))
def ease(p): p = clamp(p); return p * p * (3 - 2 * p)              # smoothstep
def ease_out(p): p = clamp(p); return 1 - (1 - p) * (1 - p)
def lerp(a, b, t): return a + (b - a) * t
def blend(c, a, bg=BG): return tuple(int(bg[i] + (c[i] - bg[i]) * clamp(a)) for i in range(3))
def mix(c1, c2, t): return tuple(int(lerp(c1[i], c2[i], clamp(t))) for i in range(3))


def tw(d, s, f): b = d.textbbox((0, 0), s, font=f); return b[2] - b[0]


def glow_dot(d, x, y, r, color, a=1.0):
    for k, ga in ((2.4, 0.10), (1.6, 0.22), (1.0, 1.0)):
        rr = r * k
        d.ellipse([x - rr, y - rr, x + rr, y + rr], fill=blend(color, a * ga))


def particles(d, a, b, t, color, n=7, speed=0.5, r=4, base=GRID):
    ax, ay = a; bx, by = b
    d.line([a, b], fill=base, width=2)
    for k in range(n):
        f = (k / n + t * speed) % 1.0
        glow_dot(d, lerp(ax, bx, f), lerp(ay, by, f), r, color, 0.9)


def chrome_base(ctx: Ctx, scene_label: str) -> Image.Image:
    img = Image.new("RGB", (W, H), BG); d = ImageDraw.Draw(img)
    F = ctx.fonts
    for x in range(0, W, 64):
        d.line([(x, BANNER_H), (x, H - STATUS_H - WAVE_H)], fill=GRID)
    for y in range(BANNER_H, H - STATUS_H - WAVE_H, 64):
        d.line([(0, y), (W, y)], fill=GRID)
    d.rectangle([0, 0, W, BANNER_H], fill=CHROME); d.line([(0, BANNER_H), (W, BANNER_H)], fill=BORDER, width=2)
    d.polygon([(28, 18), (28, 40), (40, 29)], fill=CY)
    d.text((50, 16), ctx.spec.get("wordmark", "CROSSVIEW"), font=F["word"], fill=CY)
    center = " ".join(ctx.spec.get("banner_center", ""))
    d.text(((W - tw(d, center, F["banner"])) // 2, 18), center, font=F["banner"], fill=MUTE)
    rt = ctx.spec.get("banner_right", "// UNCLASSIFIED")
    d.text((W - tw(d, rt, F["banner"]) - 28, 18), rt, font=F["banner"], fill=AM)
    sy = H - STATUS_H - WAVE_H
    d.rectangle([0, sy, W, sy + STATUS_H], fill=CHROME); d.line([(0, sy), (W, sy)], fill=BORDER, width=2)
    d.text((50, sy + 11), ctx.spec.get("telemetry", ""), font=F["tiny"], fill=MUTE)
    d.ellipse([W - 150, sy + 16, W - 136, sy + 30], fill=GR); d.text((W - 126, sy + 11), "LIVE", font=F["tiny"], fill=GR)
    if scene_label:
        d.text((W - tw(d, scene_label, F["tiny"]) - 28, BANNER_H + 14), scene_label, font=F["tiny"], fill=MUTE)
    for cx, cy, dx, dy in ((40, BANNER_H + 40, 1, 1), (W - 40, BANNER_H + 40, -1, 1),
                           (40, H - STATUS_H - WAVE_H - 40, 1, -1), (W - 40, H - STATUS_H - WAVE_H - 40, -1, -1)):
        d.line([(cx, cy), (cx + dx * 24, cy)], fill=CY, width=2); d.line([(cx, cy), (cx, cy + dy * 24)], fill=CY, width=2)
    return img


# ── scenes ────────────────────────────────────────────────────────────────
CONTENT_TOP = BANNER_H + 40
CONTENT_BOT = H - STATUS_H - WAVE_H - 40
CMID = (CONTENT_TOP + CONTENT_BOT) // 2


def sc_title(d, p, ctx):
    F = ctx.fonts
    a = ease((p - 0.05) / 0.4)
    title = ctx.spec.get("title", "CROSSVIEW"); sub = ctx.spec.get("subtitle", "")
    sz = lerp(0.86, 1.0, ease_out(p / 0.5))
    tf = F["title"]
    cx = W // 2
    d.text((cx - tw(d, title, tf) * sz / 2, CMID - 150 + (1 - a) * 30), title, font=tf, fill=blend(INK, a))
    rw = int(560 * ease((p - 0.2) / 0.4))
    d.rectangle([cx - rw // 2, CMID + 6, cx + rw // 2, CMID + 9], fill=CY)
    sa = ease((p - 0.35) / 0.4)
    d.text((cx - tw(d, sub.upper(), F["sub"]) / 2, CMID + 34), sub.upper(), font=F["sub"], fill=blend(CY, sa))
    tag = ctx.spec.get("tagline", "")
    ta = ease((p - 0.5) / 0.4)
    if tag:
        d.text((cx - tw(d, tag, F["label"]) / 2, CMID + 110), tag, font=F["label"], fill=blend(MUTE, ta))
    # orbiting recon dots
    for k in range(3):
        ang = p * 2 * math.pi + k * 2.094
        glow_dot(d, cx + 360 * math.cos(ang), CMID - 40 + 120 * math.sin(ang), 4, CY, 0.5)


CODE = [
    ("def login(username, password):", False, None),
    ("    c = db.cursor()", False, None),
    ("    user = c.execute(", False, None),
    ("        \"SELECT * FROM users WHERE \"", False, None),
    ("        \"username = '{}' and password = '{}'\"", True, "CWE-89 · SQL injection"),
    ("        .format(username, password)   # <- tainted", True, "bandit/B608 · confirmed"),
    ("    ).fetchone()", False, None),
    ("", False, None),
    ("app.secret_key = 'aaaaaaa'", True, "CWE-798 · hard-coded secret"),
    ("app.run(host='0.0.0.0', debug=True)", True, "CWE-94 · Werkzeug RCE"),
]


def sc_code(d, p, ctx):
    F = ctx.fonts; mono = F["code"]
    x0, y0, lh = 150, CONTENT_TOP + 70, 58
    beam_y = y0 + ease(p) * (lh * len(CODE) + 10)
    for i, (line, sink, label) in enumerate(CODE):
        ly = y0 + i * lh
        passed = beam_y > ly + lh * 0.5
        col = INK
        if sink and passed:
            col = RD
            d.rectangle([x0 - 14, ly - 6, x0 + 760, ly + 44], fill=blend(RD, 0.10))
        elif sink:
            col = mix(INK, MUTE, 0.3)
        d.text((40, ly + 6), f"{i+1:>2}", font=F["tiny"], fill=MUTE)
        d.text((x0, ly), line, font=mono, fill=col)
        if sink and passed and label:
            la = ease((beam_y - (ly + lh * 0.5)) / 80)
            lx = x0 + 800
            d.line([(x0 + 770, ly + 20), (lx, ly + 20)], fill=blend(RD, la), width=2)
            glow_dot(d, lx, ly + 20, 4, RD, la)
            d.text((lx + 14, ly - 2), label, font=F["label"], fill=blend(AM, la))
    # the scan beam
    if p < 0.98:
        for off, al in ((0, 0.9), (-6, 0.3), (6, 0.3)):
            d.line([(120, beam_y + off), (W - 760, beam_y + off)], fill=blend(CY, al), width=2)
        glow_dot(d, W - 760, beam_y, 6, CY, 0.9)
        d.text((120, beam_y - 34), "▼ SCANNING", font=F["tiny"], fill=CY)


def sc_matrix(d, p, ctx):
    F = ctx.fonts; data = ctx.data
    finds = data["findings"]
    cols, cw, ch, gx, gy = 5, 300, 92, 16, 14
    gw = cols * cw + (cols - 1) * gx
    x0 = (W - gw) // 2; y0 = CONTENT_TOP + 96
    sev_col = {"error": RD, "warning": AM, "note": MUTE}
    shown = 0
    for i, f in enumerate(finds):
        ap = ease((p - 0.05 - i * 0.035) / 0.3)
        if ap <= 0: continue
        shown += 1 if ap > 0.5 else 0
        r, c = divmod(i, cols)
        x = x0 + c * (cw + gx); y = y0 + r * (ch + gy) + int((1 - ap) * 20)
        col = sev_col.get(f["sev"], MUTE)
        d.rectangle([x, y, x + cw, y + ch], fill=blend(PANEL, ap), outline=blend(col, ap), width=2)
        d.rectangle([x, y, x + 6, y + ch], fill=blend(col, ap))
        d.text((x + 18, y + 12), f["cwe"], font=F["mono"], fill=blend(INK, ap))
        d.text((x + 18, y + 50), f"{f['f']}:{f['l']}"[:30], font=F["tiny"], fill=blend(MUTE, ap))
        d.text((x + cw - 70, y + 12), f["rule"], font=F["tiny"], fill=blend(col, ap))
    # live counter
    n = int(ease(p / 0.7) * len(finds))
    big = F["count"]
    lbl = "CONFIRMED VULNERABILITIES"
    d.text((x0, CONTENT_TOP + 8), lbl, font=F["label"], fill=MUTE)
    d.text((x0 + tw(d, lbl, F["label"]) + 24, CONTENT_TOP - 8), f"{n:02d}", font=big, fill=CY)


def sc_flow(d, p, ctx):
    F = ctx.fonts
    nodes = {
        "entry": (300, CMID, "ANON HTTP", "POST /user/login", CY),
        "sqli": (640, CMID - 170, "CWE-89", "SQLi auth bypass", RD),
        "secret": (640, CMID, "CWE-798", "forged session", RD),
        "apikey": (640, CMID + 170, "CWE-330", "predictable key", RD),
        "auth": (1050, CMID, "AUTH CTX", "admin", AM),
        "rce": (1480, CMID, "CWE-94", "Werkzeug RCE", RD),
    }
    edges = [("entry", "sqli"), ("entry", "secret"), ("entry", "apikey"),
             ("sqli", "auth"), ("secret", "auth"), ("apikey", "auth"), ("auth", "rce")]
    order = ["entry", "sqli", "auth", "rce"]   # the executing pulse path

    appear = ease(p / 0.25)
    flow_t = p
    # pulse phase
    pulse_p = clamp((p - 0.55) / 0.4)
    hot = {}
    seg = pulse_p * (len(order) - 1)
    for i in range(len(order)):
        if seg >= i: hot[order[i]] = True
    # edges with flowing particles
    for u, v in edges:
        ux, uy = nodes[u][:2]; vx, vy = nodes[v][:2]
        col = RD if (u in hot and v in hot) else CY
        particles(d, (ux + 130, uy), (vx - 130, vy), flow_t, col, n=6, speed=0.45, r=3)
    # traveling pulse dot
    if 0 < pulse_p < 1:
        i = int(seg); fpart = seg - i
        a = nodes[order[i]][:2]; b = nodes[order[min(i + 1, len(order) - 1)]][:2]
        px, py = lerp(a[0], b[0], fpart), lerp(a[1], b[1], fpart)
        glow_dot(d, px, py, 10, AM, 1.0)
    # nodes
    for key, (x, y, t1, t2, base) in nodes.items():
        a = appear
        on = key in hot
        col = RD if on else base
        wbox, hbox = 130, 64
        rectc = blend(PANEL, a)
        d.rectangle([x - wbox, y - hbox, x + wbox, y + hbox], fill=rectc, outline=blend(col, a), width=3 if on else 2)
        if on:
            for k in (8, 4):
                d.rectangle([x - wbox - k, y - hbox - k, x + wbox + k, y + hbox + k], outline=blend(col, 0.15))
        d.text((x - tw(d, t1, F["mono"]) / 2, y - 30), t1, font=F["mono"], fill=blend(col if on else INK, a))
        d.text((x - tw(d, t2, F["tiny"]) / 2, y + 6), t2, font=F["tiny"], fill=blend(MUTE, a))
    # RCE stamp
    if hot.get("rce"):
        st = "▶ REMOTE CODE EXECUTION"
        sa = ease((pulse_p - 0.85) / 0.15)
        d.text(((W - tw(d, st, F["sub"])) / 2, CONTENT_BOT - 40), st, font=F["sub"], fill=blend(RD, sa))


def sc_kev(d, p, ctx):
    F = ctx.fonts; data = ctx.data
    kev = data["kev"]
    total, ransom = data["kev_total"], data["kev_ransom"]
    # headline counters
    n = int(ease(p / 0.6) * total)
    r = int(ease(p / 0.6) * ransom)
    d.text((150, CONTENT_TOP + 6), "CWE-94 · ACTIVELY EXPLOITED (CISA KEV)", font=F["label"], fill=MUTE)
    d.text((150, CONTENT_TOP + 34), f"{n:02d}", font=F["count"], fill=RD)
    d.text((150 + 150, CONTENT_TOP + 60), "EXPLOITED IN THE WILD", font=F["tiny"], fill=MUTE)
    d.text((520, CONTENT_TOP + 34), f"{r:02d}", font=F["count"], fill=AM)
    d.text((520 + 110, CONTENT_TOP + 60), "RANSOMWARE", font=F["tiny"], fill=MUTE)
    # scrolling ticker
    tx, tw_, ty0, rh = 150, W - 300, CONTENT_TOP + 150, 56
    visible = (CONTENT_BOT - ty0) // rh
    scroll = ease_out(clamp((p - 0.1) / 0.9)) * max(0, len(kev) - visible) * rh
    d.rectangle([tx, ty0, tx + tw_, CONTENT_BOT], outline=BORDER, width=2)
    for i, k in enumerate(kev):
        y = ty0 + 8 + i * rh - scroll
        if y < ty0 - rh or y > CONTENT_BOT: continue
        rc = AM if (k.get("ransom") == "Known") else CY
        d.text((tx + 16, y + 8), k["cve"], font=F["mono"], fill=rc)
        nm = (k["name"] or f"{k['vendor']} {k['prod']}")[:54]
        d.text((tx + 290, y + 12), nm, font=F["tiny"], fill=INK)
        d.text((tx + tw_ - 130, y + 12), "● EXPLOITED", font=F["tiny"], fill=rc)
        d.line([(tx, y + rh), (tx + tw_, y + rh)], fill=GRID)


def sc_outro(d, p, ctx):
    F = ctx.fonts
    cx = W // 2; a = ease(p / 0.4)
    d.text((cx - tw(d, "CROSSVIEW", F["title"]) / 2, CMID - 150), "CROSSVIEW", font=F["title"], fill=blend(INK, a))
    rw = int(560 * ease((p - 0.2) / 0.4)); d.rectangle([cx - rw // 2, CMID + 6, cx + rw // 2, CMID + 9], fill=CY)
    stats = ctx.spec.get("subtitle", "15 FINDINGS · 1 CHAIN · MITRE-MAPPED")
    d.text((cx - tw(d, stats, F["sub"]) / 2, CMID + 34), stats, font=F["sub"], fill=blend(CY, ease((p - 0.3) / 0.4)))
    tag = ctx.spec.get("tagline", "")
    if tag:
        d.text((cx - tw(d, tag, F["label"]) / 2, CMID + 110), tag, font=F["label"], fill=blend(AM, ease((p - 0.45) / 0.4)))


SCENES = {"title": sc_title, "code": sc_code, "matrix": sc_matrix,
          "flow": sc_flow, "kev": sc_kev, "outro": sc_outro}


def _dur(p): return float(subprocess.check_output(
    ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(p)], text=True).strip())


def _run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"cmd failed ({r.returncode}): {' '.join(map(str, cmd))[:160]}\n"
                           f"STDERR: {r.stderr[-900:]}")
    return r


def _fonts():
    return {"title": _font("DejaVu Sans:bold", 120), "sub": _font("DejaVu Sans Mono", 40),
            "word": _font("DejaVu Sans Mono:bold", 30), "banner": _font("DejaVu Sans Mono", 24),
            "label": _font("DejaVu Sans Mono", 26), "tiny": _font("DejaVu Sans Mono", 22),
            "mono": _font("DejaVu Sans Mono:bold", 34), "code": _font("DejaVu Sans Mono", 34),
            "count": _font("DejaVu Sans:bold", 78)}


def _seg_dur(seg):
    return float(seg["duration"]) if seg.get("duration") else (_dur(Path(seg["vo"])) + 0.5)


def _workdir(spec):
    w = Path(spec["out"]).parent / "_cine_work"; w.mkdir(parents=True, exist_ok=True); return w


def render_one(spec: dict, si: int) -> None:
    """Render scene `si` to work/c{si}.mp4 + work/a{si}.wav, then exit. Designed
    to run as a short-lived subprocess so memory is fully reclaimed per scene."""
    work = _workdir(spec); fonts = _fonts()
    segs = spec["segments"]; n = len(segs); seg = segs[si]
    dur = _seg_dur(seg)
    sctx = Ctx(data=spec["data"], spec={**spec, **seg}, fonts=fonts)
    base = chrome_base(sctx, f"{si+1:02d} / {n:02d}")
    fn = SCENES[seg["scene"]]
    nframes = max(int(round(dur * FPS)), 1)
    fdir = work / f"s{si}"
    if fdir.exists():
        shutil.rmtree(fdir)
    fdir.mkdir(parents=True)
    for fi in range(nframes):
        img = base.copy(); fn(ImageDraw.Draw(img), fi / max(nframes - 1, 1), sctx)
        img.save(fdir / f"{fi:04d}.png")
    _run(["ffmpeg", "-y", "-framerate", str(FPS), "-start_number", "0", "-i", str(fdir / "%04d.png"),
          "-c:v", "libx264", "-preset", "medium", "-crf", "19", "-pix_fmt", "yuv420p", str(work / f"c{si}.mp4")])
    shutil.rmtree(fdir, ignore_errors=True)
    a = work / f"a{si}.wav"
    if seg.get("vo"):
        _run(["ffmpeg", "-y", "-i", str(seg["vo"]),
              "-af", f"adelay=200|200,apad,atrim=0:{dur:.3f},aresample=48000", "-ac", "2", str(a)])
    else:
        _run(["ffmpeg", "-y", "-f", "lavfi", "-t", f"{dur:.3f}", "-i", "anullsrc=r=48000:cl=stereo", str(a)])


def assemble(spec: dict) -> str:
    """Concatenate per-scene clips + audio (from render_one) → final video."""
    out = Path(spec["out"]); work = _workdir(spec)
    segs = spec["segments"]; n = len(segs)
    durs = [_seg_dur(s) for s in segs]
    total = sum(durs)
    clips = [work / f"c{si}.mp4" for si in range(n)]
    vo_parts = [work / f"a{si}.wav" for si in range(n)]
    (work / "v.txt").write_text("".join(f"file '{c}'\n" for c in clips))
    slides = work / "slides.mp4"
    _run(["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(work / "v.txt"), "-c", "copy", str(slides)])
    (work / "a.txt").write_text("".join(f"file '{p}'\n" for p in vo_parts))
    vot = work / "vo.wav"
    _run(["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(work / "a.txt"), "-c", "copy", str(vot)])
    mix = work / "mix.wav"
    duck = (f"[0:a]aloop=loop=-1:size=2e9,atrim=0:{total:.3f},afade=t=in:st=0:d=1.2,"
            f"afade=t=out:st={total-1.6:.3f}:d=1.6,volume=0.55,aresample=48000[bed];"
            "[1:a]aresample=48000,asplit=2[v1][v2];"
            "[bed][v1]sidechaincompress=threshold=0.025:ratio=7:attack=5:release=320[bd];"
            "[bd][v2]amix=inputs=2:normalize=0,alimiter=limit=0.95[mx]")
    _run(["ffmpeg", "-y", "-i", str(spec["music"]), "-i", str(vot), "-filter_complex", duck,
          "-map", "[mx]", "-c:a", "pcm_s16le", str(mix)])

    fc = ("color=c=0x58c8ff@0.06:s=1920x4:r=30[scan];"
          f"[0:v][scan]overlay=0:y='mod(t*160\\,{H})'[v1];"
          f"[1:a]showwaves=s={W}x{WAVE_H}:mode=cline:colors=0x58c8ff|0xf0b35a:scale=sqrt,"
          "format=rgba,colorchannelmixer=aa=0.9[wave];"
          f"[v1][wave]overlay=0:{H-WAVE_H}[v2];"
          f"[v2]fade=t=in:st=0:d=0.6,fade=t=out:st={total-0.8:.3f}:d=0.8[vout]")
    _run(["ffmpeg", "-y", "-i", str(slides), "-i", str(mix), "-filter_complex", fc,
          "-map", "[vout]", "-map", "1:a", "-c:v", "libx264", "-preset", "medium", "-crf", "20",
          "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "192k", "-movflags", "+faststart",
          "-shortest", str(out)])
    return str(out)


def render(spec: dict) -> str:
    """In-process fallback (small jobs). For memory-constrained hosts, prefer
    the per-scene subprocess path via the CLI (`one` / `finish`)."""
    for si in range(len(spec["segments"])):
        render_one(spec, si)
    return assemble(spec)


if __name__ == "__main__":
    import json
    import sys
    mode, spec_path = sys.argv[1], sys.argv[2]
    _spec = json.loads(Path(spec_path).read_text())
    if mode == "one":
        render_one(_spec, int(sys.argv[3]))
    elif mode == "finish":
        print(assemble(_spec))
    else:
        raise SystemExit(f"unknown mode {mode!r}")
