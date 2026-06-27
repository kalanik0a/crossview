#!/usr/bin/env python3
"""Render site/og-card.png — the 1280x640 social/preview card — from the cinematic
case-study video's flow-graph frame. Output is the GitHub social-preview image and
the page's og:image. Pulls the source video from the media library (CROSSVIEW_MEDIA_DIR)."""
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO = Path(__file__).resolve().parents[1]
MEDIA = Path(os.environ.get("CROSSVIEW_MEDIA_DIR",
                            os.path.expanduser("~/Videos/visionlighter/crossview")))
VIDEO = MEDIA / "case-study" / "case-study.mp4"
OUT = REPO / "site" / "og-card.png"
W, H = 1280, 640
BG = (7, 9, 13); CY = (88, 200, 255); AM = (240, 179, 90); INK = (232, 242, 246); MUTE = (140, 160, 172)


def _font(name, size):
    p = subprocess.check_output(["fc-match", "-f", "%{file}", name], text=True).strip()
    return ImageFont.truetype(p, size)


def main():
    if not VIDEO.exists():
        raise SystemExit(f"source video not found: {VIDEO}")
    tmp = Path(tempfile.mkdtemp()) / "frame.png"
    subprocess.run(["ffmpeg", "-y", "-ss", "44", "-i", str(VIDEO), "-frames:v", "1", str(tmp)],
                   check=True, capture_output=True)
    src = Image.open(tmp).convert("RGB").resize((1280, 720), Image.LANCZOS).crop((0, 40, 1280, 680))
    card = Image.new("RGB", (W, H), BG); card.paste(src, (0, 0))
    d = ImageDraw.Draw(card, "RGBA")
    for i, y in enumerate(range(H - 210, H)):
        d.line([(0, y), (W, y)], fill=(7, 9, 13, int(255 * (i / 210) * 0.94)))
    for x in range(0, 260):
        d.line([(x, 0), (x, H)], fill=(7, 9, 13, int(150 * (1 - x / 260))))
    d.polygon([(40, 30), (40, 58), (56, 44)], fill=CY)
    d.text((68, 28), "CROSSVIEW", font=_font("DejaVu Sans Mono:bold", 36), fill=CY)
    d.text((W - 360, 32), "// OPEN-SOURCE · SELF-HOSTED", font=_font("DejaVu Sans Mono", 20), fill=AM)
    d.text((48, H - 168), "MITRE silo + 5-stage code scanner", font=_font("DejaVu Sans:bold", 52), fill=INK)
    d.text((48, H - 104), "CWE · CAPEC · ATT&CK · ATLAS · D3FEND · UKC + NVD/KEV + LLM intel fusion",
           font=_font("DejaVu Sans Mono", 23), fill=CY)
    d.text((48, H - 60), "Anonymous HTTP → RCE, mapped to MITRE, prioritized by CISA KEV",
           font=_font("DejaVu Sans Mono", 21), fill=MUTE)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    card.save(OUT)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
