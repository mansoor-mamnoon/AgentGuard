"""
Generate docs/results.png — ablation results screenshot for README pinning.

Usage:
    uv run python scripts/make_results_png.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from PIL import Image, ImageDraw, ImageFont

W, H = 900, 480
FONT_SIZE = 14
LINE_H = 22
PAD_X = 36
PAD_Y = 30

BG = (13, 17, 23)
CARD = (22, 27, 34)
BORDER = (48, 54, 61)
WHITE = (201, 209, 217)
GREEN = (86, 211, 100)
RED = (248, 81, 73)
YELLOW = (227, 179, 65)
ORANGE = (255, 160, 60)
CYAN = (121, 192, 255)
DIM = (110, 118, 129)
BLUE = (88, 166, 255)

FONT_PATH = "/System/Library/Fonts/Menlo.ttc"

try:
    font = ImageFont.truetype(FONT_PATH, FONT_SIZE, index=0)
    font_bold = ImageFont.truetype(FONT_PATH, FONT_SIZE + 1, index=1)
    font_large = ImageFont.truetype(FONT_PATH, 18, index=1)
    font_small = ImageFont.truetype(FONT_PATH, 12, index=0)
except OSError:
    font = font_bold = font_large = font_small = ImageFont.load_default()


def rounded_rect(draw: ImageDraw.ImageDraw, xy, radius=8, fill=None, outline=None, width=1):
    x0, y0, x1, y1 = xy
    draw.rounded_rectangle(xy, radius=radius, fill=fill, outline=outline, width=width)


def make_bar(draw: ImageDraw.ImageDraw, x: int, y: int, frac: float, color, w=120, h=10):
    draw.rounded_rectangle([x, y, x + w, y + h], radius=3, fill=(30, 38, 50))
    if frac > 0:
        fill_w = max(4, int(frac * w))
        draw.rounded_rectangle([x, y, x + fill_w, y + h], radius=3, fill=color)


def main():
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # ── title bar ─────────────────────────────────────────────────────────
    d.rectangle([0, 0, W, 52], fill=(22, 27, 34))
    d.rectangle([0, 50, W, 52], fill=BORDER)
    d.ellipse([18, 17, 30, 29], fill=(255, 95, 87))
    d.ellipse([40, 17, 52, 29], fill=(255, 189, 46))
    d.ellipse([62, 17, 74, 29], fill=(39, 201, 63))

    title = "Prompt Injection Lab — Ablation Study Results"
    tw = d.textlength(title, font=font_large)
    d.text(((W - tw) / 2, 14), title, font=font_large, fill=WHITE)

    y = 72

    # ── headline metrics ──────────────────────────────────────────────────
    metrics = [
        ("Attack Success Rate", "16%", "full system", GREEN),
        ("False Positive Rate", "8.3%", "within 15% budget", YELLOW),
        ("p95 Latency", "0.3 ms", "per query", BLUE),
        ("Defense Layers", "4", "heuristic·semantic·gate·doc", CYAN),
    ]

    card_w = (W - PAD_X * 2 - 24) // 4
    for i, (label, value, sub, color) in enumerate(metrics):
        cx = PAD_X + i * (card_w + 8)
        rounded_rect(d, [cx, y, cx + card_w, y + 72], radius=6, fill=CARD, outline=BORDER, width=1)
        vw = d.textlength(value, font=font_large)
        d.text((cx + (card_w - vw) / 2, y + 8), value, font=font_large, fill=color)
        lw = d.textlength(label, font=font_small)
        d.text((cx + (card_w - lw) / 2, y + 32), label, font=font_small, fill=WHITE)
        sw = d.textlength(sub, font=font_small)
        d.text((cx + (card_w - sw) / 2, y + 50), sub, font=font_small, fill=DIM)

    y += 88

    # ── ablation table ────────────────────────────────────────────────────
    rounded_rect(d, [PAD_X, y, W - PAD_X, y + 264], radius=8, fill=CARD, outline=BORDER, width=1)

    table_x = PAD_X + 16
    ty = y + 16

    # header
    headers = [
        ("Configuration", 180),
        ("Description", 260),
        ("ASR", 60),
        ("FPR", 60),
        ("TDR", 60),
        ("p95 ms", 72),
    ]
    hx = table_x
    for hdr, col_w in headers:
        d.text((hx, ty), hdr, font=font_bold, fill=DIM)
        hx += col_w
    ty += LINE_H

    # separator
    d.line([table_x, ty, W - PAD_X - 16, ty], fill=BORDER, width=1)
    ty += 8

    rows = [
        ("no_defense", "No defense — always allow", 1.00, 0.00, 1.00, 0.0, RED),
        ("regex_only", "Heuristic regex only", 0.20, 0.00, 1.00, 0.3, ORANGE),
        ("no_semantic", "No semantic drift layer", 0.20, 0.00, 1.00, 0.3, ORANGE),
        ("no_gate", "No tool gate layer", 0.16, 0.083, 0.917, 0.3, YELLOW),
        ("no_doc", "No doc density layer", 0.16, 0.083, 0.917, 0.3, YELLOW),
        ("full (4-layer)", "All four signal layers (default)", 0.16, 0.083, 0.917, 0.3, GREEN),
    ]

    for name, desc, asr, fpr, tdr, p95, color in rows:
        hx = table_x
        # config name
        d.text((hx, ty), name, font=font_bold if name == "full (4-layer)" else font, fill=color)
        hx += 180
        # description
        d.text((hx, ty), desc, font=font, fill=WHITE if name == "full (4-layer)" else DIM)
        hx += 260
        # ASR
        d.text((hx, ty), f"{asr:.0%}", font=font, fill=color)
        hx += 60
        # FPR
        d.text((hx, ty), f"{fpr:.1%}", font=font, fill=DIM)
        hx += 60
        # TDR
        d.text((hx, ty), f"{tdr:.1%}", font=font, fill=DIM)
        hx += 60
        # p95
        d.text((hx, ty), f"{p95:.1f}", font=font, fill=DIM)
        ty += LINE_H

    ty += 8

    # note
    note = "Each configuration calibrated independently to FPR ≤ 15%  ·  50 attacks + 12 benign  ·  semantic layer catches synonym-evading attacks regex misses"
    nw = d.textlength(note, font=font_small)
    d.text(((W - nw) / 2, ty + 8), note, font=font_small, fill=DIM)

    # ── footer ────────────────────────────────────────────────────────────
    footer = "github.com/muneermamnoon/prompt-injection-lab"
    fw = d.textlength(footer, font=font_small)
    d.text(((W - fw) / 2, H - 20), footer, font=font_small, fill=BORDER)

    out = Path(__file__).parent.parent / "docs" / "results.png"
    img.save(out, "PNG", optimize=True)
    print(f"Saved {out}  ({out.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
