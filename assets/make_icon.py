"""
Generate the PWNAudit NetScope app icon (.ico) directly from a
re-implementation of the official PWNAudit mark — no external image needed.

Run as part of BUILD.bat. Produces assets/pwnaudit.ico (multi-resolution).
"""
from __future__ import annotations

import os
from PIL import Image, ImageDraw

ICON_SIZES = (16, 20, 24, 32, 40, 48, 64, 96, 128, 256)

BG = (3, 3, 3, 255)
TEAL = (0, 245, 180, 255)
WHITE = (247, 248, 250, 255)

DIAMONDS = [
    (16.5, 25.5, TEAL),
    (16.5, 44.5, TEAL),
    (30.5, 35.5, TEAL),
    (32.5, 14.5, WHITE),
    (32.5, 55.5, WHITE),
]
CHEVRON = [(44, 19), (60, 35), (44, 51), (31, 51), (47, 35), (31, 19)]
DIAMOND_HALF = 11 * 1.41421356 / 2.0


def _draw_diamond(draw, cx, cy, half, fill):
    points = [
        (cx, cy - half),
        (cx + half, cy),
        (cx, cy + half),
        (cx - half, cy),
    ]
    draw.polygon(points, fill=fill)


def render(size: int) -> Image.Image:
    """Render the icon at a given pixel size, super-sampled for smooth edges."""
    scale = 4 if size <= 96 else 2
    big = size * scale
    s = big / 64.0

    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img, "RGBA")

    radius = int(12 * s)
    draw.rounded_rectangle([(0, 0), (big, big)], radius=radius, fill=BG)

    half = DIAMOND_HALF * s
    for cx, cy, color in DIAMONDS:
        _draw_diamond(draw, cx * s, cy * s, half, color)

    chev = [(x * s, y * s) for x, y in CHEVRON]
    draw.polygon(chev, fill=WHITE)

    return img.resize((size, size), Image.LANCZOS)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(here, "pwnaudit.ico")

    images = [render(s) for s in ICON_SIZES]
    largest = images[-1]
    largest.save(
        out,
        format="ICO",
        sizes=[(s, s) for s in ICON_SIZES],
    )
    # Also drop a 256x256 PNG for documentation / installer banner
    images[-1].save(os.path.join(here, "pwnaudit-256.png"))
    print(f"Wrote {out} ({len(ICON_SIZES)} resolutions)")


if __name__ == "__main__":
    main()
