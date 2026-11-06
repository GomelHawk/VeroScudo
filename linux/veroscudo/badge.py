"""The keep-awake badge on the tray icon: a small green ring in the bottom-right corner, drawn over the state icon while
Keep awake is on - the same mark as the Windows tray (VeroTrayIcon.WithAwakeBadge in VeroScudo.Tray.cs). There is no
asset for it: it is drawn from the icon's own pixels, so every state and size gets it. Pure Python on an RGBA buffer, so
the Linux tray (GdkPixbuf) and the macOS menu bar can both use it."""
from __future__ import annotations

DARK = (20, 20, 20)
GREEN = (46, 204, 64)
_SS = 4                      # samples per pixel side: smooth edges without a graphics library


def _paint(px: bytearray, i: int, rgb: tuple[int, int, int], cover: float) -> None:
    """Blends one colour over pixel i (RGBA, straight alpha) with the given coverage."""
    if cover <= 0:
        return
    a = px[i + 3] / 255.0
    out_a = cover + a * (1 - cover)
    for k in range(3):
        c = (rgb[k] * cover + px[i + k] * a * (1 - cover)) / out_a
        px[i + k] = max(0, min(255, round(c)))
    px[i + 3] = max(0, min(255, round(out_a * 255)))


def awake_badge(rgba: bytes, size: int) -> bytes:
    """`rgba`: a size x size icon, 4 bytes per pixel, rows packed. Returns a copy with the badge: a dark disc 7/16 of the
    icon wide, a green ring in it and a dark centre (the Windows geometry, scaled from 16 px). Pure."""
    if len(rgba) != size * size * 4:
        raise ValueError(f"expected {size}x{size} RGBA ({size * size * 4} bytes), got {len(rgba)}")
    px = bytearray(rgba)
    u = size / 16.0
    d = 7.0 * u
    x0 = size - d
    border, hole = 1.4 * u, 1.4 * u + 1.6 * u
    cx = cy = x0 + d / 2
    rings = ((DARK, d / 2), (GREEN, d / 2 - border), (DARK, d / 2 - hole))   # painted in this order, each over the last
    first = max(0, int(x0) - 1)
    for y in range(first, size):
        for x in range(first, size):
            for rgb, r in rings:
                n = 0
                for sy in range(_SS):
                    for sx in range(_SS):
                        dx = x + (sx + 0.5) / _SS - cx
                        dy = y + (sy + 0.5) / _SS - cy
                        n += dx * dx + dy * dy <= r * r
                _paint(px, (y * size + x) * 4, rgb, n / (_SS * _SS))
    return bytes(px)
