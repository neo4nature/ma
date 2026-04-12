from __future__ import annotations

import io
import hashlib
from dataclasses import dataclass
from typing import Literal, Tuple

from PIL import Image, ImageFilter

BgMode = Literal["auto", "white", "gradient", "blur"]


@dataclass
class ProcessedMedia:
    cutout_png: bytes
    studio_png: bytes
    cutout_sha256: str
    studio_sha256: str


def _sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _img_to_png_bytes(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def _estimate_bg_color(img: Image.Image) -> Tuple[int, int, int]:
    """Estimate background color by averaging corner samples."""
    rgb = img.convert("RGB")
    w, h = rgb.size
    samples = []
    # small squares in corners
    step = max(2, min(w, h) // 40)
    for (x0, y0) in [(0, 0), (w - step, 0), (0, h - step), (w - step, h - step)]:
        for y in range(y0, min(h, y0 + step)):
            for x in range(x0, min(w, x0 + step)):
                samples.append(rgb.getpixel((x, y)))
    if not samples:
        return (255, 255, 255)
    r = sum(p[0] for p in samples) // len(samples)
    g = sum(p[1] for p in samples) // len(samples)
    b = sum(p[2] for p in samples) // len(samples)
    return (int(r), int(g), int(b))


def _color_distance(a: Tuple[int, int, int], b: Tuple[int, int, int]) -> float:
    return ((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2 + (a[2] - b[2]) ** 2) ** 0.5


def _make_simple_mask(img: Image.Image, bg: Tuple[int, int, int]) -> Image.Image:
    """Create a simple alpha mask based on distance to background color.

    This is intentionally lightweight (no ML). Works best for product photos
    on relatively uniform backgrounds.
    """
    rgb = img.convert("RGB")
    w, h = rgb.size

    # Adaptive threshold: base + a bit of image variance
    # Compute quick variance from sparse grid
    grid = 20
    step_x = max(1, w // grid)
    step_y = max(1, h // grid)
    ds = []
    for y in range(0, h, step_y):
        for x in range(0, w, step_x):
            ds.append(_color_distance(rgb.getpixel((x, y)), bg))
    avg = sum(ds) / max(1, len(ds))
    var = sum((d - avg) ** 2 for d in ds) / max(1, len(ds))
    thresh = max(18.0, min(60.0, 20.0 + (var ** 0.5) * 0.25))

    mask = Image.new("L", (w, h), 0)
    px = mask.load()
    for y in range(h):
        for x in range(w):
            d = _color_distance(rgb.getpixel((x, y)), bg)
            # Soft edge: map [thresh-8, thresh+8] into [0..255]
            if d <= thresh - 8:
                a = 0
            elif d >= thresh + 8:
                a = 255
            else:
                a = int(((d - (thresh - 8)) / 16.0) * 255)
            px[x, y] = a

    # Smooth edges a bit
    mask = mask.filter(ImageFilter.GaussianBlur(radius=max(1, min(w, h) // 300)))
    return mask


def cutout_product(img: Image.Image) -> Image.Image:
    """Return RGBA image with background removed (simple heuristic)."""
    bg = _estimate_bg_color(img)
    mask = _make_simple_mask(img, bg)
    rgba = img.convert("RGBA")
    rgba.putalpha(mask)
    return rgba


def _dominant_color_from_alpha(rgba: Image.Image) -> Tuple[int, int, int]:
    """Estimate a pleasant accent color from non-transparent pixels."""
    img = rgba.convert("RGBA")
    w, h = img.size
    px = img.load()
    r_sum = g_sum = b_sum = n = 0
    # sample grid for speed
    step = max(1, min(w, h) // 80)
    for y in range(0, h, step):
        for x in range(0, w, step):
            r, g, b, a = px[x, y]
            if a > 120:
                r_sum += r
                g_sum += g
                b_sum += b
                n += 1
    if n == 0:
        return (200, 200, 200)
    return (r_sum // n, g_sum // n, b_sum // n)


def _make_gradient_bg(size: Tuple[int, int], color: Tuple[int, int, int]) -> Image.Image:
    w, h = size
    base = Image.new("RGB", size, (255, 255, 255))
    # Create vertical gradient to a very light tint of the dominant color
    tint = tuple(int(255 - (255 - c) * 0.18) for c in color)
    grad = Image.new("RGB", (1, h))
    for y in range(h):
        t = y / max(1, h - 1)
        r = int(255 * (1 - t) + tint[0] * t)
        g = int(255 * (1 - t) + tint[1] * t)
        b = int(255 * (1 - t) + tint[2] * t)
        grad.putpixel((0, y), (r, g, b))
    grad = grad.resize((w, h))
    base.paste(grad)
    return base


def compose_studio(
    original: Image.Image,
    cutout: Image.Image,
    mode: BgMode = "auto",
) -> Image.Image:
    """Compose a "studio" image: clean background + soft shadow."""
    w, h = original.size

    if mode == "blur":
        bg = original.convert("RGB").filter(ImageFilter.GaussianBlur(radius=max(4, min(w, h) // 60)))
    elif mode == "white":
        bg = Image.new("RGB", (w, h), (255, 255, 255))
    elif mode == "gradient":
        bg = _make_gradient_bg((w, h), _dominant_color_from_alpha(cutout))
    else:  # auto
        # choose gradient if background is busy, otherwise white
        bg_color = _estimate_bg_color(original)
        busy = _color_distance(bg_color, (255, 255, 255)) > 35
        bg = _make_gradient_bg((w, h), _dominant_color_from_alpha(cutout)) if busy else Image.new("RGB", (w, h), (255, 255, 255))

    # Add subtle shadow under object
    shadow = cutout.split()[-1].copy()
    shadow = shadow.filter(ImageFilter.GaussianBlur(radius=max(6, min(w, h) // 45)))
    shadow_rgba = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    shadow_rgba.putalpha(shadow.point(lambda a: int(a * 0.25)))

    out = bg.convert("RGBA")
    out.alpha_composite(shadow_rgba)
    out.alpha_composite(cutout)
    return out


def process_product_photos(
    image_bytes: bytes,
    studio_mode: BgMode = "auto",
    max_size: int = 1200,
) -> ProcessedMedia:
    """Process single product photo into cutout + studio PNGs.

    Notes:
    - lightweight heuristic background removal
    - downscales very large images for speed
    """
    img = Image.open(io.BytesIO(image_bytes))
    img = img.convert("RGBA")

    # Downscale if needed
    w, h = img.size
    scale = 1.0
    if max(w, h) > max_size:
        scale = max_size / float(max(w, h))
        img = img.resize((int(w * scale), int(h * scale)), Image.Resampling.LANCZOS)

    original = img.convert("RGB")
    cutout = cutout_product(original)
    studio = compose_studio(original, cutout, mode=studio_mode)

    cutout_png = _img_to_png_bytes(cutout)
    studio_png = _img_to_png_bytes(studio)

    return ProcessedMedia(
        cutout_png=cutout_png,
        studio_png=studio_png,
        cutout_sha256=_sha256(cutout_png),
        studio_sha256=_sha256(studio_png),
    )
