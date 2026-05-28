#!/usr/bin/env python3
# strip-background.py — produce a transparent-background version of
# anonymous-logo-square.png and regenerate every downstream icon.
#
# What the source looks like:
#   - 1840x1840 RGBA PNG
#   - black fill (RGB ~0,0,0) over a rounded-square area
#   - a thin amber rounded-rectangle border touching the image edge
#   - the Firefox-flame swirl + Guy Fawkes mask in amber inside the border
#
# What we produce:
#   - alpha = max(R,G,B) so black -> transparent, amber -> opaque
#     RGB demultiplied so amber composites cleanly on any background
#   - the outer amber border (its own connected component, touching
#     the image edge) is masked out so only flame + mask remain
#
# Idempotent — re-run after replacing source/anonymous-logo-square.png.

import sys, shutil
from pathlib import Path

import numpy as np
from PIL import Image, ImageFilter
from scipy.ndimage import label

HERE = Path(__file__).resolve().parent
SRC  = HERE / "source" / "anonymous-logo-square.png"
OUT  = HERE / "generated"
SQ_TRANSPARENT = HERE / "source" / "anonymous-logo-square-transparent.png"

if not SRC.exists():
    sys.exit(f"error: {SRC} missing")

OUT.mkdir(parents=True, exist_ok=True)

# 1. Load + numpy view.
img = Image.open(SRC).convert("RGBA")
arr = np.array(img)                                # (H, W, 4) uint8
rgb = arr[..., :3]
H, W, _ = arr.shape

# 2. Build a "this pixel is amber" mask. Amber pixels have ANY channel
#    above ~50 (the black background sits at 0-20 with anti-alias).
#    Threshold 50 cleanly splits the background from foreground without
#    cutting into amber anti-alias edges.
amber_mask = rgb.max(axis=2) > 50                   # (H, W) bool

# 3. Find connected components of amber pixels and mark the one(s)
#    that touch the image edge as "border" — those are what we strip.
#    The flame + mask form one or more components that are bounded
#    INSIDE the rounded-square frame; they don't touch the edge.
labels, n_components = label(amber_mask)            # 8-conn by default? actually 4-conn for default structure

# Component IDs that touch any image-edge pixel.
edge_ids = set()
edge_ids.update(np.unique(labels[0,  :]))
edge_ids.update(np.unique(labels[-1, :]))
edge_ids.update(np.unique(labels[:,  0]))
edge_ids.update(np.unique(labels[:, -1]))
edge_ids.discard(0)                                 # 0 = "not labeled" (background)

print(f"found {n_components} amber components; "
      f"{len(edge_ids)} touch the image edge", file=sys.stderr)

border_mask = np.isin(labels, list(edge_ids))       # (H, W) bool

# 4. Compute alpha with a contrast-boosted ramp.
#
#    Using max(R,G,B) directly as alpha (the obvious approach) gives
#    solid amber pixels alpha ~208 — semi-transparent. That makes the
#    icon look DIM and BLURRY at small sizes because the anti-alias
#    LANCZOS filter then mixes those low-alpha solids with neighboring
#    transparent pixels.
#
#    Instead, ramp linearly from LOW (treated as fully transparent) to
#    HIGH (treated as fully opaque) with the rest in between. With
#    HIGH=80 every actual amber pixel (max channel >= 100) is alpha
#    255, so resizing keeps the lines crisp. Anti-alias band 20..80
#    preserves smooth edges where the source painter blended amber
#    into black.
LOW  = 20.0
HIGH = 80.0
m = rgb.max(axis=2).astype(np.float32)
alpha_f = np.clip((m - LOW) / (HIGH - LOW) * 255.0, 0.0, 255.0)
alpha = alpha_f.astype(np.uint16)
alpha[border_mask] = 0

# 5. Demultiply: where alpha < 255 (anti-alias band), scale RGB up so
#    the pixel composites back to its on-black appearance on dark
#    surfaces AND looks like full-saturation amber on any other.
#    For pixels at alpha 255 this is a no-op (orig * 255 / 255).
#
#    Avoid divide-by-zero where alpha == 0.
new_rgb = rgb.astype(np.uint16)
nz = alpha > 0
new_rgb[nz] = np.minimum(
    255,
    (rgb[nz].astype(np.uint16) * 255 + alpha[nz, None] // 2) // alpha[nz, None],
)

out_arr = np.dstack([new_rgb.astype(np.uint8), alpha.astype(np.uint8)])
out_img = Image.fromarray(out_arr, "RGBA")
out_img.save(SQ_TRANSPARENT, optimize=True)
print(f"wrote {SQ_TRANSPARENT}", file=sys.stderr)

# 6. Resize to every size we need. Mirror the sizes generate.sh emits
#    so dist tarballs / Mac iconset / Linux hicolor stay consistent.
#
#    LANCZOS softens line-art slightly; a small unsharp mask pass
#    brings the flame outlines back into focus without overshoot.
sizes = [16, 22, 24, 32, 48, 64, 96, 128, 192, 256, 512]
USM = ImageFilter.UnsharpMask(radius=0.7, percent=120, threshold=2)
for s in sizes:
    out = OUT / f"icon-{s}.png"
    resized = out_img.resize((s, s), Image.LANCZOS)
    # Skip the unsharp at the smallest sizes — at 16/22/24 the kernel
    # blows out sub-pixel features and produces speckles.
    if s >= 32:
        resized = resized.filter(USM)
    resized.save(out, optimize=True)

# Drop-in aliases the Mullvad/Firefox tree expects.
for s in [16, 32, 48, 64, 128]:
    shutil.copy(OUT / f"icon-{s}.png", OUT / f"default{s}.png")
shutil.copy(OUT / "icon-48.png", OUT / "updater.png")
shutil.copy(OUT / "icon-32.png", OUT / "anonymous-toolkit.png")

print(f"wrote {len(sizes) + 7} transparent icons to {OUT}", file=sys.stderr)
