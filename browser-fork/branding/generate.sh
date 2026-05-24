#!/usr/bin/env bash
# generate.sh — produce browser-fork/branding/generated/ from the source logo.
#
# Idempotent. Re-run after replacing browser-fork/branding/source/anonymous-logo.png
# to refresh every downstream icon.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="$HERE/source"
OUT_DIR="$HERE/generated"
mkdir -p "$OUT_DIR"

SRC="$SOURCE_DIR/anonymous-logo.png"
SQUARE="$SOURCE_DIR/anonymous-logo-square.png"

[[ -f "$SRC" ]] || { echo "error: $SRC missing" >&2; exit 1; }

python3 - "$SRC" "$SQUARE" "$OUT_DIR" <<'PY'
import sys, shutil, statistics
from PIL import Image

src_path, sq_path, out_dir = sys.argv[1:]

img = Image.open(src_path).convert("RGBA")
w, h = img.size

# ---- 1. auto-trim borders (uniform/near-empty rows/cols) ----

def row_var(y):
    row = [img.getpixel((x, y)) for x in range(w)]
    luma = [int(0.3*r + 0.59*g + 0.11*b) for (r, g, b, a) in row]
    return statistics.pstdev(luma) if len(luma) > 1 else 0

def col_var(x):
    col = [img.getpixel((x, y)) for y in range(h)]
    luma = [int(0.3*r + 0.59*g + 0.11*b) for (r, g, b, a) in col]
    return statistics.pstdev(luma) if len(luma) > 1 else 0

T = 8
top    = next(y for y in range(h)        if row_var(y) > T)
bottom = next(y for y in range(h-1, -1, -1) if row_var(y) > T)
left   = next(x for x in range(w)        if col_var(x) > T)
right  = next(x for x in range(w-1, -1, -1) if col_var(x) > T)
cropped = img.crop((left, top, right + 1, bottom + 1))

# ---- 2. square-pad with average of source corners ----

corners = [img.getpixel((0, 0)),     img.getpixel((w-1, 0)),
           img.getpixel((0, h-1)),   img.getpixel((w-1, h-1))]
bg = tuple(sum(c[i] for c in corners) // 4 for i in range(4))

cw, ch = cropped.size
side = max(cw, ch)
square = Image.new("RGBA", (side, side), bg)
square.paste(cropped, ((side - cw)//2, (side - ch)//2), cropped)
square.save(sq_path, optimize=True)

# ---- 3. emit every size we need ----

sizes = [16, 22, 24, 32, 48, 64, 96, 128, 192, 256, 512]
for s in sizes:
    out = f"{out_dir}/icon-{s}.png"
    square.resize((s, s), Image.LANCZOS).save(out, optimize=True)

# Aliases for Mullvad-tree drop-ins
for s in [16, 32, 48, 64, 128]:
    shutil.copy(f"{out_dir}/icon-{s}.png", f"{out_dir}/default{s}.png")

shutil.copy(f"{out_dir}/icon-48.png", f"{out_dir}/updater.png")
shutil.copy(f"{out_dir}/icon-32.png", f"{out_dir}/anonymous-toolkit.png")

print(f"wrote {len(sizes) + 7} files to {out_dir}", file=sys.stderr)
PY
