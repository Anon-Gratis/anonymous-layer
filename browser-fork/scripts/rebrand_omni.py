#!/usr/bin/env python3
"""rebrand_omni.py — rewrite browser branding inside an extracted omni.ja.

Invoked by rebrand.sh / rebrand-firefox.sh after unzipping an omni.ja
into a temp dir. Handles BOTH base browsers:
  - Mullvad Browser  (string forms: "Mullvad Browser", "MullvadBrowser",
                      brand.ftl right-hand-sides like "Mullvad Browser")
  - Vanilla Firefox  (string forms: "Firefox", "Mozilla Firefox",
                      brand.ftl right-hand-sides like "Firefox")

Operates in-place on text files (brand.ftl, brand.properties, wordmark
.ftl), preserves the rest, and rewrites the in-archive toolkit icon
with our generated one.

What we change (user-visible):
  - All locale brand.ftl files: -brand-*-name = Anonymous
  - All locale brand.properties files: brand*Name=Anonymous
  - All locale *about-wordmark-en.ftl: wordmark = ANONYMOUS
  - chrome/toolkit/skin/classic/global/icons/{mullvadbrowser,firefox}.png:
        replaced with our generated PNG (kept at same path so chrome://
        references still resolve)
  - Plain "Mullvad Browser" / "Mozilla Firefox" / "Firefox" → Anonymous
    in user-visible FTL bundles only (brandings.ftl, brand-specific
    ftl). Avoids substitutions inside .sys.mjs source so we don't
    accidentally rename JS identifiers or code paths.

What we leave alone:
  - FTL message IDs (only the right-hand-side values change).
  - Source-code identifiers in actors/ and modules/.
  - License / credits text.
"""

import os
import re
import shutil
import sys
from pathlib import Path

if len(sys.argv) != 2:
    print("usage: rebrand_omni.py <extracted-omni-dir>", file=sys.stderr)
    sys.exit(1)

ROOT = Path(sys.argv[1])
if not ROOT.is_dir():
    sys.exit(f"not a directory: {ROOT}")

REPO = Path(__file__).resolve().parents[2]  # browser-fork/scripts → repo root
TOOLKIT_ICON = REPO / "browser-fork/branding/generated/anonymous-toolkit.png"

# ---- BRAND STRINGS ----

BRAND_FTL = {
    "-brand-shorter-name":  "Anonymous",
    "-brand-short-name":    "Anonymous",
    "-brand-shortcut-name": "Anonymous",
    "-brand-full-name":     "Anonymous Browser",
    "-brand-product-name":  "Anonymous",
    "-vendor-short-name":   "Anonymous",
    "trademarkInfo":
        "Anonymous Browser is built on top of Firefox ESR. "
        "See About → Credits.",
}

BRAND_PROPERTIES = {
    "brandShorterName": "Anonymous",
    "brandShortName":   "Anonymous",
    "brandFullName":    "Anonymous Browser",
}

# ---- helpers ----

def rewrite_text(path: Path, fn) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return
    new_text = fn(text)
    if new_text != text:
        path.write_text(new_text, encoding="utf-8")

def rewrite_brand_ftl(text: str) -> str:
    # Lines look like:  -brand-short-name = Mullvad Browser
    # Or with type markers we don't currently use.
    for key, value in BRAND_FTL.items():
        text = re.sub(
            rf"^({re.escape(key)})\s*=.*$",
            rf"\1 = {value}",
            text,
            flags=re.MULTILINE,
        )
    return text

def rewrite_brand_properties(text: str) -> str:
    for key, value in BRAND_PROPERTIES.items():
        text = re.sub(
            rf"^({re.escape(key)})\s*=.*$",
            rf"\1={value}",
            text,
            flags=re.MULTILINE,
        )
    return text

def rewrite_wordmark(text: str) -> str:
    # mullvad-about-wordmark-en = MULLVAD BROWSER (Mullvad)
    # OR -aboutDialog-architecture, brand-product-name etc. (Firefox)
    text = re.sub(
        r"^(mullvad-about-wordmark-en)\s*=.*$",
        r"\1 = ANONYMOUS",
        text,
        flags=re.MULTILINE,
    )
    return text

def generic_brand_to_anonymous(text: str) -> str:
    """Soft string subs in user-visible FTL files only.

    Conservative: replaces "Mullvad Browser" / "MullvadBrowser" /
    "Mozilla Firefox" / standalone "Firefox" where we're confident no
    code identifier exists. Used on user-visible FTL bundles. Never
    on .sys.mjs (would rename JS identifiers).
    """
    text = re.sub(r"Mullvad Browser",   "Anonymous", text)
    text = re.sub(r"MullvadBrowser",    "Anonymous", text)
    text = re.sub(r"Mozilla Firefox",   "Anonymous", text)
    # Standalone "Firefox" — only at word boundaries, with negative
    # lookahead for path-like suffixes ("Firefox.app", "FirefoxNightly")
    # we want to leave alone.
    text = re.sub(r"\bFirefox\b(?!-)", "Anonymous", text)
    text = re.sub(r"\bMozilla\b",      "Anonymous Project", text)
    return text

# ---- traverse ----

changed = 0

for p in ROOT.rglob("*"):
    if not p.is_file():
        continue
    rel = p.relative_to(ROOT).as_posix()

    # locale brand files
    if rel.endswith("/branding/brand.ftl"):
        before = p.read_text(encoding="utf-8")
        rewrite_text(p, rewrite_brand_ftl)
        if p.read_text(encoding="utf-8") != before:
            changed += 1
        continue

    if rel.endswith("/branding/brand.properties"):
        before = p.read_text(encoding="utf-8")
        rewrite_text(p, rewrite_brand_properties)
        if p.read_text(encoding="utf-8") != before:
            changed += 1
        continue

    if rel.endswith("/branding/mullvad-about-wordmark-en.ftl"):
        before = p.read_text(encoding="utf-8")
        rewrite_text(p, rewrite_wordmark)
        if p.read_text(encoding="utf-8") != before:
            changed += 1
        continue

    # toolkit-side FTLs that the new-tab/about pages pull from.
    if (rel.endswith("/toolkit/branding/brandings.ftl")
            or rel.endswith("/toolkit/global/mullvad-browser.ftl")
            or rel.endswith("/browser/branding/brand.ftl")
            or rel.endswith("/browser/aboutDialog.ftl")
            or rel.endswith("/browser/branding.ftl")):
        before = p.read_text(encoding="utf-8")
        rewrite_text(p, generic_brand_to_anonymous)
        if p.read_text(encoding="utf-8") != before:
            changed += 1
        continue

# Toolkit icon (16-px badge shown next to the about: title). Mullvad
# uses mullvadbrowser.png; vanilla Firefox uses firefox.png. Replace
# whichever exists.
for icon_rel in (
    "chrome/toolkit/skin/classic/global/icons/mullvadbrowser.png",
    "chrome/toolkit/skin/classic/global/icons/firefox.png",
    "chrome/browser/content/branding/icon128.png",
    "chrome/browser/content/branding/about-logo.png",
):
    icon_path = ROOT / icon_rel
    if icon_path.exists() and TOOLKIT_ICON.exists():
        shutil.copy(TOOLKIT_ICON, icon_path)
        changed += 1

# About-dialog wordmark SVG. Replaces Firefox's vector wordmark.
# Single-color so it inherits the dialog's foreground (works in
# light + dark themes). Letter-spaced uppercase, weight 800 to read
# as a wordmark rather than body text, with a subtle leading dot/
# bracket motif framing the name.
ANONYMOUS_WORDMARK_SVG = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 360 48" fill="currentColor" aria-label="Anonymous">
  <g font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI Variable', 'Segoe UI', 'Helvetica Neue', Arial, sans-serif" font-weight="800">
    <text x="14" y="34" font-size="20" opacity="0.55">[</text>
    <text x="30" y="34" font-size="28" letter-spacing="3.2">ANONYMOUS</text>
    <text x="344" y="34" font-size="20" opacity="0.55" text-anchor="end">]</text>
  </g>
</svg>
"""
for wm_rel in (
    "chrome/browser/content/branding/firefox-wordmark.svg",
    "chrome/browser/content/branding/about-wordmark.svg",
    "chrome/branding/content/about-wordmark.svg",
):
    wm_path = ROOT / wm_rel
    if wm_path.exists():
        wm_path.write_text(ANONYMOUS_WORDMARK_SVG, encoding="utf-8")
        changed += 1

print(f"[rebrand_omni] changed {changed} file(s) in {ROOT}", file=sys.stderr)
