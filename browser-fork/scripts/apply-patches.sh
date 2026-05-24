#!/usr/bin/env bash
# Apply our branding + bundled-daemon patches to a Mullvad Browser
# source tree. Idempotent (safe to re-run).
#
# Usage: scripts/apply-patches.sh [SOURCE_DIR]
#   SOURCE_DIR defaults to ./mullvad-browser

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_DIR="${1:-$REPO/mullvad-browser}"

if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "error: $SOURCE_DIR not found. Run scripts/fetch-source.sh first." >&2
    exit 1
fi

echo "→ Applying patches to $SOURCE_DIR"

# 1. Branding: start from Mozilla's `unofficial` branding (generic
#    Firefox icons without trademark), then overlay our brand strings
#    and (eventually) our own artwork.
#
#    A real Firefox branding directory needs ~63 files (icons in 4
#    formats + locale files + moz.build + NSIS installer config +
#    Windows VisualElementsManifest). Re-implementing all those from
#    scratch is a waste — `unofficial/` already has the right
#    structure, just with generic graphics. We copy it, then overlay
#    the brand strings and (when real artwork exists) the icons.
BRANDING_SRC="$REPO/branding"
BRANDING_DST="$SOURCE_DIR/browser/branding/anon"
UNOFFICIAL_SRC="$SOURCE_DIR/browser/branding/unofficial"

if [[ ! -d "$UNOFFICIAL_SRC" ]]; then
    echo "  error: $UNOFFICIAL_SRC not found; can't copy base branding" >&2
    exit 1
fi

mkdir -p "$BRANDING_DST"
# Use rsync if available for cleaner copying; fall back to cp -r.
if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete "$UNOFFICIAL_SRC"/ "$BRANDING_DST"/
else
    rm -rf "$BRANDING_DST" && cp -r "$UNOFFICIAL_SRC" "$BRANDING_DST"
fi
echo "  · copied unofficial branding as base ($(find "$BRANDING_DST" -type f | wc -l) files)"

# Overlay our brand-strings files (locales).
mkdir -p "$BRANDING_DST/locales/en-US"
cp "$BRANDING_SRC/locales/en-US/brand.ftl" "$BRANDING_DST/locales/en-US/brand.ftl"
cp "$BRANDING_SRC/locales/en-US/brand.properties" "$BRANDING_DST/locales/en-US/brand.properties"
echo "  · overlaid brand.ftl + brand.properties"

# 2. Distribution policies.json.
POLICY_DST="$SOURCE_DIR/browser/app/distribution"
mkdir -p "$POLICY_DST"
cp "$REPO/patches/policies.json" "$POLICY_DST/policies.json"
echo "  · copied policies.json"

# 3. configure.sh override.
#    Match Mullvad's branding/mb-release/configure.sh pattern: ONLY
#    set MOZ_APP_DISPLAYNAME here. Other vars (MOZ_APP_VENDOR,
#    distribution IDs, etc.) are set by mainline confvars.sh /
#    moz.build files and rejecting confvars-level overrides is a
#    deliberate Mozilla build-system check.
cat > "$BRANDING_DST/configure.sh" <<'EOF'
# Brand override for the Anon Browser fork.
MOZ_APP_DISPLAYNAME="Anon Browser"
EOF
echo "  · wrote branding/anon/configure.sh"

# 4. Mozconfig override: select our branding.
MOZCONFIG="$SOURCE_DIR/mozconfig"
if ! grep -q "MOZ_BRANDING_DIRECTORY=browser/branding/anon" "$MOZCONFIG" 2>/dev/null; then
    cat >> "$MOZCONFIG" <<'EOF'

# --- Anon Browser fork ---
ac_add_options --with-branding=browser/branding/anon
ac_add_options --enable-update-channel=release
EOF
    echo "  · appended Anon-branding lines to mozconfig"
else
    echo "  · mozconfig already configured for Anon branding"
fi

# 5. TODO: bundle anon-socks daemon binary as a "distributed file".
#    Path: $SOURCE_DIR/browser/app/profile/anon-socks (or a more native location)
#    Approach: use `bun build --compile` or `pkg` on our anon-socks.mjs.
#    Skipping for this scaffolding pass — see BROWSER-FORK.md § 3 (Phase 2).

echo
echo "Patches applied. Next:"
echo "  scripts/build-linux.sh    (or build-macos, build-windows, build-android)"
