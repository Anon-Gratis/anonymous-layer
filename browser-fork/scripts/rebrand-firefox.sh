#!/usr/bin/env bash
# rebrand-firefox.sh — apply Anonymous branding to a vanilla-Firefox-
# based install (created by repackage-firefox.sh).
#
# Operates in-place on the install root. Idempotent: re-running on an
# already-rebranded tree is safe.
#
# What changes:
#   - Brand strings (brand.ftl, brand.properties, branding.ftl) in
#     every locale, inside both omni.ja (root) and browser/omni.ja.
#   - Application metadata in application.ini (Vendor, Name, etc.).
#   - On-disk icons under browser/chrome/icons/default/ + icons/.
#   - Window title / taskbar grouping / .desktop file (if we wrote one).
#
# What is intentionally KEPT:
#   - The `firefox` and `firefox-bin` binary names. Renaming them risks
#     breaking internal argv[0] checks inside Gecko (some code paths
#     match against MOZ_APP_NAME). We achieve the user-visible
#     "Anonymous" identity via the launcher's `--class Anonymous
#     --name Anonymous` flags + WM_CLASS, not by renaming the ELF.
#   - Mozilla/Firefox credit and license text in about:credits + LICENSE.
#     MPL2 requires attribution.
#   - Internal code identifiers (chrome:// paths, FTL filenames).
#
# Usage:
#   browser-fork/scripts/rebrand-firefox.sh <install-root>
#   browser-fork/scripts/rebrand-firefox.sh ~/anon-browser-ff

set -euo pipefail

ROOT="${1:-}"
[[ -n "$ROOT" ]] || { echo "usage: $0 <install-root>" >&2; exit 1; }
[[ -f "$ROOT/firefox" ]] || { echo "error: $ROOT/firefox not found — is this a Firefox-based install?" >&2; exit 1; }

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BRAND="$REPO/browser-fork/branding/generated"
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"

[[ -f "$BRAND/icon-128.png" ]] || {
    echo "error: browser-fork/branding/generated/ is empty. Run browser-fork/branding/generate.sh first." >&2
    exit 1
}

log() { printf '[rebrand-ff] %s\n' "$*" >&2; }

# Refuse to rebrand only if a process is running OUT OF THIS install
# tree.
ROOT_ABS="$(cd "$ROOT" && pwd)"
if pgrep -af 'firefox-bin' 2>/dev/null | grep -qF "$ROOT_ABS/"; then
    if [[ "${REBRAND_FORCE:-0}" == "1" ]]; then
        log "REBRAND_FORCE=1 — proceeding while this install's browser is running (atomic mv keeps running process safe; rebrand only visible on next launch)"
    else
        echo "error: the browser is currently running out of $ROOT_ABS. Close it first, or set REBRAND_FORCE=1." >&2
        exit 1
    fi
fi

# ----- 1. application.ini -----

log "1/6  rewriting application.ini"
APP_INI="$ROOT/application.ini"
python3 - "$APP_INI" <<'PY'
import sys, re
p = sys.argv[1]
src = open(p).read()
patches = {
    r'^Vendor=.*$':           'Vendor=Anonymous',
    r'^Name=.*$':             'Name=Anonymous',
    r'^RemotingName=.*$':     'RemotingName=Anonymous',
    r'^CodeName=.*$':         'CodeName=Anonymous',
    r'^SourceRepository=.*$': 'SourceRepository=https://github.com/anon-gratis/anonymous-layer',
    r'^URL=.*$':              'URL=',
}
for pat, repl in patches.items():
    src = re.sub(pat, repl, src, flags=re.MULTILINE)
open(p, 'w').write(src)
PY

# ----- 2. brand strings inside both omni.ja archives -----

rebrand_omni() {
    local omni="$1"
    local label="$2"
    log "2/6  rebranding strings in ${label}"
    local tmp
    tmp="$(mktemp -d -t rebrand-omni.XXXXXX)"

    # Firefox's omni.ja is an "optimized" zip — its central directory
    # has an unusual offset relative to the prepended jar header.
    # `unzip` emits warnings (and exits 2 = "warning, data intact") but
    # the extraction is correct. Accept exit 2 here; bail on anything
    # higher.
    ( cd "$tmp" && unzip -q "$omni" || [ $? -eq 2 ] )

    python3 "$SCRIPTS_DIR/rebrand_omni.py" "$tmp"

    # Repack with the same options the Mullvad path used (-X9 max).
    ( cd "$tmp" && zip -q -X -r -9 "$omni.tmp" . )
    mv -f "$omni.tmp" "$omni"
    rm -rf "$tmp"
}

[[ -f "$ROOT/omni.ja" ]]         && rebrand_omni "$ROOT/omni.ja"         "omni.ja"
[[ -f "$ROOT/browser/omni.ja" ]] && rebrand_omni "$ROOT/browser/omni.ja" "browser/omni.ja"

# ----- 3. icons on disk -----

log "3/6  replacing on-disk icons"
ICON_DEST="$ROOT/browser/chrome/icons/default"
mkdir -p "$ICON_DEST"
for sz in 16 32 48 64 128; do
    src="$BRAND/default${sz}.png"
    dst="$ICON_DEST/default${sz}.png"
    [[ -f "$src" ]] && cp "$src" "$dst"
done

# Vanilla Firefox sometimes uses different filenames; cover them all.
for stem in firefox firefox-branding default; do
    for sz in 16 32 48 64 128 192 256 512; do
        candidate="$ICON_DEST/${stem}${sz}.png"
        if [[ -f "$candidate" ]] && [[ -f "$BRAND/icon-${sz}.png" ]]; then
            cp "$BRAND/icon-${sz}.png" "$candidate"
        fi
    done
done

# Updater icon
if [[ -f "$ROOT/icons/updater.png" ]] && [[ -f "$BRAND/updater.png" ]]; then
    cp "$BRAND/updater.png" "$ROOT/icons/updater.png"
fi

# Drop any stale Firefox SVG; replace with our PNG fallback.
for svg in "$ICON_DEST/about-logo.svg" "$ICON_DEST/firefox.svg"; do
    [[ -f "$svg" ]] && rm -f "$svg"
done
for png in "$ICON_DEST/about-logo.png" "$ICON_DEST/firefox.png"; do
    if [[ -f "$png" ]] && [[ -f "$BRAND/icon-192.png" ]]; then
        cp "$BRAND/icon-192.png" "$png"
    fi
done

# ----- 4. (no binary rename — see header comment) -----

log "4/6  binary rename: skipped (vanilla Firefox needs argv[0] = firefox-bin)"

# ----- 5. desktop file & launcher (cosmetic) -----

log "5/6  desktop file"
# We generate the .desktop ourselves; the launcher's --register-app path
# writes one to ~/.local/share/applications/ at runtime. Nothing to do
# in-tree.

# ----- 6. ensure the WM_CLASS aliasing makes window manager group it
#          as "Anonymous". The launcher already passes --class/--name.

log "6/6  rebrand complete: $ROOT"

# Sanity check: confirm omni.ja sizes are reasonable (no zip corruption)
echo
echo "    omni.ja files in the rebranded install:"
for omni in "$ROOT/omni.ja" "$ROOT/browser/omni.ja"; do
    if [[ -f "$omni" ]]; then
        printf "      %s  (%s bytes)\n" "${omni#$ROOT/}" "$(stat -c %s "$omni")"
    fi
done
