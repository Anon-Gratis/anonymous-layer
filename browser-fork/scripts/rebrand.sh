#!/usr/bin/env bash
# rebrand.sh — rewrite Mullvad branding to Anonymous on a Mullvad
# Browser install.
#
# Operates in-place on the install root (the directory containing
# Browser/, start-*.desktop, etc.). Idempotent: re-running on an
# already-rebranded tree is safe.
#
# What changes:
#   - Brand strings (brand.ftl, brand.properties, wordmark) in every
#     locale, inside both Browser/omni.ja and Browser/browser/omni.ja.
#   - Application metadata in Browser/application.ini.
#   - Window title / taskbar grouping / .desktop file.
#   - Launcher script renamed:  Browser/start-mullvad-browser → Browser/start-anonymous
#   - Wrapper binary renamed:   Browser/mullvadbrowser → Browser/anonymous
#                               Browser/mullvadbrowser.real → Browser/anonymous.real
#   - All toolbar / default icons replaced with the new logo.
#
# What is intentionally KEPT:
#   - Mullvad/Tor credit + license text in about:credits and
#     LICENSE files. MPL2 and the Tor LICENSE require attribution.
#   - Internal code identifiers (AboutMullvadBrowserParent class,
#     chrome://browser/content/mullvad-browser/ paths, ftl FILENAMES).
#     These aren't user-visible; renaming them would risk silent
#     breakage with no upside.
#
# Usage:
#   browser-fork/scripts/rebrand.sh <install-root>
#   browser-fork/scripts/rebrand.sh ~/anon-browser

set -euo pipefail

ROOT="${1:-}"
[[ -n "$ROOT" ]] || { echo "usage: $0 <install-root>" >&2; exit 1; }
[[ -d "$ROOT/Browser" ]] || { echo "error: $ROOT/Browser not found — is this a Mullvad install?" >&2; exit 1; }

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BRAND="$REPO/browser-fork/branding/generated"
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"

[[ -f "$BRAND/icon-128.png" ]] || {
    echo "error: branding/generated/ is empty. Run browser-fork/branding/generate.sh first." >&2
    exit 1
}

log() { printf '[rebrand] %s\n' "$*" >&2; }

# Refuse to rebrand only if a process is running OUT OF THIS install
# tree. A different install elsewhere on the box is not our problem.
ROOT_ABS="$(cd "$ROOT" && pwd)"
if pgrep -af 'mullvadbrowser\.real|anonymous\.real' 2>/dev/null | grep -qF "$ROOT_ABS/"; then
    if [[ "${REBRAND_FORCE:-0}" == "1" ]]; then
        log "REBRAND_FORCE=1 — proceeding while this install's browser is running (atomic mv keeps running process safe; rebrand only visible on next launch)"
    else
        echo "error: the browser is currently running out of $ROOT_ABS. Close it first, or set REBRAND_FORCE=1." >&2
        exit 1
    fi
fi

# ----- 1. application.ini -----

log "1/7  rewriting application.ini"
APP_INI="$ROOT/Browser/application.ini"
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
    log "2/7  rebranding strings in ${label}"
    local tmp
    tmp="$(mktemp -d -t rebrand-omni.XXXXXX)"
    ( cd "$tmp" && unzip -q "$omni" )

    python3 "$SCRIPTS_DIR/rebrand_omni.py" "$tmp"

    # Repack — preserve zip layout. The empty-directory entries are
    # important; -r catches them, -X drops extra fields for closer-to-
    # deterministic output. We use -X9 for max compression to match
    # upstream (Mullvad ships omni.ja optimized).
    #
    # Atomic rename — we write the new archive at "$omni.tmp" and
    # then mv it in. A running browser's mmap of the old file keeps
    # working until next launch; the new content is only visible to
    # processes that open the file fresh.
    ( cd "$tmp" && zip -q -X -r -9 "$omni.tmp" . )
    mv -f "$omni.tmp" "$omni"
    rm -rf "$tmp"
}

[[ -f "$ROOT/Browser/omni.ja" ]]         && rebrand_omni "$ROOT/Browser/omni.ja"         "Browser/omni.ja"
[[ -f "$ROOT/Browser/browser/omni.ja" ]] && rebrand_omni "$ROOT/Browser/browser/omni.ja" "Browser/browser/omni.ja"

# ----- 3. icons on disk -----

log "3/7  replacing on-disk icons"
ICON_DEST="$ROOT/Browser/browser/chrome/icons/default"
for sz in 16 32 48 64 128; do
    if [[ -f "$ICON_DEST/default${sz}.png" ]]; then
        cp "$BRAND/default${sz}.png" "$ICON_DEST/default${sz}.png"
    fi
done
if [[ -f "$ROOT/Browser/icons/updater.png" ]]; then
    cp "$BRAND/updater.png" "$ROOT/Browser/icons/updater.png"
fi
# also the SVG about-logo if present — fall back to PNG
if [[ -f "$ICON_DEST/about-logo.svg" ]]; then
    rm "$ICON_DEST/about-logo.svg"  # don't ship a stale Mullvad SVG
fi
if [[ -f "$ICON_DEST/about-logo.png" ]]; then
    cp "$BRAND/icon-192.png" "$ICON_DEST/about-logo.png"
fi

# ----- 4. wrapper binary + .real -----

log "4/7  renaming wrapper binary"
if [[ -f "$ROOT/Browser/mullvadbrowser.real" ]] && [[ ! -f "$ROOT/Browser/anonymous.real" ]]; then
    mv "$ROOT/Browser/mullvadbrowser.real" "$ROOT/Browser/anonymous.real"
fi
if [[ -f "$ROOT/Browser/mullvadbrowser" ]] && [[ ! -f "$ROOT/Browser/anonymous" ]]; then
    mv "$ROOT/Browser/mullvadbrowser" "$ROOT/Browser/anonymous"
fi
# Rewrite the exec line inside the wrapper to point at the renamed .real
if [[ -f "$ROOT/Browser/anonymous" ]]; then
    sed -i 's@\bmullvadbrowser\.real\b@anonymous.real@g' "$ROOT/Browser/anonymous"
fi

# Rename the docs dir too (unreferenced — just on-disk cruft).
if [[ -d "$ROOT/Browser/MullvadBrowser" ]] && [[ ! -d "$ROOT/Browser/Anonymous" ]]; then
    mv "$ROOT/Browser/MullvadBrowser" "$ROOT/Browser/Anonymous"
fi

# ----- 5. shell launcher start-mullvad-browser → start-anonymous -----

log "5/7  rewriting launcher script"
if [[ -f "$ROOT/Browser/start-mullvad-browser" ]] && [[ ! -f "$ROOT/Browser/start-anonymous" ]]; then
    mv "$ROOT/Browser/start-mullvad-browser" "$ROOT/Browser/start-anonymous"
fi
if [[ -f "$ROOT/Browser/start-anonymous" ]]; then
    python3 - "$ROOT/Browser/start-anonymous" <<'PY'
import sys, re
p = sys.argv[1]
src = open(p).read()
subs = [
    (r'Mullvad Browser',         'Anonymous'),
    (r'MullvadBrowser',          'Anonymous'),
    (r'mullvad-browser\.log',    'anonymous.log'),
    (r'mullvad-browser\.desktop','anonymous.desktop'),
    (r'start-mullvad-browser',   'start-anonymous'),
    (r'mullvadbrowser\.real',    'anonymous.real'),
    (r'\bmullvadbrowser\b',      'anonymous'),
    (r'\$HOME/\.mullvad-browser','$HOME/.anonymous-browser'),
]
for pat, repl in subs:
    src = re.sub(pat, repl, src)
open(p, 'w').write(src)
PY
fi

# ----- 6. .desktop files -----

log "6/7  rewriting .desktop file"
DESKTOPS=()
[[ -f "$ROOT/Browser/start-mullvad-browser.desktop" ]] && DESKTOPS+=("$ROOT/Browser/start-mullvad-browser.desktop")
[[ -f "$ROOT/start-mullvad-browser.desktop"         ]] && DESKTOPS+=("$ROOT/start-mullvad-browser.desktop")

for src_desktop in "${DESKTOPS[@]:-}"; do
    [[ -z "${src_desktop:-}" ]] && continue
    new_path="${src_desktop/start-mullvad-browser.desktop/anonymous.desktop}"
    mv "$src_desktop" "$new_path"
    python3 - "$new_path" <<'PY'
import sys, re
p = sys.argv[1]
src = open(p).read()
subs = [
    (r'Mullvad Browser Setup',           'Anonymous Setup'),
    (r'Mullvad Browser',                 'Anonymous'),
    (r'MullvadBrowser',                  'Anonymous'),
    (r'start-mullvad-browser',           'start-anonymous'),
    (r'X-MullvadBrowser-',               'X-Anonymous-'),
    (r'StartupWMClass=.*',               'StartupWMClass=Anonymous'),
    (r'^Name=.*$',                       'Name=Anonymous', re.MULTILINE),
    (r'^GenericName=.*$',                'GenericName=Web Browser', re.MULTILINE),
    (r'^Comment=.*$',
        'Comment=An anonymity-focused browser for the anon-layer network.',
        re.MULTILINE),
]
for pat, repl, *flags in subs:
    f = flags[0] if flags else 0
    src = re.sub(pat, repl, src, flags=f)
open(p, 'w').write(src)
PY
done

# Also fix the .desktop Icon= line that may bake an absolute path of the OLD install
for d in "$ROOT/Browser/anonymous.desktop" "$ROOT/anonymous.desktop"; do
    [[ -f "$d" ]] || continue
    sed -i -E "s|^Icon=.*|Icon=$ROOT/Browser/browser/chrome/icons/default/default128.png|" "$d"
done

# ----- 7. update our launcher to call start-anonymous -----

log "7/7  updating Anon Layer launcher to call start-anonymous"
if [[ -f "$ROOT/anon-browser" ]]; then
    sed -i 's|start-mullvad-browser|start-anonymous|g' "$ROOT/anon-browser"
fi

log "rebrand complete: $ROOT"
