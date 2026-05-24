#!/usr/bin/env bash
# repackage-mullvad-windows.sh — build the Windows portable .zip of
# Anonymous Browser by repackaging the upstream Mullvad Browser
# windows-x86_64 release with our patches, anon-layer extension,
# bundled node/tor/i2pd binaries, and the Go launcher.
#
# Runs from a Linux build host — no Windows needed. Output:
# dist/anonymous-<OUR_VERSION>-windows-x86_64.zip
#
# Usage:
#   browser-fork/scripts/repackage-mullvad-windows.sh
#   browser-fork/scripts/repackage-mullvad-windows.sh --keep-work
#   browser-fork/scripts/repackage-mullvad-windows.sh --offline path/to/mullvad.exe
#
# Required tools: bash, curl, 7z (p7zip-full), zip, sha256sum,
# go (1.23+) to build the launcher binary if not pre-built.

set -euo pipefail

# ---------- defaults ----------

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
MULLVAD_VERSION="${MULLVAD_VERSION:-15.0.14}"
TOR_VERSION="${TOR_VERSION:-15.0.14}"        # tor-expert-bundle ships under TBB version
I2PD_VERSION="${I2PD_VERSION:-2.60.0}"
NODE_VERSION="${NODE_VERSION:-20.20.1}"
OUR_VERSION="${OUR_VERSION:-$(grep -E '"version"' "$REPO/package.json" 2>/dev/null \
                             | head -1 \
                             | sed -E 's/.*"version"\s*:\s*"([^"]+)".*/\1/' || echo 0.0.0-pre)}"
DIST="${DIST:-$REPO/dist}"
WORK="${WORK:-$(mktemp -d -t anon-windows-build.XXXXXX)}"
OFFLINE_MULLVAD=""
KEEP_WORK=0
SKIP_GPG=1   # default ON — Linux build hosts rarely have Mullvad's key imported

# ---------- arg parse ----------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)         MULLVAD_VERSION="$2"; shift 2 ;;
        --tor-version)     TOR_VERSION="$2"; shift 2 ;;
        --i2pd-version)    I2PD_VERSION="$2"; shift 2 ;;
        --node-version)    NODE_VERSION="$2"; shift 2 ;;
        --offline)         OFFLINE_MULLVAD="$2"; shift 2 ;;
        --output)          DIST="$2"; shift 2 ;;
        --work)            WORK="$2"; shift 2 ;;
        --keep-work)       KEEP_WORK=1; shift ;;
        --gpg-verify)      SKIP_GPG=0; shift ;;
        -h|--help)
            sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

# ---------- preflight ----------

log() { printf '[%s] %s\n' "$(date -u '+%H:%M:%SZ')" "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

for tool in curl zip sha256sum 7z; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool (install p7zip-full for 7z)"
done

mkdir -p "$DIST" "$WORK"

cleanup() {
    if [[ $KEEP_WORK -eq 0 ]]; then
        log "cleaning $WORK"
        rm -rf "$WORK"
    else
        log "leaving $WORK in place (--keep-work)"
    fi
}
trap cleanup EXIT

log "Anon Browser Windows repackage v${OUR_VERSION}"
log "  Mullvad version : ${MULLVAD_VERSION}"
log "  Tor version     : ${TOR_VERSION}"
log "  i2pd version    : ${I2PD_VERSION}"
log "  Node version    : ${NODE_VERSION}"
log "  Work dir        : ${WORK}"
log "  Output          : ${DIST}"

# ---------- 1. acquire Mullvad Browser (Windows .exe SFX) ----------

MULLVAD_EXE="$WORK/mullvad-browser-windows-x86_64-${MULLVAD_VERSION}.exe"
if [[ -n "$OFFLINE_MULLVAD" ]]; then
    [[ -f "$OFFLINE_MULLVAD" ]] || die "offline file not found: $OFFLINE_MULLVAD"
    log "1/9  using offline Mullvad EXE: $OFFLINE_MULLVAD"
    cp "$OFFLINE_MULLVAD" "$MULLVAD_EXE"
else
    URL="https://cdn.mullvad.net/browser/${MULLVAD_VERSION}/mullvad-browser-windows-x86_64-${MULLVAD_VERSION}.exe"
    log "1/9  downloading Mullvad Browser ($URL)"
    curl -fL --progress-bar -o "$MULLVAD_EXE" "$URL" \
        || die "Mullvad Browser download failed; check --version"

    if [[ $SKIP_GPG -eq 0 ]] && command -v gpg >/dev/null 2>&1; then
        log "     fetching .asc"
        curl -fL --progress-bar -o "${MULLVAD_EXE}.asc" "${URL}.asc" \
            || log "     (warning) no .asc; skipping verify"
        if [[ -f "${MULLVAD_EXE}.asc" ]]; then
            gpg --verify "${MULLVAD_EXE}.asc" "$MULLVAD_EXE" 2>&1 | tail -3 >&2 \
                || die "GPG verify failed. Import Mullvad's signing key, or omit --gpg-verify."
            log "     ✓ GPG verify OK"
        fi
    fi
fi

# Mullvad's Windows installer is a 7z SFX. Extract the inner "Browser"
# tree directly into $WORK/mullvad-browser/.
log "     extracting SFX with 7z"
mkdir -p "$WORK/mullvad-browser"
7z x -y -o"$WORK/mullvad-browser" "$MULLVAD_EXE" >/dev/null \
    || die "7z extract failed"
[[ -d "$WORK/mullvad-browser/Browser" ]] \
    || die "expected Browser/ tree after extract; got: $(ls "$WORK/mullvad-browser")"
BROWSER_ROOT="$WORK/mullvad-browser/Browser"

# ---------- 2. acquire Node Windows runtime ----------

NODE_ZIP="$WORK/node-v${NODE_VERSION}-win-x64.zip"
NODE_URL="https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-win-x64.zip"
log "2/9  downloading Node ${NODE_VERSION} ($NODE_URL)"
curl -fL --progress-bar -o "$NODE_ZIP" "$NODE_URL" || die "Node download failed"
( cd "$WORK" && unzip -qo "$NODE_ZIP" )
NODE_DIR="$WORK/node-v${NODE_VERSION}-win-x64"
[[ -f "$NODE_DIR/node.exe" ]] || die "expected node.exe at $NODE_DIR/node.exe"

# ---------- 3. acquire tor (Windows expert bundle) ----------

TOR_TARBALL="$WORK/tor-expert-bundle-windows-x86_64-${TOR_VERSION}.tar.gz"
TOR_URL="https://archive.torproject.org/tor-package-archive/torbrowser/${TOR_VERSION}/tor-expert-bundle-windows-x86_64-${TOR_VERSION}.tar.gz"
log "3/9  downloading Tor Expert Bundle ($TOR_URL)"
curl -fL --progress-bar -o "$TOR_TARBALL" "$TOR_URL" || die "Tor Expert Bundle download failed"
mkdir -p "$WORK/tor-expert"
tar -xzf "$TOR_TARBALL" -C "$WORK/tor-expert"
# The Expert Bundle's layout: tor/tor.exe, tor/pluggable_transports/*, data/geoip
TOR_BIN="$WORK/tor-expert/tor/tor.exe"
[[ -f "$TOR_BIN" ]] || die "tor.exe not found in expert bundle; layout: $(ls "$WORK/tor-expert/tor")"

# ---------- 4. acquire i2pd (Windows portable) ----------

I2PD_ZIP="$WORK/i2pd-${I2PD_VERSION}-win64.zip"
I2PD_URL="https://github.com/PurpleI2P/i2pd/releases/download/${I2PD_VERSION}/i2pd_${I2PD_VERSION}_win64_mingw.zip"
log "4/9  downloading i2pd ${I2PD_VERSION} ($I2PD_URL)"
curl -fL --progress-bar -o "$I2PD_ZIP" "$I2PD_URL" || die "i2pd download failed"
mkdir -p "$WORK/i2pd-extract"
( cd "$WORK/i2pd-extract" && unzip -qo "$I2PD_ZIP" )
# i2pd zip extracts to ./i2pd_X.Y.Z_win64_mingw/ (usually). Find i2pd.exe:
I2PD_BIN="$(find "$WORK/i2pd-extract" -maxdepth 3 -name 'i2pd.exe' | head -1)"
[[ -n "$I2PD_BIN" && -f "$I2PD_BIN" ]] || die "i2pd.exe not found in $WORK/i2pd-extract"

# ---------- 5. build the Go launcher (windows/amd64) ----------

log "5/9  building Go launcher (windows/amd64, CGO_ENABLED=0 — stderr splash)"
LAUNCHER_DIR="$REPO/browser-fork/launcher-go"
LAUNCHER_EXE="$WORK/anonymous.exe"
if ! command -v go >/dev/null 2>&1; then
    # Try the user-local Go install used during dev.
    [[ -x "$HOME/.local/go/bin/go" ]] && export PATH="$HOME/.local/go/bin:$PATH"
fi
command -v go >/dev/null 2>&1 || die "go toolchain not on PATH (need Go 1.23+)"
( cd "$LAUNCHER_DIR" && \
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o "$LAUNCHER_EXE" ./cmd/anonymous ) \
  || die "Go launcher build failed"
log "     wrote $LAUNCHER_EXE ($(du -h "$LAUNCHER_EXE" | cut -f1))"

# ---------- 6. build the WebExtension XPI ----------

EXT_DIR="$REPO/browser-fork/extension"
XPI="$WORK/anon-layer@anon.gratis.xpi"
log "6/9  building anon-layer extension"
if [[ -x "$EXT_DIR/build-xpi.sh" ]]; then
    # build-xpi.sh ignores any args and writes to ./dist/anon-layer-<version>.xpi.
    # Run it, then move the result to where downstream stages expect.
    ( cd "$EXT_DIR" && ./build-xpi.sh ) \
        || die "extension build failed"
    BUILT_XPI=$(ls -t "$EXT_DIR/dist"/anon-layer-*.xpi 2>/dev/null | head -1)
    [[ -n "$BUILT_XPI" && -f "$BUILT_XPI" ]] \
        || die "build-xpi.sh ran but no anon-layer-*.xpi appeared under $EXT_DIR/dist/"
    cp "$BUILT_XPI" "$XPI"
else
    # Fallback: zip the extension dir directly (skips validation).
    log "     (no build-xpi.sh — zipping extension dir directly)"
    ( cd "$EXT_DIR" && zip -qr "$XPI" . -x "build-xpi.sh" "tests/*" "*.md" )
fi
[[ -f "$XPI" ]] || die "XPI not produced at $XPI"

# ---------- 7. assemble the staging tree ----------

STAGE="$WORK/Anonymous"
log "7/9  assembling staging tree at $STAGE"
# Start clean — on --keep-work re-runs, leftover files from a prior
# staging would otherwise nest under cp -a "$BROWSER_ROOT" "$STAGE/Browser"
# and inflate the zip with duplicates.
rm -rf "$STAGE"
mkdir -p "$STAGE"

# 7a. Browser tree (patched).
cp -a "$BROWSER_ROOT" "$STAGE/Browser"

#   policies.json — patched + path placeholder for Windows. Mullvad's
#   Windows tree has the same Browser/distribution/ layout as Linux.
POLICIES="$STAGE/Browser/distribution/policies.json"
mkdir -p "$(dirname "$POLICIES")"
cp "$REPO/browser-fork/patches/repackage/policies.json" "$POLICIES"
# Leave @@INSTALL_DIR@@ as-is. The Go launcher's selfheal pass
# (internal/selfheal.Policies) rewrites it on first launch with the
# actual extract path, OS-aware (handles file:///C:/... on Windows).

#   Pre-installed extension.
mkdir -p "$STAGE/Browser/distribution/extensions"
cp "$XPI" "$STAGE/Browser/distribution/extensions/anon-layer@anon.gratis.xpi"

#   Branding icons — Windows uses the same chrome icons as Linux.
BRAND_GEN="$REPO/browser-fork/branding/generated"
for s in 16 32 48 64 128; do
    cp "$BRAND_GEN/icon-${s}.png" \
       "$STAGE/Browser/browser/chrome/icons/default/default${s}.png" \
       || log "     warn: chrome/icons/default/default${s}.png missing in upstream"
done

#   Autoconfig + mozilla.cfg.
mkdir -p "$STAGE/Browser/defaults/pref"
cp "$REPO/browser-fork/patches/repackage/autoconfig/anon-autoconfig.js" \
   "$STAGE/Browser/defaults/pref/anon-autoconfig.js"
cp "$REPO/browser-fork/patches/repackage/autoconfig/mozilla.cfg" \
   "$STAGE/Browser/mozilla.cfg"

#   omni.ja patches: the about-page rebrand + black-bg branding CSS we
#   did interactively are in the LINUX install but not in the repo as
#   a standalone script. Re-apply here using the same python-zipfile
#   approach so Windows ships identical chrome.
log "     patching Browser/browser/omni.ja"
python3 - <<PY "$STAGE/Browser/browser/omni.ja" "$REPO"
import io, os, sys, zipfile
from PIL import Image

jar_path = sys.argv[1]
repo     = sys.argv[2]
gen      = f"{repo}/browser-fork/branding/generated"
src_png  = f"{repo}/browser-fork/branding/source/anonymous-logo.png"

# 1. Icons baked into omni.ja
master = Image.open(src_png).convert("RGBA")
def at(size):
    buf = io.BytesIO()
    master.resize((size, size), Image.LANCZOS).save(buf, "PNG", optimize=True)
    return buf.getvalue()
icon_replacements = {
    "chrome/browser/content/branding/icon16.png":        at(16),
    "chrome/browser/content/branding/icon32.png":        at(32),
    "chrome/browser/content/branding/icon48.png":        at(48),
    "chrome/browser/content/branding/icon64.png":        at(64),
    "chrome/browser/content/branding/icon128.png":       at(128),
    "chrome/browser/content/branding/icon256.png":       at(256),
    "chrome/browser/content/branding/about-logo.png":    at(128),
    "chrome/browser/content/branding/about-logo@2x.png": at(384),
}

# 2. mullvad-branding.css — pure black background instead of blue gradient.
icon_replacements["chrome/browser/content/branding/mullvad-branding.css"] = (
    ':root {\n'
    '  --branding-gradient-start: #000000;\n'
    '  --branding-gradient-middle: #000000;\n'
    '  --branding-gradient-end: #000000;\n'
    '  --branding-focus-outline-color: #ffbd4f;\n'
    '  --branding-link-color: #ffbd4f;\n'
    '  --branding-link-color-hover: #ffd567;\n'
    '  --branding-link-color-active: #ffea80;\n'
    '}\n'
).encode("utf-8")

tmp_out = jar_path + ".new"
replaced = set()
with zipfile.ZipFile(jar_path, "r") as zin, zipfile.ZipFile(tmp_out, "w") as zout:
    for info in zin.infolist():
        if info.filename in icon_replacements:
            data = icon_replacements[info.filename]
            replaced.add(info.filename)
        else:
            data = zin.read(info.filename)
        new = zipfile.ZipInfo(filename=info.filename, date_time=info.date_time)
        new.compress_type = info.compress_type
        new.external_attr = info.external_attr
        new.create_system = info.create_system
        zout.writestr(new, data)
os.replace(tmp_out, jar_path)
print(f"omni.ja: replaced {len(replaced)} entries", file=sys.stderr)
PY

# 7b. AnonLayer tree.
ANON_DIR="$STAGE/AnonLayer"
mkdir -p "$ANON_DIR"/{bridge/bin,bridge/modules,tor/{bin,etc,run},i2pd/{bin,etc,run},node/bin,config/descriptors,share}

#   Node runtime.
cp "$NODE_DIR/node.exe" "$ANON_DIR/node/bin/node.exe"

#   Tor.
cp "$TOR_BIN" "$ANON_DIR/tor/bin/tor.exe"
# Tor expert bundle also ships data files (geoip, geoip6, certs).
cp -a "$WORK/tor-expert/tor/"* "$ANON_DIR/tor/bin/" 2>/dev/null || true
[[ -d "$WORK/tor-expert/data" ]] && cp -a "$WORK/tor-expert/data" "$ANON_DIR/tor/data"

#   i2pd.
cp "$I2PD_BIN" "$ANON_DIR/i2pd/bin/i2pd.exe"
I2PD_PKG_DIR="$(dirname "$I2PD_BIN")"
# i2pd ships certificates and a default i2pd.conf — copy them.
[[ -d "$I2PD_PKG_DIR/certificates" ]] && cp -a "$I2PD_PKG_DIR/certificates" "$ANON_DIR/i2pd/share/"
[[ -d "$I2PD_PKG_DIR" ]] && find "$I2PD_PKG_DIR" -maxdepth 1 -name "*.conf" -exec cp {} "$ANON_DIR/i2pd/etc/" \;

#   Bridge JS (anon-browse-gui.mjs + modules).
cp -a "$REPO/bin/anon-browse-gui.mjs" "$ANON_DIR/bridge/bin/"
cp -a "$REPO/bin/anon-browse.mjs"     "$ANON_DIR/bridge/bin/" 2>/dev/null || true
cp -a "$REPO/modules" "$ANON_DIR/bridge/"

#   tor + i2pd templates (read by launcher to render per-launch configs).
TPL_TOR="$REPO/browser-fork/patches/repackage/tor"
TPL_I2P="$REPO/browser-fork/patches/repackage/i2pd"
[[ -f "$TPL_TOR/torrc.template"     ]] && cp "$TPL_TOR/torrc.template"     "$ANON_DIR/tor/etc/"
[[ -f "$TPL_TOR/anon.pac.template"  ]] && cp "$TPL_TOR/anon.pac.template"  "$ANON_DIR/tor/etc/"
[[ -f "$TPL_I2P/i2pd.conf.template" ]] && cp "$TPL_I2P/i2pd.conf.template" "$ANON_DIR/i2pd/etc/"

#   anon-browser.conf example. Windows install path is relative — the
#   launcher resolves $INSTALL_DIR from its own location at runtime.
cat > "$ANON_DIR/config/anon-browser.conf.example" <<EOF
# Anonymous Browser — config (Windows)
#
# Rename to anon-browser.conf before first launch. Adjust DA_URLS and
# HSDIR_URL to your trust set. Paths are relative to the install root
# (the folder containing anonymous.exe).

DA_URLS=https://da1.anon.gratis,https://da2.anon.gratis,https://da3.anon.gratis
CONSENSUS=AnonLayer\\config\\consensus.bin
DA_TRUST=AnonLayer\\config\\da-trust.json
DESCRIPTOR_DIR=AnonLayer\\config\\descriptors
HSDIR_URL=https://da1.anon.gratis
ALLOW_CO_LOCATED=1
EOF

#   Demo descriptor + DA trust (ship the same bootstrap state Linux ships).
[[ -f "$REPO/deploy/state/demo-service.descriptor.bin" ]] && \
    cp "$REPO/deploy/state/demo-service.descriptor.bin" "$ANON_DIR/config/descriptors/"
[[ -f "$REPO/deploy/state/da-trust-entries.json" ]] && \
    cp "$REPO/deploy/state/da-trust-entries.json" "$ANON_DIR/config/da-trust.json"

#   App icon (used by the install + a future Windows .lnk creator).
cp "$BRAND_GEN/icon-256.png" "$ANON_DIR/share/anon-browser.png"

# 7c. Top-level launcher + docs.
cp "$LAUNCHER_EXE" "$STAGE/anonymous.exe"

cat > "$STAGE/README.txt" <<EOF
ANONYMOUS BROWSER — Windows portable build v${OUR_VERSION}
=========================================================

1. Extract this folder anywhere (e.g. C:\\Anonymous\\)
2. Copy AnonLayer\\config\\anon-browser.conf.example
       to AnonLayer\\config\\anon-browser.conf
   and edit DA_URLS / HSDIR_URL if you're not using the
   default pre-audit testnet directory authorities.
3. Double-click anonymous.exe to launch.

This is a PRE-AUDIT TESTNET build of the anon-layer protocol. Do not
rely on it for life-critical anonymity. See https://anonymous.gratis
for the project status.

Built from:
  Mullvad Browser ${MULLVAD_VERSION}  (cdn.mullvad.net)
  Tor Expert Bundle ${TOR_VERSION}    (torproject.org)
  i2pd ${I2PD_VERSION}                (PurpleI2P)
  Node.js ${NODE_VERSION}
EOF

# ---------- 8. zip ----------

OUT_ZIP="$DIST/anonymous-${OUR_VERSION}-windows-x86_64.zip"
log "8/9  zipping → $OUT_ZIP"
# zip -r *updates* an existing archive (keeps stale entries); delete first
# so each build is a clean snapshot of the current staging tree.
rm -f "$OUT_ZIP"
( cd "$WORK" && zip -qr "$OUT_ZIP" Anonymous )
log "     zipped $(du -h "$OUT_ZIP" | cut -f1)"

# ---------- 9. sha256 + done ----------

log "9/9  writing checksum"
( cd "$DIST" && sha256sum "$(basename "$OUT_ZIP")" > "$(basename "$OUT_ZIP").sha256" )

log "✓ done"
log "  $OUT_ZIP"
log "  $OUT_ZIP.sha256"
