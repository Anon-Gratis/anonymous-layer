#!/usr/bin/env bash
# repackage-mullvad-macos.sh — build the macOS .dmg of Anonymous
# Browser by repackaging upstream Mullvad Browser macos release with
# our patches, anon-layer extension, bundled node + tor + bridge,
# and the Go launcher.
#
# MUST run on macOS — uses hdiutil for .dmg mount + create. Designed
# to run in GitHub Actions macos-latest. Cross-build from Linux is not
# supported (.dmg HFS+ tooling is too flaky off-Mac).
#
# Output: dist/anonymous-<OUR_VERSION>-macos-<arch>.dmg (one per arch)
#
# Usage:
#   browser-fork/scripts/repackage-mullvad-macos.sh
#   browser-fork/scripts/repackage-mullvad-macos.sh --keep-work
#   browser-fork/scripts/repackage-mullvad-macos.sh --arch arm64
#   browser-fork/scripts/repackage-mullvad-macos.sh --offline path/to/mullvad.dmg
#
# Required tools: bash, curl, hdiutil, tar, plutil, /usr/libexec/PlistBuddy,
# zip, sha256sum (or shasum), python3, go (1.23+).

set -euo pipefail

# ---------- defaults ----------

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
MULLVAD_VERSION="${MULLVAD_VERSION:-15.0.14}"
TOR_VERSION="${TOR_VERSION:-15.0.14}"
NODE_VERSION="${NODE_VERSION:-20.20.1}"
OUR_VERSION="${OUR_VERSION:-$(grep -E '"version"' "$REPO/package.json" 2>/dev/null \
                             | head -1 \
                             | sed -E 's/.*"version"\s*:\s*"([^"]+)".*/\1/' || echo 0.0.0-pre)}"
DIST="${DIST:-$REPO/dist}"
WORK="${WORK:-$(mktemp -d -t anon-macos-build.XXXXXX)}"
OFFLINE_MULLVAD=""
KEEP_WORK=0
SKIP_GPG=1                    # default ON — CI runners rarely have Mullvad's key
TARGET_ARCH="$(uname -m)"     # arm64 (Apple Silicon) or x86_64 (Intel)

# ---------- arg parse ----------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)         MULLVAD_VERSION="$2"; shift 2 ;;
        --tor-version)     TOR_VERSION="$2"; shift 2 ;;
        --node-version)    NODE_VERSION="$2"; shift 2 ;;
        --arch)            TARGET_ARCH="$2"; shift 2 ;;
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

[[ "$(uname -s)" == "Darwin" ]] \
    || die "macOS only — hdiutil unavailable elsewhere. Run on a Mac or in GH Actions macos-latest."
for tool in curl hdiutil tar plutil zip python3; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done
[[ -x /usr/libexec/PlistBuddy ]] || die "missing /usr/libexec/PlistBuddy"
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 \
    || die "need sha256sum or shasum"

case "$TARGET_ARCH" in
    arm64)  TOR_ARCH="aarch64";  NODE_ARCH="arm64" ;;
    x86_64) TOR_ARCH="x86_64";   NODE_ARCH="x64"   ;;
    *) die "unsupported arch: $TARGET_ARCH (expected arm64 or x86_64)" ;;
esac

mkdir -p "$DIST" "$WORK"

# Track mounts so cleanup detaches everything even on error.
MOUNTS=()
cleanup() {
    for m in "${MOUNTS[@]:-}"; do
        hdiutil detach -quiet -force "$m" 2>/dev/null || true
    done
    if [[ $KEEP_WORK -eq 0 ]]; then
        log "cleaning $WORK"
        rm -rf "$WORK"
    else
        log "leaving $WORK in place (--keep-work)"
    fi
}
trap cleanup EXIT

log "Anon Browser macOS repackage v${OUR_VERSION} (arch=${TARGET_ARCH})"
log "  Mullvad version : ${MULLVAD_VERSION}"
log "  Tor version     : ${TOR_VERSION} (${TOR_ARCH})"
log "  Node version    : ${NODE_VERSION} (${NODE_ARCH})"
log "  Work dir        : ${WORK}"
log "  Output          : ${DIST}"

# ---------- 1. acquire Mullvad Browser (.dmg) ----------

MULLVAD_DMG="$WORK/mullvad-browser-macos-${MULLVAD_VERSION}.dmg"
if [[ -n "$OFFLINE_MULLVAD" ]]; then
    [[ -f "$OFFLINE_MULLVAD" ]] || die "offline DMG not found: $OFFLINE_MULLVAD"
    log "1/9  using offline Mullvad DMG: $OFFLINE_MULLVAD"
    cp "$OFFLINE_MULLVAD" "$MULLVAD_DMG"
else
    URL="https://cdn.mullvad.net/browser/${MULLVAD_VERSION}/mullvad-browser-macos-${MULLVAD_VERSION}.dmg"
    log "1/9  downloading Mullvad Browser ($URL)"
    curl -fL --progress-bar -o "$MULLVAD_DMG" "$URL" \
        || die "Mullvad Browser download failed; check --version"

    if [[ $SKIP_GPG -eq 0 ]] && command -v gpg >/dev/null 2>&1; then
        curl -fL --progress-bar -o "${MULLVAD_DMG}.asc" "${URL}.asc" \
            || log "     (warning) no .asc; skipping verify"
        if [[ -f "${MULLVAD_DMG}.asc" ]]; then
            gpg --verify "${MULLVAD_DMG}.asc" "$MULLVAD_DMG" 2>&1 | tail -3 >&2 \
                || die "GPG verify failed. Import Mullvad's key or omit --gpg-verify."
            log "     ✓ GPG verify OK"
        fi
    fi
fi

# Mount, copy .app, detach.
MOUNT_POINT="$(mktemp -d /tmp/anon-mullvad-mount.XXXXXX)"
log "     mounting → $MOUNT_POINT"
hdiutil attach -nobrowse -mountpoint "$MOUNT_POINT" -readonly "$MULLVAD_DMG" >/dev/null
MOUNTS+=("$MOUNT_POINT")
SRC_APP="$(find "$MOUNT_POINT" -maxdepth 2 -name '*.app' | head -1)"
[[ -n "$SRC_APP" && -d "$SRC_APP" ]] || die "no .app found in mounted DMG"
log "     copying $SRC_APP → Anonymous.app"
APP="$WORK/Anonymous.app"
cp -a "$SRC_APP" "$APP"
hdiutil detach -quiet "$MOUNT_POINT"
# Drop the unmount from the cleanup list now that we did it cleanly.
MOUNTS=("${MOUNTS[@]/$MOUNT_POINT}")

# ---------- 2. download Node macOS runtime ----------

NODE_TARBALL="$WORK/node-v${NODE_VERSION}-darwin-${NODE_ARCH}.tar.gz"
NODE_URL="https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-darwin-${NODE_ARCH}.tar.gz"
log "2/9  downloading Node ${NODE_VERSION} ($NODE_URL)"
curl -fL --progress-bar -o "$NODE_TARBALL" "$NODE_URL" || die "Node download failed"
( cd "$WORK" && tar -xzf "$NODE_TARBALL" )
NODE_DIR="$WORK/node-v${NODE_VERSION}-darwin-${NODE_ARCH}"
[[ -x "$NODE_DIR/bin/node" ]] || die "expected bin/node at $NODE_DIR/bin/node"

# ---------- 3. download Tor Expert Bundle ----------

TOR_TARBALL="$WORK/tor-expert-bundle-macos-${TOR_ARCH}-${TOR_VERSION}.tar.gz"
TOR_URL="https://archive.torproject.org/tor-package-archive/torbrowser/${TOR_VERSION}/tor-expert-bundle-macos-${TOR_ARCH}-${TOR_VERSION}.tar.gz"
log "3/9  downloading Tor Expert Bundle ($TOR_URL)"
curl -fL --progress-bar -o "$TOR_TARBALL" "$TOR_URL" || die "Tor Expert Bundle download failed"
mkdir -p "$WORK/tor-expert"
tar -xzf "$TOR_TARBALL" -C "$WORK/tor-expert"
TOR_BIN="$WORK/tor-expert/tor/tor"
[[ -f "$TOR_BIN" ]] || die "tor not found in expert bundle"

# ---------- 4. i2pd: NOT bundled (no upstream macOS release) ----------

log "4/9  i2pd: skipped — no upstream macOS release. Mac users wanting"
log "     .i2p access should 'brew install i2pd' and adjust their conf."

# ---------- 5. build the Go launcher (darwin/<arch>) ----------

log "5/9  building Go launcher (darwin/${NODE_ARCH}, CGO_ENABLED=0)"
LAUNCHER_DIR="$REPO/browser-fork/launcher-go"
LAUNCHER_BIN="$WORK/anonymous"
command -v go >/dev/null 2>&1 || die "go toolchain not on PATH (need Go 1.23+)"
( cd "$LAUNCHER_DIR" && \
  CGO_ENABLED=0 GOOS=darwin GOARCH=$NODE_ARCH \
    go build -trimpath -ldflags="-s -w" -o "$LAUNCHER_BIN" ./cmd/anonymous ) \
  || die "Go launcher build failed"
log "     wrote $LAUNCHER_BIN ($(du -h "$LAUNCHER_BIN" | cut -f1))"

# ---------- 6. build the WebExtension XPI ----------

EXT_DIR="$REPO/browser-fork/extension"
XPI="$WORK/anon-layer@anon.gratis.xpi"
log "6/9  building anon-layer extension"
if [[ -x "$EXT_DIR/build-xpi.sh" ]]; then
    ( cd "$EXT_DIR" && ./build-xpi.sh --output "$XPI" ) \
        || die "extension build failed"
else
    ( cd "$EXT_DIR" && zip -qr "$XPI" . -x "build-xpi.sh" "tests/*" "*.md" )
fi
[[ -f "$XPI" ]] || die "XPI not produced at $XPI"

# ---------- 7. patch the .app contents ----------

log "7/9  patching $APP"

RESOURCES="$APP/Contents/Resources"
MACOS_DIR="$APP/Contents/MacOS"
INFO_PLIST="$APP/Contents/Info.plist"

# 7a. policies.json — same patch as Linux/Windows, but the macOS path
#     inside the bundle is Contents/Resources/distribution/policies.json
#     (Mullvad puts distribution/ under Resources on Mac).
POLICIES_CANDIDATES=(
    "$RESOURCES/distribution/policies.json"
    "$RESOURCES/browser/distribution/policies.json"
)
POLICIES=""
for p in "${POLICIES_CANDIDATES[@]}"; do
    [[ -f "$p" ]] && POLICIES="$p" && break
done
if [[ -z "$POLICIES" ]]; then
    # Mullvad sometimes ships without a distribution/ dir; create one.
    POLICIES="$RESOURCES/distribution/policies.json"
    mkdir -p "$(dirname "$POLICIES")"
fi
cp "$REPO/browser-fork/patches/repackage/policies.json" "$POLICIES"
# Leave @@INSTALL_DIR@@ as-is. The Go launcher's selfheal pass
# rewrites it on first launch with the actual extract path. Per-OS
# config in internal/config sets ResourceRoot to the right value
# (Contents/Resources on macOS, install root on Win/Linux).

# 7b. Pre-installed extension.
mkdir -p "$(dirname "$POLICIES")/extensions"
cp "$XPI" "$(dirname "$POLICIES")/extensions/anon-layer@anon.gratis.xpi"

# 7c. Branding icons + omni.ja patching (identical to Windows path).
log "     patching omni.ja"
OMNI="$RESOURCES/browser/omni.ja"
[[ -f "$OMNI" ]] || OMNI="$RESOURCES/omni.ja"
[[ -f "$OMNI" ]] || die "no omni.ja found under $RESOURCES"

python3 - <<PY "$OMNI" "$REPO"
import io, os, sys, zipfile
from PIL import Image

jar_path = sys.argv[1]
repo     = sys.argv[2]
src_png  = f"{repo}/browser-fork/branding/source/anonymous-logo.png"

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

# 7d. Autoconfig + mozilla.cfg. The Mac bundle's macOS-equivalent
#     layout is Contents/Resources/defaults/pref/ and Contents/Resources/.
mkdir -p "$RESOURCES/defaults/pref"
cp "$REPO/browser-fork/patches/repackage/autoconfig/anon-autoconfig.js" \
   "$RESOURCES/defaults/pref/anon-autoconfig.js"
cp "$REPO/browser-fork/patches/repackage/autoconfig/mozilla.cfg" \
   "$RESOURCES/mozilla.cfg"

# 7e. AnonLayer bundle inside Contents/Resources/.
ANON_DIR="$RESOURCES/AnonLayer"
mkdir -p "$ANON_DIR"/{bridge/bin,bridge/modules,tor/{bin,etc,run},config/descriptors,share}
cp "$NODE_DIR/bin/node" "$ANON_DIR/bin-node"  # avoid name collision with tor/bin
mkdir -p "$ANON_DIR/node/bin" && mv "$ANON_DIR/bin-node" "$ANON_DIR/node/bin/node"
cp "$TOR_BIN" "$ANON_DIR/tor/bin/tor"
cp -a "$WORK/tor-expert/tor/"* "$ANON_DIR/tor/bin/" 2>/dev/null || true
[[ -d "$WORK/tor-expert/data" ]] && cp -a "$WORK/tor-expert/data" "$ANON_DIR/tor/data"
cp -a "$REPO/bin/anon-browse-gui.mjs" "$ANON_DIR/bridge/bin/"
cp -a "$REPO/bin/anon-browse.mjs"     "$ANON_DIR/bridge/bin/" 2>/dev/null || true
cp -a "$REPO/modules" "$ANON_DIR/bridge/"

TPL_TOR="$REPO/browser-fork/patches/repackage/tor"
[[ -f "$TPL_TOR/torrc.template"    ]] && cp "$TPL_TOR/torrc.template"    "$ANON_DIR/tor/etc/"
[[ -f "$TPL_TOR/anon.pac.template" ]] && cp "$TPL_TOR/anon.pac.template" "$ANON_DIR/tor/etc/"

cat > "$ANON_DIR/config/anon-browser.conf.example" <<EOF
# Anonymous Browser — config (macOS)
#
# Rename to anon-browser.conf before first launch. Paths are relative
# to the .app bundle root (Anonymous.app/Contents/Resources/AnonLayer).

DA_URLS=https://da1.anon.gratis,https://da2.anon.gratis,https://da3.anon.gratis
CONSENSUS=config/consensus.bin
DA_TRUST=config/da-trust.json
DESCRIPTOR_DIR=config/descriptors
HSDIR_URL=https://da1.anon.gratis
ALLOW_CO_LOCATED=1
ANON_DISABLE_I2P=1
EOF

[[ -f "$REPO/deploy/state/demo-service.descriptor.bin" ]] && \
    cp "$REPO/deploy/state/demo-service.descriptor.bin" "$ANON_DIR/config/descriptors/"
if [[ -f "$REPO/deploy/state/da-trust-entries.json" ]]; then
    # Strip the documentation "//" key — loadDaTrustSet treats every
    # top-level key as a hex fingerprint and rejects non-hex like `//`.
    # Same fix the Linux + Windows repackage scripts apply.
    python3 -c "import json,sys; d=json.load(open('$REPO/deploy/state/da-trust-entries.json')); d={k:v for k,v in d.items() if not k.startswith('//')}; json.dump(d, open('$ANON_DIR/config/da-trust.json','w'), indent=2)"
fi

cp "$REPO/browser-fork/branding/generated/icon-256.png" "$ANON_DIR/share/anon-browser.png"

# 7f. Install the Go launcher as the bundle's main executable. Save
#     the original firefox launcher's CFBundleExecutable name so we
#     can chain to it from the Go launcher.
ORIG_EXEC="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$INFO_PLIST")"
log "     original CFBundleExecutable: $ORIG_EXEC"
cp "$LAUNCHER_BIN" "$MACOS_DIR/anonymous"
chmod +x "$MACOS_DIR/anonymous"
/usr/libexec/PlistBuddy -c 'Set :CFBundleExecutable anonymous' "$INFO_PLIST"
/usr/libexec/PlistBuddy -c "Set :CFBundleName Anonymous"        "$INFO_PLIST" || true
/usr/libexec/PlistBuddy -c "Set :CFBundleDisplayName Anonymous" "$INFO_PLIST" || true
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier gratis.anonymous.browser" "$INFO_PLIST" || true

# Save the original engine name so the launcher knows what to chain to.
# (Phase 3 self-heal: the launcher's macOS browser.pickEngine can read
# this file if present, or fall back to the standard "firefox" name.)
echo -n "$ORIG_EXEC" > "$RESOURCES/.engine-binary"

# 7g. App icon — replace Mullvad's .icns with ours if iconutil works.
ICONSET="$WORK/anonymous.iconset"
mkdir -p "$ICONSET"
SRC_PNG="$REPO/browser-fork/branding/source/anonymous-logo.png"
sips -z 16 16     "$SRC_PNG" --out "$ICONSET/icon_16x16.png"     >/dev/null
sips -z 32 32     "$SRC_PNG" --out "$ICONSET/icon_16x16@2x.png"  >/dev/null
sips -z 32 32     "$SRC_PNG" --out "$ICONSET/icon_32x32.png"     >/dev/null
sips -z 64 64     "$SRC_PNG" --out "$ICONSET/icon_32x32@2x.png"  >/dev/null
sips -z 128 128   "$SRC_PNG" --out "$ICONSET/icon_128x128.png"   >/dev/null
sips -z 256 256   "$SRC_PNG" --out "$ICONSET/icon_128x128@2x.png" >/dev/null
sips -z 256 256   "$SRC_PNG" --out "$ICONSET/icon_256x256.png"   >/dev/null
sips -z 512 512   "$SRC_PNG" --out "$ICONSET/icon_256x256@2x.png" >/dev/null
sips -z 512 512   "$SRC_PNG" --out "$ICONSET/icon_512x512.png"   >/dev/null
sips -z 1024 1024 "$SRC_PNG" --out "$ICONSET/icon_512x512@2x.png" >/dev/null
ICNS="$RESOURCES/firefox.icns"
[[ -f "$RESOURCES/Mullvad Browser.icns" ]] && ICNS="$RESOURCES/Mullvad Browser.icns"
iconutil -c icns "$ICONSET" -o "$ICNS" && log "     wrote $ICNS"

# ---------- 8. build the .dmg ----------

OUT_DMG="$DIST/anonymous-${OUR_VERSION}-macos-${TARGET_ARCH}.dmg"
log "8/9  building DMG → $OUT_DMG"
rm -f "$OUT_DMG"
hdiutil create -volname "Anonymous Browser" \
               -srcfolder "$APP" \
               -ov -format UDZO \
               "$OUT_DMG" >/dev/null
log "     dmg size: $(du -h "$OUT_DMG" | cut -f1)"

# ---------- 9. sha256 + done ----------

log "9/9  writing checksum"
if command -v sha256sum >/dev/null 2>&1; then
    ( cd "$DIST" && sha256sum "$(basename "$OUT_DMG")" > "$(basename "$OUT_DMG").sha256" )
else
    ( cd "$DIST" && shasum -a 256 "$(basename "$OUT_DMG")" > "$(basename "$OUT_DMG").sha256" )
fi

log "✓ done"
log "  $OUT_DMG"
log "  $OUT_DMG.sha256"
log ""
log "Distribution: submit to Homebrew Cask (see browser-fork/distribution/homebrew-cask/)."
log "Note: this build is UNSIGNED and UNNOTARIZED. Direct-download users"
log "will hit Gatekeeper; Homebrew Cask strips the quarantine attribute."
