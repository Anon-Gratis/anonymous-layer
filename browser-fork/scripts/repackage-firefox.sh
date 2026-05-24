#!/usr/bin/env bash
# repackage-firefox.sh — build "Anon Browser" by repackaging vanilla
# Firefox ESR with our policies, autoconfig, pre-installed WebExtension,
# bundled Node runtime, and our launcher.
#
# Sibling of repackage-mullvad.sh. Same idea, different upstream:
# vanilla Firefox ESR direct from Mozilla. Trades Mullvad's anti-
# fingerprinting (and its locked policies that kept blocking our
# customizations) for a permissive base we can configure ourselves.
#
# Usage:
#   browser-fork/scripts/repackage-firefox.sh                       # download + build
#   browser-fork/scripts/repackage-firefox.sh --offline TARBALL     # use a local tarball
#   browser-fork/scripts/repackage-firefox.sh --version 128.13.0esr
#
# Required tools: bash, curl, tar, xz, zip, node, npm.
#
# Output: dist/anonymous-<our-version>-linux-x86_64.tar.xz

set -euo pipefail

# ---------- defaults ----------

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
FIREFOX_VERSION="${FIREFOX_VERSION:-140.11.0esr}"
NODE_VERSION="${NODE_VERSION:-20.20.1}"
PLATFORM="${PLATFORM:-linux-x86_64}"
NODE_PLATFORM="${NODE_PLATFORM:-linux-x64}"
OUR_VERSION="${OUR_VERSION:-$(grep -E '"version"' "$REPO/package.json" | head -1 | sed -E 's/.*"version"\s*:\s*"([^"]+)".*/\1/')}"
DIST="${DIST:-$REPO/dist}"
WORK="${WORK:-$(mktemp -d -t anon-browser-build.XXXXXX)}"
OFFLINE_TARBALL=""
KEEP_WORK=0

# Mozilla uses `linux-x86_64` in their CDN paths.
MOZ_PLATFORM_PATH="linux-x86_64"

# ---------- arg parse ----------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)         FIREFOX_VERSION="$2"; shift 2 ;;
        --node-version)    NODE_VERSION="$2"; shift 2 ;;
        --offline)         OFFLINE_TARBALL="$2"; shift 2 ;;
        --output)          DIST="$2"; shift 2 ;;
        --work)            WORK="$2"; shift 2 ;;
        --keep-work)       KEEP_WORK=1; shift ;;
        -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

mkdir -p "$DIST" "$WORK"

log() { printf '[%s] %s\n' "$(date -u '+%H:%M:%SZ')" "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

cleanup() {
    if [[ $KEEP_WORK -eq 0 ]]; then
        log "cleaning $WORK"
        rm -rf "$WORK"
    else
        log "leaving $WORK in place (--keep-work)"
    fi
}
trap cleanup EXIT

log "Anon Browser repackage v${OUR_VERSION} (Firefox ESR base)"
log "  Firefox version : ${FIREFOX_VERSION}"
log "  Node version    : ${NODE_VERSION}"
log "  Platform        : ${PLATFORM}"
log "  Work dir        : ${WORK}"
log "  Output          : ${DIST}"

# ---------- 1. acquire Firefox ESR ----------

# Mozilla's CDN serves .tar.xz for modern releases.
FIREFOX_TARBALL="$WORK/firefox-${FIREFOX_VERSION}.tar.xz"

if [[ -n "$OFFLINE_TARBALL" ]]; then
    [[ -f "$OFFLINE_TARBALL" ]] || die "offline tarball not found: $OFFLINE_TARBALL"
    log "1/8  using offline Firefox tarball: $OFFLINE_TARBALL"
    cp "$OFFLINE_TARBALL" "$FIREFOX_TARBALL"
else
    URL="https://ftp.mozilla.org/pub/firefox/releases/${FIREFOX_VERSION}/${MOZ_PLATFORM_PATH}/en-US/firefox-${FIREFOX_VERSION}.tar.xz"
    log "1/8  downloading Firefox ESR (${URL})"
    if ! curl -fL --progress-bar -o "$FIREFOX_TARBALL" "$URL"; then
        # Older releases may use .tar.bz2.
        URL_BZ2="${URL%.tar.xz}.tar.bz2"
        log "     .tar.xz not found; trying .tar.bz2 (${URL_BZ2})"
        FIREFOX_TARBALL="$WORK/firefox-${FIREFOX_VERSION}.tar.bz2"
        curl -fL --progress-bar -o "$FIREFOX_TARBALL" "$URL_BZ2" \
            || die "Firefox download failed; check version availability at https://ftp.mozilla.org/pub/firefox/releases/${FIREFOX_VERSION}/${MOZ_PLATFORM_PATH}/en-US/"
    fi

    # SHA256 verification against the SHA256SUMS file Mozilla publishes.
    SUMS_URL="https://ftp.mozilla.org/pub/firefox/releases/${FIREFOX_VERSION}/SHA256SUMS"
    log "     fetching SHA256SUMS and verifying"
    if curl -fL --progress-bar -o "$WORK/SHA256SUMS" "$SUMS_URL"; then
        EXPECTED=$(grep "${MOZ_PLATFORM_PATH}/en-US/$(basename "$FIREFOX_TARBALL")" "$WORK/SHA256SUMS" | awk '{print $1}')
        if [[ -n "$EXPECTED" ]]; then
            ACTUAL=$(sha256sum "$FIREFOX_TARBALL" | awk '{print $1}')
            if [[ "$EXPECTED" == "$ACTUAL" ]]; then
                log "     ✓ SHA256 match"
            else
                die "SHA256 mismatch: expected $EXPECTED, got $ACTUAL"
            fi
        else
            log "     (warning) couldn't find our tarball in SHA256SUMS — skipping verify"
        fi
    else
        log "     (warning) couldn't fetch SHA256SUMS — skipping verify"
    fi
fi

log "     unpacking Firefox tarball"
case "$FIREFOX_TARBALL" in
    *.tar.xz)  ( cd "$WORK" && tar -xJf "$FIREFOX_TARBALL" ) ;;
    *.tar.bz2) ( cd "$WORK" && tar -xjf "$FIREFOX_TARBALL" ) ;;
    *) die "unrecognised tarball extension: $FIREFOX_TARBALL" ;;
esac

# Mozilla's tarball extracts to ./firefox/
[[ -d "$WORK/firefox" ]] || die "expected ./firefox/ after unpack; got: $(ls "$WORK")"
BROWSER_ROOT="$WORK/firefox"

# ---------- 2. acquire Node runtime ----------

NODE_TARBALL="$WORK/node-v${NODE_VERSION}-${NODE_PLATFORM}.tar.xz"
NODE_URL="https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-${NODE_PLATFORM}.tar.xz"
log "2/8  downloading Node ${NODE_VERSION} (${NODE_URL})"
curl -fL --progress-bar -o "$NODE_TARBALL" "$NODE_URL" \
    || die "Node download failed"
( cd "$WORK" && tar -xJf "$NODE_TARBALL" )
NODE_DIR="$WORK/node-v${NODE_VERSION}-${NODE_PLATFORM}"
[[ -x "$NODE_DIR/bin/node" ]] || die "expected bin/node at $NODE_DIR/bin/node"

# ---------- 3. (extension build skipped) ----------
#
# The Firefox-ESR build handles .anon URLs natively via the mozilla.cfg
# URL-bar hook (see browser-fork/patches/repackage/autoconfig/mozilla.cfg
# section 6). The legacy WebExtension at browser-fork/extension/ is no
# longer shipped; section 6 below also no longer installs it.

log "3/8  skipping WebExtension build (native URL-bar handling instead)"

# ---------- 4. assemble AnonLayer/ sidecar inside the browser dir ----------

log "4/8  staging AnonLayer/ sidecar (Node runtime + bridge)"
ANON_DIR="$BROWSER_ROOT/AnonLayer"
mkdir -p "$ANON_DIR/node/bin" "$ANON_DIR/bridge/bin" "$ANON_DIR/bridge/modules" "$ANON_DIR/config" "$ANON_DIR/share"

cp -a "$NODE_DIR/bin/node" "$ANON_DIR/node/bin/node"

cp "$REPO/bin/anon-browse-gui.mjs" "$ANON_DIR/bridge/bin/"
cp "$REPO/bin/anon-browse.mjs"     "$ANON_DIR/bridge/bin/"
cp -a "$REPO/modules/."            "$ANON_DIR/bridge/modules/"
cp    "$REPO/package.json"         "$ANON_DIR/bridge/package.json"

PROD_DEPS_DIR="$WORK/prod-deps"
mkdir -p "$PROD_DEPS_DIR"
cp "$REPO/package.json"      "$PROD_DEPS_DIR/"
cp "$REPO/package-lock.json" "$PROD_DEPS_DIR/"
log "     installing production-only deps"
( cd "$PROD_DEPS_DIR" && npm install --omit=dev --quiet --no-audit --no-fund >/dev/null )
cp -a "$PROD_DEPS_DIR/node_modules" "$ANON_DIR/bridge/node_modules"

cat > "$ANON_DIR/config/anon-browser.conf.example" <<'EOF'
# Anon Browser bridge configuration.
#
# Edit this file and rename to anon-browser.conf before first run.
# CONSENSUS=/path/to/consensus.bin
# DA_TRUST=/path/to/da-trust.json
# DESCRIPTOR_DIR=/path/to/dir-of-descriptors
# HSDIR_URL=https://da1.anon.gratis
# DA_URLS=https://da1.anon.gratis,https://da2.anon.gratis
# ALLOW_CO_LOCATED=1
EOF
cp "$REPO/browser-fork/extension/icons/icon-256.png" "$ANON_DIR/share/anon-browser.png" 2>/dev/null || true

# ---------- 5. apply policies + user.js + autoconfig ----------
#
# Vanilla Firefox layout (no Mullvad-style Browser/ subdir):
#   <root>/firefox          — the binary
#   <root>/distribution/    — enterprise policy file goes here
#   <root>/defaults/pref/   — autoconfig pointer goes here
#   <root>/defaults/profile — user.js, chrome/* baked into new profiles
#   <root>/mozilla.cfg      — autoconfig script (loaded via defaults/pref/anon-autoconfig.js)
#
# This is FLATTER than Mullvad's <root>/Browser/* layout — adjust paths
# throughout this step accordingly.

log "5/8  applying policies.json + user.js + autoconfig"

mkdir -p "$BROWSER_ROOT/distribution"
cp "$REPO/browser-fork/patches/repackage/policies.json" "$BROWSER_ROOT/distribution/policies.json"

mkdir -p "$BROWSER_ROOT/defaults/profile"
USERJS_DEST="$BROWSER_ROOT/defaults/profile/user.js"
cp "$REPO/browser-fork/patches/repackage/user.js" "$USERJS_DEST"
log "     wrote $USERJS_DEST"

CHROME_SRC="$REPO/browser-fork/patches/repackage/profile/chrome"
if [[ -d "$CHROME_SRC" ]]; then
    mkdir -p "$BROWSER_ROOT/defaults/profile/chrome"
    cp "$CHROME_SRC/userChrome.css"  "$BROWSER_ROOT/defaults/profile/chrome/"
    cp "$CHROME_SRC/userContent.css" "$BROWSER_ROOT/defaults/profile/chrome/"
    log "     wrote chrome stylesheets"
fi

AUTOCONFIG_SRC="$REPO/browser-fork/patches/repackage/autoconfig"
if [[ -d "$AUTOCONFIG_SRC" ]]; then
    cp "$AUTOCONFIG_SRC/mozilla.cfg"        "$BROWSER_ROOT/mozilla.cfg"
    mkdir -p "$BROWSER_ROOT/defaults/pref"
    cp "$AUTOCONFIG_SRC/anon-autoconfig.js" "$BROWSER_ROOT/defaults/pref/anon-autoconfig.js"
    log "     wrote $BROWSER_ROOT/mozilla.cfg + defaults/pref/anon-autoconfig.js"
fi

# Tor templates carry over unchanged — launcher gracefully skips Tor
# when AnonLayer/tor/bin/tor isn't present, which it won't be on the
# vanilla-Firefox build until scripts/fetch-tor-bundle.sh runs.
TOR_SRC="$REPO/browser-fork/patches/repackage/tor"
if [[ -d "$TOR_SRC" ]]; then
    mkdir -p "$BROWSER_ROOT/AnonLayer/tor/etc"
    cp "$TOR_SRC/torrc.template"    "$BROWSER_ROOT/AnonLayer/tor/etc/torrc.template"
    cp "$TOR_SRC/anon.pac.template" "$BROWSER_ROOT/AnonLayer/tor/etc/anon.pac.template"
fi

# ---------- 6. (no WebExtension to install) ----------

log "6/8  no WebExtension to install (native URL-bar handling in mozilla.cfg)"

# ---------- 7. install the anonymous launcher ----------

log "7/8  installing anonymous launcher"
cp "$REPO/browser-fork/scripts/anon-browser.launcher.sh" "$BROWSER_ROOT/anonymous"
chmod +x "$BROWSER_ROOT/anonymous"

# Vanilla Firefox: the engine launcher is just `firefox` (the binary).
# Our launcher.sh tries `Browser/start-anonymous` then `start-anonymous`;
# add a symlink so the existing launcher finds it without modification.
ln -sf firefox "$BROWSER_ROOT/start-anonymous"

cat > "$BROWSER_ROOT/README.txt" <<EOF
Anonymous ${OUR_VERSION} (Firefox ESR base)
================================================================
A privacy-focused web browser with native support for the
anon-layer network.

Quick start
-----------
1. cp AnonLayer/config/anon-browser.conf.example \\
      AnonLayer/config/anon-browser.conf
2. Edit anon-browser.conf and set CONSENSUS, DA_TRUST, DESCRIPTOR_DIR
   and (optionally) HSDIR_URL.
3. Run:  ./anonymous

What's where
------------
  firefox                        Browser engine (Firefox ESR ${FIREFOX_VERSION})
  mozilla.cfg                    Browser-level autoconfig (URL-bar .anon hook)
  distribution/policies.json     Enterprise policies
  AnonLayer/node/bin/node        Bundled Node.js ${NODE_VERSION}
  AnonLayer/bridge/              Anon-layer protocol stack
  AnonLayer/config/              Bridge configuration
  AnonLayer/tor/                 Tor templates (binary fetched separately)
  anonymous                      The launcher you run
  start-anonymous                Symlink to the engine binary

The browser still says "Firefox" in places (About dialog, UA string).
We don't rebrand the binary in this build — that requires modifying
omni.ja string tables. For now we accept the Firefox identity and
layer our customizations on top.
EOF

# ---------- 8. repack ----------

log "8/8  repackaging as anonymous-${OUR_VERSION}-${PLATFORM}.tar.xz"

STAGE_NAME="anonymous-${OUR_VERSION}-${PLATFORM}-firefox"
mv "$BROWSER_ROOT" "$WORK/${STAGE_NAME}"

OUTPUT="$DIST/${STAGE_NAME}.tar.xz"
( cd "$WORK" && tar --owner=0 --group=0 -cJf "$OUTPUT" "${STAGE_NAME}" )

( cd "$DIST" && sha256sum "${STAGE_NAME}.tar.xz" > "${STAGE_NAME}.tar.xz.sha256" )

SIZE_HUMAN="$(du -sh "$OUTPUT" | cut -f1)"
log "✓ built ${OUTPUT} (${SIZE_HUMAN})"
log "  sha256: $(cut -d' ' -f1 < "${OUTPUT}.sha256")"
echo
echo "Install / test:"
echo "  tar -xJf ${OUTPUT}"
echo "  cd ${STAGE_NAME}"
echo "  cp AnonLayer/config/anon-browser.conf.example AnonLayer/config/anon-browser.conf"
echo "  \$EDITOR AnonLayer/config/anon-browser.conf"
echo "  ./anonymous"
