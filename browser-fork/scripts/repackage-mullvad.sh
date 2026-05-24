#!/usr/bin/env bash
# repackage-mullvad.sh — build "Anon Browser" by repackaging Mullvad
# Browser with our policies, pre-installed WebExtension, bundled Node
# runtime, and our launcher.
#
# This is the "no-source-build" path: Mullvad has done the hard work of
# compiling and hardening Gecko. We add our anon-layer-specific bits on
# top. The output is a working, branded browser tarball that ships in
# weeks, not months.
#
# What the output is NOT: a fully-from-source fork. The engine,
# fingerprint, and security baseline are Mullvad's. We do not modify
# the binary itself (only resources alongside it). For a true fork see
# the (much larger) browser-fork/scripts/build-linux.sh path.
#
# Usage:
#   browser-fork/scripts/repackage-mullvad.sh                   # download + build
#   browser-fork/scripts/repackage-mullvad.sh --offline TARBALL # use an already-downloaded Mullvad tarball
#   browser-fork/scripts/repackage-mullvad.sh --version 15.0.14 --node-version 20.20.1
#
# Required tools: bash, curl, tar, xz, zip, node (any modern version,
# only used at build-time; the bundled runtime is downloaded fresh).
#
# Output: dist/anon-browser-<our-version>-linux-x86_64.tar.xz

set -euo pipefail

# ---------- defaults ----------

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
MULLVAD_VERSION="${MULLVAD_VERSION:-15.0.14}"
NODE_VERSION="${NODE_VERSION:-20.20.1}"
PLATFORM="${PLATFORM:-linux-x86_64}"
NODE_PLATFORM="${NODE_PLATFORM:-linux-x64}"
OUR_VERSION="${OUR_VERSION:-$(grep -E '"version"' "$REPO/package.json" | head -1 | sed -E 's/.*"version"\s*:\s*"([^"]+)".*/\1/')}"
DIST="${DIST:-$REPO/dist}"
WORK="${WORK:-$(mktemp -d -t anon-browser-build.XXXXXX)}"
OFFLINE_TARBALL=""
SKIP_GPG=0
KEEP_WORK=0

# ---------- arg parse ----------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)         MULLVAD_VERSION="$2"; shift 2 ;;
        --node-version)    NODE_VERSION="$2"; shift 2 ;;
        --offline)         OFFLINE_TARBALL="$2"; shift 2 ;;
        --output)          DIST="$2"; shift 2 ;;
        --work)            WORK="$2"; shift 2 ;;
        --skip-gpg)        SKIP_GPG=1; shift ;;
        --keep-work)       KEEP_WORK=1; shift ;;
        -h|--help)
            sed -n '2,30p' "$0"; exit 0 ;;
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

log "Anon Browser repackage v${OUR_VERSION}"
log "  Mullvad version : ${MULLVAD_VERSION}"
log "  Node version    : ${NODE_VERSION}"
log "  Platform        : ${PLATFORM}"
log "  Work dir        : ${WORK}"
log "  Output          : ${DIST}"

# ---------- 1. acquire Mullvad Browser ----------

MULLVAD_TARBALL="$WORK/mullvad-browser-${PLATFORM}-${MULLVAD_VERSION}.tar.xz"

if [[ -n "$OFFLINE_TARBALL" ]]; then

    [[ -f "$OFFLINE_TARBALL" ]] || die "offline tarball not found: $OFFLINE_TARBALL"
    log "1/8  using offline Mullvad tarball: $OFFLINE_TARBALL"
    cp "$OFFLINE_TARBALL" "$MULLVAD_TARBALL"

else

    URL="https://cdn.mullvad.net/browser/${MULLVAD_VERSION}/mullvad-browser-${PLATFORM}-${MULLVAD_VERSION}.tar.xz"
    log "1/8  downloading Mullvad Browser (${URL})"
    curl -fL --progress-bar -o "$MULLVAD_TARBALL" "$URL" \
        || die "Mullvad Browser download failed; check version availability"

    if [[ $SKIP_GPG -eq 0 ]] && command -v gpg >/dev/null 2>&1; then
        log "     fetching .asc and attempting GPG verify"
        curl -fL --progress-bar -o "${MULLVAD_TARBALL}.asc" "${URL}.asc" \
            || log "     (warning) no .asc; skipping verify"
        # The Mullvad signing key fingerprint is documented at
        # https://mullvad.net/en/help/keys (publish-key fingerprint
        # subject to rotation). We don't trust-on-first-use here; we
        # require the user to have already imported the key into their
        # keyring. If they haven't, the verify fails noisily and the
        # build aborts. Use --skip-gpg to bypass.
        if [[ -f "${MULLVAD_TARBALL}.asc" ]]; then
            if gpg --verify "${MULLVAD_TARBALL}.asc" "$MULLVAD_TARBALL" 2>&1 | tail -5 >&2; then
                log "     ✓ GPG verify succeeded"
            else
                die "GPG verify failed. Import Mullvad's signing key, or pass --skip-gpg."
            fi
        fi
    else
        log "     (skipping GPG — pass nothing if you want it; --skip-gpg suppresses this notice)"
    fi

fi

log "     unpacking Mullvad tarball"
( cd "$WORK" && tar -xJf "$MULLVAD_TARBALL" )

# Mullvad's tarball extracts to ./mullvad-browser/
[[ -d "$WORK/mullvad-browser" ]] || die "expected ./mullvad-browser/ after unpack; got: $(ls "$WORK")"
BROWSER_ROOT="$WORK/mullvad-browser"

# ---------- 2. acquire Node runtime ----------

NODE_TARBALL="$WORK/node-v${NODE_VERSION}-${NODE_PLATFORM}.tar.xz"
NODE_URL="https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-${NODE_PLATFORM}.tar.xz"
log "2/8  downloading Node ${NODE_VERSION} (${NODE_URL})"
curl -fL --progress-bar -o "$NODE_TARBALL" "$NODE_URL" \
    || die "Node download failed"
( cd "$WORK" && tar -xJf "$NODE_TARBALL" )
NODE_DIR="$WORK/node-v${NODE_VERSION}-${NODE_PLATFORM}"
[[ -x "$NODE_DIR/bin/node" ]] || die "expected bin/node at $NODE_DIR/bin/node"

# ---------- 3. build the WebExtension ----------

log "3/8  building the WebExtension (.xpi)"
( cd "$REPO/browser-fork/extension" && ./build-xpi.sh --validate >/dev/null )
XPI="$(ls -1t "$REPO/browser-fork/extension/dist/"*.xpi | head -1)"
[[ -f "$XPI" ]] || die "no .xpi found after build-xpi.sh"
log "     using $XPI"

# ---------- 4. assemble AnonLayer/ sidecar inside the browser dir ----------

log "4/8  staging AnonLayer/ sidecar (Node runtime + bridge)"
ANON_DIR="$BROWSER_ROOT/AnonLayer"
mkdir -p "$ANON_DIR/node/bin" "$ANON_DIR/bridge/bin" "$ANON_DIR/bridge/modules" "$ANON_DIR/config" "$ANON_DIR/share"

# Bundled Node — strip headers/docs to save ~30%
cp -a "$NODE_DIR/bin/node" "$ANON_DIR/node/bin/node"
# (no npm/npx in the shipped runtime; the launcher only needs `node`)

# Bridge code + protocol modules
cp "$REPO/bin/anon-browse-gui.mjs" "$ANON_DIR/bridge/bin/"
cp "$REPO/bin/anon-browse.mjs"     "$ANON_DIR/bridge/bin/"
cp -a "$REPO/modules/."            "$ANON_DIR/bridge/modules/"
cp    "$REPO/package.json"         "$ANON_DIR/bridge/package.json"

# Production-only dependencies
PROD_DEPS_DIR="$WORK/prod-deps"
mkdir -p "$PROD_DEPS_DIR"
cp "$REPO/package.json"      "$PROD_DEPS_DIR/"
cp "$REPO/package-lock.json" "$PROD_DEPS_DIR/"
log "     installing production-only deps"
( cd "$PROD_DEPS_DIR" && npm install --omit=dev --quiet --no-audit --no-fund >/dev/null )
cp -a "$PROD_DEPS_DIR/node_modules" "$ANON_DIR/bridge/node_modules"

# Example config + share/
cat > "$ANON_DIR/config/anon-browser.conf.example" <<'EOF'
# Anon Browser bridge configuration.
#
# Edit this file and rename to anon-browser.conf before first run.
# The launcher reads it via `source`, so use plain shell syntax.
#
# --- Option A: connect mode (single-node test / development) ---
# Useful for kicking the tires against a single anon-node on localhost.
# CONNECT="127.0.0.1:31000"
#
# --- Option B: rendezvous mode (production) ---
# Choose a hidden service to browse via consensus + descriptor.
# CONSENSUS=/path/to/consensus.bin
# DA_TRUST=/path/to/da-trust.json
#
# Descriptor sources — set at least one. The bridge indexes every
# descriptor by its onion address and routes per-URL host, so you can
# browse any number of services in one session.
# DESCRIPTOR=/path/to/single-service.descriptor.bin       # single .bin
# DESCRIPTOR_DIR=/path/to/dir-of-descriptors              # all *.bin in dir
# Both may be set; the bridge merges them. An unknown `.anon` host
# returns a clean error (no silent misroute to a "default" service).
#
# Optional: ALLOW_CO_LOCATED=1 disables anti-correlation guards. Do not
# set this in production unless you understand the threat model in
# docs/THREAT_MODEL.md.
#
# --- Bundled overlay networks ---
# Tor (for .onion) starts automatically and appears in the bootstrap
# splash. Set ANON_DISABLE_TOR=1 to skip starting it; the PAC will
# route *.onion to a sentinel port so the browser refuses immediately
# rather than hanging.
# ANON_DISABLE_TOR=0
#
# --- i2p (EXPERIMENTAL — disabled by default) ---
# i2pd is bundled but does not start unless you opt in below. It is
# shipped as a preview because the current configuration has a known
# unlinkability gap (i2pd's HTTPProxy uses a single shared tunnel
# pool, so every .i2p tab shares one circuit). The integration will
# be re-enabled by default after the audit closes and per-destination
# tunnel isolation is configured. See docs/THREAT_MODEL.md.
# Until then: opting in is fine for testing, but do not rely on .i2p
# routing for anything sensitive.
# ANON_DISABLE_I2P=1   # set to 0 to opt in to the experimental i2p stack
EOF
cp "$REPO/browser-fork/extension/icons/icon-256.png" "$ANON_DIR/share/anon-browser.png" 2>/dev/null || true

# ---------- 5. apply policies + user.js ----------

log "5/8  applying policies.json and user.js"

# Mullvad Browser policy file path (their distribution channel).
# Layout: <root>/Browser/distribution/policies.json
mkdir -p "$BROWSER_ROOT/Browser/distribution"
cp "$REPO/browser-fork/patches/repackage/policies.json" "$BROWSER_ROOT/Browser/distribution/policies.json"

# Per-profile user.js. Layout moved between Mullvad versions:
#   Mullvad ≤ 14.x: Browser/TorBrowser/Data/Browser/profile.default/user.js
#   Mullvad ≥ 15.x: Browser/defaults/profile/user.js   (Firefox defaults dir;
#                   contents are copied into new user profiles at creation)
if [[ -d "$BROWSER_ROOT/Browser/TorBrowser/Data/Browser/profile.default" ]]; then
    # Pre-15 layout: bundled profile.default. Drop user.js straight in.
    USERJS_DEST="$BROWSER_ROOT/Browser/TorBrowser/Data/Browser/profile.default/user.js"
elif [[ -d "$BROWSER_ROOT/Browser/defaults" ]]; then
    # Mullvad ≥ 15: ship default user.js under defaults/profile/. Firefox
    # copies these into a new user profile when the browser first runs.
    mkdir -p "$BROWSER_ROOT/Browser/defaults/profile"
    USERJS_DEST="$BROWSER_ROOT/Browser/defaults/profile/user.js"
else
    die "Mullvad tarball layout not recognized: no profile.default or Browser/defaults/"
fi
cp "$REPO/browser-fork/patches/repackage/user.js" "$USERJS_DEST"
log "     wrote $USERJS_DEST"

# Anonymous command-line aesthetic: userChrome.css / userContent.css
# alongside the user.js. Firefox copies the whole defaults/profile/
# tree (including chrome/) into a new profile at first launch.
PROFILE_DEFAULTS_DIR="$(dirname "$USERJS_DEST")"
CHROME_SRC="$REPO/browser-fork/patches/repackage/profile/chrome"
if [[ -d "$CHROME_SRC" ]]; then
    mkdir -p "$PROFILE_DEFAULTS_DIR/chrome"
    cp "$CHROME_SRC/userChrome.css"   "$PROFILE_DEFAULTS_DIR/chrome/"
    cp "$CHROME_SRC/userContent.css"  "$PROFILE_DEFAULTS_DIR/chrome/"
    log "     wrote $PROFILE_DEFAULTS_DIR/chrome/{userChrome,userContent}.css"
fi

# Autoconfig: force-loads userChrome/userContent via nsIStyleSheetService.
# Needed because Mullvad-derived builds appear to either gate or strip
# the standard toolkit.legacyUserProfileCustomizations.stylesheets path,
# so dropping the CSS in <profile>/chrome/ alone is not enough.
AUTOCONFIG_SRC="$REPO/browser-fork/patches/repackage/autoconfig"
if [[ -d "$AUTOCONFIG_SRC" ]]; then
    cp "$AUTOCONFIG_SRC/mozilla.cfg"           "$BROWSER_ROOT/Browser/mozilla.cfg"
    cp "$AUTOCONFIG_SRC/anon-autoconfig.js"    "$BROWSER_ROOT/Browser/defaults/pref/anon-autoconfig.js"
    log "     wrote $BROWSER_ROOT/Browser/mozilla.cfg + defaults/pref/anon-autoconfig.js"
fi

# Tor templates: torrc + PAC. The tor binary itself is vendored by
# scripts/fetch-tor-bundle.sh (kept separate so this repackage step
# stays offline-friendly). Launcher materialises per-launch
# torrc/PAC into AnonLayer/tor/run/ with the chosen ports.
TOR_SRC="$REPO/browser-fork/patches/repackage/tor"
if [[ -d "$TOR_SRC" ]]; then
    mkdir -p "$BROWSER_ROOT/AnonLayer/tor/etc"
    cp "$TOR_SRC/torrc.template"      "$BROWSER_ROOT/AnonLayer/tor/etc/torrc.template"
    cp "$TOR_SRC/anon.pac.template"   "$BROWSER_ROOT/AnonLayer/tor/etc/anon.pac.template"
    log "     wrote $BROWSER_ROOT/AnonLayer/tor/etc/{torrc,anon.pac}.template"
    if [[ ! -x "$BROWSER_ROOT/AnonLayer/tor/bin/tor" ]]; then
        log "     NOTE: AnonLayer/tor/bin/tor not present — run scripts/fetch-tor-bundle.sh"
    fi
fi

# i2pd templates: i2pd.conf. The i2pd binary + reseed certificates
# are vendored by scripts/fetch-i2pd-bundle.sh (same offline-friendly
# pattern as tor). Launcher materialises per-launch i2pd.conf into
# AnonLayer/i2pd/run/ with the chosen ports.
I2PD_SRC="$REPO/browser-fork/patches/repackage/i2pd"
if [[ -d "$I2PD_SRC" ]]; then
    mkdir -p "$BROWSER_ROOT/AnonLayer/i2pd/etc"
    cp "$I2PD_SRC/i2pd.conf.template" "$BROWSER_ROOT/AnonLayer/i2pd/etc/i2pd.conf.template"
    log "     wrote $BROWSER_ROOT/AnonLayer/i2pd/etc/i2pd.conf.template"
    if [[ ! -x "$BROWSER_ROOT/AnonLayer/i2pd/bin/i2pd" ]]; then
        log "     NOTE: AnonLayer/i2pd/bin/i2pd not present — run scripts/fetch-i2pd-bundle.sh"
    fi
fi

# ---------- 6. pre-install our WebExtension ----------

log "6/8  installing the WebExtension into distribution/extensions"

# Firefox / Mullvad reads extensions out of:
#   <root>/Browser/distribution/extensions/<id>.xpi
# where <id> matches browser_specific_settings.gecko.id in our manifest.
EXT_ID="$(node -e "console.log(JSON.parse(require('fs').readFileSync('$REPO/browser-fork/extension/manifest.json')).browser_specific_settings.gecko.id)")"
[[ -n "$EXT_ID" ]] || die "could not read gecko.id from extension manifest"
EXT_DEST="$BROWSER_ROOT/Browser/distribution/extensions"
mkdir -p "$EXT_DEST"

# Drop the Mullvad-VPN companion extension that ships in upstream tarballs.
# Its toolbar button is a Mullvad-VPN UI (marmot icon, mullvad.net links,
# proxy permissions) — irrelevant to anon-layer and a phone-home vector
# (it auto-updates from cdn.mullvad.net). Removing it also makes room for
# our own anon-layer button on the toolbar.
MULLVAD_EXT_XPI="$EXT_DEST/{d19a89b9-76c1-4a61-bcd4-49e8de916403}.xpi"
if [[ -f "$MULLVAD_EXT_XPI" ]]; then
    rm -f "$MULLVAD_EXT_XPI"
    log "     removed Mullvad Browser Extension: ${MULLVAD_EXT_XPI##*/}"
fi

cp "$XPI" "$EXT_DEST/${EXT_ID}.xpi"
log "     installed: $EXT_DEST/${EXT_ID}.xpi"

# ---------- 7. install our launcher ----------

log "7/8  applying Anonymous branding (rebrand.sh)"
"$REPO/browser-fork/scripts/rebrand.sh" "$BROWSER_ROOT"

log "7.5/8  installing anonymous launcher"
cp "$REPO/browser-fork/scripts/anon-browser.launcher.sh" "$BROWSER_ROOT/anonymous"
chmod +x "$BROWSER_ROOT/anonymous"

# Top-level README — branded Anonymous; engine credits live in About > Credits.
cat > "$BROWSER_ROOT/README.txt" <<EOF
Anonymous ${OUR_VERSION}
================================================================
A privacy-focused web browser with native support for the
anon-layer network.

Quick start
-----------
1. cp AnonLayer/config/anon-browser.conf.example \\
      AnonLayer/config/anon-browser.conf
2. Edit anon-browser.conf and set CONNECT=… or the three rendezvous
   paths (CONSENSUS, DA_TRUST, DESCRIPTOR).
3. Run:  ./anonymous
   The launcher starts the bridge in the background and opens the
   browser.

What's where
------------
  Browser/                       Browser engine
  AnonLayer/node/bin/node        Bundled Node.js ${NODE_VERSION}
  AnonLayer/bridge/              Our anon-layer protocol stack
  AnonLayer/tor/                 Bundled Tor (for .onion routing)
  AnonLayer/i2pd/                Bundled i2pd (EXPERIMENTAL — off by default)
  AnonLayer/config/              Where you put your bridge config
  AnonLayer/share/               Brand assets
  anonymous                      The launcher you run
  Browser/start-anonymous        Engine launcher called by ours

Overlay networks
----------------
This build bundles Tor for .onion access (enabled by default) and
i2pd for .i2p access (EXPERIMENTAL — disabled by default). The
i2pd integration is wired and reachable but ships disabled until
the audit closes and per-destination tunnel isolation is configured;
the current shared-tunnel-pool default would link your .i2p tabs to
each other. To opt in for testing, set ANON_DISABLE_I2P=0 in
anon-browser.conf. Do not rely on .i2p routing for anything sensitive
until this notice is removed.

Engine credits and licenses
---------------------------
Help → About Anonymous → Credits (or load \`about:credits\` in the
URL bar) for the engine's full attribution chain. The engine is
unmodified; the LICENSE file in this tarball applies to it.

For the threat model see docs/THREAT_MODEL.md in the source repo.
EOF

# ---------- 8. repack as the Anon Browser tarball ----------

log "8/8  repackaging as anonymous-${OUR_VERSION}-${PLATFORM}.tar.xz"

# Rename the top-level directory inside the tarball so users get
# `anonymous-<version>/` not `mullvad-browser/`.
STAGE_NAME="anonymous-${OUR_VERSION}-${PLATFORM}"
mv "$BROWSER_ROOT" "$WORK/${STAGE_NAME}"

OUTPUT="$DIST/${STAGE_NAME}.tar.xz"
( cd "$WORK" && tar --owner=0 --group=0 -cJf "$OUTPUT" "${STAGE_NAME}" )

# Also a quick sha256 alongside
( cd "$DIST" && sha256sum "${STAGE_NAME}.tar.xz" > "${STAGE_NAME}.tar.xz.sha256" )

SIZE_HUMAN="$(du -sh "$OUTPUT" | cut -f1)"
log "✓ built ${OUTPUT} (${SIZE_HUMAN})"
log "  sha256: $(cut -d' ' -f1 < "${OUTPUT}.sha256")"
echo
echo "Install / test:"
echo "  tar -xJf ${OUTPUT}"
echo "  cd ${STAGE_NAME}"
echo "  cp AnonLayer/config/anon-browser.conf.example AnonLayer/config/anon-browser.conf"
echo "  \$EDITOR AnonLayer/config/anon-browser.conf       # set CONNECT= or CONSENSUS=/DA_TRUST=/DESCRIPTOR="
echo "  ./anonymous"
