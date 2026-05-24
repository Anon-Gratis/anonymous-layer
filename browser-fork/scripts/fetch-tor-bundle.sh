#!/usr/bin/env bash
# fetch-tor-bundle.sh — download + verify the Tor Project's official
# Tor Expert Bundle and extract the tor binary into a build's
# AnonLayer/tor/bin/. Run during the build pipeline; the regular
# repackage-mullvad.sh leaves bin/tor empty if absent.
#
# Why the expert bundle: it's the official, signed, statically-linked
# tor distribution from the Tor Project. No system libraries leak in,
# no Ubuntu-vs-Fedora dependency drift, signatures verifiable via
# torproject.org's release keys.
#
# Usage:
#   fetch-tor-bundle.sh <BROWSER_ROOT> [VERSION]
#
# BROWSER_ROOT — the install layout (the one with Browser/ + AnonLayer/)
# VERSION      — Tor Expert Bundle version. Defaults to the version
#                hard-coded in EXPECTED_VERSION below; bump alongside
#                Mullvad/Tor Browser releases.

set -euo pipefail

BROWSER_ROOT="${1:?usage: fetch-tor-bundle.sh <BROWSER_ROOT> [VERSION]}"
VERSION="${2:-${EXPECTED_VERSION:-15.0.14}}"

# Architecture: only linux-x86_64 in v0. Add aarch64 / macOS / windows
# once we have tested launchers for them.
ARCH="linux-x86_64"

DIST_DIR="${TOR_DIST_CACHE:-${TMPDIR:-/tmp}/anon-tor-dist}"
mkdir -p "$DIST_DIR"

ARCHIVE="tor-expert-bundle-${ARCH}-${VERSION}.tar.gz"
URL="https://dist.torproject.org/torbrowser/${VERSION}/${ARCHIVE}"
SIG_URL="${URL}.asc"

log() { printf 'fetch-tor: %s\n' "$*"; }
die() { printf 'fetch-tor: %s\n' "$*" >&2; exit 1; }

# 1. Download.
if [[ ! -f "$DIST_DIR/$ARCHIVE" ]]; then
    log "downloading $URL"
    curl -fsSL -o "$DIST_DIR/$ARCHIVE.part" "$URL" \
        || die "download failed"
    mv "$DIST_DIR/$ARCHIVE.part" "$DIST_DIR/$ARCHIVE"
fi
if [[ ! -f "$DIST_DIR/$ARCHIVE.asc" ]]; then
    log "downloading $SIG_URL"
    curl -fsSL -o "$DIST_DIR/$ARCHIVE.asc.part" "$SIG_URL" \
        || die "signature download failed"
    mv "$DIST_DIR/$ARCHIVE.asc.part" "$DIST_DIR/$ARCHIVE.asc"
fi

# 2. Verify signature with the Tor Browser developers key.
#
# The signing key is published at
# https://support.torproject.org/tbb/how-to-verify-signature/.
# For CI: pre-import the key into the build keyring (avoids round-
# tripping keyserver on every build). Locally, you can do
#   gpg --auto-key-locate nodefault,wkd --locate-keys \
#       torbrowser@torproject.org
if command -v gpg >/dev/null 2>&1; then
    log "verifying signature"
    gpg --verify "$DIST_DIR/$ARCHIVE.asc" "$DIST_DIR/$ARCHIVE" \
        || die "GPG verification failed — refusing to extract"
else
    die "gpg not available; refusing to ship unverified tor binary"
fi

# 3. Extract just the tor binary and its lyrebird/snowflake helpers.
EXTRACT_DIR="$(mktemp -d)"
trap 'rm -rf "$EXTRACT_DIR"' EXIT
tar -xzf "$DIST_DIR/$ARCHIVE" -C "$EXTRACT_DIR"

# Expert bundle layout: tor/tor (binary), tor/pluggable_transports/...
TOR_DEST="$BROWSER_ROOT/AnonLayer/tor"
mkdir -p "$TOR_DEST/bin" "$TOR_DEST/share/pluggable_transports"
install -m 0755 "$EXTRACT_DIR/tor/tor" "$TOR_DEST/bin/tor"
if [[ -d "$EXTRACT_DIR/tor/pluggable_transports" ]]; then
    cp -r "$EXTRACT_DIR/tor/pluggable_transports/." \
          "$TOR_DEST/share/pluggable_transports/"
fi

log "installed $($TOR_DEST/bin/tor --version | head -1)"
log "  -> $TOR_DEST/bin/tor"
