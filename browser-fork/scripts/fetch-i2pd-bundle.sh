#!/usr/bin/env bash
# fetch-i2pd-bundle.sh — download + verify the PurpleI2P i2pd release
# tarball and extract the i2pd binary into a build's AnonLayer/i2pd/bin/.
# Mirrors fetch-tor-bundle.sh in spirit: vendored, statically-linked,
# no host dependencies leaked in.
#
# Why i2pd (and not the Java i2p router): single C++ binary, ~10MB,
# no JRE, fast cold start. Right fit for a browser bundle. The Java
# router has a richer feature set but the cost in tarball size and
# startup latency is not worth it for a v0.
#
# Usage:
#   fetch-i2pd-bundle.sh <BROWSER_ROOT> [VERSION]
#
# BROWSER_ROOT — install layout (the one with Browser/ + AnonLayer/)
# VERSION      — i2pd release tag. Defaults to EXPECTED_VERSION below.
#                Bump when a newer i2pd is needed; verify the asset name
#                still matches the ASSET_TEMPLATE pattern.

set -euo pipefail

BROWSER_ROOT="${1:?usage: fetch-i2pd-bundle.sh <BROWSER_ROOT> [VERSION]}"
VERSION="${2:-${EXPECTED_VERSION:-2.60.0}}"

# PurpleI2P uses a single naming pattern across recent releases:
#   i2pd_${VERSION}_x86_64_linux.tar.bz2
# If a future release changes the naming, override via I2PD_ASSET=.
ASSET_TEMPLATE="${I2PD_ASSET_TEMPLATE:-i2pd_%s_x86_64_linux.tar.bz2}"
# shellcheck disable=SC2059
ASSET="$(printf "$ASSET_TEMPLATE" "$VERSION")"
URL="${I2PD_URL:-https://github.com/PurpleI2P/i2pd/releases/download/${VERSION}/${ASSET}}"
SIG_URL="${URL}.asc"

DIST_DIR="${I2PD_DIST_CACHE:-${TMPDIR:-/tmp}/anon-i2pd-dist}"
mkdir -p "$DIST_DIR"

log() { printf 'fetch-i2pd: %s\n' "$*"; }
die() { printf 'fetch-i2pd: %s\n' "$*" >&2; exit 1; }

# 1. Download.
if [[ ! -f "$DIST_DIR/$ASSET" ]]; then
    log "downloading $URL"
    curl -fsSL -o "$DIST_DIR/$ASSET.part" "$URL" \
        || die "download failed (URL: $URL)"
    mv "$DIST_DIR/$ASSET.part" "$DIST_DIR/$ASSET"
fi

# 2. Optional signature verification.
#
# Not every i2pd release ships a detached .asc on GitHub; if one is
# present we verify it, otherwise we fall through with a loud notice.
# To enforce signature presence set I2PD_REQUIRE_SIG=1.
SIG_OK=0
if curl -fsI "$SIG_URL" >/dev/null 2>&1; then
    if [[ ! -f "$DIST_DIR/$ASSET.asc" ]]; then
        log "downloading $SIG_URL"
        curl -fsSL -o "$DIST_DIR/$ASSET.asc.part" "$SIG_URL" \
            || die "signature download failed"
        mv "$DIST_DIR/$ASSET.asc.part" "$DIST_DIR/$ASSET.asc"
    fi
    if command -v gpg >/dev/null 2>&1; then
        log "verifying signature"
        gpg --verify "$DIST_DIR/$ASSET.asc" "$DIST_DIR/$ASSET" \
            || die "GPG verification failed — refusing to extract"
        SIG_OK=1
    else
        die "gpg not available; cannot verify signature"
    fi
else
    if [[ "${I2PD_REQUIRE_SIG:-0}" == "1" ]]; then
        die "no .asc for $ASSET at $SIG_URL and I2PD_REQUIRE_SIG=1"
    fi
    log "NOTE: no detached .asc available for $ASSET — skipping signature verify"
    log "      (set I2PD_REQUIRE_SIG=1 to make this fatal)"
fi

# 3. Extract just the i2pd binary and its certificates.
EXTRACT_DIR="$(mktemp -d)"
trap 'rm -rf "$EXTRACT_DIR"' EXIT
log "extracting"
tar -xjf "$DIST_DIR/$ASSET" -C "$EXTRACT_DIR"

# PurpleI2P tarball layout (as of 2.5x):
#   i2pd_${VERSION}/i2pd                # binary
#   i2pd_${VERSION}/certificates/...    # reseed signing certs
#   i2pd_${VERSION}/contrib/...         # default configs, ignored
SRC_DIR="$EXTRACT_DIR/i2pd_${VERSION}"
[[ -d "$SRC_DIR" ]] || SRC_DIR="$(find "$EXTRACT_DIR" -maxdepth 2 -type d -name 'i2pd*' | head -1)"
[[ -d "$SRC_DIR" ]] || die "unrecognised tarball layout; expected i2pd_${VERSION}/"
[[ -x "$SRC_DIR/i2pd" ]] || die "no i2pd binary found in tarball"

I2PD_DEST="$BROWSER_ROOT/AnonLayer/i2pd"
mkdir -p "$I2PD_DEST/bin" "$I2PD_DEST/share"
install -m 0755 "$SRC_DIR/i2pd" "$I2PD_DEST/bin/i2pd"

# Certificates are required for reseed (the SU3 signing keys live
# here). Without them i2pd refuses to verify a reseed bundle and
# never bootstraps.
if [[ -d "$SRC_DIR/certificates" ]]; then
    cp -r "$SRC_DIR/certificates" "$I2PD_DEST/share/"
fi

log "installed $("$I2PD_DEST/bin/i2pd" --version 2>&1 | head -1)"
log "  -> $I2PD_DEST/bin/i2pd"
[[ "$SIG_OK" -eq 1 ]] && log "  signature: verified" || log "  signature: not verified"
