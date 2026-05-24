#!/usr/bin/env bash
# Build the Anon Browser fork on macOS.
#
# Prerequisites:
#   - macOS hardware (Apple Silicon or Intel)
#   - Xcode + Command Line Tools
#   - homebrew installed
#   - `brew install autoconf@2.13 yasm`
#   - Apple Developer Program membership ($99/year)
#   - Code signing identity in Keychain (after enrolling)
#   - Mullvad Browser source tree (./mullvad-browser/)
#   - ~100 GB free disk space
#   - 16 GB RAM
#   - 2-3 hour build time
#
# Output:
#   ./build/macos/dist/Anon Browser.app  (signed if APPLE_SIGNING_ID set)
#   ./build/macos/dist/Anon Browser.dmg (after running create-dmg manually)
#
# NOTE: This script does NOT handle notarization. After building +
# signing, run:
#   xcrun notarytool submit --apple-id $APPLE_ID --password $APP_PWD \
#       --team-id $TEAM_ID --wait "Anon Browser.dmg"
#   xcrun stapler staple "Anon Browser.dmg"
# See https://developer.apple.com/documentation/security/customizing-the-notarization-workflow

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_DIR="$REPO/mullvad-browser"
OBJ_DIR="$REPO/build/macos"

# Build for both architectures by default. Set MOZ_ARCH=x86_64 or arm64
# to build for one.
ARCH="${MOZ_ARCH:-universal}"

if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "error: $SOURCE_DIR not found. Run fetch-source.sh then apply-patches.sh." >&2
    exit 1
fi

echo "→ Building Anon Browser (macOS $ARCH)"

cd "$SOURCE_DIR"

./mach bootstrap --application-choice=browser --no-interactive

mkdir -p "$OBJ_DIR"
export MOZ_OBJDIR="$OBJ_DIR"

case "$ARCH" in
    arm64)
        cat >> mozconfig.local <<'EOF'
ac_add_options --target=aarch64-apple-darwin
EOF
        ;;
    x86_64)
        cat >> mozconfig.local <<'EOF'
ac_add_options --target=x86_64-apple-darwin
EOF
        ;;
    universal)
        # Build x86_64 first, then arm64, then lipo together.
        # mach has limited universal-binary support; manual is simpler.
        echo "→ Universal build: building x86_64 then arm64..."
        ARCH=x86_64 "$0"
        ARCH=arm64  "$0"
        echo "→ TODO: lipo universal merge (see Mozilla docs)"
        exit 0
        ;;
    *)
        echo "error: ARCH must be x86_64, arm64, or universal" >&2
        exit 1
        ;;
esac

./mach build
./mach package

# Sign (if APPLE_SIGNING_ID set, e.g. "Developer ID Application: Anonymous Layer (TEAMID)").
if [[ -n "${APPLE_SIGNING_ID:-}" ]]; then
    echo "→ Signing with $APPLE_SIGNING_ID"
    APP="$OBJ_DIR/dist/Anon Browser.app"
    codesign --force --deep --options runtime \
        --entitlements "$SOURCE_DIR/security/mac/hardenedruntime/v2/production/browser.production.entitlements.xml" \
        --sign "$APPLE_SIGNING_ID" "$APP"
    echo "  signed: $APP"
else
    echo "→ No APPLE_SIGNING_ID set; build is UNSIGNED (won't run on default-config Macs)"
fi

echo
echo "Build complete."
echo "Next steps:"
echo "  1. Create .dmg:  create-dmg --volname \"Anon Browser\" \"$OBJ_DIR/dist/Anon Browser.dmg\" \"$OBJ_DIR/dist/Anon Browser.app\""
echo "  2. Notarize:     xcrun notarytool submit ..."
echo "  3. Staple:       xcrun stapler staple ..."
