#!/usr/bin/env bash
# Build the Anon Browser fork on Windows.
#
# This is a bash script for a Cygwin/WSL/Git Bash shell. The
# underlying build uses Mozilla's `mach` toolchain which works under
# MSYS / Git Bash.
#
# Prerequisites:
#   - Windows 11
#   - Visual Studio 2022 with C++ workload + Windows SDK
#   - Mozilla Build prerequisites: https://firefox-source-docs.mozilla.org/setup/windows_build.html
#   - MozillaBuild environment (provides bash, python, etc.)
#   - Mullvad Browser source tree (./mullvad-browser/)
#   - ~120 GB free disk
#   - 16 GB RAM
#   - 2-4 hour build time
#   - EV code signing certificate (for SmartScreen pass)
#
# Output:
#   ./build/windows/dist/install/sea/anon-browser-VERSION.exe
#
# NOTE: This script does NOT handle code signing. After build, sign with:
#   signtool sign /a /tr http://timestamp.digicert.com /td sha256 /fd sha256 anon-browser.exe

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_DIR="$REPO/mullvad-browser"
OBJ_DIR="$REPO/build/windows"

if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "error: $SOURCE_DIR not found. Run fetch-source.sh then apply-patches.sh." >&2
    exit 1
fi

echo "→ Building Anon Browser (Windows x64)"
echo "  Run this from a MozillaBuild bash shell, NOT WSL."

cd "$SOURCE_DIR"

./mach bootstrap --application-choice=browser --no-interactive

mkdir -p "$OBJ_DIR"
export MOZ_OBJDIR="$OBJ_DIR"

./mach build
./mach package
./mach build installer

echo
echo "Build complete. Artifacts:"
ls -lh "$OBJ_DIR/dist/install/sea/" 2>/dev/null || true

echo
echo "Next steps (in a Windows command prompt with EV cert hardware token plugged in):"
echo "  signtool sign /a /tr http://timestamp.digicert.com /td sha256 /fd sha256 \\"
echo "      anon-browser-installer.exe"
echo "  signtool verify /pa /v anon-browser-installer.exe"
