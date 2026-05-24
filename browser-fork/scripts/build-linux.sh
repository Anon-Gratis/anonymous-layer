#!/usr/bin/env bash
# Build the Anon Browser fork on Linux.
#
# Tested findings (from sandbox validation in chunk 12.3):
#   - mach needs a Python venv with `filelock` + `packaging` available
#     (Ubuntu 24.04 forbids `pip install --user` via PEP 668; venv works)
#   - mach configure transitively includes ~100 directories of source
#     (js/, dom/, widget/, gfx/, modules/, layout/, etc.); a full
#     checkout (not sparse) is required for the build
#   - LLVM toolchain (clang, llvm-objdump) is required by Firefox; gcc
#     alone won't work
#   - sudo is required for the system-package install in
#     `mach bootstrap`
#
# Prerequisites:
#   - Ubuntu 22.04 LTS or Debian 12 (clean VM recommended)
#   - sudo access for ./mach bootstrap step
#   - ~80 GB free disk space
#   - 16 GB RAM minimum
#   - 2-4 hour build time on modest hardware
#
# Output:
#   ./build/linux/dist/  (the built browser directory)
#   ./build/linux/anon-browser-VERSION-linux-x86_64.tar.bz2

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_DIR="$REPO/mullvad-browser"
OBJ_DIR="$REPO/build/linux"
VENV_DIR="$HOME/.venvs/anon-browser-mach"

if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "error: $SOURCE_DIR not found. Run:" >&2
    echo "    scripts/fetch-source.sh" >&2
    echo "    scripts/apply-patches.sh" >&2
    exit 1
fi

# --- Step 1: prerequisite check ---
echo "→ checking prerequisites…"
missing=()
for cmd in git make gcc g++ python3 rustc cargo clang clang++ llvm-objdump; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
done
if [[ ${#missing[@]} -gt 0 ]]; then
    echo "  missing commands: ${missing[*]}" >&2
    echo
    echo "  Install via:"
    echo "    sudo apt update && sudo apt install -y \\"
    echo "        build-essential clang llvm libgtk-3-dev libdbus-glib-1-dev \\"
    echo "        libpulse-dev libasound-dev python3-pip python3-venv mercurial wget curl"
    echo "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
    echo "    source ~/.cargo/env"
    echo
    echo "  OR let \`./mach bootstrap\` install everything (also needs sudo):"
    echo "    cd $SOURCE_DIR && ./mach bootstrap --application-choice=browser --no-interactive"
    exit 1
fi
echo "  OK"

# --- Step 2: Python venv (mach needs filelock + packaging at bootstrap time) ---
if [[ ! -d "$VENV_DIR" ]]; then
    echo "→ creating Python venv for mach prerequisites at $VENV_DIR"
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install -q filelock packaging
fi
# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

# --- Step 3: build ---
echo "→ building Anon Browser (Linux x86_64)"
echo "  source: $SOURCE_DIR"
echo "  obj:    $OBJ_DIR"

cd "$SOURCE_DIR"
export MOZ_OBJDIR="$OBJ_DIR"

# Configure step (~1 min) — populates $OBJ_DIR with build files.
./mach configure

# Build step (~2 hours).
./mach build

# Package step (~5 min) — produces the tarball.
./mach package

echo
echo "Build complete. Artifact:"
ls -lh "$OBJ_DIR/dist/" | grep -E '\.tar\.bz2|\.deb|\.rpm' || echo "  (look in $OBJ_DIR/dist/)"

echo
echo "To install locally:"
echo "  cd $OBJ_DIR/dist/"
echo "  tar xjf anon-browser-*.tar.bz2"
echo "  cd anon-browser && ./anon-browser"
