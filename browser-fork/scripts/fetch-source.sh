#!/usr/bin/env bash
# Fetch the Mullvad Browser source tree.
#
# Output: ./mullvad-browser/ (untouched clone)
#
# Usage: scripts/fetch-source.sh [TAG]
#   TAG defaults to "main" — set to a specific release tag for
#   reproducible builds (e.g. "v14.5.0").

set -euo pipefail

REPO_URL="${MULLVAD_BROWSER_REPO_URL:-https://gitlab.torproject.org/tpo/applications/mullvad-browser.git}"
TARGET_DIR="${TARGET_DIR:-./mullvad-browser}"
TAG="${1:-main}"

if [[ -d "$TARGET_DIR/.git" ]]; then
    echo "→ $TARGET_DIR already exists; updating to $TAG"
    cd "$TARGET_DIR"
    git fetch --all
    git checkout "$TAG"
    git pull
else
    echo "→ Cloning $REPO_URL into $TARGET_DIR (~30 GB)"
    git clone --branch "$TAG" "$REPO_URL" "$TARGET_DIR"
fi

echo
echo "Source ready at: $TARGET_DIR"
echo "Next: scripts/apply-patches.sh"
