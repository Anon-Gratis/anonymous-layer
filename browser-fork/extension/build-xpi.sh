#!/usr/bin/env bash
# build-xpi.sh — package the extension into a loadable .xpi.
#
# Output: ./dist/anon-layer-<version>.xpi
#
# An .xpi is just a zip with a known extension. Firefox will accept it
# loaded temporarily via about:debugging → "This Firefox" → "Load
# Temporary Add-on" (the file picker shows manifest.json directly; you
# can also feed it the .xpi). For permanent installation you have to
# sign it via AMO (addons.mozilla.org); see README.md.
#
# Usage:
#   browser-fork/extension/build-xpi.sh
#   browser-fork/extension/build-xpi.sh --validate   # also run a manifest sanity check

set -euo pipefail

cd "$(dirname "$0")"
DIST="./dist"
mkdir -p "$DIST"

VERSION="$(grep -E '"version"\s*:' manifest.json | head -n1 | sed -E 's/.*"version"\s*:\s*"([^"]+)".*/\1/')"
if [[ -z "${VERSION}" ]]; then
    echo "error: could not parse version from manifest.json" >&2
    exit 1
fi

XPI="${DIST}/anon-layer-${VERSION}.xpi"
rm -f "${XPI}"

# Regenerate icons so a `git clone && build-xpi.sh` is reproducible
# without the developer remembering an extra step.
if [[ ! -s icons/icon-256.png ]]; then
    echo "→ icons missing; running icons/generate.mjs"
    (cd icons && node generate.mjs)
fi

# Files that go into the .xpi (everything an unprivileged extension
# needs at runtime; no node_modules, no docs, no build script itself).
INCLUDE=(
    manifest.json
    background.js
    common.css
    newtab.html
    options.html
    options.js
    popup.html
    popup.js
    render.html
    render.js
    lib/render-doc.mjs
    content/intercept.js
    icons/icon-48.png
    icons/icon-96.png
    icons/icon-256.png
)

# Verify every file exists before we zip.
MISSING=0
for f in "${INCLUDE[@]}"; do
    if [[ ! -f "${f}" ]]; then
        echo "error: missing file: ${f}" >&2
        MISSING=1
    fi
done
[[ "${MISSING}" -eq 0 ]] || exit 1

# Zip is deterministic enough for our purposes (-X strips extra fields;
# we don't try to match every byte across systems).
zip -X -r -q "${XPI}" "${INCLUDE[@]}"

echo "→ built ${XPI} ($(stat -c%s "${XPI}") bytes)"

if [[ "${1:-}" == "--validate" ]]; then
    node validate.mjs "${XPI}"
fi

echo
echo "Install in Mullvad Browser / Firefox:"
echo "  1. about:debugging → This Firefox → Load Temporary Add-on…"
echo "  2. Pick ${XPI}"
echo
echo "Permanent install requires signing via AMO; see README.md."
