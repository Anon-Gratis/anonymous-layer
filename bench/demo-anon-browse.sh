#!/usr/bin/env bash
# Demo: spin up an anon-site server, launch anon-browse against it,
# verify that the browser fetches and renders the page.
#
# We can't drive a TUI interactively from a shell script easily, but
# we CAN verify the fetch + parse + layout path by checking that the
# browser process stays alive, then sending it 'q' to quit.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TMPROOT="$(mktemp -d -t anon-browse-demo.XXXXXX)"
PORT=$(( (RANDOM % 30000) + 30000 ))

cleanup() {
    kill %1 2>/dev/null || true
    rm -rf "$TMPROOT"
}
trap cleanup EXIT

# --- Build a tiny site ---
cat > "$TMPROOT/index.anon" <<'EOF'
# anon-browse demo

Welcome to the demo site. This page exercises every text/anon line
type so the renderer can be eyeballed for correctness.

## Headings

### Subsection

## Links

=> /about.anon       About this site
=> /resources.anon   Additional resources
=> https://example.org/  Off-network link (HTTPS — should be marked)

## Lists

* first item
* second item
* third item

## Quotes

> The protocol is the artefact; the implementation is the proof.

## Code

```
echo "verbatim text inside a code block"
```

EOF

cat > "$TMPROOT/about.anon" <<'EOF'
# About

This is an `anon-browse` demo site. Return home:

=> /  Go back to the index
EOF

# --- Start the server ---
node "$REPO/bin/anon-site-server.mjs" "$TMPROOT" --port "$PORT" --quiet &
sleep 0.5

# --- Mint a valid .anon address for the demo ---
ONION=$(node --input-type=module -e "
import { encodeOnionAddress } from '$REPO/modules/v2/onion_address.mjs';
process.stdout.write(encodeOnionAddress(new Uint8Array(32).fill(0x55)));
")

# --- Launch the browser; verify it loads the index without crashing.
# We pipe 'q' after a short delay so the browser quits cleanly. The
# output is the TUI render — a lot of ANSI escapes — so we sanity-
# check it contains the expected page text.
echo "--- demo: anon-browse fetches anon://$ONION/ ---"
OUTPUT=$(
    node "$REPO/bin/anon-browse.mjs" \
        "anon://$ONION/" \
        --connect "127.0.0.1:$PORT" \
        --no-color --dump
) || true

if echo "$OUTPUT" | grep -q "anon-browse demo"; then
    echo "  ✓ page title 'anon-browse demo' rendered"
else
    echo "  ✗ did not find 'anon-browse demo' in output"
    echo "--- output sample ---"
    echo "$OUTPUT" | head -30
    exit 1
fi

if echo "$OUTPUT" | grep -q "About this site"; then
    echo "  ✓ link description 'About this site' rendered"
else
    echo "  ✗ did not find 'About this site' link"
    exit 1
fi

if echo "$OUTPUT" | grep -q "first item"; then
    echo "  ✓ list item rendered"
else
    echo "  ✗ did not find list items"
    exit 1
fi

if echo "$OUTPUT" | grep -q "protocol is the artefact"; then
    echo "  ✓ blockquote rendered"
else
    echo "  ✗ did not find blockquote"
    exit 1
fi

echo "--- demo: all checks passed ---"
