#!/usr/bin/env bash
# Demo: spin up an anon-site server + anon-browse-gui (in --connect
# mode) and verify the JSON API correctly returns parsed text/anon
# lines for a known URL.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TMPROOT="$(mktemp -d -t anon-gui-demo.XXXXXX)"
SITE_PORT=$(( (RANDOM % 30000) + 30000 ))
GUI_PORT=$(( SITE_PORT + 1 ))

cleanup() {
    kill %1 %2 2>/dev/null || true
    sleep 0.2
    kill -9 %1 %2 2>/dev/null || true
    rm -rf "$TMPROOT"
}
trap cleanup EXIT

# A tiny site
cat > "$TMPROOT/index.anon" <<'EOF'
# anon-browse-gui demo

Welcome to the GUI demo.

## Features

* Renders text/anon to DOM
* Click links to navigate
* History with back/forward

=> /about.anon   About this site
=> https://example.org/  External link
EOF
cat > "$TMPROOT/about.anon" <<'EOF'
# About

This page was fetched via the GUI's JSON API.

=> /  Back home
EOF

# Start the anon-site backend
node "$REPO/bin/anon-site-server.mjs" "$TMPROOT" --port "$SITE_PORT" --quiet &
sleep 0.3

# Start the GUI
node "$REPO/bin/anon-browse-gui.mjs" \
    --connect "127.0.0.1:$SITE_PORT" \
    --listen 127.0.0.1 --port "$GUI_PORT" \
    >"$TMPROOT/gui.log" 2>&1 &
sleep 0.6

# Pull the session token out of the GUI's startup banner
TOKEN=$(grep -oE 'token=[a-f0-9]+' "$TMPROOT/gui.log" | head -1 | cut -d= -f2)
if [[ -z "$TOKEN" ]]; then
    echo "✗ failed to extract session token from GUI log:"
    cat "$TMPROOT/gui.log"
    exit 1
fi
echo "  session token: ${TOKEN:0:16}…"

# Mint a sample onion URL
ONION=$(node --input-type=module -e "
import { encodeOnionAddress } from '$REPO/modules/v2/onion_address.mjs';
process.stdout.write(encodeOnionAddress(new Uint8Array(32).fill(0x99)));
")

echo "--- demo: HTML loaded? ---"
HTML=$(curl -sf "http://127.0.0.1:$GUI_PORT/?token=$TOKEN")
if echo "$HTML" | grep -q "anon-browse"; then
    echo "  ✓ HTML served (contains 'anon-browse')"
else
    echo "  ✗ HTML did not contain expected content"
    exit 1
fi

echo "--- demo: HTML refused without token? ---"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$GUI_PORT/")
if [[ "$HTTP_CODE" == "403" ]]; then
    echo "  ✓ correctly returned 403 without token"
else
    echo "  ✗ expected 403, got $HTTP_CODE"
    exit 1
fi

echo "--- demo: /api/fetch returns parsed text/anon ---"
RESP=$(curl -sf "http://127.0.0.1:$GUI_PORT/api/fetch?token=$TOKEN&url=anon%3A%2F%2F$ONION%2F")
if echo "$RESP" | grep -q '"kind":"document"'; then
    echo "  ✓ JSON response includes kind:document"
else
    echo "  ✗ unexpected response:"
    echo "$RESP" | head -3
    exit 1
fi
if echo "$RESP" | grep -q 'anon-browse-gui demo'; then
    echo "  ✓ page title 'anon-browse-gui demo' present in lines"
else
    echo "  ✗ page title missing"
    exit 1
fi
if echo "$RESP" | grep -q '"type":"link"'; then
    echo "  ✓ link line types present"
else
    echo "  ✗ no link lines"
    exit 1
fi

echo "--- demo: /api/fetch refused without token? ---"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$GUI_PORT/api/fetch?url=anon%3A%2F%2F$ONION%2F")
if [[ "$HTTP_CODE" == "403" ]]; then
    echo "  ✓ API correctly returned 403 without token"
else
    echo "  ✗ expected 403, got $HTTP_CODE"
    exit 1
fi

echo "--- demo: all checks passed ---"
