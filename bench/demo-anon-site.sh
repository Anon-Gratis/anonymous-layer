#!/usr/bin/env bash
# Demo: serve an anon-site directory over TCP, fetch with the CLI client.
#
# Builds a small site in a tempdir, runs the server, fetches the index,
# asserts the response, then tears down. Intended as a smoke test for
# the bin/anon-site-{server,client}.mjs CLIs end-to-end.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TMPROOT="$(mktemp -d -t anon-site-demo.XXXXXX)"
trap 'kill %1 2>/dev/null || true; rm -rf "$TMPROOT"' EXIT

# --- Build a tiny site ---
cat > "$TMPROOT/index.anon" <<'EOF'
# Welcome to my .anon site

This is a demo page served via the reference anon-site protocol.

=> /about.anon  About this site
=> anon://thisexampledoesnotexistanditsfingerprintwillfail.anon/elsewhere  Off-site link

## Code example

```
echo "hello from a code block"
```

* item one
* item two

> Quoted text from somewhere wise.
EOF

cat > "$TMPROOT/about.anon" <<'EOF'
# About

A reference site served by `bin/anon-site-server.mjs` for demo purposes.

=> /  Back to home
EOF

# --- Start the server in the background ---
PORT=$(( (RANDOM % 30000) + 30000 ))
node "$REPO/bin/anon-site-server.mjs" "$TMPROOT" --port "$PORT" --quiet &
SERVER_PID=$!
sleep 0.5  # give the server a moment to bind

# --- Build a valid sample .anon URL using the codec ---
# The CLI rejects URLs whose host isn't a real .anon address (checksum
# verified), so we mint one from a fixed SVC_pk for the demo.
ONION=$(node --input-type=module -e "
import { encodeOnionAddress } from '$REPO/modules/v2/onion_address.mjs';
process.stdout.write(encodeOnionAddress(new Uint8Array(32).fill(0x33)));
")

URL="anon://$ONION/"

echo "--- demo: fetching $URL ---"
node "$REPO/bin/anon-site-client.mjs" "$URL" --connect "127.0.0.1:$PORT" --no-color

echo "--- demo: fetching /about.anon ---"
node "$REPO/bin/anon-site-client.mjs" "anon://$ONION/about.anon" --connect "127.0.0.1:$PORT" --no-color

echo "--- demo: 404 case ---"
set +e
node "$REPO/bin/anon-site-client.mjs" "anon://$ONION/does-not-exist" --connect "127.0.0.1:$PORT" --no-color
RC=$?
set -e
if [[ "$RC" -ne 1 ]]; then
    echo "FAIL: expected exit code 1 for 404, got $RC"
    exit 1
fi

echo "--- demo: all checks passed ---"
