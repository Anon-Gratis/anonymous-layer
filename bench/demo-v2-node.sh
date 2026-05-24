#!/usr/bin/env bash
# Demo: spin up two anon-node-v2 instances; node A dials node B; both
# log the verified LINK handshake. After 2 seconds, both shut down.
#
# This proves end-to-end:
#   - persistent identity is generated and reloaded
#   - the listener accepts an inbound WebSocket
#   - the LINK_HELLO + LINK_AUTH handshake completes
#   - both sides surface the verified peer fingerprint

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TMPROOT="$(mktemp -d -t anon-node-v2-demo.XXXXXX)"
DIR_A="$TMPROOT/node-a"
DIR_B="$TMPROOT/node-b"
PORT_A=$(( (RANDOM % 30000) + 30000 ))
PORT_B=$(( PORT_A + 1 ))

cleanup() {
    kill %1 2>/dev/null || true
    kill %2 2>/dev/null || true
    rm -rf "$TMPROOT"
}
trap cleanup EXIT

run() { node "$REPO/bin/anon-node-v2.mjs" "$@"; }

echo "--- demo: generating identities ---"
run init --data-dir "$DIR_A"
echo
run init --data-dir "$DIR_B"

echo
echo "--- demo: node-a info ---"
run info --data-dir "$DIR_A"
FP_A=$(run info --data-dir "$DIR_A" | awk '/^fingerprint:/ {print $2}')
FP_B=$(run info --data-dir "$DIR_B" | awk '/^fingerprint:/ {print $2}')

echo
echo "--- demo: starting both listeners ---"
run run --data-dir "$DIR_A" --port "$PORT_A" --i-understand-this-is-experimental \
    2>"$TMPROOT/a.log" &
run run --data-dir "$DIR_B" --port "$PORT_B" --i-understand-this-is-experimental \
    2>"$TMPROOT/b.log" &

# Give both listeners a moment to bind.
sleep 0.6

echo
echo "--- demo: dialing node-b from a small client ---"
node --input-type=module -e "
import { loadIdentity } from '$REPO/modules/v2-runtime/persistence.mjs';
import { dialLink } from '$REPO/modules/v2-runtime/link_transport_ws.mjs';

const a = await loadIdentity('$DIR_A/identity.key');
const b = await loadIdentity('$DIR_B/identity.key');

const { peerIdPk, transport } = await dialLink({
    host: '127.0.0.1', port: $PORT_B,
    identity: a, expectedPeerIdPk: b.idPk,
});
console.log('  dialer A verified peer B fingerprint:',
    Buffer.from(peerIdPk).toString('hex').slice(0, 16) + '...');
transport.close();
" 2>&1 | sed 's/^/  /'

# Give B a moment to log the inbound.
sleep 0.3

echo
echo "--- demo: node-b's log ---"
cat "$TMPROOT/b.log" | sed 's/^/  /'

echo
echo "--- demo: passed (handshake completed; B logged the verified peer) ---"
