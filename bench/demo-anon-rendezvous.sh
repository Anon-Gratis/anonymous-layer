#!/usr/bin/env bash
# End-to-end demo of the v0.2 hidden-service stack:
#   1. Spin up 6 anon-node-v2 relay daemons (subprocess each)
#   2. Generate a consensus file naming all 6
#   3. anon-service init → service identity + descriptor
#   4. anon-service publish → background daemon, publishes via IP
#   5. anon-site-server → serves a tiny test page on a local TCP port
#   6. anon-browse --descriptor → fetches the page via real rendezvous
#   7. assert the page content arrived
#
# This is the canonical "anyone can spin up a node and build a browser"
# demonstration. NOT for production use.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TMPROOT="$(mktemp -d -t anon-rendezvous-demo.XXXXXX)"
LOG_DIR="$TMPROOT/logs"
mkdir -p "$LOG_DIR"

declare -a PIDS=()

cleanup() {
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    sleep 0.3
    for pid in "${PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    rm -rf "$TMPROOT"
}
trap cleanup EXIT

bg() { "$@" & PIDS+=($!); }

# --- 1. Spin up 6 relays ---
echo "--- spinning up 6 relays ---"
RELAY_PORTS=()
RELAY_FPS=()
RELAY_IDPKS=()
RELAY_BPKS=()
for i in 0 1 2 3 4 5; do
    DIR="$TMPROOT/relay-$i"
    PORT=$(( (RANDOM % 30000) + 30000 + i ))
    node "$REPO/bin/anon-node-v2.mjs" init --data-dir "$DIR" >/dev/null
    INFO=$(node "$REPO/bin/anon-node-v2.mjs" info --data-dir "$DIR")
    FP=$(echo "$INFO" | awk '/^fingerprint:/ {print $2}')
    IDPK=$(echo "$INFO" | awk '/^idPk:/ {print $2}')
    BPK=$(echo "$INFO" | awk '/^B_pk:/ {print $2}')
    RELAY_PORTS+=("$PORT")
    RELAY_FPS+=("$FP")
    RELAY_IDPKS+=("$IDPK")
    RELAY_BPKS+=("$BPK")
    # Relay 5 (IP) gets reject-all (it's an IP, not an exit).
    # Relay 2 (RP candidate) needs to accept the local test port.
    if [[ $i -eq 2 ]]; then
        EXIT_POL='reduced'  # accept HTTPS/HTTP/DNS — good enough since we won't use it as a real exit here
    else
        EXIT_POL='reject'
    fi
done

# Wait for all relays to have identities generated.

# --- 2. Build the consensus + DA trust files via anon-mkconsensus ---
echo "--- generating consensus ---"
CONSENSUS_PATH="$TMPROOT/consensus.bin"
DA_TRUST_PATH="$TMPROOT/da-trust.json"
DA_DIR="$TMPROOT/da"
RELAYS_JSON="$TMPROOT/relays.json"

# Write the relays.json input for the mkconsensus build.
{
    echo '['
    for i in 0 1 2 3 4 5; do
        if [[ $i -eq 0 || $i -eq 3 ]]; then EXTRA_FLAGS='"GUARD"'; else EXTRA_FLAGS=''; fi
        if [[ $i -eq 2 || $i -eq 5 ]]; then
            if [[ -n "$EXTRA_FLAGS" ]]; then EXTRA_FLAGS="$EXTRA_FLAGS, \"EXIT\""; else EXTRA_FLAGS='"EXIT"'; fi
        fi
        if [[ $i -eq 2 ]]; then POL='reduced'; else POL='reject'; fi
        SEP=$([[ $i -lt 5 ]] && echo ',' || echo '')
        cat <<JSON
  {
    "fingerprint": "${RELAY_FPS[$i]}",
    "idPk":        "${RELAY_IDPKS[$i]}",
    "B_pk":        "${RELAY_BPKS[$i]}",
    "host":        "127.0.0.1",
    "port":        ${RELAY_PORTS[$i]},
    "flags":       [${EXTRA_FLAGS}],
    "exit_policy": "${POL}"
  }${SEP}
JSON
    done
    echo ']'
} > "$RELAYS_JSON"

node "$REPO/bin/anon-mkconsensus.mjs" init --data-dir "$DA_DIR" 2>&1 | sed 's/^/  /'
node "$REPO/bin/anon-mkconsensus.mjs" build \
    --data-dir "$DA_DIR" \
    --relays "$RELAYS_JSON" \
    --output-consensus "$CONSENSUS_PATH" \
    --output-trust "$DA_TRUST_PATH" \
    --lifetime-seconds 7200 2>&1 | sed 's/^/  /'

# --- 2b. Start the relays now that the consensus exists ---
echo "--- starting relay daemons (with --consensus) ---"
for i in 0 1 2 3 4 5; do
    DIR="$TMPROOT/relay-$i"
    PORT="${RELAY_PORTS[$i]}"
    if [[ $i -eq 2 ]]; then EXIT_POL='reduced'; else EXIT_POL='reject'; fi
    bg node "$REPO/bin/anon-node-v2.mjs" run \
        --data-dir "$DIR" --port "$PORT" \
        --consensus "$CONSENSUS_PATH" \
        --da-trust "$DA_TRUST_PATH" \
        --exit-policy "$EXIT_POL" \
        --i-understand-this-is-experimental \
        >"$LOG_DIR/relay-$i.log" 2>&1
done
sleep 1

# --- 3. Start an anon-site server (the service's local content) ---
echo "--- starting anon-site-server (local content backend) ---"
LOCAL_SITE="$TMPROOT/site"
mkdir -p "$LOCAL_SITE"
cat > "$LOCAL_SITE/index.anon" <<'EOF'
# Hello from a real hidden service!

This page was fetched through a multi-hop hybrid-PQ rendezvous splice.

* No --connect flag involved.
* The browser resolved the anon:// URL via the v0.2 protocol.
* Greetings from your local exit.
EOF
LOCAL_PORT=$(( (RANDOM % 30000) + 25000 ))
bg node "$REPO/bin/anon-site-server.mjs" "$LOCAL_SITE" --port "$LOCAL_PORT" --quiet
sleep 0.3

# --- 4. anon-service init ---
echo "--- anon-service init ---"
SVC_DIR="$TMPROOT/service"
# Use relay 5 as the IP.
IP_FP="${RELAY_FPS[5]}"
node "$REPO/bin/anon-service.mjs" init \
    --data-dir "$SVC_DIR" \
    --ip-fingerprint "$IP_FP" \
    --consensus "$CONSENSUS_PATH" \
    --da-trust "$DA_TRUST_PATH" \
    | sed 's/^/  /'

ONION_ADDR=$(node "$REPO/bin/anon-service.mjs" info --data-dir "$SVC_DIR" \
    | awk '/^onion address:/ {print $3}')
echo "  onion address: $ONION_ADDR"

# --- 5. anon-service publish ---
echo "--- anon-service publish (backgrounded) ---"
bg node "$REPO/bin/anon-service.mjs" publish \
    --data-dir "$SVC_DIR" \
    --local-port "$LOCAL_PORT" \
    --consensus "$CONSENSUS_PATH" \
    --da-trust "$DA_TRUST_PATH" \
    --allow-co-located \
    --i-understand-this-is-experimental \
    >"$LOG_DIR/service.log" 2>&1
# Wait for the service to publish (ESTABLISH_INTRO + INTRO_ESTABLISHED).
echo "  waiting for service to publish (up to 30s)…"
for i in $(seq 1 60); do
    if grep -q "service published" "$LOG_DIR/service.log" 2>/dev/null; then
        echo "  service published"
        break
    fi
    sleep 0.5
done

if ! grep -q "service published" "$LOG_DIR/service.log" 2>/dev/null; then
    echo "  ✗ service did not publish within 30s"
    echo "--- service log ---"
    cat "$LOG_DIR/service.log"
    for j in 0 1 2 3 4 5; do
        echo "--- relay-$j log (fp ${RELAY_FPS[$j]:0:16}…) ---"
        cat "$LOG_DIR/relay-$j.log" | tail -15
    done
    exit 1
fi

# --- 6. anon-browse via rendezvous ---
echo "--- anon-browse --descriptor (rendezvous mode) ---"
OUTPUT=$(
    node "$REPO/bin/anon-browse.mjs" "anon://$ONION_ADDR/" \
        --consensus "$CONSENSUS_PATH" \
        --da-trust "$DA_TRUST_PATH" \
        --descriptor "$SVC_DIR/descriptor.bin" \
        --allow-co-located \
        --no-color --dump 2>&1
) || true

if echo "$OUTPUT" | grep -q "Hello from a real hidden service"; then
    echo "  ✓ rendezvous fetch SUCCEEDED — page content arrived"
else
    echo "  ✗ rendezvous fetch FAILED"
    echo "--- browse output ---"
    echo "$OUTPUT" | head -40
    echo "--- service log ---"
    tail -30 "$LOG_DIR/service.log" 2>/dev/null
    exit 1
fi

echo "--- demo: all checks passed ---"
