#!/usr/bin/env bash
# Two-node localhost demo. Run from the repo root:
#     bash bench/demo-two-nodes.sh
#
# Spins up two anon-node daemons (A on port 18001, B on 18002) that
# know about each other via a manually-distributed seed list, waits a
# few seconds for the handshake, prints both logs, then shuts them down
# cleanly. End state: a clean exit and both logs showing a verified
# "peer connected" line on each side.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
NODE="${NODE:-node}"
CLI="$REPO/bin/anon-node.mjs"

WORKDIR="$(mktemp -d -t anon-demo-XXXXXX)"
A_DIR="$WORKDIR/a"
B_DIR="$WORKDIR/b"
mkdir -p "$A_DIR" "$B_DIR"
trap 'echo "[cleanup] $WORKDIR"; rm -rf "$WORKDIR"' EXIT

echo "[1/5] init two configs on 18001 / 18002..."
"$NODE" "$CLI" init "$A_DIR/n.json" --port 18001 > /dev/null
"$NODE" "$CLI" init "$B_DIR/n.json" --port 18002 > /dev/null
# Lower the gossip tick so the handshake completes in <1s.
sed -i.bak 's/"tickIntervalMs": 5000/"tickIntervalMs": 500/' "$A_DIR/n.json" "$B_DIR/n.json"

echo "[2/5] exchange seed records..."
A_RECORD="$("$NODE" "$CLI" share "$A_DIR/n.json")"
B_RECORD="$("$NODE" "$CLI" share "$B_DIR/n.json")"
"$NODE" "$CLI" add-seed "$B_DIR/n.json" "$A_RECORD" > /dev/null
"$NODE" "$CLI" add-seed "$A_DIR/n.json" "$B_RECORD" > /dev/null

echo "[3/5] start both daemons..."
"$NODE" "$CLI" run "$A_DIR/n.json" > "$A_DIR/run.log" 2>&1 &
A_PID=$!
"$NODE" "$CLI" run "$B_DIR/n.json" > "$B_DIR/run.log" 2>&1 &
B_PID=$!
echo "       A=$A_PID  B=$B_PID"

echo "[4/5] wait ~3s for handshake..."
sleep 3

echo "[5/5] shut down..."
kill -INT "$A_PID" "$B_PID" 2>/dev/null || true
wait 2>/dev/null || true

echo
echo "===== node A log ====="
cat "$A_DIR/run.log" || true
echo
echo "===== node B log ====="
cat "$B_DIR/run.log" || true
echo
echo "===== handshake check ====="
if grep -q "peer connected" "$A_DIR/run.log" 2>/dev/null && \
   grep -q "peer connected" "$B_DIR/run.log" 2>/dev/null; then
    echo "OK: both nodes logged a verified peer connection"
    exit 0
else
    echo "FAIL: at least one node did not log 'peer connected'"
    exit 1
fi
