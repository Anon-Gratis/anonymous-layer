#!/usr/bin/env bash
# Two-node chat demo. Run from the repo root:
#     bash bench/demo-chat.sh
#
# Sets up two anon-node configs that know about each other, then runs
# anon-chat in two background processes. Pipes "hello from A" into A's
# stdin, waits a moment, then prints both clients' output so you can
# see B received A's message and that the conversation worked.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
NODE="${NODE:-node}"
NODE_CLI="$REPO/bin/anon-node.mjs"
CHAT_CLI="$REPO/bin/anon-chat.mjs"

WORKDIR="$(mktemp -d -t anon-chat-demo-XXXXXX)"
A_DIR="$WORKDIR/a"
B_DIR="$WORKDIR/b"
mkdir -p "$A_DIR" "$B_DIR"
trap 'echo "[cleanup] $WORKDIR"; rm -rf "$WORKDIR"' EXIT

echo "[1/4] init two configs on 19501 / 19502..."
"$NODE" "$NODE_CLI" init "$A_DIR/n.json" --port 19501 > /dev/null
"$NODE" "$NODE_CLI" init "$B_DIR/n.json" --port 19502 > /dev/null
sed -i.bak 's/"tickIntervalMs": 5000/"tickIntervalMs": 200/' "$A_DIR/n.json" "$B_DIR/n.json"

echo "[2/4] exchange seed records..."
A_RECORD="$("$NODE" "$NODE_CLI" share "$A_DIR/n.json")"
B_RECORD="$("$NODE" "$NODE_CLI" share "$B_DIR/n.json")"
"$NODE" "$NODE_CLI" add-seed "$B_DIR/n.json" "$A_RECORD" > /dev/null
"$NODE" "$NODE_CLI" add-seed "$A_DIR/n.json" "$B_RECORD" > /dev/null

A_FP="$("$NODE" "$NODE_CLI" info "$A_DIR/n.json" | grep '^fingerprint:' | awk '{print $2}')"
B_FP="$("$NODE" "$NODE_CLI" info "$B_DIR/n.json" | grep '^fingerprint:' | awk '{print $2}')"

echo "[3/4] start two anon-chat sessions..."
mkfifo "$A_DIR/in" "$B_DIR/in"
"$NODE" "$CHAT_CLI" "$A_DIR/n.json" "$B_FP" < "$A_DIR/in" > "$A_DIR/out" 2>&1 &
A_PID=$!
"$NODE" "$CHAT_CLI" "$B_DIR/n.json" "$A_FP" < "$B_DIR/in" > "$B_DIR/out" 2>&1 &
B_PID=$!
# Keep the FIFOs open by holding a writer in a subshell. Tail will
# echo nothing but exists to prevent EOF on the FIFO.
exec 3> "$A_DIR/in"
exec 4> "$B_DIR/in"

# Wait for the handshake.
echo "[4/4] wait ~2s for handshake, then exchange a message..."
sleep 2

# Send a line from A to B; wait a moment; then a reply.
echo "hello from A" >&3
sleep 1
echo "ack from B" >&4
sleep 1

# Shut down by closing the FIFOs (sends EOF to stdin → anon-chat exits).
exec 3>&-
exec 4>&-
wait 2>/dev/null || true

echo
echo "===== A session ====="
cat "$A_DIR/out"
echo
echo "===== B session ====="
cat "$B_DIR/out"
echo
echo "===== check ====="
if grep -q "hello from A" "$B_DIR/out" && grep -q "ack from B" "$A_DIR/out"; then

    echo "OK: messages delivered in both directions"
    exit 0

else

    echo "FAIL: at least one direction did not deliver"
    exit 1

fi
