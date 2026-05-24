#!/bin/sh
# anon-da container entrypoint.
#
# On every start:
#   1. If /data/da-identity.bin is missing, run `anon-mkconsensus init`.
#      Generates the DA Ed25519 secret (mode 0600 enforced by the
#      bin) and writes /data/da-trust.json with this DA's entry.
#      Idempotent across restarts via the /data volume.
#
#   2. Build the first consensus immediately so /srv has content the
#      moment Caddy can answer requests. Without this, the first hour
#      after deploy returns 404 to clients.
#
#   3. Start a cron loop: rebuild consensus every hour. Cron jitters
#      to avoid all 3 DAs publishing at exactly :00; each DA staggers
#      by its own jitter (0–600s) seeded from the DA's fingerprint.

set -eu

DATA=/data
SRV=/srv
RELAYS=/etc/anon-da/relays.json

# 1. Bootstrap.
if [ ! -f "$DATA/da-identity.bin" ]; then
    echo "entrypoint: generating DA identity in $DATA"
    node /app/bin/anon-mkconsensus.mjs init --data-dir "$DATA"
    echo "entrypoint: DA identity ready. trust entry:"
    cat "$DATA/da-trust.json"
    echo ""
    echo "entrypoint: include this entry in the network-wide"
    echo "  da-trust.json (combined with the other DAs' entries)."
fi

# 2. Sanity-check input.
if [ ! -f "$RELAYS" ]; then
    echo "entrypoint: ERROR — $RELAYS missing." >&2
    echo "entrypoint: mount the network's relays.json (the curated" >&2
    echo "  list of all relay fingerprints + URLs) read-only at"      >&2
    echo "  /etc/anon-da/relays.json. See deploy/ARCHITECTURE.md § D8." >&2
    exit 1
fi

# 3. First rebuild — NON-FATAL. Two legitimate startup states:
#    a) Fresh DA, no relays in the network yet (`relays.json` is the
#       placeholder `[]`). anon-mkconsensus refuses to sign a
#       consensus with zero relays — that's correct behaviour, but
#       it shouldn't crash-loop the container. Cron will retry
#       hourly, succeed once the operator writes a real relays.json.
#    b) Fresh DA, real relays.json on disk. Rebuild succeeds, /srv
#       has content, Caddy serves it immediately. Common steady state.
#
#    Either way we proceed to cron. Operator monitors via:
#        docker exec anon-da tail -f /tmp/rebuild.log
echo "entrypoint: building initial consensus from $RELAYS"
if /usr/local/bin/rebuild.sh; then
    echo "entrypoint: initial consensus built; /srv has content"
else
    echo "entrypoint: WARN — initial build failed (likely empty relays.json)"
    echo "entrypoint:        DA identity is live; cron will retry hourly."
    echo "entrypoint:        Drop a real relays.json at /etc/anon-da/relays.json"
    echo "entrypoint:        on the host and run: docker exec anon-da /usr/local/bin/rebuild.sh"
fi

# 4. Start cron: rebuild hourly with a per-DA jitter so all 3 DAs
#    don't publish at exactly the same time (avoids brief windows
#    where clients fetch a stale-by-1s consensus from another DA).
#    The jitter is deterministic from the DA fingerprint — same DA
#    always offsets the same way.
FP_HEX="$(node /app/bin/anon-mkconsensus.mjs relay-info --data-dir "$DATA" \
            | awk '/fingerprint:/ {print $2; exit}')"
JITTER=$(( 0x${FP_HEX%???????????????????????????????????????????????????????????} % 600 ))
echo "entrypoint: cron jitter for this DA = ${JITTER}s past the hour"

# busybox crond reads from /etc/crontabs/$USER. We're 'anon' here.
mkdir -p /tmp/crontabs
cat > /tmp/crontabs/anon <<EOF
# rebuild consensus every hour, $JITTER seconds past
$((JITTER / 60)) * * * * /usr/local/bin/rebuild.sh >> /tmp/rebuild.log 2>&1
EOF

# Tail rebuild.log to stdout so 'docker logs' surfaces consensus
# refresh events without a separate volume.
touch /tmp/rebuild.log

# Foreground crond + log tail.
busybox crond -f -L /dev/stderr -c /tmp/crontabs &
CRON_PID=$!
tail -F /tmp/rebuild.log &
TAIL_PID=$!

# Wait on crond; if it exits, abort the container.
wait "$CRON_PID"
kill "$TAIL_PID" 2>/dev/null || true
exit 1
