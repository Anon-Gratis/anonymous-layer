#!/bin/sh
# anon-relay container entrypoint.
#
# On every start:
#   1. If /data/identity.key is missing, run `anon-node-v2 init`.
#      Idempotent: the init subcommand refuses to overwrite an
#      existing identity (it errors with "already exists"), so on
#      subsequent starts the init call is a no-op + the identity
#      persists across container rebuilds via the /data volume.
#   2. Sanity-check that /etc/anon-node/consensus.bin and
#      /etc/anon-node/da-trust.json exist before invoking `run` —
#      anon-node-v2 fails opaquely if either is missing, and
#      docker logs without explanation is operator-hostile.
#   3. Exec `anon-node-v2 run`. Exec replaces the shell so signals
#      land directly on the Node process (tini handles PID 1).
#
# Environment variables (set via docker-compose env_file or service env):
#   ANON_BIND_HOST   bind address (default 0.0.0.0; relay must be reachable
#                    from other relays so 127.0.0.1 only works for testing)
#   ANON_BIND_PORT   internal port Caddy proxies to (default 9001)
#   ANON_EXIT_POLICY one of: reject | reduced | standard | file:PATH
#                    (default reject — relay does middle/guard, not exit)
#
# Exit behaviour: any error here aborts with non-zero; Docker's
# restart policy (compose: unless-stopped) handles re-launch.

set -eu

DATA=/data
CFG=/etc/anon-node
BIND_HOST="${ANON_BIND_HOST:-0.0.0.0}"
BIND_PORT="${ANON_BIND_PORT:-9001}"
EXIT_POLICY="${ANON_EXIT_POLICY:-reject}"

# 1. Bootstrap identity.
if [ ! -f "$DATA/identity.key" ]; then
    echo "entrypoint: generating relay identity in $DATA"
    node /app/bin/anon-node-v2.mjs init --data-dir "$DATA"
    # Print the fingerprint so the operator can copy it into
    # relays.json on the DA. Goes to stdout = docker logs.
    echo "entrypoint: identity ready. fingerprint:"
    node /app/bin/anon-node-v2.mjs info --data-dir "$DATA"
fi

# 2. Sanity-check required config.
for f in consensus.bin da-trust.json; do
    if [ ! -f "$CFG/$f" ]; then
        echo "entrypoint: ERROR — $CFG/$f is missing." >&2
        echo "entrypoint: fetch a current consensus from a DA, e.g." >&2
        echo "  curl -fsSL https://da1.anon.gratis/consensus.bin > $CFG/consensus.bin" >&2
        echo "  curl -fsSL https://da1.anon.gratis/da-trust.json > $CFG/da-trust.json" >&2
        exit 1
    fi
done

# 3. Run.
echo "entrypoint: starting relay on $BIND_HOST:$BIND_PORT (exit-policy=$EXIT_POLICY)"
exec node /app/bin/anon-node-v2.mjs run \
    --data-dir "$DATA" \
    --host "$BIND_HOST" \
    --port "$BIND_PORT" \
    --consensus "$CFG/consensus.bin" \
    --da-trust  "$CFG/da-trust.json" \
    --exit-policy "$EXIT_POLICY" \
    --i-understand-this-is-experimental
