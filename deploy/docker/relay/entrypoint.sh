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
#   3. Launch the daemon in the background, then poll the DA for a
#      fresh consensus. On detecting a change, atomically swap the
#      file and SIGTERM the daemon so docker's restart policy
#      relaunches it with the new consensus. Without this, every
#      relay silently goes stale the moment another relay is added
#      or removed at the DA.
#
# Environment variables (set via docker-compose env_file or service env):
#   ANON_BIND_HOST              bind address (default 0.0.0.0)
#   ANON_BIND_PORT              internal port Caddy proxies to (default 9001)
#   ANON_EXIT_POLICY            reject | reduced | standard | file:PATH
#                               (default reject — relay does middle/guard)
#   ANON_REFRESH_FROM           comma-separated DA base URLs to poll for
#                               consensus refresh, e.g.
#                                 https://da1.anon.gratis,https://da2.anon.gratis
#                               Empty / unset disables auto-refresh.
#   ANON_REFRESH_INTERVAL_SEC   poll interval in seconds (default 1200 = 20 min,
#                               matches the bridge's --refresh-interval-sec).
#
# Exit behaviour: any error here aborts with non-zero; Docker's
# restart policy (compose: unless-stopped) handles re-launch.

set -eu

DATA=/data
CFG=/etc/anon-node
BIND_HOST="${ANON_BIND_HOST:-0.0.0.0}"
BIND_PORT="${ANON_BIND_PORT:-9001}"
EXIT_POLICY="${ANON_EXIT_POLICY:-reject}"
REFRESH_FROM="${ANON_REFRESH_FROM:-}"
REFRESH_INTERVAL_SEC="${ANON_REFRESH_INTERVAL_SEC:-1200}"

# 1. Bootstrap identity.
if [ ! -f "$DATA/identity.key" ]; then
    echo "entrypoint: generating relay identity in $DATA"
    node /app/bin/anon-node-v2.mjs init --data-dir "$DATA"
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

# 3a. Refresh consensus from the DA(s) before first start. Cheap
# insurance: if the on-disk copy is stale at boot, we pick up a
# fresh one before the daemon ever reads it.
refresh_consensus_once () {
    [ -n "$REFRESH_FROM" ] || return 1
    tmp="$CFG/consensus.bin.tmp.$$"
    IFS=,
    set -- $REFRESH_FROM
    unset IFS
    for url; do
        [ -n "$url" ] || continue
        # Strip trailing slashes the same way the bridge does.
        base=$(echo "$url" | sed 's:/*$::')
        echo "entrypoint: refresh: fetching $base/consensus.bin"
        if curl -fsSL --max-time 15 -o "$tmp" "$base/consensus.bin"; then
            if [ ! -s "$tmp" ]; then
                echo "entrypoint: refresh: $base returned empty body"
                rm -f "$tmp"
                continue
            fi
            mv "$tmp" "$CFG/consensus.bin.new"
            return 0
        fi
        rm -f "$tmp"
    done
    return 1
}

if [ -n "$REFRESH_FROM" ]; then
    if refresh_consensus_once && [ -f "$CFG/consensus.bin.new" ]; then
        # Adopt the freshly-fetched file IFF it differs from what's
        # on disk. cmp returns 0 on identical; anything else means
        # the bytes changed (or the old file is gone).
        if ! cmp -s "$CFG/consensus.bin" "$CFG/consensus.bin.new"; then
            mv "$CFG/consensus.bin.new" "$CFG/consensus.bin"
            echo "entrypoint: refresh: adopted fresh consensus at boot"
        else
            rm -f "$CFG/consensus.bin.new"
        fi
    fi
fi

# 3b. Start the daemon in the background so we have a PID to watch
# and to signal when the consensus changes. (Previously this used
# `exec` and the daemon became PID 1 directly; now tini stays at
# PID 1 — it already starts the entrypoint — and the daemon is a
# child of the entrypoint shell. Signals from `docker stop`/`kill`
# land on tini → entrypoint → daemon via the TERM trap below.)
echo "entrypoint: starting relay on $BIND_HOST:$BIND_PORT (exit-policy=$EXIT_POLICY)"
node /app/bin/anon-node-v2.mjs run \
    --data-dir "$DATA" \
    --host "$BIND_HOST" \
    --port "$BIND_PORT" \
    --consensus "$CFG/consensus.bin" \
    --da-trust  "$CFG/da-trust.json" \
    --exit-policy "$EXIT_POLICY" \
    --i-understand-this-is-experimental &
DAEMON_PID=$!

# Forward TERM/INT to the daemon so docker stop is clean.
trap 'kill -TERM "$DAEMON_PID" 2>/dev/null || true; wait "$DAEMON_PID" 2>/dev/null || true; exit 0' TERM INT

# 4. Periodic consensus refresh, if armed. On detected change we
# atomically swap the file then SIGTERM the daemon so docker
# relaunches the container (which re-execs this entrypoint and
# picks up the new file on the next `run`).
if [ -n "$REFRESH_FROM" ] && [ "$REFRESH_INTERVAL_SEC" -gt 0 ] 2>/dev/null; then
    echo "entrypoint: consensus auto-refresh armed: every ${REFRESH_INTERVAL_SEC}s from [${REFRESH_FROM}]"
    (
        # Subshell so the refresh loop doesn't tangle with the trap
        # above. If the daemon exits, this loop notices and exits too.
        while kill -0 "$DAEMON_PID" 2>/dev/null; do
            # Sleep in 1-second slices so we react to daemon exit
            # within a second instead of waiting out the full interval.
            i=0
            while [ "$i" -lt "$REFRESH_INTERVAL_SEC" ]; do
                sleep 1
                kill -0 "$DAEMON_PID" 2>/dev/null || exit 0
                i=$((i + 1))
            done
            if refresh_consensus_once && [ -f "$CFG/consensus.bin.new" ]; then
                if ! cmp -s "$CFG/consensus.bin" "$CFG/consensus.bin.new"; then
                    mv "$CFG/consensus.bin.new" "$CFG/consensus.bin"
                    echo "entrypoint: refresh: consensus changed; restarting daemon"
                    kill -TERM "$DAEMON_PID" 2>/dev/null || true
                    exit 0
                else
                    rm -f "$CFG/consensus.bin.new"
                fi
            fi
        done
    ) &
fi

# Wait for the daemon. `wait` is interrupted by the TERM trap; the
# trap reaps and exits 0 so docker's restart policy can take over.
wait "$DAEMON_PID"
EXIT_CODE=$?
echo "entrypoint: daemon exited with code $EXIT_CODE"
exit $EXIT_CODE
