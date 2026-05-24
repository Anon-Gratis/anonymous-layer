#!/bin/sh
# Rebuild the consensus from the current relays.json.
#
# Called from the entrypoint at startup and from cron hourly.
# Writes atomically — Caddy might be mid-serve on the previous file,
# so we build to a temp path and rename so a reader either sees the
# old file fully or the new file fully, never a half-written blob.

set -eu

DATA=/data
SRV=/srv
RELAYS=/etc/anon-da/relays.json
LIFETIME="${ANON_CONSENSUS_LIFETIME:-3600}"

TMP="$SRV/consensus.bin.tmp"

# anon-mkconsensus build writes the consensus + a copy of this DA's
# da-trust.json. We only need the consensus output — the network-wide
# da-trust.json is composed manually from all 3 DAs.
node /app/bin/anon-mkconsensus.mjs build \
    --data-dir          "$DATA" \
    --relays            "$RELAYS" \
    --output-consensus  "$TMP" \
    --output-trust      "$DATA/da-trust.json" \
    --lifetime-seconds  "$LIFETIME"

mv "$TMP" "$SRV/consensus.bin"

# Also copy the per-DA trust file into /srv so Caddy can serve it
# for tooling / debug purposes (NOT for client trust establishment —
# clients use the bundled network-wide da-trust.json instead).
cp "$DATA/da-trust.json" "$SRV/da-trust.local.json"

echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') rebuilt consensus ($(stat -c %s "$SRV/consensus.bin") bytes)"
