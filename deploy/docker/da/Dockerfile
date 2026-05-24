# anon-layer directory authority (anon-mkconsensus) — PRE-AUDIT TESTNET.
#
# Wraps the DA batch tool in a long-lived container that rebuilds the
# consensus on a schedule and writes it into a shared volume Caddy
# serves over HTTPS. Same Node base image as the relay; same deps
# install pattern.
#
# Build:
#   docker build -f deploy/docker/da/Dockerfile -t anon-da:dev .

# -------- stage 1: install production deps --------
FROM node:20-alpine AS deps

WORKDIR /build
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev --no-audit --no-fund \
    && npm cache clean --force

# -------- stage 2: runtime --------
FROM node:20-alpine

# tini for PID 1 + crond for scheduled rebuilds
RUN apk add --no-cache tini busybox-suid

# Non-root: DA secret is mode 0600 owned by anon. node:alpine ships a
# built-in 'node' user at UID/GID 1000, so we take 1500 to avoid the
# collision rather than reusing 'node' (clearer ownership semantics —
# /data shows owner 'anon', not 'node').
RUN addgroup -g 1500 anon && adduser -D -u 1500 -G anon -s /bin/sh anon

WORKDIR /app
COPY --from=deps /build/node_modules ./node_modules
COPY bin       ./bin
COPY modules   ./modules
COPY package.json ./

# Persistent state:
#   /data/da-identity.bin  (mode 0600) — Ed25519 secret, survives restarts
#   /data/da-trust.json    — DA's own trust entry (combined into the
#                            network-wide da-trust.json out-of-band)
RUN mkdir -p /data && chown anon:anon /data
VOLUME ["/data"]

# Output volume — consensus.bin + da-trust.json land here for Caddy
# to serve. Shared between the cron container and the Caddy container
# via docker-compose named volume.
RUN mkdir -p /srv && chown anon:anon /srv
VOLUME ["/srv"]

# Input — relays.json (curated list of all relays in the network,
# kept in sync across DAs via Git, mounted read-only from host)
RUN mkdir -p /etc/anon-da && chown anon:anon /etc/anon-da
VOLUME ["/etc/anon-da"]

COPY deploy/docker/da/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY deploy/docker/da/rebuild.sh    /usr/local/bin/rebuild.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/rebuild.sh

USER anon

# No exposed port: Caddy in the sidecar serves /srv contents.
# The DA container is purely a worker.

HEALTHCHECK --interval=5m --timeout=10s --start-period=1m --retries=2 \
    CMD test -f /srv/consensus.bin && \
        test $(($(date +%s) - $(stat -c %Y /srv/consensus.bin))) -lt 7200 \
        || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
