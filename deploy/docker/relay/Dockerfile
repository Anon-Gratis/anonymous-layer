# anon-layer relay (anon-node-v2) — PRE-AUDIT TESTNET.
#
# Multi-stage so the final image carries only runtime deps + the
# binary, not dev tooling or git history.
#
# Build context: project root (the directory containing bin/, modules/,
# package.json). See .dockerignore for what's excluded.
#
#   docker build -f deploy/docker/relay/Dockerfile -t anon-relay:dev .
#
# Run as part of deploy/compose/relay.yml, which adds the Caddy
# reverse proxy for wss:// termination.

# -------- stage 1: install production deps --------
FROM node:20-alpine AS deps

WORKDIR /build
COPY package.json package-lock.json* ./
# --omit=dev keeps mocha / chai / fast-check out of the runtime image
RUN npm ci --omit=dev --no-audit --no-fund \
    && npm cache clean --force

# -------- stage 2: runtime --------
FROM node:20-alpine

# tini   = small init so signals (SIGTERM from docker stop) reach the
#          Node process cleanly instead of dying at PID 1
# openssl = used by modules/v2-runtime/self_signed_cert.mjs to mint
#          the link-transport TLS cert (SPEC § 11.1) on first run.
#          ~3 MB; small price to skip vendoring a JS X.509 builder.
RUN apk add --no-cache tini openssl

# Non-root user — relay daemon doesn't need privileges, and a
# compromised relay process shouldn't be able to write outside /data.
# node:alpine ships a built-in 'node' user at UID/GID 1000, so we
# take 1500 to avoid the collision (clearer ownership semantics).
RUN addgroup -g 1500 anon && adduser -D -u 1500 -G anon -s /bin/sh anon

WORKDIR /app
COPY --from=deps /build/node_modules ./node_modules
COPY bin       ./bin
COPY modules   ./modules
COPY package.json ./

# Persistent state — identity.key (mode 0600) survives container
# rebuilds. Volume mounted from host.
RUN mkdir -p /data && chown anon:anon /data
VOLUME ["/data"]

# Config — consensus.bin + da-trust.json mounted read-only from host
RUN mkdir -p /etc/anon-node && chown anon:anon /etc/anon-node
VOLUME ["/etc/anon-node"]

COPY deploy/docker/relay/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

USER anon

# Internal WebSocket port. Caddy in the sidecar reverse-proxies
# wss://0.0.0.0:443 -> ws://anon-node:9001.
EXPOSE 9001

# Liveness: a TCP probe that the WS listener bound (anon-node-v2
# logs "link listener ready" once it does). Just checks the socket
# is accepting; the wss handshake works iff cell layer is up.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD nc -z localhost 9001 || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
