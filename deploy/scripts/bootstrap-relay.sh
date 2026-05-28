#!/usr/bin/env bash
# bootstrap-relay.sh — provision a fresh VPS as an anon-layer relay.
#
# What this does (in order):
#   1. Verify Debian/Ubuntu + root or sudo
#   2. Install Docker + docker compose plugin if not present
#   3. ufw firewall: allow 22 (ssh), 80 (ACME), 443 (wss); deny rest
#   4. Build the relay image from the local checkout
#   5. Set up /opt/anon-relay/ with compose file + Caddyfile + .env
#   6. Print next steps for the operator
#
# Assumes the project repo is already cloned at the current working
# directory (or pass --repo PATH). Does NOT start the relay — that
# requires the operator to:
#   - Fill in .env (RELAY_DOMAIN, ACME_EMAIL)
#   - Verify DNS resolves to this VPS
#   - Drop /opt/anon-relay/config/consensus.bin + da-trust.json (curl from a DA)
#   - docker compose -f relay.yml up -d

set -euo pipefail

REPO="${REPO:-$PWD}"
INSTALL_DIR="${INSTALL_DIR:-/opt/anon-relay}"

log() { printf '\033[36m[bootstrap-relay]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[bootstrap-relay]\033[0m %s\n' "$*" >&2; exit 1; }

# Shared host-hardening helpers (unattended-upgrades, fail2ban, sshd,
# sysctl, docker log-rotate). Sourced after pre-flight + firewall so
# we know we're on Debian/Ubuntu and ufw is up.
# shellcheck source=./_harden.sh
. "$(dirname "$0")/_harden.sh"

# ---------- 1. Pre-flight ----------
[[ "$(id -u)" -eq 0 ]] || die "run as root (or via sudo): sudo $0"
[[ -f /etc/os-release ]] || die "can't detect OS"
. /etc/os-release
case "${ID:-}" in
    debian|ubuntu) ;;
    *) die "this script targets Debian/Ubuntu; detected: ${ID:-unknown}" ;;
esac

[[ -d "$REPO/deploy/docker/relay" ]] \
    || die "expected deploy/docker/relay at $REPO; pass --repo PATH or cd into the cloned repo"

# ---------- 2. Docker ----------
if ! command -v docker >/dev/null 2>&1; then
    log "installing docker..."
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/${ID}/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
                            docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
else
    log "docker present: $(docker --version)"
fi

# ---------- 3. Firewall ----------
if ! command -v ufw >/dev/null 2>&1; then
    log "installing ufw..."
    apt-get install -y -qq ufw
fi
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp   comment "ssh"
ufw allow 443/tcp  comment "anon-relay ws (plain, per §11.4)"
ufw --force enable
log "ufw enabled: only 22, 443 inbound"

# ---------- 3b. Host hardening ----------
# unattended-upgrades (security pocket), fail2ban sshd jail, sshd
# drop-in (key-only — guarded by authorized_keys check, won't lock
# you out), sysctl drop-in, Docker log-rotation.
# Skip with ANON_SKIP_HARDENING=1.
apply_host_hardening

# ---------- 4. Build image ----------
log "building anon-relay:dev image..."
( cd "$REPO" && docker build -f deploy/docker/relay/Dockerfile -t anon-relay:dev . )

# ---------- 5. Lay out /opt/anon-relay ----------
log "laying out $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"/{data,config,caddy-data,caddy-config}
cp "$REPO/deploy/compose/relay.yml"             "$INSTALL_DIR/relay.yml"
[[ -f "$INSTALL_DIR/.env" ]] \
    || cp "$REPO/deploy/compose/.env.relay.example" "$INSTALL_DIR/.env"

# Volume ownership: the anon-relay container runs as UID 1500, and
# Docker bind-mounts inherit host ownership (root:root by default
# for newly-mkdir'd dirs). Chown so the container can write its
# identity (data/) and its auto-refreshed consensus (config/).
chown -R 1500:1500 "$INSTALL_DIR/data" "$INSTALL_DIR/config"

# ---------- 6. Next steps ----------
cat <<EOF

================================================================
relay bootstrap done.

NEXT STEPS (operator):

  1. Edit $INSTALL_DIR/.env
     - set RELAY_DOMAIN  (e.g. relay-is1.anon.gratis)
     - set ACME_EMAIL    (cert-expiry notices)

  2. Make sure DNS for that hostname resolves to this VPS.
     dig +short \$RELAY_DOMAIN     # should return this box's IP

  3. Drop the current consensus + da-trust:
       curl -fsSL https://da1.anon.gratis/consensus.bin \\
         > $INSTALL_DIR/config/consensus.bin
       # da-trust.json comes from your deploy repo, not from a DA:
       cp /path/to/network-da-trust.json $INSTALL_DIR/config/da-trust.json

  4. Bring up the stack:
       cd $INSTALL_DIR
       docker compose -f relay.yml up -d
       docker logs -f anon-relay     # watch identity generation + listener start

  5. Copy this relay's fingerprint + idPk + B_pk to the deploy repo's
     relays.json, push, and notify each DA so the next consensus
     refresh includes this relay:
       docker exec anon-relay node /app/bin/anon-node-v2.mjs info \\
         --data-dir /data

  6. Verify the relay is reachable from outside:
       curl -sSI https://\$RELAY_DOMAIN   # should return 200 + HSTS header

REMEMBER: this network is PRE-AUDIT TESTNET. Do not advertise it as
an anonymity service for at-risk users.
================================================================
EOF
