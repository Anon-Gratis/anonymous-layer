#!/usr/bin/env bash
# bootstrap-da.sh — provision a fresh VPS as an anon-layer directory
# authority. Mirrors bootstrap-relay.sh structurally; the differences:
#   - builds anon-da:dev image instead of anon-relay
#   - lays out /opt/anon-da/
#   - prompts for relays.json to be supplied (vs consensus.bin for relays)
#
# After this script the operator still has to:
#   - Fill in .env (DA_DOMAIN, ACME_EMAIL)
#   - Verify DNS resolves
#   - Drop the network's curated relays.json
#   - docker compose -f da.yml up -d
#   - Copy this DA's trust-entry into the network-wide da-trust.json

set -euo pipefail

REPO="${REPO:-$PWD}"
INSTALL_DIR="${INSTALL_DIR:-/opt/anon-da}"

log() { printf '\033[36m[bootstrap-da]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[bootstrap-da]\033[0m %s\n' "$*" >&2; exit 1; }

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

[[ -d "$REPO/deploy/docker/da" ]] \
    || die "expected deploy/docker/da at $REPO; pass --repo PATH or cd into the cloned repo"

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
    apt-get install -y -qq ufw
fi
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp   comment "ssh"
ufw allow 80/tcp   comment "ACME http-01"
ufw allow 443/tcp  comment "consensus serve"
ufw --force enable
log "ufw enabled: only 22, 80, 443 inbound"

# ---------- 3b. Host hardening ----------
# unattended-upgrades (security pocket), fail2ban sshd jail, sshd
# drop-in (key-only — guarded by authorized_keys check, won't lock
# you out), sysctl drop-in, Docker log-rotation.
# Skip with ANON_SKIP_HARDENING=1.
apply_host_hardening

# ---------- 4. Build image ----------
log "building anon-da:dev image..."
( cd "$REPO" && docker build -f deploy/docker/da/Dockerfile -t anon-da:dev . )

# ---------- 5. Lay out /opt/anon-da ----------
log "laying out $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"/{data,srv,caddy-data,caddy-config}
cp "$REPO/deploy/compose/da.yml"               "$INSTALL_DIR/da.yml"
cp "$REPO/deploy/compose/Caddyfile.da"         "$INSTALL_DIR/Caddyfile"
[[ -f "$INSTALL_DIR/.env" ]] \
    || cp "$REPO/deploy/compose/.env.da.example" "$INSTALL_DIR/.env"

# Placeholder relays.json so compose can start even before the operator
# drops the real one. anon-mkconsensus wants the top level to be a
# JSON array. Empty array makes the bin refuse-to-build (good — no
# consensus signed with zero relays), but entrypoint.sh now treats
# that as non-fatal so the DA stays alive while waiting.
[[ -f "$INSTALL_DIR/relays.json" ]] || echo "[]" > "$INSTALL_DIR/relays.json"

# Volume ownership: the anon-da container runs as UID 1500, and
# Docker bind-mounts inherit host ownership (root:root by default
# for newly-mkdir'd dirs). Chown so the container can write its
# identity + outputs.
chown -R 1500:1500 "$INSTALL_DIR/data" "$INSTALL_DIR/srv"

# ---------- 6. Next steps ----------
cat <<EOF

================================================================
DA bootstrap done.

NEXT STEPS (operator):

  1. Edit $INSTALL_DIR/.env
     - set DA_DOMAIN     (e.g. da1.anon.gratis)
     - set ACME_EMAIL    (cert-expiry notices)

  2. Make sure DNS for that hostname resolves to this VPS.
     dig +short \$DA_DOMAIN     # should return this box's IP

  3. Drop the network's relays.json into $INSTALL_DIR/relays.json
     (replace the placeholder). This is the curated list of all 7
     relay fingerprints + URLs; same file on all 3 DAs.

  4. Bring up the stack:
       cd $INSTALL_DIR
       docker compose -f da.yml up -d
       docker logs -f anon-da   # watch identity gen + first rebuild

  5. After first start, grab THIS DA's trust entry to combine with
     the other 2 DAs into the network-wide da-trust.json:
       docker exec anon-da cat /data/da-trust.json
     Merge the 3 DAs' entries; that file ships baked into the
     anon-browser tarball.

  6. Verify the DA serves consensus:
       curl -sSI https://\$DA_DOMAIN/consensus.bin   # expect 200

REMEMBER: PRE-AUDIT TESTNET. The DA secret in /opt/anon-da/data is
the root of trust for everything served from this VPS — back it up
(encrypted), and never copy it off the VPS in plaintext.
================================================================
EOF
