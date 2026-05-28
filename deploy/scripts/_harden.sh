#!/usr/bin/env bash
# _harden.sh — shared host-hardening helpers for bootstrap-da.sh and
# bootstrap-relay.sh. Sourced, not executed.
#
# Goals (PRE-AUDIT TESTNET baseline):
#   - patch kernel/openssl on a cadence without operator action
#     (unattended-upgrades, security pocket only — no -updates churn)
#   - rate-limit + ban brute-force ssh probes (fail2ban sshd jail)
#   - reduce sshd attack surface: no root, key-only, no password,
#     short login window  (drop-in /etc/ssh/sshd_config.d/10-anon.conf)
#   - apply kernel sysctl hardening relevant to a network-facing VPS
#     (rp_filter, source-route/redirect deny, syncookies, kptr_restrict)
#   - cap Docker JSON log growth (no per-container log explosions)
#
# Idempotence: every drop-in lives in a namespaced *anon* file. Re-running
# bootstrap overwrites our drop-ins and leaves everything else alone.
#
# Opt-out: ANON_SKIP_HARDENING=1 in the environment skips this entirely
# (e.g., for CI smoke tests or when the operator manages the host's
# security posture out-of-band via cloud-init / Ansible).
#
# Safety: the SSH drop-in is *guarded* — if no authorized_keys exists
# for the invoking sudo user (or root), we DO NOT disable password auth.
# Locking yourself out of a fresh VPS is worse than a slightly weaker
# default; the operator gets a loud warning instead.

apply_host_hardening () {
    if [ "${ANON_SKIP_HARDENING:-0}" = "1" ]; then
        log "ANON_SKIP_HARDENING=1 — skipping host hardening"
        return 0
    fi

    log "applying host hardening (unattended-upgrades, fail2ban, sshd, sysctl, docker log-rotate)"

    _harden_unattended_upgrades
    _harden_fail2ban
    _harden_sshd
    _harden_sysctl
    _harden_docker_logrotate
}

# ---------- unattended-upgrades ----------
# Pin to the security pocket only. We don't want -updates auto-applied
# on a relay — a buggy package update silently dropping the daemon at
# 03:00 is worse than a delayed feature update. Security patches only,
# no automatic reboot (operator schedules reboots).
_harden_unattended_upgrades () {
    if ! dpkg -s unattended-upgrades >/dev/null 2>&1; then
        log "installing unattended-upgrades..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades
    fi

    cat > /etc/apt/apt.conf.d/20auto-upgrades-anon <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    cat > /etc/apt/apt.conf.d/52unattended-upgrades-anon <<'EOF'
// anon-layer host hardening drop-in. Security pocket only.
// Remove this file (and 20auto-upgrades-anon) to revert.
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=Debian,codename=${distro_codename}-security";
    "origin=Ubuntu,archive=${distro_codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
EOF

    systemctl enable --now unattended-upgrades.service >/dev/null 2>&1 || true
    log "unattended-upgrades: enabled, security pocket only, no auto-reboot"
}

# ---------- fail2ban (sshd jail) ----------
_harden_fail2ban () {
    if ! dpkg -s fail2ban >/dev/null 2>&1; then
        log "installing fail2ban..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban
    fi

    # jail.d takes precedence over jail.conf; namespaced filename so
    # we don't fight any distro defaults.
    cat > /etc/fail2ban/jail.d/anon-sshd.conf <<'EOF'
# anon-layer fail2ban sshd jail.
# Remove this file to revert to fail2ban defaults.
[sshd]
enabled  = true
backend  = systemd
maxretry = 5
findtime = 10m
bantime  = 1h
EOF

    systemctl enable --now fail2ban.service >/dev/null 2>&1 || true
    systemctl reload fail2ban.service >/dev/null 2>&1 || \
        systemctl restart fail2ban.service >/dev/null 2>&1 || true
    log "fail2ban: sshd jail enabled (5 retries / 10m → 1h ban)"
}

# ---------- sshd: key-only, no root, no password ----------
# Drop-in lives at /etc/ssh/sshd_config.d/10-anon.conf — supported on
# Debian 11+ and Ubuntu 20.04+. Removing the file reverts.
#
# We *refuse* to disable password auth unless we can prove an authorized
# key exists for the user who invoked sudo (or root). Otherwise a fresh
# VPS where the operator is still using password ssh would lock itself
# the moment sshd reloads.
_harden_sshd () {
    target_user="${SUDO_USER:-root}"
    if [ "$target_user" = "root" ]; then
        keys_file="/root/.ssh/authorized_keys"
    else
        home_dir=$(getent passwd "$target_user" | cut -d: -f6 || true)
        keys_file="${home_dir:-/home/$target_user}/.ssh/authorized_keys"
    fi

    if [ ! -s "$keys_file" ]; then
        log "WARN: $keys_file is missing or empty for user '$target_user'."
        log "      SKIPPING sshd password-auth disable to avoid lockout."
        log "      To finish hardening: add your key to $keys_file, then drop"
        log "      /etc/ssh/sshd_config.d/10-anon.conf yourself (see _harden.sh)."
        return 0
    fi

    mkdir -p /etc/ssh/sshd_config.d
    # Back up any previous version of our own drop-in so a re-run is
    # auditable. We never touch the operator's sshd_config.
    if [ -f /etc/ssh/sshd_config.d/10-anon.conf ]; then
        cp /etc/ssh/sshd_config.d/10-anon.conf \
           "/etc/ssh/sshd_config.d/10-anon.conf.bak.$(date +%s)"
    fi

    cat > /etc/ssh/sshd_config.d/10-anon.conf <<'EOF'
# anon-layer host hardening drop-in. Remove this file to revert.
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
PrintMotd no
EOF

    # Validate before reloading; back out if sshd rejects.
    if ! sshd -t 2>/dev/null; then
        log "ERROR: sshd config test failed after writing 10-anon.conf — backing out"
        rm -f /etc/ssh/sshd_config.d/10-anon.conf
        return 1
    fi

    # Reload (not restart) to avoid dropping existing sessions. Service
    # name differs across distros — try both.
    systemctl reload ssh   >/dev/null 2>&1 || \
    systemctl reload sshd  >/dev/null 2>&1 || \
    systemctl restart ssh  >/dev/null 2>&1 || \
    systemctl restart sshd >/dev/null 2>&1 || true

    log "sshd hardened: key-only, no root, no password (drop-in: 10-anon.conf)"
    log "               authorized_keys verified at $keys_file"
}

# ---------- sysctl: network + kernel hardening ----------
# Conservative set. None of these break Docker bridge networking on a
# standard single-VPS deployment.
_harden_sysctl () {
    cat > /etc/sysctl.d/99-anon.conf <<'EOF'
# anon-layer host hardening drop-in. Remove this file to revert.

# ---- network: reject spoofed / routed-via-us traffic ----
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ---- network: ICMP + SYN flood mitigations ----
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1

# ---- kernel: info leaks + ASLR ----
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.randomize_va_space = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# ---- fs: hardlink/symlink/fifo abuse ----
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
EOF

    # Apply now. Errors are non-fatal — some sysctls may not exist on
    # older kernels (e.g., fs.protected_regular pre-4.19); we just log.
    if sysctl --system >/dev/null 2>&1; then
        log "sysctl: applied /etc/sysctl.d/99-anon.conf"
    else
        log "WARN: 'sysctl --system' returned non-zero — review with: sysctl --system"
    fi
}

# ---------- docker daemon: log rotation ----------
# Caps per-container JSON log growth. Without this a chatty container
# can fill /var/lib/docker/containers/<id>/ until the disk is exhausted
# and Docker itself can't write.
#
# Only writes /etc/docker/daemon.json if it doesn't already exist —
# merging arbitrary JSON safely is non-trivial in pure bash, and an
# existing daemon.json may carry operator customisation we shouldn't
# clobber. In that case we print the recommended snippet.
_harden_docker_logrotate () {
    mkdir -p /etc/docker
    if [ -f /etc/docker/daemon.json ]; then
        log "docker: /etc/docker/daemon.json already exists — leaving alone"
        log "        recommended additions (merge by hand):"
        log '          "log-driver": "json-file",'
        log '          "log-opts": { "max-size": "10m", "max-file": "5" },'
        log '          "live-restore": true'
        return 0
    fi

    cat > /etc/docker/daemon.json <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "5"
  },
  "live-restore": true
}
EOF

    # Restart docker so the new config takes effect. On a fresh
    # bootstrap no containers are running yet, so this is free.
    # On a re-run with running containers, `live-restore` is what
    # would keep them up across a restart — but it's only effective
    # *after* the restart that adopts it. Acceptable trade.
    systemctl restart docker >/dev/null 2>&1 || true
    log "docker: daemon.json written (10m × 5 log rotation, live-restore on)"
}
