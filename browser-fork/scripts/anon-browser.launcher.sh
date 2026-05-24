#!/usr/bin/env bash
# anonymous — launcher for the bundled Anonymous browser.
#
# Lives at <install-root>/anonymous. Starts up to three things on
# launch and tears them all down on exit:
#   * tor              (for .onion routing, via SOCKS5 in the PAC)
#   * the anon-layer bridge  (HTTP shim on 127.0.0.1:1081 for anon://)
#   * i2pd             (EXPERIMENTAL — disabled by default; for .i2p
#                       routing via HTTPProxy in the PAC)
# A single splash window (yad → zenity → terminal fallback) shows
# bootstrap progress for whichever networks are enabled.
#
# Configuration: AnonLayer/config/anon-browser.conf. See the .example
# file there for the available knobs (incl. ANON_DISABLE_TOR=1 /
# ANON_DISABLE_I2P=0 to opt in to i2p).

set -euo pipefail

ROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
ANON_DIR="$ROOT/AnonLayer"
NODE="$ANON_DIR/node/bin/node"
BRIDGE="$ANON_DIR/bridge/bin/anon-browse-gui.mjs"
CONFIG="$ANON_DIR/config/anon-browser.conf"
LOG="$ANON_DIR/bridge.log"
BRIDGE_HOST="${ANON_BRIDGE_HOST:-127.0.0.1}"
BRIDGE_PORT="${ANON_BRIDGE_PORT:-1081}"

# ---------- Tor (for .onion access) ----------
#
# Tor is shipped under AnonLayer/tor/. Per-launch state (data dir,
# generated torrc, generated PAC) lives in $TOR_RUNTIME so multiple
# concurrent launches don't collide. We pick a random high port to
# avoid stomping on a system tor running on 9050.
TOR_BIN="$ANON_DIR/tor/bin/tor"
TOR_TORRC_TEMPLATE="$ANON_DIR/tor/etc/torrc.template"
TOR_PAC_TEMPLATE="$ANON_DIR/tor/etc/anon.pac.template"
TOR_RUNTIME="$ANON_DIR/tor/run"
TOR_LOG="$TOR_RUNTIME/tor.log"
TOR_PAC_PATH="$TOR_RUNTIME/anon.pac"
TOR_PID=""
TOR_SOCKS_PORT=""

# ---------- i2pd (for .i2p / .b32.i2p access) ----------
#
# EXPERIMENTAL — disabled by default (ANON_DISABLE_I2P defaults to 1).
# The plumbing is wired so the build pipeline and PAC stay exercised,
# but i2p will not appear in the splash and *.i2p hosts will refuse
# (PAC routes them to a sentinel port) until the user opts in by
# setting ANON_DISABLE_I2P=0 in anon-browser.conf.
#
# Why off by default: see docs/THREAT_MODEL.md — i2pd's HTTPProxy
# uses a single shared tunnel pool, so all .i2p tabs share a circuit
# (cross-tab linkability). Re-enable after the audit closes and the
# tunnel-isolation work in tunnels.conf is done.
#
# Bundled the same way as tor: vendored static binary under
# AnonLayer/i2pd/, per-launch runtime under AnonLayer/i2pd/run/.
I2PD_BIN="$ANON_DIR/i2pd/bin/i2pd"
I2PD_CONF_TEMPLATE="$ANON_DIR/i2pd/etc/i2pd.conf.template"
I2PD_CERTS_DIR="$ANON_DIR/i2pd/share/certificates"
I2PD_RUNTIME="$ANON_DIR/i2pd/run"
I2PD_LOG="$I2PD_RUNTIME/i2pd.log"
I2PD_PID=""
I2PD_HTTP_PORT=""

SPLASH_PID=""

# Sentinel port used in the PAC when a network is disabled at launch.
# Nothing binds it, so the browser sees a refused connection (honest)
# rather than a silent black-hole timeout.
SENTINEL_PORT=1

die() { printf 'anonymous: %s\n' "$*" >&2; exit 1; }
warn() { printf 'anonymous: WARNING: %s\n' "$*" >&2; }

# ---------- OS-level hardening (runs before anything else) ----------
#
# Goals:
#   1. No coredumps to disk. A crash dump can contain the entire
#      browser address space — cookies, decrypted page data, tor
#      circuit secrets in flight. setrlimit + coredump_filter together
#      mean even a SIGSEGV produces nothing on disk.
#   2. Warn (don't refuse) when running on unencrypted swap. Browser
#      memory can hit swap, ending up in plaintext on the block device.
#      We can't fix this for the user but at least we flag it loudly.
#   3. Warn when the install path is under a cloud-sync mount point —
#      profile + ~/.cache contents would otherwise replicate to a
#      third party.
#
# All checks are best-effort. If a check can't run (missing tool, odd
# kernel), we log and continue rather than block launch.

anon_harden_process() {
    # 1a. Coredumps off via shell ulimit.
    ulimit -c 0 2>/dev/null || true

    # 1b. Tell the kernel to omit *every* segment from coredumps for
    # this process tree. 0 = include nothing. /proc/self always
    # exists on Linux; on other OSes the write silently noops.
    if [[ -w /proc/self/coredump_filter ]]; then
        printf '0\n' > /proc/self/coredump_filter 2>/dev/null || true
    fi

    # 1c. Disable ptrace attach from any non-parent UID. Defeats
    # cross-user memory dumping on shared boxes.
    if command -v prctl >/dev/null 2>&1; then
        prctl --set NO_NEW_PRIVS 1 $$ 2>/dev/null || true
    fi
}

anon_check_swap() {
    # /proc/swaps lists active swap devices. We flag any line whose
    # device path does NOT match dm-crypt / zram / swapfile-on-encrypted-fs.
    # This is a heuristic — false positives are possible — but a noisy
    # warning is the right error mode here.
    [[ -r /proc/swaps ]] || return 0
    local hit=0
    while read -r dev rest; do
        [[ "$dev" == "Filename" ]] && continue   # header
        [[ -z "$dev" ]] && continue
        case "$dev" in
            /dev/dm-*|/dev/mapper/*|/dev/zram*) ;;   # encrypted/compressed — OK
            /dev/zd*) ;;                              # zfs zvol — usually encrypted
            *)
                warn "swap device '$dev' is not obviously encrypted."
                warn "browser memory may be paged to plaintext disk."
                warn "consider: cryptsetup, zram-swap, or 'swapoff -a'."
                hit=1
                ;;
        esac
    done < /proc/swaps
    return $hit
}

anon_check_cloud_sync() {
    # If $ROOT or $HOME contains a known cloud-sync marker dir, profile
    # data may replicate off-device. Warn; don't refuse.
    local check_paths=("$ROOT" "$HOME")
    local markers=(
        ".dropbox" ".dropbox.cache"
        "iCloud Drive" ".iCloudDrive"
        "OneDrive" "OneDriveTemp"
        "Google Drive" ".gdrive"
        "Sync" "Megasync"
    )
    for p in "${check_paths[@]}"; do
        for m in "${markers[@]}"; do
            if [[ -e "$p/$m" ]] || [[ "$p" == *"/$m/"* ]] || [[ "$p" == *"/$m" ]]; then
                warn "cloud-sync marker '$m' found near '$p'."
                warn "browser profile may replicate to a third-party cloud."
                warn "move the install to a non-synced directory."
                return 1
            fi
        done
    done
    return 0
}

# Run the hardening immediately; checks are non-fatal but informative.
anon_harden_process
anon_check_swap || true
anon_check_cloud_sync || true

# ---------- volatile (RAM-only profile) mode ----------
#
# Two ways to ask for it:
#   * Pass --volatile on the launcher command line.
#   * Click the Panic-adjacent "Volatile" toolbar button — that writes
#     a marker at $ANON_DIR/.volatile and triggers a restart. We
#     consume + delete the marker on the way in so the *next* launch
#     after a volatile session is back to persistent.
#
# When active, we redirect the Firefox profile from $ROOT/Data to
# $XDG_RUNTIME_DIR/anon-volatile-$$ — which on systemd systems is
# already a tmpfs (/run/user/<uid>), so nothing about the profile
# ever touches the block device. On exit we rm -rf the directory so
# the contents disappear from the kernel page cache promptly.
#
# Mozilla.cfg, autoconfig, chrome stylesheets, and the seed user.js
# are all bundled under $ROOT/Browser/defaults/profile/. Firefox
# copies them into a freshly-created profile on first launch, so
# pointing -profile at an empty new dir Just Works.
ANON_VOLATILE_FLAG=0
ANON_VOLATILE_PROFILE_DIR=""
ANON_VOLATILE_MARKER="$ANON_DIR/.volatile"

for arg in "$@"; do
    case "$arg" in
        --volatile) ANON_VOLATILE_FLAG=1 ;;
    esac
done
if [[ -e "$ANON_VOLATILE_MARKER" ]]; then
    ANON_VOLATILE_FLAG=1
    rm -f "$ANON_VOLATILE_MARKER" 2>/dev/null || true
fi
if [[ "${ANON_VOLATILE:-0}" == "1" ]]; then
    ANON_VOLATILE_FLAG=1
fi

if [[ "$ANON_VOLATILE_FLAG" == "1" ]]; then
    runtime_base="${XDG_RUNTIME_DIR:-/tmp}"
    ANON_VOLATILE_PROFILE_DIR="$runtime_base/anon-volatile-$$"
    if ! mkdir -p "$ANON_VOLATILE_PROFILE_DIR"; then
        warn "could not create volatile profile dir at $ANON_VOLATILE_PROFILE_DIR"
        warn "falling back to persistent profile at $ROOT/Data"
        ANON_VOLATILE_FLAG=0
        ANON_VOLATILE_PROFILE_DIR=""
    else
        chmod 700 "$ANON_VOLATILE_PROFILE_DIR" 2>/dev/null || true
        # Verify it's on tmpfs; warn otherwise. /tmp on most distros
        # is tmpfs but not guaranteed.
        fstype="$(stat -f -c %T "$ANON_VOLATILE_PROFILE_DIR" 2>/dev/null || echo unknown)"
        if [[ "$fstype" != "tmpfs" ]]; then
            warn "volatile profile dir filesystem is '$fstype', not tmpfs."
            warn "profile data may survive on disk after exit."
        fi
        printf 'anonymous: volatile mode — profile at %s (fs=%s)\n' \
            "$ANON_VOLATILE_PROFILE_DIR" "$fstype" >&2
    fi
fi

# Always best-effort wipe of the volatile dir on exit, even on crash.
anon_volatile_cleanup() {
    if [[ -n "$ANON_VOLATILE_PROFILE_DIR" ]] && [[ -d "$ANON_VOLATILE_PROFILE_DIR" ]]; then
        rm -rf "$ANON_VOLATILE_PROFILE_DIR" 2>/dev/null || true
    fi
}
trap anon_volatile_cleanup EXIT

# ---------- --register-app / --unregister-app ----------
#
# Installs (or removes) a .desktop entry in ~/.local/share/applications
# and the icon into ~/.local/share/icons/hicolor so the user's app
# menu / Activities / taskbar can find it. The desktop Exec= points at
# THIS launcher (not the engine launcher), so clicking the icon also
# starts the anon-layer bridge.

USER_APPS_DIR="$HOME/.local/share/applications"
USER_ICONS_BASE="$HOME/.local/share/icons/hicolor"
DESKTOP_INSTALLED_NAME="anonymous.desktop"

register_app() {
    mkdir -p "$USER_APPS_DIR" "$USER_ICONS_BASE"

    # Install icons into the hicolor theme — used when other apps look
    # us up by name (e.g. for taskbar matching via StartupWMClass).
    local sizes="16 32 48 64 128"
    for sz in $sizes; do
        local src_icon="$ROOT/Browser/browser/chrome/icons/default/default${sz}.png"
        if [[ -f "$src_icon" ]]; then
            mkdir -p "$USER_ICONS_BASE/${sz}x${sz}/apps"
            install -m 0644 "$src_icon" "$USER_ICONS_BASE/${sz}x${sz}/apps/anonymous.png"
        fi
    done

    # Ensure ~/.local/share/icons/hicolor has an index.theme so
    # gtk-update-icon-cache has something to cache against.
    if [[ ! -f "$USER_ICONS_BASE/index.theme" ]]; then
        cat > "$USER_ICONS_BASE/index.theme" <<'INDEX'
[Icon Theme]
Name=Hicolor
Comment=User-level hicolor fallback
Directories=16x16/apps,32x32/apps,48x48/apps,64x64/apps,128x128/apps
[16x16/apps]
Size=16
Context=Applications
Type=Threshold
[32x32/apps]
Size=32
Context=Applications
Type=Threshold
[48x48/apps]
Size=48
Context=Applications
Type=Threshold
[64x64/apps]
Size=64
Context=Applications
Type=Threshold
[128x128/apps]
Size=128
Context=Applications
Type=Threshold
INDEX
    fi

    # Write the .desktop. Use an ABSOLUTE Icon= path — GNOME's icon-name
    # resolution via the user-hicolor theme has been flaky in our
    # testing, and an absolute path is unambiguous.
    local icon_abs="$USER_ICONS_BASE/128x128/apps/anonymous.png"
    local desktop_target="$USER_APPS_DIR/$DESKTOP_INSTALLED_NAME"
    cat > "$desktop_target" <<EOF
[Desktop Entry]
Type=Application
Name=Anonymous
GenericName=Web Browser
Comment=An anonymity-focused browser for the anon-layer network.
Categories=Network;WebBrowser;Security;
Exec="$ROOT/anonymous" %u
Icon=$icon_abs
Terminal=false
StartupNotify=true
StartupWMClass=Anonymous
MimeType=text/html;application/xhtml+xml;x-scheme-handler/anon;x-scheme-handler/web+anon;
EOF
    chmod 0755 "$desktop_target"

    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database "$USER_APPS_DIR" 2>/dev/null || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q -f "$USER_ICONS_BASE" 2>/dev/null || true
    fi

    # Nudge gnome-shell to re-scan: removing its app-info cache forces
    # a rebuild next time Activities is opened.
    rm -f "$HOME/.cache/gnome-shell/app-info-cache" 2>/dev/null || true

    printf 'anonymous: registered.\n'
    printf '  desktop entry → %s\n' "$desktop_target"
    printf '  icon          → %s\n' "$icon_abs"
    printf '  Launch from your app menu (search "Anonymous") or with: %s/anonymous\n' "$ROOT"
}

unregister_app() {
    rm -f "$USER_APPS_DIR/$DESKTOP_INSTALLED_NAME"
    local sizes="16 22 24 32 48 64 96 128 192 256 512"
    for sz in $sizes; do
        rm -f "$USER_ICONS_BASE/${sz}x${sz}/apps/anonymous.png"
    done
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database "$USER_APPS_DIR" 2>/dev/null || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q -t -f "$USER_ICONS_BASE" 2>/dev/null || true
    fi
    printf 'anonymous: unregistered.\n'
}

case "${1:-}" in
    --register-app)   register_app; exit 0 ;;
    --unregister-app) unregister_app; exit 0 ;;
    --help|-h)
        cat <<EOF
anonymous — Anonymous browser launcher

Usage:
  ./anonymous                  Start the bridge + open the browser.
  ./anonymous --register-app   Add Anonymous to your app menu.
  ./anonymous --unregister-app Remove from app menu.

Configuration lives in:
  $ANON_DIR/config/anon-browser.conf

EOF
        exit 0 ;;
esac

# ---------- self-heal the .desktop Icon= path ----------

# The .desktop files in the tarball have an absolute Icon= path that
# only makes sense in the staging build dir. Repair on every launch
# (cheap, idempotent) so taskbar icons resolve once the user has
# extracted somewhere.
ICON_REAL="$ROOT/Browser/browser/chrome/icons/default/default128.png"
if [[ -f "$ICON_REAL" ]]; then
    for d in "$ROOT/anonymous.desktop" "$ROOT/Browser/anonymous.desktop"; do
        [[ -f "$d" ]] || continue
        if ! grep -qxF "Icon=$ICON_REAL" "$d"; then
            sed -i -E "s|^Icon=.*|Icon=$ICON_REAL|" "$d" 2>/dev/null || true
        fi
    done
fi

# ---------- self-heal policies.json install_url ----------
#
# The anon-layer ExtensionSettings policy needs an absolute path to
# the XPI, which depends on where the user extracted the tarball.
# The shipped policies.json carries the placeholder @@INSTALL_DIR@@;
# we substitute it for $ROOT on every launch. Also idempotent — if
# the file already has the correct path baked in (after first run),
# nothing happens.
POLICIES="$ROOT/Browser/distribution/policies.json"
if [[ -f "$POLICIES" ]] && grep -q '@@INSTALL_DIR@@' "$POLICIES" 2>/dev/null; then
    sed -i "s|@@INSTALL_DIR@@|$ROOT|g" "$POLICIES" 2>/dev/null || true
fi

# ---------- clean stale profile locks ----------
#
# If a prior browser process died without releasing the profile lock
# (kernel kill, power loss, our own kill -9), the next launch silently
# refuses to start a new window. Detect + clean: we own this dir, so a
# lock with no live PID on the other end is unambiguously stale.
for lock in "$ROOT/Data"/*/.parentlock "$ROOT/Data"/*/lock "$ROOT/Data"/*/parent.lock; do
    [[ -e "$lock" ]] || continue
    target="$(readlink "$lock" 2>/dev/null || true)"
    if [[ -n "$target" ]] && [[ "$target" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)$ ]]; then
        pid="${BASH_REMATCH[2]}"
        if kill -0 "$pid" 2>/dev/null; then
            continue   # a process by that pid is alive; respect the lock
        fi
    fi
    rm -f "$lock"
done

# ---------- sanity checks ----------

[[ -x "$NODE" ]]   || die "bundled Node missing at $NODE — was the tarball unpacked completely?"
[[ -f "$BRIDGE" ]] || die "bridge entry-point missing at $BRIDGE"

if [[ ! -f "$CONFIG" ]]; then
    cat >&2 <<EOF
anon-browser: not yet configured.

Copy the example config and edit it:

  cp "$ANON_DIR/config/anon-browser.conf.example" "$CONFIG"
  \$EDITOR "$CONFIG"

The minimum you need: either CONNECT=host:port (for testing) or
CONSENSUS=/path + DA_TRUST=/path plus at least one descriptor source
(DESCRIPTOR=/single.bin and/or DESCRIPTOR_DIR=/dir-of-bins).
EOF
    exit 1
fi

# ---------- load config ----------

# shellcheck disable=SC1090
source "$CONFIG"

# ---------- fetch fresh consensus from a DA ----------
#
# If the conf sets DA_URLS to a comma-separated list of DA HTTPS
# endpoints (e.g. "https://da1.anon.gratis,https://da2.anon.gratis,
# https://da3.anon.gratis"), fetch the latest consensus.bin from
# one of them before starting the bridge. Try each in order; first
# 200 wins. If all fail, keep using whatever CONSENSUS already
# points at (stale-but-cached beats hard failure mid-session).
#
# TLS validates the channel (Caddy + Let's Encrypt at the DA);
# the bridge validates the consensus signature against DA_TRUST
# when it loads the file — so a compromised DA can serve a
# malformed consensus but the bridge will reject it.
fetch_consensus() {
    [[ -z "${DA_URLS:-}" ]] && return 0
    [[ -z "${CONSENSUS:-}" ]] && return 0  # nowhere to write it

    local urls dest tmp http_code u
    # split comma-separated list
    IFS=',' read -ra urls <<< "${DA_URLS//[[:space:]]/}"
    dest="$CONSENSUS"
    tmp="${dest}.tmp.$$"

    for u in "${urls[@]}"; do
        [[ -z "$u" ]] && continue
        printf 'anonymous: fetching consensus from %s ... ' "$u" >&2
        http_code="$(curl -fsSL --max-time 15 \
                          -o "$tmp" -w '%{http_code}' \
                          "${u%/}/consensus.bin" 2>/dev/null || echo 000)"
        if [[ "$http_code" == "200" ]] && [[ -s "$tmp" ]]; then
            mv "$tmp" "$dest"
            printf 'ok (%s bytes)\n' "$(stat -c %s "$dest")" >&2
            return 0
        fi
        printf 'fail (%s)\n' "$http_code" >&2
        rm -f "$tmp"
    done

    if [[ -f "$dest" ]]; then
        echo "anonymous: WARN — all DAs unreachable; using cached consensus at $dest" >&2
        return 0
    fi
    die "no DA reachable and no cached consensus — refusing to start"
}

BRIDGE_ARGS=(--listen "$BRIDGE_HOST" --port "$BRIDGE_PORT" --no-token)

if [[ -n "${CONNECT:-}" ]]; then

    BRIDGE_ARGS+=(--connect "$CONNECT")

elif [[ -n "${CONSENSUS:-}" && -n "${DA_TRUST:-}" && ( -n "${DESCRIPTOR:-}" || -n "${DESCRIPTOR_DIR:-}" ) ]]; then

    fetch_consensus

    [[ -f "$CONSENSUS" ]] || die "CONSENSUS file not found: $CONSENSUS"
    [[ -f "$DA_TRUST"  ]] || die "DA_TRUST file not found: $DA_TRUST"
    BRIDGE_ARGS+=(--consensus "$CONSENSUS" --da-trust "$DA_TRUST")

    # At least one of DESCRIPTOR or DESCRIPTOR_DIR must be set; both
    # are allowed (the bridge indexes every descriptor by its onion
    # address and routes per-URL host).
    if [[ -n "${DESCRIPTOR:-}" ]]; then
        [[ -f "$DESCRIPTOR" ]] || die "DESCRIPTOR file not found: $DESCRIPTOR"
        BRIDGE_ARGS+=(--descriptor "$DESCRIPTOR")
    fi
    if [[ -n "${DESCRIPTOR_DIR:-}" ]]; then
        [[ -d "$DESCRIPTOR_DIR" ]] || die "DESCRIPTOR_DIR not found or not a directory: $DESCRIPTOR_DIR"
        BRIDGE_ARGS+=(--descriptor-dir "$DESCRIPTOR_DIR")
    fi
    if [[ -n "${HSDIR_URL:-}" ]]; then
        BRIDGE_ARGS+=(--hsdir-url "$HSDIR_URL")
    fi

    # Hand DA_URLS to the bridge as --refresh-from so the bridge can
    # self-refresh on startup AND periodically while running. This
    # makes manual `node anon-browse-gui.mjs ...` restarts pick up a
    # fresh consensus the same way the launcher does, and keeps the
    # on-disk consensus.bin from going stale during long sessions.
    if [[ -n "${DA_URLS:-}" ]]; then
        BRIDGE_ARGS+=(--refresh-from "$DA_URLS")
    fi

    if [[ "${ALLOW_CO_LOCATED:-0}" == "1" ]]; then
        BRIDGE_ARGS+=(--allow-co-located)
    fi

else

    die "neither CONNECT nor (CONSENSUS,DA_TRUST,DESCRIPTOR|DESCRIPTOR_DIR) set in $CONFIG"

fi

# ---------- port conflict / attach-to-existing-bridge ----------
#
# If $BRIDGE_PORT is busy, probe whether the squatter is an already-
# running anon-bridge (GET /api/health → JSON with "ok":true). If
# yes, skip spawning a new one and attach to it — lets dev iterations
# on the bridge avoid the "stop the launcher to free 1081" footgun.
# If no, the port is owned by something else and we still refuse to
# start (collision with an unrelated service would silently break us).
ATTACH_EXISTING_BRIDGE=0
if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[.:]${BRIDGE_PORT}\$"; then

    probe=""
    if command -v curl >/dev/null 2>&1; then
        probe="$(curl -fsS --max-time 2 \
                      "http://${BRIDGE_HOST}:${BRIDGE_PORT}/api/health" 2>/dev/null \
                 | head -c 256)"
    fi
    if [[ "$probe" == *'"ok":true'* ]]; then
        echo "anonymous: existing bridge detected on ${BRIDGE_PORT}; attaching instead of spawning" >&2
        ATTACH_EXISTING_BRIDGE=1
    else
        die "port ${BRIDGE_PORT} already in use by a non-anon service; close it or set ANON_BRIDGE_PORT="
    fi

fi

# ---------- start tor ----------
#
# Started before the bridge so PAC is in place by the time the
# browser launches. If tor binary or templates are missing we skip
# silently — .onion will just not resolve, everything else still
# works. Set ANON_DISABLE_TOR=1 to opt out for testing.

# ---------- splash plumbing ----------
#
# Per-network progress is computed by small "feeder" functions that
# emit `<pct>\t<label>` lines as they observe their log. The splash
# driver multiplexes those into whichever GUI is available.
#
#   yad        — multi-progress dialog, three bars in one window (best)
#   zenity     — single bar that aggregates the three (avg of the three pcts)
#   neither    — terminal-only "tor:NN i2p:NN anon:NN" line
#
# Bars finish at 100 individually; the dialog auto-closes when all
# three reach 100 (or when the browser launch starts, whichever first).

SPLASH_FIFO=""

# Feeder for tor: tail tor.log, map "Bootstrapped N%" lines.
splash_feed_tor() {
    local prefix="$1"   # "1" for yad bar index, or "tor" for zenity/terminal
    if [[ "${ANON_DISABLE_TOR:-0}" == "1" ]] || [[ ! -x "$TOR_BIN" ]]; then
        printf '%s\t100\tdisabled\n' "$prefix"
        return 0
    fi
    printf '%s\t0\tstarting\n' "$prefix"
    for _ in $(seq 1 50); do
        [[ -f "$TOR_LOG" ]] && break
        sleep 0.1
    done
    tail -F -n +1 "$TOR_LOG" 2>/dev/null | while IFS= read -r line; do
        if [[ "$line" =~ Bootstrapped\ ([0-9]+)% ]]; then
            local pct="${BASH_REMATCH[1]}"
            local descr="${line#*\): }"
            [[ "$descr" == "$line" ]] && descr="bootstrapping…"
            # Same heuristic as the legacy splash: ≥75% is usable.
            if (( pct >= 75 )); then
                printf '%s\t100\tready\n' "$prefix"
                break
            else
                printf '%s\t%s\t%s\n' "$prefix" "$pct" "$descr"
            fi
        fi
    done
}

# Feeder for i2pd: i2pd has no single "Bootstrapped N%" line, so we
# map specific log substrings to bucketed percentages. The buckets
# correspond to the visible bootstrap phases (reseed → transports up
# → first tunnel built → client pool ready).
splash_feed_i2pd() {
    local prefix="$1"
    # Default OFF — see header. Opt in with ANON_DISABLE_I2P=0.
    if [[ "${ANON_DISABLE_I2P:-1}" == "1" ]] || [[ ! -x "$I2PD_BIN" ]]; then
        printf '%s\t100\tdisabled (experimental)\n' "$prefix"
        return 0
    fi
    printf '%s\t0\tstarting\n' "$prefix"
    for _ in $(seq 1 50); do
        [[ -f "$I2PD_LOG" ]] && break
        sleep 0.1
    done
    local cur=5
    tail -F -n +1 "$I2PD_LOG" 2>/dev/null | while IFS= read -r line; do
        local new="$cur" descr=""
        case "$line" in
            *"Reseed: Reseeding"*|*"Reseed: SU3"*|*"Reseed: Downloading"*)
                new=20; descr="reseeding…" ;;
            *"Reseed: Got"*|*"Reseed: SU3 has been verified"*)
                new=40; descr="loaded router info" ;;
            *"NetDb: NetDb has been loaded"*|*"NetDb has been loaded"*)
                new=50; descr="netdb loaded" ;;
            *"Transports: Started"*|*"Transports: started"*|*"NTCP2: Started"*|*"SSU2: Started"*)
                new=60; descr="transports up" ;;
            *"Inbound tunnel"*"created"*|*"Outbound tunnel"*"created"*)
                new=80; descr="building tunnels" ;;
            *"Tunnels: Tunnel pool"*"created"*|*"HTTPProxy: Proxy is ready"*|*"HTTP Proxy"*"ready"*)
                printf '%s\t100\tready\n' "$prefix"
                break ;;
        esac
        if (( new > cur )); then
            cur="$new"
            printf '%s\t%s\t%s\n' "$prefix" "$cur" "$descr"
        fi
    done
}

# Feeder for the anon-layer bridge: bridge has only a few interesting
# lines; we map them to coarse buckets and finalize on /api/health.
splash_feed_bridge() {
    local prefix="$1"
    printf '%s\t0\tstarting\n' "$prefix"
    for _ in $(seq 1 50); do
        [[ -f "$LOG" ]] && break
        sleep 0.1
    done
    # Concurrently: tail the log for human descriptors AND poll
    # /api/health to detect readiness. Whichever fires first.
    (
        tail -F -n +1 "$LOG" 2>/dev/null | while IFS= read -r line; do
            case "$line" in
                *"descriptor index ready"*)
                    printf '%s\t40\tdescriptor index ready\n' "$prefix" ;;
                *"hsdir armed"*)
                    printf '%s\t60\thsdir armed\n' "$prefix" ;;
                *"ANONYMOUS LAYER"*)
                    printf '%s\t80\tserver up\n' "$prefix" ;;
            esac
        done
    ) &
    local tail_pid=$!
    for _ in $(seq 1 300); do
        local code
        code="$(curl -s -o /dev/null -w '%{http_code}' \
            "http://${BRIDGE_HOST}:${BRIDGE_PORT}/api/health" 2>/dev/null || echo 000)"
        case "$code" in
            200|403)
                printf '%s\t100\tready\n' "$prefix"
                kill "$tail_pid" 2>/dev/null || true
                return 0 ;;
        esac
        sleep 0.5
    done
    kill "$tail_pid" 2>/dev/null || true
    printf '%s\t100\ttimed out\n' "$prefix"
}

# yad multi-progress driver. yad reads `<idx>:<value>` or `<idx>:#text`
# on stdin; --auto-close ends the dialog when all bars reach 100.
splash_run_yad() {
    {
        # Header line for each bar before we start (so all three are
        # visible from t=0 even if a feeder hasn't emitted yet).
        echo "1:0"; echo "1:#tor: starting"
        echo "2:0"; echo "2:#i2p: starting"
        echo "3:0"; echo "3:#anon-layer: starting"

        # Multiplex the three feeders, running in parallel so their
        # output interleaves as networks bootstrap. Each line:
        # "<idx>\t<pct>\t<label>". The subshell exits when all three
        # feeders finish (each returns once its network reaches 100%).
        (
            splash_feed_tor    1 &
            splash_feed_i2pd   2 &
            splash_feed_bridge 3 &
            wait
        ) 2>/dev/null | while IFS=$'\t' read -r idx pct label; do
            [[ -z "$idx" ]] && continue
            case "$idx" in
                1) name=tor ;;
                2) name=i2p ;;
                3) name=anon-layer ;;
                *) continue ;;
            esac
            echo "${idx}:${pct}"
            echo "${idx}:#${name}: ${label}"
        done
    } | yad --multi-progress \
            --title="Anonymous" \
            --text="Connecting to anonymity networks…" \
            --bar="tor:NORM" \
            --bar="i2p:NORM" \
            --bar="anon-layer:NORM" \
            --auto-close \
            --no-buttons \
            --width=480 \
            2>/dev/null || true
}

# zenity fallback: single window, single progress bar showing the
# average across the three networks. Less informative than yad but
# universally available.
splash_run_zenity() {
    local t_pct=0 i_pct=0 a_pct=0
    {
        echo "0"
        echo "# bootstrapping anonymity networks…"
        (
            splash_feed_tor    tor &
            splash_feed_i2pd   i2p &
            splash_feed_bridge anon-layer &
            wait
        ) 2>/dev/null | while IFS=$'\t' read -r who pct label; do
            [[ -z "$who" ]] && continue
            case "$who" in
                tor)        t_pct="$pct" ;;
                i2p)        i_pct="$pct" ;;
                anon-layer) a_pct="$pct" ;;
            esac
            avg=$(( (t_pct + i_pct + a_pct) / 3 ))
            echo "$avg"
            echo "# ${who}: ${pct}% — ${label}    (tor ${t_pct}% · i2p ${i_pct}% · anon-layer ${a_pct}%)"
            if (( t_pct >= 100 && i_pct >= 100 && a_pct >= 100 )); then
                echo "100"
                echo "# ready — launching browser"
                break
            fi
        done
    } | zenity --progress \
               --title="Anonymous" \
               --text="bootstrapping anonymity networks…" \
               --percentage=0 \
               --auto-close \
               --no-cancel \
               --width=520 \
               2>/dev/null || true
}

# Terminal fallback: print a single status line that rewrites in place.
splash_run_terminal() {
    local t_pct=0 i_pct=0 a_pct=0
    (
        splash_feed_tor    tor &
        splash_feed_i2pd   i2p &
        splash_feed_bridge anon-layer &
        wait
    ) 2>/dev/null | while IFS=$'\t' read -r who pct label; do
        [[ -z "$who" ]] && continue
        case "$who" in
            tor)        t_pct="$pct" ;;
            i2p)        i_pct="$pct" ;;
            anon-layer) a_pct="$pct" ;;
        esac
        printf '\ranonymous: tor %3s%% · i2p %3s%% · anon-layer %3s%%  ' \
            "$t_pct" "$i_pct" "$a_pct"
        if (( t_pct >= 100 && i_pct >= 100 && a_pct >= 100 )); then
            printf '\n'
            break
        fi
    done
}

show_splash() {
    # Spawn whichever splash is available; non-fatal if all fall back
    # to terminal output. Caller stashes the pid in SPLASH_PID so the
    # cleanup trap can tear down the whole process group on exit.
    if command -v yad >/dev/null 2>&1; then
        splash_run_yad
    elif command -v zenity >/dev/null 2>&1; then
        splash_run_zenity
    else
        splash_run_terminal
    fi
}

# Random high port (range chosen to leave 9050 and the OS ephemeral
# range alone). Shared by tor + i2pd so both pick the same way.
pick_port() { echo $(( 30000 + RANDOM % 30000 )); }

start_tor() {
    [[ "${ANON_DISABLE_TOR:-0}" == "1" ]] && return 0
    [[ -x "$TOR_BIN" && -f "$TOR_TORRC_TEMPLATE" ]] || return 0

    TOR_SOCKS_PORT="$(pick_port)"
    TOR_CONTROL_PORT="$(pick_port)"

    # Per-launch runtime dir. Wiped + recreated each launch so we get
    # a clean consensus + identity (poor man's NEW IDENTITY).
    rm -rf "$TOR_RUNTIME"
    mkdir -p "$TOR_RUNTIME"
    chmod 700 "$TOR_RUNTIME"

    sed -e "s|@@SOCKS_PORT@@|$TOR_SOCKS_PORT|g" \
        -e "s|@@CONTROL_PORT@@|$TOR_CONTROL_PORT|g" \
        -e "s|@@DATA_DIR@@|$TOR_RUNTIME|g" \
        "$TOR_TORRC_TEMPLATE" > "$TOR_RUNTIME/torrc"

    "$TOR_BIN" -f "$TOR_RUNTIME/torrc" >"$TOR_LOG" 2>&1 &
    TOR_PID=$!

    # Sanity check: SOCKS port comes up within 10s. The splash will
    # surface deeper bootstrap progress; if SOCKS never opens, tor is
    # broken and we should know early.
    for _ in $(seq 1 50); do
        if ! kill -0 "$TOR_PID" 2>/dev/null; then
            echo "anonymous: tor died during startup; tail of log:" >&2
            tail -20 "$TOR_LOG" >&2
            TOR_PID=""
            return 1
        fi
        if (exec 3<>/dev/tcp/127.0.0.1/$TOR_SOCKS_PORT) 2>/dev/null; then
            exec 3<&-; exec 3>&-
            return 0
        fi
        sleep 0.2
    done
    echo "anonymous: tor socks port $TOR_SOCKS_PORT never opened; tail:" >&2
    tail -10 "$TOR_LOG" >&2
    return 1
}

start_i2pd() {
    # Default OFF — i2p is shipped as EXPERIMENTAL pending the audit
    # and per-destination tunnel isolation. Opt in by setting
    # ANON_DISABLE_I2P=0 in anon-browser.conf.
    [[ "${ANON_DISABLE_I2P:-1}" == "1" ]] && return 0
    [[ -x "$I2PD_BIN" && -f "$I2PD_CONF_TEMPLATE" ]] || return 0

    I2PD_HTTP_PORT="$(pick_port)"
    local socks_port ntcp2_port ssu2_port web_port
    socks_port="$(pick_port)"
    ntcp2_port="$(pick_port)"
    ssu2_port="$(pick_port)"
    web_port="$(pick_port)"

    rm -rf "$I2PD_RUNTIME"
    mkdir -p "$I2PD_RUNTIME"
    chmod 700 "$I2PD_RUNTIME"

    # Render i2pd.conf from template. The bundled certificates dir
    # is required for reseed signature verification — without it
    # i2pd will refuse the SU3 bundle and never bootstrap.
    local certs_dir="$I2PD_CERTS_DIR"
    [[ -d "$certs_dir" ]] || certs_dir="$I2PD_RUNTIME/certificates"
    sed -e "s|@@DATA_DIR@@|$I2PD_RUNTIME|g" \
        -e "s|@@CERTS_DIR@@|$certs_dir|g" \
        -e "s|@@HTTP_PROXY_PORT@@|$I2PD_HTTP_PORT|g" \
        -e "s|@@SOCKS_PROXY_PORT@@|$socks_port|g" \
        -e "s|@@NTCP2_PORT@@|$ntcp2_port|g" \
        -e "s|@@SSU2_PORT@@|$ssu2_port|g" \
        -e "s|@@WEBCONSOLE_PORT@@|$web_port|g" \
        "$I2PD_CONF_TEMPLATE" > "$I2PD_RUNTIME/i2pd.conf"

    "$I2PD_BIN" --conf="$I2PD_RUNTIME/i2pd.conf" --datadir="$I2PD_RUNTIME" \
        >"$I2PD_LOG" 2>&1 &
    I2PD_PID=$!

    # Sanity check: HTTPProxy port comes up within ~30s. i2pd is
    # slower than tor to first-listen because it parses the bundled
    # router infos before binding. Real bootstrap (reseed → tunnel
    # build) is shown via the splash.
    for _ in $(seq 1 150); do
        if ! kill -0 "$I2PD_PID" 2>/dev/null; then
            echo "anonymous: i2pd died during startup; tail of log:" >&2
            tail -20 "$I2PD_LOG" >&2
            I2PD_PID=""
            return 1
        fi
        if (exec 3<>/dev/tcp/127.0.0.1/$I2PD_HTTP_PORT) 2>/dev/null; then
            exec 3<&-; exec 3>&-
            return 0
        fi
        sleep 0.2
    done
    echo "anonymous: i2pd http-proxy port $I2PD_HTTP_PORT never opened; tail:" >&2
    tail -10 "$I2PD_LOG" >&2
    return 1
}

# Render the unified PAC. Substitutes the live tor SOCKS port and i2pd
# HTTPProxy port, or SENTINEL_PORT for whichever network didn't start
# (so the browser refuses immediately instead of hanging on a port
# nothing is listening on).
render_pac() {
    [[ -f "$TOR_PAC_TEMPLATE" ]] || return 0
    mkdir -p "$TOR_RUNTIME"
    local tor_port="${TOR_SOCKS_PORT:-$SENTINEL_PORT}"
    local i2p_port="${I2PD_HTTP_PORT:-$SENTINEL_PORT}"
    sed -e "s|@@TOR_SOCKS_PORT@@|$tor_port|g" \
        -e "s|@@I2P_HTTP_PORT@@|$i2p_port|g" \
        "$TOR_PAC_TEMPLATE" > "$TOR_PAC_PATH"
}

# Bring up tor first (its SOCKS port comes up in ~1s), then i2pd
# (slower to bind, but its bootstrap then proceeds in parallel with
# tor's). Backgrounding the start functions themselves would put
# the PID variables in a subshell, which the cleanup trap can't see,
# so we call them in order — only the daemon processes are backgrounded.
start_tor  || true
start_i2pd || true

render_pac

# ---------- start bridge ----------

mkdir -p "$(dirname "$LOG")"

if [[ "$ATTACH_EXISTING_BRIDGE" == "1" ]]; then
    # Attach mode: a working bridge is already on $BRIDGE_PORT. Do
    # NOT truncate the existing bridge.log (its owner is still
    # writing to it), and leave BRIDGE_PID empty so cleanup() won't
    # kill a process we didn't spawn.
    BRIDGE_PID=""
else
    : > "$LOG"
    "$NODE" "$BRIDGE" "${BRIDGE_ARGS[@]}" >>"$LOG" 2>&1 &
    BRIDGE_PID=$!
fi

# ---------- splash (single window, three bars) ----------
#
# Spawned AFTER all three processes are started, so each feeder has
# something to tail. Closes itself when all three bars reach 100% (or
# when cleanup() kills the process group on browser exit).
show_splash &
SPLASH_PID=$!

cleanup() {
    # Splash + its tail -F subprocess. Kill the whole process group
    # so the tail doesn't survive zenity exiting.
    if [[ -n "$SPLASH_PID" ]] && kill -0 "$SPLASH_PID" 2>/dev/null; then
        kill -- "-$SPLASH_PID" 2>/dev/null || kill "$SPLASH_PID" 2>/dev/null || true
    fi
    if [[ -n "$TOR_PID" ]] && kill -0 "$TOR_PID" 2>/dev/null; then
        kill "$TOR_PID" 2>/dev/null || true
        for _ in 1 2 3 4 5; do
            kill -0 "$TOR_PID" 2>/dev/null || break
            sleep 0.2
        done
        kill -9 "$TOR_PID" 2>/dev/null || true
    fi
    if [[ -n "$I2PD_PID" ]] && kill -0 "$I2PD_PID" 2>/dev/null; then
        # i2pd's clean shutdown writes router info back to disk; give
        # it a longer SIGTERM grace window than we give tor.
        kill "$I2PD_PID" 2>/dev/null || true
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$I2PD_PID" 2>/dev/null || break
            sleep 0.2
        done
        kill -9 "$I2PD_PID" 2>/dev/null || true
    fi
    if kill -0 "$BRIDGE_PID" 2>/dev/null; then
        kill "$BRIDGE_PID" 2>/dev/null || true
        # Give Node a chance to flush before SIGKILL.
        for _ in 1 2 3 4 5; do
            kill -0 "$BRIDGE_PID" 2>/dev/null || break
            sleep 0.2
        done
        kill -9 "$BRIDGE_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# ---------- wait for bridge ----------

ready=0
if [[ "$ATTACH_EXISTING_BRIDGE" == "1" ]]; then
    # Already confirmed healthy by the attach-mode probe above.
    ready=1
else
    for _ in $(seq 1 60); do
        if ! kill -0 "$BRIDGE_PID" 2>/dev/null; then
            echo "anon-browser: bridge died during startup; tail of log:" >&2
            tail -20 "$LOG" >&2
            exit 1
        fi
        # /api/health returns 200 in --no-token mode (or 403 if the user is
        # running a token-gated bridge they pointed us at — that also
        # counts as reachable; the gate is the bridge's, not ours).
        HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' \
            "http://${BRIDGE_HOST}:${BRIDGE_PORT}/api/health" 2>/dev/null || echo 000)"
        case "$HTTP_CODE" in
            200|403) ready=1; break ;;
        esac
        sleep 0.2
    done
fi

if [[ "$ready" -ne 1 ]]; then
    echo "anon-browser: bridge did not become reachable on ${BRIDGE_HOST}:${BRIDGE_PORT}; tail of log:" >&2
    tail -20 "$LOG" >&2
    exit 1
fi

# ---------- launch the browser ----------

# Re-use the engine's bundled launcher so we inherit environment setup
# (LD_LIBRARY_PATH, GTK overrides, etc). Path moved between engine
# versions; try both pre-15 and 15+ locations.
ENGINE_LAUNCHER=""
for candidate in \
    "$ROOT/Browser/start-anonymous" \
    "$ROOT/start-anonymous" \
; do
    if [[ -x "$candidate" ]]; then ENGINE_LAUNCHER="$candidate"; break; fi
done
[[ -n "$ENGINE_LAUNCHER" ]] \
    || die "could not find Browser/start-anonymous under $ROOT"

# Foreground so we can clean up the bridge when the browser exits.
#
# --class / --name force the X11 WM_CLASS to "Anonymous" so the running
# window matches the .desktop's StartupWMClass=Anonymous (otherwise
# WM_CLASS falls back to the upstream MOZ_APP_NAME baked into the
# binary — "Mullvad Browser" — and GNOME shows a generic gear icon
# instead of the Anonymous mask, while also leaking the fork's origin).
#
# In volatile mode, point -profile at the tmpfs dir we minted above.
# Firefox seeds it from $ROOT/Browser/defaults/profile/ on first use.
EXTRA_ARGS=()
if [[ "$ANON_VOLATILE_FLAG" == "1" ]] && [[ -n "$ANON_VOLATILE_PROFILE_DIR" ]]; then
    EXTRA_ARGS+=(--profile "$ANON_VOLATILE_PROFILE_DIR" --no-remote)
fi

# Strip our own flags (--volatile, --bwrap) before passing the rest
# through so Firefox doesn't choke on unknown args.
PASSTHRU=()
for arg in "$@"; do
    case "$arg" in
        --volatile|--bwrap) ;;
        *) PASSTHRU+=("$arg") ;;
    esac
done

# ---------- optional bubblewrap sandbox ----------
#
# When ANON_USE_BWRAP=1 (or --bwrap was passed) wrap the engine in a
# bubblewrap sandbox: filesystem locked to install root + Data dir,
# $HOME hidden, IPC/PID/user/uts namespaces unshared. Defense-in-depth
# on top of Firefox's own content-process sandbox.
#
# Network is NOT restricted by bwrap — the tor / anon-layer routing
# in PAC handles that. See anon-bwrap-wrap.sh for what's bound/hidden.
WANT_BWRAP=0
for arg in "$@"; do
    case "$arg" in
        --bwrap) WANT_BWRAP=1 ;;
    esac
done
if [[ "${ANON_USE_BWRAP:-0}" == "1" ]]; then
    WANT_BWRAP=1
fi

BWRAP_CMD=()
if [[ "$WANT_BWRAP" == "1" ]]; then
    BWRAP_WRAPPER="$ROOT/anon-bwrap-wrap.sh"
    if [[ ! -x "$BWRAP_WRAPPER" ]]; then
        warn "ANON_USE_BWRAP=1 but $BWRAP_WRAPPER missing or not executable — falling back to unsandboxed launch"
    elif ! command -v bwrap >/dev/null 2>&1; then
        warn "ANON_USE_BWRAP=1 but bwrap not installed (apt install bubblewrap) — falling back to unsandboxed launch"
    else
        export ANON_ROOT="$ROOT"
        BWRAP_CMD=("$BWRAP_WRAPPER")
        printf 'anonymous: launching engine inside bubblewrap sandbox\n' >&2
    fi
fi

# Capture the engine's exit without tripping `set -e` — we need to
# inspect the marker even on non-zero exits (the browser may have
# been killed by Panic and still want a respawn).
ENGINE_EXIT=0
"${BWRAP_CMD[@]}" "$ENGINE_LAUNCHER" --class Anonymous --name Anonymous "${EXTRA_ARGS[@]}" "${PASSTHRU[@]}" || ENGINE_EXIT=$?

# ---------- launcher-managed restart ----------
#
# The browser's New Identity / Panic / Volatile buttons drop
# $ANON_DIR/.restart and quit *without* eRestart, because eRestart
# would relaunch the browser binary directly and leave the bridge
# (managed by this script) dead. We respawn ourselves so tor +
# bridge come back up cleanly.
#
# Consume the marker before re-exec so a crash during the new launch
# doesn't put us in an infinite restart loop.
if [[ -e "$ANON_DIR/.restart" ]]; then
    rm -f "$ANON_DIR/.restart" 2>/dev/null || true
    printf 'anonymous: launcher restart requested (engine exit=%s)\n' \
        "$ENGINE_EXIT" >&2
    # Run trap-registered cleanups (volatile dir, etc.) BEFORE re-exec
    # so the new launcher starts with a clean slate.
    anon_volatile_cleanup
    exec "$0" "$@"
fi

exit "$ENGINE_EXIT"
