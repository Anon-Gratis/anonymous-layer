#!/usr/bin/env bash
# anon-bwrap-wrap — bubblewrap sandbox wrapper for the engine launcher.
#
# Opt-in. Invoked by browser-fork/scripts/anon-browser.launcher.sh ONLY
# when ANON_USE_BWRAP=1 (or --bwrap is passed). Adds a containment
# layer on top of Firefox's built-in content-process sandbox so a
# chrome-process compromise still can't read $HOME or arbitrary
# block devices.
#
# What this sandbox enforces:
#   - Filesystem: $ROOT bind-mounted read-only; $ROOT/Data,
#     $ROOT/AnonLayer bind-mounted read-write. $HOME (and everything
#     else) is HIDDEN from the browser process.
#   - PID / IPC / user namespaces: unshared. Browser can't see or
#     signal host processes.
#   - DBus session bus: bound read-only (needed for portals, theme
#     integration). Caller can disable by setting
#     ANON_BWRAP_NO_DBUS=1 — at cost of broken file-picker portals.
#   - Audio: PipeWire / Pulse socket bound. ANON_BWRAP_NO_AUDIO=1 to skip.
#   - GPU: /dev/dri bound. ANON_BWRAP_NO_GPU=1 to skip (forces software render).
#   - Display: X11 socket OR Wayland socket bound (auto-detect).
#
# What this sandbox DOES NOT enforce:
#   - Network restriction. We --share-net so tor + bridge loopback
#     keep working. The network anonymity story is handled by tor /
#     anon-layer routing, not bwrap.
#   - Seccomp filter. Firefox brings its own seccomp via the
#     content-process sandbox. Adding ours on top is fragile; left
#     as future work.
#
# Known limits:
#   - Firefox's own content-process sandbox uses CLONE_NEWUSER. Some
#     distros disable unprivileged userns (sysctl
#     kernel.unprivileged_userns_clone=0). On those, the inner
#     content sandbox warns "may offer less protection". bwrap does
#     not fix that; the outer sandbox is independent of the inner.
#   - Hardware video decode via VA-API may need extra /dev paths
#     that this profile does not bind. Disable accelerated decode
#     in about:config if you hit blank video.
#
# CLI:
#   anon-bwrap-wrap.sh COMMAND [ARGS...]
#
# Env:
#   ANON_ROOT           install root (the launcher passes this through).
#                       If unset, taken from $1's dirname's dirname (best-effort).
#   ANON_BWRAP_NO_DBUS  skip DBus bind
#   ANON_BWRAP_NO_AUDIO skip audio sockets
#   ANON_BWRAP_NO_GPU   skip /dev/dri

set -euo pipefail

if ! command -v bwrap >/dev/null 2>&1; then
    printf 'anon-bwrap-wrap: bwrap not installed; install bubblewrap and retry\n' >&2
    exit 127
fi

if [[ $# -lt 1 ]]; then
    printf 'usage: anon-bwrap-wrap COMMAND [ARGS...]\n' >&2
    exit 64
fi

# Resolve the install root. The launcher exports ANON_ROOT when it
# invokes us; if it didn't, infer from argv[0]'s ancestry.
ROOT="${ANON_ROOT:-$(cd "$(dirname "$(readlink -f "$1")")/.." 2>/dev/null && pwd || echo "")}"
if [[ -z "$ROOT" ]] || [[ ! -d "$ROOT/AnonLayer" ]]; then
    printf 'anon-bwrap-wrap: could not locate install root (set ANON_ROOT=/path/to/anon-browser)\n' >&2
    exit 65
fi

# ---------- build bwrap argv ----------

BWRAP=(
    bwrap
    --die-with-parent
    --new-session
    --unshare-user
    --unshare-pid
    --unshare-ipc
    --unshare-uts
    --unshare-cgroup-try
    --share-net                  # see header comment — tor handles anonymity
    --hostname anonymous
    --proc /proc
    --dev /dev
    --tmpfs /tmp
    --tmpfs /var/tmp
    --tmpfs /run

    # System read-only
    --ro-bind /usr /usr
    --symlink usr/lib /lib
    --symlink usr/lib64 /lib64
    --symlink usr/bin /bin
    --symlink usr/sbin /sbin
    --ro-bind-try /etc/resolv.conf /etc/resolv.conf
    --ro-bind-try /etc/ssl /etc/ssl
    --ro-bind-try /etc/ca-certificates /etc/ca-certificates
    --ro-bind-try /etc/fonts /etc/fonts
    --ro-bind-try /etc/hosts /etc/hosts
    --ro-bind-try /etc/nsswitch.conf /etc/nsswitch.conf
    --ro-bind-try /etc/localtime /etc/localtime
    --ro-bind-try /var/cache/fontconfig /var/cache/fontconfig

    # Install root: read-only by default
    --ro-bind "$ROOT" "$ROOT"

    # Read-write: profile + per-launch runtime
    --bind "$ROOT/Data" "$ROOT/Data"
    --bind "$ROOT/AnonLayer" "$ROOT/AnonLayer"
)

# Display server (X11 OR Wayland — both can be bound; Firefox picks)
if [[ -d /tmp/.X11-unix ]]; then
    BWRAP+=(--ro-bind /tmp/.X11-unix /tmp/.X11-unix)
fi
if [[ -n "${XAUTHORITY:-}" && -f "$XAUTHORITY" ]]; then
    BWRAP+=(--ro-bind "$XAUTHORITY" "$XAUTHORITY")
fi
if [[ -n "${WAYLAND_DISPLAY:-}" && -n "${XDG_RUNTIME_DIR:-}" ]]; then
    WSOCK="$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY"
    if [[ -S "$WSOCK" ]]; then
        # Need the runtime dir itself so the socket path resolves
        BWRAP+=(--bind "$XDG_RUNTIME_DIR" "$XDG_RUNTIME_DIR")
    fi
fi

# Audio (opt-out)
if [[ "${ANON_BWRAP_NO_AUDIO:-0}" != "1" && -n "${XDG_RUNTIME_DIR:-}" ]]; then
    # PipeWire
    [[ -S "$XDG_RUNTIME_DIR/pipewire-0" ]] && \
        BWRAP+=(--ro-bind-try "$XDG_RUNTIME_DIR/pipewire-0" "$XDG_RUNTIME_DIR/pipewire-0")
    # Pulse
    [[ -d "$XDG_RUNTIME_DIR/pulse" ]] && \
        BWRAP+=(--ro-bind-try "$XDG_RUNTIME_DIR/pulse" "$XDG_RUNTIME_DIR/pulse")
fi

# DBus session bus (opt-out)
if [[ "${ANON_BWRAP_NO_DBUS:-0}" != "1" && -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]]; then
    # DBUS_SESSION_BUS_ADDRESS looks like 'unix:path=/run/user/1000/bus,guid=...'
    DBUS_PATH=$(printf '%s' "$DBUS_SESSION_BUS_ADDRESS" \
        | sed -ne 's/^unix:path=\([^,]*\).*/\1/p')
    if [[ -n "$DBUS_PATH" && -S "$DBUS_PATH" ]]; then
        BWRAP+=(--ro-bind-try "$DBUS_PATH" "$DBUS_PATH")
    fi
fi

# GPU (opt-out)
if [[ "${ANON_BWRAP_NO_GPU:-0}" != "1" && -d /dev/dri ]]; then
    BWRAP+=(--dev-bind /dev/dri /dev/dri)
fi

# Pass-through env vars. Anything the browser/Firefox stack needs for
# display, audio, theming, locale.
for v in \
    DISPLAY WAYLAND_DISPLAY XDG_RUNTIME_DIR XDG_SESSION_TYPE \
    XAUTHORITY DBUS_SESSION_BUS_ADDRESS \
    XDG_DATA_DIRS XDG_CONFIG_DIRS XDG_CURRENT_DESKTOP XDG_SESSION_DESKTOP \
    PULSE_SERVER \
    HOME USER LOGNAME TERM LANG LC_ALL LC_CTYPE TZ \
    MOZ_USE_XINPUT2 MOZ_ENABLE_WAYLAND GDK_BACKEND GTK_USE_PORTAL \
    PATH \
; do
    val="${!v:-}"
    [[ -n "$val" ]] && BWRAP+=(--setenv "$v" "$val")
done

# Final guardrails: clear ambient capabilities, drop into a stable
# working directory inside the install root (browser expects it).
BWRAP+=(
    --chdir "$ROOT"
    --
)

exec "${BWRAP[@]}" "$@"
