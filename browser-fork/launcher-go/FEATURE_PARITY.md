# Feature parity: Go launcher vs. bash launcher

Tracks every behavior in `browser-fork/scripts/anon-browser.launcher.sh`
(1118 lines, the production bash launcher) against the Go launcher.
The Go binary is what ships now (in-browser connect UI lives here);
this doc records what still has to come over from bash before we can
delete the shell script entirely.

Status legend: ✅ done, 🟡 partial, ❌ missing.

## Boot orchestration

| Feature | Status | Notes |
| --- | --- | --- |
| Load `anon-browser.conf` (strict KEY=VALUE) | ✅ | `internal/config` |
| Honor `ANON_BRIDGE_HOST/PORT` env | ✅ | `internal/config` |
| Fetch fresh consensus from `DA_URLS` | ✅ | `internal/consensus` |
| Start `tor` with rendered torrc | ✅ | `internal/tor` |
| Render PAC from template | ✅ | `internal/pac` |
| Start bridge | ✅ | `internal/bridge` |
| Attach mode when bridge already on port | ✅ | `internal/bridge.Start` returns `attached=true` |
| Bridge `/api/health` readiness probe | ✅ | inside bridge package |
| Launch browser engine (Linux/macOS/Windows) | ✅ | `internal/browser` |
| Pass `--class Anonymous --name Anonymous` on X11 | ✅ | `pickEngine` (Linux branch) |
| Passthrough extra argv to engine | ✅ | `flag.Args()` |
| **In-browser connect UI** | ✅ | NEW — `internal/connectui` (replaces yad/zenity popup) |
| Graceful shutdown on SIGTERM/INT/HUP | ✅ | `installSignalHandler` + `process.Supervisor` |

## Connection UI

| Feature | Status | Notes |
| --- | --- | --- |
| Show progress in-browser (Tor-Browser style) | ✅ | `internal/connectui` SSE server, embedded HTML |
| Tor `Bootstrapped N%` feeder | ✅ | `connectui.FeedTorLog` |
| Bridge readiness feeder | 🟡 | reported via `runBoot` updates, not a log tail |
| i2pd phase feeder | ❌ | needs porting once i2pd start path lands |
| Fatal-state UI with stderr details | ✅ | `Server.Fail()` → page shows red error block |
| Headless / `--no-ui` fallback | ✅ | stderr-only progress |
| TTY fallback for no-X11 sessions | ❌ | bash has a terminal-mode splash; deferred — most desktop users have X/Wayland |

## i2p support

| Feature | Status | Notes |
| --- | --- | --- |
| Start `i2pd` with rendered conf | ❌ | bash launcher has `start_i2pd`; nothing in Go yet |
| i2pd readiness probe (HTTPProxy port open) | ❌ | needs `internal/i2pd` package |
| PAC `@@I2P_HTTP_PORT@@` substitution | 🟡 | `pac.Render` accepts the port but main passes sentinel until i2pd lands |
| i2pd splash feeder (reseed → tunnels → ready) | ❌ | bucketed log-matching, see `splash_feed_i2pd` in bash for the regex set |

**Note:** Default install has `ANON_DISABLE_I2P=1` so this is dormant for
most users today. Required before we can promote i2p out of "experimental."

## Linux-only hardening

| Feature | Status | Notes |
| --- | --- | --- |
| `/proc/self/coredump_filter` hardening | ❌ | bash sets it to `0` to suppress core dumps that could leak memory; needs `prctl(PR_SET_DUMPABLE, 0)` equivalent in Go |
| `NO_NEW_PRIVS` via `prctl` | ❌ | trivial via `syscall.Prctl(PR_SET_NO_NEW_PRIVS, 1, …)` on Linux |
| Swap-encryption warning | ❌ | bash checks `/proc/swaps` + `cryptsetup status`; informational only |
| Cloud-sync folder warning (Dropbox/iCloud/…) | ❌ | bash warns if install dir is under a known sync root; informational only |

## Sandboxing

| Feature | Status | Notes |
| --- | --- | --- |
| `--bwrap` / `ANON_USE_BWRAP=1` → bubblewrap sandbox | ❌ | bash invokes `$ROOT/anon-bwrap-wrap.sh`; Go needs an `internal/bwrap` that constructs the same `bwrap` argv |
| Sandbox arg passthrough (skip `--bwrap`/`--volatile` to engine) | ❌ | bash strips these from `PASSTHRU`; Go currently forwards everything in `flag.Args()` |

## Profile lifecycle

| Feature | Status | Notes |
| --- | --- | --- |
| `--volatile` / `ANON_VOLATILE` → tmpfs profile dir | ❌ | bash mints a dir under `$XDG_RUNTIME_DIR`, seeds from `Browser/defaults/profile/`, passes `--profile … --no-remote`, deletes on exit |
| Restart marker `$ANON_DIR/.restart` handshake | ❌ | bash re-execs itself when marker present after engine exit; required so the browser's New Identity / Panic / Volatile buttons can recycle the whole stack (currently they just quit the browser, taking the launcher with it) |
| Stale `Data/*/.parentlock`, `lock`, `parent.lock` cleanup | ✅ | `internal/selfheal.StaleLocks` |

## Desktop integration

| Feature | Status | Notes |
| --- | --- | --- |
| `--register-app` (install `.desktop` + icons under `~/.local/share`) | ❌ | bash writes to `~/.local/share/applications/` + `~/.local/share/icons/hicolor/*/apps/`, runs `update-desktop-database`/`gtk-update-icon-cache` |
| `--unregister-app` (remove the same) | ❌ | symmetric |
| `.desktop` `Icon=` self-heal (bash lines 359–373) | ❌ | rewrite stale `Icon=` line if install was moved |
| `policies.json` `@@INSTALL_DIR@@` self-heal | ✅ | `internal/selfheal.Policies` |

## Diagnostics

| Feature | Status | Notes |
| --- | --- | --- |
| `--help` | ✅ | flag package auto-generates |
| Tor death detection with log tail to stderr | ✅ | `process.Managed` + tor readiness probe |
| Bridge death detection with log tail | ✅ | bridge readiness loop |
| i2pd death detection | ❌ | gated by i2pd port |

## Priority for Phase 3

Order suggested by user-visible impact + implementation cost:

1. **Restart marker handshake** — needed for New Identity / Panic /
   Volatile buttons in the browser to be useful. Low complexity:
   check for marker after `WaitExit`, then `syscall.Exec` self with
   original argv. ~half-day.
2. **`--volatile` / tmpfs profile** — depended on by the Panic button.
   Has to land alongside the restart marker. ~1 day.
3. **`--register-app` / `--unregister-app`** — one-time UX but
   blocking for first-install on a clean machine. ~1 day.
4. **i2pd start path + feeder** — needed before promoting i2p out of
   experimental (and to remove the conf-driven feature toggle). ~2
   days (start + readiness + PAC + connect-UI feeder).
5. **Linux hardening (`PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE=0`)** —
   defense in depth; small patch. ~half-day.
6. **`--bwrap` sandbox wrapper** — already orchestrated by
   `anon-bwrap-wrap.sh`; Go side just needs to invoke it with the
   right argv. ~1 day.
7. **TTY fallback for headless boots** — write progress with ANSI
   bars when `$DISPLAY`/`$WAYLAND_DISPLAY` are unset and we still
   can't open a browser window. ~half-day.
8. **Swap / cloud-sync warnings** — informational only; do last. ~half-day.
9. **`.desktop` Icon= self-heal** — minor; rarely hit. ~couple hours.

Total: roughly 8 working days to close every gap, after which the
bash launcher (and its yad/zenity splash) can be deleted entirely.

## How to roll back to the bash launcher

If something in the Go launcher misbehaves on a user install, the
bash original is preserved alongside the Go binary at install time:

```
cp ~/anon-browser/anonymous.bash.bak ~/anon-browser/anonymous
```

…and the user is back to the pre-swap behavior (yad/zenity popup + all
the Linux-only features above). Once Phase 3 is done we can drop the
backup step from the install script.
