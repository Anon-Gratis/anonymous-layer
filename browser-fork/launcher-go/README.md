# launcher-go

Go-language replacement for `browser-fork/scripts/anon-browser.launcher.sh`.

See `DESIGN.md` for the full architecture, scope decisions, and phase plan.

## Status

**Phases 1 + 2 shipped.** Boots tor + bridge (with attach-mode) and
launches the browser on Linux. Webview-based splash UI shows consensus /
tor / bridge progress with the amber-CRT aesthetic; falls back to
stderr-only on headless / `--no-splash`.

Phases 3–7 (Linux-only feature parity, cross-compile, repackage
scripts, distribution) are listed in `DESIGN.md`.

## Requirements

### To run the built binary

- An existing Anon Browser install at `~/anon-browser/` (or any
  path passed via `--install-dir`)
- `libwebkit2gtk-4.1-0` (runtime, already shipped on Ubuntu 24.04+)

### To build from source

- Go ≥ 1.23
- `libwebkit2gtk-4.1-dev` (CGo headers for the webview splash)
- pkg-config

### Build-deps workaround on Ubuntu 24.04+

`webview/webview_go` hardcodes `pkg-config --libs webkit2gtk-4.0` in
its cgo directive, but 4.0 was dropped from Ubuntu in 24.04. Solution:
alias `.pc` files that redirect 4.0 lookups to 4.1.

```
mkdir -p ~/.local/pkgconfig
cat > ~/.local/pkgconfig/webkit2gtk-4.0.pc <<'EOF'
Name: WebKit2GTK-4.0
Description: alias for 4.1
Version: 2.50
Requires: webkit2gtk-4.1
EOF
cat > ~/.local/pkgconfig/javascriptcoregtk-4.0.pc <<'EOF'
Name: JavaScriptCoreGTK-4.0
Description: alias for 4.1
Version: 2.50
Requires: javascriptcoregtk-4.1
EOF

export PKG_CONFIG_PATH=~/.local/pkgconfig:$PKG_CONFIG_PATH
```

(Upstream issue: <https://github.com/webview/webview/issues/1115>. Will go
away if/when the lib moves to 4.1 or adds a build tag.)

## Build

```
go build -o ./dist/anonymous ./cmd/anonymous
```

### Cross-compile

Two builds per non-Linux target — one with CGo (full webview splash,
requires per-OS SDK at build time) and one without (stderr splash
fallback, builds anywhere).

**Without CGo** — works from any Linux box, no SDKs needed:

```
for triple in linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64; do
  os="${triple%/*}"; arch="${triple#*/}"; ext=""; [ "$os" = "windows" ] && ext=".exe"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch \
    go build -o ./dist/anonymous-${os}-${arch}${ext} ./cmd/anonymous
done
```

All 5 targets currently compile clean at ~8 MB each. Validated 2026-05-24.

**With CGo (full splash)** — per-OS:

| Target | Build host | Extra requirement |
| --- | --- | --- |
| linux/amd64 | local Linux | `libwebkit2gtk-4.1-dev` + the .pc shim above |
| windows/amd64 | local Linux *or* CI | mingw-w64 toolchain + WebView2 SDK headers + cross-pkg-config |
| darwin/amd64,arm64 | GitHub Actions `macos-latest` | n/a (Apple SDK already on runner) |

Windows-with-CGo cross-compile from Linux is *possible* but painful;
plan is to do it from a GH Actions Windows runner in Task #24 instead.

## Run

```
./dist/anonymous --install-dir ~/anon-browser
```

Or drop the binary at the install root and run without `--install-dir` —
it defaults to the directory containing itself.

Honored env vars (same as the bash launcher):

| Var | Default | Notes |
| --- | --- | --- |
| `ANON_BRIDGE_HOST` | `127.0.0.1` | passed to bridge `--listen` |
| `ANON_BRIDGE_PORT` | `1081` | passed to bridge `--port`; attach-mode probes this |

Honored conf keys (`AnonLayer/config/anon-browser.conf`):
`CONNECT`, `CONSENSUS`, `DA_TRUST`, `DESCRIPTOR`, `DESCRIPTOR_DIR`,
`HSDIR_URL`, `DA_URLS`, `ALLOW_CO_LOCATED`, `ANON_DISABLE_TOR`,
`ANON_DISABLE_I2P`.

## Tested side-by-side with bash launcher

Smoke test from a clean state:

```
$ ./dist/anonymous --install-dir ~/anon-browser
anonymous: refresh: fetching https://da1.anon.gratis/consensus.bin
anonymous: refresh: wrote 504 bytes from ...
anonymous: tor SOCKS: 127.0.0.1:38931
anonymous: PAC rendered to ~/anon-browser/AnonLayer/tor/run/anon.pac
anonymous: bridge ready on 127.0.0.1:1081
anonymous: browser launched
```

Shutdown is clean on SIGINT/SIGTERM — every spawned child is reaped.
The attach-mode short-circuit means restarting the launcher while a
bridge is already up doesn't double-spawn.

## Phase 2 → Phase 3 gap

Not yet implemented (deliberately deferred per the phase plan):

- i2pd start path
- `--volatile`, `--bwrap`, `--register-app`, `--unregister-app` flags
- /proc/self/coredump_filter hardening, NO_NEW_PRIVS
- Swap-encryption + cloud-sync folder warnings
- Self-heal of `policies.json` `@@INSTALL_DIR@@` and `.desktop` Icon path
- Restart marker handshake (`$ANON_DIR/.restart`)
- Stale-lock cleanup on `Data/*/.parentlock`

These come in phase 3.

## Splash backend selection

`splash.New()` picks at runtime:

| Condition | Backend |
| --- | --- |
| `$DISPLAY` or `$WAYLAND_DISPLAY` set, webview inits OK | `webviewBackend` |
| no display server | `logBackend` (stderr) |
| `--no-splash` flag | `noopBackend` (silent) |

The webview backend embeds `internal/splash/index.html` via `//go:embed`
— editing that file changes the splash UI; rebuild required.
