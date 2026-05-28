# Go launcher — design

Replaces `browser-fork/scripts/anon-browser.launcher.sh` with a single
cross-platform Go binary that boots the anon-layer stack (tor + i2pd +
bridge), surfaces boot progress inside the browser itself
(Tor-Browser-style), and exec's the bundled Firefox-fork browser.

## Goals

1. **1:1 feature parity with the current bash launcher on Linux** —
   bwrap, --volatile tmpfs, --register-app, /proc hardening, swap
   warnings, restart marker, self-heal of `policies.json` and
   `.desktop` paths, stale-lock cleanup, etc.
2. **Native binaries for Linux / Windows / macOS** built from one
   codebase with `GOOS=… GOARCH=… go build`.
3. **No CGo, anywhere** — the connect UI is HTML served from an
   embedded HTTP server, not a native window. Cross-compilation is
   `CGO_ENABLED=0 GOOS=… GOARCH=… go build`.
4. **No regression vs. bash** — anyone running `./anonymous` today
   should see identical behavior after the swap, except the launcher
   binary name differs.

## Non-goals

- Replacing the bridge (`anon-browse-gui.mjs` stays in Node — too
  much network/crypto code to rewrite).
- Replacing the WebExtension (`anon-layer@anon.gratis.xpi` stays JS).
- Becoming a process supervisor for arbitrary apps. This is
  Anonymous-specific.

## Directory layout

```
browser-fork/launcher-go/
├── DESIGN.md                  (this file)
├── README.md                  build & test instructions
├── go.mod
├── go.sum
├── cmd/
│   └── anonymous/
│       └── main.go            entry point; flag parse → orchestrate
├── internal/
│   ├── config/                load anon-browser.conf, env, flags
│   ├── process/               start/stop/wait/kill primitives
│   ├── tor/                   tor binary + torrc render + readiness
│   ├── i2pd/                  i2pd binary + conf render + readiness
│   ├── bridge/                bridge spawn / attach / health probe
│   ├── browser/               find engine launcher, exec, restart marker
│   ├── connectui/             localhost HTTP server + embedded connect page + tor-log feeder
│   ├── volatile/              tmpfs profile dir lifecycle
│   ├── desktop/               --register-app / --unregister-app (Linux)
│   ├── selfheal/              policies.json + .desktop path rewrites,
│   │                          stale-lock cleanup
│   ├── consensus/             fetch from DA_URLS (matches bash fetch_consensus)
│   ├── harden/                /proc/self/coredump_filter, NO_NEW_PRIVS
│   │                          (Linux-only; no-op stubs elsewhere)
│   ├── safety/                swap warning, cloud-sync warning
│   ├── pac/                   PAC template render
│   ├── bwrap/                 bubblewrap wrapper (Linux-only)
│   └── platform/              build-tagged OS shims (paths, integration)
```

The connect-page HTML lives at `internal/connectui/index.html`, bundled
into the binary via `//go:embed`.

## Platform abstraction

Use Go build tags rather than per-OS files-with-different-content. Files
named `foo_linux.go`, `foo_windows.go`, `foo_darwin.go` are auto-selected
by `go build`. For things that exist on multiple OSes but with different
implementations (paths, etc.), `internal/platform/` exports a single
interface and each `_linux.go` / `_windows.go` / `_darwin.go` file
implements it.

Linux-only modules (`bwrap/`, `harden/`, `desktop/`) compile as no-op
stubs on Windows/macOS — the calling code doesn't need to branch.

| Feature | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Process spawn / kill | `os/exec` + `syscall.Setpgid` | `os/exec` + `CREATE_NEW_PROCESS_GROUP` | `os/exec` + `Setpgid` |
| Signal handling | SIGTERM / SIGINT → cleanup | CTRL_C_EVENT / WM_CLOSE → cleanup | SIGTERM / SIGINT |
| Volatile profile | tmpfs in `$XDG_RUNTIME_DIR` | `%TEMP%` + DELETE_ON_CLOSE | mounted ramdisk via `hdiutil` |
| Desktop integration | hicolor + `.desktop` | Start Menu shortcut + registry | `.app` bundle is the registration |
| bwrap sandbox | full | not applicable (use Win Sandbox separately) | not applicable |
| /proc hardening | full | no-op | no-op |
| Restart marker | `$ANON_DIR/.restart` | same | same |
| Browser engine launcher path | `Browser/start-anonymous` | `Browser\firefox.exe` | `Anonymous.app/Contents/MacOS/firefox` |

## Process supervision

Each managed process (`tor`, `i2pd`, `bridge`, `browser`) is wrapped by
the same struct:

```go
type ManagedProcess struct {
    Name        string
    Cmd         *exec.Cmd
    LogPath     string
    ReadyCheck  func(ctx context.Context) error  // poll for readiness
    GracePeriod time.Duration                    // SIGTERM grace
    ProgressCh  chan<- connectui.Event           // for connect UI feeder
}
```

Lifecycle: `Start()` → `WaitReady(ctx)` → caller proceeds → on shutdown
`StopGraceful(ctx)` (SIGTERM, wait `GracePeriod`, SIGKILL).

A central `Supervisor` owns all `ManagedProcess` instances and is the
single thing the signal handler talks to. On SIGINT/SIGTERM/SIGHUP it
calls `Supervisor.Shutdown(ctx)` which tears down in reverse-start
order (browser → bridge → i2pd → tor → connectui) with a 10s overall
budget before everything gets SIGKILL.

The bridge's **attach mode** (the recently-added feature) is modeled as
a `ManagedProcess` with `Cmd == nil` — `Start()` does the `/api/health`
probe and `Stop()` is a no-op (we didn't spawn it, we don't kill it).

## Connect-UI architecture (Tor-Browser-style)

There is no native splash window. The launcher stands up an HTTP
server on `127.0.0.1:<random-port>`, launches the browser pointed at
`http://127.0.0.1:<port>/`, then runs the boot sequence concurrently.

The connect page is **JavaScript-free** — it uses a `<meta
http-equiv="refresh">` polling tag and the server fully renders the
current state into HTML on each GET. This is deliberate: Tor-Browser
installs default to the "Safest" security level which disables JS
globally (including for localhost), so an SSE/JS-driven design would
hang silently. Meta-refresh works in every security level and gracefully
degrades to a static page if the user disables it via Firefox's
`accessibility.blockautorefresh` pref.

```
launcher                                 browser
   │                                        │
   ├─ listen 127.0.0.1:<rand>               │
   ├─ exec firefox http://127.0.0.1:<rand>/ ┤
   │                                        ├─ GET / → page (state @ t=0)
   ├─ runBoot(): consensus → tor → bridge   │
   │  └─ Server.Update(...) (stores state)  │
   │                                        ├─ GET / → page (state @ t=1) ← meta-refresh
   │                                        ├─ GET / → page (state @ t=2)
   │                                        ├─ …
   └─ runBoot done: Server.Finish() ────────┤
                                            ├─ GET / → page with 0s refresh to homepage
                                            └─ navigates to homepage
```

- `internal/connectui/server.go` owns the HTTP listener and the in-memory
  state (insertion-ordered map of bar name → latest event).
- `internal/connectui/index.html` is a Go `html/template` rendered on
  each GET. Same amber-CRT aesthetic — three progress bars (consensus
  / tor / bridge) inside a corner-bracket frame, with the fill widths
  injected as inline `style="width: N%"`. Embedded via `//go:embed`.
- `internal/connectui/feed_tor.go` tails `tor.log` for `Bootstrapped N%`
  lines and calls `Server.Update("tor", pct, label)`.
- The PAC file already routes `127.0.0.1` to DIRECT, so the connect
  page is reachable before tor or the bridge are up.

Refresh cadence is 1s. Faster would smooth the UX but burn more CPU
on slow boot sequences; slower would make the bars feel laggy.

Fallback: `--no-ui` skips the HTTP server and logs progress to stderr;
the browser still launches normally and lands on the configured
homepage. Headless (no `$DISPLAY`) is the browser's problem, not the
launcher's — the connect server is always safe to run.

## Config format

Keep the existing `anon-browser.conf` shell-source format for backward
compat (existing installs work without touching the conf). Internally
parse with [hashicorp/go-envparse](https://github.com/hashicorp/go-envparse)
or similar (a strict KEY=VALUE parser, no shell evaluation).

Honor every env var and CLI flag the bash version did:
`ANON_BRIDGE_HOST/PORT`, `ANON_DISABLE_TOR/I2P`, `ANON_USE_BWRAP`,
`ANON_VOLATILE`, `--volatile`, `--bwrap`, `--register-app`,
`--unregister-app`, `--help`. Passthrough remaining args to the
browser engine.

## Self-heal pipeline

Runs in `cmd/anonymous/main.go` BEFORE process spawn, mirroring the
bash version's lines 365–404:

1. `selfheal.Policies()` — read `Browser/distribution/policies.json`,
   replace `@@INSTALL_DIR@@` with the actual install root if found.
2. `selfheal.DesktopIcon()` — read `$ROOT/anonymous.desktop`, rewrite
   `Icon=` line if it points at a wrong path.
3. `selfheal.StaleLocks()` — scan `Data/*/.parentlock`, `lock`,
   `parent.lock`; remove if symlink target's PID isn't alive.

Idempotent — running them on a clean install is a no-op.

## Restart marker handshake

After `browser.Exec()` returns, check for `$ANON_DIR/.restart`. If
present, delete it, run `volatile.Cleanup()`, then re-exec self with
the original argv (`syscall.Exec` on Linux/macOS, `os.StartProcess` +
`os.Exit` on Windows).

## Cleanup semantics

`defer supervisor.Shutdown(ctx)` in `main()` handles every exit path
(normal exit, panic, signal). Volatile profile dir is registered via
the same supervisor so it's cleaned up after the browser is killed.

Cleanup is **idempotent and bounded** — every step has a deadline, so a
hung child process can't keep the launcher from exiting forever.

## Build / release

```
# Local dev (Linux)
cd browser-fork/launcher-go
go build -o ../../dist-launcher/linux-amd64/anonymous ./cmd/anonymous

# Cross-build for Windows (from Linux)
GOOS=windows GOARCH=amd64 \
  go build -o ../../dist-launcher/windows-amd64/anonymous.exe ./cmd/anonymous

# macOS (any host — no CGo)
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 \
  go build -o ../../dist-launcher/darwin-arm64/anonymous ./cmd/anonymous
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 \
  go build -o ../../dist-launcher/darwin-amd64/anonymous ./cmd/anonymous
```

All targets cross-compile cleanly from a single Linux host with
`CGO_ENABLED=0`. No per-OS SDKs, no mingw, no WebKitGTK headers.

## Testing

- Unit tests per `internal/` package (process lifecycle, config parse,
  PAC render, selfheal idempotency).
- Integration test: spin up the launcher against a mock bridge on a
  random high port, assert it goes through the full lifecycle and
  shuts down cleanly on SIGTERM.
- Side-by-side smoke test on Linux: alternate between bash and Go
  launchers against the same `~/anon-browser/` install, verify the
  browser starts identically in both cases.

## Phase plan

| Phase | Deliverable | ETA |
| --- | --- | --- |
| 1 | MVP Go launcher, Linux only, no splash, no Linux-only extras (bwrap/volatile/register-app). Replaces ~60% of bash. | ~3 days |
| 2 | In-browser connect UI (HTTP + SSE), with feeders matching bash protocol | ~3 days |

Phase 3 work-items (i2pd, --volatile, --bwrap, --register-app,
hardening, restart marker, TTY fallback, swap/cloud-sync warnings) are
broken out per-feature with priority + effort in
[FEATURE_PARITY.md](./FEATURE_PARITY.md).
| 3 | All Linux-only features (bwrap, volatile, register-app, hardening, swap warning, restart marker, self-heal) | ~3 days |
| 4 | Cross-compile + smoke-test Windows + macOS launcher binaries | ~2 days |
| 5 | `repackage-mullvad-windows.sh` building from Linux, Scoop manifest | ~3 days |
| 6 | `repackage-mullvad-macos.sh` running on GH Actions, Homebrew Cask | ~3 days |
| 7 | Release workflow + signed SHA256SUMS | ~1 day |

Total ~18 working days. Each phase ships a working artifact — no
big-bang reveal at the end.

## Open questions

1. **bridge crashes** — when the bridge dies mid-session, should the
   supervisor restart it or surface the error to the user? Bash
   launcher just dies. Suggest: restart up to 3 times within 5
   minutes, then surface. Survives the descfetch-timeout class of
   transient failures.
2. **macOS app bundle structure** — does the Go launcher live at
   `Anonymous.app/Contents/MacOS/anonymous` and Info.plist's
   `CFBundleExecutable` points at it? Or is there a wrapper script?
   Lean toward the former.
3. **Update mechanism** — bash version has no auto-update. Go version
   could check for new releases via signed manifest from
   `anonymous.gratis`. Defer to phase 8.
