# Go launcher — design

Replaces `browser-fork/scripts/anon-browser.launcher.sh` with a single
cross-platform Go binary that boots the anon-layer stack (tor + i2pd +
bridge), presents a splash UI, and exec's the bundled Firefox-fork
browser.

## Goals

1. **1:1 feature parity with the current bash launcher on Linux** —
   bwrap, --volatile tmpfs, --register-app, /proc hardening, swap
   warnings, restart marker, self-heal of `policies.json` and
   `.desktop` paths, stale-lock cleanup, etc.
2. **Native binaries for Linux / Windows / macOS** built from one
   codebase with `GOOS=… GOARCH=… go build`.
3. **No CGo** in the main path — keeps cross-compilation trivial. The
   only CGo dep is the splash webview lib (see below), and that's
   built per-target on the target.
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
│   ├── splash/                webview window + feeder protocol
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
└── splash-ui/
    └── index.html             single-page splash, served to webview
```

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
    ProgressCh  chan<- splash.Event              // for splash feeder
}
```

Lifecycle: `Start()` → `WaitReady(ctx)` → caller proceeds → on shutdown
`StopGraceful(ctx)` (SIGTERM, wait `GracePeriod`, SIGKILL).

A central `Supervisor` owns all `ManagedProcess` instances and is the
single thing the signal handler talks to. On SIGINT/SIGTERM/SIGHUP it
calls `Supervisor.Shutdown(ctx)` which tears down in reverse-start
order (browser → bridge → i2pd → tor → splash) with a 10s overall
budget before everything gets SIGKILL.

The bridge's **attach mode** (the recently-added feature) is modeled as
a `ManagedProcess` with `Cmd == nil` — `Start()` does the `/api/health`
probe and `Stop()` is a no-op (we didn't spawn it, we don't kill it).

## Splash architecture

One HTML page, served by an embedded webview window via
[webview/webview_go](https://github.com/webview/webview_go) (uses
WebKitGTK / WebView2 / WebKit, ~5MB binary overhead, no Chromium
bundle).

- The Go launcher binds a JS function `anonProgress(name, pct, label)`
  exposed to the webview.
- Each feeder goroutine (`internal/splash/feed_tor.go`,
  `feed_i2pd.go`, `feed_bridge.go`) tails the same logs the bash
  version did and calls the bound function via `webview.Dispatch`.
- The HTML is the same amber-CRT aesthetic as the new-tab page — three
  progress bars stacked vertically inside a corner-bracket frame.
- When all three feeders hit 100, the splash window auto-closes.

Fallback: if `webview` fails to init (e.g., no display server), drop to
a TUI splash via [bubbletea](https://github.com/charmbracelet/bubbletea)
in the controlling terminal. Same three-bar layout, just text.

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

# macOS (must build on a Mac because webview has CGo deps on Darwin)
# CI: GitHub Actions macos-latest runner
GOOS=darwin GOARCH=arm64 \
  go build -o ../../dist-launcher/darwin-arm64/anonymous ./cmd/anonymous
GOOS=darwin GOARCH=amd64 \
  go build -o ../../dist-launcher/darwin-amd64/anonymous ./cmd/anonymous
```

Note on the webview lib: it uses CGo. Linux cross-builds work because
WebKitGTK headers are available in standard Ubuntu containers. Windows
cross-builds from Linux need mingw + the WebView2 SDK headers — doable
but annoying. macOS cross-builds from anywhere other than macOS are
not realistic (Apple SDKs). So:

- Linux launcher → built locally or in a Linux CI runner
- Windows launcher → built in an Ubuntu CI runner with mingw + WebView2 SDK
- macOS launcher → built on GitHub Actions macos-latest

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
| 2 | Splash UI via webview, with feeders matching bash protocol | ~3 days |
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
