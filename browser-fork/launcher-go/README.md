# launcher-go

Go-language replacement for `browser-fork/scripts/anon-browser.launcher.sh`.

See `DESIGN.md` for the full architecture, scope decisions, and phase plan.

## Status

**Phases 1 + 2 shipped.** Boots tor + bridge (with attach-mode) and
launches the browser on Linux. The connection UI now lives **inside the
browser** (Tor-Browser-style): the launcher serves a small page on
127.0.0.1 with the amber-CRT progress aesthetic, launches the browser
pointed at it, runs the boot sequence concurrently, and the page
auto-redirects to the homepage when everything is ready.

Phases 3–7 (Linux-only feature parity, cross-compile, repackage
scripts, distribution) are listed in `DESIGN.md`.

## Requirements

### To run the built binary

- An existing Anon Browser install at `~/anon-browser/` (or any
  path passed via `--install-dir`)

No GUI toolkits or CGo libs required at runtime — the connect UI is
HTML served from the launcher's own embedded HTTP server.

### To build from source

- Go ≥ 1.23
- That's it. No CGo, no pkg-config, no WebKit headers.

## Build

```
CGO_ENABLED=0 go build -o ./dist/anonymous ./cmd/anonymous
```

### Cross-compile

One pure-Go build per target, works from any host:

```
for triple in linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64; do
  os="${triple%/*}"; arch="${triple#*/}"; ext=""; [ "$os" = "windows" ] && ext=".exe"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch \
    go build -o ./dist/anonymous-${os}-${arch}${ext} ./cmd/anonymous
done
```

## Run

```
./dist/anonymous --install-dir ~/anon-browser
```

Or drop the binary at the install root and run without `--install-dir` —
it defaults to the directory containing itself.

Flags:

| Flag | Effect |
| --- | --- |
| `--install-dir PATH` | install root (default: dir containing the launcher binary) |
| `--no-ui` | skip the in-browser connect page; log boot progress to stderr only |

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
anonymous: connect UI: http://127.0.0.1:46123/
anonymous: browser launched
anonymous: progress: consensus 100% — fresh
anonymous: progress: tor      100% — ready
anonymous: tor SOCKS: 127.0.0.1:38931
anonymous: bridge ready on 127.0.0.1:1081
anonymous: progress: bridge   100% — ready
```

Shutdown is clean on SIGINT/SIGTERM — every spawned child is reaped.
The attach-mode short-circuit means restarting the launcher while a
bridge is already up doesn't double-spawn.

## Phase 2 → Phase 3 gap

Full audit of every bash-launcher feature that hasn't landed in Go yet,
with priority + estimated effort, lives in [FEATURE_PARITY.md](./FEATURE_PARITY.md).

The high-impact items still missing:

- **Restart marker handshake** — needed for the browser's New Identity /
  Panic / Volatile buttons to actually cycle the launcher.
- **`--volatile` tmpfs profile** — paired with the restart marker; the
  Panic button depends on both.
- **i2pd start path + feeder** — gated default-off today, but required
  to retire the bash launcher.
- **`--register-app` / `--unregister-app`** — one-time UX, but blocks
  first-install on a clean machine.
- **`--bwrap` sandbox** — defense-in-depth; bash currently invokes
  `anon-bwrap-wrap.sh`, Go needs to do the same.
- **Linux hardening (`PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE=0`)**.
- **TTY fallback** for headless / SSH boots.

## Connect UI architecture

`internal/connectui` runs an HTTP server on `127.0.0.1:<random-port>`.

| Route | Purpose |
| --- | --- |
| `GET /` | the connect page — fully server-side-rendered HTML reflecting current boot state |
| `GET /healthz` | liveness probe |

The page is **JavaScript-free**. It uses a `<meta http-equiv="refresh"
content="1">` tag to repoll the server every second; each render
reflects the latest progress events. When `Finish()` has been called
the next render swaps in a `<meta http-equiv="refresh" content="0;
url=<homepage>">` and the browser navigates to the homepage.

This matters because Tor-Browser-style installs default to the "Safest"
security level which globally disables JavaScript — including for
localhost. An SSE-based design would silently hang there. Meta-refresh
works in every security level.

Localhost is DIRECT in `anon.pac`, so the page is reachable before tor
/ bridge are up.

Editing `internal/connectui/index.html` changes the UI — `go:embed`
bundles it into the binary, so a rebuild is required.

If `--no-ui` is passed (or the boot sequence can't bind a localhost
port), the launcher falls back to logging progress to stderr; the
browser is still launched normally.
