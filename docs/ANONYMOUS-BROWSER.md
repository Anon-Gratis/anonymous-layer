# Anonymous v0.1 — branded browser for the anon-layer network

| | |
|---|---|
| Status | **Functional MVP — Linux x86_64 tarball builds end-to-end** |
| Engine | Gecko (via an unmodified upstream privacy-browser engine; see Help > About > Credits) |
| Approach | Repackage + rebrand. Engine signed upstream; we add the bridge + brand. |
| Output size | ~137 MB (xz) Linux tarball |
| Time to build | ~8 minutes on a fast machine (~3 min if Mullvad tarball is cached) |
| Builder script | `browser-fork/scripts/repackage-mullvad.sh` |
| Brand assets | `browser-fork/branding/{source,generated}/` |

If you want the long-term "true fork" plan (compile the engine from
source, multi-month engineering, signing certs) see
[`BROWSER-FORK.md`](./BROWSER-FORK.md). This doc covers the
short-term, shippable path that has zero "Mullvad" in the user UI.

## What this gives you

A single tarball — `anonymous-<version>-linux-x86_64.tar.xz` — that
unpacks to a self-contained, branded directory. Inside:

```
anonymous-<version>-linux-x86_64/
├── anonymous*                 ← the launcher users actually run
├── anonymous.desktop          ← .desktop file for app menus / file managers
├── README.txt                 ← in-tarball quick start
├── Browser/                   ← engine + our patches
│   ├── start-anonymous        ← engine launcher (called by ours)
│   ├── anonymous              ← shell wrapper that sets LD_LIBRARY_PATH and execs anonymous.real
│   ├── anonymous.real         ← the actual ELF binary
│   ├── application.ini        ← Vendor/Name/RemotingName all set to "Anonymous"
│   ├── browser/omni.ja        ← brand strings in every locale → "Anonymous"
│   ├── browser/chrome/icons/default/default{16,32,48,64,128}.png ← our logo
│   ├── distribution/
│   │   ├── policies.json      ← our policies (no SOCKS proxy in v0.1)
│   │   └── extensions/
│   │       └── anon-layer@anon.gratis.xpi   ← pre-installed
│   └── defaults/profile/user.js   ← baked into new profiles
├── AnonLayer/                 ← everything we add on top
│   ├── node/bin/node          ← bundled Node runtime
│   ├── bridge/                ← anon-browse-gui + modules + production deps
│   ├── config/
│   │   ├── anon-browser.conf  ← user edits this (CONNECT or CONSENSUS/DA/DESC)
│   │   └── anon-browser.conf.example
│   └── share/anon-browser.png
```

## How to build

```bash
# From the repo root, with bash/curl/tar/xz/node installed:
browser-fork/scripts/repackage-mullvad.sh
# → dist/anonymous-<version>-linux-x86_64.tar.xz
# → dist/anonymous-<version>-linux-x86_64.tar.xz.sha256
```

The script:

1. Downloads the upstream browser tarball (~117 MB).
   (`--offline path` to skip; `--skip-gpg` to bypass signature verify.)
2. Downloads Node 20 runtime (~26 MB) from `nodejs.org`.
3. Builds the WebExtension `.xpi` via `browser-fork/extension/build-xpi.sh`.
4. Stages the AnonLayer/ sidecar (Node + bridge + prod deps).
5. Drops the v0.1 `policies.json` (no SOCKS proxy) and `user.js` into
   the right engine paths.
6. Installs the `.xpi` into `Browser/distribution/extensions/`.
7. **`rebrand.sh`** — rewrites every user-visible "Mullvad" string to
   "Anonymous", swaps icons, renames binaries and the .desktop file.
8. Installs the `anonymous` launcher at the tarball root.
9. Writes `README.txt` at the root.
10. Repacks as `anonymous-<version>-linux-x86_64.tar.xz` + sha256.

### `rebrand.sh` — what changes

| Where | Before | After |
|---|---|---|
| `application.ini` Vendor/Name/RemotingName/CodeName | `Mullvad` / `MullvadBrowser` | `Anonymous` |
| `application.ini` SourceRepository, AppUpdate.URL | upstream | github.com/anonymous-gratis, empty |
| `omni.ja` brand.ftl × 30 locales | "Mullvad Browser" | "Anonymous" / "Anonymous Browser" |
| `omni.ja` brand.properties × 30 locales | "Mullvad Browser" | "Anonymous" |
| `omni.ja` wordmark .ftl × 30 locales | "MULLVAD BROWSER" | "ANONYMOUS" |
| `omni.ja` toolkit FTL bundles | "Mullvad Browser" | "Anonymous" |
| `omni.ja` toolkit icon (16px) | upstream PNG | our mask logo |
| `Browser/browser/chrome/icons/default/default*.png` | upstream icons | our logo at 16/32/48/64/128 |
| `Browser/icons/updater.png` | upstream | our logo at 48 |
| `Browser/mullvadbrowser` shell wrapper | filename | renamed → `Browser/anonymous` |
| `Browser/mullvadbrowser.real` ELF | filename | renamed → `Browser/anonymous.real` |
| `Browser/start-mullvad-browser` | filename + strings | renamed → `start-anonymous` |
| `start-mullvad-browser.desktop` × 2 | filename + Name/Comment/Exec/StartupWMClass | renamed → `anonymous.desktop` |
| `Browser/MullvadBrowser/Docs/` | dir name | renamed → `Browser/Anonymous/Docs/` |

### What `rebrand.sh` does NOT touch

- **Engine ELF binary internals.** No binary patching. Tor/Firefox compiled-in strings stay; they're not in user-visible UI.
- **License / credits text** in `about:credits`, `about:license`, `Browser/Anonymous/Docs/Licenses/*`. MPL2 and Tor's license require attribution.
- **Internal code identifiers** (class names like `AboutMullvadBrowserParent`, chrome:// paths, ftl filenames). These aren't user-visible and renaming risks cross-file breakage.
- **The `about:mullvad-browser` URL slug**. The page content shows "Anonymous"; the slug is just an internal handle.

### Useful flags

| Flag | Purpose |
|---|---|
| `--version 15.0.14` | Pin a source version (default: 15.0.14) |
| `--node-version 20.20.1` | Pin a Node runtime version |
| `--offline <path>` | Skip the download, use a local tarball |
| `--skip-gpg` | Don't verify the upstream signature |
| `--output ./dist` | Override the output directory |
| `--keep-work` | Leave the staging dir for debugging |

`rebrand.sh` itself accepts `REBRAND_FORCE=1` to re-rebrand a tree
that's currently running (atomic mv keeps the running process safe;
the rebrand only becomes visible on next launch).

## How users install + run

```bash
tar -xJf anonymous-0.0.0-alpha-linux-x86_64.tar.xz
cd anonymous-0.0.0-alpha-linux-x86_64

# First-run config:
cp AnonLayer/config/anon-browser.conf.example AnonLayer/config/anon-browser.conf
$EDITOR AnonLayer/config/anon-browser.conf
#   Either set CONNECT="host:port"        (single-node testing)
#   Or    CONSENSUS=/path, DA_TRUST=/path, DESCRIPTOR=/path  (real rendezvous)

./anonymous
```

The launcher:

1. Sanity-checks Node + bridge + config.
2. Starts the bundled `anon-browse-gui` in `--no-token` mode on
   `127.0.0.1:1081`. (No-token is safe: loopback only, the launcher
   controls the whole process tree.)
3. Waits for `/api/health` to come up.
4. Calls `Browser/start-anonymous` to launch the engine.
5. On browser exit (or Ctrl-C / SIGTERM): kills the bridge.

The pre-installed WebExtension reads bridge URL from its defaults
(`http://127.0.0.1:1081`, no token) and handles `anon://` clicks
without any user configuration.

## Security posture (be honest)

| Property | State |
|---|---|
| Engine signed by upstream | ✓ (we don't touch the binaries) |
| Engine fingerprinting defenses intact | ✓ |
| Our wrapper signed | ✗ — v0.1 ships unsigned; users trust the tarball sha256 |
| Upstream policies.json preserved | ✗ — ours replaces it (intentional: we drop SOCKS) |
| Our user.js preserved across profile resets | ✓ — baked into `defaults/profile/` |
| Bridge reachable off-machine | ✗ — bound to 127.0.0.1; `--no-token` refuses non-loopback |
| Extension auto-installed | ✓ — via `distribution/extensions/` |
| Tarball reproducible | partial — `--owner=0 --group=0` but upstream mtimes leak through |
| Auto-update | ✗ — users re-download; document a rev cadence |
| Threat model | The bridge runs as the user. A compromised local process can read it. See `THREAT_MODEL.md`. |
| Clearnet anonymity | ✗ — v0.1 dropped the SOCKS proxy. Run `anon-socks` separately + point browser at `127.0.0.1:1080` for that. |

## When the upstream engine rev's

The upstream engine cuts a new release roughly every 4 weeks (tracking
Firefox ESR). Bump the version and rebuild:

```bash
browser-fork/scripts/repackage-mullvad.sh --version <new-version>
```

Re-test before publishing:

```bash
npm test                                  # 482 + 25 = 507 tests
bash bench/demo-anon-browse-gui.sh        # bridge JSON contract
```

If the upstream tarball layout changes (Browser/ paths, profile
defaults dir, etc.) the orchestrator refuses to build with a clear
error; update the path lookups in `repackage-mullvad.sh` /
`rebrand.sh`.

## What's missing for v1.0

- [ ] macOS .dmg + Windows .exe (need Mac/Windows runners; same script structure).
- [ ] Signing our launcher / installer (Apple Developer + Windows EV cert).
- [ ] Auto-update server + signed update manifest.
- [ ] AMO-sign the WebExtension `.xpi` so power users can pin/upgrade it independently.
- [ ] Replace the placeholder logo with a designer asset.
- [ ] Bundle `anon-socks` so clearnet also routes through the network.
- [ ] Verifiable build — pin tooling versions + record SLSA / repro provenance.

## Why repackage rather than fork

Building Gecko from source is 3-6 months of engineering and needs build
hardware we don't have. The upstream project already does that work,
hardens the result with the Tor Browser project's patches, and
publishes signed binaries every 4 weeks. By repackaging instead of
forking, we:

- Inherit upstream anti-fingerprinting maintenance.
- Inherit upstream CVE turnaround on Gecko bugs.
- Ship the first release in days, not quarters.
- Keep maintenance to "bump a version number and rebuild" instead of
  "rebase 80 patches against the latest ESR every cycle".

The tradeoff: legally, the engine is still a derivative. The About >
Credits page (and `Browser/Anonymous/Docs/Licenses/`) attributes the
upstream projects — these are MPL2 and project license requirements
we can't strip.
