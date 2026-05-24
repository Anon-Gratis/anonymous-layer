# `browser-fork/` — Anon Browser fork + WebExtension

Status: the **WebExtension is shippable** (functional MVP, packages
into a loadable `.xpi`, smoke tests green). The full **Firefox fork**
is still scaffolding; producing branded binaries needs build hardware
and signing certs we don't have here. See
[`../docs/BROWSER-FORK.md`](../docs/BROWSER-FORK.md) for the
multi-month plan and
[`../docs/USING-MULLVAD-BROWSER.md`](../docs/USING-MULLVAD-BROWSER.md)
for the no-fork path that works today (Mullvad Browser + this
extension).

## What's in here

```
patches/             Mullvad Browser pref overrides (works on existing installs)
  ├── policies.json    Enterprise-distribution policy: SOCKS5 + privacy hardening
  └── user.js          Per-profile pref tweaks

branding/            Skeleton for branding overrides applied to the fork
  ├── locales/en-US/   brand.ftl + brand.properties (drop into Firefox tree)
  ├── strings.dtd      legacy DTD strings
  ├── manifest.json    application metadata (reference, not loaded at runtime)
  └── README.md        what artwork you still need to commission

extension/           WebExtension for anon:// rendering (FUNCTIONAL MVP)
  ├── manifest.json    Manifest V3
  ├── background.js    Omnibox + context-menu + message routing
  ├── content/intercept.js   Click-intercept for in-page anon:// links
  ├── popup.html/.js   Toolbar popup
  ├── options.html/.js Bridge URL / token settings
  ├── render.html/.js  In-tab anon:// renderer
  ├── lib/render-doc.mjs  Shared pure renderer (also used by tests)
  ├── icons/           Placeholder icons + generator
  ├── build-xpi.sh     Packager → dist/anon-layer-<version>.xpi
  ├── validate.mjs     Manifest ↔ filesystem sanity check
  ├── tests-extension.mjs  25 smoke tests (parse → render contract)
  └── README.md        Full install + AMO submission instructions

scripts/             Per-platform build automation
  ├── fetch-source.sh   clone Mullvad Browser source
  ├── apply-patches.sh  apply our patches to a checked-out source tree
  ├── build-linux.sh    Linux build (most validated)
  ├── build-macos.sh    macOS build (documented, needs Mac runner to validate)
  ├── build-windows.sh  Windows build (documented, needs Win runner to validate)
  ├── build-android.sh  Android (NOT yet — Fenix fork is a separate project)
  └── README.md         prerequisites + signing-cert notes

.github/workflows/
  └── build-and-release.yml   Matrix build for Linux/macOS/Windows + draft Release
```

## Current validation state

Each row records what was tested against real upstream source and
what was learned.

| Component | Validated against | Result |
|---|---|---|
| `extension/build-xpi.sh` | Local build → `dist/anon-layer-0.1.0.xpi` | ✓ produces 18 KB .xpi with 14 files |
| `extension/validate.mjs` | manifest.json ↔ filesystem | ✓ 0 errors, 0 warnings on the produced .xpi |
| `extension/tests-extension.mjs` | text_anon.mjs → renderer JSON contract | ✓ 25 / 25 passing (includes XSS escape suite) |
| `anon-browse-gui.mjs` CORS + `/api/health` | end-to-end curl: GET/OPTIONS, valid + invalid token | ✓ 200 with token, 403 without, 204 on preflight, all with CORS headers |
| `fetch-source.sh` | `gitlab.torproject.org/tpo/applications/mullvad-browser` (when up; fallback `github.com/mozilla/gecko-dev`) | ✓ clone reaches the repo; 5.3 GB full / 268 MB sparse |
| `apply-patches.sh` — branding copy | gecko-dev HEAD (Firefox upstream) | ✓ copies `unofficial/` (62 files) as base, overlays brand.ftl + brand.properties + configure.sh |
| `apply-patches.sh` — `MOZ_APP_VENDOR` | Mozilla build system rejects free-form vendor strings in `configure.sh` | ✓ FIXED — scaffolding now only sets `MOZ_APP_DISPLAYNAME` (matches Mullvad's pattern) |
| `apply-patches.sh` — policies.json | Drops into `browser/app/distribution/` correctly | ✓ verified file lands |
| `apply-patches.sh` — mozconfig appending | Idempotent (safe to re-run) | ✓ verified |
| `./mach configure` with our patches | Runs to compiler-check stage | ✓ all gcc/g++/STL/TLS/assembler checks pass |
| `./mach configure` further | Hits `llvm-objdump not found` | ✗ requires sudo apt install llvm — blocked in sandbox |
| `./mach build` end-to-end | NOT YET VALIDATED | □ needs a sudo-capable Linux machine |
| `build-macos.sh` | NOT YET VALIDATED | □ needs a Mac runner |
| `build-windows.sh` | NOT YET VALIDATED | □ needs a Windows runner |
| `build-android.sh` | Intentionally aborts with explanation | ✓ explicit "not yet, see Fenix fork plan" |
| `.github/workflows/build-and-release.yml` | Syntax-valid; references correct secret names | ✓ valid; not yet run against real secrets |

## Known scaffolding gaps (still TODO)

| Gap | Impact | Effort |
|---|---|---|
| Real branding artwork (icons, logos, colors) | Build produces generic-Firefox-looking binary; extension uses placeholder icons | $500-2000 to commission, or DIY |
| Bundled `anon-socks` daemon in the fork | User has to start `anon-socks` separately | 2-3 weeks engineering |
| ~~Native `anon://` URL handler~~ | DONE via WebExtension (`extension/`) for desktop Firefox/Mullvad Browser. A real fork can promote it to native address-bar support. | already shipped (this dir) |
| Apple Developer cert acquisition | macOS binaries won't run without Gatekeeper warnings | $99/year + ~7 day approval |
| Windows EV signing cert | Windows users see SmartScreen warnings | $300-500/year + 1-2 week verification |
| Android Fenix fork | Android version doesn't exist | 3-6 months as separate project |
| Update server infrastructure | No auto-updates | 1-2 weeks setup |
| Download/landing page | No way for users to discover binaries | 1-2 weeks |
| AMO signing of the WebExtension `.xpi` | Otherwise only "Load Temporary Add-on" works | a few days, free |
| Maintenance cadence (every 4 weeks tracking Firefox) | Fork goes stale quickly | ongoing |

## How to actually build

**The WebExtension (works today, no special hardware):**

```bash
cd browser-fork/extension
./build-xpi.sh --validate
# → dist/anon-layer-<version>.xpi

# Install: about:debugging → This Firefox → Load Temporary Add-on…
# See extension/README.md for full setup + AMO signing.
```

**The full Firefox fork (multi-month, requires real hardware):**

```bash
# On a sudo-capable Ubuntu 22.04 machine, in a clone of this repo:
cd browser-fork
scripts/fetch-source.sh                  # 4 min, 5.3 GB
scripts/apply-patches.sh                 # < 1 min
scripts/build-linux.sh                   # 2 hours, ~10 GB additional
# → ./build/linux/dist/anon-browser-*.tar.bz2
```

The `build-linux.sh` script will check prerequisites first and tell
you exactly what to `sudo apt install` if anything's missing.

For the GitHub Actions path (no local hardware needed): push this
repo to GitHub, configure the secrets in
`scripts/README.md`, tag a release. CI does the rest.

## Why scaffolding-only?

Producing actual shippable binaries needs three things we can't
provide here:

1. **Build hardware** — real Linux/macOS/Windows machines (or paid CI
   minutes)
2. **Signing certificates** — Apple Developer ($99/yr), Windows EV
   (~$400/yr), Android signing key
3. **Distribution** — domain, CDN, auto-update server

The protocol implementation in this repo (the `bin/`, `modules/`,
`docs/SPEC-v0.2-draft.md`) doesn't depend on the fork. Users today
can browse the v0.2 network with `bin/anon-browse.mjs`,
`bin/anon-browse-gui.mjs`, or Mullvad Browser pointed at
`bin/anon-socks.mjs` (see `../docs/USING-MULLVAD-BROWSER.md`).

The fork is product polish: branded download, one-click install, no
separate daemon to launch. It's worth the multi-month effort if you
have users who specifically want "Anon Browser" the brand. Otherwise,
the no-fork path is what to ship.
