# Browser Fork: Plan, Scaffolding, and Honest Accounting

| | |
|---|---|
| Document | Plan + scaffolding for a branded "Anon Browser" |
| Status | **Plan + scaffolding only. No binaries produced here.** |
| Time estimate | 3-6 months solo · 1-2 months with a 2-3 person team |
| Cost estimate | $400-$900/yr (signing certs + dev accounts) + hardware/CI |
| License | AGPL-3.0-or-later (must match Firefox/Mullvad upstream) |

---

## ⚠️ Before you read this

This document and the `browser-fork/` directory describe **what would
need to happen** to produce branded "Anon Browser" binaries for
Linux/Windows/macOS/Android. The actual production work involves
real-world infrastructure (signing certs, build hardware, distribution
hosting, security maintenance) that lives outside any single
contributor's machine and outside any chat conversation.

**Today, with zero fork work, you can already have a working,
hardened browser** — use Mullvad Browser (a Firefox fork already
hardened by the Mullvad team with Tor's anti-fingerprinting patches)
pointed at our SOCKS5 proxy. See
[`USING-MULLVAD-BROWSER.md`](./USING-MULLVAD-BROWSER.md) for the
5-minute setup.

The fork work in this document is for "we want a branded download
that says **Anon Browser**, not Mullvad."

---

## Table of contents

1. [What problem the fork solves](#1-what-problem-the-fork-solves)
2. [Why fork Mullvad Browser, not Chromium or Firefox directly](#2-why-fork-mullvad-browser-not-chromium-or-firefox-directly)
3. [Four-phase plan](#3-four-phase-plan)
4. [Per-platform notes](#4-per-platform-notes)
5. [Cost breakdown](#5-cost-breakdown)
6. [Distribution paths](#6-distribution-paths)
7. [Maintenance commitment](#7-maintenance-commitment)
8. [Risks and contingencies](#8-risks-and-contingencies)
9. [What lives in `browser-fork/` already](#9-what-lives-in-browser-fork-already)
10. [Decision points](#10-decision-points)

---

## 1. What problem the fork solves

The fork is about **product**, not **anonymity**.

The anonymity properties are delivered by:

1. **The v0.2 protocol** + the reference daemons (`anon-node-v2`,
   `anon-service`, `anon-socks`)
2. **Mullvad Browser's existing anti-fingerprinting** (inherited from
   Tor Browser's years of hardening work)

Pointing Mullvad Browser at `socks5://127.0.0.1:1080` (where
`anon-socks` listens) gives you those properties **today, with no fork
required.** This is documented in `USING-MULLVAD-BROWSER.md`.

What the fork adds, in order of effort:

| Feature | Effort | Why fork |
|---|---|---|
| Branding ("Anon Browser" not "Mullvad Browser") | 1 week | Identity / marketing |
| Bundled `anon-socks` daemon (no separate process) | 2-3 weeks | UX: install one thing, not two |
| Pre-configured SOCKS5 to our daemon | hours | UX: no settings dance |
| Native `anon://` URL handling | 1-2 months | UX: paste address, navigate |
| Built-in service-descriptor management | 2-3 weeks | UX: subscribe to a service like a bookmark |
| Distribution channels (own download page, auto-update) | 1-2 months | Reach |

None of these change the security/anonymity properties of the
underlying anon-layer network. They make the product more usable.

---

## 2. Why fork Mullvad Browser, not Chromium or Firefox directly

**Mullvad Browser** (https://mullvad.net/en/browser) is itself a fork
of Firefox + Tor Browser's anti-fingerprinting patches, **designed to
work with any SOCKS5 proxy.** Mullvad maintains it; Mozilla and the
Tor Project provide their respective upstreams. This is the closest
existing project to what we want.

| Base | Pros | Cons |
|---|---|---|
| **Mullvad Browser** | Already anti-fingerprint hardened. SOCKS5-ready. Mullvad maintains release engineering. Mozilla + Tor handle the upstream security work. | Need to track Mullvad's release cadence (typically 1-2 weeks after Firefox). Forking creates ongoing rebase work. |
| Firefox directly | Full control. | Lose the anti-fingerprinting work (huge — it's literally years of patches). Have to re-do everything Mullvad already did. |
| Chromium | Bigger codebase, faster engine. | Anti-fingerprinting work in Chromium is much weaker. Larger source tree. Mozilla's downstream-fork tooling is friendlier. Tor Browser explicitly chose Firefox over Chromium for this reason. |
| Brave / Ungoogled-Chromium | Pre-existing privacy work. | Different threat model (advertising / data brokers, not network-level anonymity). Doesn't include Tor Browser's anti-fingerprinting at the Web API level. |
| WebKitGTK / Servo | Lightweight. | Limited compatibility, slower to update, smaller community. Realistic-but-not-realistic for a daily-driver browser. |

**Mullvad Browser is the only realistic choice** for "we want a
hardened browser branded as ours." Document below assumes Mullvad
Browser as the base.

---

## 3. Four-phase plan

### Phase 1 — Mullvad Browser preference customization (no fork, 1 week)

**Deliverable:** A `policies.json` file users drop into their existing
Mullvad Browser installation. Effects:

- Pre-configures SOCKS5 to `127.0.0.1:1080`
- Adds `anon-layer-instructions.html` as the new-tab page
- Sets a custom homepage pointing at a local anon-layer-info page
- Disables prefs that interfere (DoH for SOCKS5 destinations, etc.)

This is **no-fork**. Users still have to install Mullvad Browser
themselves and drop in the file. **But it works today** and lets us
prove the integration before committing to fork work.

**Effort:** A few days of writing config + testing across platforms.
The browser-fork/patches/policies.json file in this directory is the
starting template.

### Phase 2 — Lightweight fork: brand override + bundled SOCKS daemon (3-4 weeks)

**Deliverable:** A Mullvad Browser fork with:

- Renamed binary (`anon-browser` instead of `mullvad-browser`)
- Anon Browser branding (logos, colors, about page) — placeholder
  files in `browser-fork/branding/` show the structure; real artwork
  must be commissioned or designed
- Bundled `bin/anon-node-v2.mjs` + `bin/anon-socks.mjs` Node process
  that auto-starts when the browser launches and dies when it
  closes. (Or alternative: distribute a pre-built `anon-socks` binary
  via [`pkg`](https://github.com/vercel/pkg) or [Bun's --compile](https://bun.sh/docs/bundler/executables))

**The bundled daemon question is the hardest part of Phase 2.** Options:

| Option | Pros | Cons |
|---|---|---|
| Bundle Node.js runtime + .mjs files | Works as-is | ~100 MB extra per platform |
| Use `pkg` to compile JS to single executable | ~50 MB | `pkg` is in maintenance mode |
| Rewrite `bin/anon-socks` core in Rust/Go | ~5 MB binary | Big effort; can't share code with reference impl |
| Ship the daemon as a separate side-car install | Smaller | UX worse — two installs |

For Phase 2 I'd recommend **`pkg` or [Bun --compile](https://bun.sh/docs/bundler/executables)**
as a starting point. Migrate to a native rewrite only if size or
performance forces it.

### Phase 3 — `anon://` URL handling (2-3 months)

**Deliverable:** Native handling of `anon://` URLs in the address bar.
User types `anon://...anon/`, browser fetches via the bundled daemon,
renders the text/anon response.

Two implementation paths:

**Path A: WebExtension**
- Faster to ship (~3-4 weeks)
- Uses the WebExtension `webRequest` + `protocol_handlers` APIs (the
  latter requires desktop-only and Firefox-specific support)
- Renders text/anon by injecting HTML/JS into a `data:` URL
- Tied to extension lifecycle (could be disabled by user)

**Path B: Browser-native via patches**
- Slower (~2 months)
- Patches Firefox C++ to register `anon://` as a built-in scheme
- Renders via a privileged about: page or similar
- Cleaner UX (no extension warning, no "you've installed this")
- More upstream-tracking maintenance (every Firefox release)

Recommend **Path A first**, migrate to Path B after one production
cycle.

The `browser-fork/extension/` directory has a skeleton for Path A.

### Phase 4 — Cross-platform builds + signing + distribution (3-6 months)

This is the long-tail engineering. The branched fork from Phases 2-3
must be:

1. **Built** on each platform (Linux .deb/.rpm/AppImage/Flatpak,
   macOS .dmg, Windows .exe installer, Android .apk)
2. **Signed** with the appropriate certificates
3. **Notarized** (macOS only; required for default-config Macs)
4. **Distributed** via a download page + auto-update mechanism
5. **Maintained** — Firefox security patches every 4 weeks; Mullvad's
   downstream every 1-2 weeks after; you rebase + rebuild + re-sign
   + re-distribute

The `browser-fork/.github/workflows/` directory has GitHub Actions
YAML for matrix builds. **The workflows are skeleton — they document
the path, but actually running them needs the secrets (signing keys,
notarization credentials) configured in your repository's Actions
settings.**

---

## 4. Per-platform notes

### Linux

- **Easiest platform.** No signing required (users trust the source).
- Build environment: a clean Ubuntu 22.04 LTS or Debian 12 VM with
  ~80 GB disk, 16 GB RAM, 8 cores recommended. Build takes ~2 hours.
- Packaging: AppImage (most universal), .deb (Debian/Ubuntu/Mint),
  .rpm (Fedora/RHEL/openSUSE), Flatpak (Flathub distribution), Snap
  (Canonical store). Pick 1-2 to start.
- Distribution: a CDN-backed download page works fine. Flathub /
  Snapcraft offer free hosting + auto-update for their respective
  package formats.
- **GitHub Actions** runners can build this in CI for free.

### Windows

- **Hardest platform after macOS.** Without a signing certificate
  Windows shows a SmartScreen warning on every download (red, scary).
- Build environment: Windows 11 with Visual Studio 2022 + Windows
  SDK. ~120 GB disk, 16 GB RAM. Build takes ~3 hours.
- **Code signing certificate required for SmartScreen pass.** EV
  ("Extended Validation") cert is ~$300-500/year (DigiCert, Sectigo,
  etc.). Requires a hardware USB token for signing. Standard cert is
  ~$100-200/year but accumulates SmartScreen reputation gradually
  (downloads are scary for the first weeks/months).
- Packaging: NSIS installer or MSI. Auto-update via the Mozilla
  update server protocol (which Mullvad inherits — basically free to
  reuse).
- Distribution: own download page or Microsoft Store ($19 one-time
  for an MS Store developer account, much smaller user reach for
  a hardened-anonymity tool).
- **GitHub Actions** Windows runners are free; signing infrastructure
  is the operator's responsibility (the EV cert hardware token
  doesn't work in cloud CI; the workaround is a self-hosted CI
  runner with the token plugged in, or a third-party signing service
  like SignPath or BurntSec).

### macOS

- **Most expensive platform.** Without a signed + notarized build,
  the binary literally won't run on a default-config Mac after
  Gatekeeper checks.
- Build environment: macOS hardware (or a paid macOS CI runner —
  GitHub's macOS runners are ~10× the price of Linux runners). ~100
  GB disk. Build takes ~2 hours.
- **Apple Developer Account required** ($99/year). Without it,
  signing is impossible.
- Signing + notarization: every binary must be signed with your
  Apple developer cert, then uploaded to Apple's notarization
  service (~15 minutes per build) which scans for malware and
  staples a ticket to the binary.
- Universal binary: Apple silicon (arm64) + Intel (x86_64) bundled
  into one Mach-O. Build both, lipo together.
- Packaging: .dmg with a drag-to-Applications template. Auto-update
  via Sparkle (the same framework Firefox uses).
- Distribution: own download page. Apple Mac App Store doesn't allow
  apps that connect to non-public networks (anon-layer would be
  rejected on review).

### Android

- **Different codebase from desktop.** Mozilla's mobile browser is
  built from a separate tree (formerly Fenix; current name varies).
- Build environment: Android SDK + Gradle + ~60 GB disk. Build takes
  ~30 minutes.
- **Google Play signing key required** (or F-Droid signing key,
  which is free). Google Play developer account is $25 one-time.
- Packaging: APK (universal) or AAB (Play Store split-APKs).
- **Google Play review** is a real bottleneck — Google reviewers may
  reject "an anonymizing proxy app" depending on policy
  interpretations. Plan to also publish on F-Droid (free, no review)
  for users blocked by Play.
- Distribution: Play Store, F-Droid, direct APK download.

---

## 5. Cost breakdown

| Item | One-time | Recurring |
|---|---|---|
| Domain name (e.g. anon-browser.org) | — | $12-20/year |
| Apple Developer Program | — | $99/year |
| Windows EV code signing cert | — | $300-500/year |
| EV cert hardware USB token (one-time purchase) | $50-100 | — |
| Google Play Developer account | $25 | — |
| F-Droid publishing | $0 | $0 |
| GitHub (Public repos free; private $4/user/month) | — | $0-50/year |
| GitHub Actions for CI (free tier covers small projects; macOS minutes are 10× the cost) | — | $0-100/year |
| Hosting (CDN for downloads — Cloudflare R2, B2, GitHub Releases) | — | $0-50/year |
| Code review time, security maintenance, support — your time | huge | huge |
| **Year-1 total minimum (excl. labour)** | **~$200** | **~$500-700** |

Plus the much bigger cost: **your time, or hired engineers' time, to
do the work.** A realistic effort estimate:

- **Solo, part-time:** 6-12 months
- **Solo, full-time:** 3-6 months
- **Team of 2-3 full-time:** 1-3 months

These estimates assume **no major upstream-tracking emergencies** —
those happen (Firefox security patch out of cycle, build breaks on
some platform), expect a 20-30% slack budget.

---

## 6. Distribution paths

| Channel | Pros | Cons | Cost |
|---|---|---|---|
| Own download page (DIY hosting) | Full control, no review | You handle hosting, bandwidth, malware-shaming protection | Domain + CDN |
| GitHub Releases | Free hosting, signed checksums easy | Fewer downloads (people don't think to look there for "browser") | Free |
| Flathub (Linux Flatpak) | Auto-update, decent reach in Linux community | Single review per release | Free |
| Snapcraft (Linux Snap) | Canonical-controlled, auto-update | Canonical sometimes confuses people; Snap is controversial in Linux community | Free |
| Microsoft Store | Auto-update on Windows | $19, small audience for anonymity tools | $19 one-time |
| Mac App Store | Auto-update on macOS | Apple won't allow anon-network connections; **don't bother** | $99/year (you already need this for signing) |
| Google Play | Auto-update on Android, big reach | Review risk for anonymity apps | $25 one-time |
| F-Droid | Free, no review, anonymity-friendly audience | Smaller reach than Play | Free |

**Recommended starting distribution:** Own download page + GitHub
Releases + F-Droid for Android. Add Flathub once the build is stable.
Add Microsoft Store + Google Play later if reach matters.

---

## 7. Maintenance commitment

Firefox ships **every 4 weeks**. Mullvad Browser typically ships 1-2
weeks after each Firefox release. **You must rebase your fork onto
each new Mullvad Browser release** within ~2 weeks of it shipping, or
your users accumulate known CVEs.

| Cadence | Work involved |
|---|---|
| Every 4 weeks (Firefox release) | Wait for Mullvad's downstream patch set, then rebase your branding + extension + daemon-integration patches onto it. |
| Every 4 weeks (your re-release) | Build all 4 platforms, sign, notarize (macOS), upload to download channels, push auto-update server. |
| Occasionally (security patches) | Out-of-band Firefox security releases may force an emergency rebase + rebuild. Plan for ~3-5 of these per year. |
| Yearly | Certificate renewals (Apple, Windows EV cert, domain), policy reviews. |

**This is a real ongoing commitment.** The Tor Browser team has 3-5
full-time engineers and gets help from both Mozilla and the Tor
Project. A serious branded fork at minimum needs **one part-time
engineer indefinitely**, more like one full-time during release weeks.

If that commitment isn't sustainable, **don't fork**. Recommend
[`USING-MULLVAD-BROWSER.md`](./USING-MULLVAD-BROWSER.md) as the
official "how to use anon-layer with a real browser" instead.
Mullvad's team handles the maintenance.

---

## 8. Risks and contingencies

### Mullvad Browser is discontinued

Low probability (the project has Mozilla + Mullvad both invested),
but possible. If it happens, the fork moves directly to Firefox +
Tor Browser anti-fingerprinting patches (more work; the Tor Project
has historically been willing to accept downstream forks).

### Google Play rejects "anonymizing proxy" apps

Likely. Plan for F-Droid as primary distribution; treat Play Store as
opportunistic.

### Apple rejects signed builds for App Store review

Mac App Store: yes, will reject. Direct download with notarization
still works (the Mac App Store is a separate distribution channel
from notarized direct downloads).

### Windows SmartScreen damages reputation early

Yes. EV cert mitigates from day one; standard cert improves
gradually as downloads accumulate without malware reports. Plan for a
"download warnings will happen for the first few weeks" disclaimer.

### Firefox makes a major change that breaks our fork

Has happened (e.g., Manifest V3 transition, layout engine changes).
Budget 4-6 weeks of recovery work per major Firefox version
transition; these are ~1/year.

### Volunteer fork-maintainers burn out

This is the most common cause of forks dying. Plan for at minimum a
small paid maintenance budget OR a contributor pool of 3+
maintainers OR an explicit deprecation path that points users back
to upstream Mullvad if the fork can't keep up.

---

## 9. What lives in `browser-fork/` already

This conversation produced the scaffolding. You execute the actual
fork work.

```
browser-fork/
├── patches/
│   ├── policies.json              ← Mullvad Browser distribution policy (no-fork solution from Phase 1)
│   └── user.js                    ← Mullvad user.js overrides
├── branding/
│   ├── README.md                  ← What to commission / produce
│   ├── manifest.json              ← Application manifest skeleton
│   └── strings.dtd                ← Localizable strings (English placeholder)
├── extension/
│   ├── README.md                  ← Phase-3 WebExtension scaffolding
│   ├── manifest.json              ← Extension manifest (Manifest V3)
│   ├── background.js              ← protocol_handlers + webRequest skeleton
│   └── render.js                  ← text/anon → HTML renderer (browser-side)
├── scripts/
│   ├── README.md                  ← How to use the scripts
│   ├── fetch-source.sh            ← Clone Mullvad Browser source
│   ├── apply-patches.sh           ← Apply our patches + branding
│   ├── build-linux.sh             ← Linux build (most complete)
│   ├── build-macos.sh             ← macOS build (documented, untested)
│   ├── build-windows.sh           ← Windows build (documented, untested)
│   └── build-android.sh           ← Android build (documented, untested)
└── .github/workflows/
    └── build-and-release.yml      ← GitHub Actions: matrix build for all 4 platforms
```

**Tested:** none. The scripts are documentation as much as automation;
they specify what to run and in what order. Running them needs a
real build environment with the right toolchains.

---

## 10. Decision points

Before committing to the fork:

1. **Do you have the maintenance commitment?** A part-time engineer
   for at least 18 months minimum. Or a 3-person volunteer rotation.
2. **Do you have the budget?** ~$500/year recurring + your time.
3. **What's the audience?** A branded fork makes sense if you have
   ≥1,000 users who specifically want anon-layer-branded UX over
   "Mullvad Browser + SOCKS config." For smaller audiences, just
   distribute the config.
4. **Is the protocol stable enough?** v0.2 is pre-audit. Wait until
   it's audited and v1.0 before committing fork engineering work?
   Likely yes — every protocol change breaks browser features that
   depend on it.

**If any of these is uncertain, start with `USING-MULLVAD-BROWSER.md`.**
The unfork approach delivers the same anonymity guarantees with zero
maintenance burden. The fork is product polish on top.

---

## Document status

This is a plan + scaffolding, **not a delivered fork**. To actually
ship branded binaries, follow Phases 1-4 above. Realistic timeline:
3-6 months solo, less with a team. Real costs apply. You'll need:

- Build hardware or paid CI for each platform
- An Apple Developer account ($99/year)
- A Windows EV signing certificate ($300-500/year)
- A Google Play developer account ($25 one-time)
- Hosting for downloads
- Ongoing engineering capacity to track Firefox security releases

The reference protocol implementation (this repo's `bin/`,
`modules/`, `docs/SPEC-v0.2-draft.md`) does not depend on the fork.
The fork is one possible UX wrapper around the protocol; another is
"use Mullvad Browser directly with `anon-socks`" which works today.
