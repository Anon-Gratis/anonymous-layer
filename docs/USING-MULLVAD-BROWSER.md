# Using Mullvad Browser with anon-layer

| | |
|---|---|
| Goal | Browse anon-layer hidden services through Mullvad Browser today |
| Effort | ~5 minutes after Mullvad Browser is installed |
| Result | A hardened, anti-fingerprint-protected browser routing through anon-layer |

This document is the **no-fork path** to a usable browser experience
on the anon-layer network. No custom binaries, no compilation, no
months of work. You install Mullvad Browser the normal way, drop one
config file in, point it at our SOCKS5 proxy, and you're browsing.

If you eventually want a branded "Anon Browser" download with our own
icon and name, see [`BROWSER-FORK.md`](./BROWSER-FORK.md). That's a
multi-month engineering project.

---

## What you get with Mullvad Browser + anon-socks

| Property | Source |
|---|---|
| Anti-fingerprint hardening (canvas, WebGL, fonts, timezone, language, system version, …) | Mullvad Browser (inherits Tor Browser's work) |
| No telemetry, no Mozilla account, no Google services | Mullvad Browser |
| Built-in HTTPS-only mode, no third-party cookies, NoScript options | Mullvad Browser |
| Network anonymity via 3-hop hybrid PQ circuits | anon-socks → anon-layer |
| Hidden-service rendezvous for `.anon` sites | anon-socks → anon-layer |
| Stable upstream maintenance | Mullvad team + Mozilla + Tor Project |

**This stack gets you 95% of what a forked "Anon Browser" would do.**
The 5% gap is branding and one-click integration. For most users,
that gap doesn't matter.

---

## Setup

### 1. Install Mullvad Browser

Download from https://mullvad.net/en/browser. Available for Linux,
macOS, and Windows. Signed and notarized; no SmartScreen / Gatekeeper
warnings.

Android: Mullvad doesn't ship an Android browser. On Android, use
Tor Browser (also Firefox-based, also anti-fingerprint-hardened) with
the same SOCKS5 configuration.

### 2. Run anon-socks

In a terminal, start the anon-layer SOCKS5 proxy:

```bash
node bin/anon-socks.mjs \
    --tunnel anon-layer \
    --port 1080 \
    --data-dir ~/.anon-node-v2 \
    --consensus /path/to/consensus.bin \
    --da-trust /path/to/da-trust.json \
    --i-understand-this-is-experimental
```

You should see:

```
[…] anon-layer identity loaded: cc8fa87d28fb0500…
[…] consensus loaded: 6 relays
[…] socks5 listener on 127.0.0.1:1080, tunnel=anon-layer
```

Leave this running. As long as it's listening, Mullvad Browser can
route through it.

### 3. Configure Mullvad Browser

Mullvad Browser uses Firefox's network settings.

**Option A: Settings UI (interactive)**

1. Open Mullvad Browser
2. Three-line menu → `Settings`
3. Scroll to `Network Settings` → `Settings…`
4. Choose `Manual proxy configuration`
5. Set:
   - **SOCKS Host:** `127.0.0.1`
   - **Port:** `1080`
   - **SOCKS v5**: selected
   - **Proxy DNS when using SOCKS v5**: ⚠ see § 4 below
6. Click `OK`

**Option B: policies.json (scripted / for distribution)**

For deploying to many machines, drop
[`browser-fork/patches/policies.json`](../browser-fork/patches/policies.json)
into your Mullvad Browser's `distribution/` subdirectory. On most
systems that's:

- Linux: `~/.mullvad/firefox/distribution/policies.json` (path varies
  by install method)
- macOS: `/Applications/Mullvad Browser.app/Contents/Resources/distribution/policies.json`
- Windows: `C:\Program Files\Mullvad Browser\Browser\distribution\policies.json`

The file pre-configures the SOCKS5 proxy + disables system telemetry.

### 4. About the SOCKS-DNS option

When you enable "Proxy DNS when using SOCKS v5", Mullvad Browser
sends DNS lookups through the SOCKS5 proxy instead of using your OS
resolver. Whether to enable this depends on what you're browsing:

- **For `.anon` hidden services** (no DNS needed; the address IS the
  destination): doesn't matter, no DNS happens anyway.

- **For clearnet sites via the v0.2 exit** (Reddit, Wikipedia,
  etc.): **anon-layer's reference exit doesn't yet resolve DNS at
  the exit side.** If you enable proxy-DNS, the SOCKS5 client sends
  a DNS query through the tunnel; anon-socks tries to resolve it
  client-side (leaking to your local resolver) before forwarding the
  TCP connection.

  - **Best practice today:** disable proxy-DNS in Mullvad Browser's
    settings AND only browse to IP-literal destinations or `.anon`
    addresses. This keeps DNS off the wire entirely.

  - **Real production fix:** exit-side DNS resolution (currently a
    future-work item in the protocol spec).

  - **Acceptable middle:** enable proxy-DNS knowing that hostname
    lookups for clearnet destinations leak via your local resolver.
    Many users do this with Tor Browser anyway.

### 5. Test it

In Mullvad Browser, navigate to a non-secret IP literal:

```
http://1.1.1.1
```

If the page loads (or returns a Cloudflare error from Cloudflare's
end), the SOCKS5 path is working.

For an anon-layer hidden service, use the service's `.anon` address:

```
anon://leh4rb3icbxwruu7itv3t4pnpsef35piydbjcxkrkpfdupiyoxu6elyc.anon/
```

Mullvad Browser doesn't natively handle `anon://` URLs (that's what
the fork or extension in Phase 3 of `BROWSER-FORK.md` would add).
**As a workaround**, use the `anon-browse-gui` binary in this
repository alongside Mullvad Browser:

```bash
node bin/anon-browse-gui.mjs \
    --consensus /path/to/consensus.bin \
    --da-trust /path/to/da-trust.json \
    --descriptor /path/to/some-service.descriptor.bin
```

This prints a URL. Open it in **any browser** (Mullvad Browser
works) — that's the GUI for `.anon` browsing.

---

## Troubleshooting

### `Mullvad Browser shows a proxy error`

- Make sure `anon-socks` is running on `127.0.0.1:1080`
- Check the SOCKS5 settings: host = `127.0.0.1`, port = `1080`,
  protocol = SOCKS v5

### `Pages load but show "Connection failed" frequently`

- Mullvad Browser's HTTPS-only mode is incompatible with non-HTTPS
  destinations. Either:
  - Visit `https://` versions of clearnet sites
  - Disable HTTPS-only mode (Settings → Privacy & Security → HTTPS-Only Mode → Off)
- For `.anon` services, this shouldn't happen since `anon://` URLs
  aren't intercepted by HTTPS-only mode (they aren't recognised by
  Mullvad Browser at all). Use the GUI workaround above.

### `Browser asks "always trust this certificate?" for HTTPS sites`

- The anon-layer SOCKS5 path tunnels TCP transparently. SSL/TLS
  certificate handling is the destination server's responsibility,
  not anon-layer's. Trust the cert as normal.

### `WebRTC IP leak`

- Mullvad Browser disables WebRTC by default to prevent this. Don't
  re-enable it.

### `Pages load very slowly`

- A 3-hop hybrid PQ circuit has higher latency than a regular HTTPS
  connection. Expect ~300-800 ms per page in a healthy testnet,
  potentially higher across continents.

### `Specific site doesn't work`

- Sites that detect Tor exit IPs may also block anon-layer exit IPs
  (especially if your testnet's exits are well-known cloud
  addresses). This isn't an anon-layer bug; it's the destination
  site's choice.

---

## What this setup does NOT solve

- **Branding**: it's Mullvad Browser, not "Anon Browser." If you
  need the branded version, see `BROWSER-FORK.md` for the
  3-6-month engineering plan.

- **Native `anon://` URL handling**: Mullvad Browser doesn't know
  what `anon://` means; you use `anon-browse-gui` for that today.
  A WebExtension is the planned Phase 3 fix.

- **One-click install**: today, the user has to start `anon-socks`
  themselves before opening the browser. A bundled-daemon Phase 2
  fork would auto-start it.

- **Auto-update of `anon-socks`**: today, you `git pull` the
  reference repo and re-run. A packaged-binary distribution is
  Phase 4 work.

None of these gaps weaken the **anonymity** properties — those are
all delivered by the protocol + Mullvad Browser's hardening. The
gaps are UX polish.

---

## Recommendation

**Most users:** use this guide. Mullvad Browser + `anon-socks` is a
hardened browser routed through anon-layer, set up in 5 minutes,
maintained by the Mullvad team.

**Project leaders considering a fork:** read
[`BROWSER-FORK.md`](./BROWSER-FORK.md) for the realistic accounting
of what a branded fork costs and demands. Don't fork unless you have
the maintenance commitment.

**Operators distributing to non-technical users:** ship the
`policies.json` from `browser-fork/patches/` alongside instructions
to download Mullvad Browser. Users get a one-config-file integration
that points the browser at your network's `anon-socks` instance.
