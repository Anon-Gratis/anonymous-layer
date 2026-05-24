# Running an Anonymous-Layer Node

| | |
|---|---|
| Document | Operator's guide to the v0.2 reference implementation |
| Status | **PRE-AUDIT EXPERIMENTAL** |
| Audience | Technically-comfortable readers running their first node or service |
| License | AGPL-3.0-or-later |

---

## ⚠️ Read this first

The protocol spec (`docs/SPEC-v0.2-draft.md`) has explicit open questions
that have not been reviewed by an independent cryptographer. The code in
this repository has not been audited.

**Do not run this against any threat model where a real human would be
harmed if it leaked.** For anonymity needs today, use [Tor](https://torproject.org).

What this is good for:

- **Protocol development.** The reference implementation is small and
  auditable; a useful base for proposing changes.
- **Conformance testing.** Independent implementations in other languages
  can target the same wire format.
- **Closed testnets.** Among consenting operators who understand the
  caveats.
- **Education.** The spec + code together is a hands-on tour of how
  Tor-style onion routing works under the hood, simplified.

---

## Table of contents

1. [What's in the box](#1-whats-in-the-box)
2. [Prerequisites](#2-prerequisites)
3. [Quick start: a 5-minute relay](#3-quick-start-a-5-minute-relay)
4. [Running a relay in detail](#4-running-a-relay-in-detail)
5. [Running a hidden service](#5-running-a-hidden-service)
6. [Browsing hidden services](#6-browsing-hidden-services)
7. [Using anon-layer as a SOCKS5 proxy](#7-using-anon-layer-as-a-socks5-proxy)
8. [Building a testnet](#8-building-a-testnet)
9. [Operational notes](#9-operational-notes)
10. [Troubleshooting](#10-troubleshooting)
11. [Honest gaps and known limitations](#11-honest-gaps-and-known-limitations)
12. [Where to look next](#12-where-to-look-next)

---

## 1. What's in the box

| Binary | Purpose |
|---|---|
| `bin/anon-node-v2.mjs` | Relay daemon. Accepts incoming v0.2 link connections, forwards circuits, optionally acts as exit. Every relay also automatically serves the RP and IP roles. |
| `bin/anon-service.mjs` | Hidden-service daemon. Publishes via an IP, awaits introductions, bridges spliced streams to a local TCP destination. |
| `bin/anon-socks.mjs` | SOCKS5 proxy. With `--tunnel anon-layer`, routes browser/curl traffic through a 3-hop circuit. With `--tunnel direct`, transparent TCP (no anonymity). |
| `bin/anon-site-server.mjs` | Static-file server for the anon-site protocol. Used as the local backend behind a hidden service. |
| `bin/anon-site-client.mjs` | One-shot CLI fetcher for anon-site URLs. |
| `bin/anon-browse.mjs` | TUI browser. Renders `text/anon`, follows links, navigates history. |

For each binary, run with no arguments or `--help` for inline docs.

There are also v0.1 binaries (`bin/anon-node.mjs`, `bin/anon-chat.mjs`) from
an earlier protocol version. They share no wire format with v0.2 and are
kept around as a stepping stone, not for production use.

---

## 2. Prerequisites

- **Node.js ≥ 20.** (Tested on 22 and 24.) The codebase uses ESM, top-level
  await, `node:net` half-open sockets, and `Server.closeAllConnections`
  (Node ≥ 18.2).
- **Disk:** trivial. Identity files are 64 to 3680 bytes; logs are
  operator-bounded.
- **Network:** one TCP port per running daemon. Defaults: relay on 9001,
  SOCKS5 on 1080, anon-site server on 1965 (matches the Gemini default).
- **No special permissions required** — no root, no kernel modules, no
  `setcap`. Everything runs unprivileged on Linux, macOS, or Windows.

### Install

```bash
git clone <repo>
cd anonymous-layer
npm install         # installs @noble/{curves,hashes,post-quantum} and ws
npm test            # 477 passing in ~50 s on a 2024-era laptop
```

If tests don't pass on first run, **stop here** and figure out why. The
codebase is meant to be a working artefact end-to-end. A failing test on
fresh install indicates a Node-version or dependency-version mismatch and
running daemons would just hide the underlying bug.

---

## 3. Quick start: a 5-minute relay

```bash
# Generate a fresh identity.
node bin/anon-node-v2.mjs init

# See what you generated.
node bin/anon-node-v2.mjs info
# data-dir:    /home/.../.anon-node-v2
# fingerprint: cc8fa87d28fb0500ad2f16a5aeab2f41006ee32988fd09e6209e08df5da3be6e
# idPk:        45251615b1f6c9e3...
# B_pk:        a2630570125d3c5e...

# Run the daemon. (Requires the experimental ack flag.)
node bin/anon-node-v2.mjs run --i-understand-this-is-experimental
```

What you should see on stderr:

```
================================================================
            ANONYMOUS LAYER v0.2 — PRE-AUDIT BUILD
================================================================
...
[2026-05-21T...] fingerprint: cc8fa87d28fb0500...
[2026-05-21T...] exit-policy: reject (no exit)
[2026-05-21T...] no --consensus supplied; RELAY_EXTEND will be rejected (1-hop only)
[2026-05-21T...] listening on ws://127.0.0.1:9001
```

At this point your relay is listening but isn't useful — it has no
consensus, so it can't dispatch `RELAY_EXTEND`, and clients can't reach it
without your `idPk`. To do something meaningful you need either:

- **Build a testnet** (you control all the relays + consensus). See
  [§ 8](#8-building-a-testnet).
- **Join a real network** (someone else operates the directory and you
  add your relay to their consensus). v0.2 has no public network yet;
  see [§ 11](#11-honest-gaps-and-known-limitations).

To stop: `Ctrl-C` (`SIGINT`).

---

## 4. Running a relay in detail

### 4.1. Identity and persistence

`anon-node-v2 init` writes `$DATA_DIR/identity.key`, a 64-byte file
containing your relay's Ed25519 secret + X25519 onion secret.

- **File mode is enforced 0600.** `loadIdentity` refuses to read a file with
  any group/other bits set on Unix. If you `chmod 644` your identity key by
  accident, the daemon won't start; this is intentional.
- **Default data-dir is `~/.anon-node-v2`** (override with `--data-dir DIR`
  or set `ANON_NODE_V2_HOME` in the environment).
- The fingerprint (`Blake2b-256(idPk)`) is your relay's identity on the
  network. Once it's in a consensus, do not lose the file — generating a
  new identity makes your relay unreachable until the next consensus
  refresh.

### 4.2. Consensus and DA-trust files

Without `--consensus`, the relay is one-hop-only: it can terminate a
client's CREATE but can't extend. For full multi-hop support, pass both
`--consensus PATH` and `--da-trust PATH`:

```bash
node bin/anon-node-v2.mjs run --i-understand-this-is-experimental \
    --consensus /etc/anon/consensus.bin \
    --da-trust /etc/anon/da-trust.json
```

The consensus file is the binary output of `buildConsensus`
(`modules/v2/consensus.mjs`). The DA trust file is a JSON object mapping
`{fingerprint_hex: idPk_hex}` for each directory authority you trust.

A public consensus needs to come from somewhere. Either you produce it
yourself (testnet — § 8) or you fetch it from someone running a DA
(public network — not yet deployed for v0.2).

### 4.3. Exit policy

By default, your relay does NOT act as an exit. To opt in:

```bash
# Allow common ports (HTTPS, HTTP, DNS).
--exit-policy reduced

# Allow a Tor-style broad set of ports.
--exit-policy standard

# Load a custom policy file (output of `buildPolicy()`).
--exit-policy file:/etc/anon/my-policy.bin
```

Acting as an exit means **your IP appears as the source of all traffic
for circuits ending at your relay.** This has legal and operational
implications. Don't enable it without understanding what that means for
your jurisdiction and ISP.

The RP (rendezvous point) and IP (introduction point) roles are always on
for every relay. They impose no exit-policy concerns — they only route
protocol cells, never make outbound connections to arbitrary destinations.

### 4.4. Listening address

Default is `127.0.0.1:9001` for safety. To accept connections from other
hosts:

```bash
--host 0.0.0.0 --port 9001
```

The reference implementation uses plain `ws://`. For real deployments
you should terminate `wss://` at a reverse proxy (Caddy, nginx) or
add native TLS support (see [§ 11](#11-honest-gaps-and-known-limitations)).

---

## 5. Running a hidden service

A hidden service has three pieces:

- **A long-running service daemon** (`anon-service publish`) that connects
  to an introduction point relay and waits for clients to introduce
  themselves through the rendezvous protocol.
- **A local backend** (e.g. `anon-site-server`) that the service forwards
  rendezvous-stream traffic to.
- **A descriptor file** that clients use to reach you.

### 5.1. Pick an introduction point

You need the fingerprint of a relay in the consensus to use as your IP.
Any RUNNING+VALID relay works. The IP forwards introductions to you; it
doesn't see your traffic content (which is encrypted to your per-IP enc
keys before reaching it).

For better resistance to IP-correlation attacks, pick an IP geographically
distant from your service and don't reuse the same one indefinitely. (v0.2
reference supports one IP at a time; multi-IP rotation is future work.)

### 5.2. Generate identity + descriptor

```bash
node bin/anon-service.mjs init \
    --data-dir ~/.anon-service \
    --ip-fingerprint <64-hex-chars-of-chosen-relay> \
    --consensus /etc/anon/consensus.bin \
    --da-trust /etc/anon/da-trust.json
```

You get:

```
generated service identity → ~/.anon-service/identity.bin
wrote descriptor (1422 bytes, 3600s lifetime) → ~/.anon-service/descriptor.bin
onion address: leh4rb3icbxwruu7itv3t4pnpsef35piydbjcxkrkpfdupiyoxu6elyc.anon
IP fingerprint: a5a86f22d19c48c7...
```

The onion address comes from `base32(SVC_pk || checksum || version)
+ ".anon"` per spec § 4.4. It's how clients name your service.

The descriptor lives at `$DATA_DIR/descriptor.bin`. You distribute this
file to clients out of band (v0.2 has no HSDir yet — see § 11). Treat it
like a public URL — it's not secret, but clients need it to reach you.

`identity.bin` IS secret. It contains all four service secrets
(SVC_sk + serviceIntroSk + serviceEncX25519Sk + serviceEncMlkemSk). Mode
is enforced 0600.

### 5.3. Run a local backend

Anything that speaks raw TCP. The reference impl ships an anon-site
server for serving static files:

```bash
mkdir -p ~/my-site
cat > ~/my-site/index.anon <<'EOF'
# Welcome to my hidden service

This page is served via the v0.2 rendezvous protocol.

=> /about.anon  About this site
EOF

node bin/anon-site-server.mjs ~/my-site --port 1965
```

But the service forwards bytes blindly — the backend can be anything: a
chat bot, a static HTTP server, an SSH service, anything that listens on
a TCP port.

### 5.4. Publish

```bash
node bin/anon-service.mjs publish \
    --data-dir ~/.anon-service \
    --local-host 127.0.0.1 --local-port 1965 \
    --consensus /etc/anon/consensus.bin \
    --da-trust /etc/anon/da-trust.json \
    --i-understand-this-is-experimental
```

You should see:

```
[…] onion: leh4rb3icbxwruu7itv3t4pnpsef35piydbjcxkrkpfdupiyoxu6elyc.anon
[…] node-identity loaded: ef965a49d6e5b084…
[…] local destination: 127.0.0.1:1965
[…]   svc: service published at IP a5a86f22d19c48c7…
[…] service published — accepting introductions
```

The daemon is now listening for introductions. When a client opens your
service, you'll see logs flow as INTRODUCE2 cells arrive, ntor
handshakes complete, RP circuits build, and streams begin.

### 5.5. Descriptor lifetime + refresh

By default the descriptor has a 1-hour lifetime. After it expires,
clients receive a parse-error from `loadConsensus` when validating.

For long-running services, you need to refresh:

```bash
# Re-init the descriptor with a fresh publishEpoch.
# Existing keys are preserved (anon-service init reuses identity.bin
# if it exists).
node bin/anon-service.mjs init \
    --data-dir ~/.anon-service \
    --ip-fingerprint <same-as-before> \
    --consensus /etc/anon/consensus.bin \
    --da-trust /etc/anon/da-trust.json \
    --lifetime-seconds 86400        # 1 day
```

The daemon doesn't auto-refresh; restart it after re-init.

---

## 6. Browsing hidden services

`anon-browse` is the TUI browser. Two modes:

### 6.1. Rendezvous mode (production-shaped)

```bash
node bin/anon-browse.mjs "anon://leh4rb3icbxwru...anon/" \
    --consensus /etc/anon/consensus.bin \
    --da-trust /etc/anon/da-trust.json \
    --descriptor ~/Downloads/that-service.descriptor.bin
```

This resolves the URL via the real rendezvous protocol — builds 3-hop
circuits to the RP and IP, runs the INTRODUCE/RENDEZVOUS dance, derives
end-to-end keys, opens a stream to the service.

You need the descriptor file the service operator gave you.

### 6.2. Direct mode (development)

```bash
node bin/anon-browse.mjs "anon://localhost-test.anon/" \
    --connect 127.0.0.1:1965
```

Skips rendezvous entirely and dials a single TCP host:port for every
fetch. Used when developing an anon-site server locally.

### 6.3. TUI keys

| Key | Action |
|---|---|
| `j` / `↓` | Scroll one line down |
| `k` / `↑` | Scroll one line up |
| `Space` / `PgDn` | Scroll page down |
| `PgUp` | Scroll page up |
| `G` / `End` | Jump to bottom |
| `1`-`9` | Follow numbered link |
| `:` | Multi-digit link selector |
| `b` / `f` | Back / forward |
| `r` | Reload current URL |
| `g` | Open URL bar |
| `?` | Help |
| `q` | Quit |

### 6.4. Non-interactive (`--dump`)

```bash
node bin/anon-browse.mjs "anon://..." --consensus ... --da-trust ... --descriptor ... --dump
```

Fetches the URL, renders once to stdout, exits. Useful for scripts and CI.

---

## 7. Using anon-layer as a SOCKS5 proxy

If you want to route arbitrary TCP through the v0.2 network (e.g. point
a browser at it for clearnet browsing), use `anon-socks`.

```bash
node bin/anon-socks.mjs \
    --tunnel anon-layer \
    --port 1080 \
    --data-dir ~/.anon-node-v2 \
    --consensus /etc/anon/consensus.bin \
    --da-trust /etc/anon/da-trust.json \
    --i-understand-this-is-experimental
```

Then in your browser settings:

```
SOCKS5 host: 127.0.0.1
SOCKS5 port: 1080
```

Every TCP connection the browser makes is routed through a 3-hop circuit
ending at an exit relay (a relay with permissive exit policy in the
consensus).

> **DNS leak warning.** For hostname destinations (e.g.
> `socks5://...?host=example.com`), the v0.2 reference resolves DNS
> client-side. This **leaks the DNS query to your local resolver.** For
> real anonymity, you need to either (a) only use IPv4 destinations
> (no DNS resolution needed) or (b) wait for exit-side DNS (future work
> — see § 11).

---

## 8. Building a testnet

For local development, run all the relays + DA + service yourself.

The canonical example is `bench/demo-anon-rendezvous.sh`. It spins up
6 relays + a service + a backend + a client, then asserts a hidden-service
page round-trips. **Read that script** — it's the most concrete
documentation of how the pieces fit together.

### 8.1. Generating a testnet consensus

Use `bin/anon-mkconsensus.mjs`. First, initialize a directory authority
identity (one-time):

```bash
node bin/anon-mkconsensus.mjs init --data-dir ~/.anon-mkconsensus
# generated DA identity → ~/.anon-mkconsensus/da-identity.bin
# wrote DA-trust file   → ~/.anon-mkconsensus/da-trust.json
# fingerprint: a1067e88518ec2114a1a99980fca219bebaf20bd5e52bd47dea514b9a2a09be6
# idPk:        d5fa1c750fe954669d582ded9d3095beff1de2e8c54f3e42d2fda8a8da032d77
```

Then collect each relay's metadata (`anon-node-v2 info` on each
machine) and write a `relays.json`:

```json
[
  {
    "fingerprint": "8dc6dd6401563f8f...",
    "idPk":        "45251615b1f6c9e3...",
    "B_pk":        "a2630570125d3c5e...",
    "host":        "127.0.0.1",
    "port":        9001,
    "flags":       ["GUARD"],
    "exit_policy": "reject"
  },
  {
    "fingerprint": "...",
    "idPk":        "...",
    "B_pk":        "...",
    "host":        "127.0.0.1",
    "port":        9002,
    "flags":       ["EXIT"],
    "exit_policy": "reduced"
  }
]
```

Flag names accepted: `GUARD`, `EXIT`, `STABLE`, `FAST`, `HSDIR`,
`AUTHORITY`, `BAD_EXIT`. `RUNNING` and `VALID` are always added.

`exit_policy` accepts `"reject"`, `"reduced"`, `"standard"`, or
`"file:PATH"` (binary policy bytes).

Sign the consensus:

```bash
node bin/anon-mkconsensus.mjs build \
    --data-dir ~/.anon-mkconsensus \
    --relays relays.json \
    --output-consensus consensus.bin \
    --output-trust da-trust.json \
    --lifetime-seconds 86400
```

Distribute `consensus.bin` and `da-trust.json` to every relay,
service, and client.

### 8.2. `--allow-co-located`

On a testnet with all relays on `127.0.0.1`, the default `pickPath`
rejects every 3-hop path because hops share a `/16` (the anti-correlation
rule from spec § 6.1). For testnets only, pass:

```bash
--allow-co-located
```

to `anon-service publish` and `anon-browse`. The flag is intentionally
absent from path-internal calls; tests pinning the rule's enforcement
on production paths still pass.

**Do not use this flag in production.** Co-located relays may share an
operator or upstream provider; the anti-correlation rule meaningfully
hampers traffic-correlation attacks.

### 8.3. Run the demo

```bash
bench/demo-anon-rendezvous.sh
```

Spins up everything, runs an assertion, tears down. Takes ~5 seconds.
If the demo passes on your machine, every cryptographic and protocol
layer is working.

---

## 9. Operational notes

### 9.1. File permissions

| File | Mode | Contains |
|---|---|---|
| `~/.anon-node-v2/identity.key` | 0600 | relay Ed25519+X25519 secrets |
| `~/.anon-service/identity.bin` | 0600 | service Ed25519+X25519+ML-KEM secrets |
| `~/.anon-service/node-identity.key` | 0600 | the service's relay-style node identity |
| `~/.anon-service/descriptor.bin` | 0644 typical | PUBLIC; share with clients |
| `consensus.bin`, `da-trust.json` | 0644 typical | PUBLIC |

The daemons enforce 0600 on the secret files: they refuse to start if
group/other bits are set. The public files are operator-managed.

### 9.2. Logging

Both relays and services log to stderr. Lines start with an ISO 8601
timestamp. Volume is low under normal operation — a few lines per
circuit built or stream opened. Pipe to a log file if you need
persistence:

```bash
anon-node-v2 run ... 2>>~/anon-node.log
```

### 9.3. Graceful shutdown

`SIGINT` and `SIGTERM` trigger a clean shutdown:

1. Stop accepting new connections
2. Send `DESTROY` on every active circuit
3. Close every link
4. Exit 0

If the process hangs on shutdown, that's a bug — report it. Force-kill
with `SIGKILL` is safe (identity file is atomic-written; no recovery
state to corrupt).

### 9.4. Resource use

Per relay, idle: ~70 MB RSS, < 1% CPU, < 10 KB/s bandwidth.

Per active circuit: small additional memory (one circuit-state struct).
The dispatcher's reassemblers (for fragmented CREATE/EXTEND/INTRODUCE)
have a default 30-second timeout and 16-concurrent-handshakes cap to
bound memory under load.

### 9.5. Service descriptor distribution

There is no automated descriptor-distribution mechanism (HSDir is future
work). Until that lands, operators distribute `descriptor.bin` files
out-of-band — email, web download, signal, etc. Treat them like public
URLs.

---

## 10. Troubleshooting

### `pickPath: no usable 3-hop path`

The path selector rejected every candidate. Causes:

- **All relays share a `/16`** (typical on testnets) → pass `--allow-co-located`
- **Too few relays in the consensus** (need at least 3 with the right flags) → add more
- **Destination port not permitted by any exit's policy** → use `--exit-policy reduced` or `standard` on at least one relay

### `peer sent DESTROY during build`

A relay you tried to extend through tore down the circuit. Most common cause:

- The next-hop relay doesn't have a consensus loaded (so it can't resolve
  ITS next hop). Solution: start all relays with `--consensus` and `--da-trust`.

### `INTRO_ESTABLISHED timeout`

The service couldn't get a response from its IP within 15 seconds.

- Check the IP relay is actually running (`ps`, `netstat`)
- Check the IP relay loaded the same consensus (it needs to know about your service's circuit hops)
- Check `--ip-fingerprint` matches a relay in the consensus

### `RENDEZVOUS2 timeout`

The client's rendezvous handshake didn't get a response.

- Likely cause: the service couldn't build its RP circuit (check the service log for path-selection or dial errors)
- Or: the cookie was already consumed (cookies are one-shot; happens if you re-ran the client without re-running everything)

### `service identity ~/.anon-service/identity.bin has overly permissive mode`

`chmod 600 ~/.anon-service/identity.bin`.

### `consensus at /path/to/consensus.bin failed to parse / verify / validate`

- File doesn't exist, is corrupt, or has the wrong byte layout
- DA signature threshold not met (need majority of DA trust set)
- Current time outside `[valid_after, valid_until]` window

### `bad cell size N` (in relay logs)

Someone connected to the WebSocket port and sent non-514-byte messages.
Usually a scanning bot or someone hitting the URL in a regular browser.
The handshake handler closes the connection. Safe to ignore.

### The TUI browser doesn't display anything

- Confirm `process.stdout.isTTY === true` (the binary refuses to run a
  TUI without a real terminal)
- For non-TTY environments (scripts, CI), use `--dump`

---

## 11. Honest gaps and known limitations

The v0.2 reference implementation is feature-complete for the protocol
spec but has documented gaps before it can be a production-grade
anonymity tool.

### 11.1. No public network

v0.2 has not been deployed as a public anonymity network. Anyone who
wants to use it for a real testnet must run their own relays and
distribute their own consensus. There is no equivalent of Tor's
directory authorities operating on the public internet.

### 11.2. No HSDir descriptor distribution

Spec § 10.4 defines hidden-service-directory storage; the reference does
not yet implement the responsible-set calculation or distribution
protocol. Operators distribute descriptor files out-of-band.

### 11.3. Client-side DNS resolution

When `anon-socks` receives a SOCKS5 CONNECT to a hostname, it resolves
the hostname using the local OS resolver. **This leaks the DNS query.**
Exit-side resolution is a future design item (it requires careful
handling of resolver-fingerprint and DNS-poisoning surfaces).

For full anonymity today, only connect to IPv4-literal destinations.

### 11.4. ~~Plain ws:// transport~~ — CLOSED (2026-05-22)

The reference implementation now uses `wss://` natively per SPEC
§ 11.1. See `modules/v2-runtime/link_transport_ws.mjs` (carrier) and
`modules/v2-runtime/self_signed_cert.mjs` (per-relay self-signed
cert, generated on first `anon-node-v2 run`, persisted in the data
dir at `link-{cert,key}.pem`).

**Trust model** (auditor-relevant, exactly as the spec describes it):

- The TLS cert is **not** the relay's identity. Relay identity is its
  Ed25519 `idPk`, authenticated at the LINK_AUTH step (§ 11.2).
- The dialer passes `rejectUnauthorized: false`. This is intentional
  and load-bearing on the spec: any cert is acceptable because none
  of them are evidence of identity. Replacing this with strict CA
  validation would NOT improve security and WOULD introduce a CA-
  trust dependency the protocol avoids.
- SNI is left unset on the dialer (no `servername` option) — no
  destination-hostname leak in pre-handshake plaintext.
- Cert rotation is decoupled from identity rotation: an operator may
  delete `link-{cert,key}.pem` and the daemon will mint fresh ones
  on next start. The relay's place in the consensus is unaffected.
- Cell-layer AEAD (§ 5.4) is independent of TLS and unchanged. TLS
  adds metadata-flow protection at the link level; it doesn't add
  anonymity properties.

No reverse-proxy needed; the daemon terminates TLS itself. Earlier
deploy-side guidance about a Caddy front-door is obsolete.

### 11.5. Classical Ed25519 signatures

**SITE-SIDE CLOSED (2026-05-22).** Hidden-service identity, descriptor
signing, and address derivation are now hybrid Ed25519 + ML-DSA-65
(NIST claim-3, matches our ML-KEM-768 level). See:

- `modules/crypto/hybrid_sign.mjs` — primitive (AND-of-sigs, not OR)
- `modules/v2/onion_address.mjs` — v3 address = base32(Blake2b(SVC_pk_ed
  || SVC_pk_mldsa) || checksum || 0x03), the address itself binds both
  pubkeys so a quantum attacker who breaks Ed25519 can't swap in a
  different ML-DSA key
- `modules/v2/descriptor.mjs` — v3 descriptor carries both pubkeys
  and both signatures; verifier requires both valid AND the
  address-binding hash to match
- `modules/v2-runtime/service_persistence.mjs` — identity file grew
  from 3680 → 7712 bytes to hold SVC_sk_mldsa (4032 B). Legacy v2
  files are rejected with a "please re-init" message.

**STILL OPEN** (each is its own future chunk):

- LINK_AUTH (relay-to-relay) — still classical Ed25519. Quantum
  adversary can impersonate relays. Wire-format change needed:
  LINK_AUTH cell is currently 64 bytes (single Ed25519 sig); adding
  ML-DSA-65 (3309 B) requires multi-cell LINK_AUTH or a new larger
  cell variant.
- DA consensus — DAs sign with classical Ed25519. Quantum adversary
  can forge consensus → replace network. Same wire-format change
  surface as LINK_AUTH.
- IP intro key (`serviceIntroSk`) — Ed25519 per-IP key for
  ESTABLISH_INTRO. Hybridizing it independently from service
  identity gives separation; same engineering pattern as service
  identity.
- External cryptographic audit — the gate for dropping the PRE-AUDIT
  TESTNET label entirely.

### 11.6. No SENDME flow control

Spec § 7.5 calls for SENDME windows; the reference uses TCP backpressure
on each link leg. Works in practice; a fast sender can theoretically
overwhelm a slow receiver across the multi-hop path. Production hardening.

### 11.7. Test vectors

`docs/SPEC-v0.2-draft.md` is the canonical wire format. Independent
implementations in other languages would benefit from test vectors
(known-good byte sequences for every codec). The `test-vectors/`
directory is scheduled for chunk 9.1 but is currently empty.

### 11.8. v0.2 daemon ↔ v0.1 daemon incompatibility

The two protocols are wire-incompatible. v0.1 daemons (`bin/anon-node.mjs`,
`bin/anon-chat.mjs`) cannot talk to v0.2 daemons. The v0.1 codebase is
retained as a stepping stone, not as a deployment target.

---

## 12. Where to look next

| You want to… | Read |
|---|---|
| Understand the wire format | `docs/SPEC-v0.2-draft.md` |
| Understand the sites protocol | `docs/SITES-v0.1.md` |
| Verify the demo works locally | `bench/demo-anon-rendezvous.sh` |
| Read the source for a specific piece | Most relevant code is in `modules/v2/` (protocol) and `modules/v2-runtime/` (runtime) |
| Report a bug or contribute | Open an issue / PR on the repo |
| Get help running a node | Same |

If you're considering deploying v0.2 against a real threat model where
people would be harmed by deanonymization, **stop and use Tor instead.**
Anon-layer v0.2 is a research/learning artefact, not a production tool.

---

## Document status

This guide describes the v0.2 reference implementation as of 2026-05-21.
It will need updates when:

- Test vectors land (chunk 9.1)
- HSDir distribution is implemented
- Exit-side DNS lands
- `wss://` becomes a native option
- A consensus-generation CLI is added
- A public testnet with operating DAs exists
