# anon-layer testnet deployment — architecture

| | |
|---|---|
| **Document** | Decision log for the v0 testnet deployment |
| **Date** | 2026-05-22 |
| **Status** | **PRE-AUDIT TESTNET — not for anonymity needs.** See `docs/RUNNING-A-NODE.md` § 11. |
| **Audience** | The operator (you), and anyone reading the deploy artifacts later |

---

## ⚠️ Framing

This network is being deployed before:

- the crypto rewrite (ElGamal/Twofish → X25519/ChaCha20-Poly1305) is complete,
- the v0.2 transport reference is feature-complete,
- the § 11 gaps (HSDir, DNS leaks, `wss://` link transport, hybrid-PQ signatures) are closed,
- and any external cryptographic audit.

It launches as an explicit **PRE-AUDIT TESTNET** — for protocol development,
conformance testing by independent implementers, and education. The user-facing
warning ("Not for anonymity needs") appears on the browser new-tab landing, About
dialog, anonymous.gratis, descriptor handouts, and every artifact in this directory.
Promote to "production" only after the gaps above are closed.

---

## Topology

```
                              ┌──────────────┐
                              │  client      │
                              │ (anon-browser) ── fetches consensus on launch
                              └──────┬───────┘   from any DA in da-trust.json
                                     │
            ┌────────────────────────┼────────────────────────┐
            │                        │                        │
       https://da1                https://da2              https://da3
       .anon.gratis               .anon.gratis            .anon.gratis
       (FlokiNET IS)              (FlokiNET RO)           (Njalla NL)
            │                        │                        │
            │ ── each holds the same relays.json ──           │
            │   (synced out-of-band, see § Relays.json sync)  │
            │                                                 │
            └─────────────── consensus.bin ───────────────────┘
                              ↑ signed by own DA key
                              ↑ refreshed hourly via cron
```

```
relays (7 total, jurisdictionally spread):
  Iceland   (FlokiNET):  relay-is1.anon.gratis, relay-is2.anon.gratis
  Romania   (FlokiNET):  relay-ro1.anon.gratis, relay-ro2.anon.gratis
  Netherlands (Njalla):  relay-nl1.anon.gratis, relay-nl2.anon.gratis, relay-nl3.anon.gratis

Each relay listens on wss://relay-X.anon.gratis:443
(Caddy terminates TLS, reverse-proxies to anon-node-v2 ws://localhost:9001)
```

Cost estimate: ~$150-250/mo for all 10 VPSes (FlokiNET $15-30/mo, Njalla $15/mo).

---

## Decision log

### D1. Single domain (`anon.gratis`) for all hostnames

All DA + relay hostnames live under `anon.gratis`. **Documented risk:** if
the `anon.gratis` DNS or TLS chain is compromised, the network is compromised
— every relay and DA appears under one DNS authority. Mitigation: once 2
partner orgs come online to run DAs, they use their own domains
(D5 below).

### D2. Operator runs all 3 DAs for v0

Federated 3-DA topology, but all three currently run by the same operator
across 3 different VPS providers (Iceland, Romania, Netherlands). This is
"provider federation," not "operator federation." A motivated adversary
who compromises the operator owns all three DAs. Documented as a v0
compromise; revisit once 2 partner orgs are lined up.

### D3. 1-of-N consensus trust, not M-of-N

Each DA produces its own signed `consensus.bin`. The client trusts a
consensus if **any** DA listed in `da-trust.json` signed it. Weaker than
Tor's majority-signature model (where clients require ≥5-of-9 DA
signatures), but simpler and matches the v0 reference's single-signature
output. **Upgrade path:** add multi-signature support in
`modules/v2/consensus.mjs` post-audit and switch clients to M-of-N
verification.

### D4. Hourly consensus refresh, hourly descriptor lifetime

Matches Tor's hourly cadence. Each DA's cron rebuilds `consensus.bin` from
its local `relays.json` every hour. Browser launcher re-fetches at startup
and every hour while running. Hidden-service operators re-publish their
descriptors before the 1-hour expiry.

### D5. Trust file (`da-trust.json`) ships baked into the browser tarball

The root of trust is the set of 3 DA Ed25519 fingerprints. We ship that
list pinned into the browser tarball; the tarball itself is the
distribution unit users verify (PGP signature on the tarball + Sigstore
transparency log, both future work). At startup the browser fetches
`consensus.bin` from any of the 3 DA HTTPS endpoints and validates the
signature against the pinned trust file.

### D6. Consensus served via Caddy on the DA VPS, not custom HTTP

`anon-mkconsensus` is a batch tool — no HTTP listener. We wrap it in a
Caddy container that auto-provisions a Let's Encrypt cert for
`daN.anon.gratis` and serves `consensus.bin` + `da-trust.json` as static
files. The cron container writes new files into a shared volume; Caddy
picks them up on next request. Standard `text/plain` + `application/octet-stream`
content types; no special protocol.

### D7. Relays use Caddy `reverse_proxy` for `wss://` termination

Closes part of the § 11.4 gap (link-transport TLS). Each relay's Caddy
proxies `wss://relay-X.anon.gratis:443` → `ws://anon-node:9001`. Cell-layer
encryption inside is still hybrid post-quantum — TLS at the link adds
metadata-flow protection between relays, not anonymity. Spec-compliant
once link transport is upgraded; for now the reverse proxy is a deployment
workaround.

### D8. `relays.json` sync via Git, manual review

Each DA holds a local copy of `relays.json` (the manually-curated list of
all relay fingerprints + URLs that the operator considers part of the
network). For v0 (single operator), this lives in a private Git repo
mirrored to all 3 DAs via cron `git pull`. Adding a new relay = PR
against the repo, manual merge, all DAs pick up on next refresh. **For
multi-org later:** each org maintains its own `relays.json` and clients
intersect / union across them based on the M-of-N policy (D3).

### D9. Manual bootstrap, automated steady-state

First-time bring-up requires manual coordination (init each DA, init
each relay, gather fingerprints into `relays.json`, distribute
`da-trust.json`). Documented in `OPERATOR.md`. Subsequent relay rotation
+ consensus refresh is fully automated via cron + Git.

### D10. No client-side consensus auto-refresh in the daemon itself

The bundled relay daemon (`anon-node-v2`) doesn't reload consensus at
runtime (spec gap; documented). On consensus rotation, we bounce the
container — `docker compose restart anon-node`. The launcher script
includes a sidecar that polls every hour; if consensus hash changed,
it triggers the restart.

---

## Bootstrap sequence (one-time)

1. **Provision 3 DA VPSes**: 1× FlokiNET Iceland, 1× FlokiNET Romania, 1× Njalla Netherlands. DNS for `da{1,2,3}.anon.gratis`.
2. **Run `scripts/bootstrap-da.sh`** on each. Generates the DA identity (`da-identity.bin`, mode 0600), starts Caddy.
3. **Collect each DA's fingerprint + idPk** from `scripts/print-da-trust-entry.sh`. Compose `da-trust.json` from all 3 entries; commit to deploy repo.
4. **Provision 7 relay VPSes**: 2× FlokiNET IS, 2× FlokiNET RO, 3× Njalla NL. DNS for `relay-{is,ro,nl}{N}.anon.gratis`.
5. **Run `scripts/bootstrap-relay.sh`** on each. Generates `identity.key`, prints fingerprint + idPk + B_pk.
6. **Compose `relays.json`** with all 7 entries (hostname, port, fingerprint, keys, exit-policy=reject-all initially). Commit to deploy repo.
7. **Push deploy repo to all 3 DAs**; each DA's cron picks up the new `relays.json` + `da-trust.json` on next tick.
8. **Each DA builds its first consensus**; serves over HTTPS.
9. **Distribute `da-trust.json`** by baking into the next anon-browser tarball release.
10. **Browser launcher** fetches consensus from any DA, validates, network is live.

## Steady-state operation

- **Add a relay:** operator generates identity on new VPS, files a PR against `relays.json` with the new entry, merges, all DAs pick up on next refresh (within 1h), consensus updated, relays bounce on next consensus tick.
- **Rotate a DA key:** harder — every client needs the new `da-trust.json`. Treat as a release event (new browser tarball).
- **Remove a relay:** delete from `relays.json`, merge, consensus rebuilds without it.
- **Update relay binary:** push new Docker image tag, `docker compose pull && docker compose up -d` on each relay. Roll out over multiple hours so the network isn't fully simultaneously bounced.

---

## What this document is NOT

- A spec change. The wire protocol is unchanged.
- A guarantee. Anything in this doc may turn out wrong; the deploy is pre-audit and the architecture is provisional.
- A production launch plan. See § Framing.

## Open questions for next round

- Multi-signature consensus (M-of-N) implementation work.
- Client-side consensus auto-fetch — currently spec-gap, fetcher will live in `bin/anon-browse-gui.mjs` as a launcher hook.
- Tarball signing + transparency log integration.
- HSDir for descriptor distribution (§ 11.2).
- How to do reproducible builds of the bundled tarball.
