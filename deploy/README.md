# `deploy/` — anon-layer testnet operator guide

> **⚠️ PRE-AUDIT TESTNET — NOT FOR ANONYMITY NEEDS.**
>
> The protocol stack here has not been audited. Multiple `§ 11` gaps
> in `docs/RUNNING-A-NODE.md` are still open (HSDir, DNS leak, link
> transport TLS, hybrid-PQ signatures). The crypto rewrite to
> X25519/ChaCha20-Poly1305 is in progress. Do not advertise this
> network to at-risk users until the audit is done and the gaps are
> closed. For real anonymity today, use [Tor](https://torproject.org).

This directory contains everything an operator needs to spin up the
anon-layer testnet on real VPSes. The architecture (why these
choices, what the trust model is) lives in
[`ARCHITECTURE.md`](./ARCHITECTURE.md). This README is the **runbook**.

---

## What you need before you start

- **DNS for `anon.gratis`** (or your chosen domain). You'll point one
  A record per VPS at the VPS's public IP — 10 records total for the
  default 3-DA + 7-relay topology.
- **10 VPSes**, ideally jurisdictionally spread. The default split is:
  - **DAs:** 1× FlokiNET Iceland, 1× FlokiNET Romania, 1× Njalla Netherlands
  - **Relays:** 2× FlokiNET IS, 2× FlokiNET RO, 3× Njalla NL
  - 1 GB RAM, 10 GB disk, 1 vCPU per box is enough. Estimated cost
    $150–250 / month total.
- **The cloned project repo on each VPS.** The bootstrap scripts
  expect to find `deploy/docker/relay/` or `deploy/docker/da/`
  relative to the current dir.
- **Docker daemon access for your local user** if you'll be testing
  locally first: `sudo usermod -aG docker $USER && newgrp docker`.

---

## Directory tour

```
deploy/
├── ARCHITECTURE.md       — decision log + topology diagram
├── README.md             — this file
├── docker/
│   ├── relay/
│   │   ├── Dockerfile    — anon-node-v2 image
│   │   └── entrypoint.sh — init identity + run loop
│   └── da/
│       ├── Dockerfile    — anon-mkconsensus + hourly cron
│       ├── entrypoint.sh — init DA secret + first build + start cron
│       └── rebuild.sh    — single consensus rebuild (cron target)
├── compose/
│   ├── relay.yml         — anon-node + Caddy wss:// terminator
│   ├── da.yml            — anon-da worker + Caddy https file server
│   ├── Caddyfile.relay   — reverse_proxy to ws://anon-node:9001
│   ├── Caddyfile.da      — file_server for /srv contents
│   ├── .env.relay.example
│   └── .env.da.example
└── scripts/
    ├── bootstrap-relay.sh — first-time VPS setup for a relay
    └── bootstrap-da.sh    — first-time VPS setup for a DA
```

---

## Bootstrap sequence (do this once)

The order matters: DAs first (so they have identities), then relays,
then build relays.json with all relay fingerprints, then push to DAs
so they sign the first consensus.

### 1. Bring up the 3 DAs

On **each** DA VPS (e.g. `da1.anon.gratis`):

```bash
# 1.1. Clone the project
git clone https://github.com/anon-gratis/anonymous-layer.git
cd anonymous-layer

# 1.2. Run the bootstrap (installs docker, ufw, builds image, lays out /opt/anon-da)
sudo ./deploy/scripts/bootstrap-da.sh

# 1.3. Edit /opt/anon-da/.env  →  set DA_DOMAIN + ACME_EMAIL
sudo nano /opt/anon-da/.env

# 1.4. Make sure DNS is live: dig +short $DA_DOMAIN should return this VPS's IP.

# 1.5. Start (will block on building first consensus — see step 3 first)
sudo docker compose -f /opt/anon-da/da.yml up -d
sudo docker logs -f anon-da
```

After first start, copy the DA's trust entry off the box:

```bash
sudo docker exec anon-da cat /data/da-trust.json
# Looks like:
# { "<fingerprint-hex>": "<idPk-hex>" }
```

Repeat for `da2.anon.gratis` (FlokiNET RO) and `da3.anon.gratis` (Njalla NL).

### 2. Bring up the 7 relays

On **each** relay VPS (e.g. `relay-is1.anon.gratis`):

```bash
git clone https://github.com/anon-gratis/anonymous-layer.git
cd anonymous-layer
sudo ./deploy/scripts/bootstrap-relay.sh

# Edit /opt/anon-relay/.env  →  set RELAY_DOMAIN + ACME_EMAIL
sudo nano /opt/anon-relay/.env

# Bring up (will fail until consensus + da-trust are dropped — see step 4)
sudo docker compose -f /opt/anon-relay/relay.yml up -d
sudo docker logs anon-relay    # prints the new relay's fingerprint
```

Copy each relay's fingerprint + idPk + B_pk off the box:

```bash
sudo docker exec anon-relay node /app/bin/anon-node-v2.mjs info \
    --data-dir /data
```

### 3. Build `relays.json` and `da-trust.json`

Locally on your dev machine, compose two files from the values you
collected:

**`relays.json`** — same file goes on all 3 DAs. Replace placeholders
with real values from step 2:

```json
{
  "relays": [
    {
      "nickname":    "relay-is1",
      "host":        "relay-is1.anon.gratis",
      "port":        443,
      "fingerprint": "<from anon-node-v2 info>",
      "idPk":        "<from anon-node-v2 info>",
      "bPk":         "<from anon-node-v2 info>",
      "flags":       ["RUNNING", "VALID", "FAST", "GUARD"],
      "exitPolicy":  "reject"
    },
    ...
  ]
}
```

(Full schema: `modules/v2/consensus.mjs` and `bin/anon-mkconsensus.mjs`.)

**`da-trust.json`** — concatenate the entries from step 1.5:

```json
{
  "<da1-fingerprint>": "<da1-idPk>",
  "<da2-fingerprint>": "<da2-idPk>",
  "<da3-fingerprint>": "<da3-idPk>"
}
```

### 4. Distribute the files

- `relays.json` → `scp` to each of the 3 DAs at
  `/opt/anon-da/relays.json` (replaces the placeholder).
- `da-trust.json` → `scp` to each of the 7 relays at
  `/opt/anon-relay/config/da-trust.json`.
- Pull a fresh consensus from any DA, write to each relay:
  ```bash
  curl -fsSL https://da1.anon.gratis/consensus.bin \
      | ssh root@relay-is1.anon.gratis \
        "cat > /opt/anon-relay/config/consensus.bin"
  ```
- On each DA: `sudo docker exec anon-da /usr/local/bin/rebuild.sh`
  to sign the first real consensus (overrides the empty placeholder).
- On each relay: `sudo docker compose -f /opt/anon-relay/relay.yml restart anon-node`
  to pick up the new consensus.

### 5. Distribute `da-trust.json` to clients

Bake `da-trust.json` into the next anon-browser tarball release. Until
then, ship it manually:

```bash
cp da-trust.json /home/$USER/anon-browser/AnonLayer/config/da-trust.json
# also edit AnonLayer/config/anon-browser.conf to set DA_URLS
```

The launcher fetches a fresh consensus from one of the URLs in
`DA_URLS` on every start.

---

## Steady-state operations

### Add a new relay

1. Spin up the VPS, run `bootstrap-relay.sh`, collect fingerprint.
2. Add an entry to `relays.json` in your deploy repo, commit, push.
3. SCP the new `relays.json` to each of the 3 DAs.
4. Wait for next hourly rebuild, or force one:
   `sudo docker exec anon-da /usr/local/bin/rebuild.sh`.
5. New consensus propagates; existing relays will pull it on their
   next operator-driven refresh (see below).

### Refresh consensus on existing relays

The relay daemon doesn't auto-reload consensus today (spec gap). On a
schedule (or whenever the relay-set changes), bounce each relay:

```bash
# On each relay VPS:
curl -fsSL https://da1.anon.gratis/consensus.bin \
    > /opt/anon-relay/config/consensus.bin
sudo docker compose -f /opt/anon-relay/relay.yml restart anon-node
```

(Future: a sidecar that polls + restarts automatically. For v0,
operator-driven is fine.)

### Update the relay or DA binary

```bash
cd /path/to/anonymous-layer   # the cloned repo on the VPS
git pull
sudo docker build -f deploy/docker/relay/Dockerfile -t anon-relay:dev .
sudo docker compose -f /opt/anon-relay/relay.yml up -d   # picks up new image
```

Roll the update out one relay at a time, leaving a few-minute gap, so
the network isn't entirely bounced simultaneously.

### Rotate a DA key

This is a hard change — every client needs the updated `da-trust.json`.
Treat it as a release event:

1. On the DA VPS: stop the stack, delete `/opt/anon-da/data/da-identity.bin`,
   bring back up. A new identity is generated.
2. Get the new trust entry.
3. Cut a new browser tarball with the updated bundled `da-trust.json`.
4. Announce on `anonymous.gratis` that clients must upgrade.

### Remove a relay

Delete its entry from `relays.json`, push to DAs, rebuild consensus.
Take the VPS down at your leisure.

---

## Monitoring sanity checks

- **Is a DA reachable?**
  `curl -sSI https://da1.anon.gratis/consensus.bin` → expect 200,
  `Content-Type: application/octet-stream`.
- **Is the consensus fresh?**
  `curl -sSI https://da1.anon.gratis/consensus.bin | grep -i last-modified` →
  should be within the last hour.
- **Is my relay in consensus?**
  `curl -sS https://da1.anon.gratis/consensus.bin > /tmp/c.bin`
  then grep your fingerprint with whatever tool can parse the binary
  (or trust that if `docker logs` shows traffic, you're in).
- **Are relay-to-relay links alive?** `docker logs anon-relay`
  should show `link established` events for the other 6 relays.

---

## Security hardening checklist (per VPS)

- [ ] SSH: key-only, no password (`PasswordAuthentication no`).
- [ ] `ufw` enabled (bootstrap scripts do this).
- [ ] `unattended-upgrades` enabled for kernel/openssl/etc.
- [ ] Root login disabled; admin via sudo account.
- [ ] Off-box backup of DA secret (`/opt/anon-da/data/da-identity.bin`)
      — encrypted, restricted access. Without it, you can't sign new
      consensus and the DA is effectively dead.
- [ ] Off-box backup of each relay's `identity.key` — without it the
      relay loses its fingerprint and is treated as a new relay
      (consensus needs updating again).
- [ ] Monitor cert expiry — Caddy auto-renews but if the renewal cron
      fails silently, clients can't reach you.
- [ ] Confirm Docker logs aren't filling disk
      (`/var/lib/docker/containers/`); set log rotation if needed.

---

## Honest limits of this deploy

- **Single operator, federated topology.** All 3 DAs run by you. An
  adversary who compromises you owns all 3 DAs. Documented compromise;
  fix by recruiting 2 partner orgs to run their own DA on their own
  domain.
- **`relays.json` synced by `scp`.** Drift between DAs (one updated,
  others stale) → clients fetching from a lagging DA see an
  inconsistent consensus. Fix: shared git repo + cron `git pull` on
  each DA. v0.1 ops, do it manually.
- **Relays don't auto-reload consensus.** Bounce-on-change is
  operator-driven.
- **No HSDir.** Hidden-service operators distribute descriptors out
  of band (sign + post a link).
- **No tarball signing.** Until the release process integrates PGP +
  Sigstore, the bundled `da-trust.json` could be swapped by anyone
  with write access to the download. Mitigate by signing the tarball
  out of band and publishing fingerprints on `anonymous.gratis`.

If any of these become deal-breakers, file an issue against the
project repo — they're all addressable, just not in v0.

---

## See also

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — why we chose what we chose
- [`../docs/RUNNING-A-NODE.md`](../docs/RUNNING-A-NODE.md) — the
  operator's intro to relays + services (mostly written for local
  testnets, but the protocol detail is identical)
- [`../docs/SPEC-v0.2-draft.md`](../docs/SPEC-v0.2-draft.md) — the
  wire protocol the relays speak
- [`../docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md) — what this
  protocol does and doesn't promise to defend against
