# Anonymous Layer

**A post-quantum anonymity network, derived from Tor's lessons and built for the next thirty years.**

| | |
|---|---|
| **Document** | Anonymous Layer Whitepaper |
| **Version** | 0.1 (draft) |
| **Status** | **Pre-audit. Testnet. Not production.** |
| **Editor** | Anonymous Gratis `<admin@anon.gratis>` |
| **Date** | 2026-05-25 |
| **License** | AGPL-3.0-or-later |

> This whitepaper describes (a) what Anonymous Layer is today, (b) what
> design choices it inherits, breaks, or replaces from Tor, and (c)
> the specific milestones required before it can be called an
> anonymity network in any sense beyond protocol research.
>
> **Use Tor for life-safety needs today.** Anonymous Layer is not
> ready. We say so on every entry point — the launcher, the bridge
> landing page, the GitHub README, this document. Until external
> audit, public testnet, and the operator-diversity milestones in §6
> are met, this project is reference software, not a tool.

---

## 0. TL;DR

- Anonymous Layer is a from-scratch, AGPL'd, **wire-format-incompatible** alternative to Tor.
- The wire is **post-quantum hybrid** by default — X25519 + ML-KEM-768 for every circuit hop, day one. Tor adopted ML-KEM in 2024 as an option; we make it mandatory.
- The browser, bridge, and circuit machinery already ship in this repo. **Three relays** participate in the current testnet. That is **not anonymity** — it is end-to-end protocol validation.
- The honest path to "the post-quantum Tor" is: spec → audit → ≥30 operator-diverse relays → public testnet → security review → general availability. We are between step 1 and 2.

---

## 1. Why a new network

Tor is the best-deployed anonymity network in history. It is also a
twenty-year-old codebase carrying twenty years of architectural
decisions made before lattice-based KEMs, before AEAD became
mainstream, before fixed-size relay cells were known to leak less
than variable-size ones. Tor's own modernization track (arti,
relay-side post-quantum) is several years out from making any of
this default behaviour.

Anonymous Layer is the answer to a different question: **what would
you build today, with twenty years of Tor hindsight, if backward
compatibility were not a constraint?**

The non-negotiable design axioms:

1. **Post-quantum by default.** Every key-agreement on every hop
   uses a hybrid construction. No "fallback to classical" mode. No
   pref toggle. A future quantum adversary that recovers all X25519
   shared secrets via Shor's algorithm still cannot recover the
   per-circuit AEAD keys, because the ML-KEM half of the handshake
   was independent.
2. **Small spec, auditable implementation.** The protocol document
   ([`SPEC-v0.2-draft.md`](./SPEC-v0.2-draft.md)) is intentionally
   short. The reference implementation in `modules/v2/` and
   `modules/v2-runtime/` is plain JavaScript without metaprogramming
   or transpilation, so an auditor can read each handshake byte-by-byte
   against the spec.
3. **Browser is part of the project.** Tor Browser is a separate
   organisation downstream of Tor. We ship Anonymous Browser
   ([`browser-fork/`](../browser-fork/)) — a hardened Mullvad/Firefox
   fork — in the same repository so the threat model spans the entire
   user-visible surface.
4. **No telemetry. No accounts. No update channel by default.**
   Every running binary is reproducible from this repo at a tagged
   commit. SHA256 manifests are signed and published with each
   release.

---

## 2. Where we are today (v0.2 pre-audit testnet)

### 2.1. What works end-to-end

- **Multi-hop circuits with post-quantum hybrid handshakes.** Each
  hop derives session keys from `X25519(client, relay) || X25519(client, relay_ephemeral) || ML-KEM-768.Decaps(client_ct)` — protected against both classical and harvest-now-decrypt-later quantum attackers.
- **Hidden services.** Onion-address-equivalent: a 56-character base32 identifier (e.g. `anona4y4gpit3bbuunqhvubajjgmnvuhupka4gqibkdldpby64ujtkqd.anon`) resolves to a rendezvous circuit without exposing the service operator's IP. Implemented in `modules/v2-runtime/rendezvous_client.mjs` and `modules/v2-runtime/service_publisher.mjs`.
- **Stream multiplexing.** A single circuit carries many concurrent application streams (`modules/v2-runtime/streams.mjs`) without re-doing path setup.
- **Anon Browser.** Mullvad Browser fork with a Tor-Browser-style URL bar (now showing `SECURE — ONION / ANON / I2P` pills instead of "Not Secure" for anonymity-network hosts), Safest security level by default, integrated in-browser circuit display via the bridge's `/api/tor-circuit` endpoint.
- **Bundled launcher.** Go-language launcher with an in-browser connect UI (Tor-Browser-style) at `browser-fork/launcher-go/`. Spawns tor (for `.onion` access), the anon-layer bridge (for `.anon` access), and the engine in one window.

### 2.2. What is missing

| Surface | Status | Gating issue |
|---|---|---|
| External cryptographic audit | ❌ | Funding + scheduling |
| Independent reimplementation | ❌ | One implementation is one bug-class away from compromise |
| Anti-Sybil at protocol level | ❌ | v0.3 work; current testnet trusts the operator-curated consensus |
| Pluggable transports (anti-censorship) | ❌ | v0.4; cells are currently DPI-fingerprintable |
| Public testnet | ❌ | 3 relays, all under shared operator authority |
| Operator diversity | ❌ | See §6 |
| Mix-net style traffic shaping | ❌ | Out of scope for v0.x; long-term v2+ |

### 2.3. What we do *not* claim to defend against (today)

Borrowed honestly from Tor's threat model, extended for our protocol stage:

- A **global passive adversary** observing a substantial fraction of all relay traffic. No anonymity network defends against this; ours doesn't either.
- A **targeted active adversary** capable of traffic confirmation against a specific high-value user. Protocol-level limit.
- **Browser-level fingerprinting** beyond what Mullvad/Tor Browser's hardening provides. The browser is hardened; the user is responsible for their environment (no third-party plugins, no logged-in accounts mixed with anonymous use).
- **OS-level compromise** of the device a node or user runs.
- **Operator coercion** when only 3 relays exist (i.e., now). See §6.

---

## 3. How we differ from Tor

| Dimension | Tor (today) | Anonymous Layer (v0.2) |
|---|---|---|
| Circuit handshake | ntor v3 (classical-only by default; hybrid optional, opt-in 2024–) | **Hybrid X25519 + ML-KEM-768 mandatory** |
| Cell size | 514 bytes | 514 bytes (same — fixed-size cells are correct) |
| Hidden services | v3 onion (Ed25519 + classical Diffie-Hellman intro) | Same address shape, but the **intro handshake is hybrid** end-to-end |
| Identity keys | Ed25519 | Ed25519 (classical signatures will need a PQ replacement when SLH-DSA / ML-DSA matures; see §5.2) |
| Consensus signing | RSA-2048 (legacy) + Ed25519 | **Ed25519 only**, moving to a PQ-signature hybrid once standards stabilise |
| Directory authorities | 9 hard-coded DAs maintained by The Tor Project | **DA-trust JSON** at install — operator-distributed, swappable; long-term goal is multi-org governance |
| Browser | Tor Browser (Mozilla fork, separate org) | Anonymous Browser ships in this repo, single audit surface |
| Anti-censorship | obfs4, meek, snowflake | **Not yet** — explicit v0.4 milestone |
| License | 3-clause BSD | **AGPL-3.0-or-later** (forks must publish source if they offer the network as a service) |
| Anonymity-set size | ~2M daily users | testnet (single-digit) |

The differences in this table are **deliberate design choices, not improvements over Tor in the abstract**. Tor's choices were correct given when they were made and what they had to interoperate with. We have the luxury of starting fresh.

---

## 4. Cryptographic posture

### 4.1. What is post-quantum-secure today

Every circuit hop, including the rendezvous handshake for hidden
services, performs the construction described in
[`SPEC-v0.2-draft.md`](./SPEC-v0.2-draft.md) § 3.7:

```
secret_input = X25519(y, X)
            || X25519(B_sk, X)
            || ML-KEM-768.Decaps(K_sk, ct)
            || ID_R || B_pk || X || K_pk || Y || ct || PROTOID
KEY_SEED     = HKDF-SHA-256(secret_input, ...)
```

The classical (X25519) and post-quantum (ML-KEM-768) shared secrets
are concatenated *before* HKDF. A break of *either* primitive
weakens the handshake by exactly zero bits — the surviving primitive
provides the full security level. This is the same construction
TLS 1.3 hybrid groups (`X25519MLKEM768`) use and that the Tor
Project has begun shipping as an opt-in.

### 4.2. What is not yet post-quantum-secure

| Component | Primitive | PQ risk | Plan |
|---|---|---|---|
| Long-term node identity | Ed25519 | A future quantum adversary could forge node-identity signatures. Cannot retroactively decrypt traffic (per-circuit ephemerals dominate). | Adopt SLH-DSA or ML-DSA hybrid signatures once a stable NIST FIPS draft exists; rotate identity keys. |
| Hidden-service onion address | Ed25519-derived | Quantum adversary could forge a service's descriptor signature → service-impersonation attack. **Cannot retroactively decrypt past sessions** thanks to PQ hybrid handshakes. | Same as above. |
| Consensus signatures | Ed25519 | Same: forged consensus → directory-injection attack. Detectable via out-of-band fingerprint verification. | Hybrid signature on the consensus when PQ-sig standards are stable. |
| Application data | Whatever the application picks | Browser HTTPS is the main concern; TLS 1.3 + X25519MLKEM768 already shipping in modern Firefox. | Documented as the application's responsibility. |

The summary: **session confidentiality is fully post-quantum today.
Long-term-identity unforgeability is not, but the impact is bounded
to active impersonation; recorded traffic stays unreadable.** This
is the same gap every other PQ-transitional protocol faces.

### 4.3. AEAD and hashing

- **AEAD**: ChaCha20-Poly1305 (RFC 8439). Constant-time, 64-byte
  state, no timing side-channels on commodity hardware, no
  AES-NI dependency.
- **Hashing**: BLAKE2b-256 for protocol-internal hashing,
  HKDF-SHA-256 for key derivation (because the HKDF construction
  is widely audited and SHA-256 is a fine PRF).
- **Random**: `crypto.randomBytes` (Node) → `getrandom(2)` (Linux),
  `BCryptGenRandom` (Windows). No userspace PRNG ever.

---

## 5. Architecture summary

```
                  ┌─────────────────────────────┐
   user ──────────│       Anonymous Browser     │
                  │ (Mullvad fork, Safest, +    │
                  │   userChrome.css amber UI)  │
                  └─────────────┬───────────────┘
                                │ http://127.0.0.1:1081/?url=anon://…
                  ┌─────────────▼───────────────┐
                  │   anon-browse-gui bridge    │
                  │ (Node; SOCKS for content,   │
                  │   /api/* for chrome panel)  │
                  └────────┬───────────┬────────┘
        anon://             │           │             tor SOCKS
        rendezvous ─────────┘           └──────────── 9050 (.onion)
        │
        │  (post-quantum hybrid 3-hop circuit)
        │
        ▼
  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
  │  guard   │──▶│  middle  │──▶│  RP/IP   │◀──│ service  │
  └──────────┘   └──────────┘   └──────────┘   └──────────┘
                                  ↑
                          rendezvous splice
                          (4-hop client-side,
                           7 distinct relays total
                           when service-side path
                           is also 3 hops)
```

- **`modules/v2/`** — wire format, cell parsing, crypto primitives, ntor-hybrid handshake.
- **`modules/v2-runtime/`** — circuit builder, rendezvous client, service publisher, descriptor index, HSDir.
- **`modules/v2-site/`** — `text/anon` document format (a deliberately small, no-JS document type for hidden services).
- **`bin/anon-browse-gui.mjs`** — bridge between the browser and the anon-layer runtime; exposes a localhost HTTP UI and JSON API.
- **`browser-fork/`** — Mullvad Browser rebrand + hardening + integration.
- **`browser-fork/launcher-go/`** — Go launcher that boots tor, the bridge, and the browser; in-browser connect UI.
- **`deploy/`** — systemd + nginx + DA artifacts for running a network node.

---

## 6. Operator diversity — the unsolved problem

**The protocol does not produce anonymity. Operator diversity produces
anonymity.** A perfect spec running on 3 relays at one hosting
provider gives users nothing.

The honest assessment of the current testnet:

- **3 relays.** All operated by Anonymous Gratis. All on one set of VPS hosts.
- **Path-diversity rule relaxation (`ALLOW_CO_LOCATED=1`)** is currently set in the bundled config because strict diversity would refuse to build any 3-hop circuit on a 3-relay network. This is a testnet workaround documented in the conf file and the threat model.
- **Anonymity-set size for any current user is bounded by the number of other concurrent users on the same 3 relays.** At this stage that is ≤ tens.

### 6.1. Why count alone is not enough

For a 3-hop circuit through N relays where an adversary controls F·N relays, the probability of compromising *both* the guard and the exit (and therefore correlating circuit endpoints by timing) is approximately F². The relevant numbers:

| Relays controlled by adversary | F | F² (correlation probability) |
|---:|---:|---:|
| 1 of 10 | 10% | **1.0%** |
| 1 of 30 | 3.3% | **0.11%** |
| 1 of 100 | 1% | **0.01%** |
| 10 of 100 | 10% | **1.0%** |
| 5 of 1000 | 0.5% | **0.0025%** |

So a network of 100 well-distributed relays where an adversary can spin up 10 of their own offers about the same per-circuit correlation risk (1%) as Tor under a 10%-adversarial assumption. **The number that matters is the maximum fraction of the network a single adversary can plausibly own — not the absolute relay count.**

But the same 100 relays all hosted on Hetzner in Germany is *worse* than 30 relays distributed across 15 hosting providers in 12 countries. Hetzner sees everything from the upstream; the 12-country setup makes any single observer see only fragments.

### 6.2. Milestone targets

| Stage | Relays | Operators | Jurisdictions | ASes | What it claims |
|---|---:|---:|---:|---:|---|
| **Testnet (today)** | 3 | 1 | 1 | 1 | Protocol works end-to-end. Not anonymity. |
| **Closed alpha** | ≥10 | ≥5 | ≥3 | ≥3 | "Experimental — for protocol feedback only." |
| **v0.1 GA** | ≥30 | ≥15 | ≥6 | ≥10 | "Non-life-critical anonymous use against casual adversaries." |
| **v1.0** | ≥150 | ≥50 | ≥12 | ≥30 | "Anonymity against small nation-state passive collection." |
| **v2.0** | ≥1000 | ≥300 | ≥30 | ≥100 | The word "anonymity" used without caveats. |
| **Tor-comparable** | ~7000 | ~3000 | ~70 | ~700 | Production privacy infrastructure. |

These numbers come from Tor's own deployment history. v1.0-equivalent for Tor was reached around 2007–2010; v2.0-equivalent around 2013–2015. Tor took roughly a decade to reach v2.0. We will not be faster — we will be more honest about where we are along the curve.

### 6.3. How we grow the network

Three pipelines, in increasing order of effort:

1. **University partnerships.** EFF / TorServers' decade-old playbook. CS departments run a relay as a research artefact; we provide the hardening config, systemd unit, monitoring dashboard, and a per-institution descriptor key.
2. **Sponsored relays.** A small number of well-known operators (privacy NGOs, journalist-protection orgs, established VPN providers willing to run a relay outside their commercial product). Diversity by design.
3. **Bring-your-own-relay (BYOR).** Anyone can submit a descriptor and join the consensus. This is the long-tail volume but also the Sybil-attack vector. v0.3 work item: descriptor-level proof of work + operator-signed attestation.

The order matters. We do not open BYOR until the pluggable-transport story (v0.4) is in place — without it, hostile relays can collect timing signatures of every circuit they're on, which is more damaging on a small network than a large one.

---

## 7. Roadmap

### 7.1. Near-term (next ~3 months)

- **External cryptographic audit** of `modules/v2/ntor_hybrid.mjs`, `modules/v2/cells.mjs`, and the rendezvous handshake. Funded via NLnet / OTF / Sovereign Tech Fund applications.
- **Independent reimplementation** in a second language (Rust candidate). A protocol with one implementation is one implementation-bug away from network-wide compromise.
- **Public testnet** with ≥10 operator-diverse relays. Operators recruited from existing relay-runner communities.
- **`docs/SPEC-v0.2.md`** finalised (drop the `-draft` suffix), wire format frozen at v0.2.0.

### 7.2. Medium-term (~6–12 months)

- **v0.1 general availability** of the *protocol* (not the anonymity claim — see §6 for that), tied to ≥30 relays, ≥15 operators, audit complete.
- **Pluggable transports** (v0.4 work) — obfs4/meek-equivalent for censorship resistance.
- **Post-quantum signature scheme** for long-term identity keys, once NIST FIPS 204/205 are stable enough to commit to. Hybrid Ed25519 + ML-DSA most likely.
- **Hardware-signed consensus** — DA signing keys held in HSMs, multi-org governance for the DA-trust set.

### 7.3. Long-term (12+ months)

- **Mix-network traffic shaping** as an opt-in mode for the highest-risk users, at a latency cost. Anti-traffic-confirmation by design.
- **Anti-Sybil via stake / proof-of-uptime / proof-of-bandwidth.** v0.3 / v1.0 work.
- **Browser-level deanonymization hardening** beyond Mullvad/Tor Browser baseline — chrome-side circuit display done, but app-level partitioning, per-tab circuit isolation, and TLS-stack fingerprint masking are open.
- **Mobile clients.** Android first (Mullvad Browser Android is the obvious base), iOS pending the same political question Tor faces.

---

## 8. What this project is, in one sentence

**Anonymous Layer is a pre-audit research artefact attempting to be
the post-quantum, audit-friendly, browser-integrated successor to
Tor — and it will only become that if the spec survives audit, the
implementation survives independent review, the network grows to 30+
operator-diverse relays, and we tell the truth at every step about
where it is on that curve.**

We have not lied to a user yet. We intend to keep that record.

---

## 9. How to help

- **Read the spec.** [`docs/SPEC-v0.2-draft.md`](./SPEC-v0.2-draft.md). File issues against any ambiguity.
- **Run a relay.** See [`docs/RUNNING-A-NODE.md`](./RUNNING-A-NODE.md). Even a single relay on a non-Hetzner / non-OVH / non-US-East-1 host meaningfully improves diversity at this stage.
- **Audit the crypto.** `modules/v2/ntor_hybrid.mjs` is ~200 lines. The handshake is the highest-leverage thing for outside eyes.
- **Reimplement in another language.** A Rust port of `modules/v2/` against `test-vectors/` would let us claim spec-not-implementation-defined behaviour.
- **Donations / funding.** `admin@anon.gratis` (PGP per [`SECURITY.md`](../SECURITY.md)). Audit funding is the gating item.

---

## 10. Where the bodies are buried

Honesty section. Things you should know before deciding whether to
trust this project:

1. **The network is 3 relays.** Until §6's milestones are met, we are protocol research, not infrastructure.
2. **No external audit yet.** Memory-safe languages do not save you from cryptographic bugs.
3. **`ALLOW_CO_LOCATED=1` is the default in the bundled config.** Strict path-diversity would refuse to build any circuit on the current testnet.
4. **One implementation.** A bug in `modules/v2-runtime/circuit_builder.mjs` is a network-wide bug.
5. **DA-trust is operator-curated.** The signed consensus comes from `da1.anon.gratis`, which is operated by Anonymous Gratis. Future versions move to multi-org DA governance; today, this is one server you have to trust.
6. **Identity keys are still Ed25519.** Post-quantum *session* secrecy is real; post-quantum *identity unforgeability* is a future task.
7. **The reference implementation is in JavaScript.** Choice driven by audit-readability (no transpilation, no metaprogramming), not by JavaScript being a good systems language. A Rust port is on the roadmap.

If after reading this you still want to use Anonymous Layer instead
of Tor for actual sensitive work — please don't. Use Tor. Come back
when this document's §6 milestone table is at v1.0 or above and the
audit is published.

---

**Document control**

- This file lives at `docs/WHITEPAPER.md`.
- It is the canonical statement of the project's claims and roadmap. Marketing copy (the website, the social channels) must match this document.
- Material changes require an editor pass against [`SPEC-v0.2-draft.md`](./SPEC-v0.2-draft.md) and [`THREAT_MODEL.md`](./THREAT_MODEL.md). They must not diverge.
- When the spec finalises (`SPEC-v0.2.md`), §3 and §4 of this document update in the same PR.
