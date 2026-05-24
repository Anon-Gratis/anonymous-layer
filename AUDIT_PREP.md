# Audit Preparation — Anonymous Layer

This document captures the state of the codebase as received and the findings
from a comprehension pass (Phase 0 of the production-readiness roadmap). It is
intended for the maintainers, an eventual external auditor, and anyone deciding
whether to deploy this protocol.

**Status as of 2026-05-20:** Spec v0.1 draft + threat model v0.1 draft are
in `docs/`. Phase 4 (reference implementation against the v0.1 spec) is
substantially complete: 154 passing tests covering crypto primitives, wire
format, coordination packets, peer discovery, and end-to-end node behaviour.
The legacy pre-spec implementation has been deleted (chunk 4.8), which
closes findings C1, C2, C3, C4, C5, and C6 by removal. Findings H1-H5 are
closed by the new implementation; H6 is partial. The protocol still has
**not been externally audited.** WebSocket transport, key persistence,
and a CLI/daemon are not yet implemented. **Do not deploy to real users.**

---

## 1. What this project is

A from-scratch anonymity-network protocol pitched as a Tor alternative,
authored by a pseudonymous developer (`wellbehaveddemon@proton.me` per the
README). The protocol consists of:

- Hand-rolled ElGamal-2048 over the safe prime `p = 2²⁰⁴⁸ − 1942289`, generator `g = 2`.
- Twofish-128 (reference implementation from Schneier's paper) plus a custom block-chaining mode.
- A custom "multiplexing" primitive that matches handshake buffers against
  `(sharedSecret, remainder)` pairs via XOR and polynomial reduction.
- A 256-byte coordination-packet header with fixed offsets and a 17-bit
  CRC-style polynomial checksum.
- A WebSocket-based node that broadcasts peer-announce messages every 750 ms
  in a least-announced round-robin, aiming for a fully-connected graph.

Repo entry points: `npm run tests` (mocha). No CLI, no daemon, no client, no
bootstrap, no key persistence, no spec, no threat model.

---

## 2. Baseline test status

Initial state: **the test suite fails to load** because of a missing export
and inconsistent module boundaries.

After the minimum unblock (commit `a66bea0`):
- **12 tests pass** across 7 module-level test files.
- The **router test is disabled** — the router module is broken against the
  current `constants` and `format/parse` modules (see C6).

**Post-Phase-4 (2026-05-20):**
- **154 tests pass** across `crypto/`, `wire/`, `peer/`, and `node/`.
- Legacy modules (`cryptography/`, `packets/`, `random/`, `router/`,
  `utilities/`, `constants/`) have been deleted. The new router
  (`modules/node/`) is fully wired and tested end-to-end with in-memory
  transports.

---

## 3. Critical findings (must fix before any deployment)

### C1 — PRNG seeded from `Math.random()`

**STATUS: CLOSED** (2026-05-20, chunk 4.8). The `modules/random/` module
has been deleted. The new implementation uses Node's `crypto.randomBytes`
/ `crypto.randomFillSync` directly (in `modules/crypto/onion.mjs` for
nonces) and `@noble/curves` / `@noble/hashes` (which use the same CSPRNG
internally) for all key material. No `Math.random()` seed source exists
in the reference code.

**Original finding:**

**Location:** `modules/random/index.mjs:52-55` *(deleted)*

The PRNG state was XORed with `Math.random()` (V8's xorshift128+), which is
**not cryptographically secure**. Every ElGamal private exponent, every
Twofish symmetric key, every handshake buffer was derived from this PRNG.

> An attacker who observes a few outputs can predict the state and recover all
> subsequent (and prior) "random" values, including private keys.

### C2 — Twofish key schedule in module-level mutable state

**STATUS: CLOSED** (2026-05-20, chunk 4.8). The `modules/cryptography/`
tree has been deleted. The v0.1 spec uses ChaCha20-Poly1305 via Node's
`crypto.createCipheriv` (in `modules/crypto/onion.mjs`), which keeps all
state local to each cipher instance — concurrent encryptions cannot cross-
contaminate.

**Original finding:**

**Location:** `modules/cryptography/twofish/index.mjs:256-257` *(deleted)*

`KEY_EXPANDED` and `KEY_FULL` were module-scoped `Uint32Array`s. Every call to
`encrypt128` / `decrypt128` / `encrypt128Chain` / `decrypt128Chain` overwrote
them with the schedule derived from the call's key. In an async network
server, two interleaved encryptions on the same Node instance would
**cross-contaminate the key schedules** and produce wrong ciphertext or, worse,
encrypt with a key the caller did not intend.

### C3 — ElGamal is textbook, non-constant-time, no padding, no MAC

**STATUS: CLOSED** (2026-05-20, chunks 4.2 + 4.8). Hand-rolled ElGamal has
been replaced with **X25519** key agreement (via `@noble/curves`, which is
constant-time by construction) + **ChaCha20-Poly1305** AEAD (via Node's
`crypto.createCipheriv`). See `modules/crypto/onion.mjs`. The v0.1 wire
format (SPEC § 5) carries an authenticated tag and a fresh per-packet
ephemeral key, so the original malleability and authenticity gaps are
gone. The 2048-bit BigInt-modexp code has been deleted.

**Original finding:**

**Location:** `modules/cryptography/elgamal/index.mjs` *(deleted)*

- `MODULAR_EXPONENTIATION` was a textbook square-and-multiply with a
  data-dependent conditional multiply. **Leaked the private exponent through
  timing** to a local attacker (and likely a remote one via network timing
  given JS BigInt performance variance).
- The encryption was `m × g^xy mod p` with no padding scheme — **multiplicatively
  malleable**, no IND-CPA, no IND-CCA.
- No MAC over ciphertext — the recipient could not detect tampering. Combined
  with the malleability, an active attacker could transform valid ciphertexts
  into other valid ciphertexts.
- The "safe prime" claim (`p = 2²⁰⁴⁸ − 1942289`) was uncited.

### C4 — Custom Twofish "chain" mode is not CTR; deterministic encryption

**STATUS: CLOSED** (2026-05-20, chunks 4.2 + 4.8). The custom chain mode
has been deleted along with the rest of `modules/cryptography/`. The new
wire path uses ChaCha20-Poly1305 with a fresh 12-byte random nonce per
packet (SPEC § 5.3 step 5; implemented in `encodePacket` via
`generateNonce`). The "each encode produces a fresh ephemeral key and a
fresh nonce" wire-level test (`modules/wire/tests.mjs`) pins this: two
encodes of identical plaintext produce distinct ciphertexts.

**Original finding:**

**Location:** `modules/cryptography/twofish/index.mjs:986-1092` *(deleted)*

`encrypt128Chain` was **not standard CTR mode**. For each 16-byte block it
XORed an internal 128-bit counter into the *key* and ECB-encrypted the
plaintext block under that derived key. The counter always started at 0,
so the same `(key, plaintext)` produced identical ciphertext every time —
**deterministic encryption**, which is fatal for anonymity (an observer can
identify identical messages). There was also no integrity tag.

### C5 — Multiplexing primitive is undocumented and unproven

**STATUS: CLOSED** (2026-05-20, chunks 4.2 + 4.8). The multiplexing
primitive has been deleted. The v0.1 wire format does not carry it
forward — recipient identification is done by an 8-byte fingerprint
prefix (SPEC § 5.2), and authentication is provided by Poly1305 over the
outer header as AAD (SPEC § 5.5). No novel constructions remain.

**Original finding:**

**Location:** `modules/cryptography/multiplexing/index.mjs` *(deleted)*

A novel construction with no published basis. The 64-bit "remainder" was below
modern MAC strength thresholds. The intended security property was not stated
anywhere in the repo.

### C6 — Router does not compile against the current modules

**STATUS: CLOSED** (2026-05-20, chunks 4.5 + 4.8). The pre-spec
`modules/router/` has been deleted. The replacement
`modules/node/` is fully wired and tested end-to-end with in-memory
transports: dispatcher (`dispatcher.mjs`), node assembly (`node.mjs`),
identity management (`identity.mjs`), and identity cache
(`identity_cache.mjs`). Integration tests cover DATA exchange,
KEY_CERTIFICATE handshake, ANNOUNCE_PEER gossip, FORWARD relay, and
silent-drop / eviction policy. WebSocket transport is not yet
implemented — only the in-memory transport pair (`transport_inmemory.mjs`)
is shipped.

**Original finding:**

**Location:** `modules/router/index.mjs` *(deleted)*

The router imported symbols that did not exist in `constants/index.mjs`
and constructed packet-text objects with a schema inconsistent with
`format/index.mjs`. The router had never run successfully against the
format/parse layer it shipped with.

---

## 4. High-severity findings

### H1 — `SEND_ANNOUNCE_PEER` is an empty stub

**STATUS: CLOSED** (2026-05-20, chunk 4.5). Replaced by `sendAnnouncePeer`
in `modules/node/node.mjs`. The three-node gossip integration test
(`modules/node/tests.mjs`) exercises the full path: tick scheduler →
`planAnnounces` → encode → transmit → recipient verifies and updates
peer table.

**Original:** `modules/router/index.mjs:53` *(deleted)* — `const SEND_ANNOUNCE_PEER = (socket, peerData) => {};`

### H2 — Peer-announce records are not authenticated against the announcer

**STATUS: CLOSED** (2026-05-20, chunks 4.3 + 4.5). `verifyAnnouncePeer`
in `modules/wire/announce.mjs` requires `H(announcedIdPk) ==
announcedFingerprint` AND a valid certificate signature under
`announcedIdPk`. The dispatcher only accepts ANNOUNCE_PEER for peers
whose `idPk` it already knows via a prior KEY_CERTIFICATE (SPEC § 6.6).
Unverifiable announces are silently dropped, not cached.

**Original:** `HANDLE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET` *(deleted)*
accepted the host/port in the packet without verifying it corresponded to
the WebSocket peer that sent it.

### H3 — Forward handler is an open SSRF/amplification primitive

**STATUS: CLOSED** (2026-05-20, chunk 4.3). `modules/wire/forward_rate_limit.mjs`
implements the three sliding-window limits from SPEC § 6.5.1 (32 per source
ephemeral key / 60s; 64 per destination fingerprint / 60s; 4096 global / 60s).
The dispatcher runs the rate-limit check before any further work
(`modules/node/dispatcher.mjs`). The unit tests in `modules/wire/tests-types.mjs`
verify each limit and the "rejected requests do not consume budget"
property. Additionally, v0.1 forwarders only dial peers already in their
peer table — there is no path for an attacker to inject an arbitrary
host:port as a forward destination.

**Original:** `HANDLE_COORDINATION_FORWARD_IPV6_WEBSOCKET` *(deleted)* opened
an outbound WebSocket to any IPv6 host:port specified in the packet.

### H4 — No protocol version field in the wire format

**STATUS: CLOSED** (2026-05-20, chunk 4.2). The v0.1 outer header carries
a 1-byte `version` field at offset 0 (`modules/wire/constants.mjs`,
`WIRE_VERSION = 0x01`). The receive path rejects any packet whose
version byte is not `0x01` (`modules/wire/packet.mjs` step 2). SPEC
§ 10 defines compatibility and negotiation rules.

### H5 — Packet handler does not validate length before crypto

**STATUS: CLOSED** (2026-05-20, chunk 4.2). SPEC § 5.7 step 1 rejects any
packet whose wire length is not exactly 256, 1024, or 4096 bytes —
checked before any X25519 operation in `decodePacket`. Bucket-vs-length
consistency is enforced in step 3.

### H6 — No memory zeroization

**STATUS: CLOSED** (2026-05-20, chunk 5). Zeroization is now
consistent across the library. See `modules/crypto/zeroize.mjs` for
the lifetime contract. Summary:

**Zeroed by the library:**

- Sender ephemeral X25519 secret key, after AEAD output is built
  (`modules/wire/packet.mjs::encodePacket`).
- X25519 shared secret + derived AEAD key, after the AEAD step, on
  both send and receive (`modules/wire/packet.mjs`).
- Peer record fields (`idPk`, `fingerprint`, `certBytes`, `onionPk`,
  per-transport `address`) on eviction via `remove`,
  `markInnerValidationFailed`, or `prune` (`modules/peer/table.mjs`).
- AEAD output buffers are copies, not aliases — `aeadEncrypt` /
  `aeadDecrypt` use `Uint8Array.from(Buffer)` rather than wrapping
  the underlying Buffer-pool memory, so callers that mutate or
  retain the slice cannot collide with other pool consumers.

**Intentionally retained for process lifetime:**

- Node identity (`idSk`, `onionSk`) — must live as long as the node
  serves traffic. On-disk persistence file (`identity.key`) is
  written with mode `0600` and atomic-rename via
  `modules/node/persistence.mjs`.

**Caller responsibility (documented but not enforced):**

- Plaintext buffer handed to `encodePacket` — caller may zero on
  return.
- `onData` callback's `payload` Uint8Array — application layer owns
  the receive-plaintext lifetime.

V8 + the kernel determine when freed memory is reclaimed and whether
it is scrubbed. Zeroization here narrows the window during which
sensitive bytes are reachable from JS land; it does not turn
userspace into a secure enclave.

---

## 4a. Known v0.1 timing leak (§ 9.2 partial-compliance)

The SPEC § 9.2 constant-time requirement is **not fully satisfied** in
the current implementation. `decodePacket` short-circuits on pre-AEAD
failures, producing observable timing differences. Measurement
(`bench/timing.mjs`, 2000 iterations, Node v20.20.1, Linux):

| Outcome                  | p50    | p95    | p99    |
|--------------------------|-------:|-------:|-------:|
| success                  | 5680 µs | 8385 µs | 9601 µs |
| AEAD tamper              | 5647 µs | 8118 µs | 9133 µs |
| replay                   | 5285 µs | 7724 µs | 8916 µs |
| prefix mismatch          |   42 µs |   73 µs |   86 µs |
| wrong version            |    8 µs |   14 µs |   28 µs |
| bucket-length mismatch   |    7 µs |   10 µs |   14 µs |
| wrong length             |  0.3 µs |  0.4 µs |  0.5 µs |

**Risks:**

- **Success / AEAD-tamper / replay are statistically indistinguishable**
  (p50 within ~7%). § 9.2's *primary* concern — that an active attacker
  cannot tell whether their tampered packet hit a valid recipient — is
  satisfied for the post-AEAD outcomes.
- **Prefix-mismatch leaks identity.** An attacker who can measure
  drop-handling time (e.g. via subsequent legitimate-traffic timing on
  the same transport connection) can probe whether a given fingerprint
  prefix belongs to this node. SPEC § 5.7 step 4 explicitly labels the
  prefix filter as an optimisation, not a security check — but does
  not anticipate this anonymity-relevant timing channel.
- Steps 1-3 (length / version / bucket) leak nothing additional: those
  fields are pre-shared knowledge an attacker has from the wire spec.

**Recommendation (Phase 5):** add a constant-time blinding delay on the
prefix-mismatch path to match the slow-path median (≈ 5500 µs). The
simpler "always run AEAD" approach is not viable for wrong-length
inputs (AEAD expects bucket-aligned data) but is viable for prefix
mismatch — pad the rejection path by performing a dummy X25519 against
a stored decoy secret and a dummy AEAD against junk.

This is documented as a known v0.1 limitation; deployments must
assume an attacker can de-anonymise nodes by timed probing until this
is closed.

## 5. Medium / dev-experience

All items below are about modules that no longer exist:

- ~~`constants/index.mjs:50` — comment typo `x⁶64` should be `x^64`.~~ **Moot — module deleted.**
- ~~`constants/index.mjs:96` — symbol typo `OFFSET_COORDINAITION_KEY_SENDER`.~~ **Moot — module deleted.**
- ~~`cryptography/elgamal/tests.mjs:274-275` — non-deterministic test seed.~~ **Moot — module deleted.**
- ~~`router/tests.mjs` — flaky 12s deadline races.~~ **Moot — module deleted; new node tests use deterministic in-memory transports.**
- ~~`package.json` — script renamed.~~ **Fixed** — `npm test` works.
- **Dev-dependency advisories (informational):** `npm audit` reports high-
  severity issues in mocha's transitive deps. These do not ship to
  production. Re-evaluate when mocha publishes a release with a clean tree.

---

## 6. Missing features

Not bugs, but gaps before the system is a usable anonymity tool. Phase 4
closed several; the remainder are Phase 5+ work.

**Closed in Phase 4:**

- ~~Client (today, only relays talk to each other)~~ — `node.send()` and
  `onData` callback in `modules/node/node.mjs` are the client API.
- ~~Peer bootstrap (peers must be added manually)~~ — `modules/peer/bootstrap.mjs`
  + seed-list codec (`modules/peer/seed.mjs`) per SPEC § 7.
- ~~Version negotiation~~ — wire version byte + SPEC § 10. (Cross-version
  negotiation rules specified; only v0.1 currently implemented, so
  there's nothing to negotiate against yet.)

**Still missing (Phase 5+ backlog):**

- WebSocket transport — the current `Transport` interface is satisfied
  only by the in-memory test transport. Adapting `ws` to it is a small
  module; the spec-defined wire format is transport-agnostic.
- On-disk key persistence — identity regenerates per process. Format
  TBD (likely just the 64 bytes of `idSk ‖ onionSk`).
- CLI / daemon entry point — no `bin/` yet.
- Exit/entry/middle role distinction — v0.1 forwarders are uniform.
- NAT traversal.
- Transport obfuscation — the wire format is trivially DPI-fingerprintable
  (fixed-size buckets, distinctive prefix).
- Directory authorities / consensus mechanism — v0.1 is gossip-only.
- Bandwidth accounting / fair scheduling.
- Anti-Sybil measures — explicitly out-of-scope for v0.1 per SPEC § 7.5.

---

## 7. What an auditor needs from us before they will engage

**Status as of 2026-05-20:**

1. ✅ **Protocol specification** — `docs/SPEC.md` v0.1 draft, 1268 lines.
2. ✅ **Threat model** — `docs/THREAT_MODEL.md` v0.1 draft, 573 lines.
3. ✅ **C1–C6 fixed** (by replacement with X25519 + ChaCha20-Poly1305 and
   wholesale deletion of the legacy code). 154 tests passing.
4. ⬜ **Code freeze branch** — not yet established. Recommended once
   WebSocket transport + key persistence land in Phase 5.

Before engaging an auditor we additionally recommend:

- A second independent review of the v0.1 spec by a cryptographer
  unaffiliated with the authors — cheap and catches issues an
  implementation auditor would flag at high cost.
- A test-coverage pass that adds property-based tests (e.g.
  `fast-check`) for the wire format — current tests are example-based.
- A documented threat-model walkthrough for each of the C1–C6
  closures, explaining why the *replacement* is sound, not just that
  the original was broken.

Estimated audit budget for a project of this size, once ready: **USD
$50,000–$200,000** depending on auditor and scope. Audit cycles are 6–12
weeks plus remediation.

---

## 8. Recommendation

**Updated 2026-05-20.** Phase 4 has closed every critical and high-
severity finding from the original audit pass. The reference
implementation now matches the v0.1 spec end-to-end (in-memory). The
remaining gap to "production-grade anonymity for at-risk users" is:

1. **WebSocket transport + CLI** — engineering, no novel decisions.
2. **External cryptographic audit** of `docs/SPEC.md` v0.1 and the
   `modules/{crypto,wire,peer,node}/` implementation. The v0.1
   construction is plain X25519 + ChaCha20-Poly1305 + Ed25519 + Blake2b
   over a small wire format; an audit at this state is meaningful work
   rather than a list of "obviously broken" items.
3. **Independent review of the threat model.** v0.1 documents narrow
   anonymity claims (sender/receiver unlinkability for short messages
   over a one-hop overlay) and is explicit about what it does not
   provide (multi-hop circuits, intersection-attack resistance,
   anti-Sybil). The threat model should be challenged by a reviewer
   outside the project before users see those claims.
4. **At-risk users should still use Tor today.** v0.1 is now defensibly
   *implemented* but not yet *audited*. The README's experimental-
   status warning remains correct until an audit cycle completes.

The path from here is roughly: WebSocket + persistence + CLI (weeks) →
external review (months) → audit cycle 6-12 weeks → remediation →
public testnet → at-risk-user readiness.

The responsible alternatives while that runs remain:

- **Ship clearly-labelled experimental testnet** for researchers only.
- **Recommend Tor / I2P / Mullvad** to at-risk users while this matures.
- **Sponsor this protocol as long-term R&D**, not a product.

These are not failures; they are the honest paths.
