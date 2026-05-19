# Audit Preparation — Anonymous Layer

This document captures the state of the codebase as received and the findings
from a comprehension pass (Phase 0 of the production-readiness roadmap). It is
intended for the maintainers, an eventual external auditor, and anyone deciding
whether to deploy this protocol.

**Status as of 2026-05-19:** Pre-spec, pre-audit, pre-threat-model. The
existing implementation is research code. **Do not deploy to real users.**

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

---

## 3. Critical findings (must fix before any deployment)

### C1 — PRNG seeded from `Math.random()`

**Location:** `modules/random/index.mjs:52-55`

The PRNG state is XORed with `Math.random()` (V8's xorshift128+), which is
**not cryptographically secure**. Every ElGamal private exponent, every
Twofish symmetric key, every handshake buffer is derived from this PRNG.

> An attacker who observes a few outputs can predict the state and recover all
> subsequent (and prior) "random" values, including private keys.

**Fix:** Replace `Math.random()` seed source with `crypto.randomBytes` from
Node's `crypto` module. For long-running processes, periodically re-seed.

### C2 — Twofish key schedule in module-level mutable state

**Location:** `modules/cryptography/twofish/index.mjs:256-257`

`KEY_EXPANDED` and `KEY_FULL` are module-scoped `Uint32Array`s. Every call to
`encrypt128` / `decrypt128` / `encrypt128Chain` / `decrypt128Chain` overwrites
them with the schedule derived from the call's key. In an async network
server, two interleaved encryptions on the same Node instance will
**cross-contaminate the key schedules** and produce wrong ciphertext or, worse,
encrypt with a key the caller did not intend.

**Fix:** Move state into per-call local variables, or cache schedules by key
in a `WeakMap`/`Map` keyed by the key buffer.

### C3 — ElGamal is textbook, non-constant-time, no padding, no MAC

**Location:** `modules/cryptography/elgamal/index.mjs`

- `MODULAR_EXPONENTIATION` is a textbook square-and-multiply with a
  data-dependent conditional multiply. **Leaks the private exponent through
  timing** to a local attacker (and likely a remote one via network timing
  given JS BigInt performance variance).
- The encryption is `m × g^xy mod p` with no padding scheme — **multiplicatively
  malleable**, no IND-CPA, no IND-CCA.
- No MAC over ciphertext — the recipient cannot detect tampering. Combined
  with the malleability, an active attacker can transform valid ciphertexts
  into other valid ciphertexts.
- The "safe prime" claim (`p = 2²⁰⁴⁸ − 1942289`) is uncited; needs verification
  that `p` and `(p-1)/2` are both prime and that `g = 2` generates a
  large-order subgroup.

**Fix path (in increasing rigor):**
1. Replace with libsodium's `crypto_box` (X25519 + XSalsa20-Poly1305) or Node's
   `crypto.diffieHellman` + AES-GCM. This is the right answer.
2. If keeping ElGamal for spec reasons: add OAEP-style padding, Encrypt-then-MAC,
   constant-time exponentiation via Montgomery ladder.

### C4 — Custom Twofish "chain" mode is not CTR; deterministic encryption

**Location:** `modules/cryptography/twofish/index.mjs:986-1092`

`encrypt128Chain` is **not standard CTR mode**. For each 16-byte block it
XORs an internal 128-bit counter into the *key* and ECB-encrypts the
plaintext block under that derived key. The counter always starts at 0,
so the same `(key, plaintext)` produces identical ciphertext every time —
**deterministic encryption**, which is fatal for anonymity (an observer can
identify identical messages).

There is also no integrity tag.

**Fix:** Use AES-GCM or ChaCha20-Poly1305 with a unique random nonce per
message. If the Twofish dependency must be preserved (e.g. spec requirement),
use Twofish-CTR with a unique random IV and a separate Poly1305/HMAC tag.

### C5 — Multiplexing primitive is undocumented and unproven

**Location:** `modules/cryptography/multiplexing/index.mjs`

A novel construction with no published basis. The 64-bit "remainder" is below
modern MAC strength thresholds. The intended security property is not stated
anywhere in the repo.

**Fix:** Either remove the primitive, replace with a standard MAC, or
publish a security proof. Pending Phase 2 spec, treat this as "do not rely
on for security."

### C6 — Router does not compile against the current modules

**Location:** `modules/router/index.mjs`

The router imports symbols that **do not exist** in `constants/index.mjs`:

- `TYPE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET`
- `TYPE_COORDINATION_FORWARD_IPV6_WEBSOCKET`
- `OFFSET_FORWARD_IPV6_WEBSOCKET_HOST`
- `OFFSET_FORWARD_IPV6_WEBSOCKET_PORT`

It also constructs packet-text objects with `destination` at the top level
(e.g. `continuousAnnouncePeer`), but the `format/index.mjs` module expects
`text.target.destination`. The router's `HANDLE_*` functions destructure
fields from parsed text that the parser does not produce.

**Conclusion:** The router has never run successfully against the current
format/parse layer. It is dead code in its present state.

**Fix:** Full rewrite in Phase 4. The router test (`modules/router/tests.mjs`)
is disabled in `tests.mjs` until then.

---

## 4. High-severity findings

### H1 — `SEND_ANNOUNCE_PEER` is an empty stub

`modules/router/index.mjs:53` — `const SEND_ANNOUNCE_PEER = (socket, peerData) => {};`

### H2 — Peer-announce records are not authenticated against the announcer

`HANDLE_COORDINATION_ANNOUNCE_PEER_IPV6_WEBSOCKET` accepts the host/port in
the packet without verifying it corresponds to the WebSocket peer that sent
it. Trivial peer-table poisoning.

### H3 — Forward handler is an open SSRF/amplification primitive

`HANDLE_COORDINATION_FORWARD_IPV6_WEBSOCKET` opens an outbound WebSocket to
any IPv6 host:port specified in the packet. No rate limit, no allowlist, no
authentication. An attacker uses your node to attack arbitrary targets.

### H4 — No protocol version field in the wire format

The 256-byte coordination header has no version byte. Future protocol changes
will fork the network with no graceful upgrade path. Reserve bytes now.

### H5 — Packet handler does not validate length before crypto

`router/index.mjs:322-360` decrypts the entire post-header buffer as Twofish
chain regardless of size. Undersized packets cause out-of-bounds reads. Add
strict length validation before dispatch.

### H6 — No memory zeroization

Private exponents, symmetric keys, and shared secrets are written to plain
`Uint8Array`s and left for GC. Sensitive material lingers on the heap and may
be recovered from swap/core dumps. Add `.fill(0)` on dispose.

---

## 5. Medium / dev-experience

- `constants/index.mjs:50` — comment typo: `x⁶64` should be `x^64`.
- `constants/index.mjs:96` — symbol typo: `OFFSET_COORDINAITION_KEY_SENDER`.
- `cryptography/elgamal/tests.mjs:274-275` — tests seed from `Math.random()`,
  so test runs are non-deterministic.
- `router/tests.mjs` — races four servers on port 0 with a 12 s wall-clock
  deadline; flaky on slow CI.
- ~~`package.json` — script is named `"tests"` (plural); standard Node tooling
  expects `"test"`~~. **Fixed** — `npm test` now works; `npm run tests` kept
  as an alias for the README.
- **Dev-dependency advisories (informational):** `npm audit` reports high-
  severity issues in mocha's transitive deps (`serialize-javascript`,
  `minimatch`, `diff`). These do not ship to production. CI audits
  `--omit=dev` for failure-gating and runs a separate informational dev-dep
  audit. Re-evaluate when mocha publishes a release with a clean tree.

---

## 6. Missing features (Phase 4 backlog)

Not bugs, but gaps before the system is a usable anonymity tool:

- Client (today, only relays talk to each other)
- Peer bootstrap (peers must be added manually)
- On-disk key persistence (identity regenerates per process)
- Exit/entry/middle role distinction
- NAT traversal
- Transport obfuscation (this protocol is trivially DPI-fingerprinted today)
- Version negotiation
- Directory authorities / consensus mechanism
- Bandwidth accounting / fair scheduling
- Anti-sybil measures

---

## 7. What an auditor needs from us before they will engage

Most reputable cryptographic auditors (NCC Group, Trail of Bits, Cure53,
Quarkslab) will refuse or heavily discount engagements at this state. The
critical findings above are "you can fix this in an afternoon" issues; an
auditor's report would consist of those findings and little else, which is
not a useful spend of audit budget.

Before engaging an auditor, this project needs:

1. **A protocol specification** (Phase 2 of our roadmap). Wire format,
   cryptographic primitives, key derivation, packet flow, error handling.
2. **A threat model** (Phase 3). What we claim to defend against and what
   we don't.
3. **C1–C6 fixed** and the test suite re-enabled in full, with CI green.
4. **A code freeze branch** for the audit, with a clear scope statement.

Estimated audit budget for a project of this size, once ready: **USD
$50,000–$200,000** depending on auditor and scope. Audit cycles are 6–12
weeks plus remediation.

---

## 8. Recommendation

If the goal is "production-grade anonymity for at-risk users" — the stated
target — this project is **9–18 months** away from being a defensible
deliverable. Anyone proposing a shorter timeline is either underestimating
the work or planning to ship something that will get its users hurt.

If the timeline cannot accommodate that, the responsible alternatives are:

- **Ship clearly-labelled experimental testnet** for researchers only.
- **Recommend Tor / I2P / Mullvad** to at-risk users while this matures.
- **Sponsor this protocol as long-term R&D**, not a product.

These are not failures; they are the honest paths.
