# Anonymous Layer Protocol Specification — v0.2 (draft)

| | |
|---|---|
| **Document** | Anonymous Layer Protocol Specification |
| **Version** | 0.2 (early draft) |
| **Date** | 2026-05-20 |
| **Status** | **EARLY DRAFT — architectural decisions only. Wire formats and exact byte offsets to be finalised before reference implementation begins.** |
| **Editor** | Anonymous Gratis `<admin@anon.gratis>` |
| **License** | AGPL-3.0-or-later |

> This document defines the protocol changes that distinguish v0.2 from
> v0.1 ([`SPEC.md`](./SPEC.md)). v0.2 is **wire-format-incompatible
> with v0.1**: it adds multi-hop circuits, fixed-size cells, streams
> over circuits, exit policy, and hidden services. Read this document
> alongside the v0.1 spec and the v0.1 threat model
> ([`THREAT_MODEL.md`](./THREAT_MODEL.md)); v0.2 supersedes both where
> it conflicts, and inherits where it does not.
>
> **The reference implementation for v0.2 does not yet exist.** This
> document is the design contract that the implementation will be
> built against, in the same order v0.1 was built: spec → threat model
> → reference implementation → external audit → testnet → release.

---

## Table of contents

1. [Introduction](#1-introduction)
2. [Relationship to v0.1](#2-relationship-to-v01)
3. [Cryptographic primitives](#3-cryptographic-primitives)
4. [Identity](#4-identity)
5. [Cell format](#5-cell-format)
6. [Circuit construction](#6-circuit-construction)
7. [Streams over circuits](#7-streams-over-circuits)
8. [Exit policy](#8-exit-policy)
9. [Hidden services](#9-hidden-services)
10. [Directory and consensus](#10-directory-and-consensus)
11. [Link transport](#11-link-transport)
12. [Error handling](#12-error-handling)
13. [Migration from v0.1](#13-migration-from-v01)
14. [Security considerations](#14-security-considerations)
15. [Appendix A: Design decisions ledger](#15-appendix-a-design-decisions-ledger)
16. [Appendix B: Open research questions](#16-appendix-b-open-research-questions)

---

## 1. Introduction

### 1.1. Purpose

v0.2 of the Anonymous Layer protocol provides:

- **Sender / receiver unlinkability over multi-hop circuits.** A
  passive observer at any single relay learns at most one neighbour
  in the circuit, not the full path.
- **Sender anonymity from the receiver, even when the receiver is on
  the public internet.** v0.1 only provided sender anonymity from
  network observers between sender and forwarder; v0.2 supports
  exit-node forwarding to arbitrary clearnet destinations.
- **Receiver anonymity ("hidden services").** A receiver can publish
  a stable identifier (an *onion address*) that resolves to a
  rendezvous point without exposing the receiver's network location.
- **Stream multiplexing.** A single circuit carries many concurrent
  application streams without re-doing the path-setup work.

### 1.2. Non-goals (still out of scope in v0.2)

The following remain out of scope and require future work:

- **Anti-Sybil at the protocol level.** Operators still size their
  directory / seed list such that Sybil populations cannot dominate
  any honest user's circuit selection. v0.3 may address this.
- **Censorship resistance / pluggable transports.** v0.2 cells are
  trivially DPI-fingerprintable. Anti-censorship is a transport-layer
  concern (the equivalent of obfs4, meek, snowflake) and a future
  document will define a pluggable-transport interface.
- **Defence against a global passive adversary.** As with Tor, v0.2
  does not defend against an attacker who can observe a substantial
  fraction of all relay traffic simultaneously. Traffic-analysis
  resistance (mix-network style) is out of scope.
- **Browser-grade anonymity guarantees.** Browser fingerprinting,
  JavaScript-mediated identity leaks, and DNS resolution behaviour
  are all the responsibility of the application layer (the browser),
  not the network protocol. This document defines the *transport*
  guarantees; a browser running over v0.2 still needs Tor-Browser-
  equivalent hardening.
- **Forward secrecy for long-term identity keys.** The Ed25519
  identity key is long-lived; if compromised, an attacker can
  retroactively impersonate the node (cannot decrypt past traffic
  thanks to per-circuit ephemerals, but can sign forged descriptors).
  This matches Tor's model.

### 1.3. Relationship to v0.1

v0.2 is **wire-incompatible** with v0.1:

- The packet's outer-header version byte is `0x02` instead of `0x01`.
- v0.1 nodes drop v0.2 packets at SPEC § 5.7 step 2 (version check).
- v0.2 nodes drop v0.1 packets the same way.
- A node MAY implement both versions and dispatch by version byte,
  but this document does not specify the dispatching rules. In
  practice, v0.2 supersedes v0.1 entirely and operators are expected
  to migrate.

### 1.4. Conformance

Same conventions as v0.1 § 2.1: **MUST / MUST NOT / SHOULD / SHOULD NOT
/ MAY** as in RFC 2119. All multi-byte integers are big-endian unless
stated otherwise.

---

## 2. Relationship to v0.1

### 2.1. What v0.2 keeps unchanged from v0.1

- **Cryptographic primitives** (§ 3 below): X25519, ChaCha20-Poly1305,
  Ed25519, Blake2b-256, HKDF-SHA-256.
- **Node identity** (§ 4 below): Ed25519 long-term + X25519 onion +
  Blake2b-256 fingerprint.
- **Key certificate format** (§ 4.4 of v0.1 — 105-byte certificate).
- **Silent-drop discipline** (v0.1 § 9): all receive-path failures
  drop without an observable response.
- **Peer-table eviction asymmetry** (v0.1 § 7.4): pre-cryptographic
  failures MUST NOT cause peer eviction.

### 2.2. What v0.2 changes

- **Wire format.** Single-AEAD 54-byte-header packets (v0.1 § 5.2)
  are replaced by fixed-size cells (§ 5 below). Cells carry
  layered encryption for multi-hop delivery.
- **Forwarding.** v0.1's single-hop `FORWARD` packet (v0.1 § 6.5) is
  replaced by source-routed multi-hop circuits (§ 6 below).
- **Coordination packet types.** v0.1 `DATA` / `ANNOUNCE_PEER` /
  `FORWARD` / `KEY_CERTIFICATE` are replaced by *cell commands*
  (§ 5.3 below). `KEY_CERTIFICATE` survives in spirit as the
  service-descriptor mechanism; `ANNOUNCE_PEER` survives in the
  directory protocol (§ 10).

### 2.3. v0.2 inherits all of v0.1's known limitations except those
explicitly closed.

The v0.1 timing leak documented in `AUDIT_PREP.md § 4a` (prefix-match
short-circuit) **survives into v0.2** unless explicitly addressed. The
v0.2 wire format has no prefix-filter optimisation, so the original
short-circuit doesn't exist — but other early-failure paths (cell
length, version) are still observably faster than full AEAD failure.
Phase-5 blinding-delay work is carried into v0.2.

---

## 3. Cryptographic primitives

Inherited unchanged from v0.1 § 3 except as noted.

### 3.1–3.6 (unchanged)

X25519, ChaCha20-Poly1305, Blake2b-256, HKDF-SHA-256, Ed25519 are used
exactly as in v0.1.

### 3.7. Circuit-handshake (hybrid X25519 + ML-KEM-768 ntor)

Each hop in a circuit derives session keys via a **hybrid
one-way-authenticated handshake** combining classical X25519 key
agreement (ntor; Goldberg, Stebila, Ustaoglu, 2013) with post-quantum
ML-KEM-768 encapsulation (FIPS 203, formerly Kyber-768).

The hybrid construction protects against two distinct threats:

- **Classical adversary** (today): equivalent to plain ntor — only the
  ML-KEM half is "extra," and any cryptanalytic break of ML-KEM does
  not weaken the classical guarantee.
- **Quantum adversary** ("harvest-now-decrypt-later"): if a future
  cryptographically-relevant quantum computer recovers the X25519
  shared secrets via Shor's algorithm, the ML-KEM shared secret still
  protects the session.

Compromise of the session requires breaking BOTH primitives.

```
Client (sender):
    x  = RAND(32); X    = X25519_scalarmult_base(x)
    (K_pk, K_sk) = ML-KEM-768.KeyGen()
    send (X || K_pk) to relay R                  // 32 + 1184 = 1216 bytes

Relay R (with identity-onion key (B_sk, B_pk)):
    y  = RAND(32); Y    = X25519_scalarmult_base(y)
    (ct, shared_pq) = ML-KEM-768.Encaps(K_pk)    // ct: 1088 bytes; shared_pq: 32 bytes
    shared_x_y      = X25519(y, X)               // 32 bytes
    shared_b_x      = X25519(B_sk, X)            // 32 bytes
    secret_input    = shared_x_y || shared_b_x || shared_pq
                    || ID_R || B_pk || X || K_pk || Y || ct || PROTOID
    KEY_SEED        = HKDF-Extract(KEY_SEED_INFO, secret_input)
    auth_input      = secret_input || ID_R || B_pk || Y || ct || PROTOID || "Server"
    AUTH            = HKDF-Extract(AUTH_INFO, auth_input)
    send (Y || ct || AUTH) to client             // 32 + 1088 + 32 = 1152 bytes

Client:
    shared_pq     = ML-KEM-768.Decaps(K_sk, ct)
    shared_x_y    = X25519(x, Y)
    shared_b_x    = X25519(x, B_pk)
    secret_input  = shared_x_y || shared_b_x || shared_pq
                  || ID_R || B_pk || X || K_pk || Y || ct || PROTOID
    KEY_SEED      = HKDF-Extract(KEY_SEED_INFO, secret_input)
    auth_input    = secret_input || ID_R || B_pk || Y || ct || PROTOID || "Server"
    AUTH'         = HKDF-Extract(AUTH_INFO, auth_input)
    verify constant-time AUTH == AUTH'           // abort circuit on mismatch
    derive (Kf, Kb, Kdf, Kdb) from KEY_SEED via HKDF-Expand
```

Where:

- `B_pk` is the relay's **identity-onion public key** — see § 4.2.
- `ID_R` is the relay's Blake2b-256 fingerprint.
- `PROTOID = "anon-layer-pq-ntor-v1"` (ASCII).
- `KEY_SEED_INFO = "anon-layer/v2/pq-handshake-extract"`.
- `AUTH_INFO = "anon-layer/v2/pq-handshake-auth"`.

`Kf` and `Kb` are the **forward** and **backward** ChaCha20 stream-
cipher keys (32 bytes each). `Kdf` and `Kdb` seed the running BLAKE2b
digest states (§ 5.4.2). The relay verifies nothing about the client's
identity at handshake time — the client is anonymous to the relay by
design. Authentication of senders, where required, happens at the
application layer.

> **Design decision (v0.2):** The hybrid construction inserts the
> ML-KEM shared secret into `secret_input` between the two X25519
> shared secrets and the contextual identity material. KEY_SEED is
> derived from BOTH shared secrets; an attacker who breaks only one
> primitive cannot recover the session keys.

> **Design decision (v0.2):** ML-KEM-768 over ML-KEM-512 / ML-KEM-1024.
> ML-KEM-768 targets NIST Category 3 (≈AES-192) which exceeds
> ChaCha20's 256-bit key material's post-Grover residual security
> (128 bits). ML-KEM-512 would be sufficient but offers less margin.
> ML-KEM-1024 adds bytes without meaningful security improvement at
> the symmetric-baseline we're paired with.

> **Implication for wire format:** the 1216-byte client message and
> 1152-byte relay message do NOT fit in a single 508-byte cell payload.
> The handshake is therefore carried across **multiple cells** using
> the fragmentation encoding defined in § 6.2.1.

---

## 4. Identity

### 4.1. Node identity (unchanged from v0.1)

Each node has an **Ed25519 identity keypair** `(ID_sk, ID_pk)`,
long-lived. The node's **fingerprint** is `Blake2b-256(ID_pk)`.

### 4.2. Identity-onion key (RENAMED from v0.1's "onion key")

Each node has an **X25519 identity-onion keypair**
`(IDOnion_sk, IDOnion_pk)`. This is the key used in the ntor
handshake (§ 3.7). It MUST be rotated periodically; SHOULD be rotated
at least every 30 days. The current key is published in the node's
key certificate (v0.1 § 4.4 format, unchanged).

The v0.1 onion key and v0.2 identity-onion key are the same field
in practice; v0.2 renames it for clarity — in v0.1 the onion key was
a one-shot per-packet handshake target, in v0.2 it is the relay-side
input to the ntor handshake at circuit-construction time.

### 4.3. Service identity (NEW)

A **hidden service** publishes a separate Ed25519 keypair
`(SVC_sk, SVC_pk)`. This is the service's *long-term* identity,
analogous to a Tor v3 hidden-service master key. The service identity:

- MUST be distinct from any node-identity key. A node MAY host a
  service, but the service's identity is not bound to that node.
- Is the input to the **onion address** (§ 4.4).
- Signs **service descriptors** (§ 9.1) which point to introduction
  points.

### 4.4. Onion address (NEW)

The on-disk / on-screen address of a hidden service is:

```
onion_address = base32(SVC_pk || CHECKSUM || VERSION) + ".anon"
```

Where:

- `SVC_pk` is 32 bytes (Ed25519 public key).
- `CHECKSUM = Blake2b-256(".anon-checksum" || SVC_pk || VERSION)[0:2]`.
- `VERSION = 0x02`.
- Total: 35 bytes → base32 → 56 characters + `.anon` suffix.

> **Design decision (v0.2):** the 35-byte / 56-char format matches Tor
> v3 onion-address sizing. `.anon` distinguishes our addresses from
> Tor's `.onion`. Tooling that needs to disambiguate can check the
> suffix; DNS does not resolve `.anon` so leakage to clearnet DNS is
> non-functional, not anonymity-fatal.

### 4.5. Out-of-band identity verification (unchanged from v0.1)

Operators distribute their fingerprint / their service's onion
address over the same out-of-band channels as v0.1. No protocol-level
anchor signing.

---

## 5. Cell format

### 5.1. Fixed cell size

Every v0.2 cell on the wire is **exactly 514 bytes**. This matches
Tor's cell size and exists for the same reasons:

- A fixed size defeats trivial traffic-analysis based on message
  length.
- Per-hop padding (§ 5.5) keeps that property end-to-end.
- 514 bytes was chosen by Tor to fit a 512-byte payload after a
  2-byte cell ID prefix; we keep that for ease of cross-tooling.

A cell whose on-wire length is not 514 bytes MUST be rejected by the
receiver before any cryptographic processing.

> **Design decision (v0.2):** 514 is non-negotiable. v0.1's three
> bucket sizes saved bandwidth at the cost of length-correlation
> attacks across hops. v0.2 trades bandwidth for the anonymity
> property. Applications that need to send less than 509 bytes of
> useful payload (§ 5.2) MUST pad; applications that need to send more
> MUST fragment.

### 5.2. Cell structure

```
   +---------------------------------------------+
   | version                          (1 byte)   |
   +---------------------------------------------+
   | circuit ID                       (4 bytes)  |
   +---------------------------------------------+
   | command                          (1 byte)   |
   +---------------------------------------------+
   |                                             |
   | payload                       (508 bytes)   |
   |   (per-command structure)                   |
   |                                             |
   +---------------------------------------------+
```

Total: 514 bytes.

| Field | Length | Notes |
|---|---:|---|
| `version` | 1 | This document specifies `0x02`. |
| `circuit ID` | 4 | Big-endian unsigned 32-bit. Assigned by the **sender** at circuit-construction time. Two endpoints of a connection MUST NOT use the same `circuit ID` for two concurrent circuits. The high bit (`circuit_id & 0x80000000`) is reserved as the **direction bit**: 1 if the sender is the lower-fingerprint endpoint, 0 otherwise. This prevents circuit-ID collisions between simultaneous outbound circuits in opposite directions on the same hop-to-hop transport. |
| `command` | 1 | Cell command — see § 5.3. |
| `payload` | 508 | Per-command layout. Includes encryption / authentication overhead. |

### 5.3. Cell commands

| Code | Name | § |
|---:|---|---|
| `0x00` | `PADDING` | 5.5 |
| `0x01` | `CREATE` | 6.2 |
| `0x02` | `CREATED` | 6.2 |
| `0x03` | `RELAY` | 5.4 |
| `0x04` | `DESTROY` | 6.4 |
| `0x05` | `LINK_HELLO` | 11.2 |
| `0x06` | `LINK_AUTH` | 11.2 |
| `0x07`–`0x7F` | reserved (v0.2) | — |
| `0x80`–`0xFF` | reserved (≥ v0.3) | — |

> **Correction (early-draft erratum):** Earlier drafts listed `EXTEND`
> and `EXTENDED` here as top-level cell commands. They are RELAY
> sub-commands (§ 5.4.1) and never appear as top-level cell commands
> on the wire.

### 5.4. RELAY cells (the load-bearing cell type)

A `RELAY` cell carries application data (or in-band control) along
an established circuit. Its payload is **layered-AEAD encrypted**:
each hop applies one layer of ChaCha20-Poly1305 with its session key.

```
   +---------------------------------------------+
   | layered encryption                          |
   |                                             |
   | innermost plaintext (after all layers       |
   | peeled by their respective hops):           |
   |                                             |
   |   relay command           (1 byte)          |
   |   stream ID               (2 bytes)         |
   |   digest                  (4 bytes)         |
   |   length                  (2 bytes)         |
   |   data            (length bytes)            |
   |   padding         (rest, zero-filled)       |
   |                                             |
   +---------------------------------------------+
```

| Field | Length | Notes |
|---|---:|---|
| `relay command` | 1 | See § 5.4.1. |
| `stream ID` | 2 | Big-endian; identifies the multiplexed stream within the circuit (§ 7.1). `0x0000` for circuit-level commands. |
| `digest` | 4 | Running BLAKE2b digest of the cell stream — see § 5.4.2. |
| `length` | 2 | Big-endian; payload length in bytes. MUST be ≤ 499 (the per-cell payload minus the 9-byte relay header). |
| `data` | length | Stream payload. |
| `padding` | rest | Zero bytes. MUST be zero-checked on every cell-decryption layer. |

Each layer of encryption is **the ChaCha20 stream cipher** (no Poly1305
tag — integrity is provided end-to-end by the running digest field
described in § 5.4.2):

```
layered_payload[i+1] = ChaCha20(K_f[i], nonce_f[i], layered_payload[i])
```

Where `K_f[i]` is the forward session key for hop `i`, and `nonce_f[i]`
is a per-cell, per-direction nonce (§ 5.4.3).

The stream cipher is reversible by XOR; encryption and decryption are
the same operation. Each hop applies one round of ChaCha20 with its
own session key to peel its layer.

> **Design decision (v0.2):** stream cipher per layer (no per-layer
> tag) is what makes cells fixed-size end-to-end. Per-layer AEAD would
> add a 16-byte tag at each hop, growing the cell by `16 × N` bytes
> across a circuit, and the integrity check would happen at each hop
> independently — adversarial-relay-amplification but no real
> security gain over end-to-end integrity. Matches Tor's design;
> well-studied.

### 5.4.1. RELAY sub-commands

| Code | Name | Direction | Purpose |
|---:|---|---|---|
| `0x00` | `RELAY_BEGIN` | client → exit | Open a TCP stream to a remote endpoint. |
| `0x01` | `RELAY_DATA` | both | Carry stream payload. |
| `0x02` | `RELAY_END` | both | Tear down a single stream. |
| `0x03` | `RELAY_CONNECTED` | exit → client | Stream connection succeeded. |
| `0x04` | `RELAY_EXTEND` | client → last hop | Extend the circuit one more hop. |
| `0x05` | `RELAY_EXTENDED` | last hop → client | Extension succeeded. |
| `0x06` | `RELAY_INTRODUCE1` | client → IP | Hidden-service introduction (§ 9.3). |
| `0x07` | `RELAY_INTRODUCE2` | IP → service | (§ 9.3) |
| `0x08` | `RELAY_RENDEZVOUS1` | client → RP | (§ 9.3) |
| `0x09` | `RELAY_RENDEZVOUS2` | RP → service | (§ 9.3) |
| `0x0A` | `RELAY_RESOLVE` | client → exit | DNS resolution. |
| `0x0B` | `RELAY_RESOLVED` | exit → client | Resolution reply. |
| `0x0C` | `RELAY_TRUNCATE` | client → relay | Discard the rest of the circuit. |
| `0x0D` | `RELAY_TRUNCATED` | relay → client | TRUNCATE complete. |
| `0x0E` | `RELAY_ESTABLISH_INTRO` | service → IP | Service registers itself with this relay as an introduction point (§ 9.2). |
| `0x0F` | `RELAY_INTRO_ESTABLISHED` | IP → service | IP acknowledges that the service is registered. |
| `0x10` | `RELAY_ESTABLISH_RENDEZVOUS` | client → RP | Client registers a 20-byte rendezvous cookie at the rendezvous point. |
| `0x11` | `RELAY_RENDEZVOUS_ESTABLISHED` | RP → client | RP acknowledges that the cookie is stored. |
| `0x12` | `RELAY_INTRODUCE_ACK` | IP → client | IP acknowledges that an `INTRODUCE1` was forwarded to the service. Status byte: 0x00 success, 0x01 unknown service, 0x02 rate-limited. |
| `0x13`–`0x7F` | reserved | — | |

### 5.4.2. Digest field

The 4-byte `digest` field is a **running** BLAKE2b digest of every
RELAY cell seen on this circuit in this direction at this hop,
truncated to 4 bytes. It defends against an attacker who controls one
hop and tries to inject cells that look valid to subsequent hops.

```
digest_state[direction] = BLAKE2b.create({ dkLen: 32 })
digest_state[direction].update(K_digest[direction])
    # K_digest derived per-hop from KEY_SEED, see § 3.7

For each cell sent in `direction`:
    let zeroed = cell-payload with the digest field overwritten by 0x00000000
    digest_state[direction].update(zeroed)
    cell.digest = first 4 bytes of digest_state[direction].clone().digest()
```

Receivers compute the expected digest **speculatively**: clone the
state, update the clone with the zeroed cell payload, derive the
expected digest, compare in constant time against the cell's digest
field. On match, commit the speculative update to the real state and
process the cell; on mismatch, discard the speculative update and
forward the cell to the next hop. The final hop that sees a digest
mismatch tears the circuit down via `DESTROY` (§ 6.4).

> **Design decision (v0.2):** 4 bytes of running digest matches Tor's
> design and gives 2^32 forgery resistance over the lifetime of a
> circuit. Sufficient for the ~10-minute circuit lifetime; an
> attacker who wants to forge a cell with valid digest must guess
> 4 bytes per cell.

### 5.4.3. Nonces

Each direction (`f` forward, `b` backward) at each hop maintains a
**16-byte nonce** for ChaCha20:

```
nonce = counter[direction] || zero[8]
```

where `counter[direction]` is a 64-bit big-endian counter starting at 0
and incremented for each cell sent in that direction at that hop. The
8 trailing zero bytes pad the counter to ChaCha20's 16-byte IV (which
internally splits into a 64-bit counter + 64-bit nonce; we use only
the counter half and leave the nonce half zeroed for clarity, with
the understanding that per-hop session keys make this safe).

> **Design decision (v0.2):** counter-based nonces (rather than random
> nonces as in v0.1) are correct here because: (a) the cell sequence
> is in-order within a hop direction, (b) we have a per-hop session
> key derived fresh per circuit, so nonce-reuse-with-different-key
> concerns don't apply, and (c) deterministic nonces simplify replay
> detection: cells received with `counter <= last_seen` are dropped.

### 5.5. PADDING cells

`PADDING` cells exist solely to defeat traffic-volume side channels.
They carry no application data and are dropped by their immediate
receiver (NOT decrypted through all layers). Implementations:

- MAY send `PADDING` cells at any time on any circuit.
- SHOULD send `PADDING` cells when an attacker who can observe the
  hop-to-hop transport would otherwise see significant volume
  variation between circuits.
- MUST accept `PADDING` cells without error.

The exact padding policy is a *Phase 7 hardening decision*. Tor's
**circuit-padding state machines** (PADDING_NEGOTIATE) are a candidate
but are themselves a 2018–2020 research area.

---

## 6. Circuit construction

### 6.1. Path selection

The client (sender) selects a path of `N` relays from the directory
(§ 10). v0.2 specifies:

- **Default `N = 3`** (entry, middle, exit). Implementations MAY
  use longer paths but SHOULD NOT use shorter — `N = 1` is v0.1's
  threat model; `N = 2` leaks the exit to the entry guard.
- Relays MUST be distinct (no relay appears twice in one circuit).
- Relays SHOULD NOT share a `/16` IPv4 prefix or `/48` IPv6 prefix
  (anti-correlation heuristic — matches Tor's `EnforceDistinctSubnets`).
- The **entry guard** is selected from a small persistent set
  (per-client) to minimise long-term de-anonymisation risk (matches
  Tor's "guard" design).
- The **exit relay** MUST have an exit policy (§ 8) that permits the
  intended destination.

### 6.2. CREATE / EXTEND handshake

Circuit construction is one-hop-at-a-time. The hybrid ntor handshake
(§ 3.7) does not fit in a single 508-byte cell payload, so CREATE and
CREATED are carried across multiple cells using the encoding in
§ 6.2.1.

The client:

1. Generates ntor state and serialises the 1216-byte CREATE message
   (§ 3.7). Splits into 3 fragments and sends 3 `CREATE` cells to the
   chosen entry guard with circuit ID `cid` and a fresh `handshake_id`.
2. The entry guard reassembles, runs the ntor handshake, splits the
   1152-byte CREATED response into 3 fragments, sends 3 `CREATED` cells.
3. Client reassembles, verifies AUTH, derives keys `(K_f[0], K_b[0],
   K_df[0], K_db[0])`.
4. Client sends a `RELAY_EXTEND` cell sequence (single-layer encrypted
   to hop 0) carrying the *next* relay's fingerprint plus the client's
   next CREATE message in fragments.
5. Hop 0 reassembles, forwards the inner CREATE to hop 1 on a fresh
   link.
6. Hop 1 responds with CREATED.
7. Hop 0 wraps the CREATED in fragmented `RELAY_EXTENDED` cells back
   through the existing circuit.
8. Client now has session keys for hops 0 and 1. Repeat for hop 2.

> **Design decision (v0.2):** one-hop-at-a-time extension is Tor's
> approach. The alternative — pre-authenticated path bundles — is
> faster but exposes the full path to the entry guard, which is a
> non-starter.

### 6.2.1. Fragmented CREATE / CREATED encoding (NEW)

CREATE and CREATED cells carry a fragment header at the start of the
cell payload, then up to 500 bytes of handshake payload:

```
   +---------------------------------------------+
   | fragment_index                   (1 byte)   |   0..(count-1)
   +---------------------------------------------+
   | fragment_count                   (1 byte)   |   1..255
   +---------------------------------------------+
   | handshake_id                     (4 bytes)  |   BE u32 — random per handshake
   +---------------------------------------------+
   | payload_len                      (2 bytes)  |   BE u16 — bytes of handshake in THIS cell
   +---------------------------------------------+
   | payload                       (≤ 500 bytes) |
   +---------------------------------------------+
   | padding              (rest, zero-filled)    |
   +---------------------------------------------+
```

Constraints:

- `fragment_count` MUST be the same on every fragment of one handshake.
- `handshake_id` MUST be the same on every fragment of one handshake.
- `fragment_index` MUST be unique within `[0, fragment_count)`. Receivers
  MUST drop duplicate-index fragments (otherwise an attacker could
  override an earlier fragment with adversarial bytes).
- `payload_len` for fragments `0..(count-2)` SHOULD be 500 (the cell
  capacity); the last fragment's `payload_len` MAY be smaller.
- A receiver MUST buffer fragments per `handshake_id` with a timeout
  (RECOMMENDED 30 seconds). On timeout, partial state is discarded.
- A receiver MUST cap concurrent in-progress handshakes per peer
  connection (RECOMMENDED 16) to bound memory.
- A receiver MUST reject `fragment_count == 0` and `fragment_index
  >= fragment_count`.

When all fragments arrive, the receiver concatenates payloads in
`fragment_index` order, producing the assembled handshake message
(§ 3.7).

> **Design decision (v0.2):** fragmentation rather than variable-size
> cells. Variable-size cells would break the on-wire size-uniformity
> property (§ 5.1) for the bytes between relays during circuit
> construction — observable as "circuit-build traffic" by passive
> on-path observers. Fixed-size CREATE / CREATED cells reveal only
> "circuit-build cell of standard size" which is consistent with the
> rest of the cell stream.

### 6.3. Layered encryption

Once the circuit is built, every RELAY cell from the client is wrapped
in `N` layers of ChaCha20-Poly1305:

```
cell_payload = layer_0(layer_1(layer_2(inner_relay_payload)))
```

Where `layer_i(p) = ChaCha20-Poly1305(K_f[i], nonce_f[i], "", p)`.

Each hop peels off its layer and forwards. Replies are encrypted in
reverse order:

```
reply_payload = layer_0_b(layer_1_b(layer_2_b(inner_reply_payload)))
```

The exit (last hop) sees the innermost plaintext. Intermediate hops
see only the layer addressed to them and the still-encrypted onion
below.

### 6.4. Circuit teardown

A `DESTROY` cell tears the circuit down. Sent by any hop on any
cryptographic or protocol failure, OR by the client at end-of-use.
`DESTROY` cells are NOT layered: they are sent in cleartext along
the cell stream (a hop that receives `DESTROY` from its predecessor
forwards `DESTROY` to its successor, with the same `circuit ID`).

### 6.5. Circuit lifetime

- A circuit's session keys remain valid until either endpoint sends
  `DESTROY`.
- Clients SHOULD discard a circuit after **10 minutes** of use OR
  after a configurable byte budget, whichever is shorter. This
  matches Tor's circuit-rotation guidance.
- Once discarded, the client constructs a fresh circuit with a fresh
  entry guard rotation per the guard policy (§ 6.1).

---

## 7. Streams over circuits

### 7.1. Stream IDs

Each circuit multiplexes streams identified by a 2-byte `stream ID`
in the relay-cell header (§ 5.4). `0x0000` is reserved for
circuit-level control. Stream IDs are assigned by the client at
`RELAY_BEGIN` time and MUST be unique per circuit.

### 7.2. RELAY_BEGIN

Client opens a TCP stream by sending `RELAY_BEGIN` to the last hop
(exit). Payload format:

```
   +---------------------------------------------+
   | addr_type                        (1 byte)   |
   +---------------------------------------------+
   | addr                            (variable)  |
   +---------------------------------------------+
   | port                             (2 bytes)  |
   +---------------------------------------------+
   | flags                            (1 byte)   |
   +---------------------------------------------+
```

| `addr_type` | Address layout |
|---:|---|
| `0x01` | 4-byte IPv4 |
| `0x02` | 16-byte IPv6 |
| `0x03` | hostname — 1-byte length + length bytes ASCII |

Exit relay attempts the TCP connection. On success, sends back
`RELAY_CONNECTED` with the status code (§ 7.2.1). On failure, sends
`RELAY_END` with a reason code.

#### 7.2.1. RELAY_CONNECTED

Sent by the exit relay in response to a successful `RELAY_BEGIN`.
Payload format:

```
   +---------------------------------------------+
   | status                           (1 byte)   |
   +---------------------------------------------+
```

| `status` | Meaning |
|---:|---|
| `0x00` | success — stream is open |
| `0x01`–`0xFF` | mirrors `RELAY_END` reason codes; the exit MAY send `RELAY_END` instead and SHOULD if the stream actually failed to open. `RELAY_CONNECTED` with non-zero status is reserved for transient successes (e.g., "connected but to a different address than requested"); v0.2 implementations MAY treat any non-zero status as a stream-open failure. |

v0.2 does NOT include the bound destination address in the
`RELAY_CONNECTED` payload. Clients trust the exit to have honoured the
address from `RELAY_BEGIN`; the alternative (echoing the bound address)
would leak destination-address bytes through additional cells without
useful client-side validation, since clients have no independent way
to verify what the exit actually connected to.

### 7.3. RELAY_DATA

Carries up to **499 bytes** of stream payload per cell. Applications
above v0.2 see a stream interface; v0.2 chunks application bytes into
cells transparently.

### 7.4. RELAY_END

Tears down a single stream without affecting the circuit. Reason
codes (1-byte) include:

| Code | Meaning |
|---:|---|
| `0x01` | misc / unknown |
| `0x02` | exit policy rejected |
| `0x03` | resolve failed |
| `0x04` | connection refused |
| `0x05` | connection timeout |
| `0x06` | remote closed |
| `0x07` | client closed |
| `0x08`–`0xFF` | reserved |

### 7.5. Flow control

Stream-level flow control uses **SENDME windows** (matching Tor's
design):

- Each stream maintains a receive window initialised to 500 cells.
- Receiver sends a `RELAY_SENDME` (stream-level, every 50 cells) to
  signal "I've consumed 50 cells; you may send 50 more."
- Sender stops sending when its window reaches 0.

Circuit-level SENDMEs (stream ID `0x0000`) provide flow control for
the circuit as a whole.

> **Design decision (v0.2):** SENDME windows are the same scheme Tor
> uses. The fixed windows are a known cause of "circuit unfairness"
> in adverse network conditions but the tradeoff for protocol
> simplicity is worth it for v0.2. v0.3 may revisit.

---

## 8. Exit policy

### 8.1. Policy advertisement

Each node's directory entry (§ 10) carries an **exit policy**
indicating which destinations the node is willing to act as an exit
for. Policies are ordered lists of rules:

```
   +---------------------------------------------+
   | rule_count                       (2 bytes)  |
   +---------------------------------------------+
   | rules            (rule_count records)       |
   |                                             |
   |   action          (1 byte)   ACCEPT|REJECT  |
   |   addr_type       (1 byte)   IPv4|IPv6|ANY  |
   |   addr_prefix     (variable) net + mask len |
   |   port_min        (2 bytes)                 |
   |   port_max        (2 bytes)                 |
   |                                             |
   +---------------------------------------------+
```

| `action` | |
|---:|---|
| `0x01` | ACCEPT |
| `0x02` | REJECT |

| `addr_type` | `addr_prefix` layout |
|---:|---|
| `0x01` IPv4 | 4-byte net ‖ 1-byte mask length (0..32) |
| `0x02` IPv6 | 16-byte net ‖ 1-byte mask length (0..128) |
| `0xFF` ANY | empty (zero bytes; matches any destination address) |

Note that `0x03` is reserved here so as not to collide with
`RELAY_BEGIN`'s hostname `addr_type` (§ 7.2) — exit policies are
evaluated against resolved addresses only, never hostnames.

Rules are evaluated in order; the first match wins. An implicit
`REJECT *:*` is appended.

### 8.2. Enforcement

When a `RELAY_BEGIN` arrives at an exit, the exit:

1. Resolves the destination (per `addr_type`).
2. Evaluates its exit policy against the resolved address + port.
3. If REJECT or no match → sends `RELAY_END` with reason `0x02`.
4. If ACCEPT → opens the TCP connection.

### 8.3. Default policies

Operators MAY use any policy. RECOMMENDED defaults:

- **Non-exit:** `REJECT *:*`. The vast majority of relays.
- **Reduced exit:** `ACCEPT *:80, *:443, *:53; REJECT *:*`. Just
  web + DNS.
- **Standard exit:** matches Tor's `ReducedExitPolicy`. Permits
  major protocols, blocks abuse-attractive ports.

### 8.4. DNS resolution

`RELAY_RESOLVE` lets a client ask an exit to perform DNS resolution
without opening a TCP stream. This avoids leaking DNS to the
clearnet from the client's local DNS resolver (Tor's standard
mitigation for DNS-based de-anonymisation).

---

## 9. Hidden services

### 9.1. Service descriptors

A hidden service publishes a **service descriptor** to the directory
(§ 10) signed by `SVC_sk`. Format:

```
   +---------------------------------------------+
   | descriptor version               (1 byte)   |
   +---------------------------------------------+
   | SVC_pk                          (32 bytes)  |
   +---------------------------------------------+
   | publish epoch                    (8 bytes)  |
   +---------------------------------------------+
   | lifetime seconds                 (4 bytes)  |
   +---------------------------------------------+
   | intro_point_count                (1 byte)   |
   +---------------------------------------------+
   | intro_points    (intro_point_count records) |
   +---------------------------------------------+
   | signature                       (64 bytes)  |
   |   Ed25519(SVC_sk, all fields above)         |
   +---------------------------------------------+
```

Each intro-point record (1312 bytes):

```
   +---------------------------------------------+
   | IP fingerprint                  (32 bytes)  |
   |   (Blake2b-256(IP_ID_pk))                   |
   +---------------------------------------------+
   | IP onion key                    (32 bytes)  |
   |   (X25519, for circuit-extension to IP)     |
   +---------------------------------------------+
   | service intro auth key          (32 bytes)  |
   |   (Ed25519 per-IP ephemeral, signs          |
   |    ESTABLISH_INTRO to authenticate the      |
   |    service to the IP — § 9.5.1)             |
   +---------------------------------------------+
   | service enc X25519 key          (32 bytes)  |
   |   (X25519 — classical half of hybrid        |
   |    sealed-box, § 9.4)                       |
   +---------------------------------------------+
   | service enc ML-KEM key         (1184 bytes) |
   |   (ML-KEM-768 — post-quantum half of        |
   |    hybrid sealed-box, § 9.4)                |
   +---------------------------------------------+
```

The service generates ALL of these keys per intro point and holds the
matching secrets. Intermediate observers (including the IP itself) see
only the public components.

> **Design decision (v0.2):** descriptors are NOT encrypted at the
> directory level in v0.2. Tor's HSv3 encrypts descriptors to defend
> against directory enumeration; we defer that to v0.3. v0.2
> descriptors are public — anyone querying the directory for
> `Blake2b-256(SVC_pk)` can fetch the descriptor.

### 9.2. Introduction points

Each intro-point (IP) is a relay that has agreed to forward
`RELAY_INTRODUCE2` cells to the service. The service maintains a
long-lived circuit to each IP. Selection criteria are similar to
exit selection: stability, not on the same subnet as the service's
guard, etc.

### 9.3. Rendezvous protocol

Connecting a client to a hidden service:

1. **Client** fetches the service descriptor from the directory
   using `Blake2b-256(SVC_pk)` as the lookup key.
2. **Client** picks a **rendezvous point (RP)**: any relay it
   doesn't already have a circuit through. Constructs a 3-hop
   circuit to RP. Picks a 20-byte **rendezvous cookie** and sends
   `RELAY_ESTABLISH_RENDEZVOUS` to RP, which stores the cookie.
3. **Client** picks an IP from the descriptor. Constructs a separate
   3-hop circuit to the IP. Sends `RELAY_INTRODUCE1` containing:
   - `service_intro_key` (from descriptor)
   - Encrypted-to-service inner payload: `rendezvous_cookie` || RP
     fingerprint || ntor-shake material for circuit extension at RP.
4. **IP** forwards the inner cell to the **service** via the
   long-lived service-to-IP circuit, as `RELAY_INTRODUCE2`.
5. **Service** decrypts the inner payload, learns RP and the
   rendezvous cookie. Constructs a 3-hop circuit to RP. Sends
   `RELAY_RENDEZVOUS1` with the cookie.
6. **RP** matches the cookie to the client's pending circuit,
   splices them. Both sides now have an end-to-end 6-hop circuit
   (client → 3 hops → RP → 3 hops → service).
7. **Service** sends `RELAY_RENDEZVOUS2` back to the client over the
   spliced circuit. Application data flows from then on.

```
Client                                                     Service
  | 3-hop circuit ─────► RP ◄───── 3-hop circuit              |
  |                                                            |
  |  via 3-hop circuit ─────► IP ─────► service-to-IP circuit |
  |  RELAY_INTRODUCE1                  RELAY_INTRODUCE2       |
  +─────────────────────────────────────────────────────────────+
```

> **Design decision (v0.2):** the 6-hop rendezvous splice matches Tor's
> design. Six hops is overkill from a pure-latency standpoint but
> provides receiver anonymity against introduction points and
> rendezvous points alike.

### 9.4. Hybrid sealed-box (NEW)

INTRODUCE1's inner payload is encrypted to the service so that the
introduction point cannot read the rendezvous cookie or the
embedded handshake material. The construction is a **hybrid sealed-
box** combining ephemeral X25519, ML-KEM-768 encapsulation, and
ChaCha20-Poly1305 AEAD:

```
seal(plaintext, recipient_x25519_pk, recipient_mlkem_pk):
    (e_sk, E)        = X25519.KeyGen()
    shared_x         = X25519(e_sk, recipient_x25519_pk)
    (ct, shared_pq)  = ML-KEM-768.Encaps(recipient_mlkem_pk)
    K                = HKDF-Extract("anon-layer/v2/sealed-box", shared_x || shared_pq)
    nonce            = RAND(12)
    (ciphertext, tag) = ChaCha20-Poly1305.Encrypt(K, nonce, aad="", plaintext)
    return E || ct || nonce || ciphertext || tag

unseal(envelope, recipient_x25519_sk, recipient_mlkem_sk):
    parse E (32) || ct (1088) || nonce (12) || (ciphertext, tag) (rest)
    shared_x         = X25519(recipient_x25519_sk, E)
    if shared_x is all-zero: abort
    shared_pq        = ML-KEM-768.Decaps(ct, recipient_mlkem_sk)
    K                = HKDF-Extract("anon-layer/v2/sealed-box", shared_x || shared_pq)
    plaintext        = ChaCha20-Poly1305.Decrypt(K, nonce, aad="", ciphertext, tag)
    return plaintext or null on any failure
```

Envelope overhead: 32 (E) + 1088 (ct) + 12 (nonce) + 16 (tag) = 1148 bytes.

> **Design decision (v0.2):** the sealed-box is hybrid (parallel X25519
> + ML-KEM) for the same reason the ntor handshake is (§ 3.7). A
> harvest-now-decrypt-later attacker who captures INTRODUCE1 today and
> develops a quantum computer in 2046 still cannot recover the
> rendezvous cookie or the embedded handshake X / K_pk — they would
> need to break both X25519 AND ML-KEM-768.

### 9.5. Rendezvous-flow payload byte layouts (NEW)

The RELAY sub-commands used by hidden services have the following
inner-payload (RELAY-cell `data` field, § 5.4) byte layouts.

#### 9.5.1. `RELAY_ESTABLISH_INTRO` (0x0E)

```
   +---------------------------------------------+
   | service_intro_pubkey            (32 bytes)  |
   +---------------------------------------------+
   | publish_epoch                   (8 bytes)   |
   +---------------------------------------------+
   | signature                       (64 bytes)  |
   |   Ed25519(service_intro_sk, signed_body)    |
   |   where:                                    |
   |     signed_body =                           |
   |       "anon-layer/v2/establish-intro"       |
   |       || ip_fingerprint                     |
   |       || publish_epoch                      |
   +---------------------------------------------+
```

Total: 104 bytes.

The IP verifies the signature using `service_intro_pubkey` and its
own `ip_fingerprint`. On success the IP records: "this circuit is the
service for `service_intro_pubkey`." Subsequent INTRODUCE1 cells
addressed to `service_intro_pubkey` are forwarded down this circuit
as INTRODUCE2.

#### 9.5.2. `RELAY_INTRO_ESTABLISHED` (0x0F)

```
   +---------------------------------------------+
   | status                           (1 byte)   |
   +---------------------------------------------+
```

`status`: 0x00 success, 0x01 signature failure, 0x02 rate-limited,
0x03 duplicate.

#### 9.5.3. `RELAY_ESTABLISH_RENDEZVOUS` (0x10)

```
   +---------------------------------------------+
   | rendezvous_cookie               (20 bytes)  |
   +---------------------------------------------+
```

The RP stores `(rendezvous_cookie → this_circuit)` for matching when a
future `RELAY_RENDEZVOUS1` arrives. Cookies are 20 bytes per Tor's
convention; collisions are astronomical.

#### 9.5.4. `RELAY_RENDEZVOUS_ESTABLISHED` (0x11)

```
   +---------------------------------------------+
   | status                           (1 byte)   |
   +---------------------------------------------+
```

`status`: 0x00 success, 0x01 cookie collision, 0x02 rate-limited.

#### 9.5.5. `RELAY_INTRODUCE1` (0x06)

Sent from client (over a 3-hop circuit) to the IP. The IP forwards
the inner sealed envelope to the service as INTRODUCE2.

```
   +---------------------------------------------+
   | service_intro_pubkey            (32 bytes)  |
   |   (identifies which service)                |
   +---------------------------------------------+
   | sealed_envelope               (variable)    |
   |   (output of seal() per § 9.4)              |
   +---------------------------------------------+
```

The `sealed_envelope` encrypts an inner payload (§ 9.5.5.1) to the
service's per-IP enc keys (also embedded in the descriptor).

##### 9.5.5.1. Sealed inner payload (after unseal at the service)

```
   +---------------------------------------------+
   | rendezvous_cookie               (20 bytes)  |
   +---------------------------------------------+
   | rp_fingerprint                  (32 bytes)  |
   |   (Blake2b-256 of rendezvous point's idPk)  |
   +---------------------------------------------+
   | rp_onion_pk                     (32 bytes)  |
   |   (X25519, for circuit extension to RP)     |
   +---------------------------------------------+
   | handshake_message            (1216 bytes)   |
   |   (hybrid ntor CREATE per § 3.7)            |
   +---------------------------------------------+
```

Total: 1300 bytes inside the seal, plus 1148 bytes seal envelope plus
32 bytes outer service_intro_pubkey = 2480 bytes for INTRODUCE1's
RELAY data payload. This does NOT fit in a single RELAY cell's 499-byte
data field; the introduce payload is therefore fragmented using the
§ 6.2.1 fragmentation header carried in the RELAY data field. (Five
RELAY cells per INTRODUCE1.)

#### 9.5.6. `RELAY_INTRODUCE2` (0x07)

Identical structure to INTRODUCE1 except `service_intro_pubkey` is
verified by the IP before forwarding (it MUST match an ESTABLISH_INTRO
this IP has accepted). The IP does NOT touch the `sealed_envelope`.

#### 9.5.7. `RELAY_RENDEZVOUS1` (0x08)

Sent from service (over a 3-hop circuit it has just built) to the RP.
RP looks up `rendezvous_cookie` to find the client's circuit and
forwards `handshake_response` as RENDEZVOUS2.

```
   +---------------------------------------------+
   | rendezvous_cookie               (20 bytes)  |
   +---------------------------------------------+
   | handshake_response           (1152 bytes)   |
   |   (hybrid ntor CREATED per § 3.7)           |
   +---------------------------------------------+
```

Total: 1172 bytes. Fragmented via § 6.2.1.

#### 9.5.8. `RELAY_RENDEZVOUS2` (0x09)

```
   +---------------------------------------------+
   | handshake_response           (1152 bytes)   |
   +---------------------------------------------+
```

The RP strips the cookie (which was the matching key) before forwarding
to the client. Fragmented via § 6.2.1.

#### 9.5.9. `RELAY_INTRODUCE_ACK` (0x12)

```
   +---------------------------------------------+
   | status                           (1 byte)   |
   +---------------------------------------------+
```

`status`: 0x00 forwarded, 0x01 unknown service_intro_pubkey, 0x02 rate-
limited, 0x03 service circuit closed.

---

## 10. Directory and consensus

### 10.1. The hard part

v0.2 has the same anti-Sybil non-protection as v0.1. The directory
mechanism therefore CANNOT be self-securing — it must rest on an
out-of-band root of trust, exactly like v0.1's seed list.

### 10.2. Directory authorities (v0.2 design)

A small set (5–9) of **directory authorities** (DAs) maintains the
canonical view of the network:

- Each DA has a long-lived signing key, published out of band.
- Each DA collects **router status entries** (RSEs) from relays that
  want to participate.
- DAs reach **consensus** on the network state hourly via a voting
  protocol (matching Tor's `dir-spec` § 3.1).
- Clients fetch the consensus from any DA or any **directory mirror**
  (a relay that caches the latest consensus).

The DA voting protocol, signature schemes, and consensus parameters
are NOT specified in this draft — they require their own document
(call it `DIRSPEC-v0.2.md`).

### 10.3. Router status entries

Each RSE has the following byte layout:

```
   +---------------------------------------------+
   | fingerprint                     (32 bytes)  |
   +---------------------------------------------+
   | identity public key             (32 bytes)  |
   +---------------------------------------------+
   | identity-onion public key       (32 bytes)  |
   +---------------------------------------------+
   | IPv4 address (host || port)     (6 bytes)   |
   |   (all-zero if relay has no IPv4 transport) |
   +---------------------------------------------+
   | IPv6 address (host || port)     (18 bytes)  |
   |   (all-zero if relay has no IPv6 transport) |
   +---------------------------------------------+
   | flags                            (2 bytes)  |
   +---------------------------------------------+
   | exit_policy length              (2 bytes)   |
   +---------------------------------------------+
   | exit_policy bytes               (variable)  |
   |   (encoded per § 8.1)                       |
   +---------------------------------------------+
```

Total fixed prefix: 32 + 32 + 32 + 6 + 18 + 2 + 2 = 124 bytes, plus
the variable-length exit policy.

Flag bit values:

| Bit    | Name      | Meaning                                  |
|-------:|-----------|------------------------------------------|
| 0x0001 | EXIT      | Acts as an exit (has a non-empty policy) |
| 0x0002 | GUARD     | Eligible as an entry guard               |
| 0x0004 | RUNNING   | Currently reachable per DA polling       |
| 0x0008 | STABLE    | Sustained uptime (≥ DA-defined threshold)|
| 0x0010 | FAST      | High bandwidth (≥ DA-defined threshold)  |
| 0x0020 | HSDIR     | Acts as a hidden-service-directory cache |
| 0x0040 | VALID     | Well-behaved per DA observation          |
| 0x0080 | AUTHORITY | Is itself a directory authority          |
| 0x0100 | BAD_EXIT  | Operators known to misbehave as exit     |
| 0x0200 –|         | reserved (≥ v0.3)                        |
| 0x8000 |          |                                          |

A relay used in a 3-hop circuit MUST have at minimum the RUNNING and
VALID flags. The entry guard MUST additionally have GUARD; the exit
MUST additionally have EXIT and not have BAD_EXIT. The middle hop has
no additional flag requirements.

### 10.3a. Consensus document format

The consensus is the canonical byte-level artefact produced by the DA
voting protocol (deferred to a future `DIRSPEC-v0.2.md`). A client
that has received consensus bytes from any source verifies and parses
them per this section.

Layout:

```
   +---------------------------------------------+
   | version                          (1 byte)   |   0x02
   +---------------------------------------------+
   | valid_after                     (8 bytes)   |   Unix seconds, BE
   +---------------------------------------------+
   | fresh_until                     (8 bytes)   |   Unix seconds, BE
   +---------------------------------------------+
   | valid_until                     (8 bytes)   |   Unix seconds, BE
   +---------------------------------------------+
   | da_signature_count               (1 byte)   |
   +---------------------------------------------+
   | da_signatures   (da_signature_count × 96)   |
   |   each: DA fingerprint (32) ‖                |
   |          Ed25519 signature (64)              |
   +---------------------------------------------+
   | rse_count                       (4 bytes)   |   BE u32
   +---------------------------------------------+
   | rses                          (variable)    |
   |   (each per § 10.3 above)                   |
   +---------------------------------------------+
```

Each Ed25519 signature covers the **signed-bytes view**: the
concatenation of all fields above EXCEPT the `da_signatures` block
itself. Concretely:

```
signed_bytes = version || valid_after || fresh_until || valid_until
            || da_signature_count || rse_count || rses
```

> **Design decision (v0.2):** the signed bytes include the *number*
> of DA signatures (so an attacker cannot truncate the signature
> block) but not the signatures themselves (avoiding circularity).

A client MUST:

1. Receive the consensus bytes from some source.
2. For each `(da_fingerprint, signature)` pair, look up the DA's
   public key in its hardcoded / config-supplied DA trust set. Skip
   pairs for unknown DAs.
3. Verify the Ed25519 signature against `signed_bytes`.
4. Count verified signatures from KNOWN DAs.
5. Accept the consensus only if the count is ≥ `⌊|known_DAs| / 2⌋ + 1`
   (majority of the DA set the client trusts).
6. Reject the consensus if `now < valid_after` or `now > valid_until`.

> **Design decision (v0.2):** the DA root of trust is operator-
> configured (a list of Ed25519 public keys distributed out of band
> by the protocol authors, analogous to Tor's `DirAuthority` list in
> source). Compromising ⌊N/2⌋+1 of those keys compromises the
> consensus the client believes; this is the well-known weakness of
> the DA model that v0.3 research (Walking Onions etc.) aims to
> reduce.

### 10.4. Service-descriptor distribution

Hidden-service descriptors (§ 9.1) are stored by a subset of relays
acting as **HSDir** (hidden-service directory) relays. Storage and
fetch routing matches Tor's distributed-hash-table model:

```
hsdir_key = Blake2b-256("anon-layer/v2/hsdir" || SVC_pk || period)
```

where `period` rotates daily. The descriptor is stored at the relays
whose fingerprints come immediately after `hsdir_key` in the
sorted-fingerprint ring (the "responsible HSDir set"). Tor uses 6
replicas per descriptor; v0.2 picks 6.

> **Open question:** The DA design and HSDir mechanism inherit Tor's
> known weaknesses (DA compromise → network-wide attack). Modern
> research (Walking Onions, PrivOps consensus) could substantially
> improve this. For v0.2 we accept the Tor model; v0.3 should
> revisit.

---

## 11. Link transport

### 11.1. Carrier

Relays exchange v0.2 cells over an authenticated, encrypted point-to-
point connection. The carrier is **TLS-over-TCP**. The TLS layer
provides confidentiality and integrity for the cell stream against
network observers; cell-level encryption (§ 5.4 layered AEAD) provides
the anonymity properties on top.

The TLS certificate the relay presents need not be signed by a public
CA. Operators MAY use self-signed certificates: the relay's identity
of record is its Ed25519 `idPk` (§ 4.1), authenticated at the
LINK_AUTH step (§ 11.2). The certificate's role is solely to enable
TLS; trust comes from the link-auth signature.

Once the TLS handshake completes, both sides stream 514-byte cells
end-to-end in both directions. Framing is implicit (fixed cell size);
no length prefix is needed.

### 11.2. Link handshake

Before any circuit traffic flows, both endpoints exchange two cells
each: `LINK_HELLO` then `LINK_AUTH`. The handshake establishes:

- The peer's claimed Ed25519 identity (`idPk`)
- Mutual proof of possession of the matching `idSk` via signature
- Freshness via per-handshake nonces (defeats replay)

```
Dialer (D)                                      Acceptor (A)
   │                                                  │
   │── LINK_HELLO {idPk_D, nonce_D, version, flags} ─►│
   │◄── LINK_HELLO {idPk_A, nonce_A, version, flags} ─│
   │── LINK_AUTH  {sig_D = Ed25519(idSk_D, ...)}    ─►│
   │◄── LINK_AUTH  {sig_A = Ed25519(idSk_A, ...)}    ─│
   │                                                  │
   │            cell stream (CREATE, RELAY, ...)      │
```

Either side MAY send `LINK_HELLO` first; the protocol does not
require ordering. A side MUST NOT send `LINK_AUTH` before receiving
the peer's `LINK_HELLO`. A side MUST NOT accept any non-handshake
cell (`CREATE`, `RELAY`, `DESTROY`, `PADDING`) before completing both
its own and the peer's `LINK_AUTH`.

#### 11.2.1. `LINK_HELLO` payload (68 bytes)

```
   +---------------------------------------------+
   | protocol_version                 (1 byte)   |   0x02
   +---------------------------------------------+
   | flags                            (1 byte)   |
   |   bit 0 = is_dialer (set if this side       |
   |          initiated the underlying TCP/TLS)  |
   |   bit 1 = reserved                          |
   |   bits 2-7 = reserved                       |
   +---------------------------------------------+
   | reserved                         (2 bytes)  |   0x0000
   +---------------------------------------------+
   | nonce                           (32 bytes)  |   RAND(32)
   +---------------------------------------------+
   | idPk                            (32 bytes)  |   Ed25519 public key
   +---------------------------------------------+
```

#### 11.2.2. `LINK_AUTH` payload (64 bytes)

```
   +---------------------------------------------+
   | signature                       (64 bytes)  |
   +---------------------------------------------+
```

The signature is `Ed25519(idSk_self, transcript)` where:

```
transcript = "anon-layer/v2/link-auth"
          || nonce_self ||  idPk_self
          || nonce_peer ||  idPk_peer
```

`nonce_self` and `idPk_self` are the values this side sent in its own
`LINK_HELLO`; `nonce_peer` and `idPk_peer` are the values received
from the peer's `LINK_HELLO`. Both sides reconstruct the transcript
the same way (each side substitutes "self" and "peer" from their own
vantage), so each side's transcript naturally differs — and each
signature is valid only under the signer's own `idSk`.

### 11.3. Handshake-success conditions

A side considers the link authenticated when ALL of the following hold:

1. Peer's `LINK_HELLO.protocol_version == 0x02`. Mismatch → close.
2. Peer's `LINK_AUTH.signature` verifies under
   `peer_LINK_HELLO.idPk` over the transcript constructed by the
   verifier substituting its own values for `*_self`. Mismatch → close.
3. **Dialer only:** `peer_LINK_HELLO.idPk` matches the
   expected-recipient `idPk` the dialer was instructed to connect to
   (typically from the consensus or from an out-of-band record).
   Mismatch → close.

The acceptor performs check (2) but does NOT do (3) — it accepts any
peer who can prove possession of an `idSk`. The runtime above may
apply additional policy (consensus presence, rate-limiting, etc.).

### 11.4. Failure dispositions

All link-handshake failures (TLS handshake failure, malformed cell,
wrong version, bad signature, dialer-identity mismatch) result in
immediate TCP close. No `DESTROY` cell is sent because no circuit
exists yet at the link layer. The runtime above MAY log the failure
locally (silent on the wire per § 9.1).

> **Design decision (v0.2):** TLS provides confidentiality of the
> cell stream against network observers, but the v0.2 cells inside
> are already onion-encrypted, so TLS adds bandwidth without
> additional anonymity. We accept the cost because TLS also provides
> the framing-and-flow-control substrate operators are familiar with,
> and self-signed certs avoid the CA-trust complexity Tor's link
> protocol historically tangled with.

> **Open question:** TLS itself is currently classical (X25519 +
> ECDSA via the certificate); a future revision should adopt hybrid
> PQ TLS (e.g. `x25519_mlkem768` key share) when widely deployed in
> Node's TLS stack. Bandwidth overhead is acceptable given we already
> pay for fixed-cell padding.

---

## 12. Error handling

### 11.1. Silent-drop discipline (inherited from v0.1)

Every receive-path failure results in a silent drop, with the
following circuit-level extensions:

- A cell whose layered-AEAD decryption fails at any hop causes that
  hop to send `DESTROY` toward the **client** (not toward the
  successor). The successor is not informed of the failure. Direction
  matters: cells coming from the client toward the exit are dropped
  by the failing hop; cells from the exit toward the client are
  dropped by the client's nearest hop on the back-path.
- A cell whose `digest` field (§ 5.4.2) doesn't match also triggers
  `DESTROY` from the failing hop.
- A `length` field that exceeds the cell's payload capacity triggers
  `DESTROY`.
- Padding-not-zero triggers `DESTROY`.

### 11.2. Constant-time accept / reject (inherited + extended)

The v0.1 timing concern (§ 9.2) applies at every layer. v0.2 hops
SHOULD process cells in a way that does not distinguish
accept-vs-reject through wall-clock time. The pragmatic approach
remains "always run the AEAD step on every cell"; rejecting at the
length check is acceptable because cell length is a public,
attacker-known invariant.

### 11.3. Transport-level rate limiting (inherited)

Same as v0.1 § 9.3: connection-level disconnect after pathological
malformed-packet volume.

---

## 13. Migration from v0.1

### 12.1. No mixed-network coexistence

A v0.2 client cannot use a v0.1-only relay (different wire format,
different identity-onion-key semantics). A v0.2 relay's directory
status entry is not understood by a v0.1 node.

### 12.2. Operator migration

The recommended migration path:

1. v0.2 reference implementation is released.
2. Operators run **both** a v0.1 daemon and a v0.2 daemon on
   different ports during the transition window.
3. Once a quorum of the v0.1 network has v0.2 endpoints, v0.1 is
   deprecated.
4. v0.1 client tooling continues to work against v0.1-only peer-to-
   peer use cases (e.g., the `anon-chat` deployment between known
   peers) but is no longer suitable for clearnet exit.

### 12.3. Identity continuity

A node's Ed25519 `ID_pk` MAY be the same across v0.1 and v0.2 — it's
just an identity key. The v0.1 onion key and v0.2 identity-onion key
are the same primitive (X25519); operators MAY publish the same key.
This lets users build out-of-band trust in v0.1 and carry it
forward.

---

## 14. Security considerations

### 13.1. What v0.2 defends against (positive claims)

- **Single passive observer at any one hop.** No single hop learns
  both the sender and the receiver. The entry guard knows the sender
  but not the destination; the exit knows the destination but not
  the sender; middle hops know neither.
- **Active modification of cells in transit.** Per-cell AEAD plus the
  running digest field reject any tampering. A modified cell tears
  down the circuit.
- **Replay of captured cells.** Counter-based nonces (§ 5.4.3) make
  replays trivially detectable per hop.
- **Length-based traffic analysis.** Fixed 514-byte cells.
- **Receiver de-anonymisation via the rendezvous flow.** A client
  initiating a hidden-service connection cannot learn the service's
  network location through the protocol alone.

### 13.2. What v0.2 does NOT defend against (negative claims)

- **Global passive adversary.** As with Tor, an attacker who can
  observe a substantial fraction of all relay-to-relay traffic can
  perform timing correlation. Multi-hop helps until the attacker is
  too big.
- **Compromised entry guard PLUS exit.** If the same adversary
  controls both your entry guard and your exit, they can correlate
  your traffic. Guard policy (§ 6.1) reduces but does not eliminate
  this.
- **Browser-layer leaks.** WebRTC ICE candidates leak local IP; DNS
  prefetch leaks destinations; canvas-rendering leaks identity. v0.2
  cannot fix these — that's the browser-fork project (Mullvad
  Browser-style hardening).
- **Compromised directory authorities.** N/2+1 DAs colluding can
  publish a malicious consensus listing only adversary-controlled
  relays. v0.3+ research (Walking Onions, etc.) may help.
- **Long-term identity-key compromise.** As noted in § 1.2,
  past-traffic is safe (per-circuit ephemerals) but future-traffic
  impersonation is feasible.
- **Anti-Sybil.** Operators MUST size DA / seed-list trust assumptions
  such that the directory cannot be flooded with adversarial relays.
- **Side-channel attacks on the host platform.** Spectre-style speculation
  attacks, RAM cold-boot attacks, etc. v0.2 is a network protocol;
  these are operating-system / hardware concerns.

### 13.3. Threat model document

A separate `THREAT_MODEL-v0.2.md` (to be written) will lay out
v0.2's anonymity properties, adversary classes, and capability matrix
in the same format as v0.1's threat model.

---

## 15. Appendix A: Design decisions ledger

| § | Decision | Alternative considered | Rationale |
|---|---|---|---|
| 3.7 | hybrid X25519+ML-KEM-768 ntor | classical ntor only | resists harvest-now-decrypt-later quantum attacks on session keys; cost is multi-cell handshake (§ 6.2.1) |
| 4.4 | `.anon` suffix | reuse `.onion` | clarity: tooling can disambiguate |
| 5.1 | 514-byte cells | variable-size with bucketing | fixed size defeats length-correlation; matches Tor |
| 5.4.3 | counter nonces | random nonces | per-direction-per-hop key invariant; saves 12 bytes/cell |
| 5.4.2 | 4-byte running digest | per-cell HMAC | matches Tor; sufficient for 10-min circuit |
| 6.1 | 3 hops default | 2 hops or longer | 2 leaks exit to guard; 3 is Tor-equivalent |
| 6.5 | 10-minute circuit lifetime | 1 hour | matches Tor's published guidance |
| 7.5 | SENDME flow control | TCP-style window | matches Tor; simpler than continuous backpressure |
| 9.1 | unencrypted descriptors | HSv3 encrypted-to-credential | v0.3 work; v0.2 accepts directory enumeration |
| 10.2 | Tor-style DAs | gossip-only directory | gossip is unable to defend against Sybil; DAs are the known-bad-but-tractable option |
| 12 | hard wire-incompatibility | v0.1/v0.2 interop bridge | bridge would import v0.1's threat model into v0.2; not worth it |

---

## 16. Appendix B: Open research questions

These are decisions this draft does NOT make and which deserve their
own focused work before v0.2 is finalised:

1. **Padding state machines.** § 5.5 says "circuit-padding state
   machines are a candidate" but doesn't pick one. Tor's PADDING_NEGOTIATE
   work post-dates the original Tor spec and is itself controversial.
   Recommendation: defer to a `PADDING-v0.2.md` document with at
   least one named author who has done padding-traffic analysis
   before.

2. **Directory-authority voting protocol.** § 10.2 names voting but
   doesn't specify it. Tor's `dir-spec` § 3.1 is the candidate; we
   would adapt minor details. Needs its own document.

3. **HSDir replication and consensus.** § 10.4 commits to a Tor-
   style sorted-ring with 6 replicas, but the failure modes (DA
   compromise → wrong responsible-HSDir-set) need explicit study.

4. **Walking Onions / alternative directory designs.** A modern
   alternative to DAs is to embed a small slice of the consensus in
   every relay's response, so the client never fetches a full
   consensus and the DA-compromise blast radius shrinks. Excellent
   research, complex implementation. v0.3 candidate.

5. ~~**Quantum-safe handshake.**~~ **CLOSED in v0.2** (chunk 8.1). The
   handshake is now hybrid X25519 + ML-KEM-768; the multi-cell encoding
   that allows it is in § 6.2.1. Signatures (Ed25519) are not yet
   hybridised because they have no harvest-now-decrypt-later exposure;
   that upgrade is deferred to v0.3 with the larger spec-and-byte-
   layout work it entails.

6. **Pluggable transports.** v0.2 cells are trivially DPI-finger-
   printable. Anti-censorship (obfs4 / meek / snowflake equivalents)
   is a separate document and a separate ecosystem of plugins. v0.2
   leaves room for them at the transport layer but does not specify
   them.

7. **Anti-Sybil mechanisms.** v0.2 accepts that DAs + operator
   judgment are the anti-Sybil mechanism, but research (proof-of-
   resource, vouching graphs, identity-token-based admission) offers
   alternatives. v0.3+ candidate.

8. **End-to-end congestion control.** v0.2 uses Tor's SENDME windows.
   Tor's own congestion control has been a 2020–present research
   area (CongestionControl proposal). v0.3 candidate.

9. **Browser integration patterns.** Out of scope for this document
   but adjacent: the relationship between v0.2 cells and a
   SOCKS5-style proxy interface that a forked browser would use. To
   be specified in `BROWSER-INTEGRATION.md`.

---

## Document status

This draft commits to architectural decisions but does NOT yet pin
every byte-level field encoding. Before reference implementation
begins, the following must be added:

- Exact cell-payload byte layouts for each `RELAY_*` sub-command.
- Exact DA voting protocol (or import-by-reference from `DIRSPEC-v0.2.md`).
- Exact HSDir replication parameters and failure-mode behaviour.
- Per-platform behaviour for path-selection edge cases (e.g., when
  the client's directory view contains fewer than 3 eligible relays).

The expected next-step is **independent cryptographic review of this
draft**, in parallel with closing out the open questions in § 15.
Reference implementation should not start until that review is
complete; the v0.1 experience showed that the spec is the load-
bearing artefact.

---

*End of v0.2 draft.*
