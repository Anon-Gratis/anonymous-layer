# Anonymous Layer Protocol Specification

| | |
|---|---|
| **Document** | Anonymous Layer Protocol Specification |
| **Version** | 0.1 (draft) |
| **Date** | 2026-05-19 |
| **Status** | **DRAFT — not implemented, not deployed, not audited** |
| **Editor** | Anonymous Gratis `<admin@anon.gratis>` |
| **License** | This document is released under [AGPL-3.0-or-later](../LICENSE), identical to the reference implementation. |

> This is **version 0.1 of a draft** specification. The corresponding
> reference code (`modules/`) does **not** yet implement this document — it
> implements an earlier, pre-spec design with known critical defects (see
> [`AUDIT_PREP.md`](../AUDIT_PREP.md)). The implementation will be migrated
> to match this specification during Phase 4 of the production-readiness
> roadmap. Until that migration is complete and an external audit has been
> commissioned, **do not rely on this protocol for safety**.

---

## Table of contents

1. [Introduction](#1-introduction)
2. [Document conventions](#2-document-conventions)
3. [Cryptographic primitives](#3-cryptographic-primitives)
4. [Node identity](#4-node-identity)
5. [Wire format](#5-wire-format)
6. [Coordination packets](#6-coordination-packets)
7. [Peer discovery and bootstrap](#7-peer-discovery-and-bootstrap)
8. [Forwarding model](#8-forwarding-model)
9. [Error handling](#9-error-handling)
10. [Protocol versioning](#10-protocol-versioning)
11. [Security considerations](#11-security-considerations) — *(TODO, depends on Phase 3 threat model)*
12. [References](#12-references)
13. [Appendix A: Design decisions ledger](#13-appendix-a-design-decisions-ledger)

---

## 1. Introduction

### 1.1. Purpose

Anonymous Layer is an experimental network protocol that provides
**sender / receiver unlinkability** for short messages exchanged over a
peer-to-peer overlay. It is not a circuit-based transport; it is a
forwarding network in which each hop applies fresh authenticated
encryption and the source and destination identities are decoupled from
the network layer beneath.

The protocol is designed so that:

- **Independent re-implementations are practical.** All packet formats,
  cryptographic constructions, and state machines are specified in this
  document. A conforming implementation does not need to share code
  with the reference implementation.
- **All cryptography is built from well-studied, standardised
  primitives.** No bespoke primitives, no roll-your-own block modes, no
  novel handshake constructions.
- **Implementations can be audited independently of the network.** No
  central directory authority is required to verify a peer's identity
  or a packet's authenticity.

### 1.2. Non-goals

This document does **not** specify:

- A circuit-construction protocol equivalent to Tor's. There are no
  multi-hop sessions in v0.1; each packet is independently routed.
- Bandwidth accounting, fair scheduling, or congestion control.
- Censorship-resistant transports (pluggable obfuscation). Transport
  obfuscation is out of scope for v0.1 and addressed in a separate
  companion specification (TBD).
- An onion-service-style hidden-service mechanism. Single-hop and
  multi-hop responder anonymity are scoped for v0.2.
- A consensus protocol or directory authority. Peer discovery is
  gossip-based; see § 7.

### 1.3. Threat model summary

A complete threat model lives in [`docs/THREAT_MODEL.md`](THREAT_MODEL.md)
(forthcoming, Phase 3). The summary, against which all design choices in
this document are made, is:

- **In scope.** A *passive* network adversary observing packet metadata
  on links they control, including arbitrary fractions of the network's
  links. An *active* adversary capable of injecting, dropping, replaying,
  and modifying packets on links they control. An adversary who operates
  a bounded fraction of the network's nodes and learns everything those
  nodes learn.
- **Out of scope.** A global passive adversary who observes every link
  simultaneously (we make no claim of resistance to traffic-analysis at
  that scale). Compromised endpoints. Application-layer fingerprinting
  by sites the user reaches through the network. Coercion of the user.

### 1.4. Conformance levels

An implementation is **conforming** if it implements every MUST and
SHALL clause in this document and does not implement any clause as MUST
NOT or SHALL NOT. An implementation is **interoperable** at protocol
version `0x01` if it conforms to every clause in this document that
applies to version `0x01`.

---

## 2. Document conventions

### 2.1. Requirements language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD,
SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be
interpreted as described in [RFC 2119][rfc2119] when, and only when,
they appear in all capitals.

### 2.2. Byte ordering and bit numbering

- All multi-byte integer fields are encoded in **network byte order**
  (big-endian).
- Within a byte, **bit 0 is the most significant bit** and bit 7 is the
  least significant bit, consistent with RFC packet diagrams.
- All byte offsets are zero-indexed.

### 2.3. Field notation

Wire-format diagrams use the following notation:

```
   +-------------------------------+
   |       <field name>            |  <byte count> bytes
   +-------------------------------+
```

Multi-row diagrams are grouped by logical section. Trailing variable-
length fields are labelled with `…` in the length column.

### 2.4. Cryptographic notation

| Notation | Meaning |
|---|---|
| `H(x)` | Blake2b-256 of `x` (see § 3.4). |
| `KDF(ikm, info, n)` | HKDF-SHA-256: extract from `ikm`, expand to `n` bytes with `info` (see § 3.5). |
| `KX(sk, pk)` | X25519 scalar multiplication of secret key `sk` with public key `pk`, yielding a 32-byte shared secret (see § 3.2). |
| `SIG(sk, m)` | Ed25519 signature over `m` under signing key `sk`, yielding a 64-byte signature (see § 3.6). |
| `VRF(pk, sig, m)` | Ed25519 signature verification; returns `true` iff `sig` is a valid signature on `m` under `pk`. |
| `AEAD_ENC(k, n, ad, p)` | ChaCha20-Poly1305 encrypt: key `k`, nonce `n`, associated data `ad`, plaintext `p`. Yields `ciphertext ‖ tag` (see § 3.3). |
| `AEAD_DEC(k, n, ad, c)` | ChaCha20-Poly1305 decrypt; returns plaintext or fails. |
| `RAND(n)` | `n` bytes from the operating-system CSPRNG (see § 3.1). |
| `‖` | Byte-string concatenation. |
| `=` | Byte-string equality (constant-time when applied to secret values). |

### 2.5. Terminology

- **Node:** An autonomous participant in the network that can send,
  receive, and forward packets. Identified by its long-term identity
  public key (§ 4).
- **Peer:** A specific node from another node's local point of view,
  typically one to which a transport connection is currently open.
- **Identity key:** A long-term Ed25519 keypair used to sign assertions
  about a node (§ 4.1).
- **Onion key:** A long-term X25519 keypair used by peers to encrypt
  packets to this node (§ 4.2).
- **Session key:** A short-lived symmetric key derived from an X25519
  exchange and used to authenticate-and-encrypt exactly one packet
  (§ 6 forthcoming).

---

## 3. Cryptographic primitives

All primitives in this section MUST be drawn from a vetted cryptographic
library. The reference implementation uses Node.js' built-in `crypto`
module (which is bound to OpenSSL); other implementations are RECOMMENDED
to use libsodium or an equivalent.

> **Design decision (v0.1):** The protocol uses only primitives that
> appear in IETF or NIST standards and are implemented by both libsodium
> and OpenSSL. No bespoke primitives are introduced. This is a clean
> break from the pre-spec implementation, which used hand-rolled
> ElGamal-2048, Twofish-128, and a custom block-chaining mode.

### 3.1. Randomness

Implementations MUST source all secret-bearing random values
(identity-key generation, ephemeral X25519 secrets, nonces) from the
operating-system cryptographically-secure pseudo-random number
generator (CSPRNG). On POSIX systems this is `getrandom(2)` or
`/dev/urandom`; the reference implementation uses
`crypto.randomFillSync` from Node.js' `crypto` module, which wraps
these.

Implementations MUST NOT seed any non-cryptographic PRNG (e.g.
JavaScript `Math.random()`, C `rand(3)`, Java `java.util.Random`) for
any value used in or derived from a cryptographic operation.

### 3.2. Key agreement: X25519

Key agreement uses the X25519 elliptic-curve Diffie-Hellman function
defined in [RFC 7748][rfc7748] § 5. Public keys and secret keys are
each **32 bytes**. The shared secret produced by `KX(sk, pk)` is
**32 bytes**.

Implementations MUST reject the result of `KX` if it is the all-zero
32-byte string (this corresponds to the small-subgroup attack on
Curve25519 and indicates that the peer's public key is invalid).
This check MUST be performed in constant time.

X25519 implementations MUST be constant-time.

### 3.3. Authenticated encryption: ChaCha20-Poly1305

Authenticated encryption uses ChaCha20-Poly1305 as defined in
[RFC 8439][rfc8439]. Key length is **32 bytes**; nonce length is
**12 bytes**; authentication tag length is **16 bytes**.

For every distinct `(key, nonce)` pair an implementation transmits, the
combination MUST be unique. Reuse of a nonce under the same key is a
catastrophic failure (loss of confidentiality and authenticity) and an
implementation MUST take affirmative measures to prevent it. The
prescribed nonce derivation is given in § 6 (forthcoming).

> **Design decision (v0.1):** ChaCha20-Poly1305 (RFC 8439) was selected
> over XChaCha20-Poly1305 because each packet uses a single-use session
> key derived from a fresh ephemeral X25519 keypair (§ 5), making the
> 12-byte nonce space comfortably collision-free under any plausible
> deployment scale. In v0.1, nonces MUST be drawn uniformly at random
> from `RAND(12)`; deterministic nonces derived from a session counter
> are reserved for the v0.2 multi-hop session mechanism.

### 3.4. Hashing: Blake2b-256

Cryptographic hashing uses Blake2b with an output length of 32 bytes,
as defined in [RFC 7693][rfc7693]. Where a fingerprint or commitment
shorter than 32 bytes is required, the leftmost N bytes of the
Blake2b-256 output are used.

Implementations MAY substitute SHA-256 for portability with hardware or
runtime environments that lack a Blake2 implementation; this
substitution is application-local and MUST NOT alter any value
transmitted on the wire. (For wire-level hashing, Blake2b-256 is
mandatory.)

### 3.5. Key derivation: HKDF-SHA-256

Key derivation uses HKDF as defined in [RFC 5869][rfc5869] with
SHA-256 as the underlying hash. HKDF is used in its two-step extract /
expand form whenever multiple keys are derived from a single shared
secret.

The protocol uses the following standardised `info` strings (each is the
literal ASCII byte string with no terminator):

| Purpose | `info` |
|---|---|
| Per-packet AEAD key (v0.1, single-use) | `anon-layer/v1/aead` |
| Per-packet session key, direction A→B (v0.2, reserved) | `anon-layer/v1/session/AtoB` |
| Per-packet session key, direction B→A (v0.2, reserved) | `anon-layer/v1/session/BtoA` |

> **Design decision (v0.1):** Each packet derives a single-use AEAD key
> via `HKDF-SHA-256(KX(eph_sk, onion_pk), "anon-layer/v1/aead", 32)`. The
> directional labels are reserved for the v0.2 session protocol but are
> not used in v0.1 — a v0.1 packet is a one-shot, one-direction transmission.

### 3.6. Signatures: Ed25519

Node identity signatures use Ed25519 as defined in [RFC 8032][rfc8032].
Public keys are **32 bytes**; secret keys are **32 bytes** (the seed)
plus the corresponding 32-byte public key; signatures are **64 bytes**.

Ed25519 implementations MUST be the deterministic variant
specified in RFC 8032 (no random nonce). They MUST be constant-time.

> **Design decision (v0.1):** Ed25519 was selected for identity
> signatures because it is the only signature primitive in widespread
> deployment that is both fast and side-channel-resistant by
> construction. Ed448 is permitted as a future v2 option but not v1.

### 3.7. Constant-time operations

All implementations MUST use constant-time routines for:

- Comparing MAC tags or any other secret-bearing byte string.
- Looking up secret-indexed table entries (no
  `lookup_table[secret_byte]` constructions over public memory).
- Conditional moves whose condition depends on secret data.

The use of high-level language constructs (e.g. `Buffer.compare`,
`crypto.timingSafeEqual` in Node.js) is REQUIRED for equality tests on
secret data.

---

## 4. Node identity

### 4.1. Identity key

Every node has exactly one long-term Ed25519 identity keypair
`(idSk, idPk)`. The identity key:

- MUST be generated using the CSPRNG defined in § 3.1.
- MUST be persisted to disk encrypted-at-rest by the implementation if
  the device is shared, single-user with sensitive data, or otherwise
  inappropriate for plaintext storage. The encryption-at-rest mechanism
  is implementation-defined and outside the scope of this document.
- MUST NOT be transmitted on the wire in any form. The corresponding
  public key MAY be transmitted (it identifies the node).

The identity public key is the **canonical, long-term identifier** of a
node. All other keys MUST be derivable from or signed by the identity
key.

### 4.2. Onion key

In addition to the identity key, each node maintains an X25519 onion
keypair `(onionSk, onionPk)`. The onion key:

- MUST be generated using the CSPRNG defined in § 3.1.
- MUST be signed by the identity key in a **key certificate** (§ 4.4).
- SHOULD be rotated at least every 7 days. Rotated onion keys MUST
  remain decryptable for at least 24 hours after rotation to allow
  in-flight packets to be received.
- MUST NOT be reused across nodes.

### 4.3. Node fingerprint

The node fingerprint is the canonical 32-byte identifier used in peer-
discovery, packet routing, and out-of-band identity verification:

```
fingerprint = H(idPk)
```

The fingerprint is `Blake2b-256(idPk)`. Implementations MAY display
a truncated representation to users (e.g. first 16 bytes as 32
lowercase hexadecimal characters in groups of four) but MUST always
compare fingerprints in full when verifying identity programmatically.

### 4.4. Key certificate

A node's onion key is bound to its identity key by a key certificate.
A key certificate is the byte sequence:

```
   +-------------------------------+
   | version           (1 byte)    |  0x01
   +-------------------------------+
   | onion public key  (32 bytes)  |
   +-------------------------------+
   | expiry            (8 bytes)   |  Unix seconds, big-endian
   +-------------------------------+
   | identity sig      (64 bytes)  |  Ed25519 over the preceding 41 bytes
   +-------------------------------+
```

Total: **105 bytes**.

Receivers MUST verify:

1. `version == 0x01`.
2. `expiry > now()` (i.e. the certificate is not expired).
3. `VRF(idPk, sig, version ‖ onionPk ‖ expiry) == true`.

Implementations MUST reject any packet whose route requires a node
whose key certificate fails any of these checks.

### 4.5. Out-of-band identity verification

The fingerprint of a node identity key is the only value that
out-of-band verification (printed business cards, signed messages,
in-person meetings) needs to confirm. Onion keys are inferred from
key certificates, which are signed by the identity key.

> **Design note:** This document deliberately does not specify a
> trust-on-first-use heuristic, an identity-key revocation mechanism,
> or a key-transparency log. Each of these is a v0.2 concern and is
> tracked in `docs/ROADMAP.md` (forthcoming).

---

## 5. Wire format

### 5.1. Packet sizes

Every packet transmitted on the wire MUST have a total length of
exactly one of:

| Bucket | Total bytes | Symbolic name |
|---:|---:|---|
| 0x01 | 256 | `BUCKET_SMALL` |
| 0x02 | 1024 | `BUCKET_MEDIUM` |
| 0x03 | 4096 | `BUCKET_LARGE` |

A packet whose on-wire length is not exactly one of these three values
MUST be rejected by the receiver before any cryptographic processing.

> **Design decision (v0.1):** Fixed-size buckets are used (rather than
> variable-length packets) to prevent passive observers from
> correlating message lengths across hops, and to defeat trivial
> traffic-analysis side channels such as keystroke-timing inference.
> Three buckets balance bandwidth overhead against length-leakage:
> short coordination and chat messages use 256, larger documents up to
> ~4 KB go into 1024, and bulk transfers up to ~16 KB use 4096.
> Messages exceeding `BUCKET_LARGE`'s plaintext capacity are fragmented
> at the application layer (§ 6, forthcoming).

### 5.2. Packet structure

A packet has two logical regions: an **outer header** which is
transmitted in cleartext on the wire and an **AEAD-protected body** in
which the outer header is authenticated as associated data.

```
   +---------------------------------------------+
   | version                          (1 byte)   |
   +---------------------------------------------+
   | bucket                           (1 byte)   |
   +---------------------------------------------+
   | recipient fingerprint prefix     (8 bytes)  |
   +---------------------------------------------+
   |                                             |
   | sender ephemeral X25519 public  (32 bytes)  |
   |                                             |
   +---------------------------------------------+
   | nonce                           (12 bytes)  |
   +---------------------------------------------+ <-- 54 bytes outer header
   |                                             |
   | AEAD body                                   |
   |   (encrypted + authenticated inner)         |
   |                       (bucket - 70 bytes)   |
   |                                             |
   +---------------------------------------------+
   | Poly1305 tag                    (16 bytes)  |
   +---------------------------------------------+
```

Total: exactly `bucket` bytes.

| Field | Length | Notes |
|---|---:|---|
| `version` | 1 | This document specifies `0x01`. |
| `bucket` | 1 | One of `0x01`, `0x02`, `0x03`. |
| `recipient fingerprint prefix` | 8 | First 8 bytes of `H(recipient idPk)`. Used for fast local filtering only; the full fingerprint is verified during decryption. |
| `sender ephemeral X25519 public key` | 32 | Fresh per packet. Single-use. MUST be discarded after the packet is sent. |
| `nonce` | 12 | `RAND(12)`. Random and unique within `(sender_ephemeral_pk, nonce)` space (collision-free by construction of the ephemeral key). |
| `AEAD body` | bucket − 70 | ChaCha20-Poly1305 ciphertext of the inner plaintext (§ 5.4). |
| `tag` | 16 | Poly1305 tag, computed over `outer_header ‖ ciphertext`. |

### 5.3. AEAD key derivation

For a packet sent to a recipient whose onion public key is `onionPk`:

1. The sender generates an ephemeral X25519 keypair `(ephSk, ephPk)` with
   `RAND(32)` for `ephSk` (clamped per RFC 7748 § 5).
2. The sender computes `shared = KX(ephSk, onionPk)`.
3. If `shared` is the all-zero 32-byte string, the sender MUST abort and
   regenerate the ephemeral keypair.
4. The AEAD key is `K = KDF(shared, "anon-layer/v1/aead", 32)`.
5. The sender computes `nonce = RAND(12)`.

The recipient, receiving a packet, computes the inverse:

1. `shared = KX(onionSk, ephPk)`.
2. If `shared` is the all-zero string, the packet MUST be silently dropped.
3. `K = KDF(shared, "anon-layer/v1/aead", 32)`.
4. The AEAD is decrypted with `K`, `nonce` from the outer header, and
   `aad` from the outer header (§ 5.5).

### 5.4. Inner plaintext layout

After AEAD decryption, the inner plaintext has length `bucket − 70` and
the following layout:

```
   +---------------------------------------------+
   | packet type                      (1 byte)   |
   +---------------------------------------------+
   | real length                      (2 bytes)  |
   +---------------------------------------------+
   |                                             |
   | sender identity fingerprint     (32 bytes)  |
   |                                             |
   +---------------------------------------------+
   |                                             |
   | payload                  (real_length bytes)|
   |                                             |
   +---------------------------------------------+
   |                                             |
   | padding   (bucket - 70 - 35 - real_length)  |
   |   all zero bytes                            |
   |                                             |
   +---------------------------------------------+
```

| Field | Length | Notes |
|---|---:|---|
| `packet type` | 1 | One of the values defined in § 6. |
| `real length` | 2 | Big-endian unsigned 16-bit count of payload bytes. MUST be ≤ `bucket − 70 − 35`. |
| `sender identity fingerprint` | 32 | The full `H(idPk)` of the sender. **This identifies the sender to the recipient inside the AEAD; it is not visible to network observers.** |
| `payload` | real_length | Type-dependent (§ 6). |
| `padding` | rest | Zero bytes. The receiver MUST verify that every byte of the padding region is exactly `0x00` and MUST reject the packet otherwise. |

The padding region is mandatory and its all-zero contents are
authenticated by the AEAD tag; this prevents an active adversary from
truncating or extending the apparent payload.

> **Design decision (v0.1):** The sender's identity fingerprint is
> placed *inside* the AEAD so that only the recipient learns who sent
> the packet. Forwarders (in the future v0.2 multi-hop construction)
> will only see the outer header.

> **Design decision (v0.1):** The sender's identity is conveyed by
> fingerprint only, not by a signature inside the packet. The sender's
> identity is **claimed** at the network layer but not proved; an
> application that requires non-repudiation MUST add a signature in the
> payload itself. This keeps v0.1 simple and avoids the cost (~64 bytes
> per packet) of an Ed25519 signature.

### 5.5. Authenticated associated data (AAD)

The AAD passed to `AEAD_ENC` and `AEAD_DEC` is the **entire outer
header**, exactly as transmitted on the wire, concatenated in field
order:

```
aad = version ‖ bucket ‖ recipient_prefix ‖ ephPk ‖ nonce
```

Length: **54 bytes**.

Any modification by an active attacker to any cleartext outer-header
byte causes AEAD verification to fail.

### 5.6. Replay protection

Each node MUST maintain a **sliding-window log** of packets it has
recently accepted. The log key is the pair
`(sender_ephemeral_pk, nonce)`, derived from the outer header of each
accepted packet.

Window semantics:

- **Time window.** Entries are retained for at least **300 seconds**
  (5 minutes) and MAY be retained longer.
- **Size bound.** Implementations MUST retain at least the **most
  recent 8192** entries even if doing so requires extending the time
  window. They MAY retain more.
- **Eviction.** Implementations MAY evict entries older than the time
  window before the size bound is reached.

On receipt of a packet whose AEAD verification has succeeded, the
receiver:

1. Looks up `(ephPk, nonce)` in the replay log.
2. If found, the packet is a replay; it MUST be silently dropped.
3. If not found, the packet is accepted; `(ephPk, nonce)` is inserted
   into the log.

> **Design decision (v0.1):** Because each packet has a *fresh*
> ephemeral public key (§ 5.3), `ephPk` alone is already a unique
> single-use token in honest traffic. The window log thus primarily
> defends against an active adversary who *retransmits* a captured
> packet. The 5-minute / 8192-entry minima are chosen so a node sized
> for ~30 packets/sec retains at least 4-5 minutes of history;
> high-volume nodes will retain proportionally less time but never
> fewer than 8192 entries.

> **Design decision (v0.1):** The log is per-recipient (i.e., per
> node), not per-(sender, recipient) pair. Because the sender is
> network-layer anonymous (§ 5.4), no stable sender identity is
> available at the layer that performs replay rejection.

### 5.7. Receive-path order of operations

A receiver processing a single inbound packet MUST perform these
checks in this order, aborting on the first failure:

1. **Length check.** Packet length is exactly 256, 1024, or 4096 bytes.
   Otherwise drop.
2. **Version check.** `version == 0x01`. Otherwise drop.
3. **Bucket check.** `bucket` matches the actual length. Otherwise drop.
4. **Fingerprint-prefix filter (advisory).** The first 8 bytes of
   `H(my idPk)` match `recipient_prefix`. If not, drop without further
   work. This is an optimisation, not a security check.
5. **AEAD decrypt.** Compute `shared`, derive `K`, decrypt. On any
   failure (including all-zero `shared` or Poly1305 tag mismatch),
   drop silently.
6. **Padding check.** Every byte of the padding region is `0x00`.
   Otherwise drop.
7. **`real_length` sanity.** `real_length ≤ bucket − 70 − 35`.
   Otherwise drop.
8. **Replay check.** `(ephPk, nonce)` is not in the replay log.
   Otherwise drop.
9. **Insert into replay log.** Add `(ephPk, nonce)`.
10. **Dispatch by `packet type`.** Hand the payload to the handler
    for the type, defined in § 6.

All failure dispositions in this list MUST be **silent**: the receiver
MUST NOT emit a response that distinguishes between failure causes,
nor measurably alter its timing. (Practical guidance: in implementations
where AEAD failure and padding failure take noticeably different time,
extend both paths to constant time using a constant-time `OR` mask
before the final accept/reject decision.)

### 5.8. Send-path order of operations

A sender constructing an outbound packet:

1. Select `bucket` such that the inner plaintext fits:
   `bucket = smallest b ∈ {256, 1024, 4096} such that 70 + 35 + real_length ≤ b`.
   If even `BUCKET_LARGE` is insufficient, fragment at the application
   layer.
2. Generate `(ephSk, ephPk)` per § 5.3.
3. Compute `shared = KX(ephSk, recipient onionPk)`. Abort + retry on
   all-zero.
4. Derive `K`, generate `nonce = RAND(12)`.
5. Construct the inner plaintext with the sender's identity fingerprint
   and zero-padding (§ 5.4).
6. Construct AAD per § 5.5.
7. Compute `(ciphertext, tag) = AEAD_ENC(K, nonce, aad, inner_plaintext)`.
8. Concatenate `aad ‖ ciphertext ‖ tag` and transmit.
9. Discard `ephSk`, `shared`, `K`, and `inner_plaintext` (zeroize).

---

## 6. Coordination packets

This section defines the set of packet types valid in v0.1 and the
layout of each type's payload. The `packet type` byte in the inner
plaintext (§ 5.4) selects which subsection applies.

### 6.1. Type registry

| Code | Name | Direction | Purpose | § |
|---:|---|---|---|---|
| `0x00` | `RESERVED` | — | Reserved; never valid on the wire. Receivers MUST drop. | 6.2 |
| `0x01` | `DATA` | sender → recipient | Carry an opaque application-layer payload to the recipient. | 6.3 |
| `0x02` | `ANNOUNCE_PEER` | sender → recipient | Inform the recipient that the named peer exists, with a key certificate. | 6.4 |
| `0x03` | `FORWARD` | sender → forwarder | Ask the forwarder to deliver the enclosed inner packet to a named next-hop. | 6.5 |
| `0x04` | `KEY_CERTIFICATE` | sender → recipient | Publish the sender's current key certificate. | 6.6 |
| `0x05`–`0x7F` | reserved (v0.1) | — | Reserved for v0.1 extensions; receivers MUST drop. | — |
| `0x80`–`0xFF` | reserved (≥ v0.2) | — | Reserved for future major / minor versions. | — |

> **Design decision (v0.1):** Only four packet types are exposed in
> v0.1. The pre-spec `FASTER_LINK_{PLEAD,GRANT,TRADE,CHECK}` and
> `REDIRECT_STATIC` types were bandwidth-negotiation and connection-
> migration mechanisms that depend on session state; they are
> deferred to v0.2 along with the multi-hop / circuit construction.

### 6.2. `RESERVED` (`0x00`)

Never valid. A receiver MUST drop any packet whose decrypted inner
`packet type` byte is `0x00`. This reservation prevents accidental
processing of zero-initialised buffers.

### 6.3. `DATA` (`0x01`)

Payload layout (within the `payload` region of § 5.4):

```
   +---------------------------------------------+
   | conversation tag                (16 bytes)  |
   +---------------------------------------------+
   | sequence number                  (8 bytes)  |
   +---------------------------------------------+
   |                                             |
   | opaque application bytes (real_length - 24) |
   |                                             |
   +---------------------------------------------+
```

| Field | Length | Notes |
|---|---:|---|
| `conversation tag` | 16 | Application-defined opaque identifier. Used by the recipient's application layer to demultiplex concurrent conversations from the same sender. SHOULD be derived from a Blake2b-256 of an application-layer conversation key, truncated to 16 bytes, so it is unlinkable to network-layer identity. |
| `sequence number` | 8 | Big-endian unsigned 64-bit. Application-defined ordering within a conversation. v0.1 does not impose semantics; the application MAY use it for ordering, fragmentation indices, or ignore it (set to `0x00…0`). |
| application bytes | rest | Opaque to v0.1. End-to-end encryption above this layer is the application's responsibility. |

The minimum valid `real_length` for `DATA` is **24** (the two header
fields with zero application bytes). A receiver MUST drop a `DATA`
packet whose `real_length` is less than 24.

> **Design decision (v0.1):** `DATA` packets are opaque at the network
> layer. The network does **not** parse, route, or modify the
> application bytes. This is the layering boundary between the
> anonymity network and whatever protocol (chat, file transfer,
> HTTP-over-anon) rides on top of it.

### 6.4. `ANNOUNCE_PEER` (`0x02`)

Payload layout:

```
   +---------------------------------------------+
   | announced fingerprint           (32 bytes)  |
   +---------------------------------------------+
   |                                             |
   | announced key certificate      (105 bytes)  |
   |   (format defined in § 4.4)                 |
   |                                             |
   +---------------------------------------------+
   | announced transport count        (1 byte)   |
   +---------------------------------------------+
   |                                             |
   | announced transports         (variable)     |
   |   (format defined in § 6.4.1, one per entry)|
   |                                             |
   +---------------------------------------------+
```

Minimum `real_length`: `32 + 105 + 1 = 138` bytes (zero transports).

Receivers MUST:

1. Verify that `H(idPk_of_cert) == announced_fingerprint`. The
   identity public key is recovered from the key certificate by
   verifying the signature in § 4.4 and extracting the signing key.
   *(Note: Ed25519 signatures alone do not embed the public key;
   implementations are REQUIRED to learn `idPk` out of band or from a
   previous `KEY_CERTIFICATE` packet. See § 6.6.)*
2. Verify the key certificate per § 4.4.
3. Drop the packet on any failure.

A successfully verified `ANNOUNCE_PEER` packet results in the
announced node being added to the receiver's peer table with the
listed transports.

#### 6.4.1. Transport record format

Each transport record is variable-length:

```
   +---------------------------------------------+
   | transport type                   (1 byte)   |
   +---------------------------------------------+
   | transport length                 (1 byte)   |
   +---------------------------------------------+
   | transport address     (transport length B)  |
   +---------------------------------------------+
```

| Type | Name | Length | Address format |
|---:|---|---:|---|
| `0x01` | `WEBSOCKET_IPV4` | 6 | 4-byte IPv4 + 2-byte big-endian port |
| `0x02` | `WEBSOCKET_IPV6` | 18 | 16-byte IPv6 + 2-byte big-endian port |
| `0x03`–`0xFF` | reserved | — | Receivers MUST skip unknown transport types using the `transport length` byte. |

> **Design decision (v0.1):** Length-prefixed transport records permit
> forward-compatible addition of new transports (Tor onion, QUIC,
> Bluetooth Mesh, etc.) without bumping the protocol version.

### 6.5. `FORWARD` (`0x03`)

Asks the recipient (acting as a forwarder) to deliver an enclosed
inner packet to a named next-hop. The inner packet is itself a
fully-formed anonymous-layer packet per § 5, and is opaque to the
forwarder beyond its size and routing prefix.

Payload layout:

```
   +---------------------------------------------+
   |                                             |
   | next-hop fingerprint            (32 bytes)  |
   |                                             |
   +---------------------------------------------+
   | next-hop transport count         (1 byte)   |
   +---------------------------------------------+
   | next-hop transports             (variable)  |
   |   (transport-record format, § 6.4.1)        |
   +---------------------------------------------+
   |                                             |
   | inner packet                    (variable)  |
   |   (one of: 256, 1024, or 4096 bytes)        |
   |                                             |
   +---------------------------------------------+
```

Receivers MUST:

1. Confirm the inner packet's length is exactly one of the three
   buckets (§ 5.1). Otherwise drop.
2. Confirm the inner packet's `recipient_prefix` (its byte offsets
   2..10) matches the first 8 bytes of the supplied next-hop
   fingerprint. Otherwise drop.
3. Apply rate-limit accounting (§ 6.5.1) and drop if the limit is
   exceeded.
4. Establish a transport connection to the next-hop using one of the
   supplied transport records (selected at the implementation's
   discretion).
5. Transmit the inner packet verbatim.
6. Discard all state associated with this `FORWARD` request.

A forwarder MUST NOT modify the inner packet in any way, including
re-encrypting or re-padding it.

#### 6.5.1. Forward-rate limiting

To prevent the open-amplification primitive flagged in `AUDIT_PREP.md`
finding H3, every node that processes `FORWARD` packets MUST enforce:

- A **per-source rate limit** of at most 32 `FORWARD` requests per
  source `ephPk` per 60 seconds. (This is loose because each
  legitimate packet uses a fresh `ephPk`; in practice, "per source"
  is "per recently-seen ephemeral key," not per identity.)
- A **per-destination rate limit** of at most 64 `FORWARD` requests
  per next-hop fingerprint per 60 seconds.
- A **global rate limit** of at most 4096 `FORWARD` requests per
  60 seconds.

Implementations MAY enforce stricter limits. Implementations MAY
expose these limits as operator configuration. A `FORWARD` packet
that exceeds any limit is dropped silently per § 5.7 disposition.

> **Design decision (v0.1):** The pre-spec implementation's forward
> handler had no rate limiting and accepted any next-hop the packet
> named — a textbook amplification primitive. The v0.1 limits above
> are intentionally conservative; we expect a Phase 5 hardening pass
> and the Phase 3 threat model to refine them.

### 6.6. `KEY_CERTIFICATE` (`0x04`)

Publishes the sender's identity public key together with their current
key certificate. This is the bootstrap channel by which a recipient
learns the `idPk` needed to verify subsequent `ANNOUNCE_PEER` packets
(§ 6.4) about other nodes whose identity key is unfamiliar.

Payload layout:

```
   +---------------------------------------------+
   |                                             |
   | identity public key             (32 bytes)  |
   |                                             |
   +---------------------------------------------+
   |                                             |
   | key certificate                (105 bytes)  |
   |   (format defined in § 4.4)                 |
   |                                             |
   +---------------------------------------------+
```

Exact `real_length`: **137** bytes. A receiver MUST drop any
`KEY_CERTIFICATE` packet whose `real_length` is not 137.

Receivers MUST:

1. Verify that the inner `sender identity fingerprint` (§ 5.4) equals
   `H(identity public key)`. Otherwise drop.
2. Verify the key certificate per § 4.4. Otherwise drop.
3. Cache the `(idPk, key certificate)` pair indexed by
   `H(idPk)` for use in future `ANNOUNCE_PEER` validation.

> **Design decision (v0.1):** Ed25519 raw signatures do not embed the
> signing public key, so the receiver must learn it through an
> explicit channel. `KEY_CERTIFICATE` is that channel. A future
> revision may inline the `idPk` directly into the certificate to
> remove this two-message bootstrap.

---

## 7. Peer discovery and bootstrap

Peer discovery in v0.1 is gossip-based. There is no consensus
mechanism, no directory authority, and no on-line "trust graph"
beyond the manual seed list each node starts from.

### 7.1. Seed list

Every implementation MUST ship with, or accept on startup, a
**seed list** of zero or more bootstrap peers. The seed list is the
out-of-band root of trust for an otherwise-empty peer table.

A seed list is a sequence of seed records:

```
   +---------------------------------------------+
   |                                             |
   | identity public key             (32 bytes)  |
   |                                             |
   +---------------------------------------------+
   |                                             |
   | key certificate                (105 bytes)  |
   |   (format defined in § 4.4)                 |
   |                                             |
   +---------------------------------------------+
   | transport count                  (1 byte)   |
   +---------------------------------------------+
   | transports                      (variable)  |
   |   (transport-record format, § 6.4.1)        |
   +---------------------------------------------+
```

The encoding for distribution is implementation-defined (PEM-style
armored block, JSON document, raw binary) but the on-disk byte
sequence above MUST be the canonical form for hashing or signing.

A seed list distributed publicly SHOULD be signed by a long-lived
"anchor" key whose public component is published widely out of band
(e.g., on multiple websites, in printed media, in PGP-signed
release announcements). The anchor signature is **out of scope** for
this protocol document; it is a deployment concern.

> **Design decision (v0.1):** No on-protocol seed-list signature
> format is specified. Distributing the seed list and rotating the
> anchor key is treated as a deployment concern (analogous to Tor's
> hard-coded directory authorities). A future revision may add
> protocol-level anchor signatures if cross-implementation seed-list
> interchange becomes common.

### 7.2. Bootstrap procedure

On startup, an implementation MUST:

1. Load the seed list.
2. Verify each seed record's key certificate per § 4.4. Drop records
   that fail.
3. Open transport connections to a sample of `min(K, seed_count)`
   seeds, where `K` is implementation-defined (RECOMMENDED `K = 8`).
4. Send each connected seed a `KEY_CERTIFICATE` packet (§ 6.6) so the
   seed can announce *this* node to its peers.

If the seed list is empty and no peers can be loaded from local
state, the implementation MUST refuse to send any application
traffic and SHOULD emit a local error indicating no bootstrap
candidates were available.

### 7.3. Gossip propagation

Once a node has at least one connected peer, it MUST periodically
emit `ANNOUNCE_PEER` packets (§ 6.4) to advertise *other* peers in
its table. The default cadence is:

- One `ANNOUNCE_PEER` per peer per **30 seconds**.
- Subject of the announcement: a uniformly random selection from the
  receiver's *not-currently-connected* peer set, with selection
  weighted to prefer peers that the recipient is least likely to have
  seen recently. The "least likely" estimate is an
  implementation-local heuristic.

A node MUST NOT announce itself to a peer that already has it in its
peer table; nodes are responsible for tracking which peers they have
announced themselves to.

> **Design decision (v0.1):** The pre-spec implementation announced
> at 750 ms intervals, which produced ~1.3 announcements per second
> per peer and dominated bandwidth on idle networks. The 30 s
> default scales reasonably to ~1000-node networks; larger networks
> are out of scope for v0.1.

### 7.4. Peer eviction

Peers are evicted from the local peer table when any of these holds:

- Their key certificate has expired.
- Their identity has been observed to send a malformed packet that
  reached AEAD-decryption-success but failed inner validation
  (§ 5.7 step 7 or 8). Evict on first such occurrence.
- They have not been reachable on any of their advertised
  transports for at least **1 hour** of attempted contact.
- An operator command explicitly removes them.

Implementations MUST NOT evict peers solely for outer-header-failed
packets (§ 5.7 steps 1–5), because those failures can be induced by
any on-path adversary and form a trivial blocklist-poisoning
vector.

> **Design decision (v0.1):** Eviction policy distinguishes
> failures that *require* possession of the recipient's onion key
> (post-AEAD) from those that don't (pre-AEAD). Only the former
> are attributable to the named sender.

### 7.5. Anti-Sybil considerations

v0.1 has **no** protocol-level anti-Sybil mechanism. Operators are
expected to size their seed lists and peer-table caps such that
Sybil populations cannot dominate any honest node's gossip view.

> **Design decision (v0.1):** Defer anti-Sybil to v0.2. Proof-of-
> work, vouching graphs, and stake-based anti-Sybil are all
> distinguishably costly to operators and users; v0.1 keeps the
> protocol surface small enough that an audit can scope to it
> meaningfully.

---

## 8. Forwarding model

### 8.1. One-hop forwarding semantics

A v0.1 anonymous-layer packet is delivered in **at most two hops**:

- A direct packet: sender → recipient. The packet's
  `recipient_prefix` (§ 5.2) identifies the recipient; the AEAD is
  decryptable only by the recipient's onion key.
- A forwarded packet: sender → forwarder → recipient. The packet
  reaching the forwarder is itself a one-hop packet whose recipient
  is the forwarder; its inner plaintext is a `FORWARD` (§ 6.5)
  carrying a complete inner packet whose recipient is the next hop.

In both cases, each *hop* terminates a complete AEAD-protected
packet. Forwarders never decrypt the inner packet, and senders never
construct a packet that traverses more than two hops in v0.1.

### 8.2. What v0.1 does not provide

v0.1 forwarding **does not**:

- Provide circuit-level anonymity (Tor's onion routing).
- Mix multiple senders' traffic across many hops to defeat
  intersection attacks.
- Defend against a forwarder that is also the recipient (it
  trivially knows it received a `FORWARD` to itself).
- Defend against an active adversary who controls the forwarder and
  observes its uplink.

The anonymity provided by `FORWARD` in v0.1 is the modest property
that an *on-path observer of the sender's uplink* does not learn
the ultimate recipient. This is useful for cases such as: a
journalist behind a passive ISP eavesdropper publishing a message to
a target whose IP must not be tied to the journalist's traffic.

> **Design decision (v0.1):** Calling out the limits of one-hop
> forwarding is part of the spec to prevent overclaiming. Multi-hop
> circuits are v0.2 and will be specified with their own threat-
> model section.

### 8.3. Exit policy

Forwarders MAY publish, via the `transports` list in their own
`KEY_CERTIFICATE` (§ 6.6), an **exit-policy capability bit**
indicating that they accept `FORWARD` packets whose ultimate
destination is outside the anonymous-layer network (e.g., to a
plain-IP HTTP server). The exact bit assignment and policy-
description format are deferred to v0.2.

A v0.1 forwarder MUST treat unknown next-hop transport types as
"do not forward there" and drop the `FORWARD` packet silently.

---

## 9. Error handling

### 9.1. Silent-drop discipline

Every failure on the receive path (§ 5.7), regardless of cause,
results in **silent packet drop**. Specifically:

- **No error packet** is emitted in response to a failure.
- **No ICMP-style** notification (or equivalent at the transport
  layer) is sent.
- **No log message** that is observable on the wire (e.g., via
  timing of subsequent unrelated packets) distinguishes between
  failure causes.
- **No connection close** is performed in response to a single
  failed packet. Repeated failures MAY trigger transport-level
  policy (§ 9.3) but a single failure MUST NOT.

> **Design decision (v0.1):** Distinguishable error responses are
> the most common active-probing side channel in deployed network
> protocols. Silent drop is the strongest single guarantee a
> network-anonymity protocol can offer at the packet level.

### 9.2. Constant-time accept / reject

Implementations MUST take the same wall-clock time, within
measurement noise of the host platform, to process a packet
regardless of whether it ultimately succeeds or fails.

This is achievable by:

1. Performing every step in § 5.7 even on early failures (e.g., a
   bad outer-header byte does not skip the AEAD decryption); or
2. Adding a constant-time blinding delay to the failure path.

Approach (1) is preferred where the additional work is cheap (the
AEAD step is the dominant cost; doing it once on every packet is
acceptable).

### 9.3. Transport-level policy

While the *packet* layer drops silently, the *transport* layer (e.g.,
the WebSocket connection underneath) MAY apply rate-limiting and
disconnect policies against peers that send pathological volumes of
malformed packets. The thresholds are implementation-defined.
RECOMMENDED defaults:

- **Per-peer:** if more than 64 malformed packets are received from
  a single transport connection within 60 seconds, the connection
  MAY be closed without notice.
- **Per-source-IP:** the same threshold applies to all transport
  connections originating from the same network-layer source IP, if
  observable.

> **Design decision (v0.1):** Transport-level disconnection is
> intentionally separated from packet-level processing. The two
> have different observability properties: a transport disconnect
> is visible to the peer (they see TCP RST or WebSocket close), but
> only after a sustained pattern, not from a single probe.

### 9.4. Local logging

Implementations MAY log packet processing failures to a *local*
log. Logs SHOULD distinguish failure causes (bad version,
AEAD failure, padding failure, replay, …) for operator debugging.
Logs MUST NOT be transmitted over the wire by the protocol itself.
Operator-grade log shipping is out of scope for this document.

---

## 8. Forwarding model

> **Status: TODO.** Anticipated content:
>
> - One-hop forwarding semantics for v0.1 (no circuits; each packet
>   independently routed).
> - Exit policy and abuse mitigation.
> - Multi-hop construction (v0.2 preview).

---

## 9. Error handling

> **Status: TODO.** Will specify the constant-time, side-channel-safe
> response to: malformed packets, expired certificates, replayed
> nonces, decryption failures, and over-long packets.

---

## 10. Protocol versioning

### 10.1. Version byte

The first byte of every packet (§ 5.2) is the protocol version. This
document specifies version `0x01`.

A packet whose version byte does not match a version the implementation
supports MUST be dropped silently at step 2 of the receive-path checks
(§ 5.7). No error packet, ICMP-style reply, or distinguishable timing
behaviour is emitted.

### 10.2. Compatibility rules

- **Major-version boundary.** Versions `0x01` through `0x0F` reserve
  the low nibble for backward-compatible revisions and the high nibble
  for major versions. Major versions are not interoperable. A node
  supporting only `0x01` MUST drop `0x02..0xFF` packets without
  processing.
- **Minor-version semantics.** Within a major version, packet *fields*
  defined in this document MUST NOT change interpretation; new packet
  *types* MAY be added (§ 6 reserves a registry for this). A node MUST
  treat unknown packet types as if the packet had been dropped at step
  10 of § 5.7 — silently, no response.
- **Bucket additions.** New `bucket` values (e.g., `0x04` for 16384
  bytes) MAY be introduced in a future minor version. A v0.1 node
  receiving a packet with an unknown `bucket` value MUST drop it at
  step 3 of § 5.7.

### 10.3. Negotiation

Version `0x01` performs **no** explicit version negotiation. Nodes
emit packets at the highest version they support; recipients drop
packets at versions they do not support. Future versions MAY introduce
a capability-advertisement coordination packet to enable graceful
fallback.

> **Design decision (v0.1):** No version-negotiation handshake. The
> network layer is one-shot per packet (§ 1.1); a handshake would add
> round trips that defeat the latency advantage of one-shot delivery.
> Senders are expected to learn a recipient's supported version out of
> band (e.g., from the recipient's key certificate's extensions in a
> future revision).

---

## 11. Security considerations

> **Status: TODO (depends on Phase 3 threat model).** Will mirror the
> threat model document and describe, for each adversary class, which
> primitives and protocol mechanisms defend against which capabilities.

---

## 12. References

[rfc2119]: https://www.rfc-editor.org/rfc/rfc2119 "Key words for use in RFCs to Indicate Requirement Levels"
[rfc5869]: https://www.rfc-editor.org/rfc/rfc5869 "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)"
[rfc7693]: https://www.rfc-editor.org/rfc/rfc7693 "The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)"
[rfc7748]: https://www.rfc-editor.org/rfc/rfc7748 "Elliptic Curves for Security"
[rfc8032]: https://www.rfc-editor.org/rfc/rfc8032 "Edwards-Curve Digital Signature Algorithm (EdDSA)"
[rfc8439]: https://www.rfc-editor.org/rfc/rfc8439 "ChaCha20 and Poly1305 for IETF Protocols"

- [RFC 2119][rfc2119] — Requirements language.
- [RFC 5869][rfc5869] — HKDF.
- [RFC 7693][rfc7693] — Blake2.
- [RFC 7748][rfc7748] — Curve25519 / X25519.
- [RFC 8032][rfc8032] — Ed25519.
- [RFC 8439][rfc8439] — ChaCha20-Poly1305.

---

## 13. Appendix A: Design decisions ledger

Each row records a non-obvious decision made while drafting this
specification. New entries are appended at the bottom; existing entries
are never deleted (use a follow-on entry to record a reversal). Dates
are ISO 8601.

| # | Date | Decision | Rationale | Reversibility |
|---:|---|---|---|---|
| 1 | 2026-05-19 | Clean break from the pre-spec on-wire format. | The pre-spec implementation has 6 critical defects (`AUDIT_PREP.md` § 3) and zero deployed users; preserving compatibility would lock in those defects. | Permanent. |
| 2 | 2026-05-19 | Cryptographic primitives are exclusively libsodium-equivalent IETF standards: X25519, ChaCha20-Poly1305, Blake2b-256, HKDF-SHA-256, Ed25519. | All five primitives are constant-time, widely implemented, and have decades of academic review. None are bespoke. | Reversible only by a major version. |
| 3 | 2026-05-19 | All randomness for cryptographic values MUST come from the OS CSPRNG (`crypto.randomFillSync` in Node.js). | The pre-spec code used `Math.random()`-seeded custom PRNG — critical finding C1 in `AUDIT_PREP.md`. | Permanent (universally true property of secure protocols). |
| 4 | 2026-05-19 | One-hop forwarding only in v0.1; multi-hop / circuits are v0.2. | Multi-hop construction is a substantial design problem (cell sizing, traffic-analysis padding, per-hop key derivation). Shipping the v0.1 foundation first lets us iterate on the multi-hop layer separately. | Reversible (v0.2 is additive). |
| 5 | 2026-05-19 | Node identity is split into a long-term Ed25519 identity key and a 7-day-rotated X25519 onion key, bound by a 105-byte key certificate. | Standard hygiene: limit damage from any single key compromise. Identity-key compromise still requires a full identity rotation, but onion-key compromise expires within a week. | Reversible (rotation period is a parameter). |
| 6 | 2026-05-19 | Wire format uses three fixed-size buckets (256 / 1024 / 4096 bytes). | Defends against length-based traffic correlation across hops; balances bandwidth overhead against length-leakage. Tor's 514-byte cell precedent. | Reversible (additional buckets are forward-compatible per § 10.2). |
| 7 | 2026-05-19 | Each packet uses a fresh ephemeral X25519 keypair; the AEAD key is `HKDF(KX(eph_sk, onion_pk), "anon-layer/v1/aead", 32)`. Nonce is `RAND(12)`. | Single-use keys remove nonce-reuse risk entirely. Forward-secrecy per packet, not per session. | Reversible (v0.2 session protocol layered on top). |
| 8 | 2026-05-19 | The sender's identity fingerprint appears *inside* the AEAD, not in the outer header. | Network observers must not learn who sent a packet; only the recipient learns. The sender is "network-layer anonymous" to everyone except the recipient. | Permanent property. |
| 9 | 2026-05-19 | No sender signature inside the network-layer packet. Applications that need non-repudiation sign at the payload layer. | Saves 64 bytes per packet and avoids implying a security property the network layer doesn't enforce (the AEAD only proves *someone* with a working ephemeral key sent the packet, not *which* claimed-fingerprint sender). | Reversible (signed packet types can be added in § 6). |
| 10 | 2026-05-19 | Replay-protection log is per-recipient and keyed by `(ephPk, nonce)`. Minimum 8192 entries and ≥ 300 s retention. | Network-layer-anonymous senders cannot be used as a log key; the ephemeral key is already a unique single-use token in honest traffic. | Reversible (bounds are parameters). |
| 11 | 2026-05-19 | All receive-path failures are silent and constant-time. No error packets, no ICMP-style replies, no observable timing differences. | Distinguishable error responses are a primary side channel for active probing. Silent drop is the strongest guarantee. | Permanent. |
| 12 | 2026-05-19 | Version byte is the first byte of every packet, single-byte. Major / minor split into high / low nibble. | Single-byte parsing is the cheapest possible filter; nibble-split allows backward-compatible minor extensions. | Reversible by major version. |
| 13 | 2026-05-19 | No explicit version-negotiation handshake. Receivers silently drop unsupported versions. | One-shot semantics preclude a round-trip handshake; future revisions can layer capability discovery on top via a coordination packet. | Reversible (future versions can add). |
| 14 | 2026-05-19 | v0.1 packet-type registry has four types: `DATA` (0x01), `ANNOUNCE_PEER` (0x02), `FORWARD` (0x03), `KEY_CERTIFICATE` (0x04). | Smallest set that supports one-hop messaging, gossip peer discovery, one-hop forwarding, and key-material bootstrap. Pre-spec `FASTER_LINK_*` and `REDIRECT_STATIC` types deferred to v0.2 (session protocol). | Reversible (registry is extensible per § 10.2). |
| 15 | 2026-05-19 | `DATA` payloads are opaque to the network layer. End-to-end authentication / encryption is the application's responsibility. | Clean layering boundary. Lets the same network carry chat, file transfer, and other application protocols without protocol-version churn. | Permanent property. |
| 16 | 2026-05-19 | `FORWARD` packets are rate-limited per source ephemeral key (32/min), per destination fingerprint (64/min), and globally (4096/min). | Closes the open-amplification primitive flagged in `AUDIT_PREP.md` H3. Conservative limits subject to Phase 3 / Phase 5 refinement. | Reversible (limits are parameters). |
| 17 | 2026-05-19 | A forwarder MUST NOT modify the inner packet (no re-encryption, no re-padding). The inner packet is opaque ciphertext to the forwarder. | Preserves end-to-end AEAD authentication; ensures that an honest forwarder cannot accidentally compromise sender anonymity by altering observable properties. | Permanent property. |
| 18 | 2026-05-19 | `ANNOUNCE_PEER` and `KEY_CERTIFICATE` are split. The latter ships the raw `idPk`; the former assumes the receiver already knows it. | Ed25519 signatures don't embed the public key. Rather than inline `idPk` in every announcement (a 32-byte cost on every gossip packet), it is published once via `KEY_CERTIFICATE` and cached. A future revision may merge them. | Reversible (can merge in v1 minor revision via type registry). |
| 19 | 2026-05-19 | Seed-list signing is out of scope for v0.1; treated as a deployment concern. | Mirrors Tor's hard-coded directory authorities. Adds protocol-level seed signing only if cross-implementation seed interchange becomes common. | Reversible (additive in v0.2). |
| 20 | 2026-05-19 | Gossip cadence default: one `ANNOUNCE_PEER` per peer per 30 s. | Pre-spec 750 ms cadence saturated idle networks at >1 pps per peer. 30 s scales to ~1000-node networks. Larger networks are out of scope for v0.1. | Reversible (cadence is a parameter). |
| 21 | 2026-05-19 | Peer eviction distinguishes pre-AEAD failures (attributable to any on-path adversary) from post-AEAD failures (attributable to the named sender). Only the latter cause eviction. | Pre-AEAD eviction is a trivial blocklist-poisoning vector. | Permanent property. |
| 22 | 2026-05-19 | No protocol-level anti-Sybil in v0.1; deferred to v0.2. | Proof-of-work / vouching / stake all have distinct operator and user costs; choosing one prematurely locks in a deployment story. | Reversible (additive in v0.2). |
| 23 | 2026-05-19 | v0.1 forwarding is one-hop only (at most two AEAD-protected hops total). Tor-style circuits are v0.2. | Spec is small enough to audit. Honest about the limited anonymity v0.1 provides (sender-uplink-observer protection only). | Reversible (additive in v0.2). |
| 24 | 2026-05-19 | Silent-drop discipline is normative for every receive-path failure. No error packets, no ICMP-style replies, no observable timing differences. | Distinguishable error responses are the most common active-probing side channel. | Permanent property. |
| 25 | 2026-05-19 | Transport-level rate-limit / disconnect policy is *separate* from packet-level silent-drop, with different observability. Per-peer ~64 malformed packets / 60 s threshold. | Single-probe attacks must be undetectable; sustained abuse may be visibly mitigated. | Reversible (thresholds are parameters). |
