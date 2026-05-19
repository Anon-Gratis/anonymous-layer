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
5. [Wire format](#5-wire-format) — *(TODO)*
6. [Coordination packets](#6-coordination-packets) — *(TODO)*
7. [Peer discovery and bootstrap](#7-peer-discovery-and-bootstrap) — *(TODO)*
8. [Forwarding model](#8-forwarding-model) — *(TODO)*
9. [Error handling](#9-error-handling) — *(TODO)*
10. [Protocol versioning](#10-protocol-versioning) — *(TODO)*
11. [Security considerations](#11-security-considerations) — *(TODO, depends on Phase 3 threat model)*
12. [References](#12-references)

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
> over XChaCha20-Poly1305 because nonces in this protocol are derived
> deterministically from a counter and per-direction key (§ 6),
> eliminating the need for a 24-byte random nonce. Implementations MAY
> additionally support XChaCha20-Poly1305 for application-layer payload
> encryption but the on-wire packet construction MUST use the standard
> 12-byte nonce.

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
| Per-packet session key (direction A→B) | `anon-layer/v1/session/AtoB` |
| Per-packet session key (direction B→A) | `anon-layer/v1/session/BtoA` |
| Per-packet nonce derivation seed | `anon-layer/v1/nonce` |

> **Design decision (v0.1):** Directional separation of session keys is
> baked into the KDF labels rather than into the protocol message
> structure, so a single X25519 exchange yields two independent session
> keys without an additional exchange.

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

> **Status: TODO (next chunk).** This section will define the on-wire
> packet structure. Anticipated content:
>
> - 16-byte fixed packet header (version, type, length, recipient
>   fingerprint prefix, sender ephemeral pubkey commitment).
> - 32-byte sender ephemeral X25519 public key.
> - 12-byte nonce.
> - Variable-length AEAD ciphertext.
> - 16-byte Poly1305 tag.
>
> Open design questions:
>
> - **Fixed vs. variable packet size.** Fixed size leaks less timing /
>   length information but wastes bandwidth on small messages.
>   Recommended: padding to fixed buckets (256 / 1024 / 4096 bytes).
> - **Replay protection.** Per-(sender, recipient) sequence number, or
>   a windowed nonce log?
> - **Versioning placement.** First byte (proposed) or first 4-byte
>   magic?

---

## 6. Coordination packets

> **Status: TODO.** This section will replace the existing
> `TYPE_COORDINATION_*` enumeration. Each type will be defined with:
>
> - Exact payload layout.
> - Pre- and post-conditions for processing.
> - Allowed transitions in any associated state machine.

---

## 7. Peer discovery and bootstrap

> **Status: TODO.** Anticipated content:
>
> - Static seed-list format (file, signing, distribution).
> - Gossip-mode peer-announcement semantics (replaces the current
>   750 ms continuousAnnouncePeer loop).
> - Anti-Sybil rate limits.
> - Bootstrap from out-of-band (PGP-signed seed manifests, dropbox-
>   style discovery hidden behind PGP).

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

> **Status: TODO.** v0.1 packets use version byte `0x01`. Forward-
> compatibility rules (must-ignore unknown extensions, must-fail
> unknown packet types in v1) will be specified here.

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
