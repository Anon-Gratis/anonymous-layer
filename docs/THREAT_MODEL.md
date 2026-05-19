# Anonymous Layer Threat Model

| | |
|---|---|
| **Document** | Anonymous Layer Threat Model |
| **Version** | 0.1 (draft) |
| **Date** | 2026-05-19 |
| **Status** | **DRAFT — companion to [`SPEC.md`](SPEC.md) v0.1; not yet audited** |
| **Editor** | Anonymous Gratis `<admin@anon.gratis>` |
| **License** | AGPL-3.0-or-later (see [`../LICENSE`](../LICENSE)) |

> This document enumerates the anonymity-relevant properties the v0.1
> protocol claims and does not claim, the adversaries it defends against,
> and the protocol mechanisms that provide each defence. Read with
> [`SPEC.md`](SPEC.md) alongside; the section references below point into
> that document.

---

## Table of contents

1. [Scope](#1-scope)
2. [Anonymity properties](#2-anonymity-properties)
3. [Adversary classes](#3-adversary-classes)
4. [Capability-by-property matrix](#4-capability-by-property-matrix)
5. [Defensive mechanisms](#5-defensive-mechanisms)
6. [Residual risks](#6-residual-risks)
7. [Environmental assumptions](#7-environmental-assumptions)
8. [Out of scope](#8-out-of-scope)
9. [Methodology](#9-methodology)

---

## 1. Scope

### 1.1. What this document covers

- The **anonymity properties** the v0.1 protocol is intended to deliver
  to honest users running conforming implementations.
- The **adversary classes** the protocol defends against, each
  parameterised by what they can observe and what they can do.
- The **mechanisms** in [`SPEC.md`](SPEC.md) that provide each defence,
  and the **residual risks** that remain even when every mechanism is
  applied correctly.
- The **environmental assumptions** under which the claimed properties
  hold.

### 1.2. What this document does not cover

- Application-layer protocols carried by the network (chat, file
  transfer, etc.). End-to-end confidentiality and authentication
  of *payloads* is the application's responsibility. The network
  layer is intentionally payload-opaque (`SPEC.md` § 6.3).
- Operating-system security of the device a node runs on.
- Physical and legal coercion of operators, users, and developers.
- Side channels exposed by the host platform (electromagnetic
  emanations, RowHammer-style memory attacks, etc.) below the level
  of cryptographic primitive implementation.

### 1.3. Relation to `SPEC.md`

`SPEC.md` § 11 (Security considerations) mirrors this document
section-by-section once the threat model is stable. Edits here MUST
be reflected there before any release candidate cycle.

---

## 2. Anonymity properties

The protocol describes anonymity in terms of three pairwise
**unlinkability** properties between honest parties and an adversary
identified in § 3.

### 2.1. Sender anonymity

**Claim:** Given a packet observed by an adversary in class A, B, or
D (see § 3), the adversary SHALL NOT be able to attribute that packet
to a specific sender identity (`idPk` per `SPEC.md` § 4.1) with
probability appreciably greater than the size of the network's
honest-sender anonymity set at the time of observation.

**Mechanism summary:** The sender's identity fingerprint appears only
*inside* the AEAD-protected inner plaintext (`SPEC.md` § 5.4). The
outer header reveals only an ephemeral, single-use X25519 public key
that is generated freshly per packet and provides no link to any
long-term identity.

### 2.2. Recipient anonymity

**Claim:** Given a packet observed by an adversary in class A, B, or
D *on the sender-side link*, the adversary SHALL NOT be able to learn
the ultimate recipient identity if the packet was sent via a
`FORWARD` (`SPEC.md` § 6.5).

**Mechanism summary:** A `FORWARD` packet's outer header names only
the forwarder, not the ultimate recipient. The recipient's identity
appears only after the forwarder decrypts the AEAD.

**Limitation:** A direct (non-forwarded) packet *does* reveal the
recipient prefix in cleartext (`SPEC.md` § 5.2). Recipient anonymity
against an on-path sender-side observer requires the use of
`FORWARD`. Recipient anonymity against a forwarder is **not claimed**;
the forwarder by definition sees the next hop.

### 2.3. Sender–recipient unlinkability

**Claim:** Given two packets observed on disjoint links by an
adversary in class A, B, or D, the adversary SHALL NOT be able to
determine whether they belong to the same sender–recipient pair with
probability appreciably greater than the rate of accidental
co-occurrence in the honest-traffic baseline.

**Mechanism summary:** Fresh ephemeral keys per packet
(`SPEC.md` § 5.3), fixed-size buckets that prevent length-based
correlation (`SPEC.md` § 5.1), and AEAD that prevents content-based
fingerprinting.

**Limitation:** Sender–recipient unlinkability is **not** claimed
against:

- An adversary observing both endpoints' links simultaneously
  (class C, "global passive").
- An adversary running a peer that participates in the conversation
  (class E or F).
- Timing-correlation attacks across hops in v0.1, which has only
  one-hop forwarding (`SPEC.md` § 8.2) — multi-hop unlinkability is
  a v0.2 concern.

---

## 3. Adversary classes

Each adversary is described by its **observation** (what links and
nodes it sees) and its **capability** (what actions it can take).

### Class A — Local passive observer (LPO)

**Observation:** One specific network link adjacent to one honest
party (e.g., the user's ISP, an open WiFi access point, an
on-LAN sniffer).

**Capability:** Read every packet on that link. Cannot inject, drop,
or modify. Cannot read packets on any other link.

**Realism:** Trivially achievable. Every adversary worth defending
against has at least this capability.

### Class B — Regional passive observer (RPO)

**Observation:** A non-negligible fraction of all links in some
geographic or topological region (e.g., a national-level adversary
with cooperating ISPs).

**Capability:** Read every packet on every observed link. Cannot
inject, drop, or modify. Cannot read packets on unobserved links.

**Realism:** Achieved by several major signals-intelligence
agencies in production today.

### Class C — Global passive observer (GPO)

**Observation:** Every link in the network simultaneously.

**Capability:** Read every packet anywhere. Cannot inject, drop, or
modify.

**Realism:** Probably unachievable at scale due to encrypted backbone
links and undersea cable physics, but treated as theoretically
possible.

**Position in this protocol:** **Out of scope** for v0.1 defence.
A GPO defeats every anonymity-network design that does not introduce
heavy cover traffic (which v0.1 explicitly does not). Stating this
explicitly is the point of this section.

### Class D — Active on-path adversary (AOPA)

**Observation:** A subset of links, as in class A or B.

**Capability:** All passive capabilities of class A/B, plus: inject
arbitrary packets, drop arbitrary packets, modify packets, replay
captured packets, induce packet reordering.

**Realism:** Achievable by anyone with a router on a link the victim
traverses, plus most public WiFi operators, ISPs willing to abuse
their position, and BGP-hijack-capable adversaries.

### Class E — Single compromised peer (SCP)

**Observation:** Whatever the peer software receives during normal
protocol operation: incoming packets, results of any forwarding it
performs.

**Capability:** Run the peer software with arbitrary modifications,
including refusing to forward, fabricating peer-announce packets,
logging everything, attempting key exfiltration of in-RAM state.

**Realism:** Trivial. Anyone can run a peer.

### Class F — Coalition of compromised peers (CCP)

**Observation:** Union of what each peer in the coalition sees.

**Capability:** Combine information across nodes; coordinate
forwarding decisions; simulate honest behaviour while logging.
Bounded by a parameter `c` (the coalition's fraction of total nodes).

**Realism:** Achievable by a well-resourced adversary running many
nodes. Sybil attack is the dominant route to high `c`.

**Defence threshold in v0.1:** The protocol does not provide a
formal bound. v0.2 will quantify resistance once anti-Sybil
(deferred per `SPEC.md` § 7.5) is specified.

### Class G — Endpoint compromise (EC)

**Observation:** Full memory and disk of one endpoint device.

**Capability:** All cryptographic keys present on that device,
including long-term identity keys.

**Realism:** Achievable via malware, physical seizure, or supply-
chain attack on the device.

**Position in this protocol:** **Out of scope.** No network-layer
protocol can recover from endpoint compromise. Mentioned here only
to set expectations.

### Class H — Coercer

**Observation:** Whatever the coerced party reveals.

**Capability:** Compel an operator, user, or developer (legally or
extralegally) to act on the adversary's behalf, including key
disclosure and protocol-rule violation.

**Realism:** A reality in the protocol's target deployments.

**Position in this protocol:** **Out of scope** for cryptographic
defence. The protocol's defence here is **deniability of operation**
(the AGPL licence and pseudonymous authorship reduce the
identifiability of individual operators) and **forward secrecy** of
ephemeral keys (a coerced operator cannot retroactively decrypt
packets they did not capture in real time).

### Class I — Application-layer fingerprinter (ALF)

**Observation:** Whatever the endpoint reveals at the application
layer (HTTP headers, TLS fingerprints, behavioural timing, content).

**Capability:** Match observed traffic features against a profile
of known users / sessions.

**Realism:** The dominant practical de-anonymisation vector in
deployed anonymity tools today.

**Position in this protocol:** **Out of scope.** The network layer
delivers opaque application bytes (`SPEC.md` § 6.3) and cannot
influence what the application says.

---

## 4. Capability-by-property matrix

`✔` indicates the protocol claims defence; `✘` indicates explicit
non-defence; `~` indicates partial defence with caveats described
below the table.

| Adversary → / Property ↓ | A (LPO) | B (RPO) | C (GPO) | D (AOPA) | E (SCP) | F (CCP) | G (EC) | H (Coercer) | I (ALF) |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Sender anonymity (§ 2.1) | ✔ | ✔ | ✘ | ✔ | ~₁ | ~₂ | ✘ | ✘ | ✘ |
| Recipient anonymity, FORWARD (§ 2.2) | ✔ | ✔ | ✘ | ✔ | ~₃ | ~₂ | ✘ | ✘ | ✘ |
| Recipient anonymity, direct packet | ✘ | ✘ | ✘ | ✘ | ✔ | ~₂ | ✘ | ✘ | ✘ |
| Sender–recipient unlinkability (§ 2.3) | ✔ | ~₄ | ✘ | ~₅ | ~₁ | ~₂ | ✘ | ✘ | ✘ |
| Confidentiality of payload | ✔ | ✔ | ✔ | ✔ | ~₆ | ~₆ | ✘ | ~₇ | ✘ |
| Integrity of payload | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✘ | ✔ | ✔ |
| Replay resistance | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✘ | ✔ | ✔ |

**Caveats:**

- **₁** A peer that is *one endpoint* of the conversation knows who it
  is talking to. "Sender anonymity to E/F" is meaningful only for
  peers not party to the specific conversation.
- **₂** Coalition-of-peers defences depend on the coalition's
  fraction `c` and the path-selection algorithm. v0.1 has no formal
  bound; defence is qualitative.
- **₃** A peer that *is* the forwarder of a `FORWARD` packet learns
  the next hop. "Recipient anonymity to E" applies to peers that
  are neither sender, forwarder, nor recipient.
- **₄** Sender–recipient unlinkability degrades as the RPO's
  observed link fraction approaches 100% (which converges to the
  GPO case).
- **₅** An AOPA can mount targeted active correlation attacks
  (selective packet drop, traffic-shape injection) that are stronger
  than passive correlation. v0.1 does not defend against these.
- **₆** A peer that is the AEAD recipient sees the inner plaintext;
  that includes the *payload* bytes which the application is then
  responsible for end-to-end encrypting if confidentiality from peers
  is required.
- **₇** Coerced operators cannot retroactively decrypt past packets
  they did not capture (forward secrecy of ephemeral keys), but they
  can disclose any captured ciphertext together with the AEAD key
  they computed at receive time if they captured both.

---

## 5. Defensive mechanisms

This section maps each protocol mechanism in `SPEC.md` to the
adversary capability it defeats or mitigates.

### 5.1. Fresh ephemeral X25519 per packet (`SPEC.md` § 5.3)

**Defeats:** A → sender anonymity; D → replay; D → cross-packet
linking by long-term sender public-key fingerprinting.

**Mechanism:** Each packet's outer header carries only a 32-byte
random-looking X25519 public key with no link to any prior packet.
An adversary cannot bucket packets by "same sender" using outer-
header bytes alone.

**Forward secrecy:** Because the ephemeral secret is discarded
immediately after the packet is sent (`SPEC.md` § 5.8 step 9), a
coercer (class H) who later compels an operator cannot retroactively
decrypt past packets even if they captured them.

### 5.2. Sender identity inside AEAD (`SPEC.md` § 5.4)

**Defeats:** A, B, D → sender anonymity from non-recipients.

**Mechanism:** The 32-byte sender identity fingerprint is part of
the AEAD plaintext, not the cleartext header. Only a party able to
compute the AEAD key — i.e., the holder of the recipient onion
secret key — sees it.

### 5.3. Fixed-size buckets (`SPEC.md` § 5.1)

**Defeats:** A, B → sender–recipient unlinkability via length
correlation.

**Mechanism:** Three fixed packet sizes (256, 1024, 4096 bytes)
collapse the per-packet length leakage to a 2-bit observation.

**Limitation:** A sustained-traffic adversary can still infer
aggregate volume; the bucket scheme defends against per-packet
length correlation, not bandwidth correlation.

### 5.4. AEAD over outer header (`SPEC.md` § 5.5)

**Defeats:** D → integrity of routing-relevant headers.

**Mechanism:** The full 54-byte outer header is the AEAD's
associated data. Any modification by an active adversary causes
Poly1305 tag verification to fail and the packet to be silently
dropped.

### 5.5. Zero-padding inside AEAD (`SPEC.md` § 5.4)

**Defeats:** D → truncation / extension attacks; A, B → length
inference within a bucket.

**Mechanism:** The padding region's all-zero contents are
authenticated by the AEAD. A receiver MUST verify the padding;
truncation or extension by an active attacker results in either an
AEAD-tag failure or a padding-check failure (both silent drops).

### 5.6. Silent-drop + constant-time discipline (`SPEC.md` § 5.7, § 9)

**Defeats:** D → active-probing side channels; A, B → packet-
classification timing channels.

**Mechanism:** No error packets, no observable timing differences
between accept/reject paths. An adversary probing the network
cannot distinguish "you are a node" from "you are not" by sending
malformed packets and timing the absence-of-response.

### 5.7. Replay-window log (`SPEC.md` § 5.6)

**Defeats:** D → replay attacks.

**Mechanism:** Each recipient retains (`ephPk`, `nonce`) of every
recently-accepted packet. Replays are silently dropped before
dispatch.

### 5.8. FORWARD rate limits (`SPEC.md` § 6.5.1)

**Defeats:** D → amplification using a forwarder; D → directed-
flooding DoS via forwarders.

**Mechanism:** Per-source, per-destination, and global rate limits
on `FORWARD` processing.

### 5.9. Eviction policy distinguishing pre/post-AEAD failures (`SPEC.md` § 7.4)

**Defeats:** D → peer-table poisoning by injected malformed packets.

**Mechanism:** Only failures that *require* the recipient's onion
secret key (post-AEAD failures) cause peer eviction. Failures
attainable by any on-path adversary do not.

### 5.10. Mandatory CSPRNG-only randomness (`SPEC.md` § 3.1)

**Defeats:** Every adversary, in every property — by ruling out the
single most catastrophic implementation defect (PRNG-state recovery
from observed outputs).

**Mechanism:** Implementations MUST source all secret-bearing random
values from the OS CSPRNG. The reference implementation enforces
this in `modules/random/index.mjs`.

---

## 6. Residual risks

These are anonymity-relevant attacks that the protocol does **not**
defeat, listed here so operators and auditors can decide whether
the residual is acceptable for a given deployment.

### 6.1. Intersection attacks

An adversary who watches the network over time and correlates which
nodes were online during each of a target's observed activities can
intersect the candidate sets and narrow down the target. v0.1 has
no per-packet cover traffic, no padding for *temporal* presence, and
no pseudonym rotation, so a long-running adversary against a
recurring user erodes the anonymity set monotonically.

**Mitigation:** Operators concerned about intersection should run
long-lived peers with constant presence rather than only when
sending traffic. v0.2 may introduce cover traffic.

### 6.2. Predecessor / first-hop attack

A peer that often appears as the first hop on a target's `FORWARD`
chains will, over time, learn that the target is the sender. v0.1's
one-hop forwarding (`SPEC.md` § 8) does not offer a path-selection
strategy to defend against this; multi-hop in v0.2 will.

### 6.3. Sybil-amplified peer-table flooding

Although `ANNOUNCE_PEER` requires a valid key certificate
(`SPEC.md` § 6.4), an adversary willing to generate large numbers of
Sybil identities can flood honest nodes' peer tables and dominate
gossip. v0.1 has no anti-Sybil; this is `SPEC.md` design decision 22.

### 6.4. Endpoint compromise

Class G (endpoint compromise) is out of scope. The protocol cannot
defend a compromised endpoint; the protocol can, however, ensure
that endpoint compromise does not retroactively decrypt past traffic
(§ 5.1, forward secrecy).

### 6.5. Implementation side channels

Constant-time implementations of X25519, ChaCha20-Poly1305, and
Ed25519 are required (`SPEC.md` § 3), but:

- Memory-allocation patterns may leak.
- Garbage collector pauses in JavaScript runtimes may leak.
- CPU cache patterns of the underlying libsodium / OpenSSL build
  may leak under co-located attacker (e.g., a malicious cloud
  neighbour).

These are out of scope for the protocol document but in scope for
implementation-level audit (Phase 5 of the production-readiness
roadmap).

### 6.6. Application-layer fingerprinting (class I)

The protocol carries opaque application bytes (`SPEC.md` § 6.3) and
cannot defend against an application that fingerprints itself.

### 6.7. Traffic-volume correlation

A regional adversary observing aggregate volume to/from a node can
correlate "this node sent traffic in the same minute the target
website received traffic." Fixed-size buckets help only on a per-
packet basis; they do not change aggregate volume.

---

## 7. Environmental assumptions

The properties of § 2 are claimed only under the following
assumptions. Each is stated explicitly because audit findings
against the protocol depend on whether the assumption holds.

### 7.1. Cryptographic primitives

- X25519 (RFC 7748), ChaCha20-Poly1305 (RFC 8439), Blake2b-256
  (RFC 7693), HKDF-SHA-256 (RFC 5869), and Ed25519 (RFC 8032) are
  assumed cryptographically sound at the parameter sizes specified.
- The implementations used are assumed constant-time and free of
  side-channel leaks beyond those listed in § 6.5.

### 7.2. Randomness

- The host OS CSPRNG is correctly seeded and produces output
  indistinguishable from uniform random to any computationally-
  bounded adversary.

### 7.3. Trusted computing base

- The OS kernel, language runtime, and any third-party crypto
  library used are not malicious.
- Implementations are deployed without unsigned modifications.

### 7.4. Key generation and storage

- Identity keypairs are generated using the host CSPRNG
  (`SPEC.md` § 3.1) and stored encrypted-at-rest on devices that
  warrant it (`SPEC.md` § 4.1).

### 7.5. Honest user behaviour

- Users do not voluntarily reveal their identity (e.g., by logging
  into a username-based service on top of the network).
- Users do not deploy the protocol on the same machine as
  fingerprinting applications that they expect to remain unlinked
  to their anonymous-layer traffic.

### 7.6. Network topology

- The network has at least *some* honest nodes the user can connect
  to. The protocol degrades gracefully against partial Sybil
  populations but provides no defence against a fully-Sybil
  network.

---

## 8. Out of scope

Stated separately for clarity. The protocol explicitly does **not**
defend against the following, regardless of how much an operator
might wish otherwise:

| Out-of-scope concern | Why out of scope |
|---|---|
| Global passive adversary (class C) | Heavy cover traffic would be required and is not in v0.1. |
| Endpoint compromise (class G) | No network-layer defence is possible. |
| Coercion of operators / users (class H) | Out of cryptographic scope; partially mitigated by forward secrecy. |
| Application-layer fingerprinting (class I) | The network carries opaque bytes; defence is the application's job. |
| Long-running intersection attacks | v0.1 has no cover traffic; v0.2 may. |
| Multi-hop circuit anonymity | v0.1 is one-hop; v0.2 will specify. |
| Anti-Sybil at the protocol layer | Deferred to v0.2 per `SPEC.md` design decision 22. |
| Censorship-resistant transports | A separate companion spec. |
| Quantum adversaries | All chosen primitives are classically secure but not post-quantum. v0.3 may introduce post-quantum key agreement (Kyber/Frodo) once an IETF standard is stable. |

---

## 9. Methodology

This document was produced by reading the v0.1 specification and
applying the STRIDE framework loosely to each protocol mechanism,
then organising the findings by adversary class and property rather
than by STRIDE category (which is more useful for application-layer
threat models). Where a STRIDE category mapped naturally to a class
above, it is implicit:

| STRIDE | Mapped class(es) |
|---|---|
| Spoofing | D (active on-path), E/F (peers spoofing identities) |
| Tampering | D |
| Repudiation | Out of scope at the network layer; see `SPEC.md` § 5.4 design decision 9. |
| Information disclosure | A, B, C, D, E, F |
| Denial of service | D, F (DoS at network or peer-table level) |
| Elevation of privilege | Not meaningfully applicable to this protocol |

This document SHOULD be re-validated against a more formal
adversary model before external audit engagement (Phase 6). A
formal-method or symbolic-analysis pass (e.g., ProVerif, Tamarin)
on the AEAD construction (§ 5 of `SPEC.md`) is in scope for the
audit-preparation work.
