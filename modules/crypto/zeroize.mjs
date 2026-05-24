// Zeroization helper and library-wide lifetime contract.
//
// Lifetime contract — what the anon-layer library owns and zeros:
//
//   Wire layer (modules/wire/packet.mjs)
//   - sender ephemeral X25519 secret key   zeroed at end of encodePacket
//   - X25519 shared secret (send + recv)   zeroed after AEAD key derivation
//   - derived per-packet AEAD key          zeroed after AEAD step
//
//   Peer layer (modules/peer/table.mjs)
//   - evicted peer record buffers          zeroed before deletion
//     (idPk, fingerprint, certBytes, onionPk, transport addresses)
//
//   Crypto layer (modules/crypto/onion.mjs, cert.mjs, identity.mjs)
//   - AEAD outputs are copies, not aliases (no Buffer pool exposure).
//   - Long-lived node identity (idSk, onionSk) is NOT zeroed: it must
//     live for the node's full process lifetime.
//
// What the library does NOT zero — caller responsibility:
//
//   - The plaintext buffer handed to encodePacket()
//   - The payload Uint8Array delivered to onData() callbacks
//   - On-disk identity files (persistence.mjs writes them; only the
//     in-memory `idSk`/`onionSk` are eligible for zeroization at all,
//     and they live for the process lifetime as noted above)
//
// V8 + the kernel ultimately decide when freed memory is reclaimed and
// whether it is scrubbed. Zeroization here narrows the window during
// which sensitive bytes are reachable from JS land; it does not turn
// userspace into a secure enclave.
//
// All call-sites should use this helper rather than open-coding
// `.fill(0)`. Grep-ability matters when an auditor wants to find every
// place we touch sensitive state.

export const zeroize = (buf) => {

    if (!buf) return buf;
    if (buf.fill) buf.fill(0);
    return buf;

};
