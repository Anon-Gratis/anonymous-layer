// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

// Onion address codec for SPEC-v0.2-draft § 4.4.
//
// Two on-wire formats live side by side:
//
//   v2 (VERSION=0x02, Ed25519-only — legacy, pre-PQ):
//     onion_address = base32(SVC_pk || CHECKSUM || 0x02) + ".anon"
//     SVC_pk    32 bytes (Ed25519 public key)
//     CHECKSUM  Blake2b-256(".anon-checksum" || SVC_pk || 0x02)[0:2]
//
//   v3 (VERSION=0x03, hybrid Ed25519 + ML-DSA — quantum-safe identity):
//     onion_address = base32(identity_hash || CHECKSUM || 0x03) + ".anon"
//     identity_hash  Blake2b-256(SVC_pk_ed || SVC_pk_mldsa)
//     CHECKSUM       Blake2b-256(".anon-checksum" || identity_hash || 0x03)[0:2]
//
// Both formats encode to 56 base32 chars + ".anon" (35-byte body).
// v3 is binary-distinguishable from v2 via the version byte at offset
// 34. Decoders accept either; producers should default to v3 for any
// new service.
//
// Auditor notes (v3):
//
//   - The identity is the PAIR of pubkeys. Including both in the
//     address-derivation hash binds them at the URL level: a quantum
//     adversary who can forge Ed25519 still cannot construct the same
//     onion address with a substituted ML-DSA key. The hash is
//     Blake2b-256, collision-resistant against quantum (sqrt speedup
//     leaves 128-bit preimage security, well above breakable).
//
//   - The pubkeys are NOT recoverable from the address (it's a hash).
//     The descriptor carries them explicitly; the client verifies
//     hash(descriptor.pkEd || descriptor.pkMldsa) matches the address.
//
//   - Order matters: (Ed25519 || ML-DSA), exactly 32 + 1952 = 1984
//     bytes into Blake2b. Order is part of the wire format; changing
//     it would change every address.

import { blake2b } from '@noble/hashes/blake2.js';

import {
    ED25519_PK_BYTES,
    MLDSA_PK_BYTES,
} from '../crypto/hybrid_sign.mjs';

export const ONION_VERSION       = 0x02;   // v2 (legacy Ed25519-only)
export const ONION_VERSION_PQ    = 0x03;   // v3 (hybrid Ed25519 + ML-DSA-65)
export const ONION_ADDR_BYTES    = 35;
export const ONION_ADDR_CHARS    = 56;
export const ONION_ADDR_SUFFIX   = '.anon';
export const ONION_ADDR_FULL_LEN = ONION_ADDR_CHARS + ONION_ADDR_SUFFIX.length;

const CHECKSUM_PREFIX = new TextEncoder().encode('.anon-checksum');
const ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

// Build a reverse lookup once at module load.
const ALPHABET_INDEX = new Int8Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i += 1) {

    ALPHABET_INDEX[ALPHABET.charCodeAt(i)] = i;
    // Accept uppercase too — common in spoken/written sharing.
    ALPHABET_INDEX[ALPHABET.charCodeAt(i) & ~0x20] = i;

}

// ----- Base32 (RFC 4648 lowercase, no padding) -----

const base32encode = (bytes) => {

    const len = bytes.length;
    const outLen = Math.ceil((len * 8) / 5);
    const out = new Array(outLen);
    let buffer = 0;
    let bitsInBuffer = 0;
    let outIdx = 0;
    for (let i = 0; i < len; i += 1) {

        buffer = (buffer << 8) | bytes[i];
        bitsInBuffer += 8;
        while (bitsInBuffer >= 5) {

            bitsInBuffer -= 5;
            out[outIdx] = ALPHABET[(buffer >>> bitsInBuffer) & 0x1F];
            outIdx += 1;

        }

    }
    if (bitsInBuffer > 0) {

        out[outIdx] = ALPHABET[(buffer << (5 - bitsInBuffer)) & 0x1F];
        outIdx += 1;

    }
    return out.join('');

};

const base32decode = (s) => {

    const len = s.length;
    const outLen = Math.floor((len * 5) / 8);
    const out = new Uint8Array(outLen);
    let buffer = 0;
    let bitsInBuffer = 0;
    let outIdx = 0;
    for (let i = 0; i < len; i += 1) {

        const code = s.charCodeAt(i);
        const idx = code < 128 ? ALPHABET_INDEX[code] : -1;
        if (idx < 0) return null;
        buffer = (buffer << 5) | idx;
        bitsInBuffer += 5;
        if (bitsInBuffer >= 8) {

            bitsInBuffer -= 8;
            out[outIdx] = (buffer >>> bitsInBuffer) & 0xFF;
            outIdx += 1;

        }

    }
    // Anything left in the buffer should be zero pad bits. If they're
    // non-zero the input was malformed (had trailing junk encoded into
    // pad bits) and we should reject.
    if (bitsInBuffer > 0) {

        const tail = buffer & ((1 << bitsInBuffer) - 1);
        if (tail !== 0) return null;

    }
    return out;

};

// ----- Checksum -----

// SPEC § 4.4: CHECKSUM = Blake2b-256(".anon-checksum" || body32 || VERSION)[0:2]
// where `body32` is SVC_pk (v2) or identity_hash (v3) — both 32 bytes.
const computeChecksum = (body32, version) => {

    const input = new Uint8Array(CHECKSUM_PREFIX.length + 32 + 1);
    input.set(CHECKSUM_PREFIX, 0);
    input.set(body32, CHECKSUM_PREFIX.length);
    input[input.length - 1] = version;
    return blake2b(input, { dkLen: 32 }).subarray(0, 2);

};

// v3 identity-hash: Blake2b-256(SVC_pk_ed || SVC_pk_mldsa). 32 bytes.
const computeIdentityHash = (svcPkEd, svcPkMldsa) => {

    const input = new Uint8Array(svcPkEd.length + svcPkMldsa.length);
    input.set(svcPkEd, 0);
    input.set(svcPkMldsa, svcPkEd.length);
    return blake2b(input, { dkLen: 32 });

};

// ----- Public API -----

// v2: Encode an Ed25519 SVC_pk into the canonical .anon address.
// Legacy / pre-PQ. Prefer encodeOnionAddressV3 for new services.
export const encodeOnionAddress = (svcPk) => {

    if (!(svcPk instanceof Uint8Array) || svcPk.length !== ED25519_PK_BYTES) {

        throw new Error('SVC_pk must be a 32-byte Uint8Array');

    }
    const checksum = computeChecksum(svcPk, ONION_VERSION);
    const payload = new Uint8Array(ONION_ADDR_BYTES);
    payload.set(svcPk, 0);
    payload.set(checksum, 32);
    payload[34] = ONION_VERSION;
    return `${base32encode(payload)}${ONION_ADDR_SUFFIX}`;

};

// v3: Encode a HYBRID identity (Ed25519 + ML-DSA-65 pubkeys) into a
// quantum-safe .anon address. Same length as v2 (56 chars + ".anon")
// but distinguishable by the version byte at offset 34.
export const encodeOnionAddressV3 = (svcPkEd, svcPkMldsa) => {

    if (!(svcPkEd instanceof Uint8Array) || svcPkEd.length !== ED25519_PK_BYTES) {

        throw new Error(`SVC_pk_ed must be a ${ED25519_PK_BYTES}-byte Uint8Array`);

    }
    if (!(svcPkMldsa instanceof Uint8Array) || svcPkMldsa.length !== MLDSA_PK_BYTES) {

        throw new Error(`SVC_pk_mldsa must be a ${MLDSA_PK_BYTES}-byte Uint8Array`);

    }
    const identityHash = computeIdentityHash(svcPkEd, svcPkMldsa);
    const checksum = computeChecksum(identityHash, ONION_VERSION_PQ);
    const payload = new Uint8Array(ONION_ADDR_BYTES);
    payload.set(identityHash, 0);
    payload.set(checksum, 32);
    payload[34] = ONION_VERSION_PQ;
    return `${base32encode(payload)}${ONION_ADDR_SUFFIX}`;

};

// Decode a .anon onion address. Accepts both v2 and v3 (distinguished
// by the version byte at offset 34). Returns:
//   { version: 0x02, svcPk: Uint8Array(32) }                  for v2
//   { version: 0x03, identityHash: Uint8Array(32) }            for v3
// Returns null on:
//   - missing or wrong-cased suffix (suffix check is case-insensitive)
//   - wrong total length
//   - base32 decode failure (non-alphabet character or non-zero pad bits)
//   - unsupported VERSION byte
//   - CHECKSUM mismatch (typo defence)
//
// Note: v3 callers MUST cross-check identityHash against the descriptor's
// (SVC_pk_ed, SVC_pk_mldsa) themselves; this codec deliberately does
// NOT carry that responsibility because the codec doesn't see the
// descriptor.
export const decodeOnionAddress = (addr) => {

    if (typeof addr !== 'string') return null;
    const lower = addr.toLowerCase();
    if (!lower.endsWith(ONION_ADDR_SUFFIX)) return null;
    const body = lower.slice(0, -ONION_ADDR_SUFFIX.length);
    if (body.length !== ONION_ADDR_CHARS) return null;
    const bytes = base32decode(body);
    if (bytes === null || bytes.length !== ONION_ADDR_BYTES) return null;

    const version = bytes[34];
    if (version !== ONION_VERSION && version !== ONION_VERSION_PQ) return null;

    const body32  = bytes.subarray(0, 32);
    const claimed = bytes.subarray(32, 34);
    const computed = computeChecksum(body32, version);
    if (claimed[0] !== computed[0] || claimed[1] !== computed[1]) return null;

    if (version === ONION_VERSION) {

        return { version, svcPk: new Uint8Array(body32) };

    }
    return { version, identityHash: new Uint8Array(body32) };

};

// Convenience: is `addr` a syntactically valid .anon address (v2 or v3)?
export const isOnionAddress = (addr) => decodeOnionAddress(addr) !== null;

// Convenience for v3 callers: given a claimed address + the two
// pubkeys (e.g. from a descriptor), verify that hash(edPk || mldsaPk)
// matches the address's embedded identity_hash.
export const verifyAddressBindsPubkeys = (addr, svcPkEd, svcPkMldsa) => {

    const decoded = decodeOnionAddress(addr);
    if (decoded === null || decoded.version !== ONION_VERSION_PQ) return false;
    const computed = computeIdentityHash(svcPkEd, svcPkMldsa);
    if (computed.length !== decoded.identityHash.length) return false;
    for (let i = 0; i < computed.length; i += 1) {

        if (computed[i] !== decoded.identityHash[i]) return false;

    }
    return true;

};
