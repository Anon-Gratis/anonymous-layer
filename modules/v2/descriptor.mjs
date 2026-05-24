// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

// Hidden-service descriptor codec for SPEC-v0.2-draft § 9.1.
//
// A service publishes a descriptor to the directory that points to its
// current introduction points. Layout:
//
//   version              (1 byte)   = 0x02
//   SVC_pk               (32 bytes)
//   publish_epoch        (8 bytes)  Unix seconds, BE
//   lifetime_seconds     (4 bytes)  BE u32
//   intro_point_count    (1 byte)
//   intro_points         (intro_point_count × 96 bytes)
//   signature            (64 bytes) Ed25519(SVC_sk, all bytes above)
//
// Each intro-point record (per spec § 9.1, updated in chunk 7.7b):
//
//   IP fingerprint              (32 bytes)   H(IP's idPk)
//   IP onion key                (32 bytes)   X25519, for circuit extension to IP
//   service intro auth key      (32 bytes)   Ed25519, signs ESTABLISH_INTRO
//   service enc X25519 key      (32 bytes)   X25519, classical half of sealed-box
//   service enc ML-KEM key      (1184 bytes) ML-KEM-768, PQ half of sealed-box

import { sign, verify } from '../crypto/identity.mjs';
import { MLKEM_PK_BYTES } from './ntor_hybrid.mjs';
import {
    hybridSign,
    hybridVerify,
    ED25519_PK_BYTES,
    ED25519_SIG_BYTES,
    MLDSA_PK_BYTES,
    MLDSA_SIG_BYTES,
} from '../crypto/hybrid_sign.mjs';
import { verifyAddressBindsPubkeys } from './onion_address.mjs';

export const DESCRIPTOR_VERSION    = 0x02;
export const DESCRIPTOR_VERSION_PQ = 0x03;  // hybrid Ed25519 + ML-DSA-65

const LEN_FINGERPRINT = 32;
const LEN_ONION_PK = 32;
const LEN_INTRO_KEY = 32;
const LEN_ENC_X25519 = 32;
const LEN_ENC_MLKEM = MLKEM_PK_BYTES; // 1184

export const LEN_INTRO_POINT = LEN_FINGERPRINT + LEN_ONION_PK
    + LEN_INTRO_KEY + LEN_ENC_X25519 + LEN_ENC_MLKEM; // 1312

const LEN_VERSION = 1;
const LEN_SVC_PK = 32;
const LEN_PUBLISH_EPOCH = 8;
const LEN_LIFETIME = 4;
const LEN_INTRO_COUNT = 1;
const LEN_SIGNATURE = 64;

export const LEN_DESCRIPTOR_HEADER = LEN_VERSION + LEN_SVC_PK
    + LEN_PUBLISH_EPOCH + LEN_LIFETIME + LEN_INTRO_COUNT;

const MAX_INTRO_POINTS = 255;

// ----- Helpers -----

const writeBigUint64BE = (buf, off, value) => {

    new DataView(buf.buffer, buf.byteOffset, buf.byteLength).setBigUint64(off, BigInt(value), false);

};

const readBigUint64BE = (buf, off) => {

    return Number(new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getBigUint64(off, false));

};

const writeUint32BE = (buf, off, value) => {

    new DataView(buf.buffer, buf.byteOffset, buf.byteLength).setUint32(off, value, false);

};

const readUint32BE = (buf, off) => {

    return new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(off, false);

};

// ----- Intro-point codec -----

const OFFSET_IP_FINGERPRINT    = 0;
const OFFSET_IP_ONION_PK       = OFFSET_IP_FINGERPRINT + LEN_FINGERPRINT;
const OFFSET_SERVICE_INTRO_KEY = OFFSET_IP_ONION_PK + LEN_ONION_PK;
const OFFSET_SERVICE_ENC_X25519 = OFFSET_SERVICE_INTRO_KEY + LEN_INTRO_KEY;
const OFFSET_SERVICE_ENC_MLKEM  = OFFSET_SERVICE_ENC_X25519 + LEN_ENC_X25519;

const validateIntroPoint = (ip) => {

    if (!(ip.fingerprint instanceof Uint8Array) || ip.fingerprint.length !== LEN_FINGERPRINT) {

        throw new Error('intro-point fingerprint must be a 32-byte Uint8Array');

    }
    if (!(ip.ipOnionPk instanceof Uint8Array) || ip.ipOnionPk.length !== LEN_ONION_PK) {

        throw new Error('intro-point ipOnionPk must be a 32-byte Uint8Array');

    }
    if (!(ip.serviceIntroKey instanceof Uint8Array) || ip.serviceIntroKey.length !== LEN_INTRO_KEY) {

        throw new Error('intro-point serviceIntroKey must be a 32-byte Ed25519 public key');

    }
    if (!(ip.serviceEncX25519Pk instanceof Uint8Array) || ip.serviceEncX25519Pk.length !== LEN_ENC_X25519) {

        throw new Error('intro-point serviceEncX25519Pk must be a 32-byte X25519 public key');

    }
    if (!(ip.serviceEncMlkemPk instanceof Uint8Array) || ip.serviceEncMlkemPk.length !== LEN_ENC_MLKEM) {

        throw new Error(`intro-point serviceEncMlkemPk must be a ${LEN_ENC_MLKEM}-byte ML-KEM-768 public key`);

    }

};

const writeIntroPoint = (buf, off, ip) => {

    buf.set(ip.fingerprint,         off + OFFSET_IP_FINGERPRINT);
    buf.set(ip.ipOnionPk,           off + OFFSET_IP_ONION_PK);
    buf.set(ip.serviceIntroKey,     off + OFFSET_SERVICE_INTRO_KEY);
    buf.set(ip.serviceEncX25519Pk,  off + OFFSET_SERVICE_ENC_X25519);
    buf.set(ip.serviceEncMlkemPk,   off + OFFSET_SERVICE_ENC_MLKEM);

};

const readIntroPoint = (buf, off) => {

    return {
        fingerprint:        new Uint8Array(buf.subarray(off + OFFSET_IP_FINGERPRINT,    off + OFFSET_IP_ONION_PK)),
        ipOnionPk:          new Uint8Array(buf.subarray(off + OFFSET_IP_ONION_PK,       off + OFFSET_SERVICE_INTRO_KEY)),
        serviceIntroKey:    new Uint8Array(buf.subarray(off + OFFSET_SERVICE_INTRO_KEY, off + OFFSET_SERVICE_ENC_X25519)),
        serviceEncX25519Pk: new Uint8Array(buf.subarray(off + OFFSET_SERVICE_ENC_X25519, off + OFFSET_SERVICE_ENC_MLKEM)),
        serviceEncMlkemPk:  new Uint8Array(buf.subarray(off + OFFSET_SERVICE_ENC_MLKEM,  off + LEN_INTRO_POINT)),
    };

};

// ----- Descriptor codec -----

// SPEC § 9.1: build a service descriptor signed by SVC_sk.
//
// Inputs:
//   SVC_sk          Ed25519 secret seed
//   SVC_pk          Ed25519 public key (32 bytes)
//   publishEpoch    Unix seconds (the time the service published this)
//   lifetimeSeconds u32, how long the descriptor is valid for
//   introPoints     array of { fingerprint, ipOnionPk, serviceIntroKey }
export const buildServiceDescriptor = ({
    SVC_sk, SVC_pk, publishEpoch, lifetimeSeconds, introPoints,
}) => {

    if (!(SVC_sk instanceof Uint8Array) || SVC_sk.length !== 32) {

        throw new Error('SVC_sk must be a 32-byte Uint8Array');

    }
    if (!(SVC_pk instanceof Uint8Array) || SVC_pk.length !== LEN_SVC_PK) {

        throw new Error('SVC_pk must be a 32-byte Uint8Array');

    }
    if (!Number.isInteger(lifetimeSeconds) || lifetimeSeconds < 0 || lifetimeSeconds > 0xFFFFFFFF) {

        throw new Error('lifetimeSeconds must be a u32');

    }
    if (introPoints.length > MAX_INTRO_POINTS) {

        throw new Error(`intro-point count exceeds 255 (got ${introPoints.length})`);

    }
    for (const ip of introPoints) validateIntroPoint(ip);

    const headerLen = LEN_DESCRIPTOR_HEADER + introPoints.length * LEN_INTRO_POINT;
    const signedRegion = new Uint8Array(headerLen);
    let off = 0;
    signedRegion[off] = DESCRIPTOR_VERSION; off += LEN_VERSION;
    signedRegion.set(SVC_pk, off); off += LEN_SVC_PK;
    writeBigUint64BE(signedRegion, off, publishEpoch); off += LEN_PUBLISH_EPOCH;
    writeUint32BE(signedRegion, off, lifetimeSeconds); off += LEN_LIFETIME;
    signedRegion[off] = introPoints.length; off += LEN_INTRO_COUNT;
    for (const ip of introPoints) {

        writeIntroPoint(signedRegion, off, ip);
        off += LEN_INTRO_POINT;

    }

    const signature = sign(signedRegion, SVC_sk);

    const out = new Uint8Array(headerLen + LEN_SIGNATURE);
    out.set(signedRegion, 0);
    out.set(signature, headerLen);
    return out;

};

// Parse a descriptor's structural fields WITHOUT verifying the
// signature or the validity window. Returns null on any structural
// failure (wrong length, bad version byte, trailing bytes). Use
// verifyServiceDescriptor for the signature + timestamp checks.
export const parseServiceDescriptor = (buf) => {

    if (!buf || buf.length < LEN_DESCRIPTOR_HEADER + LEN_SIGNATURE) return null;

    let off = 0;
    if (buf[off] !== DESCRIPTOR_VERSION) return null;
    off += LEN_VERSION;
    const SVC_pk = new Uint8Array(buf.subarray(off, off + LEN_SVC_PK));
    off += LEN_SVC_PK;
    const publishEpoch = readBigUint64BE(buf, off);
    off += LEN_PUBLISH_EPOCH;
    const lifetimeSeconds = readUint32BE(buf, off);
    off += LEN_LIFETIME;
    const introCount = buf[off];
    off += LEN_INTRO_COUNT;

    const expectedLen = LEN_DESCRIPTOR_HEADER + introCount * LEN_INTRO_POINT + LEN_SIGNATURE;
    if (buf.length !== expectedLen) return null;

    const introPoints = [];
    for (let i = 0; i < introCount; i += 1) {

        introPoints.push(readIntroPoint(buf, off));
        off += LEN_INTRO_POINT;

    }
    const signature = new Uint8Array(buf.subarray(off, off + LEN_SIGNATURE));
    const signedRegion = new Uint8Array(buf.subarray(0, off));

    return {
        version: DESCRIPTOR_VERSION,
        SVC_pk,
        publishEpoch,
        lifetimeSeconds,
        introPoints,
        signature,
        // Kept so verifyServiceDescriptor doesn't have to re-slice.
        signedRegion,
    };

};

// SPEC § 9.1: verify a parsed v2 descriptor.
//   - signature verifies under `parsed.SVC_pk` (or under `expectedSvcPk`
//     if supplied — the client typically has the SVC_pk from the
//     onion address and wants to confirm the descriptor is for that
//     service)
//   - now is within [publishEpoch, publishEpoch + lifetimeSeconds]
//
// Returns true on success, false on any failure.
//
// Auditor note: for v3 descriptors use verifyServiceDescriptorV3.
// verifyServiceDescriptor (auto-dispatching by parsed.version) is the
// preferred surface for new callers.
export const verifyServiceDescriptorV2 = ({ parsed, nowEpoch, expectedSvcPk = null }) => {

    if (!parsed) return false;
    if (parsed.version !== DESCRIPTOR_VERSION) return false;

    if (expectedSvcPk) {

        if (!(expectedSvcPk instanceof Uint8Array) || expectedSvcPk.length !== LEN_SVC_PK) {

            return false;

        }
        // Constant-time comparison.
        let diff = 0;
        for (let i = 0; i < LEN_SVC_PK; i += 1) diff |= expectedSvcPk[i] ^ parsed.SVC_pk[i];
        if (diff !== 0) return false;

    }

    if (typeof nowEpoch !== 'number') return false;
    if (nowEpoch < parsed.publishEpoch) return false;
    if (nowEpoch > parsed.publishEpoch + parsed.lifetimeSeconds) return false;

    return verify(parsed.signature, parsed.signedRegion, parsed.SVC_pk);

};

// ───────────────────────────────────────────────────────────────────
//
// v3 descriptor (SPEC-v0.2-draft § 9.1 update, hybrid PQ)
//
// Layout:
//
//   version              (1 byte)     = 0x03
//   SVC_pk_ed            (32 bytes)   Ed25519
//   SVC_pk_mldsa         (1952 bytes) ML-DSA-65
//   publish_epoch        (8 bytes)    Unix seconds, BE
//   lifetime_seconds     (4 bytes)    BE u32
//   intro_point_count    (1 byte)
//   intro_points         (count × 1312 bytes)         <-- same as v2
//   ed_signature         (64 bytes)   Ed25519  over all bytes above
//   mldsa_signature      (3309 bytes) ML-DSA-65 over all bytes above
//
// Auditor notes:
//   - Both signatures are over the SAME byte string (the entire
//     pre-signature region). This avoids the trap where a verifier
//     could be tricked into checking one sig against transcript A
//     and the other against transcript B.
//   - The two sigs are appended in fixed order (ed then mldsa). A
//     different order changes the byte format; updating the order
//     is a wire-format change, not a config knob.
//   - Both pubkeys live in the descriptor itself; they are NOT
//     derivable from the onion address (which is a hash). The
//     onion address binds them: a v3 address is verified by
//     hashing the two pubkeys carried here and comparing to the
//     identity_hash baked into the address. See
//     onion_address.mjs::verifyAddressBindsPubkeys.
//   - Both signatures must verify (hybridVerify is AND, not OR).
//     See modules/crypto/hybrid_sign.mjs for the rationale.
//
// ───────────────────────────────────────────────────────────────────

const LEN_SVC_PK_ED    = ED25519_PK_BYTES;          // 32
const LEN_SVC_PK_MLDSA = MLDSA_PK_BYTES;            // 1952
const LEN_HYBRID_SIG   = ED25519_SIG_BYTES + MLDSA_SIG_BYTES; // 3373

export const LEN_DESCRIPTOR_HEADER_V3 = LEN_VERSION + LEN_SVC_PK_ED
    + LEN_SVC_PK_MLDSA + LEN_PUBLISH_EPOCH + LEN_LIFETIME + LEN_INTRO_COUNT;

export const buildServiceDescriptorV3 = ({
    SVC_sk_ed, SVC_pk_ed, SVC_sk_mldsa, SVC_pk_mldsa,
    publishEpoch, lifetimeSeconds, introPoints,
}) => {

    if (!(SVC_sk_ed instanceof Uint8Array) || SVC_sk_ed.length !== 32) {

        throw new Error('SVC_sk_ed must be a 32-byte Uint8Array');

    }
    if (!(SVC_pk_ed instanceof Uint8Array) || SVC_pk_ed.length !== LEN_SVC_PK_ED) {

        throw new Error(`SVC_pk_ed must be a ${LEN_SVC_PK_ED}-byte Uint8Array`);

    }
    if (!(SVC_sk_mldsa instanceof Uint8Array)) {

        throw new Error('SVC_sk_mldsa must be a Uint8Array');

    }
    if (!(SVC_pk_mldsa instanceof Uint8Array) || SVC_pk_mldsa.length !== LEN_SVC_PK_MLDSA) {

        throw new Error(`SVC_pk_mldsa must be a ${LEN_SVC_PK_MLDSA}-byte Uint8Array`);

    }
    if (!Number.isInteger(lifetimeSeconds) || lifetimeSeconds < 0 || lifetimeSeconds > 0xFFFFFFFF) {

        throw new Error('lifetimeSeconds must be a u32');

    }
    if (introPoints.length > MAX_INTRO_POINTS) {

        throw new Error(`intro-point count exceeds 255 (got ${introPoints.length})`);

    }
    for (const ip of introPoints) validateIntroPoint(ip);

    const headerLen = LEN_DESCRIPTOR_HEADER_V3 + introPoints.length * LEN_INTRO_POINT;
    const signedRegion = new Uint8Array(headerLen);
    let off = 0;
    signedRegion[off] = DESCRIPTOR_VERSION_PQ; off += LEN_VERSION;
    signedRegion.set(SVC_pk_ed, off);          off += LEN_SVC_PK_ED;
    signedRegion.set(SVC_pk_mldsa, off);       off += LEN_SVC_PK_MLDSA;
    writeBigUint64BE(signedRegion, off, publishEpoch); off += LEN_PUBLISH_EPOCH;
    writeUint32BE(signedRegion, off, lifetimeSeconds); off += LEN_LIFETIME;
    signedRegion[off] = introPoints.length;    off += LEN_INTRO_COUNT;
    for (const ip of introPoints) {

        writeIntroPoint(signedRegion, off, ip);
        off += LEN_INTRO_POINT;

    }

    const { edSig, mldsaSig } = hybridSign(signedRegion, {
        edSk: SVC_sk_ed, mldsaSk: SVC_sk_mldsa,
    });

    const out = new Uint8Array(headerLen + ED25519_SIG_BYTES + MLDSA_SIG_BYTES);
    out.set(signedRegion, 0);
    out.set(edSig,    headerLen);
    out.set(mldsaSig, headerLen + ED25519_SIG_BYTES);
    return out;

};

const parseServiceDescriptorV3 = (buf) => {

    if (!buf || buf.length < LEN_DESCRIPTOR_HEADER_V3 + LEN_HYBRID_SIG) return null;

    let off = 0;
    if (buf[off] !== DESCRIPTOR_VERSION_PQ) return null;
    off += LEN_VERSION;
    const SVC_pk_ed = new Uint8Array(buf.subarray(off, off + LEN_SVC_PK_ED));
    off += LEN_SVC_PK_ED;
    const SVC_pk_mldsa = new Uint8Array(buf.subarray(off, off + LEN_SVC_PK_MLDSA));
    off += LEN_SVC_PK_MLDSA;
    const publishEpoch = readBigUint64BE(buf, off);
    off += LEN_PUBLISH_EPOCH;
    const lifetimeSeconds = readUint32BE(buf, off);
    off += LEN_LIFETIME;
    const introCount = buf[off];
    off += LEN_INTRO_COUNT;

    const expectedLen = LEN_DESCRIPTOR_HEADER_V3
        + introCount * LEN_INTRO_POINT + LEN_HYBRID_SIG;
    if (buf.length !== expectedLen) return null;

    const introPoints = [];
    for (let i = 0; i < introCount; i += 1) {

        introPoints.push(readIntroPoint(buf, off));
        off += LEN_INTRO_POINT;

    }
    const edSig    = new Uint8Array(buf.subarray(off, off + ED25519_SIG_BYTES));
    off += ED25519_SIG_BYTES;
    const mldsaSig = new Uint8Array(buf.subarray(off, off + MLDSA_SIG_BYTES));
    off += MLDSA_SIG_BYTES;
    const signedRegion = new Uint8Array(buf.subarray(0, buf.length - LEN_HYBRID_SIG));

    return {
        version: DESCRIPTOR_VERSION_PQ,
        SVC_pk_ed,
        SVC_pk_mldsa,
        publishEpoch,
        lifetimeSeconds,
        introPoints,
        edSig,
        mldsaSig,
        signedRegion,
    };

};

// Verify a parsed v3 descriptor.
// Must pass:
//   - parsed.version === 0x03
//   - if expectedAddress supplied, the address binds these pubkeys
//     (Blake2b(SVC_pk_ed || SVC_pk_mldsa) == address.identityHash)
//   - now within [publishEpoch, publishEpoch + lifetimeSeconds]
//   - hybridVerify({edPk, mldsaPk}, signedRegion, {edSig, mldsaSig})
//
// Returns true on success, false otherwise. Never throws.
export const verifyServiceDescriptorV3 = ({ parsed, nowEpoch, expectedAddress = null }) => {

    if (!parsed) return false;
    if (parsed.version !== DESCRIPTOR_VERSION_PQ) return false;

    if (expectedAddress !== null) {

        // Address-to-pubkey binding: the v3 onion address embeds a
        // hash of the two pubkeys. If the descriptor's pubkeys don't
        // hash to that, the descriptor is not for this service.
        // Critical for the quantum-safe property: without this check,
        // an attacker who can forge Ed25519 sigs could swap in their
        // own ML-DSA pubkey.
        if (!verifyAddressBindsPubkeys(expectedAddress, parsed.SVC_pk_ed, parsed.SVC_pk_mldsa)) {

            return false;

        }

    }

    if (typeof nowEpoch !== 'number') return false;
    if (nowEpoch < parsed.publishEpoch) return false;
    if (nowEpoch > parsed.publishEpoch + parsed.lifetimeSeconds) return false;

    return hybridVerify(
        parsed.signedRegion,
        { edPk: parsed.SVC_pk_ed, mldsaPk: parsed.SVC_pk_mldsa },
        { edSig: parsed.edSig,    mldsaSig: parsed.mldsaSig },
    );

};

// ───────────────────────────────────────────────────────────────────
// Version-dispatching surface — new callers SHOULD use these.
// ───────────────────────────────────────────────────────────────────

// Parses either v2 or v3 by sniffing the version byte at offset 0.
// Use the version-specific parsers above if you need to refuse one
// version explicitly.
export const parseServiceDescriptorAny = (buf) => {

    if (!buf || buf.length < 1) return null;
    if (buf[0] === DESCRIPTOR_VERSION)    return parseServiceDescriptor(buf);
    if (buf[0] === DESCRIPTOR_VERSION_PQ) return parseServiceDescriptorV3(buf);
    return null;

};

// Verifies either, dispatching by parsed.version.
//   - v2: expectedSvcPk (32-byte Ed25519 pubkey)
//   - v3: expectedAddress (string, .anon address)
// Pass only the matching expectation for the version; mismatched is
// ignored.
export const verifyServiceDescriptor = ({ parsed, nowEpoch, expectedSvcPk = null, expectedAddress = null }) => {

    if (!parsed) return false;
    if (parsed.version === DESCRIPTOR_VERSION) {

        return verifyServiceDescriptorV2({ parsed, nowEpoch, expectedSvcPk });

    }
    if (parsed.version === DESCRIPTOR_VERSION_PQ) {

        return verifyServiceDescriptorV3({ parsed, nowEpoch, expectedAddress });

    }
    return false;

};
