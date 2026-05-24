// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

// Rendezvous-flow payload codecs (SPEC-v0.2-draft § 9.5).
//
// Each function here build / parses a single RELAY sub-command's
// `data` field. The state machine that wires these together (long-
// lived service-to-IP circuits, rendezvous-cookie store at the RP,
// rendezvous splice) is the runtime's responsibility — deferred to
// chunk 7.7c.

import { sign, verify } from '../crypto/identity.mjs';
import { seal, unseal, LEN_SEAL_ENVELOPE_OVERHEAD } from './sealed_box.mjs';
import { CREATE_MSG_BYTES, CREATED_MSG_BYTES } from './ntor_hybrid.mjs';

const writeBigUint64BE = (buf, off, value) => {

    new DataView(buf.buffer, buf.byteOffset, buf.byteLength).setBigUint64(off, BigInt(value), false);

};

const readBigUint64BE = (buf, off) => {

    return Number(new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getBigUint64(off, false));

};

const concat = (...arrays) => {

    let total = 0;
    for (const a of arrays) total += a.length;
    const out = new Uint8Array(total);
    let o = 0;
    for (const a of arrays) { out.set(a, o); o += a.length; }
    return out;

};

// ----- ESTABLISH_INTRO (§ 9.5.1) -----

const ESTABLISH_INTRO_SIG_CONTEXT = new TextEncoder().encode('anon-layer/v2/establish-intro');

export const LEN_ESTABLISH_INTRO = 32 + 8 + 64; // 104

// Build ESTABLISH_INTRO payload. Caller supplies the per-IP signing
// key (`serviceIntroSk`) and the IP's fingerprint (the receiver
// verifies the signature against its own fingerprint, anchoring the
// authentication to this specific link).
export const buildEstablishIntro = ({
    serviceIntroPk, serviceIntroSk, ipFingerprint, publishEpoch,
}) => {

    if (serviceIntroPk.length !== 32) throw new Error('serviceIntroPk must be 32 bytes');
    if (serviceIntroSk.length !== 32) throw new Error('serviceIntroSk must be 32 bytes');
    if (ipFingerprint.length !== 32) throw new Error('ipFingerprint must be 32 bytes');

    const epochBytes = new Uint8Array(8);
    writeBigUint64BE(epochBytes, 0, publishEpoch);

    const signed = concat(ESTABLISH_INTRO_SIG_CONTEXT, ipFingerprint, epochBytes);
    const signature = sign(signed, serviceIntroSk);

    return concat(serviceIntroPk, epochBytes, signature);

};

// Parse and verify. Returns { serviceIntroPk, publishEpoch } | null.
// The IP supplies its own fingerprint to anchor verification.
export const parseAndVerifyEstablishIntro = ({ payload, ipFingerprint, nowEpoch, maxAgeSeconds = 3600 }) => {

    if (!payload || payload.length !== LEN_ESTABLISH_INTRO) return null;
    if (ipFingerprint.length !== 32) return null;

    const serviceIntroPk = payload.subarray(0, 32);
    const epochBytes = payload.subarray(32, 40);
    const signature = payload.subarray(40, 104);

    const publishEpoch = readBigUint64BE(payload, 32);
    // Replay defence: reject ESTABLISH_INTRO older than maxAgeSeconds.
    if (typeof nowEpoch === 'number') {

        if (publishEpoch > nowEpoch + 60) return null; // too far in the future
        if (publishEpoch < nowEpoch - maxAgeSeconds) return null;

    }

    const signed = concat(ESTABLISH_INTRO_SIG_CONTEXT, ipFingerprint, epochBytes);
    if (!verify(signature, signed, serviceIntroPk)) return null;

    return {
        serviceIntroPk: new Uint8Array(serviceIntroPk),
        publishEpoch,
    };

};

// ----- INTRO_ESTABLISHED (§ 9.5.2) -----

export const INTRO_ESTABLISHED_STATUS_OK             = 0x00;
export const INTRO_ESTABLISHED_STATUS_BAD_SIGNATURE  = 0x01;
export const INTRO_ESTABLISHED_STATUS_RATE_LIMITED   = 0x02;
export const INTRO_ESTABLISHED_STATUS_DUPLICATE      = 0x03;

export const buildIntroEstablished = (status) => Uint8Array.from([status & 0xFF]);

export const parseIntroEstablished = (payload) => {

    if (!payload || payload.length !== 1) return null;
    return { status: payload[0] };

};

// ----- ESTABLISH_RENDEZVOUS (§ 9.5.3) -----

export const LEN_RENDEZVOUS_COOKIE = 20;

export const buildEstablishRendezvous = (cookie) => {

    if (cookie.length !== LEN_RENDEZVOUS_COOKIE) throw new Error('cookie must be 20 bytes');
    return new Uint8Array(cookie);

};

export const parseEstablishRendezvous = (payload) => {

    if (!payload || payload.length !== LEN_RENDEZVOUS_COOKIE) return null;
    return { cookie: new Uint8Array(payload) };

};

// ----- RENDEZVOUS_ESTABLISHED (§ 9.5.4) -----

export const RENDEZVOUS_ESTABLISHED_STATUS_OK           = 0x00;
export const RENDEZVOUS_ESTABLISHED_STATUS_COLLISION    = 0x01;
export const RENDEZVOUS_ESTABLISHED_STATUS_RATE_LIMITED = 0x02;

export const buildRendezvousEstablished = (status) => Uint8Array.from([status & 0xFF]);

export const parseRendezvousEstablished = (payload) => {

    if (!payload || payload.length !== 1) return null;
    return { status: payload[0] };

};

// ----- INTRODUCE1 inner payload (§ 9.5.5.1) — pre-seal -----

export const LEN_INTRODUCE_INNER = 20 + 32 + 32 + CREATE_MSG_BYTES; // 1300

const buildIntroduceInner = ({ cookie, rpFingerprint, rpOnionPk, handshakeMessage }) => {

    if (cookie.length !== LEN_RENDEZVOUS_COOKIE) throw new Error('cookie must be 20 bytes');
    if (rpFingerprint.length !== 32) throw new Error('rpFingerprint must be 32 bytes');
    if (rpOnionPk.length !== 32) throw new Error('rpOnionPk must be 32 bytes');
    if (handshakeMessage.length !== CREATE_MSG_BYTES) {

        throw new Error(`handshakeMessage must be ${CREATE_MSG_BYTES} bytes`);

    }
    return concat(cookie, rpFingerprint, rpOnionPk, handshakeMessage);

};

const parseIntroduceInner = (buf) => {

    if (!buf || buf.length !== LEN_INTRODUCE_INNER) return null;
    return {
        cookie: new Uint8Array(buf.subarray(0, 20)),
        rpFingerprint: new Uint8Array(buf.subarray(20, 52)),
        rpOnionPk: new Uint8Array(buf.subarray(52, 84)),
        handshakeMessage: new Uint8Array(buf.subarray(84, 84 + CREATE_MSG_BYTES)),
    };

};

// ----- INTRODUCE1 (§ 9.5.5) and INTRODUCE2 (§ 9.5.6) -----

// Build the full INTRODUCE1/2 payload (they share the byte layout —
// INTRODUCE2 is just the same bytes forwarded by the IP).
//
//   service_intro_pubkey (32) || sealed_envelope (variable)
//
// Returns the wire bytes that go in the RELAY cell `data` field.
// Total length: 32 + (1148 + LEN_INTRODUCE_INNER) = 32 + 2448 = 2480 bytes.
export const buildIntroducePayload = ({
    serviceIntroPk,
    serviceEncX25519Pk,
    serviceEncMlkemPk,
    cookie,
    rpFingerprint,
    rpOnionPk,
    handshakeMessage,
}) => {

    if (serviceIntroPk.length !== 32) throw new Error('serviceIntroPk must be 32 bytes');

    const inner = buildIntroduceInner({ cookie, rpFingerprint, rpOnionPk, handshakeMessage });
    const envelope = seal({
        plaintext: inner,
        recipientX25519Pk: serviceEncX25519Pk,
        recipientMlkemPk: serviceEncMlkemPk,
    });
    return concat(serviceIntroPk, envelope);

};

// Parse the structural envelope without unsealing. The IP uses this
// to look up which service this is for (by serviceIntroPk) and to
// forward the sealed envelope unchanged.
export const parseIntroduceEnvelope = (payload) => {

    if (!payload || payload.length < 32 + LEN_SEAL_ENVELOPE_OVERHEAD) return null;
    return {
        serviceIntroPk: new Uint8Array(payload.subarray(0, 32)),
        sealedEnvelope: new Uint8Array(payload.subarray(32)),
    };

};

// Unseal at the service. Returns the inner payload or null.
export const unsealIntroduceInner = ({
    sealedEnvelope, serviceEncX25519Sk, serviceEncMlkemSk,
}) => {

    const inner = unseal({
        envelope: sealedEnvelope,
        recipientX25519Sk: serviceEncX25519Sk,
        recipientMlkemSk: serviceEncMlkemSk,
    });
    if (inner === null) return null;
    return parseIntroduceInner(inner);

};

// ----- RENDEZVOUS1 (§ 9.5.7) -----

export const LEN_RENDEZVOUS1 = LEN_RENDEZVOUS_COOKIE + CREATED_MSG_BYTES; // 1172

export const buildRendezvous1 = ({ cookie, handshakeResponse }) => {

    if (cookie.length !== LEN_RENDEZVOUS_COOKIE) throw new Error('cookie must be 20 bytes');
    if (handshakeResponse.length !== CREATED_MSG_BYTES) {

        throw new Error(`handshakeResponse must be ${CREATED_MSG_BYTES} bytes`);

    }
    return concat(cookie, handshakeResponse);

};

export const parseRendezvous1 = (payload) => {

    if (!payload || payload.length !== LEN_RENDEZVOUS1) return null;
    return {
        cookie: new Uint8Array(payload.subarray(0, LEN_RENDEZVOUS_COOKIE)),
        handshakeResponse: new Uint8Array(payload.subarray(LEN_RENDEZVOUS_COOKIE)),
    };

};

// ----- RENDEZVOUS2 (§ 9.5.8) -----

// RP strips the cookie before forwarding; the client only sees the
// handshake response.

export const LEN_RENDEZVOUS2 = CREATED_MSG_BYTES;

export const buildRendezvous2 = (handshakeResponse) => {

    if (handshakeResponse.length !== CREATED_MSG_BYTES) {

        throw new Error(`handshakeResponse must be ${CREATED_MSG_BYTES} bytes`);

    }
    return new Uint8Array(handshakeResponse);

};

export const parseRendezvous2 = (payload) => {

    if (!payload || payload.length !== LEN_RENDEZVOUS2) return null;
    return { handshakeResponse: new Uint8Array(payload) };

};

// ----- INTRODUCE_ACK (§ 9.5.9) -----

export const INTRODUCE_ACK_STATUS_FORWARDED      = 0x00;
export const INTRODUCE_ACK_STATUS_UNKNOWN_SVC    = 0x01;
export const INTRODUCE_ACK_STATUS_RATE_LIMITED   = 0x02;
export const INTRODUCE_ACK_STATUS_CIRCUIT_CLOSED = 0x03;

export const buildIntroduceAck = (status) => Uint8Array.from([status & 0xFF]);

export const parseIntroduceAck = (payload) => {

    if (!payload || payload.length !== 1) return null;
    return { status: payload[0] };

};
