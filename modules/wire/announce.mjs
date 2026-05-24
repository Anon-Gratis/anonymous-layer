import { serializeTransports, parseTransports } from './transport.mjs';
import { verifyCertificate, CERT_BYTES } from '../crypto/cert.mjs';
import { fingerprint } from '../crypto/fingerprint.mjs';

// SPEC § 6.4: ANNOUNCE_PEER payload.
//
//   announced fingerprint (32) ‖ key certificate (105) ‖ transport list
//
// Verification per § 6.4 requires `H(idPk) == announced_fingerprint`
// and a valid certificate under `idPk`. Because Ed25519 raw signatures
// do not embed the public key, the receiver MUST learn `idPk` out of
// band (typically from a prior KEY_CERTIFICATE packet; see § 6.6).
// We therefore separate the structural parse (`parse*`) from the
// signature/identity verification (`verify*`) — callers walk peer-cache
// lookups between the two.

const LEN_ANNOUNCED_FINGERPRINT = 32;
const OFFSET_ANNOUNCED_FINGERPRINT = 0;
const OFFSET_CERT = 32;
const OFFSET_TRANSPORTS = 32 + CERT_BYTES;

export const ANNOUNCE_PEER_MIN_LENGTH = LEN_ANNOUNCED_FINGERPRINT + CERT_BYTES + 1; // 138

export const buildAnnouncePeerPayload = ({ announcedFingerprint, certBytes, transports }) => {

    if (announcedFingerprint.length !== LEN_ANNOUNCED_FINGERPRINT) {

        throw new Error('announcedFingerprint must be 32 bytes');

    }

    if (certBytes.length !== CERT_BYTES) {

        throw new Error(`certBytes must be ${CERT_BYTES} bytes`);

    }

    const transportBytes = serializeTransports(transports);
    const buf = new Uint8Array(OFFSET_TRANSPORTS + transportBytes.length);
    buf.set(announcedFingerprint, OFFSET_ANNOUNCED_FINGERPRINT);
    buf.set(certBytes, OFFSET_CERT);
    buf.set(transportBytes, OFFSET_TRANSPORTS);
    return buf;

};

// Structural parse only — does NOT verify the certificate or check
// fingerprint binding. Use verifyAnnouncePeer for the policy checks.
export const parseAnnouncePeerPayload = (payload) => {

    if (!payload || payload.length < ANNOUNCE_PEER_MIN_LENGTH) {

        return null;

    }

    const parsedTransports = parseTransports(payload, OFFSET_TRANSPORTS);
    if (parsedTransports === null) return null;

    // SPEC § 6.4: the transport list is the last field. If the parser
    // consumed less than the payload's remainder, there are trailing
    // bytes — reject as malformed.
    if (OFFSET_TRANSPORTS + parsedTransports.consumed !== payload.length) {

        return null;

    }

    return {
        announcedFingerprint: new Uint8Array(payload.subarray(OFFSET_ANNOUNCED_FINGERPRINT, LEN_ANNOUNCED_FINGERPRINT)),
        certBytes: new Uint8Array(payload.subarray(OFFSET_CERT, OFFSET_TRANSPORTS)),
        transports: parsedTransports.transports,
    };

};

// SPEC § 6.4 verification. Receiver supplies the announced node's
// identity public key (learned out-of-band per § 6.4 / § 6.6 note) and
// the current time in seconds. Returns true on success, false on any
// failure.
export const verifyAnnouncePeer = ({ parsed, announcedIdPk, nowSeconds }) => {

    if (!parsed) return false;

    const computed = fingerprint(announcedIdPk);
    if (computed.length !== parsed.announcedFingerprint.length) return false;
    let diff = 0;
    for (let i = 0; i < computed.length; i += 1) {

        diff |= computed[i] ^ parsed.announcedFingerprint[i];

    }
    if (diff !== 0) return false;

    const cert = verifyCertificate(parsed.certBytes, announcedIdPk, nowSeconds);
    return cert !== null;

};
