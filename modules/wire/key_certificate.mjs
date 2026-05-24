import { verifyCertificate, CERT_BYTES } from '../crypto/cert.mjs';
import { fingerprint } from '../crypto/fingerprint.mjs';

// SPEC § 6.6: KEY_CERTIFICATE payload — exactly 137 bytes.
//
//   identity public key (32) ‖ key certificate (105)
//
// The receiver verifies that the inner sender-identity fingerprint
// (§ 5.4) equals H(idPk), and that the certificate verifies under
// idPk. Once accepted, the (idPk, cert) pair is cached indexed by
// H(idPk) for future ANNOUNCE_PEER verification (§ 6.4).

const LEN_ID_PK = 32;
const OFFSET_ID_PK = 0;
const OFFSET_CERT = 32;

export const KEY_CERTIFICATE_LENGTH = LEN_ID_PK + CERT_BYTES; // 137

export const buildKeyCertificatePayload = ({ idPk, certBytes }) => {

    if (idPk.length !== LEN_ID_PK) {

        throw new Error('idPk must be 32 bytes');

    }
    if (certBytes.length !== CERT_BYTES) {

        throw new Error(`certBytes must be ${CERT_BYTES} bytes`);

    }

    const buf = new Uint8Array(KEY_CERTIFICATE_LENGTH);
    buf.set(idPk, OFFSET_ID_PK);
    buf.set(certBytes, OFFSET_CERT);
    return buf;

};

export const parseKeyCertificatePayload = (payload) => {

    if (!payload || payload.length !== KEY_CERTIFICATE_LENGTH) {

        return null;

    }

    return {
        idPk: new Uint8Array(payload.subarray(OFFSET_ID_PK, OFFSET_CERT)),
        certBytes: new Uint8Array(payload.subarray(OFFSET_CERT, KEY_CERTIFICATE_LENGTH)),
    };

};

// SPEC § 6.6: receiver verifies that the inner sender fingerprint
// matches H(idPk), and that the certificate verifies under idPk.
export const verifyKeyCertificate = ({ parsed, senderFingerprint, nowSeconds }) => {

    if (!parsed) return false;

    const computed = fingerprint(parsed.idPk);
    if (computed.length !== senderFingerprint.length) return false;
    let diff = 0;
    for (let i = 0; i < computed.length; i += 1) {

        diff |= computed[i] ^ senderFingerprint[i];

    }
    if (diff !== 0) return false;

    const cert = verifyCertificate(parsed.certBytes, parsed.idPk, nowSeconds);
    return cert !== null;

};
