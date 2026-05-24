import { sign, verify } from './identity.mjs';

// SPEC § 4.4: key certificate is exactly 105 bytes.
//   version  (1)  + onionPk (32) + expiry (8) + signature (64) = 105
// The signature is Ed25519(idSk, version || onionPk || expiry), i.e. the
// 41 bytes that precede the signature.

const CERT_VERSION = 0x01;
const LEN_CERT = 105;
const LEN_SIGNED = 41;
const OFFSET_VERSION = 0;
const OFFSET_ONION_PK = 1;
const OFFSET_EXPIRY = 33;
const OFFSET_SIG = 41;

const LEN_ONION_PK = 32;
const LEN_EXPIRY = 8;
const LEN_SIG = 64;

const writeBigUint64BE = (buf, offset, value) => {

    // Node's DataView does big-endian by default for u64.
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    view.setBigUint64(offset, BigInt(value), false);

};

const readBigUint64BE = (buf, offset) => {

    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    return Number(view.getBigUint64(offset, false));

};

// SPEC § 4.4: produce a 105-byte certificate signed by `idSk` binding
// `onionPk` to the identity until `expirySeconds` (Unix seconds, big-endian).
export const buildCertificate = ({ idSk, onionPk, expirySeconds }) => {

    if (onionPk.length !== LEN_ONION_PK) {

        throw new Error('onionPk must be 32 bytes');

    }

    const cert = new Uint8Array(LEN_CERT);
    cert[OFFSET_VERSION] = CERT_VERSION;
    cert.set(onionPk, OFFSET_ONION_PK);
    writeBigUint64BE(cert, OFFSET_EXPIRY, expirySeconds);

    const signed = cert.subarray(0, LEN_SIGNED);
    const signature = sign(signed, idSk);
    cert.set(signature, OFFSET_SIG);

    return cert;

};

// SPEC § 4.4: verify a 105-byte certificate against a known identity
// public key. Returns parsed fields on success, or null on any failure.
// Failure dispositions are uniform per SPEC § 9 silent-drop discipline.
export const verifyCertificate = (cert, idPk, nowSeconds) => {

    if (!cert || cert.length !== LEN_CERT) {

        return null;

    }

    if (cert[OFFSET_VERSION] !== CERT_VERSION) {

        return null;

    }

    const expirySeconds = readBigUint64BE(cert, OFFSET_EXPIRY);
    if (expirySeconds <= nowSeconds) {

        return null;

    }

    const signed = cert.subarray(0, LEN_SIGNED);
    const signature = cert.subarray(OFFSET_SIG, OFFSET_SIG + LEN_SIG);
    if (!verify(signature, signed, idPk)) {

        return null;

    }

    const onionPk = new Uint8Array(cert.subarray(OFFSET_ONION_PK, OFFSET_ONION_PK + LEN_ONION_PK));
    return { onionPk, expirySeconds };

};

export const CERT_BYTES = LEN_CERT;
