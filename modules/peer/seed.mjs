import { serializeTransports, parseTransports } from '../wire/transport.mjs';
import { verifyCertificate, CERT_BYTES } from '../crypto/cert.mjs';

// SPEC § 7.1: canonical seed-record byte layout.
//
//   identity public key (32) ‖ key certificate (105) ‖ transport list
//
// The distribution wrapper (PEM-style armor, JSON, raw bytes) is
// implementation-defined per § 7.1, but this byte sequence is the
// canonical form. Multi-record lists are concatenated; each record is
// self-delimiting via the transport count + length-prefixed records.
//
// Verification is split from parse so the caller can decide whether to
// drop unverified records or keep them around (e.g. for diagnostics);
// SPEC § 7.2 step 2 mandates dropping unverified records before they
// reach the dial path.

const LEN_ID_PK = 32;
const OFFSET_ID_PK = 0;
const OFFSET_CERT = 32;
const OFFSET_TRANSPORTS = 32 + CERT_BYTES; // 137

const MIN_RECORD_LENGTH = OFFSET_TRANSPORTS + 1; // 138 (zero transports)

export const buildSeedRecord = ({ idPk, certBytes, transports }) => {

    if (idPk.length !== LEN_ID_PK) {

        throw new Error('idPk must be 32 bytes');

    }
    if (certBytes.length !== CERT_BYTES) {

        throw new Error(`certBytes must be ${CERT_BYTES} bytes`);

    }

    const transportBytes = serializeTransports(transports);
    const buf = new Uint8Array(OFFSET_TRANSPORTS + transportBytes.length);
    buf.set(idPk, OFFSET_ID_PK);
    buf.set(certBytes, OFFSET_CERT);
    buf.set(transportBytes, OFFSET_TRANSPORTS);
    return buf;

};

// Parse one seed record starting at `offset`. Returns the record and
// the number of bytes consumed so callers can walk a list.
export const parseSeedRecord = (buf, offset = 0) => {

    if (!buf || buf.length < offset + MIN_RECORD_LENGTH) {

        return null;

    }

    const parsedTransports = parseTransports(buf, offset + OFFSET_TRANSPORTS);
    if (parsedTransports === null) return null;

    const consumed = OFFSET_TRANSPORTS + parsedTransports.consumed;

    return {
        record: {
            idPk: new Uint8Array(buf.subarray(offset + OFFSET_ID_PK, offset + OFFSET_CERT)),
            certBytes: new Uint8Array(buf.subarray(offset + OFFSET_CERT, offset + OFFSET_TRANSPORTS)),
            transports: parsedTransports.transports,
        },
        consumed,
    };

};

// Parse a concatenated list of seed records. Returns the array; returns
// null if any record fails to parse or there are unconsumed trailing
// bytes — the seed list is canonical data and partial parses are
// programmer / corruption errors, not adversarial drops.
export const parseSeedList = (buf) => {

    if (!buf) return [];

    const records = [];
    let cursor = 0;
    while (cursor < buf.length) {

        const result = parseSeedRecord(buf, cursor);
        if (result === null) return null;
        records.push(result.record);
        cursor += result.consumed;

    }
    return records;

};

// SPEC § 7.2 step 2: verify each seed record's key certificate. We
// only check the certificate's signature + expiry under the seed's
// claimed idPk; § 7.1 explicitly defers anchor-key signatures to a
// deployment concern.
export const verifySeedRecord = ({ record, nowSeconds }) => {

    if (!record) return false;
    const cert = verifyCertificate(record.certBytes, record.idPk, nowSeconds);
    return cert !== null;

};
