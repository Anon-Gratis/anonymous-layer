import {
    LEN_SENDER_FINGERPRINT,
    LEN_INNER_PREFIX,
    OFFSET_PACKET_TYPE,
    OFFSET_REAL_LENGTH,
    OFFSET_SENDER_FINGERPRINT,
    OFFSET_PAYLOAD,
    innerLengthForBucket,
    maxPayloadForBucket,
} from './constants.mjs';

// SPEC § 5.4: build the inner plaintext for a given bucket. The result
// is exactly (bucket - 70) bytes: a 35-byte prefix (type + real_length
// + sender_fingerprint), the payload, then zero-padding to the bucket's
// inner length. Throws on programmer error (oversized payload, wrong-
// sized fingerprint); the caller is responsible for selecting a bucket
// that fits the payload.
export const buildInnerPlaintext = ({ bucket, packetType, senderFingerprint, payload }) => {

    const innerLen = innerLengthForBucket(bucket);
    if (innerLen === 0) {

        throw new Error('unknown bucket code');

    }

    if (senderFingerprint.length !== LEN_SENDER_FINGERPRINT) {

        throw new Error('senderFingerprint must be 32 bytes');

    }

    const maxPayload = maxPayloadForBucket(bucket);
    if (payload.length > maxPayload) {

        throw new Error(`payload exceeds bucket capacity (${payload.length} > ${maxPayload})`);

    }

    if (payload.length > 0xFFFF) {

        // real_length is a u16; the bucket check above already enforces
        // this for legal buckets, but guard explicitly for clarity.
        throw new Error('payload exceeds 65535 bytes');

    }

    const inner = new Uint8Array(innerLen);
    inner[OFFSET_PACKET_TYPE] = packetType & 0xFF;
    // real_length as big-endian u16
    inner[OFFSET_REAL_LENGTH]     = (payload.length >>> 8) & 0xFF;
    inner[OFFSET_REAL_LENGTH + 1] = payload.length & 0xFF;
    inner.set(senderFingerprint, OFFSET_SENDER_FINGERPRINT);
    inner.set(payload, OFFSET_PAYLOAD);
    // remaining bytes are already zero from `new Uint8Array`.
    return inner;

};

// SPEC § 5.4 / § 5.7: parse and validate the inner plaintext after AEAD
// decryption has already succeeded. Returns null per silent-drop
// discipline on any structural defect:
//   - wrong total length for the claimed bucket
//   - real_length exceeds the bucket's payload capacity
//   - any padding byte is non-zero
// The packet-type byte is returned as-is; § 6.1 / § 6.2 reservations
// (e.g. 0x00, 0x05-0xFF) are the dispatch layer's responsibility.
export const parseInnerPlaintext = (plaintext, bucket) => {

    const expectedLen = innerLengthForBucket(bucket);
    if (expectedLen === 0) {

        return null;

    }

    if (!plaintext || plaintext.length !== expectedLen) {

        return null;

    }

    const packetType = plaintext[OFFSET_PACKET_TYPE];
    const realLength = (plaintext[OFFSET_REAL_LENGTH] << 8) | plaintext[OFFSET_REAL_LENGTH + 1];

    const maxPayload = maxPayloadForBucket(bucket);
    if (realLength > maxPayload) {

        return null;

    }

    const payloadStart = OFFSET_PAYLOAD;
    const payloadEnd = payloadStart + realLength;

    // SPEC § 5.4: every byte of padding MUST be 0x00.
    for (let i = payloadEnd; i < expectedLen; i += 1) {

        if (plaintext[i] !== 0x00) {

            return null;

        }

    }

    return {
        packetType,
        senderFingerprint: new Uint8Array(plaintext.subarray(OFFSET_SENDER_FINGERPRINT, OFFSET_SENDER_FINGERPRINT + LEN_SENDER_FINGERPRINT)),
        payload: new Uint8Array(plaintext.subarray(payloadStart, payloadEnd)),
        realLength,
    };

};

export { LEN_INNER_PREFIX };
