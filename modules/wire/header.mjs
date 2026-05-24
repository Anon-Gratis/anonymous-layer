import {
    LEN_OUTER_HEADER,
    LEN_RECIPIENT_PREFIX,
    LEN_EPH_PK,
    LEN_NONCE,
    OFFSET_VERSION,
    OFFSET_BUCKET,
    OFFSET_RECIPIENT_PREFIX,
    OFFSET_EPH_PK,
    OFFSET_NONCE,
} from './constants.mjs';

// SPEC § 5.2: build the 54-byte outer header. Fields are written in
// document order. No semantic validation of `version` or `bucket` is
// performed here — those checks belong to the receive path (SPEC § 5.7
// steps 2-3). The caller is responsible for supplying field values of
// the correct length; mismatches throw because they indicate programmer
// error, not adversarial input.
export const buildOuterHeader = ({ version, bucket, recipientPrefix, ephPk, nonce }) => {

    if (recipientPrefix.length !== LEN_RECIPIENT_PREFIX) {

        throw new Error('recipientPrefix must be 8 bytes');

    }

    if (ephPk.length !== LEN_EPH_PK) {

        throw new Error('ephPk must be 32 bytes');

    }

    if (nonce.length !== LEN_NONCE) {

        throw new Error('nonce must be 12 bytes');

    }

    const header = new Uint8Array(LEN_OUTER_HEADER);
    header[OFFSET_VERSION] = version & 0xFF;
    header[OFFSET_BUCKET] = bucket & 0xFF;
    header.set(recipientPrefix, OFFSET_RECIPIENT_PREFIX);
    header.set(ephPk, OFFSET_EPH_PK);
    header.set(nonce, OFFSET_NONCE);
    return header;

};

// SPEC § 5.2: parse the 54-byte outer header out of an arbitrary input
// buffer. Returns null if the buffer is too short — this is the
// adversarial-input boundary, so silent-drop discipline (SPEC § 9)
// applies. Returned slices alias into `buf`; callers that mutate or
// retain the buffer should copy. Version/bucket semantics are NOT
// validated here — only the receive path enforces those.
export const parseOuterHeader = (buf) => {

    if (!buf || buf.length < LEN_OUTER_HEADER) {

        return null;

    }

    return {
        version: buf[OFFSET_VERSION],
        bucket: buf[OFFSET_BUCKET],
        recipientPrefix: buf.subarray(OFFSET_RECIPIENT_PREFIX, OFFSET_RECIPIENT_PREFIX + LEN_RECIPIENT_PREFIX),
        ephPk: buf.subarray(OFFSET_EPH_PK, OFFSET_EPH_PK + LEN_EPH_PK),
        nonce: buf.subarray(OFFSET_NONCE, OFFSET_NONCE + LEN_NONCE),
    };

};
