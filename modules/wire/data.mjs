// SPEC § 6.3: DATA packet payload.
//
//   conversation tag (16) ‖ sequence number (8, big-endian u64) ‖ opaque bytes
//
// real_length minimum: 24 bytes (no application bytes). Receivers MUST
// drop DATA packets whose real_length is below this minimum.

const LEN_CONVERSATION_TAG = 16;
const LEN_SEQUENCE = 8;
export const LEN_DATA_PREFIX = LEN_CONVERSATION_TAG + LEN_SEQUENCE;

const OFFSET_CONVERSATION_TAG = 0;
const OFFSET_SEQUENCE = 16;
const OFFSET_APP = 24;

const writeBigUint64BE = (buf, offset, value) => {

    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    view.setBigUint64(offset, BigInt(value), false);

};

const readBigUint64BE = (buf, offset) => {

    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    return view.getBigUint64(offset, false);

};

export const buildDataPayload = ({ conversationTag, sequenceNumber, payload }) => {

    if (conversationTag.length !== LEN_CONVERSATION_TAG) {

        throw new Error('conversationTag must be 16 bytes');

    }

    const buf = new Uint8Array(LEN_DATA_PREFIX + payload.length);
    buf.set(conversationTag, OFFSET_CONVERSATION_TAG);
    writeBigUint64BE(buf, OFFSET_SEQUENCE, sequenceNumber);
    buf.set(payload, OFFSET_APP);
    return buf;

};

export const parseDataPayload = (payload) => {

    if (!payload || payload.length < LEN_DATA_PREFIX) {

        return null;

    }

    return {
        conversationTag: new Uint8Array(payload.subarray(OFFSET_CONVERSATION_TAG, OFFSET_CONVERSATION_TAG + LEN_CONVERSATION_TAG)),
        sequenceNumber: readBigUint64BE(payload, OFFSET_SEQUENCE),
        payload: new Uint8Array(payload.subarray(OFFSET_APP)),
    };

};
