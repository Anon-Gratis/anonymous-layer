import {
    LENGTH_COORDINATION_HEADER,
    LENGTH_KEY_DECRYPTION,
    LENGTH_KEY_SYMMETRIC,
    LENGTH_SESSION_TOKEN,
    LENGTH_SHARED_REMAINDER,
    LENGTH_SHARED_SECRET,

    OFFSET_ADDRESS_TARGET_IPV6_PORT,
    OFFSET_ADDRESS_TARGET_IPV6_HOST,
    OFFSET_ADDRESS_REPLY_IPV6_PORT,
    OFFSET_ADDRESS_REPLY_IPV6_HOST,
    OFFSET_ADDRESS_TYPE,
    OFFSET_COORDINATION_TYPE,
    OFFSET_CHECKSUM,
    OFFSET_FLAGS_32BITS,
    OFFSET_KEY_COLOR_CHANGE,
    OFFSET_KEY_DECRYPTION,
    OFFSET_LENGTH_REAL,
    OFFSET_LENGTH_NEXT,
    OFFSET_REMAINDER_DECRYPTION,
    OFFSET_REMAINDER_ENCRYPTION,
    OFFSET_SESSION_TOKEN,
    OFFSET_SHARED_SECRET_DECRYPTION,
    OFFSET_SHARED_SECRET_ENCRYPTION,
    OFFSET_SHIFT_DATA_AVERAGE,
    OFFSET_SHIFT_DATA_TOTAL,
    OFFSET_SHIFT_TIME_IDLE,
    OFFSET_SHIFT_TIME_TOTAL,

    TYPE_ADDRESS_IPV6_UDP,
    TYPE_ADDRESS_IPV6_WEBSOCKET,
    TYPE_COORDINATION_ANNOUNCE_PEER,
    TYPE_COORDINATION_FASTER_LINK_GRANT,
    TYPE_COORDINATION_FASTER_LINK_PLEAD,
    TYPE_COORDINATION_FORWARD,
    TYPE_COORDINATION_REDIRECT_STATIC,
} from '../../../constants/index.mjs'

import {
    EXTRACT_HOST_IPV6,
    EXTRACT_SUBARRAY,
    EXTRACT_UINT16,
    EXTRACT_UINT32,
    POLYNOMIAL_HEADER_CHECKSUM,
} from '../../../utilities/index.mjs';

////////////////////////////////////////////////////////////////////////
// TYPE-SPECIFIC PARSE HELPERS                                        //
////////////////////////////////////////////////////////////////////////

const PARSE_REPLY_IPV6 = (reply, binary) => {

    const host = EXTRACT_HOST_IPV6(binary, OFFSET_ADDRESS_REPLY_IPV6_HOST);
    const port = EXTRACT_UINT16(binary, OFFSET_ADDRESS_REPLY_IPV6_PORT);
    reply.destination = { host, port };

};

const PARSE_REPLY = (binary, text) => {

    text.reply = {};
    text.reply.type = (binary[OFFSET_ADDRESS_TYPE] >> 0) & 0xF;

    switch (text.reply.type) {

        case TYPE_ADDRESS_IPV6_UDP:
        case TYPE_ADDRESS_IPV6_WEBSOCKET: {

            PARSE_REPLY_IPV6(text.reply, binary);
            break;

        }

    }

};

const PARSE_TARGET_IPV6 = (target, binary) => {

    const host = EXTRACT_HOST_IPV6(binary, OFFSET_ADDRESS_TARGET_IPV6_HOST);
    const port = EXTRACT_UINT16(binary, OFFSET_ADDRESS_TARGET_IPV6_PORT);
    target.destination = { host, port };

};

const PARSE_TARGET = (binary, text) => {

    text.target = {};
    text.target.type = (binary[OFFSET_ADDRESS_TYPE] >> 4) & 0xF;

    switch (text.target.type) {

        case TYPE_ADDRESS_IPV6_UDP:
        case TYPE_ADDRESS_IPV6_WEBSOCKET: {

            PARSE_TARGET_IPV6(text.target, binary);
            break;

        }

    }

};

const PARSE_COORDINATION_ANNOUNCE_PEER = (binary, text) => {

    PARSE_TARGET(binary, text);

    text.capabilities = EXTRACT_UINT32(binary, OFFSET_FLAGS_32BITS);

};

const PARSE_COORDINATION_FASTER_LINK_GRANT = (binary, text) => {

    const subarraySessionToken = EXTRACT_SUBARRAY(
        binary,
        OFFSET_SESSION_TOKEN,
        LENGTH_SESSION_TOKEN,
    );

    text.sessionToken = new Uint8Array(subarraySessionToken);

    PARSE_REPLY(binary, text);

};

const PARSE_COORDINATION_FASTER_LINK_PLEAD = (binary, text) => {

    const subarrayRemainderDecryption = EXTRACT_SUBARRAY(
        binary,
        OFFSET_REMAINDER_DECRYPTION,
        LENGTH_SHARED_REMAINDER,
    );

    const subarraySharedSecretDecryption = EXTRACT_SUBARRAY(
        binary,
        OFFSET_SHARED_SECRET_DECRYPTION,
        LENGTH_SHARED_SECRET,
    );

    text.sharedSecretDecryption = new Uint8Array(subarraySharedSecretDecryption);
    text.remainderDecryption = new Uint8Array(subarrayRemainderDecryption);

    const subarrayRemainderEncryption = EXTRACT_SUBARRAY(
        binary,
        OFFSET_REMAINDER_ENCRYPTION,
        LENGTH_SHARED_REMAINDER,
    );

    const subarraySharedSecretEncryption = EXTRACT_SUBARRAY(
        binary,
        OFFSET_SHARED_SECRET_ENCRYPTION,
        LENGTH_SHARED_SECRET,
    );

    text.sharedSecretEncryption = new Uint8Array(subarraySharedSecretEncryption);
    text.remainderEncryption = new Uint8Array(subarrayRemainderEncryption);

    const subarraySessionToken = EXTRACT_SUBARRAY(
        binary,
        OFFSET_SESSION_TOKEN,
        LENGTH_SESSION_TOKEN,
    );

    text.sessionToken = new Uint8Array(subarraySessionToken);

    text.shiftTimeIdle = binary[OFFSET_SHIFT_TIME_IDLE];
    text.shiftTimeTotal = binary[OFFSET_SHIFT_TIME_TOTAL];
    text.shiftDataAverage = binary[OFFSET_SHIFT_DATA_AVERAGE];
    text.shiftDataTotal = binary[OFFSET_SHIFT_DATA_TOTAL];

    PARSE_REPLY(binary, text);

    text.capabilities = EXTRACT_UINT32(binary, OFFSET_FLAGS_32BITS);

};

const PARSE_COORDINATION_FORWARD = (binary, text) => {

    PARSE_TARGET(binary, text);

};

const PARSE_COORDINATION_REDIRECT_STATIC = (binary, text) => {

    PARSE_TARGET(binary, text);
    PARSE_REPLY(binary, text);

    const subarrayRemainderDecryption = EXTRACT_SUBARRAY(
        binary,
        OFFSET_REMAINDER_DECRYPTION,
        LENGTH_SHARED_REMAINDER,
    );

    const subarraySharedSecretDecryption = EXTRACT_SUBARRAY(
        binary,
        OFFSET_SHARED_SECRET_DECRYPTION,
        LENGTH_SHARED_SECRET,
    );

    text.sharedSecretDecryption = new Uint8Array(subarraySharedSecretDecryption);
    text.remainderDecryption = new Uint8Array(subarrayRemainderDecryption);

    const subarrayRemainderEncryption = EXTRACT_SUBARRAY(
        binary,
        OFFSET_REMAINDER_ENCRYPTION,
        LENGTH_SHARED_REMAINDER,
    );

    const subarraySharedSecretEncryption = EXTRACT_SUBARRAY(
        binary,
        OFFSET_SHARED_SECRET_ENCRYPTION,
        LENGTH_SHARED_SECRET,
    );

    text.sharedSecretEncryption = new Uint8Array(subarraySharedSecretEncryption);
    text.remainderEncryption = new Uint8Array(subarrayRemainderEncryption);

    const subarrayKeyColorChange = EXTRACT_SUBARRAY(
        binary,
        OFFSET_KEY_COLOR_CHANGE,
        LENGTH_KEY_SYMMETRIC,
    );

    text.keyColorChange = new Uint8Array(subarrayKeyColorChange);

    text.shiftTimeIdle = binary[OFFSET_SHIFT_TIME_IDLE];
    text.shiftTimeTotal = binary[OFFSET_SHIFT_TIME_TOTAL];
    text.shiftDataAverage = binary[OFFSET_SHIFT_DATA_AVERAGE];
    text.shiftDataTotal = binary[OFFSET_SHIFT_DATA_TOTAL];

};

export const parse = (binary) => {

    const text = {};

    if (binary.length < LENGTH_COORDINATION_HEADER) {

        return null;

    }

    const checksumA = EXTRACT_UINT16(binary, OFFSET_CHECKSUM);
    const checksumB = POLYNOMIAL_HEADER_CHECKSUM(binary);
    if (checksumA !== checksumB) {

        return null;

    }

    text.type = binary[OFFSET_COORDINATION_TYPE];
    switch (text.type) {

        case TYPE_COORDINATION_ANNOUNCE_PEER: {

            PARSE_COORDINATION_ANNOUNCE_PEER(binary, text);
            break;

        }

        case TYPE_COORDINATION_FASTER_LINK_PLEAD: {

            PARSE_COORDINATION_FASTER_LINK_PLEAD(binary, text);
            break;

        }

        case TYPE_COORDINATION_FASTER_LINK_GRANT: {

            PARSE_COORDINATION_FASTER_LINK_GRANT(binary, text);
            break;

        }

        case TYPE_COORDINATION_FORWARD: {

            PARSE_COORDINATION_FORWARD(binary, text);
            break;

        }

        case TYPE_COORDINATION_REDIRECT_STATIC: {

            PARSE_COORDINATION_REDIRECT_STATIC(binary, text);
            break;

        }

        default: {

            return null;

        }

    }

    text.lengthReal = EXTRACT_UINT16(binary, OFFSET_LENGTH_REAL);
    text.lengthNext = EXTRACT_UINT16(binary, OFFSET_LENGTH_NEXT);

    const subarrayKey = EXTRACT_SUBARRAY(
        binary,
        OFFSET_KEY_DECRYPTION,
        LENGTH_KEY_DECRYPTION,
    );

    text.key = new Uint8Array(subarrayKey);

    return text;

};

const CoordinationPackets = Object.freeze({
    parse,
});

export default CoordinationPackets;
