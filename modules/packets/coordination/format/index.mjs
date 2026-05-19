import {
    OFFSET_ADDRESS_TARGET_IPV6_HOST,
    OFFSET_ADDRESS_TARGET_IPV6_PORT,
    OFFSET_ADDRESS_REPLY_IPV6_HOST,
    OFFSET_ADDRESS_REPLY_IPV6_PORT,
    OFFSET_ADDRESS_TYPE,
    OFFSET_CHECKSUM,
    OFFSET_COORDINATION_TYPE,
    OFFSET_FLAGS_32BITS,
    OFFSET_KEY_COLOR_CHANGE,
    OFFSET_KEY_DECRYPTION,
    OFFSET_LENGTH_REAL,
    OFFSET_LENGTH_NEXT,
    OFFSET_REMAINDER_DECRYPTION,
    OFFSET_REMAINDER_ENCRYPTION,
    OFFSET_SESSION_TOKEN,
    OFFSET_SHIFT_DATA_AVERAGE,
    OFFSET_SHIFT_DATA_TOTAL,
    OFFSET_SHIFT_TIME_IDLE,
    OFFSET_SHIFT_TIME_TOTAL,
    OFFSET_SHARED_SECRET_DECRYPTION,
    OFFSET_SHARED_SECRET_ENCRYPTION,

    TYPE_COORDINATION_ANNOUNCE_PEER,
    TYPE_COORDINATION_FASTER_LINK_GRANT,
    TYPE_COORDINATION_FASTER_LINK_PLEAD,
    TYPE_COORDINATION_FORWARD,
    TYPE_COORDINATION_REDIRECT_STATIC,
    TYPE_ADDRESS_IPV6_UDP,
    TYPE_ADDRESS_IPV6_WEBSOCKET,
} from '../../../constants/index.mjs';

import {
    INSERT_HOST_IPV6,
    INSERT_UINT16,
    INSERT_UINT32,
    POLYNOMIAL_HEADER_CHECKSUM,
} from '../../../utilities/index.mjs';

////////////////////////////////////////////////////////////////////////
// TYPE-SPECIFIC FORMAT HELPERS                                       //
////////////////////////////////////////////////////////////////////////

const FORMAT_REPLY_IPV6 = (reply, binary) => {

    const { destination } = reply;
    const { host, port } = destination;

    INSERT_UINT16(binary, OFFSET_ADDRESS_REPLY_IPV6_PORT, port);
    INSERT_HOST_IPV6(binary, OFFSET_ADDRESS_REPLY_IPV6_HOST, host);

};

const FORMAT_REPLY = (reply, binary) => {

    const { type } = reply;
    binary[OFFSET_ADDRESS_TYPE] = (binary[OFFSET_ADDRESS_TYPE] & 0xF0) | (type << 0);

    switch (type) {

        case TYPE_ADDRESS_IPV6_UDP:
        case TYPE_ADDRESS_IPV6_WEBSOCKET: {

            FORMAT_REPLY_IPV6(reply, binary);
            break;

        }

    }

};

const FORMAT_TARGET_IPV6 = (target, binary) => {

    const { destination } = target;
    const { host, port } = destination;

    INSERT_UINT16(binary, OFFSET_ADDRESS_TARGET_IPV6_PORT, port);
    INSERT_HOST_IPV6(binary, OFFSET_ADDRESS_TARGET_IPV6_HOST, host);

};

const FORMAT_TARGET = (target, binary) => {

    const { type } = target;
    binary[OFFSET_ADDRESS_TYPE] = (binary[OFFSET_ADDRESS_TYPE] & 0x0F) | (type << 4);

    switch (type) {

        case TYPE_ADDRESS_IPV6_UDP:
        case TYPE_ADDRESS_IPV6_WEBSOCKET: {

            FORMAT_TARGET_IPV6(target, binary);
            break;

        }

    }

};

const FORMAT_COORDINATION_ANNOUNCE_PEER = (text, binary) => {

    const { target } = text;
    FORMAT_TARGET(target, binary);

    const { capabilities } = text;
    INSERT_UINT32(binary, OFFSET_FLAGS_32BITS, capabilities);

};

const FORMAT_COORDINATION_FASTER_LINK_GRANT = (text, binary) => {

    const { sessionToken } = text;
    binary.set(sessionToken, OFFSET_SESSION_TOKEN);

    const { reply } = text;
    FORMAT_REPLY(reply, binary);

};

const FORMAT_COORDINATION_FASTER_LINK_PLEAD = (text, binary) => {

    const { sharedSecretDecryption, remainderDecryption } = text;
    binary.set(sharedSecretDecryption, OFFSET_SHARED_SECRET_DECRYPTION);
    binary.set(remainderDecryption, OFFSET_REMAINDER_DECRYPTION);

    const { sharedSecretEncryption, remainderEncryption } = text;
    binary.set(sharedSecretEncryption, OFFSET_SHARED_SECRET_ENCRYPTION);
    binary.set(remainderEncryption, OFFSET_REMAINDER_ENCRYPTION);

    const { sessionToken } = text;
    binary.set(sessionToken, OFFSET_SESSION_TOKEN);

    const { shiftTimeIdle, shiftTimeTotal } = text;
    binary[OFFSET_SHIFT_TIME_IDLE] = shiftTimeIdle;
    binary[OFFSET_SHIFT_TIME_TOTAL] = shiftTimeTotal;

    const { shiftDataAverage, shiftDataTotal } = text;
    binary[OFFSET_SHIFT_DATA_AVERAGE] = shiftDataAverage;
    binary[OFFSET_SHIFT_DATA_TOTAL] = shiftDataTotal;

    const { reply } = text;
    FORMAT_REPLY(reply, binary);

    const { capabilities } = text;
    INSERT_UINT32(binary, OFFSET_FLAGS_32BITS, capabilities);

};

const FORMAT_COORDINATION_FORWARD = (text, binary) => {

    const { target } = text;
    FORMAT_TARGET(target, binary);

};

const FORMAT_COORDINATION_REDIRECT_STATIC = (text, binary) => {

    const { target } = text;
    FORMAT_TARGET(target, binary);

    const { sharedSecretDecryption, remainderDecryption } = text;
    binary.set(sharedSecretDecryption, OFFSET_SHARED_SECRET_DECRYPTION);
    binary.set(remainderDecryption, OFFSET_REMAINDER_DECRYPTION);

    const { sharedSecretEncryption, remainderEncryption } = text;
    binary.set(sharedSecretEncryption, OFFSET_SHARED_SECRET_ENCRYPTION);
    binary.set(remainderEncryption, OFFSET_REMAINDER_ENCRYPTION);

    const { keyColorChange } = text;
    binary.set(keyColorChange, OFFSET_KEY_COLOR_CHANGE);

    const { shiftTimeIdle, shiftTimeTotal } = text;
    binary[OFFSET_SHIFT_TIME_IDLE] = shiftTimeIdle;
    binary[OFFSET_SHIFT_TIME_TOTAL] = shiftTimeTotal;

    const { shiftDataAverage, shiftDataTotal } = text;
    binary[OFFSET_SHIFT_DATA_AVERAGE] = shiftDataAverage;
    binary[OFFSET_SHIFT_DATA_TOTAL] = shiftDataTotal;

    const { reply } = text;
    FORMAT_REPLY(reply, binary);

};

////////////////////////////////////////////////////////////////////////
// EXPORTED PROCEDURES                                                //
////////////////////////////////////////////////////////////////////////

export const format = (text, binary) => {

    const { type, key, lengthReal, lengthNext } = text;

    binary[OFFSET_COORDINATION_TYPE] = type;
    INSERT_UINT16(binary, OFFSET_LENGTH_REAL, lengthReal);
    INSERT_UINT16(binary, OFFSET_LENGTH_NEXT, lengthNext);

    binary.set(key, OFFSET_KEY_DECRYPTION);

    switch (type) {

        case TYPE_COORDINATION_ANNOUNCE_PEER: {

            FORMAT_COORDINATION_ANNOUNCE_PEER(text, binary);
            break;

        }

        case TYPE_COORDINATION_FASTER_LINK_GRANT: {

            FORMAT_COORDINATION_FASTER_LINK_GRANT(text, binary);
            break;

        }

        case TYPE_COORDINATION_FASTER_LINK_PLEAD: {

            FORMAT_COORDINATION_FASTER_LINK_PLEAD(text, binary);
            break;

        }

        case TYPE_COORDINATION_FORWARD: {

            FORMAT_COORDINATION_FORWARD(text, binary);
            break;

        }

        case TYPE_COORDINATION_REDIRECT_STATIC: {

            FORMAT_COORDINATION_REDIRECT_STATIC(text, binary);
            break;

        }

    }

    const checksum = POLYNOMIAL_HEADER_CHECKSUM(binary);
    INSERT_UINT16(binary, OFFSET_CHECKSUM, checksum);

};

const CoordinationPackets = Object.freeze({
    format,
});

export default CoordinationPackets;
