// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE
//
// Reference v0.2 runtime, see docs/SPEC-v0.2-draft.md.

// Codecs for the stream-level RELAY sub-command payloads (SPEC § 7).
//
//   RELAY_BEGIN     — client → exit: open a TCP stream to (addr, port)
//   RELAY_CONNECTED — exit → client: stream is open (or status code)
//   RELAY_DATA      — bidirectional: raw stream bytes
//   RELAY_END       — bidirectional: tear down THIS stream

export const ADDR_TYPE_IPV4     = 0x01;
export const ADDR_TYPE_IPV6     = 0x02;
export const ADDR_TYPE_HOSTNAME = 0x03;

// RELAY_END reason codes (SPEC § 7.4).
export const END_REASON_MISC          = 0x01;
export const END_REASON_EXIT_POLICY   = 0x02;
export const END_REASON_RESOLVE_FAIL  = 0x03;
export const END_REASON_REFUSED       = 0x04;
export const END_REASON_TIMEOUT       = 0x05;
export const END_REASON_REMOTE_CLOSED = 0x06;
export const END_REASON_CLIENT_CLOSED = 0x07;

// RELAY_CONNECTED status codes (SPEC § 7.2.1).
export const CONNECTED_STATUS_OK = 0x00;

const HOSTNAME_MAX_LEN = 255;

// ----- RELAY_BEGIN -----

// Build a RELAY_BEGIN payload.
//
//   destination = {
//     addrType: ADDR_TYPE_IPV4 | ADDR_TYPE_IPV6 | ADDR_TYPE_HOSTNAME,
//     addr:     Uint8Array (4 bytes IPv4, 16 bytes IPv6, or arbitrary
//               UTF-8 bytes for hostname — NOT length-prefixed; encoder
//               adds the length byte for hostnames),
//     port:     u16,
//     flags:    optional u8, default 0
//   }
export const buildBeginPayload = ({ addrType, addr, port, flags = 0 }) => {

    if (!Number.isInteger(port) || port < 0 || port > 0xFFFF) {

        throw new Error(`port must be a u16, got ${port}`);

    }

    let addrField;
    if (addrType === ADDR_TYPE_IPV4) {

        if (addr.length !== 4) throw new Error('IPv4 addr must be 4 bytes');
        addrField = addr;

    } else if (addrType === ADDR_TYPE_IPV6) {

        if (addr.length !== 16) throw new Error('IPv6 addr must be 16 bytes');
        addrField = addr;

    } else if (addrType === ADDR_TYPE_HOSTNAME) {

        if (addr.length === 0 || addr.length > HOSTNAME_MAX_LEN) {

            throw new Error(`hostname must be 1..${HOSTNAME_MAX_LEN} bytes`);

        }
        addrField = new Uint8Array(1 + addr.length);
        addrField[0] = addr.length;
        addrField.set(addr, 1);

    } else {

        throw new Error(`unknown addr_type: 0x${addrType.toString(16)}`);

    }

    const buf = new Uint8Array(1 + addrField.length + 2 + 1);
    let off = 0;
    buf[off] = addrType; off += 1;
    buf.set(addrField, off); off += addrField.length;
    buf[off] = (port >> 8) & 0xFF; off += 1;
    buf[off] = port & 0xFF; off += 1;
    buf[off] = flags & 0xFF;
    return buf;

};

export const parseBeginPayload = (payload) => {

    if (!payload || payload.length < 4) return null;
    const addrType = payload[0];
    let addrLen;
    let addrStart = 1;
    if (addrType === ADDR_TYPE_IPV4) {

        addrLen = 4;

    } else if (addrType === ADDR_TYPE_IPV6) {

        addrLen = 16;

    } else if (addrType === ADDR_TYPE_HOSTNAME) {

        if (payload.length < 2) return null;
        const hnLen = payload[1];
        if (hnLen === 0 || hnLen > HOSTNAME_MAX_LEN) return null;
        addrLen = hnLen;
        addrStart = 2;

    } else {

        return null;

    }
    const minLen = addrStart + addrLen + 2 + 1; // addr + port(2) + flags(1)
    if (payload.length < minLen) return null;
    const addr = new Uint8Array(payload.subarray(addrStart, addrStart + addrLen));
    const port = (payload[addrStart + addrLen] << 8) | payload[addrStart + addrLen + 1];
    const flags = payload[addrStart + addrLen + 2];
    return { addrType, addr, port, flags };

};

// Helper: convert an IPv4-byte addr to dotted-decimal string.
export const ipv4ToString = (addr) =>
    `${addr[0]}.${addr[1]}.${addr[2]}.${addr[3]}`;

// ----- RELAY_CONNECTED -----

export const buildConnectedPayload = ({ status = CONNECTED_STATUS_OK } = {}) =>
    Uint8Array.from([status & 0xFF]);

export const parseConnectedPayload = (payload) => {

    if (!payload || payload.length < 1) return null;
    return { status: payload[0] };

};

// ----- RELAY_END -----

export const buildEndPayload = (reason) => Uint8Array.from([reason & 0xFF]);

export const parseEndPayload = (payload) => {

    if (!payload || payload.length < 1) return null;
    return { reason: payload[0] };

};
