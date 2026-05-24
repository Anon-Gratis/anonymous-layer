// SPEC § 6.4.1: transport record codec, shared by ANNOUNCE_PEER (§ 6.4)
// and FORWARD (§ 6.5).
//
// Wire format of a single transport record:
//
//   type (1) ‖ length (1) ‖ address (length bytes)
//
// And of a transport list:
//
//   count (1) ‖ record_0 ‖ record_1 ‖ ...
//
// Receivers MUST tolerate unknown `type` codes by skipping past the
// length-prefixed `address` and continuing — forward compatibility for
// new transports (Tor onion, QUIC, etc.) without bumping the wire
// version. Decoded records preserve the raw `type` and `address` bytes
// so callers can ignore unfamiliar types without losing data they may
// want to gossip onward.

export const TRANSPORT_WEBSOCKET_IPV4 = 0x01;
export const TRANSPORT_WEBSOCKET_IPV6 = 0x02;

export const LEN_TRANSPORT_HEADER = 2;
export const MAX_TRANSPORT_COUNT = 255;

// Known fixed lengths for sanity-checking known types. Unknown types
// accept any length the wire claims, up to 255.
const KNOWN_LENGTHS = new Map([
    [TRANSPORT_WEBSOCKET_IPV4, 6],
    [TRANSPORT_WEBSOCKET_IPV6, 18],
]);

export const serializeTransports = (transports) => {

    if (transports.length > MAX_TRANSPORT_COUNT) {

        throw new Error(`transport list exceeds count limit (${transports.length} > ${MAX_TRANSPORT_COUNT})`);

    }

    let total = 1; // count byte
    for (const t of transports) {

        if (t.address.length > 0xFF) {

            throw new Error('transport address exceeds 255 bytes');

        }
        const expected = KNOWN_LENGTHS.get(t.type);
        if (expected !== undefined && t.address.length !== expected) {

            throw new Error(`transport type 0x${t.type.toString(16)} requires ${expected}-byte address`);

        }
        total += LEN_TRANSPORT_HEADER + t.address.length;

    }

    const buf = new Uint8Array(total);
    buf[0] = transports.length;
    let off = 1;
    for (const t of transports) {

        buf[off]     = t.type & 0xFF;
        buf[off + 1] = t.address.length & 0xFF;
        buf.set(t.address, off + 2);
        off += LEN_TRANSPORT_HEADER + t.address.length;

    }
    return buf;

};

// Parse a length-prefixed transport list starting at `offset` of `buf`.
// Returns { transports, consumed } — `consumed` is the number of bytes
// read (including the count byte). Returns null on any structural
// failure (truncation, address-length running past buffer end).
//
// Unknown transport types are returned as-is so the caller can decide
// whether to gossip them onward.
export const parseTransports = (buf, offset = 0) => {

    if (!buf || buf.length < offset + 1) {

        return null;

    }

    const count = buf[offset];
    let cursor = offset + 1;
    const transports = [];

    for (let i = 0; i < count; i += 1) {

        if (buf.length < cursor + LEN_TRANSPORT_HEADER) {

            return null;

        }
        const type = buf[cursor];
        const len = buf[cursor + 1];
        const addrStart = cursor + LEN_TRANSPORT_HEADER;
        const addrEnd = addrStart + len;
        if (buf.length < addrEnd) {

            return null;

        }
        // For known types, enforce the canonical length on parse too.
        // Unknown types pass through.
        const expected = KNOWN_LENGTHS.get(type);
        if (expected !== undefined && len !== expected) {

            return null;

        }
        transports.push({
            type,
            address: new Uint8Array(buf.subarray(addrStart, addrEnd)),
        });
        cursor = addrEnd;

    }

    return {
        transports,
        consumed: cursor - offset,
    };

};
