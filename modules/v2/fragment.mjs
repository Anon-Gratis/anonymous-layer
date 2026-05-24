// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

// Multi-cell handshake fragmentation for SPEC-v0.2-draft § 6.2.1.
//
// Used at two layers in v0.2:
//   - cell layer:  CMD_CREATE / CMD_CREATED carry fragments in their
//                  full 508-byte cell payloads (capacity 500)
//   - RELAY layer: RELAY_EXTEND / RELAY_EXTENDED carry fragments in
//                  the 499-byte RELAY data field (capacity 491)
//
// Both layers share the same 8-byte fragment header. The reassembler
// pins the fragment size on first ingest and rejects subsequent
// fragments of mismatched size, preventing a mixed-size attack where
// an adversary tries to interleave fragments from different carriers.

import { LEN_CELL_PAYLOAD } from './cells.mjs';

export const LEN_FRAGMENT_HEADER = 8;
export const FRAGMENT_PAYLOAD_CAPACITY = LEN_CELL_PAYLOAD - LEN_FRAGMENT_HEADER; // 500

const OFFSET_FRAGMENT_INDEX = 0;
const OFFSET_FRAGMENT_COUNT = 1;
const OFFSET_HANDSHAKE_ID   = 2;
const OFFSET_PAYLOAD_LEN    = 6;
const OFFSET_FRAGMENT_DATA  = 8;

// SPEC § 6.2.1: max 255 fragments per handshake (1-byte field).
const MAX_FRAGMENT_COUNT = 255;

// Operator-tunable upper bound on reassembly: any handshake claiming
// more bytes than this is rejected before allocation. Comfortably above
// hybrid ntor's 1216/1152 to leave room for future handshake additions
// without code change, while still bounding memory per peer.
const MAX_REASSEMBLED_BYTES = 65536;

// ----- Fragment one assembled message into wire fragments -----

// Split `message` into N fragments, each `payloadCapacity + 8` bytes
// (header + data + zero padding). Default capacity is FRAGMENT_PAYLOAD_CAPACITY
// (500 bytes — the full cell-payload minus the 8-byte header), suitable
// for direct carriage in CMD_CREATE/CMD_CREATED. RELAY-carried EXTEND
// fragments use a smaller capacity (491 bytes — RELAY data field minus
// the 8-byte header).
//
// Returns an array of (payloadCapacity + 8)-byte Uint8Arrays.
export const fragmentMessage = ({
    message,
    handshakeId,
    payloadCapacity = FRAGMENT_PAYLOAD_CAPACITY,
}) => {

    if (!Number.isInteger(handshakeId) || handshakeId < 0 || handshakeId > 0xFFFFFFFF) {

        throw new Error('handshakeId must be a u32');

    }
    if (message.length === 0) throw new Error('cannot fragment empty message');
    if (!Number.isInteger(payloadCapacity) || payloadCapacity <= 0 || payloadCapacity > 0xFFFF) {

        throw new Error('payloadCapacity must be a positive u16');

    }

    const count = Math.ceil(message.length / payloadCapacity);
    if (count > MAX_FRAGMENT_COUNT) {

        throw new Error(`message too large to fragment (${count} > ${MAX_FRAGMENT_COUNT})`);

    }

    const fragmentSize = payloadCapacity + LEN_FRAGMENT_HEADER;
    const out = [];
    for (let i = 0; i < count; i += 1) {

        const start = i * payloadCapacity;
        const end = Math.min(start + payloadCapacity, message.length);
        const payloadLen = end - start;
        const frag = new Uint8Array(fragmentSize);
        frag[OFFSET_FRAGMENT_INDEX] = i;
        frag[OFFSET_FRAGMENT_COUNT] = count;
        new DataView(frag.buffer).setUint32(OFFSET_HANDSHAKE_ID, handshakeId, false);
        new DataView(frag.buffer).setUint16(OFFSET_PAYLOAD_LEN, payloadLen, false);
        frag.set(message.subarray(start, end), OFFSET_FRAGMENT_DATA);
        out.push(frag);

    }
    return out;

};

// ----- Parse a single fragment header -----

// Parse a fragment of arbitrary size. The per-fragment payload capacity
// is determined implicitly from the buffer length (= capacity + 8).
const parseFragmentHeader = (frag) => {

    if (!frag || frag.length < LEN_FRAGMENT_HEADER + 1) return null;
    const capacity = frag.length - LEN_FRAGMENT_HEADER;
    const view = new DataView(frag.buffer, frag.byteOffset, frag.byteLength);
    const index = frag[OFFSET_FRAGMENT_INDEX];
    const count = frag[OFFSET_FRAGMENT_COUNT];
    const handshakeId = view.getUint32(OFFSET_HANDSHAKE_ID, false);
    const payloadLen = view.getUint16(OFFSET_PAYLOAD_LEN, false);

    if (count === 0 || count > MAX_FRAGMENT_COUNT) return null;
    if (index >= count) return null;
    if (payloadLen > capacity) return null;
    // Last fragment may be short; earlier fragments MUST be full.
    if (index < count - 1 && payloadLen !== capacity) return null;
    // Padding region must be zero.
    for (let i = OFFSET_FRAGMENT_DATA + payloadLen; i < frag.length; i += 1) {

        if (frag[i] !== 0) return null;

    }

    return {
        index,
        count,
        handshakeId,
        payloadLen,
        fragmentSize: frag.length,
        data: frag.subarray(OFFSET_FRAGMENT_DATA, OFFSET_FRAGMENT_DATA + payloadLen),
    };

};

// ----- Reassembly buffer -----

// Tracks in-progress reassemblies keyed by handshake_id. Caller is
// responsible for periodically calling sweep(now) to drop stale
// entries; without that, an attacker could fill memory with partial
// handshakes.
export const createReassembler = ({
    timeoutMs = 30_000,
    maxConcurrent = 16,
    now = () => Date.now(),
} = {}) => {

    // handshakeId → { count, total: bytes-expected-once-complete,
    //                  fragments: Array<Uint8Array|null>, createdAt }
    const inFlight = new Map();

    // Try to absorb a fragment. Returns:
    //   { complete: true, message }   if this fragment completes a handshake
    //   { complete: false }            if more fragments expected
    //   null                            on any structural failure (caller should DESTROY)
    const ingest = (cellPayload) => {

        const f = parseFragmentHeader(cellPayload);
        if (f === null) return null;

        let entry = inFlight.get(f.handshakeId);
        if (!entry) {

            if (inFlight.size >= maxConcurrent) {

                // Drop the OLDEST entry to make room; if the caller
                // has a longer time horizon they can call sweep more
                // often. Without this an attacker can starve legitimate
                // handshakes.
                let oldestKey = null;
                let oldestAt = Infinity;
                for (const [k, v] of inFlight) {

                    if (v.createdAt < oldestAt) { oldestAt = v.createdAt; oldestKey = k; }

                }
                if (oldestKey !== null) inFlight.delete(oldestKey);

            }
            entry = {
                count: f.count,
                fragmentSize: f.fragmentSize, // pinned on first ingest
                fragments: new Array(f.count).fill(null),
                received: 0,
                createdAt: now(),
            };
            inFlight.set(f.handshakeId, entry);

        }

        // Consistency: count must match across all fragments of this handshake.
        if (entry.count !== f.count) return null;
        // Mixed-size attack defence: every fragment of a handshake MUST
        // arrive at the same fragment-buffer size. Otherwise an
        // adversary could try to confuse the assembler by mixing
        // cell-carried and RELAY-carried fragments of one handshake.
        if (entry.fragmentSize !== f.fragmentSize) return null;

        // Duplicate index — adversarial override attempt; reject and
        // drop the entire reassembly.
        if (entry.fragments[f.index] !== null) {

            inFlight.delete(f.handshakeId);
            return null;

        }

        entry.fragments[f.index] = new Uint8Array(f.data);
        entry.received += 1;

        if (entry.received < entry.count) return { complete: false };

        // Complete — assemble.
        let total = 0;
        for (const part of entry.fragments) total += part.length;
        if (total > MAX_REASSEMBLED_BYTES) {

            inFlight.delete(f.handshakeId);
            return null;

        }

        const message = new Uint8Array(total);
        let off = 0;
        for (const part of entry.fragments) {

            message.set(part, off);
            off += part.length;

        }

        inFlight.delete(f.handshakeId);
        return { complete: true, message };

    };

    const sweep = (currentMs = now()) => {

        const cutoff = currentMs - timeoutMs;
        let dropped = 0;
        for (const [k, v] of inFlight) {

            if (v.createdAt < cutoff) { inFlight.delete(k); dropped += 1; }

        }
        return dropped;

    };

    const size = () => inFlight.size;

    return { ingest, sweep, size };

};
