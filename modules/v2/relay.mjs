// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

// RELAY cell inner-layout, running BLAKE2b digest, and RELAY sub-
// command codec for SPEC-v0.2-draft § 5.4.
//
// A RELAY cell rides inside a regular cell (command = CMD_RELAY) and
// its 508-byte payload, after all layered encryption has been peeled,
// has this structure:
//
//   relay_command (1)
//   stream_id     (2, BE)
//   digest        (4)
//   length        (2, BE; ≤ 499)
//   data          (length bytes)
//   padding       (508 − 9 − length bytes, all zero)
//
// The digest is a running BLAKE2b state per direction, per hop. When
// a hop receives a cell, it tries to verify the digest using its own
// state. A match means the cell is destined for this hop; a mismatch
// means the cell is for a later hop and should be forwarded with the
// speculative state update DISCARDED. This is what lets a single
// RELAY-cell stream be addressed to specific hops without telling
// intermediate hops who the recipient is.

import { blake2b } from '@noble/hashes/blake2.js';

import {
    LEN_CELL_PAYLOAD,
    CMD_DESTROY,
    buildCell,
    parseCell,
} from './cells.mjs';

// ----- RELAY inner header layout -----

export const LEN_RELAY_COMMAND = 1;
export const LEN_STREAM_ID = 2;
export const LEN_DIGEST_FIELD = 4;
export const LEN_REAL_LENGTH = 2;
export const LEN_RELAY_PREFIX = 9; // 1 + 2 + 4 + 2

export const OFFSET_RELAY_COMMAND = 0;
export const OFFSET_STREAM_ID = 1;
export const OFFSET_DIGEST = 3;
export const OFFSET_REAL_LENGTH = 7;
export const OFFSET_RELAY_DATA = 9;

export const MAX_RELAY_DATA = LEN_CELL_PAYLOAD - LEN_RELAY_PREFIX; // 499

// ----- RELAY sub-commands (SPEC § 5.4.1) -----

export const RELAY_BEGIN       = 0x00;
export const RELAY_DATA        = 0x01;
export const RELAY_END         = 0x02;
export const RELAY_CONNECTED   = 0x03;
export const RELAY_EXTEND      = 0x04;
export const RELAY_EXTENDED    = 0x05;
export const RELAY_INTRODUCE1  = 0x06;
export const RELAY_INTRODUCE2  = 0x07;
export const RELAY_RENDEZVOUS1 = 0x08;
export const RELAY_RENDEZVOUS2 = 0x09;
export const RELAY_RESOLVE     = 0x0A;
export const RELAY_RESOLVED    = 0x0B;
export const RELAY_TRUNCATE    = 0x0C;
export const RELAY_TRUNCATED   = 0x0D;
// Rendezvous flow (SPEC § 5.4.1 / § 9.5).
export const RELAY_ESTABLISH_INTRO       = 0x0E;
export const RELAY_INTRO_ESTABLISHED     = 0x0F;
export const RELAY_ESTABLISH_RENDEZVOUS  = 0x10;
export const RELAY_RENDEZVOUS_ESTABLISHED = 0x11;
export const RELAY_INTRODUCE_ACK         = 0x12;

// ---- HSDir descriptor fetch (Phase 1.5) ----
//
// A narrow exit-side primitive: the client sends RELAY_DESCFETCH with
// the address body (16–64 byte ASCII, i.e. an .anon address minus its
// .anon suffix) as the cell payload. The exit relay HTTPS-fetches the
// descriptor from a hardcoded HSDir URL (the DA) and streams the
// response back to the client over the circuit as a sequence of
// RELAY_DESCFETCH_REPLY cells, terminated by RELAY_DESCFETCH_END.
//
// First reply cell payload:
//     0..3   uint32 BE  HTTP status (0 = relay-side error / synthetic)
//     4..7   uint32 BE  total body length in bytes
//     8..n   first body chunk (up to MAX_RELAY_DATA - 8)
//
// Subsequent reply cells: pure body bytes, up to MAX_RELAY_DATA each.
// Final cell: RELAY_DESCFETCH_END with empty payload — completion
// signal. The client closes the circuit when END arrives or on error.
//
// Unlike RELAY_BEGIN, the destination is NOT user-controllable — the
// relay-side handler hardcodes the DA URL — so this does not grant
// general internet egress. It's a narrow "directory tunnel" in the
// Tor sense.
export const RELAY_DESCFETCH       = 0x13;
export const RELAY_DESCFETCH_REPLY = 0x14;
export const RELAY_DESCFETCH_END   = 0x15;

// SPEC § 7.1: stream_id 0x0000 is reserved for circuit-level commands
// (EXTEND/EXTENDED/SENDME-circuit). Application streams use 0x0001+.
export const STREAM_ID_CIRCUIT = 0x0000;

// ----- Running digest state -----

// Build a fresh BLAKE2b digest state seeded with K_digest. The state
// is then incrementally updated with every (zeroed-digest) RELAY cell
// the hop sees in this direction.
export const createDigestState = (kDigest) => {

    if (kDigest.length !== 32) throw new Error('K_digest must be 32 bytes');
    const state = blake2b.create({ dkLen: 32 });
    state.update(kDigest);
    return state;

};

// Compute the 4-byte digest field for the next cell to be sent. MUTATES
// the state: after this call the state has consumed the (zeroed-
// digest) payload as if the cell were sent.
const consumeAndDigest = (state, zeroedPayload) => {

    state.update(zeroedPayload);
    return state.clone().digest().subarray(0, LEN_DIGEST_FIELD);

};

// ----- RELAY cell payload codec -----

// Build a RELAY cell's INNER PAYLOAD (the 508-byte plaintext that the
// client wraps in layered encryption before sending). MUTATES the
// digest state: after this call the state reflects the sent cell.
//
// Inputs:
//   relayCommand   one of the RELAY_* constants
//   streamId       2-byte stream ID (0x0000 for circuit-level)
//   data           up to MAX_RELAY_DATA bytes of payload
//   digestState    running BLAKE2b state for the FORWARD direction at
//                  the target hop
export const buildRelayPayload = ({
    relayCommand,
    streamId,
    data = new Uint8Array(0),
    digestState,
}) => {

    if (data.length > MAX_RELAY_DATA) {

        throw new Error(`data exceeds RELAY capacity (${data.length} > ${MAX_RELAY_DATA})`);

    }
    if (streamId < 0 || streamId > 0xFFFF) {

        throw new Error('streamId must be 0..65535');

    }

    const payload = new Uint8Array(LEN_CELL_PAYLOAD);
    const view = new DataView(payload.buffer, payload.byteOffset);
    payload[OFFSET_RELAY_COMMAND] = relayCommand & 0xFF;
    view.setUint16(OFFSET_STREAM_ID, streamId, false);
    // digest field stays zero for the speculative-state input
    view.setUint16(OFFSET_REAL_LENGTH, data.length, false);
    if (data.length > 0) payload.set(data, OFFSET_RELAY_DATA);
    // padding region is already zero from `new Uint8Array`

    // Feed the zeroed-digest payload to the digest state, derive the
    // 4-byte digest, then patch it back into the cell. This is the
    // standard running-digest construction.
    const digest = consumeAndDigest(digestState, payload);
    payload.set(digest, OFFSET_DIGEST);

    return payload;

};

// Speculatively verify a RELAY cell's digest against `digestState`.
// Returns:
//   { match: true,  parsed: { relayCommand, streamId, data } }   on match (state IS updated)
//   { match: false }                                              on mismatch (state NOT updated)
//   null                                                          on structural failure
export const tryConsumeRelayPayload = (payload, digestState) => {

    if (!payload || payload.length !== LEN_CELL_PAYLOAD) return null;

    // Build the "zeroed-digest" view: a fresh copy with the 4 digest
    // bytes replaced by zero.
    const zeroed = new Uint8Array(payload);
    zeroed[OFFSET_DIGEST]     = 0;
    zeroed[OFFSET_DIGEST + 1] = 0;
    zeroed[OFFSET_DIGEST + 2] = 0;
    zeroed[OFFSET_DIGEST + 3] = 0;

    // Speculative update on a clone.
    const tentative = digestState.clone();
    tentative.update(zeroed);
    const expected = tentative.clone().digest().subarray(0, LEN_DIGEST_FIELD);
    const claimed  = payload.subarray(OFFSET_DIGEST, OFFSET_DIGEST + LEN_DIGEST_FIELD);

    // Constant-time compare.
    let diff = 0;
    for (let i = 0; i < LEN_DIGEST_FIELD; i += 1) diff |= claimed[i] ^ expected[i];
    if (diff !== 0) return { match: false };

    // Match — commit the speculative update to the real state.
    digestState.update(zeroed);

    // Parse the structural fields. A bad length or non-zero padding
    // here is a protocol violation by a peer with whom we share a key,
    // so the right disposition is "tear down the circuit" — but at
    // this layer we just return null and let the caller issue DESTROY.
    const view = new DataView(payload.buffer, payload.byteOffset);
    const relayCommand = payload[OFFSET_RELAY_COMMAND];
    const streamId = view.getUint16(OFFSET_STREAM_ID, false);
    const realLength = view.getUint16(OFFSET_REAL_LENGTH, false);

    if (realLength > MAX_RELAY_DATA) return null;
    for (let i = OFFSET_RELAY_DATA + realLength; i < LEN_CELL_PAYLOAD; i += 1) {

        if (payload[i] !== 0) return null;

    }

    return {
        match: true,
        parsed: {
            relayCommand,
            streamId,
            data: new Uint8Array(payload.subarray(OFFSET_RELAY_DATA, OFFSET_RELAY_DATA + realLength)),
        },
    };

};

// ----- DESTROY cell -----

// SPEC § 6.4: DESTROY tears a circuit down. Payload byte 0 is the
// reason code; remaining bytes are zero.
export const DESTROY_REASON_NONE          = 0x00;
export const DESTROY_REASON_PROTOCOL      = 0x01;
export const DESTROY_REASON_INTERNAL      = 0x02;
export const DESTROY_REASON_REQUESTED     = 0x03;
export const DESTROY_REASON_HIBERNATING   = 0x04;
export const DESTROY_REASON_RESOURCELIMIT = 0x05;
export const DESTROY_REASON_CONNECTFAILED = 0x06;
export const DESTROY_REASON_OR_IDENTITY   = 0x07;
export const DESTROY_REASON_TIMEOUT       = 0x08;

export const buildDestroyCell = ({ circuitId, reason = DESTROY_REASON_NONE }) => {

    const payload = new Uint8Array(LEN_CELL_PAYLOAD);
    payload[0] = reason & 0xFF;
    return buildCell({ circuitId, command: CMD_DESTROY, payload });

};

export const parseDestroyCell = (raw) => {

    const parsed = parseCell(raw);
    if (parsed === null) return null;
    if (parsed.command !== CMD_DESTROY) return null;
    return { circuitId: parsed.circuitId, reason: parsed.payload[0] };

};
