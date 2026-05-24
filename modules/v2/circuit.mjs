// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

// Circuit construction for SPEC-v0.2-draft § 6, using the hybrid
// X25519 + ML-KEM-768 ntor handshake (§ 3.7).
//
// Because the hybrid handshake doesn't fit in a single 508-byte cell
// payload, CREATE / CREATED / RELAY_EXTEND / RELAY_EXTENDED are
// MULTI-CELL. The receive-side functions are stateful: they take a
// reassembler that accumulates fragments and only complete when all
// fragments have arrived.
//
// Counter semantics (SPEC § 5.4.3) are per-hop; each client-side hop
// and relay-side hop maintains its own forward + backward counter that
// advances only when a cell actually passes through it.

import { randomInt } from 'node:crypto';

import {
    CELL_BYTES,
    LEN_CELL_PAYLOAD,
    CMD_CREATE,
    CMD_CREATED,
    CMD_RELAY,
    buildCell,
    parseCell,
    buildLayerIV,
    applyLayer,
} from './cells.mjs';
import {
    clientInit,
    clientFinish,
    relayResponse,
    deriveHopKeys,
    CREATE_MSG_BYTES,
    CREATED_MSG_BYTES,
} from './ntor_hybrid.mjs';
import {
    fragmentMessage,
    createReassembler,
    LEN_FRAGMENT_HEADER,
    FRAGMENT_PAYLOAD_CAPACITY,
} from './fragment.mjs';
import {
    RELAY_EXTEND,
    RELAY_EXTENDED,
    STREAM_ID_CIRCUIT,
    MAX_RELAY_DATA,
    createDigestState,
    buildRelayPayload,
    tryConsumeRelayPayload,
} from './relay.mjs';

// RELAY-carriage fragment capacity = RELAY data field (499) minus 8-byte
// header = 491 bytes per fragment.
const RELAY_FRAGMENT_CAPACITY = MAX_RELAY_DATA - LEN_FRAGMENT_HEADER;

const EXTEND_PAYLOAD_BYTES = 32 + 32 + CREATE_MSG_BYTES; // 1280

const newHandshakeId = () => randomInt(0, 0x100000000);

const concat = (...arrays) => {

    let total = 0;
    for (const a of arrays) total += a.length;
    const out = new Uint8Array(total);
    let o = 0;
    for (const a of arrays) { out.set(a, o); o += a.length; }
    return out;

};

// ----- Client circuit state -----

export const createClientCircuit = ({ circuitId }) => ({
    circuitId,
    hops: [],
});

export const addHop = (circuit, hopKeys) => {

    circuit.hops.push({
        Kf: hopKeys.Kf,
        Kb: hopKeys.Kb,
        Kdf: hopKeys.Kdf,
        Kdb: hopKeys.Kdb,
        forwardCounter: 0n,
        backwardCounter: 0n,
        forwardDigest: createDigestState(hopKeys.Kdf),
        backwardDigest: createDigestState(hopKeys.Kdb),
        // Reassembler for RELAY_EXTENDED fragments that arrive from
        // this hop (the hop initiated the EXTEND response).
        extendedReassembler: createReassembler(),
    });

};

// ----- Relay circuit state -----

export const createRelayHop = ({ inboundCircuitId, hopKeys }) => ({
    inboundCircuitId,
    Kf: hopKeys.Kf,
    Kb: hopKeys.Kb,
    Kdf: hopKeys.Kdf,
    Kdb: hopKeys.Kdb,
    forwardCounter: 0n,
    backwardCounter: 0n,
    forwardDigest: createDigestState(hopKeys.Kdf),
    backwardDigest: createDigestState(hopKeys.Kdb),
    // Reassembler for RELAY_EXTEND fragments arriving at this hop.
    extendReassembler: createReassembler(),
});

// ----- Layered encryption (unchanged from chunk 7.4 — independent of handshake choice) -----

export const encryptOutbound = (circuit, plaintext) => {

    if (plaintext.length !== LEN_CELL_PAYLOAD) {

        throw new Error('layered encryption operates on full 508-byte cell payload');

    }
    if (circuit.hops.length === 0) {

        throw new Error('cannot encrypt: circuit has no hops');

    }

    let payload = plaintext;
    for (let i = circuit.hops.length - 1; i >= 0; i -= 1) {

        const hop = circuit.hops[i];
        payload = applyLayer(hop.Kf, buildLayerIV(hop.forwardCounter), payload);
        hop.forwardCounter += 1n;

    }
    return payload;

};

export const decryptInbound = (circuit, ciphertext) => {

    if (ciphertext.length !== LEN_CELL_PAYLOAD) {

        throw new Error('layered decryption operates on full 508-byte cell payload');

    }
    if (circuit.hops.length === 0) {

        throw new Error('cannot decrypt: circuit has no hops');

    }

    let payload = ciphertext;
    for (let i = 0; i < circuit.hops.length; i += 1) {

        const hop = circuit.hops[i];
        payload = applyLayer(hop.Kb, buildLayerIV(hop.backwardCounter), payload);
        hop.backwardCounter += 1n;

    }
    return payload;

};

export const relayPeelForward = (relayHop, payload) => {

    if (payload.length !== LEN_CELL_PAYLOAD) {

        throw new Error('relay layer ops require full 508-byte payload');

    }
    const iv = buildLayerIV(relayHop.forwardCounter);
    const result = applyLayer(relayHop.Kf, iv, payload);
    relayHop.forwardCounter += 1n;
    return result;

};

export const relayWrapBackward = (relayHop, payload) => {

    if (payload.length !== LEN_CELL_PAYLOAD) {

        throw new Error('relay layer ops require full 508-byte payload');

    }
    const iv = buildLayerIV(relayHop.backwardCounter);
    const result = applyLayer(relayHop.Kb, iv, payload);
    relayHop.backwardCounter += 1n;
    return result;

};

// ----- Multi-cell CREATE / CREATED -----

// Client: begin a new handshake. Returns:
//   {
//     cells:        array of 3 CMD_CREATE cells to send (in order)
//     ntorState:    state needed to finish the handshake on CREATED
//     handshakeId:  the client-chosen handshake_id (for caller logging)
//   }
export const beginCreate = ({ circuitId }) => {

    const ntorState = clientInit();
    const handshakeId = newHandshakeId();
    const fragments = fragmentMessage({
        message: ntorState.createMsg,
        handshakeId,
    });
    const cells = fragments.map((frag) => buildCell({
        circuitId,
        command: CMD_CREATE,
        payload: frag,
    }));
    return { cells, ntorState, handshakeId };

};

// Relay-side reassembly state. Each circuit-being-built has its own.
export const createHandshakeReassembler = (opts) => createReassembler(opts);

// Relay: ingest one CMD_CREATE cell. Returns:
//   { complete: true, createdCells, relayHop, handshakeId } — handshake done
//   { complete: false }                                      — more cells expected
//   null                                                     — failure (DESTROY)
export const handleCreate = ({ cell, B_sk, B_pk, ID_R, reassembler }) => {

    const parsed = parseCell(cell);
    if (parsed === null) return null;
    if (parsed.command !== CMD_CREATE) return null;

    const r = reassembler.ingest(parsed.payload);
    if (r === null) return null;
    if (!r.complete) return { complete: false };

    const response = relayResponse({ createMsg: r.message, B_sk, B_pk, ID_R });
    if (response === null) return null;

    const respHandshakeId = newHandshakeId();
    const fragments = fragmentMessage({
        message: response.createdMsg,
        handshakeId: respHandshakeId,
    });
    const createdCells = fragments.map((frag) => buildCell({
        circuitId: parsed.circuitId,
        command: CMD_CREATED,
        payload: frag,
    }));
    const hopKeys = deriveHopKeys(response.KEY_SEED);
    const relayHop = createRelayHop({
        inboundCircuitId: parsed.circuitId,
        hopKeys,
    });
    return {
        complete: true,
        createdCells,
        relayHop,
        handshakeId: respHandshakeId,
    };

};

// Client: ingest one CMD_CREATED cell. Returns:
//   { complete: true, hopKeys }    — derived; caller calls addHop
//   { complete: false }            — more cells expected
//   null                           — failure (DESTROY)
export const finishCreate = ({ cell, ntorState, B_pk, ID_R, reassembler }) => {

    const parsed = parseCell(cell);
    if (parsed === null) return null;
    if (parsed.command !== CMD_CREATED) return null;

    const r = reassembler.ingest(parsed.payload);
    if (r === null) return null;
    if (!r.complete) return { complete: false };

    const KEY_SEED = clientFinish({
        ntorState,
        B_pk,
        ID_R,
        createdMsg: r.message,
    });
    if (KEY_SEED === null) return null;
    return { complete: true, hopKeys: deriveHopKeys(KEY_SEED) };

};

// ----- Multi-cell RELAY_EXTEND / RELAY_EXTENDED -----

// Client: build RELAY_EXTEND cells to extend the circuit by one hop.
// Returns:
//   {
//     cells:        array of CMD_RELAY cells (each wrapping one RELAY_EXTEND
//                   fragment, layered-encrypted through the current circuit)
//     ntorState:    state needed to finish
//     handshakeId:  for caller logging
//   }
export const beginExtend = ({ circuit, nextHopFingerprint, nextHopBpk }) => {

    if (circuit.hops.length === 0) {

        throw new Error('cannot extend empty circuit; use beginCreate for the first hop');

    }
    if (nextHopFingerprint.length !== 32) throw new Error('nextHopFingerprint must be 32 bytes');
    if (nextHopBpk.length !== 32) throw new Error('nextHopBpk must be 32 bytes');

    const lastHop = circuit.hops[circuit.hops.length - 1];

    const ntorState = clientInit();
    const extendPayload = concat(nextHopFingerprint, nextHopBpk, ntorState.createMsg);
    const handshakeId = newHandshakeId();
    const fragments = fragmentMessage({
        message: extendPayload,
        handshakeId,
        payloadCapacity: RELAY_FRAGMENT_CAPACITY,
    });

    const cells = fragments.map((fragData) => {

        const relayPayload = buildRelayPayload({
            relayCommand: RELAY_EXTEND,
            streamId: STREAM_ID_CIRCUIT,
            data: fragData,
            digestState: lastHop.forwardDigest,
        });
        const ciphertext = encryptOutbound(circuit, relayPayload);
        return buildCell({
            circuitId: circuit.circuitId,
            command: CMD_RELAY,
            payload: ciphertext,
        });

    });

    return { cells, ntorState, handshakeId };

};

// Relay: process a RELAY cell that has arrived at this hop. Returns
// one of:
//   { kind: 'forward',         payload }                — cell is for a later hop; forward it
//   { kind: 'extend-fragment'}                          — accumulating; more cells expected
//   { kind: 'extend',          payload: { nextHopFingerprint, nextHopBpk, handshakeMessage } }
//                                                       — EXTEND payload fully reassembled
//   { kind: 'data', relayCommand, streamId, data }      — non-EXTEND RELAY for this hop
//   null                                                — structural failure (DESTROY)
export const handleRelayAtHop = ({ relayHop, cellPayload }) => {

    const peeled = relayPeelForward(relayHop, cellPayload);
    const result = tryConsumeRelayPayload(peeled, relayHop.forwardDigest);
    if (result === null) return null;
    if (!result.match) return { kind: 'forward', payload: peeled };

    const { relayCommand, streamId, data } = result.parsed;

    if (relayCommand === RELAY_EXTEND) {

        const r = relayHop.extendReassembler.ingest(data);
        if (r === null) return null;
        if (!r.complete) return { kind: 'extend-fragment' };
        if (r.message.length !== EXTEND_PAYLOAD_BYTES) return null;
        return {
            kind: 'extend',
            streamId,
            payload: {
                nextHopFingerprint: new Uint8Array(r.message.subarray(0, 32)),
                nextHopBpk:         new Uint8Array(r.message.subarray(32, 64)),
                handshakeMessage:   new Uint8Array(r.message.subarray(64, 64 + CREATE_MSG_BYTES)),
            },
        };

    }

    if (relayCommand === RELAY_EXTENDED) {

        // EXTENDED cells flow backward toward the client, not forward
        // through hops. Receipt of one in the forward direction is a
        // protocol error.
        return null;

    }

    return { kind: 'data', relayCommand, streamId, data };

};

// Relay (current exit): once the next-hop CREATE/CREATED handshake has
// completed and we have the 1152-byte hybrid CREATED response, build
// the RELAY_EXTENDED cells back to the client. Each fragment goes in a
// RELAY_EXTENDED cell whose RELAY payload is constructed against THIS
// hop's backward digest state; the cell is then layered-encrypted via
// relayWrapBackward at this hop. Earlier hops (closer to the client)
// will each add their own backward layer as the cell traverses back.
//
// Returns an array of RELAY-cell payloads (NOT full cells — the caller
// wraps the outer CMD_RELAY cell on whichever transport carries
// hop-to-hop traffic).
export const buildExtendedRelayCells = ({ relayHop, handshakeResponse }) => {

    if (handshakeResponse.length !== CREATED_MSG_BYTES) {

        throw new Error(`handshakeResponse must be ${CREATED_MSG_BYTES} bytes`);

    }

    const handshakeId = newHandshakeId();
    const fragments = fragmentMessage({
        message: handshakeResponse,
        handshakeId,
        payloadCapacity: RELAY_FRAGMENT_CAPACITY,
    });

    return fragments.map((fragData) => {

        const relayPayload = buildRelayPayload({
            relayCommand: RELAY_EXTENDED,
            streamId: STREAM_ID_CIRCUIT,
            data: fragData,
            digestState: relayHop.backwardDigest,
        });
        return relayWrapBackward(relayHop, relayPayload);

    });

};

// Client: process an inbound RELAY cell. The 508-byte payload has
// already been peeled through all N backward layers via decryptInbound.
// Try each hop's backward digest to find which hop originated the cell.
//
// Returns:
//   { kind: 'extend-fragment', hopIndex }      — accumulating; more cells expected
//   { kind: 'extended',        hopIndex,
//                              handshakeResponse }  — RELAY_EXTENDED fully reassembled
//   { kind: 'data', hopIndex, relayCommand,
//                   streamId, data }            — non-EXTENDED RELAY cell
//   null                                        — no hop matched the digest
export const dispatchInboundRelay = ({ circuit, peeledPayload }) => {

    for (let i = 0; i < circuit.hops.length; i += 1) {

        const hop = circuit.hops[i];
        const r = tryConsumeRelayPayload(peeledPayload, hop.backwardDigest);
        if (r === null) return null;
        if (!r.match) continue;

        const { relayCommand, streamId, data } = r.parsed;

        if (relayCommand === RELAY_EXTENDED) {

            const f = hop.extendedReassembler.ingest(data);
            if (f === null) return null;
            if (!f.complete) return { kind: 'extend-fragment', hopIndex: i };
            if (f.message.length !== CREATED_MSG_BYTES) return null;
            return {
                kind: 'extended',
                hopIndex: i,
                handshakeResponse: new Uint8Array(f.message),
            };

        }

        return {
            kind: 'data',
            hopIndex: i,
            relayCommand,
            streamId,
            data,
        };

    }
    return null;

};

// Client: complete an EXTEND handshake using the reassembled hybrid
// CREATED response. Returns the new hop's session keys, or null.
export const finishExtend = ({ handshakeResponse, ntorState, nextHopBpk, nextHopFingerprint }) => {

    const KEY_SEED = clientFinish({
        ntorState,
        B_pk: nextHopBpk,
        ID_R: nextHopFingerprint,
        createdMsg: handshakeResponse,
    });
    if (KEY_SEED === null) return null;
    return deriveHopKeys(KEY_SEED);

};

export {
    CELL_BYTES,
    LEN_CELL_PAYLOAD,
    CREATE_MSG_BYTES,
    CREATED_MSG_BYTES,
    EXTEND_PAYLOAD_BYTES,
    RELAY_FRAGMENT_CAPACITY,
};
