// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE
//
// Reference v0.2 runtime, see docs/SPEC-v0.2-draft.md.

// CircuitBuilder — constructs a fresh 3-hop circuit through a path
// supplied by `pickPath()` from the consensus.
//
// The build is a sequence of three handshakes:
//   1. Direct CREATE/CREATED with the entry guard (multi-cell hybrid ntor)
//   2. RELAY_EXTEND/EXTENDED to the middle relay (multi-cell)
//   3. RELAY_EXTEND/EXTENDED to the exit relay (multi-cell)
//
// Each step is async — fragments arrive interleaved with other cells
// on the entry-guard link. The CellRouter routes them to this
// builder's per-circuit handler.

import { randomInt } from 'node:crypto';

import {
    CMD_CREATED,
    CMD_RELAY,
    CMD_DESTROY,
    LEN_CELL_PAYLOAD,
    buildCell,
} from '../v2/cells.mjs';
import {
    createClientCircuit,
    addHop,
    beginCreate,
    beginExtend,
    createHandshakeReassembler,
    dispatchInboundRelay,
    decryptInbound,
} from '../v2/circuit.mjs';
import {
    clientFinish,
    deriveHopKeys,
} from '../v2/ntor_hybrid.mjs';
import {
    CLIENT_CIRCUIT_ID_MIN,
    CLIENT_CIRCUIT_ID_MAX,
} from './cell_router.mjs';

const allocateClientCircuitId = () =>
    randomInt(CLIENT_CIRCUIT_ID_MIN, CLIENT_CIRCUIT_ID_MAX + 1);

// Per-circuit handler. Holds the in-flight handshake state and
// the resolver callbacks that the CircuitBuilder is awaiting.
//
// Two flavors of in-flight operation:
//   - Direct CREATE: awaiting CMD_CREATED fragments
//   - RELAY_EXTEND: awaiting RELAY_EXTENDED fragments via dispatchInboundRelay
const createHandler = ({ circuit, onData, onDestroy, logger }) => {

    let state = 'idle'; // 'idle' | 'create' | 'extend' | 'closed'
    let createdReassembler = null;
    let pendingCreate = null;  // { ntorState, B_pk, ID_R, resolve, reject }
    let pendingExtend = null;  // { ntorState, B_pk, ID_R, resolve, reject }

    const failPending = (err) => {

        if (pendingCreate) {

            pendingCreate.reject(err);
            pendingCreate = null;
            createdReassembler = null;

        }
        if (pendingExtend) {

            pendingExtend.reject(err);
            pendingExtend = null;

        }

    };

    return {

        // Begin awaiting a direct CMD_CREATED.
        beginCreate: ({ ntorState, B_pk, ID_R }) => {

            if (state !== 'idle') throw new Error(`cannot beginCreate in state ${state}`);
            state = 'create';
            createdReassembler = createHandshakeReassembler();
            return new Promise((resolve, reject) => {

                pendingCreate = { ntorState, B_pk, ID_R, resolve, reject };

            });

        },

        // Begin awaiting a RELAY_EXTENDED at the LAST hop currently in
        // circuit.hops. The caller has already called beginExtend()
        // from circuit.mjs and sent the RELAY cells; this handler just
        // waits for the response.
        beginExtend: ({ ntorState, B_pk, ID_R }) => {

            if (state !== 'idle') throw new Error(`cannot beginExtend in state ${state}`);
            state = 'extend';
            return new Promise((resolve, reject) => {

                pendingExtend = { ntorState, B_pk, ID_R, resolve, reject };

            });

        },

        // CellRouter calls this for every inbound cell on this circuit.
        onCell: (cell, parsed) => {

            if (state === 'closed') return;

            switch (parsed.command) {

                case CMD_CREATED: {

                    if (state !== 'create') return;
                    const r = createdReassembler.ingest(parsed.payload);
                    if (r === null) {

                        state = 'closed';
                        failPending(new Error('CREATED reassembly failed'));
                        return;

                    }
                    if (!r.complete) return;
                    const KEY_SEED = clientFinish({
                        ntorState: pendingCreate.ntorState,
                        B_pk: pendingCreate.B_pk,
                        ID_R: pendingCreate.ID_R,
                        createdMsg: r.message,
                    });
                    if (KEY_SEED === null) {

                        state = 'closed';
                        failPending(new Error('CREATED AUTH did not verify'));
                        return;

                    }
                    const hopKeys = deriveHopKeys(KEY_SEED);
                    const { resolve } = pendingCreate;
                    pendingCreate = null;
                    createdReassembler = null;
                    state = 'idle';
                    resolve(hopKeys);
                    return;

                }

                case CMD_RELAY: {

                    // Peel all known backward layers and dispatch.
                    const peeled = decryptInbound(circuit, parsed.payload);
                    const d = dispatchInboundRelay({ circuit, peeledPayload: peeled });
                    if (d === null) return; // no hop matched; drop
                    if (d.kind === 'extend-fragment') return; // still accumulating
                    if (d.kind === 'extended') {

                        if (state !== 'extend' || !pendingExtend) return;
                        const KEY_SEED = clientFinish({
                            ntorState: pendingExtend.ntorState,
                            B_pk: pendingExtend.B_pk,
                            ID_R: pendingExtend.ID_R,
                            createdMsg: d.handshakeResponse,
                        });
                        if (KEY_SEED === null) {

                            state = 'closed';
                            failPending(new Error('EXTENDED AUTH did not verify'));
                            return;

                        }
                        const hopKeys = deriveHopKeys(KEY_SEED);
                        const { resolve } = pendingExtend;
                        pendingExtend = null;
                        state = 'idle';
                        resolve(hopKeys);
                        return;

                    }
                    if (d.kind === 'data') {

                        try { onData(d); } catch (err) { logger(`onData threw: ${err.message}`); }
                        return;

                    }
                    return;

                }

                case CMD_DESTROY: {

                    state = 'closed';
                    failPending(new Error('peer sent DESTROY during build'));
                    try { onDestroy('peer-destroy'); } catch { /* ignore */ }
                    return;

                }

                default:
                    return;

            }

        },

        close: () => {

            state = 'closed';
            failPending(new Error('circuit closed by caller'));

        },

    };

};

// CircuitBuilder factory. Returns:
//   buildCircuit({ path, onData, onDestroy }) → Promise<{ circuit, entryLink, circuitId }>
export const createCircuitBuilder = ({
    linkManager,
    cellRouter,
    peerResolver,
    handshakeTimeoutMs = 30000,
    logger = () => {},
}) => {

    const buildCircuit = async ({
        path, // { guard, middle, exit } RSEs from pickPath
        onData = () => {},
        onDestroy = () => {},
    }) => {

        if (!path || !path.guard || !path.middle || !path.exit) {

            throw new Error('path must include { guard, middle, exit }');

        }

        // Resolve entry guard's transport.
        const guardInfo = peerResolver({ fingerprint: path.guard.fingerprint });
        if (!guardInfo) throw new Error('guard not resolvable via consensus');

        // Open link to the entry guard (or reuse if exists).
        const entryLink = await linkManager.ensureLink({
            peerIdPk: guardInfo.idPk,
            host: guardInfo.host,
            port: guardInfo.port,
        });

        // Allocate a fresh client-side circuit_id; retry on collision
        // (which can only happen if many circuits share this entry guard).
        let circuitId = allocateClientCircuitId();
        const circuit = createClientCircuit({ circuitId });
        const handler = createHandler({ circuit, onData, onDestroy, logger });
        cellRouter.registerClientCircuit(entryLink, circuitId, handler);

        const cleanup = (err) => {

            cellRouter.unregisterClientCircuit(entryLink, circuitId);
            handler.close();
            // Send DESTROY courtesy notice (best-effort).
            try {

                entryLink.sendCell(buildCell({
                    circuitId, command: CMD_DESTROY,
                    payload: new Uint8Array(LEN_CELL_PAYLOAD),
                }));

            } catch { /* link may be dead */ }

        };

        try {

            // --- Hop 0: direct CREATE/CREATED with the entry guard ---
            const begin0 = beginCreate({ circuitId });
            const hop0Promise = handler.beginCreate({
                ntorState: begin0.ntorState,
                B_pk: guardInfo.B_pk,
                ID_R: path.guard.fingerprint,
            });
            for (const cell of begin0.cells) entryLink.sendCell(cell);
            const hop0Keys = await withTimeout(hop0Promise, handshakeTimeoutMs, 'hop 0 CREATE');
            addHop(circuit, hop0Keys);
            logger(`hop 0 keys derived (entry guard)`);

            // --- Hop 1: RELAY_EXTEND to middle ---
            const ext1 = beginExtend({
                circuit,
                nextHopFingerprint: path.middle.fingerprint,
                nextHopBpk: peerResolver({ fingerprint: path.middle.fingerprint }).B_pk,
            });
            const hop1Promise = handler.beginExtend({
                ntorState: ext1.ntorState,
                B_pk: peerResolver({ fingerprint: path.middle.fingerprint }).B_pk,
                ID_R: path.middle.fingerprint,
            });
            for (const cell of ext1.cells) entryLink.sendCell(cell);
            const hop1Keys = await withTimeout(hop1Promise, handshakeTimeoutMs, 'hop 1 EXTEND');
            addHop(circuit, hop1Keys);
            logger(`hop 1 keys derived (middle)`);

            // --- Hop 2: RELAY_EXTEND to exit ---
            const ext2 = beginExtend({
                circuit,
                nextHopFingerprint: path.exit.fingerprint,
                nextHopBpk: peerResolver({ fingerprint: path.exit.fingerprint }).B_pk,
            });
            const hop2Promise = handler.beginExtend({
                ntorState: ext2.ntorState,
                B_pk: peerResolver({ fingerprint: path.exit.fingerprint }).B_pk,
                ID_R: path.exit.fingerprint,
            });
            for (const cell of ext2.cells) entryLink.sendCell(cell);
            const hop2Keys = await withTimeout(hop2Promise, handshakeTimeoutMs, 'hop 2 EXTEND');
            addHop(circuit, hop2Keys);
            logger(`hop 2 keys derived (exit)`);

            return { circuit, entryLink, circuitId, handler };

        } catch (err) {

            cleanup(err);
            throw err;

        }

    };

    return { buildCircuit };

};

// Helper: race a promise against a timeout.
const withTimeout = (promise, ms, label) => new Promise((resolve, reject) => {

    let settled = false;
    const timer = setTimeout(() => {

        if (settled) return;
        settled = true;
        reject(new Error(`${label} timeout after ${ms}ms`));

    }, ms);
    promise.then(
        (v) => { if (settled) return; settled = true; clearTimeout(timer); resolve(v); },
        (e) => { if (settled) return; settled = true; clearTimeout(timer); reject(e); },
    );

});
