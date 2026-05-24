// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE
//
// Reference v0.2 runtime, see docs/SPEC-v0.2-draft.md.
// The draft has open architectural questions; the code has not been
// audited. Do not rely on this for anonymity.

// Relay-side circuit dispatcher.
//
// The LinkManager (chunk 9.4a) hands every post-handshake cell to a
// single `onCell(link, cell)` callback. This module IS that callback's
// implementation — it routes cells to the right circuit state machine
// based on (link, circuit_id, command).
//
// State per circuit:
//   inbound  — { link, circuitId }  the side CREATE came from
//   outbound — { link, circuitId } | null  the side CREATE went to (after EXTEND)
//   relayHop — session keys + counters + digests for THIS hop's view
//   role     — 'pending-create' | 'established' | 'extending' | 'destroyed'
//
// Inbound forward cells (from client side):
//   CMD_CREATE     → accumulate fragments → derive keys → send CREATED
//   CMD_RELAY      → peel forward layer; dispatch by handleRelayAtHop:
//                       'forward'  → ship peeled bytes to outbound link
//                       'extend'   → dial next hop, send CREATE, await CREATED
//                       'data'     → call onExitData (RELAY_BEGIN/DATA/END at exit)
//   CMD_DESTROY    → tear down on both sides
//
// Outbound backward cells (from network side, after we extended):
//   CMD_CREATED    → accumulate fragments → send RELAY_EXTENDED on inbound
//   CMD_RELAY      → wrap with our backward layer → ship to inbound
//   CMD_DESTROY    → propagate to inbound, tear down

import { randomInt } from 'node:crypto';

import {
    CELL_BYTES,
    LEN_CELL_PAYLOAD,
    CMD_CREATE,
    CMD_CREATED,
    CMD_RELAY,
    CMD_DESTROY,
    buildCell,
    parseCell,
} from '../v2/cells.mjs';
import {
    handleCreate,
    handleRelayAtHop,
    buildExtendedRelayCells,
    createRelayHop,
    createHandshakeReassembler,
    relayWrapBackward,
    relayPeelForward,
} from '../v2/circuit.mjs';
import {
    fragmentMessage,
    createReassembler,
} from '../v2/fragment.mjs';
import {
    relayResponse,
    deriveHopKeys,
    CREATE_MSG_BYTES,
    CREATED_MSG_BYTES,
} from '../v2/ntor_hybrid.mjs';

const ROLE_PENDING    = 'pending-create';
const ROLE_ESTABLISHED = 'established';
const ROLE_EXTENDING  = 'extending';
const ROLE_DESTROYED  = 'destroyed';

const keyOf = (link, circuitId) => `${link.peerFingerprintHex}:${circuitId}`;

// Pick a fresh circuit_id on an outbound link, avoiding collision with
// any circuit we already have on that link. Collision probability is
// astronomical (32-bit random) but we still retry on the rare case.
const allocateOutboundCircuitId = (circuits, link) => {

    for (let attempt = 0; attempt < 16; attempt += 1) {

        const candidate = randomInt(1, 0x80000000); // avoid 0 (reserved for link cells)
        const probeKey = keyOf(link, candidate);
        if (!circuits.has(probeKey)) return candidate;

    }
    throw new Error('failed to allocate outbound circuit_id after 16 attempts');

};

export const createCircuitDispatcher = ({
    identity,
    linkManager,
    peerResolver = () => null,
    onExitData = () => {},
    logger = () => {},
}) => {

    // "linkFpHex:circuitId" → circuit
    const circuits = new Map();

    const destroyCircuit = (circuit, reason = 'normal') => {

        if (circuit.role === ROLE_DESTROYED) return;
        const wasRole = circuit.role;
        circuit.role = ROLE_DESTROYED;
        logger(`destroy circuit (was ${wasRole}, reason=${reason})`);
        if (circuit.inbound) {

            try {

                circuit.inbound.link.sendCell(buildCell({
                    circuitId: circuit.inbound.circuitId,
                    command: CMD_DESTROY,
                    payload: new Uint8Array(LEN_CELL_PAYLOAD),
                }));

            } catch { /* link may already be closed */ }
            circuits.delete(keyOf(circuit.inbound.link, circuit.inbound.circuitId));

        }
        if (circuit.outbound) {

            try {

                circuit.outbound.link.sendCell(buildCell({
                    circuitId: circuit.outbound.circuitId,
                    command: CMD_DESTROY,
                    payload: new Uint8Array(LEN_CELL_PAYLOAD),
                }));

            } catch { /* ignore */ }
            circuits.delete(keyOf(circuit.outbound.link, circuit.outbound.circuitId));

        }

    };

    // ----- Inbound CMD_CREATE -----

    const onInboundCreate = (link, cellBytes, parsed) => {

        const key = keyOf(link, parsed.circuitId);
        let circuit = circuits.get(key);
        if (circuit && circuit.role !== ROLE_PENDING) {

            // CREATE arriving on an already-established circuit is a
            // protocol error.
            destroyCircuit(circuit, 'create-on-established');
            return;

        }
        if (!circuit) {

            circuit = {
                inbound: { link, circuitId: parsed.circuitId },
                outbound: null,
                relayHop: null,
                role: ROLE_PENDING,
                createReassembler: createHandshakeReassembler(),
                createdReassembler: null,
                extendNtorState: null,
                pendingExtend: null,
            };
            circuits.set(key, circuit);

        }

        const result = handleCreate({
            cell: cellBytes,
            B_sk: identity.B_sk,
            B_pk: identity.B_pk,
            ID_R: identity.fingerprint,
            reassembler: circuit.createReassembler,
        });
        if (result === null) {

            destroyCircuit(circuit, 'create-failed');
            return;

        }
        if (!result.complete) return; // more fragments expected

        // Handshake complete. Register hop state, send CREATED cells back.
        circuit.relayHop = result.relayHop;
        circuit.createReassembler = null;
        circuit.role = ROLE_ESTABLISHED;
        for (const respCell of result.createdCells) {

            link.sendCell(respCell);

        }
        logger(`circuit established with peer ${link.peerFingerprintHex.slice(0, 16)}…  cid=${parsed.circuitId}`);

    };

    // ----- Inbound CMD_RELAY (forward direction) -----

    const onInboundRelay = (link, cellBytes, parsed) => {

        const key = keyOf(link, parsed.circuitId);
        const circuit = circuits.get(key);
        if (!circuit || circuit.role === ROLE_DESTROYED) {

            // No circuit — drop. Could send DESTROY back but spec § 9.x
            // calls for silent drops on unknown cells.
            return;

        }
        if (circuit.role === ROLE_PENDING) {

            // RELAY before CREATE finished — protocol error.
            destroyCircuit(circuit, 'relay-before-create');
            return;

        }

        // Forward direction. Peel + dispatch.
        const result = handleRelayAtHop({
            relayHop: circuit.relayHop,
            cellPayload: parsed.payload,
        });
        if (result === null) {

            destroyCircuit(circuit, 'relay-malformed');
            return;

        }

        if (result.kind === 'forward') {

            // Ship the peeled bytes to the outbound link, if any.
            if (!circuit.outbound) {

                // No outbound. If the circuit has been spliced (e.g.
                // by the RP role after a successful RENDEZVOUS1), let
                // the splice handler forward the cell to its partner
                // on the other half of the rendezvous. Otherwise drop.
                if (typeof circuit.spliceHandler === 'function') {

                    try { circuit.spliceHandler(result.payload); }
                    catch (err) { logger(`spliceHandler threw: ${err.message}`); }
                    return;

                }
                logger(`drop forward-bound cell on circuit without outbound`);
                return;

            }
            const outCell = buildCell({
                circuitId: circuit.outbound.circuitId,
                command: CMD_RELAY,
                payload: result.payload,
            });
            circuit.outbound.link.sendCell(outCell);
            return;

        }

        if (result.kind === 'extend-fragment') {

            // EXTEND fragments still accumulating; no action.
            return;

        }

        if (result.kind === 'extend') {

            beginExtend(circuit, result.payload);
            return;

        }

        if (result.kind === 'data') {

            // RELAY_BEGIN/DATA/END/etc. at exit. Defer to onExitData.
            try {

                onExitData({
                    circuit, link, circuitId: parsed.circuitId,
                    relayCommand: result.relayCommand,
                    streamId: result.streamId,
                    data: result.data,
                });

            } catch (err) {

                logger(`onExitData threw: ${err.message}`);

            }
            return;

        }

    };

    // ----- EXTEND: set up outbound link, send CREATE, await CREATED -----

    const beginExtend = async (circuit, extendPayload) => {

        if (circuit.outbound) {

            // Already extended; second EXTEND is a protocol error.
            destroyCircuit(circuit, 'duplicate-extend');
            return;

        }

        const nextHopFp = Buffer.from(extendPayload.nextHopFingerprint).toString('hex');
        const peerInfo = peerResolver({ fingerprint: extendPayload.nextHopFingerprint });
        if (!peerInfo || !peerInfo.host || !peerInfo.port || !peerInfo.idPk) {

            logger(`extend: peerResolver could not locate ${nextHopFp.slice(0, 16)}…`);
            destroyCircuit(circuit, 'extend-unknown-peer');
            return;

        }

        let outboundLink;
        try {

            outboundLink = await linkManager.ensureLink({
                peerIdPk: peerInfo.idPk,
                host: peerInfo.host,
                port: peerInfo.port,
            });

        } catch (err) {

            logger(`extend: dial to ${nextHopFp.slice(0, 16)}… failed: ${err.message}`);
            destroyCircuit(circuit, 'extend-dial-failed');
            return;

        }
        if (circuit.role === ROLE_DESTROYED) return;

        const outboundCircuitId = allocateOutboundCircuitId(circuits, outboundLink);
        circuit.outbound = { link: outboundLink, circuitId: outboundCircuitId };
        circuit.createdReassembler = createHandshakeReassembler();
        circuit.role = ROLE_EXTENDING;
        circuits.set(keyOf(outboundLink, outboundCircuitId), circuit);

        // Send the embedded handshake message to the next hop as
        // CMD_CREATE fragments on the outbound link.
        const handshakeId = randomInt(0, 0x100000000);
        const fragments = fragmentMessage({
            message: extendPayload.handshakeMessage,
            handshakeId,
        });
        for (const frag of fragments) {

            outboundLink.sendCell(buildCell({
                circuitId: outboundCircuitId,
                command: CMD_CREATE,
                payload: frag,
            }));

        }
        logger(`extend: sent CREATE to ${nextHopFp.slice(0, 16)}…  outbound-cid=${outboundCircuitId}`);

    };

    // ----- Outbound CMD_CREATED (we're extending, response is arriving) -----

    const onOutboundCreated = (link, cellBytes, parsed) => {

        const key = keyOf(link, parsed.circuitId);
        const circuit = circuits.get(key);
        if (!circuit || circuit.role !== ROLE_EXTENDING) {

            // Unexpected CREATED — drop.
            return;

        }

        const r = circuit.createdReassembler.ingest(parsed.payload);
        if (r === null) {

            destroyCircuit(circuit, 'extending-created-malformed');
            return;

        }
        if (!r.complete) return;

        // Assembled CREATED. Build RELAY_EXTENDED cells and send on inbound.
        if (r.message.length !== CREATED_MSG_BYTES) {

            destroyCircuit(circuit, 'extending-created-wrong-size');
            return;

        }

        const extendedRelayPayloads = buildExtendedRelayCells({
            relayHop: circuit.relayHop,
            handshakeResponse: r.message,
        });
        for (const payload of extendedRelayPayloads) {

            circuit.inbound.link.sendCell(buildCell({
                circuitId: circuit.inbound.circuitId,
                command: CMD_RELAY,
                payload,
            }));

        }
        circuit.createdReassembler = null;
        circuit.role = ROLE_ESTABLISHED;
        logger(`extend: completed; circuit now spans inbound + outbound`);

    };

    // ----- Outbound CMD_RELAY (backward direction from network) -----

    const onOutboundRelay = (link, cellBytes, parsed) => {

        const key = keyOf(link, parsed.circuitId);
        const circuit = circuits.get(key);
        if (!circuit || circuit.role === ROLE_DESTROYED) return;
        if (!circuit.outbound || circuit.outbound.link !== link) {

            // Unexpected RELAY on outbound side — drop.
            return;

        }

        // Wrap with our backward layer and forward to inbound.
        const wrapped = relayWrapBackward(circuit.relayHop, parsed.payload);
        const outCell = buildCell({
            circuitId: circuit.inbound.circuitId,
            command: CMD_RELAY,
            payload: wrapped,
        });
        circuit.inbound.link.sendCell(outCell);

    };

    // ----- DESTROY (from either side) -----

    const onDestroy = (link, parsed) => {

        const key = keyOf(link, parsed.circuitId);
        const circuit = circuits.get(key);
        if (!circuit) return;
        // Propagate to the OTHER side, then drop state.
        const otherSide = (circuit.inbound.link === link
            && circuit.inbound.circuitId === parsed.circuitId)
            ? circuit.outbound : circuit.inbound;
        if (otherSide) {

            try {

                otherSide.link.sendCell(buildCell({
                    circuitId: otherSide.circuitId,
                    command: CMD_DESTROY,
                    payload: new Uint8Array(LEN_CELL_PAYLOAD),
                }));

            } catch { /* ignore */ }

        }
        circuit.role = ROLE_DESTROYED;
        if (circuit.inbound) circuits.delete(keyOf(circuit.inbound.link, circuit.inbound.circuitId));
        if (circuit.outbound) circuits.delete(keyOf(circuit.outbound.link, circuit.outbound.circuitId));
        logger(`circuit destroyed by peer ${link.peerFingerprintHex.slice(0, 16)}…`);

    };

    // ----- Top-level dispatch -----

    const onCell = (link, cellBytes) => {

        if (!cellBytes || cellBytes.length !== CELL_BYTES) return;
        const parsed = parseCell(cellBytes);
        if (parsed === null) return;

        // Direction is determined by which side of the circuit this
        // link is on. We look up the circuit by both possible keys.
        const key = keyOf(link, parsed.circuitId);
        const circuit = circuits.get(key);
        const isInboundSide = circuit
            && circuit.inbound.link === link
            && circuit.inbound.circuitId === parsed.circuitId;
        const isOutboundSide = circuit
            && circuit.outbound
            && circuit.outbound.link === link
            && circuit.outbound.circuitId === parsed.circuitId;

        switch (parsed.command) {

            case CMD_CREATE:
                // CREATE only arrives on the inbound side from the
                // perspective of THIS relay (the relay that's terminating
                // it). If circuit doesn't exist yet, isInboundSide is
                // false but that's the normal initial state for a fresh
                // circuit.
                if (circuit && !isInboundSide) {

                    // CREATE arrived on the outbound side of a circuit
                    // — protocol error.
                    destroyCircuit(circuit, 'create-on-outbound');
                    return;

                }
                onInboundCreate(link, cellBytes, parsed);
                return;

            case CMD_CREATED:
                if (isOutboundSide) {

                    onOutboundCreated(link, cellBytes, parsed);
                    return;

                }
                // CREATED received on inbound side — we're not the
                // initiator; drop.
                return;

            case CMD_RELAY:
                if (isOutboundSide) {

                    onOutboundRelay(link, cellBytes, parsed);
                    return;

                }
                if (isInboundSide) {

                    onInboundRelay(link, cellBytes, parsed);
                    return;

                }
                // RELAY on a circuit we don't have — drop.
                return;

            case CMD_DESTROY:
                if (circuit) onDestroy(link, parsed);
                return;

            case 0x00: // CMD_PADDING — drop
                return;

            default:
                // Unknown / link cell on a non-link path — drop.
                return;

        }

    };

    const getCircuitCount = () => circuits.size;

    const closeAll = () => {

        for (const c of circuits.values()) {

            if (c.role !== ROLE_DESTROYED) destroyCircuit(c, 'shutdown');

        }
        circuits.clear();

    };

    return {
        onCell,
        getCircuitCount,
        closeAll,
        // Exposed for tests/inspection.
        _circuits: circuits,
    };

};
