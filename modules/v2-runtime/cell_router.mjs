// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE
//
// Reference v0.2 runtime, see docs/SPEC-v0.2-draft.md.

// CellRouter — multiplexes incoming cells from the LinkManager between
// the relay-side dispatcher (which handles CREATE/EXTEND etc. *arriving*
// at this node acting as a relay) and client-side circuit handlers
// (which handle CREATED/RELAY_EXTENDED/data *coming back* for circuits
// this node initiated as a client).
//
// Conventions for v0.2 reference impl:
//   - Client-initiated circuits use circuit_id in [0x80000000, 0xFFFFFFFF].
//   - Relay-accepted circuits use circuit_id in [0x00000001, 0x7FFFFFFF].
//   - 0x00000000 is reserved for link cells (LINK_HELLO/LINK_AUTH).
//
// This prevents collisions on a link where both sides may initiate
// circuits (a bidirectional relay-to-relay link). Routing here uses
// the (link, circuit_id) key — client circuit handlers register at a
// specific (link, cid) and unregister on teardown.

import { parseCell } from '../v2/cells.mjs';

const keyOf = (link, circuitId) => `${link.peerFingerprintHex}:${circuitId}`;

export const CLIENT_CIRCUIT_ID_MIN = 0x80000000;
export const CLIENT_CIRCUIT_ID_MAX = 0xFFFFFFFF;
export const RELAY_CIRCUIT_ID_MIN  = 0x00000001;
export const RELAY_CIRCUIT_ID_MAX  = 0x7FFFFFFF;

export const isClientCircuitId = (cid) => cid >= CLIENT_CIRCUIT_ID_MIN && cid <= CLIENT_CIRCUIT_ID_MAX;

// `relayDispatcher`  — the relay-side dispatcher's onCell (CREATE etc.)
// Returns a router with:
//   onCell(link, cell)                          — entry point from LinkManager
//   registerClientCircuit(link, cid, handler)   — handler.onCell(cell, parsed)
//   unregisterClientCircuit(link, cid)
export const createCellRouter = ({ relayDispatcher }) => {

    // "linkFpHex:circuitId" → { onCell: (cell, parsed) => void }
    const clientCircuits = new Map();

    const onCell = (link, cell) => {

        const parsed = parseCell(cell);
        if (parsed === null) return;

        // Look up by exact (link, circuit_id).
        const handler = clientCircuits.get(keyOf(link, parsed.circuitId));
        if (handler) {

            try { handler.onCell(cell, parsed); } catch { /* swallow */ }
            return;

        }

        // Otherwise, hand to the relay dispatcher.
        try { relayDispatcher.onCell(link, cell); } catch { /* swallow */ }

    };

    const registerClientCircuit = (link, circuitId, handler) => {

        clientCircuits.set(keyOf(link, circuitId), handler);

    };

    const unregisterClientCircuit = (link, circuitId) => {

        clientCircuits.delete(keyOf(link, circuitId));

    };

    const getClientCircuitCount = () => clientCircuits.size;

    return {
        onCell,
        registerClientCircuit,
        unregisterClientCircuit,
        getClientCircuitCount,
    };

};
