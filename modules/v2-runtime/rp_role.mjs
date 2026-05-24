// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE
//
// Reference v0.2 runtime, see docs/SPEC-v0.2-draft.md.

// Rendezvous-point role for relays.
//
// State machine:
//   1. Client sends RELAY_ESTABLISH_RENDEZVOUS to the RP via a 3-hop
//      circuit terminating at this relay.
//   2. RP stores (cookie → client_circuit) and sends back
//      RELAY_RENDEZVOUS_ESTABLISHED with status=OK (or collision).
//   3. Eventually, the service sends RELAY_RENDEZVOUS1 to the RP via
//      its own 3-hop circuit terminating at the same RP. The cell
//      carries (cookie, hybrid-ntor handshake response).
//   4. RP looks up the cookie. If found:
//        - install splice handlers on both circuits so future
//          opaque RELAY cells from one side get forwarded to the other
//        - send RELAY_RENDEZVOUS2 (handshake response only — no
//          cookie) to the client's circuit via backward direction
//
// After splice, the dispatcher's "forward at exit without outbound"
// path consults circuit.spliceHandler (set up here) to forward cells
// across the splice. The cells are end-to-end-encrypted (ntor-derived
// session keys between client and service); the RP and intermediate
// hops see only opaque bytes.

import { randomInt } from 'node:crypto';

import {
    CMD_RELAY,
    buildCell,
} from '../v2/cells.mjs';
import {
    RELAY_RENDEZVOUS2,
    RELAY_RENDEZVOUS_ESTABLISHED,
    MAX_RELAY_DATA,
    buildRelayPayload,
} from '../v2/relay.mjs';
import { relayWrapBackward } from '../v2/circuit.mjs';
import {
    fragmentMessage,
    createReassembler,
    LEN_FRAGMENT_HEADER,
} from '../v2/fragment.mjs';
import {
    parseEstablishRendezvous,
    parseRendezvous1,
    buildRendezvousEstablished,
    buildRendezvous2,
    RENDEZVOUS_ESTABLISHED_STATUS_OK,
    RENDEZVOUS_ESTABLISHED_STATUS_COLLISION,
} from '../v2/rendezvous.mjs';

const RELAY_FRAGMENT_CAPACITY = MAX_RELAY_DATA - LEN_FRAGMENT_HEADER;

// Helper: send a backward RELAY cell from this hop toward the client.
// `circuit` is the dispatcher's circuit object; `relayHop` is its
// relayHop (this hop's view of that circuit).
const sendBackwardOnCircuit = ({ circuit, relayCommand, streamId, data }) => {

    const relayPayload = buildRelayPayload({
        relayCommand, streamId, data,
        digestState: circuit.relayHop.backwardDigest,
    });
    const wrapped = relayWrapBackward(circuit.relayHop, relayPayload);
    circuit.inbound.link.sendCell(buildCell({
        circuitId: circuit.inbound.circuitId,
        command: CMD_RELAY,
        payload: wrapped,
    }));

};

// Splice two circuits at this RP. After this call, opaque RELAY cells
// arriving on either circuit's forward direction (i.e., not addressed
// to this hop) get forwarded to the partner circuit via the dispatcher's
// circuit.spliceHandler hook.
const spliceCircuits = (clientCircuit, serviceCircuit) => {

    clientCircuit.spliceHandler = (peeledPayload) => {

        // Cell came from the client side, peeled at this RP. Forward
        // backward on the service's circuit (toward the service).
        const wrapped = relayWrapBackward(serviceCircuit.relayHop, peeledPayload);
        serviceCircuit.inbound.link.sendCell(buildCell({
            circuitId: serviceCircuit.inbound.circuitId,
            command: CMD_RELAY,
            payload: wrapped,
        }));

    };
    serviceCircuit.spliceHandler = (peeledPayload) => {

        const wrapped = relayWrapBackward(clientCircuit.relayHop, peeledPayload);
        clientCircuit.inbound.link.sendCell(buildCell({
            circuitId: clientCircuit.inbound.circuitId,
            command: CMD_RELAY,
            payload: wrapped,
        }));

    };

};

const cookieKey = (bytes) => Buffer.from(bytes).toString('hex');

export const createRpRole = ({ logger = () => {} } = {}) => {

    // cookie-hex → { circuit, streamId }
    const cookies = new Map();
    // For inspection / tests.
    let spliceCount = 0;
    // Per (service-circuit, stream) RENDEZVOUS1 reassemblers
    // (the payload is 1172 bytes — fragmented across ~3 RELAY cells).
    // Keyed by linkFp:cid:streamId.
    const rendezvous1Reassemblers = new Map();
    const reasmKey = (circuit, streamId) =>
        `${circuit.inbound.link.peerFingerprintHex}:${circuit.inbound.circuitId}:${streamId}`;

    const handleEstablishRendezvous = ({ circuit, streamId, data }) => {

        const parsed = parseEstablishRendezvous(data);
        if (parsed === null) {

            logger('ESTABLISH_RENDEZVOUS: malformed');
            return;

        }
        const key = cookieKey(parsed.cookie);
        if (cookies.has(key)) {

            sendBackwardOnCircuit({
                circuit, relayCommand: RELAY_RENDEZVOUS_ESTABLISHED, streamId,
                data: buildRendezvousEstablished(RENDEZVOUS_ESTABLISHED_STATUS_COLLISION),
            });
            logger(`ESTABLISH_RENDEZVOUS: collision on cookie ${key.slice(0, 16)}…`);
            return;

        }
        cookies.set(key, { circuit, streamId });
        sendBackwardOnCircuit({
            circuit, relayCommand: RELAY_RENDEZVOUS_ESTABLISHED, streamId,
            data: buildRendezvousEstablished(RENDEZVOUS_ESTABLISHED_STATUS_OK),
        });
        logger(`ESTABLISH_RENDEZVOUS: stored cookie ${key.slice(0, 16)}…`);

    };

    const handleRendezvous1 = ({ circuit: serviceCircuit, streamId, data }) => {

        // RENDEZVOUS1 is 1172 bytes; fragmented per § 6.2.1.
        const key = reasmKey(serviceCircuit, streamId);
        let reasm = rendezvous1Reassemblers.get(key);
        if (!reasm) {

            reasm = createReassembler();
            rendezvous1Reassemblers.set(key, reasm);

        }
        const result = reasm.ingest(data);
        if (result === null) {

            rendezvous1Reassemblers.delete(key);
            logger('RENDEZVOUS1: malformed fragment');
            return;

        }
        if (!result.complete) return; // more fragments
        rendezvous1Reassemblers.delete(key);

        const parsed = parseRendezvous1(result.message);
        if (parsed === null) {

            logger('RENDEZVOUS1: assembled payload did not parse');
            return;

        }
        const cKey = cookieKey(parsed.cookie);
        const clientEntry = cookies.get(cKey);
        if (!clientEntry) {

            logger(`RENDEZVOUS1: no matching cookie ${cKey.slice(0, 16)}…`);
            return;

        }
        cookies.delete(cKey);
        spliceCircuits(clientEntry.circuit, serviceCircuit);
        spliceCount += 1;

        // RENDEZVOUS2 is 1152 bytes — needs fragmenting before sending
        // backward on the client's circuit.
        const respPayload = buildRendezvous2(parsed.handshakeResponse);
        const handshakeId = randomInt(0, 0x100000000);
        const respFragments = fragmentMessage({
            message: respPayload,
            handshakeId,
            payloadCapacity: RELAY_FRAGMENT_CAPACITY,
        });
        for (const fragData of respFragments) {

            sendBackwardOnCircuit({
                circuit: clientEntry.circuit,
                relayCommand: RELAY_RENDEZVOUS2,
                streamId: clientEntry.streamId,
                data: fragData,
            });

        }
        logger(`RENDEZVOUS1: spliced cookie ${cKey.slice(0, 16)}… → ${respFragments.length} RENDEZVOUS2 fragments sent`);

    };

    // Plug into the dispatcher's onExitData. Dispatch by relayCommand.
    const handleData = (d) => {

        switch (d.relayCommand) {

            case 0x10 /* RELAY_ESTABLISH_RENDEZVOUS */:
                return handleEstablishRendezvous(d);
            case 0x08 /* RELAY_RENDEZVOUS1 */:
                return handleRendezvous1(d);
            default:
                return; // not for the RP role

        }

    };

    const getCookieCount = () => cookies.size;
    const getSpliceCount = () => spliceCount;
    const clear = () => { cookies.clear(); };

    return { handleData, getCookieCount, getSpliceCount, clear };

};
