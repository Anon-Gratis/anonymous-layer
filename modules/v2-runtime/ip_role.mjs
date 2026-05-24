// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE
//
// Reference v0.2 runtime, see docs/SPEC-v0.2-draft.md.

// Introduction-point role for relays.
//
// State machine:
//   1. Service builds a long-lived 3-hop circuit terminating at this
//      relay. Sends RELAY_ESTABLISH_INTRO with its service_intro_pubkey
//      + a signature over (context || ip_fingerprint || publish_epoch).
//   2. IP verifies the signature against ip_fingerprint (this IP's own
//      fingerprint). On success, stores (service_intro_pubkey →
//      service_circuit) and sends RELAY_INTRO_ESTABLISHED with status=OK.
//   3. Eventually, a client sends RELAY_INTRODUCE1 to the IP via its
//      own 3-hop circuit. Cell carries:
//        - service_intro_pubkey (32 bytes, plaintext)
//        - sealed envelope (encrypted to the service's per-IP enc key)
//      INTRODUCE1's full payload is ~2480 bytes, fragmented across ~5
//      RELAY cells using § 6.2.1 fragmentation header in RELAY data.
//   4. IP reassembles, looks up the service_intro_pubkey, and forwards
//      the (intact) payload as RELAY_INTRODUCE2 cells on the service's
//      circuit (backward direction). The IP does NOT touch the sealed
//      envelope.
//   5. IP sends RELAY_INTRODUCE_ACK to the client.

import { randomInt } from 'node:crypto';

import {
    CMD_RELAY,
    LEN_CELL_PAYLOAD,
    buildCell,
} from '../v2/cells.mjs';
import {
    RELAY_INTRO_ESTABLISHED,
    RELAY_INTRODUCE2,
    RELAY_INTRODUCE_ACK,
    MAX_RELAY_DATA,
    buildRelayPayload,
} from '../v2/relay.mjs';
import {
    relayWrapBackward,
} from '../v2/circuit.mjs';
import {
    fragmentMessage,
    createReassembler,
    LEN_FRAGMENT_HEADER,
} from '../v2/fragment.mjs';
import {
    parseAndVerifyEstablishIntro,
    parseIntroduceEnvelope,
    buildIntroEstablished,
    buildIntroduceAck,
    INTRO_ESTABLISHED_STATUS_OK,
    INTRO_ESTABLISHED_STATUS_BAD_SIGNATURE,
    INTRODUCE_ACK_STATUS_FORWARDED,
    INTRODUCE_ACK_STATUS_UNKNOWN_SVC,
} from '../v2/rendezvous.mjs';

const RELAY_FRAGMENT_CAPACITY = MAX_RELAY_DATA - LEN_FRAGMENT_HEADER; // 491

const introKey = (svcIntroPk) => Buffer.from(svcIntroPk).toString('hex');

// Helper: send a backward RELAY cell from this hop on `circuit`.
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

// Forward fragmented INTRODUCE2 cells to the service's circuit.
// `payload` is the full (serviceIntroPk || sealedEnvelope) bytes.
// Backward direction at this IP on the service's circuit.
const forwardIntroduce2 = ({ serviceCircuit, payload }) => {

    const handshakeId = randomInt(0, 0x100000000);
    const fragments = fragmentMessage({
        message: payload,
        handshakeId,
        payloadCapacity: RELAY_FRAGMENT_CAPACITY,
    });
    for (const fragData of fragments) {

        sendBackwardOnCircuit({
            circuit: serviceCircuit,
            relayCommand: RELAY_INTRODUCE2,
            streamId: 0, // circuit-level control
            data: fragData,
        });

    }

};

export const createIpRole = ({
    identity, // this relay's identity (we need our fingerprint for ESTABLISH_INTRO verify)
    logger = () => {},
    now = () => Math.floor(Date.now() / 1000),
} = {}) => {

    // service_intro_pubkey-hex → { serviceCircuit, registeredAt }
    const services = new Map();

    // Per (client circuit + stream_id) state for accumulating
    // INTRODUCE1 fragments. Key: linkFp:cid:streamId.
    const introduceReassemblers = new Map();

    const handleEstablishIntro = ({ circuit, streamId, data }) => {

        const ipFingerprint = identity.fingerprint;
        const parsed = parseAndVerifyEstablishIntro({
            payload: data,
            ipFingerprint,
            nowEpoch: now(),
        });
        if (parsed === null) {

            sendBackwardOnCircuit({
                circuit, relayCommand: RELAY_INTRO_ESTABLISHED, streamId,
                data: buildIntroEstablished(INTRO_ESTABLISHED_STATUS_BAD_SIGNATURE),
            });
            logger('ESTABLISH_INTRO: signature/format invalid');
            return;

        }
        const key = introKey(parsed.serviceIntroPk);
        services.set(key, { serviceCircuit: circuit, registeredAt: now() });
        sendBackwardOnCircuit({
            circuit, relayCommand: RELAY_INTRO_ESTABLISHED, streamId,
            data: buildIntroEstablished(INTRO_ESTABLISHED_STATUS_OK),
        });
        logger(`ESTABLISH_INTRO: registered service ${key.slice(0, 16)}…`);

    };

    const handleIntroduce1 = ({ circuit, streamId, data }) => {

        // INTRODUCE1 is fragmented (§ 9.5.5 references § 6.2.1).
        // The fragment header lives in the RELAY data field.
        const reasmKey = `${circuit.inbound.link.peerFingerprintHex}:${circuit.inbound.circuitId}:${streamId}`;
        let reasm = introduceReassemblers.get(reasmKey);
        if (!reasm) {

            reasm = createReassembler();
            introduceReassemblers.set(reasmKey, reasm);

        }
        const result = reasm.ingest(data);
        if (result === null) {

            // Malformed fragment; drop reassembler.
            introduceReassemblers.delete(reasmKey);
            logger('INTRODUCE1: malformed fragment');
            return;

        }
        if (!result.complete) return; // more fragments expected

        // Reassembled INTRODUCE1 payload. Clean up the reassembler.
        introduceReassemblers.delete(reasmKey);

        const envelope = parseIntroduceEnvelope(result.message);
        if (envelope === null) {

            logger('INTRODUCE1: envelope parse failed');
            sendBackwardOnCircuit({
                circuit, relayCommand: RELAY_INTRODUCE_ACK, streamId,
                data: buildIntroduceAck(0x01 /* status: unknown svc */),
            });
            return;

        }
        const key = introKey(envelope.serviceIntroPk);
        const reg = services.get(key);
        if (!reg) {

            sendBackwardOnCircuit({
                circuit, relayCommand: RELAY_INTRODUCE_ACK, streamId,
                data: buildIntroduceAck(INTRODUCE_ACK_STATUS_UNKNOWN_SVC),
            });
            logger(`INTRODUCE1: unknown service ${key.slice(0, 16)}…`);
            return;

        }

        // Forward INTRODUCE2 to the service (fragmented).
        forwardIntroduce2({
            serviceCircuit: reg.serviceCircuit,
            payload: result.message,
        });

        // ACK the client.
        sendBackwardOnCircuit({
            circuit, relayCommand: RELAY_INTRODUCE_ACK, streamId,
            data: buildIntroduceAck(INTRODUCE_ACK_STATUS_FORWARDED),
        });
        logger(`INTRODUCE1: forwarded INTRODUCE2 to service ${key.slice(0, 16)}…`);

    };

    const handleData = (d) => {

        switch (d.relayCommand) {

            case 0x0E /* RELAY_ESTABLISH_INTRO */:
                return handleEstablishIntro(d);
            case 0x06 /* RELAY_INTRODUCE1 */:
                return handleIntroduce1(d);
            default:
                return; // not for the IP role

        }

    };

    const getServiceCount = () => services.size;
    const clear = () => { services.clear(); introduceReassemblers.clear(); };

    return { handleData, getServiceCount, clear };

};
