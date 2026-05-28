// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE
//
// Reference v0.2 runtime, see docs/SPEC-v0.2-draft.md.

// Client-side rendezvous orchestration. `openHiddenService` builds
// two circuits, performs the rendezvous handshake, and returns an
// object with a stream interface.
//
// State machine:
//   1. Build a 3-hop circuit to the RP. Send ESTABLISH_RENDEZVOUS with
//      a random 20-byte cookie. Await RENDEZVOUS_ESTABLISHED.
//   2. Build a 3-hop circuit to the IP. Send INTRODUCE1 (fragmented).
//      Await INTRODUCE_ACK on the IP circuit.
//   3. Await RENDEZVOUS2 fragments on the RP circuit. Reassemble.
//   4. Finish hybrid ntor. Add the e2e virtual hop to the client's RP
//      circuit (no swap — client is the originator of the virtual hop).
//   5. Return a connection object. openStream() multiplexes streams on
//      the now-4-hop client RP circuit (which is end-to-end the
//      spliced 7-relay rendezvous circuit).

import { randomInt, randomBytes } from 'node:crypto';

import {
    CMD_RELAY,
    LEN_CELL_PAYLOAD,
    buildCell,
} from '../v2/cells.mjs';
import {
    RELAY_ESTABLISH_RENDEZVOUS,
    RELAY_RENDEZVOUS_ESTABLISHED,
    RELAY_RENDEZVOUS2,
    RELAY_INTRODUCE1,
    RELAY_INTRODUCE_ACK,
    MAX_RELAY_DATA,
    buildRelayPayload,
} from '../v2/relay.mjs';
import {
    addHop,
    encryptOutbound,
} from '../v2/circuit.mjs';
import {
    fragmentMessage,
    createReassembler,
    LEN_FRAGMENT_HEADER,
} from '../v2/fragment.mjs';
import {
    clientInit,
    clientFinish,
    deriveHopKeys,
} from '../v2/ntor_hybrid.mjs';
import {
    buildEstablishRendezvous,
    buildIntroducePayload,
    parseRendezvous2,
    LEN_RENDEZVOUS_COOKIE,
} from '../v2/rendezvous.mjs';
import { createClientStreams } from './streams.mjs';

const RELAY_FRAGMENT_CAPACITY = MAX_RELAY_DATA - LEN_FRAGMENT_HEADER;

const sendForward = ({ circuit, entryLink, relayCommand, streamId, data }) => {

    const exitHop = circuit.hops[circuit.hops.length - 1];
    const relayPayload = buildRelayPayload({
        relayCommand, streamId, data,
        digestState: exitHop.forwardDigest,
    });
    const cipher = encryptOutbound(circuit, relayPayload);
    entryLink.sendCell(buildCell({
        circuitId: circuit.circuitId,
        command: CMD_RELAY,
        payload: cipher,
    }));

};

export const openHiddenService = async ({
    descriptor,                  // parsed descriptor (modules/v2/descriptor.mjs)
    SVC_pk,                      // also in descriptor.SVC_pk; passed explicitly for clarity
    consensus,
    rpPathFn,                    // ({ rpRse }) → 3-hop path with rpRse as exit
    ipPathFn,                    // ({ ipFingerprint }) → 3-hop path with ipRse as exit
    circuitBuilder,
    logger = () => {},
    handshakeTimeoutMs = 30000,
}) => {

    if (!descriptor.introPoints || descriptor.introPoints.length === 0) {

        throw new Error('descriptor has no intro points');

    }

    // Pick an IP (first one for simplicity).
    const ipRecord = descriptor.introPoints[0];
    const findRseByFp = (fp) => consensus.rses.find(
        (r) => Buffer.from(r.fingerprint).equals(Buffer.from(fp)),
    );

    const ipRse = findRseByFp(ipRecord.fingerprint);
    if (!ipRse) throw new Error('IP fingerprint not in consensus');

    // Pick an RP: any RUNNING+VALID relay that isn't the IP and isn't
    // in the IP's path. For simplicity, pick the first eligible.
    const rpRse = consensus.rses.find(
        (r) => !Buffer.from(r.fingerprint).equals(Buffer.from(ipRecord.fingerprint))
            && (r.flags & 0x06) === 0x06, // RUNNING + VALID
    );
    if (!rpRse) throw new Error('no RP candidate in consensus');

    // -------- Step 1: RP circuit + ESTABLISH_RENDEZVOUS --------

    const cookie = randomBytes(LEN_RENDEZVOUS_COOKIE);
    let rendezvousEstablishedResolve = null;
    let rendezvous2Resolve = null;
    const rendezvous2Reassembler = createReassembler();

    const handleRpCircuitData = (dispatched) => {

        switch (dispatched.relayCommand) {

            case RELAY_RENDEZVOUS_ESTABLISHED:
                if (rendezvousEstablishedResolve) {

                    const r = rendezvousEstablishedResolve;
                    rendezvousEstablishedResolve = null;
                    r(dispatched.data.length > 0 ? dispatched.data[0] : null);

                }
                return;
            case RELAY_RENDEZVOUS2: {

                const r = rendezvous2Reassembler.ingest(dispatched.data);
                if (r === null) {

                    logger('RENDEZVOUS2: bad fragment');
                    return;

                }
                if (!r.complete) return;
                if (rendezvous2Resolve) {

                    const resolveFn = rendezvous2Resolve;
                    rendezvous2Resolve = null;
                    resolveFn(r.message);

                }
                return;

            }
            default:
                // Post-rendezvous data cells (RELAY_BEGIN responses etc.)
                // go through the streams object once it's installed.
                if (streamsRef.streams) streamsRef.streams.handleInboundRelay(dispatched);
                return;

        }

    };

    // Retry buildCircuit on transient hop-failures. The dominant
    // failure mode in v0.x is a peer mid-handshake DESTROY (e.g. when
    // a single relay in a 3-relay testnet rejects EXTEND because of
    // its own path-diversity rules). Each retry calls the path-picker
    // fresh, so a different middle/exit is likely to be tried.
    //
    // Transient = anything thrown by handler.beginCreate/beginExtend
    // mid-build: peer DESTROY, EXTENDED AUTH fail, hop timeout. A
    // higher-level error (e.g. "path must include guard/middle/exit"
    // — bad input) won't get fixed by retrying, but those are caught
    // separately by the path-picker before we ever get here.
    const RETRY_LIMIT = 4;
    const isTransientBuildError = (err) => {
        const m = err && err.message;
        if (!m) return false;
        return /peer sent DESTROY|EXTENDED AUTH did not verify|hop \d+ (CREATE|EXTEND) timeout/i
            .test(m);
    };
    const buildWithRetry = async ({ pickPath, onData, label }) => {
        let lastErr;
        for (let attempt = 0; attempt < RETRY_LIMIT; attempt++) {
            try {
                return await circuitBuilder.buildCircuit({
                    path: pickPath(),
                    onData,
                });
            } catch (err) {
                lastErr = err;
                if (!isTransientBuildError(err)) throw err;
                logger(`${label} attempt ${attempt + 1}/${RETRY_LIMIT} failed: `
                    + `${err.message} — retrying with a fresh path`);
            }
        }
        throw lastErr;
    };

    const streamsRef = { streams: null };
    const rpBuilt = await buildWithRetry({
        pickPath: () => rpPathFn({ rpRse }),
        onData: handleRpCircuitData,
        label: 'RP circuit',
    });
    logger('client RP circuit built');

    const rendezvousEstablishedStatus = await new Promise((resolve, reject) => {

        rendezvousEstablishedResolve = resolve;
        sendForward({
            circuit: rpBuilt.circuit, entryLink: rpBuilt.entryLink,
            relayCommand: RELAY_ESTABLISH_RENDEZVOUS,
            streamId: 0,
            data: buildEstablishRendezvous(cookie),
        });
        setTimeout(() => reject(new Error('RENDEZVOUS_ESTABLISHED timeout')), handshakeTimeoutMs);

    });
    if (rendezvousEstablishedStatus !== 0x00) {

        throw new Error(`RENDEZVOUS_ESTABLISHED returned status=0x${rendezvousEstablishedStatus.toString(16)}`);

    }
    logger('ESTABLISH_RENDEZVOUS confirmed');

    // -------- Step 2: IP circuit + INTRODUCE1 --------

    let introduceAckResolve = null;
    const handleIpCircuitData = (dispatched) => {

        if (dispatched.relayCommand === RELAY_INTRODUCE_ACK) {

            if (introduceAckResolve) {

                const r = introduceAckResolve;
                introduceAckResolve = null;
                r(dispatched.data.length > 0 ? dispatched.data[0] : null);

            }

        }

    };
    const ipBuilt = await buildWithRetry({
        pickPath: () => ipPathFn({ ipFingerprint: ipRecord.fingerprint }),
        onData: handleIpCircuitData,
        label: 'IP circuit',
    });
    logger('client IP circuit built');

    // Build the hybrid ntor CREATE message for the rendezvous handshake.
    const ntorState = clientInit();

    const introducePayload = buildIntroducePayload({
        serviceIntroPk: ipRecord.serviceIntroKey,
        serviceEncX25519Pk: ipRecord.serviceEncX25519Pk,
        serviceEncMlkemPk: ipRecord.serviceEncMlkemPk,
        cookie,
        rpFingerprint: rpRse.fingerprint,
        rpOnionPk: rpRse.onionPk,
        handshakeMessage: ntorState.createMsg,
    });
    // Fragment INTRODUCE1 across RELAY cells.
    const introduceHandshakeId = randomInt(0, 0x100000000);
    const introduceFragments = fragmentMessage({
        message: introducePayload,
        handshakeId: introduceHandshakeId,
        payloadCapacity: RELAY_FRAGMENT_CAPACITY,
    });
    const ackPromise = new Promise((resolve, reject) => {

        introduceAckResolve = resolve;
        setTimeout(() => reject(new Error('INTRODUCE_ACK timeout')), handshakeTimeoutMs);

    });
    for (const fragData of introduceFragments) {

        sendForward({
            circuit: ipBuilt.circuit, entryLink: ipBuilt.entryLink,
            relayCommand: RELAY_INTRODUCE1,
            streamId: 0,
            data: fragData,
        });

    }
    const ackStatus = await ackPromise;
    if (ackStatus !== 0x00) {

        throw new Error(`INTRODUCE_ACK returned status=0x${ackStatus.toString(16)}`);

    }
    logger('INTRODUCE1 acked by IP');

    // -------- Step 3: await RENDEZVOUS2 + finish handshake --------

    const rendezvous2Bytes = await new Promise((resolve, reject) => {

        rendezvous2Resolve = resolve;
        setTimeout(() => reject(new Error('RENDEZVOUS2 timeout')), handshakeTimeoutMs);

    });
    const r2 = parseRendezvous2(rendezvous2Bytes);
    if (r2 === null) throw new Error('RENDEZVOUS2 parse failed');

    const KEY_SEED = clientFinish({
        ntorState,
        B_pk: ipRecord.serviceEncX25519Pk,
        ID_R: SVC_pk || descriptor.SVC_pk_ed || descriptor.SVC_pk,
        createdMsg: r2.handshakeResponse,
    });
    if (KEY_SEED === null) {

        throw new Error('rendezvous handshake AUTH did not verify');

    }
    const e2eKeys = deriveHopKeys(KEY_SEED);
    addHop(rpBuilt.circuit, e2eKeys); // client side: no Kf/Kb swap
    logger('rendezvous handshake complete; circuit is now 4-hop e2e');

    // -------- Step 4: install streams object --------

    streamsRef.streams = createClientStreams({
        circuit: rpBuilt.circuit, entryLink: rpBuilt.entryLink,
    });

    // Helper: open a stream to the service. For hidden services the
    // destination address bytes are ignored by the service (it has a
    // pinned local target), so we use a placeholder.
    const openStream = ({ port = 80 } = {}) => streamsRef.streams.openStream({
        destination: {
            addrType: 0x01,
            addr: new Uint8Array([127, 0, 0, 1]),
            port,
        },
    });

    return {
        openStream,
        close: () => {

            try { streamsRef.streams && streamsRef.streams.closeAll(); } catch { /* ignore */ }
            // Cleanup of the actual circuits is the caller's responsibility
            // via their circuit_builder / link_manager.

        },
    };

};
