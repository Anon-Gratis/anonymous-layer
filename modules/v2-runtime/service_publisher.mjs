// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE
//
// Reference v0.2 runtime, see docs/SPEC-v0.2-draft.md.

// Service publisher — the service-side runtime for hidden services.
//
// Lifecycle:
//   1. start(): build a long-lived 3-hop circuit terminating at the
//      configured IP. Send ESTABLISH_INTRO. Await INTRO_ESTABLISHED.
//   2. Idle: wait for INTRODUCE2 to arrive on the IP circuit
//      (backward direction). Each INTRODUCE2 is fragmented; reassemble.
//   3. On INTRODUCE2: unseal the inner payload → cookie, RP info,
//      handshake message. Run hybrid ntor as the relay-side → produces
//      KEY_SEED + handshake response. Build a fresh 3-hop circuit to
//      the RP. Send RELAY_RENDEZVOUS1 (fragmented).
//   4. The RP splices. Subsequent cells arriving on the service's RP
//      circuit are forward-direction from the client (through the
//      virtual hop). After adding the virtual e2e hop with Kf/Kb
//      swapped, decryptInbound + dispatchInboundRelay pulls out RELAY
//      sub-commands (RELAY_BEGIN, RELAY_DATA, RELAY_END).
//   5. The service handles RELAY_BEGIN by opening a TCP connection
//      to its configured local destination and bridging bytes.

import { randomInt, randomBytes } from 'node:crypto';
import { createConnection } from 'node:net';

import {
    CMD_RELAY,
    LEN_CELL_PAYLOAD,
    buildCell,
} from '../v2/cells.mjs';
import {
    RELAY_ESTABLISH_INTRO,
    RELAY_INTRO_ESTABLISHED,
    RELAY_INTRODUCE2,
    RELAY_RENDEZVOUS1,
    RELAY_BEGIN,
    RELAY_DATA,
    RELAY_END,
    RELAY_CONNECTED,
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
    relayResponse,
    deriveHopKeys,
} from '../v2/ntor_hybrid.mjs';
import {
    buildEstablishIntro,
    buildRendezvous1,
    parseIntroduceEnvelope,
    unsealIntroduceInner,
    LEN_RENDEZVOUS_COOKIE,
} from '../v2/rendezvous.mjs';
import {
    buildConnectedPayload,
    buildEndPayload,
    CONNECTED_STATUS_OK,
    END_REASON_REFUSED,
    END_REASON_REMOTE_CLOSED,
} from './stream_payloads.mjs';

const RELAY_FRAGMENT_CAPACITY = MAX_RELAY_DATA - LEN_FRAGMENT_HEADER;

const now = () => Math.floor(Date.now() / 1000);

// Send a forward RELAY cell through `circuit` via `entryLink`.
// The circuit's last hop is the "destination" of this forward cell.
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

export const createServicePublisher = ({
    SVC_pk,                         // for ID_R in the rendezvous ntor
    introductionPoint,              // { fingerprint, ipOnionPk, ipIdPk,
                                    //   serviceIntroSk, serviceIntroPk,
                                    //   serviceEncX25519Sk, serviceEncX25519Pk,
                                    //   serviceEncMlkemSk, serviceEncMlkemPk }
    rpPath,                         // path picker that returns a 3-hop path for the service's RP circuit
                                    //   ({ rpRse }) → { guard, middle, exit }
    ipPath,                         // path picker for the service-to-IP circuit
                                    //   ({ ipFingerprint }) → { guard, middle, exit }
    consensus,
    peerResolver,
    linkManager,
    cellRouter,
    circuitBuilder,
    localDestination,               // { host, port } — where to forward RELAY_BEGIN streams
    logger = () => {},
}) => {

    let ipCircuit = null;             // long-lived service↔IP circuit
    let entryLinkForIp = null;        // the entry-guard transport for ipCircuit
    let introEstablishedResolve = null;
    const introduce2Reassemblers = new Map();
    // cookie-hex → { rpCircuit, entryLink, sockets }
    const activeRendezvous = new Map();
    // exit-side TCP sockets keyed by (rpCircuit, streamId) inside an active rendezvous

    const findRseByFp = (fp) => consensus.rses.find(
        (r) => Buffer.from(r.fingerprint).equals(Buffer.from(fp)),
    );

    // Handle protocol cells from the IP circuit.
    const handleIpCircuitData = (dispatched) => {

        switch (dispatched.relayCommand) {

            case RELAY_INTRO_ESTABLISHED:
                if (introEstablishedResolve) {

                    const r = introEstablishedResolve;
                    introEstablishedResolve = null;
                    r(dispatched.data.length > 0 ? dispatched.data[0] : null);

                }
                return;
            case RELAY_INTRODUCE2:
                return handleIntroduce2(dispatched);
            default:
                logger(`IP circuit: unexpected relayCommand=0x${dispatched.relayCommand.toString(16)}`);
                return;

        }

    };

    const handleIntroduce2 = ({ streamId, data }) => {

        const key = `s:${streamId}`;
        let reasm = introduce2Reassemblers.get(key);
        if (!reasm) {

            reasm = createReassembler();
            introduce2Reassemblers.set(key, reasm);

        }
        const r = reasm.ingest(data);
        if (r === null) {

            introduce2Reassemblers.delete(key);
            logger('INTRODUCE2: bad fragment');
            return;

        }
        if (!r.complete) return;
        introduce2Reassemblers.delete(key);

        // Parse outer envelope.
        const env = parseIntroduceEnvelope(r.message);
        if (env === null) {

            logger('INTRODUCE2: outer envelope parse failed');
            return;

        }
        // The service may register multiple intro keys; we only have one
        // here, so verify it matches what we registered.
        if (!Buffer.from(env.serviceIntroPk).equals(Buffer.from(introductionPoint.serviceIntroPk))) {

            logger('INTRODUCE2: serviceIntroPk mismatch — wrong service?');
            return;

        }

        // Unseal the inner payload.
        const inner = unsealIntroduceInner({
            sealedEnvelope: env.sealedEnvelope,
            serviceEncX25519Sk: introductionPoint.serviceEncX25519Sk,
            serviceEncMlkemSk: introductionPoint.serviceEncMlkemSk,
        });
        if (inner === null) {

            logger('INTRODUCE2: unseal failed');
            return;

        }

        beginRendezvous(inner).catch((err) => logger(`rendezvous failed: ${err.message}`));

    };

    const beginRendezvous = async ({ cookie, rpFingerprint, rpOnionPk, handshakeMessage }) => {

        // 1. Run hybrid ntor as the relay side. B_sk/B_pk are the
        //    service's per-IP enc X25519 keys (same key used for the
        //    sealed-box recipient; documented design choice).
        //    ID_R is the service's long-term SVC_pk.
        const response = relayResponse({
            createMsg: handshakeMessage,
            B_sk: introductionPoint.serviceEncX25519Sk,
            B_pk: introductionPoint.serviceEncX25519Pk,
            ID_R: SVC_pk,
        });
        if (response === null) throw new Error('relayResponse failed');

        const e2eKeys = deriveHopKeys(response.KEY_SEED);
        // For the SERVICE-side virtual hop, swap Kf/Kb (and Kdf/Kdb)
        // because the service is the "destination" of the virtual hop,
        // not the originator. The client encrypts outbound with their
        // virtual_service_hop.Kf = e2eKf; the service receives that as
        // the inner layer and peels with its virtual_client_hop.Kb,
        // which must also equal e2eKf for the layers to line up.
        const swappedE2e = {
            Kf: e2eKeys.Kb,
            Kb: e2eKeys.Kf,
            Kdf: e2eKeys.Kdb,
            Kdb: e2eKeys.Kdf,
        };

        // 2. Find the RP in the consensus.
        const rpRse = findRseByFp(rpFingerprint);
        if (!rpRse) throw new Error('RP fingerprint not in consensus');

        // 3. Build a 3-hop circuit ending at the RP.
        const path = rpPath({ rpRse });
        const cookieHex = Buffer.from(cookie).toString('hex');
        const built = await circuitBuilder.buildCircuit({
            path,
            onData: (d) => handleRendezvousCircuitData(cookieHex, d),
        });

        // 4. Send RELAY_RENDEZVOUS1 (fragmented).
        const rendezvous1Payload = buildRendezvous1({
            cookie, handshakeResponse: response.createdMsg,
        });
        const handshakeId = randomInt(0, 0x100000000);
        const fragments = fragmentMessage({
            message: rendezvous1Payload,
            handshakeId,
            payloadCapacity: RELAY_FRAGMENT_CAPACITY,
        });
        for (const fragData of fragments) {

            sendForward({
                circuit: built.circuit,
                entryLink: built.entryLink,
                relayCommand: RELAY_RENDEZVOUS1,
                streamId: 0,
                data: fragData,
            });

        }

        // 5. Add the e2e virtual hop (with swap) to the service's RP
        //    circuit so subsequent cells arriving here decrypt all the
        //    way down to the inner RELAY payload.
        addHop(built.circuit, swappedE2e);

        // 6. Stash for stream handling.
        const tcpSockets = new Map();
        activeRendezvous.set(cookieHex, {
            rpCircuit: built.circuit,
            entryLink: built.entryLink,
            tcpSockets,
        });

        logger(`rendezvous initiated for cookie ${cookieHex.slice(0, 16)}…`);

    };

    // Cells arriving on the service's RP circuit, AFTER the e2e virtual
    // hop has been added. The dispatcher peels all 4 layers and hands us
    // the inner RELAY data via dispatchInboundRelay (kind='data' on the
    // virtual hop).
    const handleRendezvousCircuitData = (cookieHex, dispatched) => {

        const entry = activeRendezvous.get(cookieHex);
        if (!entry) return;

        const { rpCircuit, entryLink, tcpSockets } = entry;
        const { relayCommand, streamId, data } = dispatched;

        const sendBack = (cmd, payload) => sendForward({
            circuit: rpCircuit,
            entryLink,
            relayCommand: cmd,
            streamId,
            data: payload,
        });

        if (relayCommand === RELAY_BEGIN) {

            // The destination address from RELAY_BEGIN is ignored; the
            // service has ONE pinned local destination.
            const sock = createConnection({
                host: localDestination.host, port: localDestination.port,
            });
            tcpSockets.set(streamId, sock);
            sock.on('connect', () => {

                sendBack(RELAY_CONNECTED, buildConnectedPayload({ status: CONNECTED_STATUS_OK }));

            });
            sock.on('data', (chunk) => {

                let off = 0;
                while (off < chunk.length) {

                    const len = Math.min(MAX_RELAY_DATA, chunk.length - off);
                    sendBack(RELAY_DATA, chunk.subarray(off, off + len));
                    off += len;

                }

            });
            sock.on('end', () => {

                sendBack(RELAY_END, buildEndPayload(END_REASON_REMOTE_CLOSED));
                tcpSockets.delete(streamId);

            });
            sock.on('error', (err) => {

                sendBack(RELAY_END, buildEndPayload(END_REASON_REFUSED));
                tcpSockets.delete(streamId);
                logger(`stream ${streamId}: TCP error to ${localDestination.host}:${localDestination.port}: ${err.code || err.message}`);

            });
            return;

        }
        if (relayCommand === RELAY_DATA) {

            const sock = tcpSockets.get(streamId);
            if (sock) try { sock.write(data); } catch { /* ignore */ }
            return;

        }
        if (relayCommand === RELAY_END) {

            const sock = tcpSockets.get(streamId);
            if (sock) {

                try { sock.end(); } catch { /* ignore */ }
                tcpSockets.delete(streamId);

            }
            return;

        }

    };

    const start = async () => {

        // Build the IP circuit (service → IP).
        const path = ipPath({ ipFingerprint: introductionPoint.fingerprint });
        const built = await circuitBuilder.buildCircuit({
            path,
            onData: handleIpCircuitData,
        });
        ipCircuit = built.circuit;
        entryLinkForIp = built.entryLink;

        // Send ESTABLISH_INTRO (single RELAY cell — 104 bytes).
        const payload = buildEstablishIntro({
            serviceIntroPk: introductionPoint.serviceIntroPk,
            serviceIntroSk: introductionPoint.serviceIntroSk,
            ipFingerprint: introductionPoint.fingerprint,
            publishEpoch: now(),
        });
        const introEstablished = new Promise((resolve, reject) => {

            introEstablishedResolve = resolve;
            setTimeout(() => reject(new Error('INTRO_ESTABLISHED timeout')), 15000);

        });
        sendForward({
            circuit: ipCircuit, entryLink: entryLinkForIp,
            relayCommand: RELAY_ESTABLISH_INTRO,
            streamId: 0,
            data: payload,
        });
        const status = await introEstablished;
        if (status !== 0x00 /* INTRO_ESTABLISHED_STATUS_OK */) {

            throw new Error(`ESTABLISH_INTRO rejected with status=0x${status.toString(16)}`);

        }
        logger(`service published at IP ${Buffer.from(introductionPoint.fingerprint).toString('hex').slice(0, 16)}…`);

    };

    const stop = () => {

        for (const { tcpSockets } of activeRendezvous.values()) {

            for (const sock of tcpSockets.values()) {

                try { sock.destroy(); } catch { /* ignore */ }

            }

        }
        activeRendezvous.clear();
        introduce2Reassemblers.clear();

    };

    return { start, stop };

};
