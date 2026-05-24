// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE
//
// Reference v0.2 runtime, see docs/SPEC-v0.2-draft.md.

// Stream multiplexing — both client side (open RELAY_BEGIN, send/recv
// RELAY_DATA, RELAY_END) and exit side (accept RELAY_BEGIN, dial TCP,
// stream bytes both ways).
//
// What's deliberately NOT here (yet):
//   - SENDME flow control (SPEC § 7.5). Without it, a fast sender on
//     either side can fill the receiver's memory. v0.2 reference impl
//     relies on TCP backpressure on each leg of the circuit; a
//     follow-on chunk should add SENDME windows for production.
//   - Hostname resolution at the exit. Only IPv4 destinations are
//     accepted; hostname RELAY_BEGIN returns RELAY_END(resolve-fail).
//     DNS-resolution-at-exit is a leakage surface that deserves its
//     own design pass.

import { createConnection } from 'node:net';

import {
    CMD_RELAY,
    buildCell,
} from '../v2/cells.mjs';
import {
    RELAY_BEGIN,
    RELAY_DATA,
    RELAY_END,
    RELAY_CONNECTED,
    MAX_RELAY_DATA,
    buildRelayPayload,
} from '../v2/relay.mjs';
import {
    encryptOutbound,
    relayWrapBackward,
} from '../v2/circuit.mjs';
import {
    ADDR_TYPE_IPV4,
    ADDR_TYPE_HOSTNAME,
    END_REASON_MISC,
    END_REASON_EXIT_POLICY,
    END_REASON_RESOLVE_FAIL,
    END_REASON_REFUSED,
    END_REASON_REMOTE_CLOSED,
    END_REASON_CLIENT_CLOSED,
    CONNECTED_STATUS_OK,
    buildBeginPayload,
    parseBeginPayload,
    buildConnectedPayload,
    buildEndPayload,
    parseEndPayload,
    ipv4ToString,
} from './stream_payloads.mjs';
import { evaluate, ADDR_TYPE_IPV4 as POLICY_ADDR_TYPE_IPV4 } from '../v2/exit_policy.mjs';

// ----- CLIENT SIDE: stream multiplex over a built circuit -----

// A registry of active streams on one circuit. The caller calls
// `streams.handleInboundRelay(d)` for each `kind: 'data'` returned
// from dispatchInboundRelay; the streams object routes to the right
// per-stream callbacks by stream_id.
export const createClientStreams = ({ circuit, entryLink }) => {

    let nextStreamId = 1; // 0 reserved for circuit control
    const streams = new Map(); // streamId → { onConnected, onData, onEnd, onError }

    const allocStreamId = () => {

        const id = nextStreamId;
        nextStreamId = (nextStreamId + 1) & 0xFFFF;
        if (nextStreamId === 0) nextStreamId = 1; // skip 0
        return id;

    };

    // Send a RELAY cell forward through the entire circuit. Builds the
    // RELAY payload with the EXIT hop's forward digest (since the exit
    // is the destination of this cell), then encryptOutbound applies
    // all hops' Kf layers.
    const sendForward = (relayCommand, streamId, data) => {

        if (circuit.hops.length === 0) throw new Error('circuit has no hops');
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

    // Open a new stream to (destination). Returns a Promise that
    // resolves with a stream handle once RELAY_CONNECTED arrives.
    //
    // The stream handle:
    //   stream.streamId
    //   stream.send(data)       — chunks into RELAY_DATA cells
    //   stream.end(reason?)     — sends RELAY_END
    //   stream.onData(handler)  — incoming RELAY_DATA bytes
    //   stream.onEnd(handler)   — incoming RELAY_END (reason)
    const openStream = ({
        destination, // { addrType, addr, port }
        connectTimeoutMs = 30000,
    }) => new Promise((resolve, reject) => {

        const streamId = allocStreamId();
        let closed = false;

        const dataHandlers = [];
        const endHandlers = [];

        const stream = {
            streamId,
            send: (data) => {

                if (closed) throw new Error('stream is closed');
                let off = 0;
                while (off < data.length) {

                    const chunkLen = Math.min(MAX_RELAY_DATA, data.length - off);
                    const chunk = data.subarray(off, off + chunkLen);
                    sendForward(RELAY_DATA, streamId, chunk);
                    off += chunkLen;

                }

            },
            end: (reason = END_REASON_CLIENT_CLOSED) => {

                if (closed) return;
                closed = true;
                try { sendForward(RELAY_END, streamId, buildEndPayload(reason)); } catch { /* ignore */ }
                streams.delete(streamId);

            },
            onData: (h) => { dataHandlers.push(h); },
            onEnd:  (h) => { endHandlers.push(h); },
        };

        streams.set(streamId, {
            onConnected: (status) => {

                if (status === CONNECTED_STATUS_OK) resolve(stream);
                else reject(new Error(`stream open failed: status=${status}`));

            },
            onData: (bytes) => {

                for (const h of dataHandlers) {

                    try { h(bytes); } catch { /* ignore */ }

                }

            },
            onEnd: (reason) => {

                closed = true;
                streams.delete(streamId);
                for (const h of endHandlers) {

                    try { h(reason); } catch { /* ignore */ }

                }

            },
        });

        // Send RELAY_BEGIN.
        try {

            sendForward(RELAY_BEGIN, streamId, buildBeginPayload(destination));

        } catch (err) {

            streams.delete(streamId);
            reject(err);
            return;

        }

        // Connect timeout.
        const timer = setTimeout(() => {

            if (streams.has(streamId)) {

                streams.delete(streamId);
                stream.end(END_REASON_CLIENT_CLOSED);
                reject(new Error('RELAY_CONNECTED timeout'));

            }

        }, connectTimeoutMs);
        const origResolve = streams.get(streamId).onConnected;
        streams.get(streamId).onConnected = (status) => {

            clearTimeout(timer);
            origResolve(status);

        };

    });

    // Called by the per-circuit handler for every 'data' dispatch.
    const handleInboundRelay = (dispatched) => {

        const entry = streams.get(dispatched.streamId);
        if (!entry) return; // unknown stream — drop
        switch (dispatched.relayCommand) {

            case RELAY_CONNECTED: {

                const status = dispatched.data.length > 0 ? dispatched.data[0] : 0xFF;
                entry.onConnected(status);
                return;

            }
            case RELAY_DATA:
                entry.onData(dispatched.data);
                return;
            case RELAY_END: {

                const reason = dispatched.data.length > 0 ? dispatched.data[0] : END_REASON_MISC;
                entry.onEnd(reason);
                return;

            }
            default:
                return; // unknown stream command — drop

        }

    };

    const getStreamCount = () => streams.size;

    const closeAll = (reason = END_REASON_CLIENT_CLOSED) => {

        for (const [streamId, entry] of streams) {

            try { entry.onEnd(reason); } catch { /* ignore */ }

        }
        streams.clear();

    };

    return { openStream, handleInboundRelay, getStreamCount, closeAll };

};

// ----- EXIT SIDE: handle RELAY_BEGIN/DATA/END at the exit relay -----

// Send a backward RELAY cell from this (exit) hop toward the client.
// We build the RELAY payload using THIS hop's backward digest state,
// wrap it backward at this hop, and send on the inbound link with
// the inbound circuit_id. Intermediate hops add their own backward
// layers as the cell traverses back.
const sendBackwardFromExit = ({ circuit, relayCommand, streamId, data }) => {

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

// Factory for the exit-side handler. Plug into the dispatcher's
// `onExitData` callback.
//
// `exitPolicy` is a parsed v2 exit-policy (array of rules). Use
// POLICY_REJECT_ALL to refuse everything.
export const createExitStreamHandler = ({
    exitPolicy,
    connectTimeoutMs = 10000,
    logger = () => {},
}) => {

    // Map: "linkFp:circuitId:streamId" → tcpSocket
    const sockets = new Map();

    const keyOf = (circuit, streamId) =>
        `${circuit.inbound.link.peerFingerprintHex}:${circuit.inbound.circuitId}:${streamId}`;

    const handleBegin = ({ circuit, streamId, data }) => {

        const begin = parseBeginPayload(data);
        if (begin === null) {

            sendBackwardFromExit({
                circuit, relayCommand: RELAY_END, streamId,
                data: buildEndPayload(END_REASON_MISC),
            });
            return;

        }

        if (begin.addrType !== ADDR_TYPE_IPV4) {

            // v0.2 reference: IPv4 only. Hostname / IPv6 not yet supported.
            logger(`stream ${streamId}: rejecting non-IPv4 addr_type=${begin.addrType}`);
            sendBackwardFromExit({
                circuit, relayCommand: RELAY_END, streamId,
                data: buildEndPayload(END_REASON_RESOLVE_FAIL),
            });
            return;

        }

        // Check exit policy.
        const dest = { addrType: POLICY_ADDR_TYPE_IPV4, addr: begin.addr, port: begin.port };
        if (evaluate(exitPolicy, dest) !== 'accept') {

            logger(`stream ${streamId}: exit policy denied ${ipv4ToString(begin.addr)}:${begin.port}`);
            sendBackwardFromExit({
                circuit, relayCommand: RELAY_END, streamId,
                data: buildEndPayload(END_REASON_EXIT_POLICY),
            });
            return;

        }

        const host = ipv4ToString(begin.addr);
        const port = begin.port;
        const sock = createConnection({ host, port });
        const key = keyOf(circuit, streamId);
        sockets.set(key, sock);

        let connected = false;
        const connectTimer = setTimeout(() => {

            if (connected) return;
            try { sock.destroy(); } catch { /* ignore */ }

        }, connectTimeoutMs);

        sock.on('connect', () => {

            connected = true;
            clearTimeout(connectTimer);
            logger(`stream ${streamId}: connected ${host}:${port}`);
            sendBackwardFromExit({
                circuit, relayCommand: RELAY_CONNECTED, streamId,
                data: buildConnectedPayload({ status: CONNECTED_STATUS_OK }),
            });

        });

        sock.on('data', (chunk) => {

            // Send back as RELAY_DATA cells, chunked to MAX_RELAY_DATA.
            let off = 0;
            while (off < chunk.length) {

                const len = Math.min(MAX_RELAY_DATA, chunk.length - off);
                sendBackwardFromExit({
                    circuit, relayCommand: RELAY_DATA, streamId,
                    data: chunk.subarray(off, off + len),
                });
                off += len;

            }

        });

        sock.on('end', () => {

            sendBackwardFromExit({
                circuit, relayCommand: RELAY_END, streamId,
                data: buildEndPayload(END_REASON_REMOTE_CLOSED),
            });
            sockets.delete(key);

        });

        sock.on('error', (err) => {

            clearTimeout(connectTimer);
            if (connected) {

                sendBackwardFromExit({
                    circuit, relayCommand: RELAY_END, streamId,
                    data: buildEndPayload(END_REASON_REMOTE_CLOSED),
                });

            } else {

                logger(`stream ${streamId}: connect ${host}:${port} failed: ${err.code || err.message}`);
                sendBackwardFromExit({
                    circuit, relayCommand: RELAY_END, streamId,
                    data: buildEndPayload(END_REASON_REFUSED),
                });

            }
            sockets.delete(key);

        });

    };

    const handleStreamData = ({ circuit, streamId, data }) => {

        const sock = sockets.get(keyOf(circuit, streamId));
        if (!sock) return; // no stream — drop
        try { sock.write(data); } catch { /* ignore */ }

    };

    const handleStreamEnd = ({ circuit, streamId }) => {

        const key = keyOf(circuit, streamId);
        const sock = sockets.get(key);
        if (sock) {

            try { sock.end(); } catch { /* ignore */ }
            sockets.delete(key);

        }

    };

    // Main entry: the dispatcher's onExitData hands cells here.
    const handleData = ({ circuit, link, circuitId, relayCommand, streamId, data }) => {

        switch (relayCommand) {

            case RELAY_BEGIN: return handleBegin({ circuit, streamId, data });
            case RELAY_DATA:  return handleStreamData({ circuit, streamId, data });
            case RELAY_END:   return handleStreamEnd({ circuit, streamId });
            default:          return;

        }

    };

    const closeAll = () => {

        for (const sock of sockets.values()) {

            try { sock.destroy(); } catch { /* ignore */ }

        }
        sockets.clear();

    };

    return { handleData, closeAll, getStreamCount: () => sockets.size };

};
