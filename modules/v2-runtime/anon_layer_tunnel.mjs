// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE
//
// Reference v0.2 runtime, see docs/SPEC-v0.2-draft.md.

// anonLayerTunnelFactory — the glue between the SOCKS5 server (in
// modules/v2/socks.mjs) and the v0.2 runtime.
//
// SOCKS5's handleSocksConnection calls `tunnelFactory({host, port})`
// and expects back a Node-stream-like Duplex. This module produces
// a tunnelFactory that:
//
//   1. Resolves the destination (parses IPv4 literal, or DNS-lookup
//      hostnames client-side — known limitation: DNS leaks to the
//      client's local resolver).
//   2. Ensures a standby circuit exists (builds one on first use via
//      pickPath() through the consensus); reuses it for subsequent
//      destinations. If a destination's port isn't permitted by the
//      standby exit's policy, the stream open fails — the caller
//      sees the SOCKS5 error and may retry, at which point a fresh
//      circuit gets built.
//   3. Opens a stream on the circuit via createClientStreams.openStream.
//   4. Wraps the stream as a Node Duplex.
//
// For v0.2 reference impl, ONE standby circuit per factory is enough
// to demonstrate end-to-end functionality. Production would maintain
// a pool of circuits with diverse exit policies and rotate by lifetime.

import { Duplex } from 'node:stream';
import { promises as dnsPromises } from 'node:dns';

import { pickPath } from '../v2/consensus.mjs';
import { createClientStreams } from './streams.mjs';
import {
    ADDR_TYPE_IPV4,
    CONNECTED_STATUS_OK,
} from './stream_payloads.mjs';

const parseIPv4Literal = (str) => {

    if (typeof str !== 'string') return null;
    const m = str.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return null;
    const bytes = new Uint8Array(4);
    for (let i = 0; i < 4; i += 1) {

        const n = parseInt(m[i + 1], 10);
        if (n < 0 || n > 255) return null;
        bytes[i] = n;

    }
    return bytes;

};

const resolveToIPv4 = async (host) => {

    const literal = parseIPv4Literal(host);
    if (literal) return literal;
    // Hostname — fall back to client-side DNS. KNOWN LIMITATION: this
    // leaks the lookup to the client's local resolver. Exit-side DNS
    // resolution is a future-work item (it's a sizeable anonymity-
    // surface design pass on its own — see § 7.2 open questions).
    const { address } = await dnsPromises.lookup(host, { family: 4 });
    const bytes = parseIPv4Literal(address);
    if (!bytes) throw new Error(`DNS lookup for ${host} returned non-IPv4 address ${address}`);
    return bytes;

};

// Adapter: wrap a v2-runtime client stream as a Node Duplex.
class StreamDuplex extends Duplex {

    constructor(stream) {

        super({ allowHalfOpen: true });
        this._anonStream = stream;
        this._queue = [];
        this._ended = false;

        stream.onData((bytes) => {

            this._queue.push(Buffer.from(bytes));
            this._flush();

        });
        stream.onEnd(() => {

            this._ended = true;
            this._flush();

        });

    }

    _read() { this._flush(); }

    _flush() {

        while (this._queue.length > 0) {

            const chunk = this._queue.shift();
            if (!this.push(chunk)) return; // backpressure; resume on next _read

        }
        if (this._ended && this._queue.length === 0) {

            this.push(null);
            this._ended = false; // don't push null twice

        }

    }

    _write(chunk, encoding, callback) {

        try {

            this._anonStream.send(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
            callback();

        } catch (err) {

            callback(err);

        }

    }

    _final(callback) {

        try { this._anonStream.end(); } catch { /* ignore */ }
        callback();

    }

}

// Build a tunnelFactory suitable for handleSocksConnection.
//
// Required:
//   consensus        parsed consensus (modules/v2/consensus.mjs)
//   circuitBuilder   from createCircuitBuilder
//
// Optional:
//   pathSelectorPort  port to use for pickPath's destination filter
//                     when building the standby circuit. Default 443.
//   logger
export const createAnonLayerTunnelFactory = ({
    consensus, circuitBuilder, pathSelectorPort = 443, logger = () => {},
    // Optional override for path selection. Default uses pickPath from
    // modules/v2/consensus.mjs which enforces /16 anti-correlation.
    // Tests or operators with special constraints may pass a custom
    // function returning `{ guard, middle, exit }` RSEs (or null).
    pickPathFn = null,
}) => {

    let standby = null;       // { built, streams }
    let buildPromise = null;  // in-flight build

    const selectPath = (destination) => {

        if (pickPathFn) return pickPathFn({ consensus, destination });
        return pickPath({ consensus, destination });

    };

    const ensureCircuit = async () => {

        if (standby) return standby;
        if (buildPromise) return buildPromise;

        buildPromise = (async () => {

            const path = selectPath({
                addrType: ADDR_TYPE_IPV4,
                addr: new Uint8Array([0, 0, 0, 0]),
                port: pathSelectorPort,
            });
            if (!path) throw new Error('pickPath: no usable 3-hop path');

            logger(`building standby circuit via ${
                Buffer.from(path.guard.fingerprint).toString('hex').slice(0, 16)
            }… → ${Buffer.from(path.middle.fingerprint).toString('hex').slice(0, 16)
            }… → ${Buffer.from(path.exit.fingerprint).toString('hex').slice(0, 16)}…`);

            const streamsHolder = { streams: null };
            const built = await circuitBuilder.buildCircuit({
                path,
                onData: (d) => {

                    if (streamsHolder.streams) streamsHolder.streams.handleInboundRelay(d);

                },
                onDestroy: () => {

                    logger('standby circuit destroyed; will rebuild on next request');
                    standby = null;

                },
            });
            const streams = createClientStreams({
                circuit: built.circuit, entryLink: built.entryLink,
            });
            streamsHolder.streams = streams;
            standby = { built, streams };
            return standby;

        })();

        try { return await buildPromise; }
        finally { buildPromise = null; }

    };

    const tunnelFactory = async ({ host, port }) => {

        const addr = await resolveToIPv4(host);
        const destination = { addrType: ADDR_TYPE_IPV4, addr, port };
        const { streams } = await ensureCircuit();
        const stream = await streams.openStream({ destination });
        return new StreamDuplex(stream);

    };

    const closeStandby = () => {

        if (standby) {

            try { standby.streams.closeAll(); } catch { /* ignore */ }
            standby = null;

        }

    };

    return { tunnelFactory, closeStandby };

};
