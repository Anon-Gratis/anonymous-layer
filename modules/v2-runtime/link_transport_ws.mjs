// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE
//
// Reference v0.2 runtime, see docs/SPEC-v0.2-draft.md.
// The draft has open architectural questions; the code has not been
// audited. Do not rely on this for anonymity.

// WebSocket-over-TLS carrier for v0.2 link cells (SPEC § 11).
//
// Each WebSocket message is exactly one 514-byte cell. The link.mjs
// handshake state machine drives the LINK_HELLO / LINK_AUTH exchange
// on this carrier; once `established`, subsequent cells (CREATE,
// CREATED, RELAY, DESTROY) flow on the same WebSocket and are
// dispatched to a caller-supplied `onCell` handler.
//
// TRUST MODEL (SPEC § 11.1):
// The TLS layer provides confidentiality + integrity on the wire.
// It does NOT establish peer identity — the LINK_AUTH step (§ 11.2)
// does that via an Ed25519 signature over a transcript that includes
// both sides' nonces and identity keys. As a direct consequence:
//
//   - Certificates SHOULD be self-signed. The spec is explicit:
//     "the relay's identity of record is its Ed25519 idPk … the
//     certificate's role is solely to enable TLS; trust comes from
//     the link-auth signature."
//
//   - The dialer therefore passes `rejectUnauthorized: false`. This
//     looks alarming in code review; it is intentional and load-
//     bearing on the spec. Auditor note: replacing this with strict
//     CA validation would NOT improve security (the cert isn't the
//     identity) and WOULD introduce a CA-trust dependency the
//     protocol explicitly avoids.
//
//   - SNI is left unset on the dialer (no `servername` option).
//     Sending one would leak the destination hostname in
//     pre-handshake plaintext; since cert validation is off, SNI has
//     no functional role anyway.
//
//   - Cells inside the TLS tunnel are independently encrypted by
//     the circuit-layer AEAD (§ 5.4). TLS adds a metadata-flow
//     wrapper, not an anonymity property.

import { WebSocket, WebSocketServer } from 'ws';
import { createServer as createHttpsServer } from 'node:https';

import { CELL_BYTES } from '../v2/cells.mjs';
import {
    createLinkHandshake,
    HANDSHAKE_STATE_ESTABLISHED,
} from '../v2/link.mjs';

// Wrap a WebSocket as a duplex "cell stream":
//   transport.sendCell(cell)        — send one 514-byte cell
//   transport.onCell(handler)       — register cell-received callback
//   transport.onClose(handler)      — register close callback
//   transport.close()
//
// Cells received via 'message' that are not exactly 514 bytes
// terminate the underlying WebSocket.
const wrapWebSocketAsTransport = (ws) => {

    let onCell = null;
    let onClose = null;
    let closed = false;
    const pending = []; // cells queued while WS not yet open

    const flushPending = () => {

        while (pending.length > 0) {

            try { ws.send(pending.shift()); } catch { return; }

        }

    };

    ws.on('open', () => { flushPending(); });

    ws.on('message', (data, isBinary) => {

        if (closed) return;
        // Coerce to Uint8Array regardless of input type (Node ws gives
        // Buffer for binary, string for text).
        let bytes;
        if (data instanceof Uint8Array) {

            bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);

        } else if (typeof data === 'string') {

            // We don't expect text frames on a cell stream; close.
            closed = true;
            try { ws.close(1003, 'text frame on cell stream'); } catch {}
            return;

        } else {

            bytes = new Uint8Array(data);

        }
        if (bytes.length !== CELL_BYTES) {

            closed = true;
            try { ws.close(1002, `bad cell size ${bytes.length}`); } catch {}
            return;

        }
        if (onCell) onCell(bytes);

    });

    ws.on('close', () => {

        if (closed) return;
        closed = true;
        if (onClose) onClose();

    });

    ws.on('error', () => {

        // Suppress error; 'close' will fire afterwards.

    });

    return {
        sendCell: (cell) => {

            if (closed) return;
            if (cell.length !== CELL_BYTES) {

                throw new Error(`cell must be ${CELL_BYTES} bytes`);

            }
            if (ws.readyState === WebSocket.OPEN) {

                try { ws.send(cell, { binary: true }); } catch { /* ignore */ }

            } else {

                pending.push(cell);

            }

        },
        onCell: (h) => { onCell = h; },
        onClose: (h) => { onClose = h; },
        close: () => {

            if (closed) return;
            closed = true;
            try { ws.close(); } catch {}

        },
    };

};

// Run the link handshake on top of a transport. On success resolves
// with `{ peerIdPk, transport }`. On failure or timeout, the transport
// is closed and the promise rejects.
//
// `transport` is a wrapped WebSocket from wrapWebSocketAsTransport.
const performLinkHandshakeOnTransport = ({
    transport, identity, expectedPeerIdPk, isDialer, timeoutMs = 15000,
}) => new Promise((resolve, reject) => {

    const handshake = createLinkHandshake({
        identity, expectedPeerIdPk, isDialer,
    });

    let settled = false;
    const settle = (fn, value) => {

        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        fn(value);

    };

    const timer = setTimeout(() => {

        transport.close();
        settle(reject, new Error('link handshake timeout'));

    }, timeoutMs);

    transport.onCell((cell) => {

        const result = handshake.ingestCell(cell);
        if (result === null) {

            transport.close();
            settle(reject, new Error(`link handshake failed: ${handshake.getFailureReason()}`));
            return;

        }
        if (result.kind === 'send') {

            transport.sendCell(result.cell);

        }
        if (result.kind === 'established') {

            settle(resolve, { peerIdPk: result.peerIdPk, transport });

        }

    });

    transport.onClose(() => {

        settle(reject, new Error('transport closed during handshake'));

    });

    // Send our own HELLO immediately.
    transport.sendCell(handshake.buildHelloCell());

});

// ----- Public API -----

// Dial a relay by host/port; verify it presents the expected idPk.
// Returns a Promise resolving to `{ peerIdPk, transport }` once the
// handshake is established.
//
// Uses wss:// per SPEC § 11.1. Cert validation is intentionally
// disabled (`rejectUnauthorized: false`) — see TRUST MODEL note at
// the top of this file. Identity comes from the LINK_AUTH Ed25519
// signature in performLinkHandshakeOnTransport, not from the TLS
// chain.
export const dialLink = ({ host, port, path = '/', identity, expectedPeerIdPk, timeoutMs = 15000 }) => {

    const url = `wss://${host}:${port}${path}`;
    const ws = new WebSocket(url, {
        perMessageDeflate: false,
        // Spec § 11.1: cert is for transport encryption only; identity
        // is proven by LINK_AUTH. Do NOT remove this without also
        // designing how cert pinning would interact with relay key
        // rotation, what CT logs would carry, and how dialer-side cert
        // validation would handle relay-IP changes that the consensus
        // hasn't propagated yet.
        rejectUnauthorized: false,
        // No `servername`: we don't leak the destination via SNI, and
        // since validation is off SNI has no role.
    });
    const transport = wrapWebSocketAsTransport(ws);
    return performLinkHandshakeOnTransport({
        transport, identity, expectedPeerIdPk, isDialer: true, timeoutMs,
    });

};

// Create a TLS-terminating listener that runs the link handshake on
// each accepted WebSocket. The `onLink` callback receives
// `{ peerIdPk, transport }` for every successfully-authenticated peer
// connection. Connections that fail the handshake are closed silently.
//
// Required params:
//   tlsCert, tlsKey  — PEM strings (self-signed per SPEC § 11.1).
//                       Auditor note: these certs are NOT the relay's
//                       identity. They are an enveloping carrier; the
//                       Ed25519 keypair in `identity` is the identity.
//                       The cert MAY rotate freely without touching
//                       the relay's consensus entry.
//
// Returns:
//   { port, address, close }    once the server is listening
export const createLinkListener = ({
    port = 0, host = '127.0.0.1', identity, onLink,
    tlsCert, tlsKey,
    handshakeTimeoutMs = 15000,
}) => new Promise((resolve, reject) => {

    if (!tlsCert || !tlsKey) {

        reject(new Error('createLinkListener: tlsCert + tlsKey required (per SPEC § 11.1)'));
        return;

    }

    // The `ws` library accepts `server: <httpServerLike>` and attaches
    // its WebSocket-upgrade handling. Using https.createServer gives
    // us TLS termination at the same Node process — no separate
    // reverse-proxy, no DNS dependency.
    const httpsServer = createHttpsServer({
        cert: tlsCert,
        key:  tlsKey,
        // No ALPN advertising: clients dial expecting wss, no
        // negotiation needed. Default ciphersuites are fine — Node's
        // defaults exclude legacy/weak suites.
    });

    const server = new WebSocketServer({
        server: httpsServer,
        perMessageDeflate: false,
    });

    httpsServer.on('listening', () => {

        const addr = httpsServer.address();
        resolve({
            port: addr.port,
            address: addr.address,
            close: () => new Promise((r) => {

                for (const client of server.clients) {

                    try { client.terminate(); } catch {}

                }
                server.close(() => httpsServer.close(() => r()));

            }),
        });

    });

    httpsServer.on('error', reject);

    server.on('connection', async (ws) => {

        const transport = wrapWebSocketAsTransport(ws);
        try {

            const link = await performLinkHandshakeOnTransport({
                transport, identity, expectedPeerIdPk: null,
                isDialer: false, timeoutMs: handshakeTimeoutMs,
            });
            if (onLink) onLink(link);

        } catch {

            // handshake failure already closes the transport; nothing else to do.

        }

    });

    httpsServer.listen(port, host);

});
