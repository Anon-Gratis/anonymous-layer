import { WebSocket, WebSocketServer } from 'ws';

// WebSocket adapter implementing the Transport interface used by
// node.mjs and dispatcher.mjs (matching transport_inmemory.mjs):
//
//   send(bytes)           transmit a frame (Uint8Array)
//   onMessage(handler)    register receive callback
//   onClose(handler)      register close callback
//   close()               disconnect
//
// `ws` is asynchronous: a freshly-constructed WebSocket is in
// CONNECTING state and sends will throw. The adapter queues outbound
// frames until OPEN, then flushes. Incoming frames are delivered
// synchronously to the handler as they arrive.
//
// Incoming frames from `ws` arrive as Buffer; we hand the dispatcher
// a Uint8Array. Note: Buffer IS a Uint8Array on Node, but its
// .subarray semantics differ slightly — we re-wrap to be explicit.

export const wrapWebSocket = (ws) => {

    const sendQueue = [];
    let opened = ws.readyState === WebSocket.OPEN;
    let messageHandler = null;
    let closeHandler = null;
    let closed = ws.readyState === WebSocket.CLOSED || ws.readyState === WebSocket.CLOSING;

    const flushQueue = () => {

        while (sendQueue.length > 0) {

            const frame = sendQueue.shift();
            try {

                ws.send(frame);

            } catch {

                // If send fails, the peer is gone; close handler will
                // be invoked by the ws lifecycle event. Drop silently
                // per SPEC § 9 — pending traffic at disconnect is lost.
                return;

            }

        }

    };

    ws.on('open', () => {

        opened = true;
        flushQueue();

    });

    ws.on('message', (data) => {

        // Coerce Buffer (or whatever raw form ws hands us) to Uint8Array.
        const bytes = data instanceof Uint8Array
            ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
            : new Uint8Array(data);
        if (messageHandler) messageHandler(bytes);

    });

    ws.on('close', () => {

        if (closed) return;
        closed = true;
        if (closeHandler) closeHandler();

    });

    ws.on('error', () => {

        // ws emits 'error' before 'close' on connection failures. The
        // close handler will run too; here we just suppress so an
        // unhandled-error event doesn't crash the process. SPEC § 9
        // forbids surfacing transport-level errors to peers; for
        // *local* errors we still want the close callback to fire.

    });

    const transport = {
        send: (bytes) => {

            if (closed) return;
            if (!opened) {

                sendQueue.push(bytes);
                return;

            }
            try {

                ws.send(bytes);

            } catch {

                // Same disposition as flush-time errors.

            }

        },
        onMessage: (handler) => { messageHandler = handler; },
        onClose: (handler) => { closeHandler = handler; },
        close: () => {

            if (closed) return;
            closed = true;
            try {

                ws.close();

            } catch {

                // already-closing; ignore

            }

        },
    };

    return transport;

};

// Open a WebSocket connection to a peer. Returns a Transport whose
// underlying socket is in CONNECTING state. Sends are queued until
// the connection opens. If the connection never opens (e.g. the
// host is unreachable), the close callback fires.
export const dialWebSocket = ({ host, port, path = '/' }) => {

    const ws = new WebSocket(`ws://${host}:${port}${path}`);
    return wrapWebSocket(ws);

};

// Start a WebSocket listener. For each accepted connection, invoke
// `onTransport(transport)`. The returned object has a close() that
// shuts down the server, and a `port` field reflecting the bound
// port (useful when `port: 0` was passed to get an ephemeral port).
export const createWebSocketListener = ({ port, host = '127.0.0.1' }, onTransport) => {

    const server = new WebSocketServer({ port, host });

    server.on('connection', (ws) => {

        onTransport(wrapWebSocket(ws));

    });

    // Resolve once the underlying TCP listener has bound. Callers that
    // need the bound port should await this promise before reading it.
    const ready = new Promise((resolve) => {

        server.on('listening', () => resolve());

    });

    return {
        ready,
        get port() { return server.address() ? server.address().port : null; },
        close: () => new Promise((resolve) => {

            // server.close() stops accepting new connections but does
            // NOT terminate existing ones. Force-close every live client
            // first so the server's close callback resolves promptly.
            for (const client of server.clients) {

                try { client.terminate(); } catch { /* ignore */ }

            }
            server.close(() => resolve());

        }),
    };

};
