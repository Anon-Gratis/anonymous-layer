// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

// SOCKS5 server-side handler (RFC 1928).
//
// This module implements only the bytes-on-the-wire SOCKS5 protocol +
// a pluggable `tunnelFactory` interface. The factory is given
// (host, port) and returns a duplex stream the SOCKS server will pipe
// the client's TCP bytes through. A future v0.2 runtime will provide
// an anon-layer-backed factory; for now the default factory opens a
// direct TCP connection (no anonymity).
//
// Only CONNECT is supported. BIND and UDP_ASSOCIATE return REP=0x07
// ("Command not supported"). No authentication — clients must offer
// method 0x00 (no auth).

import { createConnection } from 'node:net';

export const SOCKS_VERSION = 0x05;

// Methods
export const AUTH_NONE          = 0x00;
export const AUTH_NO_ACCEPTABLE = 0xFF;

// Commands
export const CMD_CONNECT      = 0x01;
export const CMD_BIND         = 0x02;
export const CMD_UDP_ASSOC    = 0x03;

// Address types
export const ATYP_IPV4   = 0x01;
export const ATYP_DOMAIN = 0x03;
export const ATYP_IPV6   = 0x04;

// Reply codes
export const REP_SUCCESS                 = 0x00;
export const REP_GENERAL_FAILURE         = 0x01;
export const REP_NOT_ALLOWED             = 0x02;
export const REP_NETWORK_UNREACHABLE     = 0x03;
export const REP_HOST_UNREACHABLE        = 0x04;
export const REP_CONNECTION_REFUSED      = 0x05;
export const REP_TTL_EXPIRED             = 0x06;
export const REP_COMMAND_NOT_SUPPORTED   = 0x07;
export const REP_ADDR_TYPE_NOT_SUPPORTED = 0x08;

// ----- Stream-reading helpers -----

// Buffered reader on top of a Duplex stream. Uses flowing mode (the
// 'data' event) plus explicit pause/resume to hand off cleanly when
// the handshake finishes and the caller takes over with pipe().
//
// The reader buffers all incoming bytes until `readExactly(n)` calls
// drain them in order. On `detach()`, the reader pauses the stream,
// removes its listeners, and returns any unread bytes — the caller
// is responsible for writing them onward.
const createBufferedReader = (socket) => {

    let buffer = Buffer.alloc(0);
    let closed = false;
    let error = null;
    const waiters = [];

    const drain = () => {

        while (waiters.length > 0) {

            const w = waiters[0];
            if (error) { waiters.shift(); if (w.timer) clearTimeout(w.timer); w.reject(error); continue; }
            if (buffer.length >= w.n) {

                waiters.shift();
                const out = Uint8Array.from(buffer.subarray(0, w.n));
                buffer = buffer.subarray(w.n);
                if (w.timer) clearTimeout(w.timer);
                w.resolve(out);
                continue;

            }
            if (closed) { waiters.shift(); if (w.timer) clearTimeout(w.timer); w.reject(new Error('stream ended before all bytes arrived')); continue; }
            break;

        }

    };

    const onData = (chunk) => { buffer = Buffer.concat([buffer, chunk]); drain(); };
    const onEnd = () => { closed = true; drain(); };
    const onError = (err) => { error = err; drain(); };

    socket.on('data', onData);
    socket.once('end', onEnd);
    socket.once('error', onError);

    return {
        readExactly: (n, { timeoutMs = 15000 } = {}) => new Promise((resolve, reject) => {

            const w = { n, resolve, reject, timer: null };
            if (timeoutMs > 0) {

                w.timer = setTimeout(() => {

                    const idx = waiters.indexOf(w);
                    if (idx >= 0) waiters.splice(idx, 1);
                    reject(new Error('readExactly timeout'));

                }, timeoutMs);

            }
            waiters.push(w);
            drain();

        }),
        detach: () => {

            // Pause flowing mode BEFORE removing listeners — otherwise
            // bytes that arrive between removeListener and the
            // subsequent pipe() call get dropped on the floor.
            socket.pause();
            socket.removeListener('data', onData);
            socket.removeListener('end', onEnd);
            socket.removeListener('error', onError);
            return buffer;

        },
    };

};

// ----- Reply builders -----

const buildReply = ({ rep, atyp = ATYP_IPV4, addr = new Uint8Array(4), port = 0 }) => {

    const buf = new Uint8Array(4 + addr.length + 2);
    buf[0] = SOCKS_VERSION;
    buf[1] = rep;
    buf[2] = 0x00; // RSV
    buf[3] = atyp;
    buf.set(addr, 4);
    buf[4 + addr.length]     = (port >> 8) & 0xFF;
    buf[4 + addr.length + 1] = port & 0xFF;
    return buf;

};

// ----- Default tunnel factory -----

// Opens a direct TCP connection — transparent proxy, NO anonymity.
// This is the placeholder; a v0.2-runtime tunnel factory will route
// through a circuit by opening a stream via RELAY_BEGIN.
export const directTcpTunnelFactory = ({ host, port }) => new Promise((resolve, reject) => {

    const sock = createConnection({ host, port });
    const onError = (err) => {

        sock.removeListener('connect', onConnect);
        reject(err);

    };
    const onConnect = () => {

        sock.removeListener('error', onError);
        resolve(sock);

    };
    sock.once('error', onError);
    sock.once('connect', onConnect);

});

// Refuses to route. Useful when no factory is configured — better to
// fail loud than silently leak.
export const refusingTunnelFactory = () => Promise.reject(new Error(
    'no tunnel factory configured — refusing to route SOCKS connections without an explicit destination',
));

// ----- Main handler -----

// Read a CONNECT request body off the wire and return its parsed form.
// Returns null on any structural failure.
const readConnectRequest = async (reader) => {

    const head = await reader.readExactly(4);
    if (head[0] !== SOCKS_VERSION) return null;
    if (head[2] !== 0x00) return null; // RSV must be 0x00
    const cmd = head[1];
    const atyp = head[3];

    let host;
    if (atyp === ATYP_IPV4) {

        const ip = await reader.readExactly(4);
        host = `${ip[0]}.${ip[1]}.${ip[2]}.${ip[3]}`;

    } else if (atyp === ATYP_IPV6) {

        const ip = await reader.readExactly(16);
        const parts = [];
        for (let i = 0; i < 16; i += 2) {

            parts.push(((ip[i] << 8) | ip[i + 1]).toString(16));

        }
        host = parts.join(':');

    } else if (atyp === ATYP_DOMAIN) {

        const lenByte = await reader.readExactly(1);
        const nameLen = lenByte[0];
        if (nameLen === 0) return null;
        const nameBytes = await reader.readExactly(nameLen);
        host = Buffer.from(nameBytes).toString('utf8');

    } else {

        return null;

    }

    const portBytes = await reader.readExactly(2);
    const port = (portBytes[0] << 8) | portBytes[1];

    return { cmd, atyp, host, port };

};

// Serve a single SOCKS5 client connection. The `socket` is a Duplex
// (typically a `net.Socket`). On success, the socket and the tunnel
// are piped together bidirectionally; the function resolves when
// either side closes.
//
// `tunnelFactory` is async ({host, port}) => Duplex. It may reject;
// the handler will translate common rejection codes into appropriate
// SOCKS reply codes.
//
// Returns a Promise that resolves to a short status string useful for
// logging: 'ok', 'rejected', 'unsupported-cmd', 'unsupported-atyp',
// 'tunnel-failed', 'malformed'.
export const handleSocksConnection = async ({ socket, tunnelFactory }) => {

    const safeWrite = (buf) => new Promise((resolve) => {

        if (socket.destroyed) return resolve();
        socket.write(buf, () => resolve());

    });
    const safeEnd = () => new Promise((resolve) => {

        if (socket.destroyed) return resolve();
        socket.end(() => resolve());

    });

    const reader = createBufferedReader(socket);

    try {

        // Greeting.
        const greetHead = await reader.readExactly(2);
        if (greetHead[0] !== SOCKS_VERSION) {

            await safeEnd();
            return 'malformed';

        }
        const nMethods = greetHead[1];
        if (nMethods === 0) {

            await safeWrite(Uint8Array.from([SOCKS_VERSION, AUTH_NO_ACCEPTABLE]));
            await safeEnd();
            return 'malformed';

        }
        const methods = await reader.readExactly(nMethods);
        if (!methods.includes(AUTH_NONE)) {

            await safeWrite(Uint8Array.from([SOCKS_VERSION, AUTH_NO_ACCEPTABLE]));
            await safeEnd();
            return 'rejected';

        }
        await safeWrite(Uint8Array.from([SOCKS_VERSION, AUTH_NONE]));

        // Request.
        const req = await readConnectRequest(reader);
        if (req === null) {

            await safeWrite(buildReply({ rep: REP_GENERAL_FAILURE }));
            await safeEnd();
            return 'malformed';

        }

        if (req.cmd !== CMD_CONNECT) {

            await safeWrite(buildReply({ rep: REP_COMMAND_NOT_SUPPORTED }));
            await safeEnd();
            return 'unsupported-cmd';

        }
        if (req.atyp !== ATYP_IPV4 && req.atyp !== ATYP_IPV6 && req.atyp !== ATYP_DOMAIN) {

            await safeWrite(buildReply({ rep: REP_ADDR_TYPE_NOT_SUPPORTED }));
            await safeEnd();
            return 'unsupported-atyp';

        }

        // Open the tunnel.
        let tunnel;
        try {

            tunnel = await tunnelFactory({ host: req.host, port: req.port });

        } catch (err) {

            // Translate common error codes into SOCKS reply codes.
            const code = err.code || '';
            const rep = code === 'ECONNREFUSED' ? REP_CONNECTION_REFUSED
                      : code === 'ENETUNREACH'  ? REP_NETWORK_UNREACHABLE
                      : code === 'EHOSTUNREACH' ? REP_HOST_UNREACHABLE
                      : code === 'ETIMEDOUT'    ? REP_TTL_EXPIRED
                      : REP_GENERAL_FAILURE;
            await safeWrite(buildReply({ rep }));
            await safeEnd();
            return 'tunnel-failed';

        }

        // Success reply. We report the tunnel-local address as 0.0.0.0:0
        // because a v0.2-backed tunnel has no meaningful local address
        // to expose.
        await safeWrite(buildReply({ rep: REP_SUCCESS }));

        // Detach the reader; any bytes the client already sent past
        // the handshake go forward into the tunnel.
        const leftover = reader.detach();
        if (leftover.length > 0) tunnel.write(leftover);

        // Bidirectional pipe. Each side closes the other on end/error.
        return await new Promise((resolve) => {

            let done = false;
            const finish = (status) => { if (done) return; done = true; resolve(status); };
            const onError = () => finish('ok');
            const onEnd = () => finish('ok');

            socket.on('error', onError);
            socket.on('end', onEnd);
            tunnel.on('error', onError);
            tunnel.on('end', onEnd);

            socket.pipe(tunnel);
            tunnel.pipe(socket);

        });

    } catch (err) {

        await safeEnd();
        return 'malformed';

    }

};
