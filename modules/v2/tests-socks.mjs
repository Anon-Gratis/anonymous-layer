// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

import { expect } from 'chai';
import net from 'node:net';

import {
    SOCKS_VERSION,
    AUTH_NONE,
    AUTH_NO_ACCEPTABLE,
    CMD_CONNECT,
    CMD_BIND,
    ATYP_IPV4,
    ATYP_DOMAIN,
    REP_SUCCESS,
    REP_COMMAND_NOT_SUPPORTED,
    REP_CONNECTION_REFUSED,
    handleSocksConnection,
    directTcpTunnelFactory,
} from './socks.mjs';

// Spin up a SOCKS server on an ephemeral port with the given factory.
const startSocksServer = (tunnelFactory) => new Promise((resolve) => {

    const server = net.createServer((socket) => {

        handleSocksConnection({ socket, tunnelFactory }).catch(() => {});

    });
    server.listen(0, '127.0.0.1', () => {

        resolve({
            port: server.address().port,
            close: () => new Promise((r) => server.close(() => r())),
        });

    });

});

// Spin up a TCP echo server on an ephemeral port.
const startEchoServer = () => new Promise((resolve) => {

    const server = net.createServer((socket) => {

        socket.on('data', (d) => socket.write(d));
        socket.on('end', () => socket.end());

    });
    server.listen(0, '127.0.0.1', () => {

        resolve({
            port: server.address().port,
            close: () => new Promise((r) => server.close(() => r())),
        });

    });

});

// A buffered SOCKS5 client. Connects to (host, port) and exposes
// readExactly(n) + write(buf) primitives so the test logic can read
// fixed-size protocol frames without worrying about TCP coalescing.
const createSocksClient = ({ host, port }) => new Promise((resolve, reject) => {

    const sock = net.createConnection({ host, port });

    let buffer = Buffer.alloc(0);
    let closed = false;
    let error = null;
    const waiters = [];

    const drain = () => {

        while (waiters.length > 0) {

            const w = waiters[0];
            if (error) { waiters.shift(); w.reject(error); continue; }
            if (buffer.length >= w.n) {

                waiters.shift();
                const out = Buffer.from(buffer.subarray(0, w.n));
                buffer = buffer.subarray(w.n);
                w.resolve(out);
                continue;

            }
            if (closed) { waiters.shift(); w.reject(new Error('stream ended')); continue; }
            break;

        }

    };

    sock.on('data', (chunk) => { buffer = Buffer.concat([buffer, chunk]); drain(); });
    sock.once('end', () => { closed = true; drain(); });
    sock.once('error', (err) => { error = err; drain(); });
    sock.once('connect', () => {

        resolve({
            sock,
            write: (buf) => sock.write(buf),
            end: (buf) => { if (buf) sock.end(buf); else sock.end(); },
            destroy: () => sock.destroy(),
            readExactly: (n) => new Promise((res, rej) => {

                waiters.push({ n, resolve: res, reject: rej });
                drain();

            }),
            readRemaining: () => new Promise((res) => {

                if (closed) return res(buffer);
                sock.once('end', () => res(buffer));

            }),
            waitClose: () => new Promise((res) => {

                if (closed) return res();
                sock.once('close', () => res());

            }),
        });

    });
    sock.once('error', (e) => reject(e));

});

const buildConnectRequest = ({ host, port, atyp }) => {

    let addrBytes;
    if (atyp === ATYP_IPV4) {

        addrBytes = Buffer.from(host.split('.').map((n) => parseInt(n, 10)));

    } else if (atyp === ATYP_DOMAIN) {

        addrBytes = Buffer.concat([Buffer.from([host.length]), Buffer.from(host, 'utf8')]);

    } else {

        throw new Error(`unsupported test ATYP ${atyp}`);

    }
    return Buffer.concat([
        Buffer.from([SOCKS_VERSION, CMD_CONNECT, 0x00, atyp]),
        addrBytes,
        Buffer.from([(port >> 8) & 0xFF, port & 0xFF]),
    ]);

};

const replyAddrLength = (atyp) => atyp === ATYP_IPV4 ? 4 : atyp === ATYP_DOMAIN ? -1 : 16;

describe('v2/socks — SOCKS5 server', function () {

    this.timeout(8000);

    let echoServer;
    let socksServer;

    afterEach(async () => {

        if (socksServer) { await socksServer.close(); socksServer = null; }
        if (echoServer)  { await echoServer.close();  echoServer  = null; }

    });

    it('CONNECT to a TCP destination via direct factory: bytes round-trip', async () => {

        echoServer = await startEchoServer();
        socksServer = await startSocksServer(directTcpTunnelFactory);

        const client = await createSocksClient({ host: '127.0.0.1', port: socksServer.port });

        // Greeting.
        client.write(Buffer.from([SOCKS_VERSION, 1, AUTH_NONE]));
        const greetReply = await client.readExactly(2);
        expect(greetReply[0]).to.equal(SOCKS_VERSION);
        expect(greetReply[1]).to.equal(AUTH_NONE);

        // CONNECT.
        client.write(buildConnectRequest({
            host: '127.0.0.1', port: echoServer.port, atyp: ATYP_IPV4,
        }));
        // Reply: 4 + 4 (IPv4 BND.ADDR) + 2 (BND.PORT) = 10 bytes.
        const reply = await client.readExactly(10);
        expect(reply[0]).to.equal(SOCKS_VERSION);
        expect(reply[1]).to.equal(REP_SUCCESS);

        // Write a known-size payload and read exactly that many echo bytes.
        const payload = Buffer.from('hello world', 'utf8');
        client.write(payload);
        const echo = await client.readExactly(payload.length);
        expect(echo.toString('utf8')).to.equal('hello world');
        client.destroy();

    });

    it('CONNECT via DOMAIN address type', async () => {

        echoServer = await startEchoServer();
        socksServer = await startSocksServer(directTcpTunnelFactory);

        const client = await createSocksClient({ host: '127.0.0.1', port: socksServer.port });

        client.write(Buffer.from([SOCKS_VERSION, 1, AUTH_NONE]));
        await client.readExactly(2);

        client.write(buildConnectRequest({
            host: 'localhost', port: echoServer.port, atyp: ATYP_DOMAIN,
        }));
        const reply = await client.readExactly(10);
        expect(reply[1]).to.equal(REP_SUCCESS);

        const payload = Buffer.from('ping', 'utf8');
        client.write(payload);
        const echo = await client.readExactly(payload.length);
        expect(echo.toString('utf8')).to.equal('ping');
        client.destroy();

    });

    it('rejects clients that do not offer AUTH_NONE', async () => {

        socksServer = await startSocksServer(directTcpTunnelFactory);
        const client = await createSocksClient({ host: '127.0.0.1', port: socksServer.port });
        // Offer GSSAPI only.
        client.write(Buffer.from([SOCKS_VERSION, 1, 0x01]));
        const reply = await client.readExactly(2);
        expect(reply[0]).to.equal(SOCKS_VERSION);
        expect(reply[1]).to.equal(AUTH_NO_ACCEPTABLE);
        client.destroy();

    });

    it('BIND command returns REP=0x07 (command not supported)', async () => {

        socksServer = await startSocksServer(directTcpTunnelFactory);
        const client = await createSocksClient({ host: '127.0.0.1', port: socksServer.port });

        client.write(Buffer.from([SOCKS_VERSION, 1, AUTH_NONE]));
        await client.readExactly(2);

        // BIND with IPv4 dst.
        client.write(Buffer.concat([
            Buffer.from([SOCKS_VERSION, CMD_BIND, 0x00, ATYP_IPV4]),
            Buffer.from([127, 0, 0, 1]),
            Buffer.from([0x00, 0x50]),
        ]));
        const reply = await client.readExactly(10);
        expect(reply[1]).to.equal(REP_COMMAND_NOT_SUPPORTED);
        client.destroy();

    });

    it('connection refused by destination → REP=0x05', async () => {

        socksServer = await startSocksServer(directTcpTunnelFactory);
        const client = await createSocksClient({ host: '127.0.0.1', port: socksServer.port });

        client.write(Buffer.from([SOCKS_VERSION, 1, AUTH_NONE]));
        await client.readExactly(2);

        // CONNECT to a likely-unbound high port.
        client.write(buildConnectRequest({
            host: '127.0.0.1', port: 50000, atyp: ATYP_IPV4,
        }));
        const reply = await client.readExactly(10);
        expect(reply[1]).to.equal(REP_CONNECTION_REFUSED);
        client.destroy();

    });

    it('malformed greeting (wrong version) closes the connection', async () => {

        socksServer = await startSocksServer(directTcpTunnelFactory);
        const client = await createSocksClient({ host: '127.0.0.1', port: socksServer.port });
        client.write(Buffer.from([0x04, 1, AUTH_NONE]));
        await client.waitClose();

    });

});
