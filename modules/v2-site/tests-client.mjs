// v2-site — PRE-AUDIT EXPERIMENTAL CODE

import { expect } from 'chai';
import { createServer, createConnection } from 'node:net';

import { encodeOnionAddress } from '../v2/onion_address.mjs';
import {
    handleConnection,
    createStaticHandler,
} from './server.mjs';
import { fetchOnce, fetchWithRedirects } from './client.mjs';
import {
    STATUS_SUCCESS,
    STATUS_REDIRECT_TEMP,
    STATUS_NOT_FOUND,
    STATUS_INPUT,
} from './response.mjs';

const sampleOnion = (fill = 0x33) => encodeOnionAddress(new Uint8Array(32).fill(fill));
const ONION = sampleOnion();

const startServer = (handler) => new Promise((resolve) => {

    const server = createServer({ allowHalfOpen: true }, (socket) => {

        handleConnection({ socket, requestHandler: handler }).catch(() => {});

    });
    server.listen(0, '127.0.0.1', () => {

        resolve({
            port: server.address().port,
            close: () => new Promise((r) => server.close(() => r())),

        });

    });

});

describe('v2-site/client — fetchOnce', function () {

    this.timeout(5000);
    let server;

    afterEach(async () => {

        if (server) { await server.close(); server = null; }

    });

    it('returns body for a SUCCESS response with explicit length', async () => {

        const body = new TextEncoder().encode('hello world');
        server = await startServer(async () => ({
            status: STATUS_SUCCESS,
            meta: `text/plain; charset=utf-8; length=${body.length}`,
            body,
        }));
        const sock = createConnection({ host: '127.0.0.1', port: server.port });
        await new Promise((r) => sock.once('connect', r));
        const resp = await fetchOnce({ socket: sock, url: `anon://${ONION}/` });
        sock.end();
        expect(resp.status).to.equal(STATUS_SUCCESS);
        expect(new TextDecoder().decode(resp.body)).to.equal('hello world');

    });

    it('returns body for a SUCCESS response without explicit length (ends at stream close)', async () => {

        const body = new TextEncoder().encode('# heading\n');
        server = await startServer(async () => ({
            status: STATUS_SUCCESS, meta: 'text/anon; charset=utf-8', body,
        }));
        // For this test, the server doesn't include length; the client
        // can only know the body has ended when the stream closes.
        const sock = createConnection({ host: '127.0.0.1', port: server.port });
        await new Promise((r) => sock.once('connect', r));
        const fetchPromise = fetchOnce({ socket: sock, url: `anon://${ONION}/`, timeoutMs: 2000 });
        // Wait briefly for the response to be written, then close server-side.
        setTimeout(() => sock.end(), 200);
        const resp = await fetchPromise;
        expect(new TextDecoder().decode(resp.body)).to.equal('# heading\n');

    });

    it('returns null body for a non-SUCCESS response', async () => {

        server = await startServer(async () => ({
            status: STATUS_NOT_FOUND, meta: 'gone', body: null,
        }));
        const sock = createConnection({ host: '127.0.0.1', port: server.port });
        await new Promise((r) => sock.once('connect', r));
        const resp = await fetchOnce({ socket: sock, url: `anon://${ONION}/` });
        sock.end();
        expect(resp.status).to.equal(STATUS_NOT_FOUND);
        expect(resp.body).to.equal(null);

    });

    // Regression for the fetchOnce body-buffering bug: when the response
    // arrives in multiple TCP chunks (which it always does on real
    // network paths > 499 bytes because RELAY_DATA cells cap at that
    // size), the old implementation parsed the head on the first chunk
    // but then never folded subsequent chunks from `buffer` into
    // `bodySoFar`. Result: completion check `bodySoFar.length >= bodyBytesNeeded`
    // never tripped and the call timed out.
    //
    // This test fragments the response across multiple writes deliberately:
    // 1. head + a partial body chunk
    // 2. middle of body, after a setImmediate yield
    // 3. tail of body
    //
    // Pre-fix: this test times out. Post-fix: completes with the full body.
    it('accumulates body across multiple TCP chunks (regression for fragmentation bug)', async () => {

        // Body big enough that the client MUST accumulate at least 3
        // chunks before the completion check fires.
        const bodyText = 'A'.repeat(800) + 'B'.repeat(800) + 'C'.repeat(800); // 2400 bytes
        const body = new TextEncoder().encode(bodyText);
        const head = new TextEncoder().encode(`20 text/plain; charset=utf-8; length=${body.length}\r\n`);

        const fragServer = createServer((sock) => {

            // Read the request line (we don't actually need it).
            sock.once('data', () => {

                // Write head + first slice of body together.
                sock.write(Buffer.concat([head, body.subarray(0, 500)]));
                // Then two more writes, each on a separate tick, to force
                // the client into the "head set, more body coming in
                // later chunks" path that the fix targets.
                setImmediate(() => {

                    sock.write(body.subarray(500, 1700));
                    setImmediate(() => {

                        sock.write(body.subarray(1700));

                    });

                });

            });

        });
        await new Promise((r) => fragServer.listen(0, '127.0.0.1', r));
        const fragPort = fragServer.address().port;
        const cleanup = () => new Promise((r) => fragServer.close(() => r()));

        try {

            const sock = createConnection({ host: '127.0.0.1', port: fragPort });
            await new Promise((r) => sock.once('connect', r));
            const resp = await fetchOnce({
                socket: sock, url: `anon://${ONION}/`, timeoutMs: 3000,
            });
            sock.end();
            expect(resp.status).to.equal(STATUS_SUCCESS);
            expect(resp.body.length).to.equal(body.length);
            expect(new TextDecoder().decode(resp.body)).to.equal(bodyText);

        } finally {

            await cleanup();

        }

    });

});

describe('v2-site/client — fetchWithRedirects', function () {

    this.timeout(5000);
    let servers = [];

    afterEach(async () => {

        await Promise.all(servers.map((s) => s.close()));
        servers = [];

    });

    it('follows a single redirect', async () => {

        // Server: GET /a → redirect to /b. GET /b → SUCCESS "ok".
        const handler = async ({ path }) => {

            if (path === '/a') {

                return { status: STATUS_REDIRECT_TEMP, meta: `anon://${ONION}/b`, body: null };

            }
            if (path === '/b') {

                const body = new TextEncoder().encode('ok');
                return { status: STATUS_SUCCESS, meta: `text/plain; length=${body.length}`, body };

            }
            return { status: STATUS_NOT_FOUND, meta: 'nf', body: null };

        };
        const server = await startServer(handler);
        servers.push(server);

        const connect = () => new Promise((r, j) => {

            const s = createConnection({ host: '127.0.0.1', port: server.port });
            s.once('connect', () => r(s));
            s.once('error', j);

        });
        const resp = await fetchWithRedirects({
            connect, url: `anon://${ONION}/a`, maxRedirects: 5,
        });
        expect(resp.status).to.equal(STATUS_SUCCESS);
        expect(new TextDecoder().decode(resp.body)).to.equal('ok');

    });

    it('refuses an infinite redirect loop', async () => {

        const handler = async ({ path }) => {

            if (path === '/a') {

                return { status: STATUS_REDIRECT_TEMP, meta: `anon://${ONION}/b`, body: null };

            }
            if (path === '/b') {

                return { status: STATUS_REDIRECT_TEMP, meta: `anon://${ONION}/a`, body: null };

            }
            return { status: STATUS_NOT_FOUND, meta: 'nf', body: null };

        };
        const server = await startServer(handler);
        servers.push(server);

        const connect = () => new Promise((r, j) => {

            const s = createConnection({ host: '127.0.0.1', port: server.port });
            s.once('connect', () => r(s));
            s.once('error', j);

        });
        let threw = false;
        try {

            await fetchWithRedirects({
                connect, url: `anon://${ONION}/a`, maxRedirects: 10,
            });

        } catch (err) {

            threw = err.message.includes('redirect loop');

        }
        expect(threw).to.equal(true);

    });

    it('caps at maxRedirects', async () => {

        // Server keeps redirecting through a fresh URL each time.
        let next = 0;
        const handler = async () => ({
            status: STATUS_REDIRECT_TEMP,
            meta: `anon://${ONION}/step${++next}`,
            body: null,
        });
        const server = await startServer(handler);
        servers.push(server);

        const connect = () => new Promise((r, j) => {

            const s = createConnection({ host: '127.0.0.1', port: server.port });
            s.once('connect', () => r(s));
            s.once('error', j);

        });
        let threw = false;
        try {

            await fetchWithRedirects({
                connect, url: `anon://${ONION}/start`, maxRedirects: 3,
            });

        } catch (err) {

            threw = err.message.includes('exceeded');

        }
        expect(threw).to.equal(true);

    });

    it('surfaces INPUT via onInput callback and resubmits with query', async () => {

        const handler = async ({ path, query }) => {

            if (path === '/search' && query === null) {

                return { status: STATUS_INPUT, meta: 'search term?', body: null };

            }
            if (path === '/search' && query !== null) {

                const body = new TextEncoder().encode(`you searched for: ${decodeURIComponent(query)}`);
                return { status: STATUS_SUCCESS, meta: `text/plain; length=${body.length}`, body };

            }
            return { status: STATUS_NOT_FOUND, meta: 'nf', body: null };

        };
        const server = await startServer(handler);
        servers.push(server);

        const connect = () => new Promise((r, j) => {

            const s = createConnection({ host: '127.0.0.1', port: server.port });
            s.once('connect', () => r(s));
            s.once('error', j);

        });
        const resp = await fetchWithRedirects({
            connect,
            url: `anon://${ONION}/search`,
            onInput: async () => 'hello world',
        });
        expect(resp.status).to.equal(STATUS_SUCCESS);
        expect(new TextDecoder().decode(resp.body)).to.equal('you searched for: hello world');

    });

});
