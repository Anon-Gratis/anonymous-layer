// v2-site — PRE-AUDIT EXPERIMENTAL CODE

import { expect } from 'chai';
import { createServer, createConnection } from 'node:net';
import { mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { encodeOnionAddress } from '../v2/onion_address.mjs';
import {
    handleConnection,
    createStaticHandler,
} from './server.mjs';
import {
    STATUS_SUCCESS,
    STATUS_NOT_FOUND,
    STATUS_BAD_REQUEST,
    STATUS_PERMANENT_FAILURE,
    parseResponseHead,
} from './response.mjs';

const sampleOnion = (fill = 0x33) => encodeOnionAddress(new Uint8Array(32).fill(fill));
const ONION = sampleOnion();

// Spin up a server with a supplied handler on an ephemeral port.
const startServer = (handler) => new Promise((resolve) => {

    // allowHalfOpen: true so the server's writable side does NOT auto-
    // close when it reads FIN from the client. Required because our
    // handlers are async; if the writable side auto-closes mid-await
    // the response gets silently dropped.
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

// Buffered client: sends `requestBytes`, reads everything until close.
const sendAndCollect = ({ port, requestBytes, closeAfterWrite = true }) => new Promise((resolve, reject) => {

    const sock = createConnection({ host: '127.0.0.1', port });
    const chunks = [];
    sock.on('connect', () => {

        sock.write(requestBytes);
        if (closeAfterWrite) sock.end();

    });
    sock.on('data', (d) => chunks.push(d));
    sock.on('end', () => resolve(Buffer.concat(chunks)));
    sock.on('error', reject);

});

// ----- Persistent-session request loop -----

describe('v2-site/server — request loop', function () {

    this.timeout(5000);
    let server;

    afterEach(async () => {

        if (server) { await server.close(); server = null; }

    });

    it('answers a single valid request and stays open for more', async () => {

        let count = 0;
        server = await startServer(async () => {

            count += 1;
            return { status: STATUS_SUCCESS, meta: 'text/plain', body: new Uint8Array([0x68, 0x69]) }; // 'hi'

        });
        // Send two requests on one connection.
        const url = `anon://${ONION}/`;
        const req = `${url}\r\n${url}\r\n`;
        const buf = await sendAndCollect({
            port: server.port,
            requestBytes: Buffer.from(req),
        });
        // We expect two response heads back-to-back.
        const first = parseResponseHead(buf);
        expect(first.status).to.equal(STATUS_SUCCESS);
        const afterFirstHead = buf.subarray(first.headEnd);
        // The first response body is 2 bytes ('hi'); then the second head.
        const second = parseResponseHead(afterFirstHead.subarray(2));
        expect(second.status).to.equal(STATUS_SUCCESS);
        expect(count).to.equal(2);

    });

    it('returns BAD_REQUEST + closes on malformed URL', async () => {

        server = await startServer(async () => ({
            status: STATUS_SUCCESS, meta: 'text/plain', body: new Uint8Array(0),
        }));
        const buf = await sendAndCollect({
            port: server.port,
            requestBytes: Buffer.from('https://example.com/\r\n'),
        });
        const parsed = parseResponseHead(buf);
        expect(parsed.status).to.equal(STATUS_BAD_REQUEST);

    });

    it('returns BAD_REQUEST on oversized request', async () => {

        server = await startServer(async () => ({
            status: STATUS_SUCCESS, meta: 'text/plain', body: new Uint8Array(0),
        }));
        // 3000 bytes of junk, no CRLF — server should give up.
        const junk = Buffer.alloc(3000).fill(0x61);
        const buf = await sendAndCollect({
            port: server.port, requestBytes: junk,
        });
        const parsed = parseResponseHead(buf);
        expect(parsed.status).to.equal(STATUS_BAD_REQUEST);

    });

    it('returns PERMANENT_FAILURE when the handler throws', async () => {

        server = await startServer(async () => {

            throw new Error('oops');

        });
        const buf = await sendAndCollect({
            port: server.port,
            requestBytes: Buffer.from(`anon://${ONION}/\r\n`),
        });
        const parsed = parseResponseHead(buf);
        expect(parsed.status).to.equal(STATUS_PERMANENT_FAILURE);

    });

});

// ----- Static-file handler -----

describe('v2-site/server — static handler', function () {

    this.timeout(5000);
    let root;
    let server;

    beforeEach(async () => {

        root = await mkdtemp(join(tmpdir(), 'anon-site-'));
        await writeFile(join(root, 'index.anon'), '# Hello\n\nWelcome\n');
        await mkdir(join(root, 'sub'));
        await writeFile(join(root, 'sub', 'a.txt'), 'plain text');
        await writeFile(join(root, 'sub', 'index.anon'), '# Sub index\n');
        await writeFile(join(root, 'small.bin'), Buffer.from([0, 1, 2, 3]));
        const handler = createStaticHandler({ root });
        server = await startServer(handler);

    });

    afterEach(async () => {

        if (server) { await server.close(); server = null; }
        if (root) { await rm(root, { recursive: true, force: true }); root = null; }

    });

    const fetch = (path) => sendAndCollect({
        port: server.port,
        requestBytes: Buffer.from(`anon://${ONION}${path}\r\n`),
    });

    it('serves the root index.anon for "/"', async () => {

        const buf = await fetch('/');
        const head = parseResponseHead(buf);
        expect(head.status).to.equal(STATUS_SUCCESS);
        expect(head.meta).to.contain('text/anon; charset=utf-8');
        expect(head.meta).to.contain('length=');
        const body = buf.subarray(head.headEnd);
        expect(body.toString('utf8')).to.contain('Welcome');

    });

    it('serves a subdirectory index when path resolves to a directory', async () => {

        const buf = await fetch('/sub/');
        const head = parseResponseHead(buf);
        expect(head.status).to.equal(STATUS_SUCCESS);
        const body = buf.subarray(head.headEnd);
        expect(body.toString('utf8')).to.contain('Sub index');

    });

    it('serves a plain file with correct MIME type', async () => {

        const buf = await fetch('/sub/a.txt');
        const head = parseResponseHead(buf);
        expect(head.status).to.equal(STATUS_SUCCESS);
        expect(head.meta).to.contain('text/plain; charset=utf-8');

    });

    it('serves a binary file with explicit length', async () => {

        const buf = await fetch('/small.bin');
        const head = parseResponseHead(buf);
        expect(head.status).to.equal(STATUS_SUCCESS);
        expect(head.meta).to.contain('application/octet-stream');
        expect(head.meta).to.contain('length=4');

    });

    it('returns NOT_FOUND for missing file', async () => {

        const buf = await fetch('/does/not/exist');
        const head = parseResponseHead(buf);
        expect(head.status).to.equal(STATUS_NOT_FOUND);

    });

    it('returns NOT_FOUND for path-traversal attempt', async () => {

        const buf = await fetch('/../../../etc/passwd');
        const head = parseResponseHead(buf);
        expect(head.status).to.equal(STATUS_NOT_FOUND);

    });

    it('returns NOT_FOUND for percent-encoded traversal attempt', async () => {

        // %2e%2e is `..`
        const buf = await fetch('/%2e%2e/%2e%2e/etc/passwd');
        const head = parseResponseHead(buf);
        expect(head.status).to.equal(STATUS_NOT_FOUND);

    });

});
