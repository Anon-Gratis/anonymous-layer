#!/usr/bin/env node
// Reference anon-site server (PRE-AUDIT EXPERIMENTAL).
//
// Serves files from a directory over plain TCP. In a production
// deployment this would sit BENEATH the v0.2 anon-layer transport;
// for now it accepts plain TCP so the protocol can be demoed today.

import { createServer } from 'node:net';
import { resolve } from 'node:path';

import {
    handleConnection,
    createStaticHandler,
} from '../modules/v2-site/server.mjs';

const USAGE = `\
anon-site-server — serve a directory over the anon-site protocol (PRE-AUDIT)

Usage:
  anon-site-server <root-dir> [--port N] [--host H] [--quiet]

  root-dir   Directory to serve. An 'index.anon' at any directory
             level is served when the request resolves to a directory.
  --port N   Listen port (default 1965, matching Gemini's port).
  --host H   Listen address (default 127.0.0.1).
  --quiet    Suppress per-request logging.

NOTE: This serves over plain TCP. The anon-site protocol is designed
to ride on top of a v0.2 anon-layer session, which provides identity
authentication and end-to-end encryption. Running over plain TCP gives
NEITHER. Use only for demos / local development.
`;

const die = (msg, code = 1) => {

    process.stderr.write(`error: ${msg}\n`);
    process.exit(code);

};

const main = async () => {

    const args = process.argv.slice(2);
    if (args.length === 0) { process.stdout.write(USAGE); process.exit(0); }

    let root = null;
    let port = 1965;
    let host = '127.0.0.1';
    let quiet = false;

    for (let i = 0; i < args.length; i += 1) {

        const a = args[i];
        if (a === '--port') { port = parseInt(args[i + 1], 10); i += 1; continue; }
        if (a === '--host') { host = args[i + 1]; i += 1; continue; }
        if (a === '--quiet') { quiet = true; continue; }
        if (a.startsWith('--')) die(`unknown option: ${a}`);
        if (root === null) { root = a; continue; }
        die(`unexpected argument: ${a}`);

    }
    if (root === null) die('root directory is required');
    if (!Number.isInteger(port) || port < 0 || port > 65535) die(`bad port: ${port}`);

    const rootResolved = resolve(root);
    const handler = createStaticHandler({ root: rootResolved });

    // allowHalfOpen: true so async handlers can write responses after
    // the peer half-closes; without this Node auto-ends the writable
    // side on FIN and the response gets silently dropped.
    const server = createServer({ allowHalfOpen: true }, (socket) => {

        const remote = `${socket.remoteAddress}:${socket.remotePort}`;
        handleConnection({
            socket,
            requestHandler: async (req) => {

                const response = await handler(req);
                if (!quiet) {

                    process.stderr.write(
                        `[${new Date().toISOString()}] ${remote} `
                        + `${req.url} → ${response.status}\n`,
                    );

                }
                return response;

            },
        }).catch(() => {});

    });

    server.on('error', (err) => die(`listener error: ${err.message}`));
    server.listen(port, host, () => {

        const addr = server.address();
        process.stderr.write(
            `[${new Date().toISOString()}] anon-site-server on ${addr.address}:${addr.port}, `
            + `root=${rootResolved}\n`,
        );
        process.stderr.write(
            'WARNING: serving over plain TCP, no identity authentication or transport encryption.\n',
        );

    });

    const shutdown = () => {

        process.stderr.write(`\n[${new Date().toISOString()}] shutting down\n`);
        server.close(() => process.exit(0));

    };
    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);

};

main().catch((err) => die(err.stack || err.message));
