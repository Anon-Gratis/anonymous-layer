#!/usr/bin/env node
// Reference anon-site CLI client (PRE-AUDIT EXPERIMENTAL).
//
// Fetches an anon:// URL over plain TCP and renders the response.
// In production this would ride on a v0.2 anon-layer session; for
// now it dials TCP directly using --connect host:port.

import { createConnection } from 'node:net';
import { createInterface } from 'node:readline';

import { fetchWithRedirects } from '../modules/v2-site/client.mjs';
import { parseSuccessMeta, isSuccess } from '../modules/v2-site/response.mjs';
import { parseDocument } from '../modules/v2-site/text_anon.mjs';
import { renderToString } from '../modules/v2-site/renderer.mjs';

const USAGE = `\
anon-site-client — fetch and render an anon:// URL (PRE-AUDIT)

Usage:
  anon-site-client <url> --connect <host:port> [--no-color] [--raw]

  url                     anon:// URL to fetch
  --connect host:port     TCP host:port of the anon-site server
                          (production would resolve the .anon address
                          via a v0.2 anon-layer rendezvous; for the
                          reference impl, you supply the dial target)
  --no-color              Don't emit ANSI colour escapes
  --raw                   Print the body verbatim (no rendering)

Status: status codes other than 20 SUCCESS are reported on stderr.
Body is printed to stdout.
`;

const die = (msg, code = 1) => {

    process.stderr.write(`error: ${msg}\n`);
    process.exit(code);

};

const promptUser = ({ prompt, sensitive }) => new Promise((resolve) => {

    const rl = createInterface({
        input: process.stdin, output: process.stderr,
    });
    if (sensitive) {

        // Crude no-echo: not a real terminal-secret prompt, just a
        // visible note. A production client would use a proper
        // password-prompt library.
        process.stderr.write('(sensitive input; visible on this terminal)\n');

    }
    rl.question(`${prompt} `, (answer) => { rl.close(); resolve(answer); });

});

const main = async () => {

    const args = process.argv.slice(2);
    if (args.length === 0) { process.stdout.write(USAGE); process.exit(0); }

    let url = null;
    let connectArg = null;
    let color = process.stdout.isTTY === true;
    let raw = false;

    for (let i = 0; i < args.length; i += 1) {

        const a = args[i];
        if (a === '--connect') { connectArg = args[i + 1]; i += 1; continue; }
        if (a === '--no-color') { color = false; continue; }
        if (a === '--raw') { raw = true; continue; }
        if (a.startsWith('--')) die(`unknown option: ${a}`);
        if (url === null) { url = a; continue; }
        die(`unexpected argument: ${a}`);

    }
    if (url === null) die('url is required');
    if (connectArg === null) {

        die('--connect host:port is required (no v0.2 transport resolver yet)');

    }
    const [hostStr, portStr] = connectArg.split(':');
    const port = parseInt(portStr, 10);
    if (!hostStr || !Number.isInteger(port)) die(`bad --connect value: ${connectArg}`);

    const connect = () => new Promise((res, rej) => {

        const sock = createConnection({ host: hostStr, port });
        sock.once('connect', () => res(sock));
        sock.once('error', rej);

    });

    let response;
    try {

        response = await fetchWithRedirects({
            connect,
            url,
            maxRedirects: 5,
            onInput: promptUser,
        });

    } catch (err) {

        die(err.message);

    }

    process.stderr.write(`${response.status} ${response.meta}\n`);

    if (!isSuccess(response.status) || response.body === null) {

        process.exit(response.status === 20 ? 0 : 1);

    }

    if (raw) {

        process.stdout.write(response.body);
        return;

    }

    const mime = parseSuccessMeta(response.meta);
    const mimeType = mime ? mime.mimeType : 'application/octet-stream';

    if (mimeType === 'text/anon') {

        const text = new TextDecoder('utf-8', { fatal: false })
            .decode(response.body);
        process.stdout.write(`${renderToString(parseDocument(text), { color })}\n`);

    } else if (mimeType.startsWith('text/')) {

        process.stdout.write(new TextDecoder('utf-8', { fatal: false }).decode(response.body));

    } else {

        process.stderr.write(`binary body (${mimeType}, ${response.body.length} bytes); use --raw to dump\n`);

    }

};

main().catch((err) => die(err.stack || err.message));
