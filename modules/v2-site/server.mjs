// v2-site — PRE-AUDIT EXPERIMENTAL CODE
//
// Anon-site protocol codec, see docs/SITES-v0.1.md.
// The draft has open architectural questions; the code has not been
// audited. Do not rely on this for anonymity or content authenticity
// beyond what the v0.2 transport already provides.

// Anon-site server framework.
//
// `handleConnection({socket, requestHandler})` runs the persistent-
// session request loop on a duplex stream. The handler is async and
// returns the response object. The framework handles framing,
// malformed-input rejection, and graceful shutdown.
//
// In production this sits BENEATH a v0.2-transport stream; for the
// reference implementation we wire it up to plain TCP via
// bin/anon-site-server.mjs so the protocol can be demoed today.

import { stat, readFile } from 'node:fs/promises';
import { resolve, normalize, join, extname, sep } from 'node:path';

import {
    parseRequest,
    MAX_REQUEST_BYTES,
} from './request.mjs';
import {
    buildResponse,
    STATUS_SUCCESS,
    STATUS_NOT_FOUND,
    STATUS_BAD_REQUEST,
    STATUS_PERMANENT_FAILURE,
} from './response.mjs';

// ----- Persistent-session request loop -----

// Wire `handleConnection` to a duplex stream. The stream MUST emit
// 'data', 'end', 'error' and have a writable side. For TCP usage,
// the underlying server MUST be created with `allowHalfOpen: true` —
// otherwise Node auto-ends the writable side when the readable side
// sees FIN, which silently drops responses written by async handlers
// (stat, readFile) that complete after the FIN arrives.
//
// `requestHandler({url, host, path, query})` is async and returns
// `{status, meta, body?}` — body is a Uint8Array for SUCCESS or null
// for other statuses.
//
// Returns a Promise that resolves when the connection closes.
export const handleConnection = ({ socket, requestHandler }) => new Promise((resolve) => {

    let buffer = Buffer.alloc(0);
    let busy = false;       // mid-handler; defer next-request parsing
    let closing = false;    // we've initiated close on our write side
    let peerClosed = false; // peer sent FIN; we may still have in-flight writes

    // Close our write side IFF:
    //   - peer has half-closed (no more requests coming)
    //   - no handler is currently in flight
    //   - the input buffer has no pending request
    //   - we haven't already closed
    const maybeClose = () => {

        if (closing) return;
        if (!peerClosed) return;
        if (busy) return;
        if (buffer.length > 0) return;
        closing = true;
        try { socket.end(); } catch { /* ignore */ }

    };

    // Send a response. Optionally force-close after (used for BAD_REQUEST etc).
    const sendResponse = (response, forceClose = false) => {

        if (closing) return;
        try { socket.write(response); } catch { /* ignore */ }
        if (forceClose) {

            closing = true;
            try { socket.end(); } catch { /* ignore */ }

        }

    };

    const processBuffer = async () => {

        if (busy || closing) return;

        while (buffer.length > 0 && !busy && !closing) {

            const parsed = parseRequest(buffer);
            if (parsed === null) break; // incomplete; await more data

            if (parsed.error) {

                const meta = parsed.error === 'too-long' ? 'request too long' : 'bad request';
                sendResponse(
                    buildResponse({ status: STATUS_BAD_REQUEST, meta }),
                    /* forceClose */ true,
                );
                return;

            }

            // Advance past the CRLF terminator.
            let crlfEnd = -1;
            for (let i = 0; i + 1 < buffer.length; i += 1) {

                if (buffer[i] === 0x0D && buffer[i + 1] === 0x0A) {

                    crlfEnd = i + 2;
                    break;

                }

            }
            if (crlfEnd === -1) break; // shouldn't happen if parse succeeded
            buffer = buffer.subarray(crlfEnd);

            busy = true;
            let response;
            try {

                response = await requestHandler(parsed);

            } catch {

                response = {
                    status: STATUS_PERMANENT_FAILURE,
                    meta: 'internal server error',
                    body: null,
                };

            }
            busy = false;

            sendResponse(buildResponse(response));

        }
        maybeClose();

    };

    socket.on('data', (chunk) => {

        if (closing) return;
        buffer = Buffer.concat([buffer, chunk]);
        if (buffer.length > MAX_REQUEST_BYTES * 2) {

            // Some headroom over MAX_REQUEST_BYTES so a request that
            // straddles a chunk boundary still parses; beyond that, no
            // valid client is sending this much without intervening
            // CRLFs. Treat as adversarial.
            sendResponse(
                buildResponse({ status: STATUS_BAD_REQUEST, meta: 'request too long' }),
                /* forceClose */ true,
            );
            return;

        }
        processBuffer().catch(() => {});

    });

    socket.on('end', () => {

        // Peer's done sending. We may still have requests in the
        // buffer or a handler in flight; let those complete, then
        // close via maybeClose().
        peerClosed = true;
        if (!busy) processBuffer().catch(() => {}); // triggers maybeClose at the end
        else maybeClose();

    });
    socket.on('error', () => {

        closing = true;
        resolve();

    });
    socket.on('close', () => resolve());

});

// ----- Static-file handler -----

// MIME-type registry by extension. Conservative — defaults to
// application/octet-stream for anything unknown.
const MIME_BY_EXT = {
    '.anon':  'text/anon; charset=utf-8',
    '.txt':   'text/plain; charset=utf-8',
    '.md':    'text/plain; charset=utf-8',
    '.json':  'application/json; charset=utf-8',
    '.png':   'image/png',
    '.jpg':   'image/jpeg',
    '.jpeg':  'image/jpeg',
    '.gif':   'image/gif',
    '.svg':   'image/svg+xml',
    '.pdf':   'application/pdf',
    '.bin':   'application/octet-stream',
};

const mimeFor = (filename) => {

    const ext = extname(filename).toLowerCase();
    return MIME_BY_EXT[ext] || 'application/octet-stream';

};

// Validate a path is safely contained within `root`. Returns the
// resolved absolute path or null on traversal attempts / suspicious
// inputs.
const resolveSafe = (root, requestPath) => {

    // Decode percent-encoding; reject if anything decodes to a
    // path-traversal character we didn't expect.
    let decoded;
    try {

        decoded = decodeURIComponent(requestPath);

    } catch {

        return null;

    }

    // Strip leading slash so resolve() works against root.
    const rel = decoded.replace(/^\/+/, '');
    if (rel.length === 0) return root;

    // Reject NUL bytes outright (some platforms truncate paths at \0).
    if (rel.includes('\0')) return null;

    const candidate = resolve(join(root, rel));
    const rootResolved = resolve(root);
    // Containment check: candidate must be root, or start with root + separator.
    if (candidate !== rootResolved && !candidate.startsWith(rootResolved + sep)) {

        return null;

    }
    return candidate;

};

// Create a request handler that serves files under `root`.
//
// Options:
//   indexFile — file name to serve when the requested path resolves
//               to a directory. Default 'index.anon'.
//   maxBodyBytes — refuse files larger than this. Default 10 MiB.
//                  (No streaming response in v0.1; the whole body
//                  must fit in memory before send.)
export const createStaticHandler = ({
    root,
    indexFile = 'index.anon',
    maxBodyBytes = 10 * 1024 * 1024,
} = {}) => {

    if (typeof root !== 'string' || root.length === 0) {

        throw new Error('root must be a non-empty path');

    }
    const rootResolved = resolve(root);

    return async ({ path }) => {

        const safePath = resolveSafe(rootResolved, path || '/');
        if (safePath === null) {

            return { status: STATUS_NOT_FOUND, meta: 'not found', body: null };

        }

        let info;
        try { info = await stat(safePath); } catch { /* fall through to 404 */ }
        if (!info) {

            return { status: STATUS_NOT_FOUND, meta: 'not found', body: null };

        }

        let filePath = safePath;
        if (info.isDirectory()) {

            filePath = join(safePath, indexFile);
            try { info = await stat(filePath); } catch { info = null; }
            if (!info || !info.isFile()) {

                return { status: STATUS_NOT_FOUND, meta: 'not found', body: null };

            }

        } else if (!info.isFile()) {

            // Symlinks to non-files, devices, etc.
            return { status: STATUS_NOT_FOUND, meta: 'not found', body: null };

        }

        if (info.size > maxBodyBytes) {

            return {
                status: STATUS_PERMANENT_FAILURE,
                meta: `resource too large (${info.size} > ${maxBodyBytes})`,
                body: null,
            };

        }

        const body = new Uint8Array(await readFile(filePath));
        const mime = mimeFor(filePath);
        // Always include length so clients can correctly delimit the
        // body on persistent sessions (§ 5.2): omitting length is only
        // safe when the session closes at end of response, and we
        // don't know that at the handler level.
        const meta = `${mime}; length=${body.length}`;
        return { status: STATUS_SUCCESS, meta, body };

    };

};
