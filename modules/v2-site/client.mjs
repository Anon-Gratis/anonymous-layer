// v2-site — PRE-AUDIT EXPERIMENTAL CODE
//
// Anon-site protocol codec, see docs/SITES-v0.1.md.
// The draft has open architectural questions; the code has not been
// audited. Do not rely on this for anonymity or content authenticity
// beyond what the v0.2 transport already provides.

// Anon-site client.
//
// `fetchOnce({socket, url})` sends a single request, reads the
// response, and resolves with `{ status, meta, body }`. The caller
// owns the socket; this function does NOT open or close it (so a
// caller can pipeline multiple requests on a persistent session).
//
// `fetchWithRedirects({connect, url, maxRedirects, onInput})` is the
// higher-level helper used by the CLI: it opens a fresh socket per
// request, follows REDIRECT statuses up to a limit, and surfaces
// INPUT prompts via the `onInput` callback.

import { buildRequest } from './request.mjs';
import {
    parseResponseHead,
    parseSuccessMeta,
    isSuccess,
    isRedirect,
    isInput,
} from './response.mjs';

// ----- Low-level: fetch one response on an open duplex stream -----

export const fetchOnce = ({ socket, url, timeoutMs = 30000 }) => new Promise((resolve, reject) => {

    let buffer = Buffer.alloc(0);
    let head = null;        // parsed response head once available
    let bodyBytesNeeded = null; // total body bytes expected (null if streaming-to-end)
    let bodySoFar = Buffer.alloc(0);
    let resolved = false;
    let timer = null;

    const cleanup = () => {

        socket.removeListener('data', onData);
        socket.removeListener('end', onEnd);
        socket.removeListener('error', onError);
        if (timer) clearTimeout(timer);

    };
    const succeed = (result) => {

        if (resolved) return;
        resolved = true;
        cleanup();
        resolve(result);

    };
    const fail = (err) => {

        if (resolved) return;
        resolved = true;
        cleanup();
        reject(err);

    };

    const onData = (chunk) => {

        buffer = Buffer.concat([buffer, chunk]);
        tryAdvance();

    };
    const onEnd = () => {

        // If we already have the head, surface what body we got.
        if (head !== null) {

            if (bodyBytesNeeded === null) {

                // text/* without explicit length — body ends at stream end.
                succeed({ status: head.status, meta: head.meta, body: new Uint8Array(bodySoFar) });

            } else if (bodySoFar.length === bodyBytesNeeded) {

                succeed({ status: head.status, meta: head.meta, body: new Uint8Array(bodySoFar) });

            } else {

                fail(new Error(`stream ended with ${bodySoFar.length}/${bodyBytesNeeded} body bytes`));

            }
            return;

        }
        fail(new Error('connection closed before response head arrived'));

    };
    const onError = (err) => fail(err);

    const tryAdvance = () => {

        if (head === null) {

            const r = parseResponseHead(buffer);
            if (r === null) return;
            if (r.error) return fail(new Error(`malformed response head: ${r.error}`));
            head = { status: r.status, meta: r.meta };
            // Consume head bytes.
            bodySoFar = Buffer.alloc(0);
            const rest = buffer.subarray(r.headEnd);
            buffer = Buffer.alloc(0);
            if (rest.length > 0) bodySoFar = Buffer.from(rest);
            // For SUCCESS, determine if body has explicit length.
            if (isSuccess(head.status)) {

                const parsed = parseSuccessMeta(head.meta);
                if (parsed && parsed.parameters.length !== undefined) {

                    const n = parseInt(parsed.parameters.length, 10);
                    if (Number.isInteger(n) && n >= 0) bodyBytesNeeded = n;

                }
                // else: no length; body ends at stream end.

            } else {

                // Non-SUCCESS responses have no body — resolve immediately.
                succeed({ status: head.status, meta: head.meta, body: null });
                return;

            }

        }

        // We have a head; move any pending bytes from `buffer` into
        // `bodySoFar`. The head-parsing branch above only consumes
        // `buffer` on the *first* tryAdvance — subsequent chunks land
        // here in `buffer` and need to be folded in before we can
        // detect completion. (Real network paths fragment the response
        // across cells; the in-process unit-test happens to deliver
        // everything in one chunk and therefore never hit this path.)
        if (buffer.length > 0) {

            bodySoFar = Buffer.concat([bodySoFar, buffer]);
            buffer = Buffer.alloc(0);

        }

        if (bodyBytesNeeded !== null && bodySoFar.length >= bodyBytesNeeded) {

            succeed({
                status: head.status,
                meta: head.meta,
                body: new Uint8Array(bodySoFar.subarray(0, bodyBytesNeeded)),
            });

        }

    };

    socket.on('data', onData);
    socket.once('end', onEnd);
    socket.once('error', onError);
    if (timeoutMs > 0) {

        timer = setTimeout(() => fail(new Error('fetchOnce timeout')), timeoutMs);

    }

    // Send the request.
    try {

        socket.write(buildRequest(url));

    } catch (err) {

        fail(err);

    }

});

// ----- Higher-level: fetch + follow redirects -----

// `connect({host, port})` is a Promise-returning function the caller
// provides; it opens a duplex stream to the destination. The client
// uses this to open a fresh connection per redirect hop (anon-site is
// session-based but redirects often land on different services).
//
// `onInput({prompt, sensitive})` is an async callback returning the
// user's response string for INPUT/SENSITIVE_INPUT statuses, or null
// to cancel. If omitted, INPUT statuses are returned as-is.
//
// Returns the final response or throws on redirect-loop / failure.
export const fetchWithRedirects = async ({
    connect,
    url,
    maxRedirects = 5,
    onInput = null,
}) => {

    let currentUrl = url;
    const visited = [currentUrl];

    for (let hop = 0; hop <= maxRedirects; hop += 1) {

        const socket = await connect(parseHostFromUrl(currentUrl));
        let response;
        try {

            response = await fetchOnce({ socket, url: currentUrl });

        } finally {

            try { socket.end(); } catch { /* ignore */ }

        }

        if (isRedirect(response.status)) {

            const nextUrl = response.meta.trim();
            if (visited.includes(nextUrl)) {

                throw new Error(`redirect loop: ${nextUrl} already visited`);

            }
            visited.push(nextUrl);
            currentUrl = nextUrl;
            continue;

        }

        if (isInput(response.status) && onInput) {

            const sensitive = response.status === 11;
            const userInput = await onInput({
                prompt: response.meta,
                sensitive,
            });
            if (userInput === null || userInput === undefined) {

                return response; // user cancelled; surface the INPUT status

            }
            // Re-send the request with the user input encoded in the query.
            const newUrl = appendQuery(currentUrl, userInput);
            visited.push(newUrl);
            currentUrl = newUrl;
            continue;

        }

        return response;

    }

    throw new Error(`exceeded ${maxRedirects} redirects`);

};

// Helper: extract host (and implicit port) from an anon:// URL. For
// the reference impl we map .anon → host:port via a caller-supplied
// resolver; here we just split the URL.
//
// Returns { host, port }. Default port from the URL parser; the
// caller's connect() function decides how to actually dial.
const parseHostFromUrl = (url) => {

    const after = url.slice('anon://'.length);
    const slash = after.indexOf('/');
    const query = after.indexOf('?');
    let hostEnd = after.length;
    if (slash !== -1) hostEnd = Math.min(hostEnd, slash);
    if (query !== -1) hostEnd = Math.min(hostEnd, query);
    return { host: after.slice(0, hostEnd), port: null };

};

const appendQuery = (url, query) => {

    const encoded = encodeURIComponent(query);
    return url.includes('?') ? `${url}&${encoded}` : `${url}?${encoded}`;

};
