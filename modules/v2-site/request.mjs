// v2-site — PRE-AUDIT EXPERIMENTAL CODE
//
// Anon-site protocol codec, see docs/SITES-v0.1.md.
// The draft has open architectural questions; the code has not been
// audited. Do not rely on this for anonymity or content authenticity
// beyond what the v0.2 transport already provides.

// Request codec for SITES-v0.1 § 4.1.
//
// A request is a single UTF-8 line: <URL>\r\n. URL MUST be ≤ 1024
// bytes total. The server reads until \r\n is received OR 1024
// bytes have been consumed without \r\n; in the latter case the
// server returns status 59 (BAD_REQUEST) per § 5.5.

import { decodeOnionAddress } from '../v2/onion_address.mjs';

export const MAX_REQUEST_BYTES = 1024;
const CR = 0x0D;
const LF = 0x0A;

export const URL_SCHEME = 'anon://';

// Build a request line for `url`. Returns Uint8Array of UTF-8 bytes
// terminated by CR LF.
//
// Throws on:
//   - URL exceeds MAX_REQUEST_BYTES (after CR LF)
//   - URL is not anon:// scheme
//   - onion address (host part) is not a valid `.anon` address
//   - URL contains a fragment (#…) or userinfo (user@) or port (:N)
export const buildRequest = (url) => {

    if (typeof url !== 'string') throw new Error('url must be a string');
    if (!url.startsWith(URL_SCHEME)) {

        throw new Error(`url must use ${URL_SCHEME} scheme`);

    }

    if (url.includes('#')) {

        throw new Error('URL fragments are not permitted; client-local concern');

    }
    if (url.includes('@')) {

        throw new Error('URL userinfo is not permitted');

    }

    // Extract host portion to validate as .anon address.
    const afterScheme = url.slice(URL_SCHEME.length);
    const slashIdx = afterScheme.indexOf('/');
    const queryIdx = afterScheme.indexOf('?');
    let hostEnd = afterScheme.length;
    if (slashIdx !== -1) hostEnd = Math.min(hostEnd, slashIdx);
    if (queryIdx !== -1) hostEnd = Math.min(hostEnd, queryIdx);
    const host = afterScheme.slice(0, hostEnd);

    if (host.includes(':')) {

        throw new Error('explicit ports are not permitted; anon:// has no transport port');

    }
    if (!decodeOnionAddress(host)) {

        throw new Error(`URL host is not a valid .anon address: ${host}`);

    }

    const encoded = new TextEncoder().encode(url);
    if (encoded.length + 2 > MAX_REQUEST_BYTES) {

        throw new Error(`URL exceeds ${MAX_REQUEST_BYTES - 2} bytes`);

    }

    const buf = new Uint8Array(encoded.length + 2);
    buf.set(encoded, 0);
    buf[encoded.length]     = CR;
    buf[encoded.length + 1] = LF;
    return buf;

};

// Parse a request from a buffer. Returns:
//   { url }                                — success, URL is valid
//   null                                   — incomplete; caller should
//                                            keep reading until either
//                                            \r\n arrives OR
//                                            MAX_REQUEST_BYTES seen
//   { error: 'too-long' }                  — > 1024 bytes without \r\n
//                                            (caller MUST return 59)
//   { error: 'malformed-url' }             — URL is not parseable
//                                            (caller MUST return 59)
//
// `bytesAvailable` is the bytes the caller has accumulated so far on
// the stream. The parser returns null when it has not yet seen \r\n
// AND the buffer length is below MAX_REQUEST_BYTES.
export const parseRequest = (bytesAvailable) => {

    if (!(bytesAvailable instanceof Uint8Array)) return { error: 'malformed-url' };

    // Find CR LF.
    let terminator = -1;
    for (let i = 0; i + 1 < bytesAvailable.length; i += 1) {

        if (bytesAvailable[i] === CR && bytesAvailable[i + 1] === LF) {

            terminator = i;
            break;

        }

    }

    if (terminator === -1) {

        if (bytesAvailable.length >= MAX_REQUEST_BYTES) {

            return { error: 'too-long' };

        }
        return null; // incomplete

    }

    if (terminator + 2 > MAX_REQUEST_BYTES) {

        return { error: 'too-long' };

    }

    const url = new TextDecoder('utf-8', { fatal: true })
        .decode(bytesAvailable.subarray(0, terminator));

    // Validate.
    if (!url.startsWith(URL_SCHEME)) return { error: 'malformed-url' };
    if (url.includes('#')) return { error: 'malformed-url' };
    if (url.includes('@')) return { error: 'malformed-url' };

    const afterScheme = url.slice(URL_SCHEME.length);
    const slashIdx = afterScheme.indexOf('/');
    const queryIdx = afterScheme.indexOf('?');
    let hostEnd = afterScheme.length;
    if (slashIdx !== -1) hostEnd = Math.min(hostEnd, slashIdx);
    if (queryIdx !== -1) hostEnd = Math.min(hostEnd, queryIdx);
    const host = afterScheme.slice(0, hostEnd);

    if (host.includes(':')) return { error: 'malformed-url' };
    if (!decodeOnionAddress(host)) return { error: 'malformed-url' };

    return {
        url,
        host,
        path: slashIdx === -1 ? '/' : afterScheme.slice(slashIdx, queryIdx === -1 ? undefined : queryIdx),
        query: queryIdx === -1 ? null : afterScheme.slice(queryIdx + 1),
    };

};
