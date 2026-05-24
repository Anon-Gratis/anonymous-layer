// v2-site — PRE-AUDIT EXPERIMENTAL CODE
//
// Anon-site protocol codec, see docs/SITES-v0.1.md.
// The draft has open architectural questions; the code has not been
// audited. Do not rely on this for anonymity or content authenticity
// beyond what the v0.2 transport already provides.

// Response codec for SITES-v0.1 § 4.2.
//
// A response is:
//   <STATUS> <META>\r\n
//   [<body bytes>]
//
// STATUS is two ASCII digits 10..69. SP is space (0x20). META is
// UTF-8 up to 1024 bytes. Body is present only for 2x statuses.

export const MAX_META_BYTES = 1024;
const CR = 0x0D;
const LF = 0x0A;
const SP = 0x20;

// Status code categories.
export const STATUS_INPUT             = 10;
export const STATUS_SENSITIVE_INPUT   = 11;
export const STATUS_SUCCESS           = 20;
export const STATUS_REDIRECT_TEMP     = 30;
export const STATUS_REDIRECT_PERM     = 31;
export const STATUS_TEMPORARY_FAILURE = 40;
export const STATUS_SERVER_UNAVAIL    = 41;
export const STATUS_CGI_ERROR         = 42;
export const STATUS_PROXY_ERROR       = 43;
export const STATUS_SLOW_DOWN         = 44;
export const STATUS_PERMANENT_FAILURE = 50;
export const STATUS_NOT_FOUND         = 51;
export const STATUS_GONE              = 52;
export const STATUS_PROXY_REFUSED     = 53;
export const STATUS_BAD_REQUEST       = 59;

export const isSuccess  = (status) => status >= 20 && status <= 29;
export const isRedirect = (status) => status >= 30 && status <= 39;
export const isInput    = (status) => status >= 10 && status <= 19;
export const isTempFail = (status) => status >= 40 && status <= 49;
export const isPermFail = (status) => status >= 50 && status <= 59;
export const isReserved = (status) => status >= 60 && status <= 69;

export const isValidStatus = (status) => Number.isInteger(status)
    && status >= 10 && status <= 69;

// Build a response head (everything up to and including the CRLF
// after META). Returns Uint8Array. The caller appends the body bytes
// separately if applicable.
export const buildResponseHead = ({ status, meta }) => {

    if (!isValidStatus(status)) {

        throw new Error(`invalid status code: ${status}`);

    }
    if (typeof meta !== 'string') throw new Error('meta must be a string');

    const metaBytes = new TextEncoder().encode(meta);
    if (metaBytes.length > MAX_META_BYTES) {

        throw new Error(`META exceeds ${MAX_META_BYTES} bytes`);

    }
    // META MUST NOT contain CR or LF — the line terminator is unique.
    for (const b of metaBytes) {

        if (b === CR || b === LF) {

            throw new Error('META MUST NOT contain CR or LF');

        }

    }

    const statusStr = status.toString().padStart(2, '0');
    const statusBytes = new TextEncoder().encode(statusStr);

    const buf = new Uint8Array(statusBytes.length + 1 + metaBytes.length + 2);
    buf.set(statusBytes, 0);
    buf[statusBytes.length] = SP;
    buf.set(metaBytes, statusBytes.length + 1);
    buf[statusBytes.length + 1 + metaBytes.length]     = CR;
    buf[statusBytes.length + 1 + metaBytes.length + 1] = LF;
    return buf;

};

// Convenience: build a full response (head + body). For SUCCESS
// responses, body is the body bytes; for non-success, body is ignored.
export const buildResponse = ({ status, meta, body = null }) => {

    const head = buildResponseHead({ status, meta });
    if (!isSuccess(status) || body === null) return head;
    if (!(body instanceof Uint8Array)) {

        throw new Error('body must be a Uint8Array (or null)');

    }
    const out = new Uint8Array(head.length + body.length);
    out.set(head, 0);
    out.set(body, head.length);
    return out;

};

// Parse a response head from a buffer. Returns:
//   { status, meta, headEnd }              — success, body (if any)
//                                            begins at buffer[headEnd]
//   null                                   — incomplete; caller keeps reading
//   { error: 'too-long' }                  — META region > 1024 bytes
//                                            without CR LF
//   { error: 'malformed' }                 — structural error
//
// headEnd is the index just past the CR LF terminator — the first
// byte of any body bytes the caller has already received.
export const parseResponseHead = (bytesAvailable) => {

    if (!(bytesAvailable instanceof Uint8Array)) return { error: 'malformed' };

    // Find CR LF.
    let terminator = -1;
    for (let i = 0; i + 1 < bytesAvailable.length; i += 1) {

        if (bytesAvailable[i] === CR && bytesAvailable[i + 1] === LF) {

            terminator = i;
            break;

        }

    }

    if (terminator === -1) {

        // Reasonable upper bound on a head: 2 (status) + 1 (sp) + 1024 (meta) + 2 (crlf) = 1029
        if (bytesAvailable.length > 2 + 1 + MAX_META_BYTES + 2) {

            return { error: 'too-long' };

        }
        return null;

    }

    if (terminator < 3) {

        // Need at least STATUS(2) + SP(1) = 3 bytes before CR.
        return { error: 'malformed' };

    }

    const statusByte0 = bytesAvailable[0];
    const statusByte1 = bytesAvailable[1];
    const isDigit = (b) => b >= 0x30 && b <= 0x39;
    if (!isDigit(statusByte0) || !isDigit(statusByte1)) return { error: 'malformed' };
    if (bytesAvailable[2] !== SP) return { error: 'malformed' };

    const status = (statusByte0 - 0x30) * 10 + (statusByte1 - 0x30);
    if (!isValidStatus(status)) return { error: 'malformed' };

    const metaBytes = bytesAvailable.subarray(3, terminator);
    if (metaBytes.length > MAX_META_BYTES) return { error: 'too-long' };

    let meta;
    try {

        meta = new TextDecoder('utf-8', { fatal: true }).decode(metaBytes);

    } catch {

        return { error: 'malformed' };

    }

    return { status, meta, headEnd: terminator + 2 };

};

// Parse META for content-type responses (`<MIME-type>[; params]`).
// Returns { mimeType, parameters } where parameters is a plain object
// mapping parameter name (lower-case) to value.
//
//   parseSuccessMeta("text/anon; charset=utf-8; length=1234")
//     → { mimeType: "text/anon", parameters: { charset: "utf-8", length: "1234" } }
//
// Returns null on malformed META.
export const parseSuccessMeta = (meta) => {

    if (typeof meta !== 'string' || meta.length === 0) return null;
    const parts = meta.split(';').map((p) => p.trim());
    const mimeType = parts[0].toLowerCase();
    if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i.test(mimeType)) return null;
    const parameters = {};
    for (let i = 1; i < parts.length; i += 1) {

        const eq = parts[i].indexOf('=');
        if (eq === -1) return null;
        const name = parts[i].slice(0, eq).trim().toLowerCase();
        const value = parts[i].slice(eq + 1).trim();
        if (name.length === 0) return null;
        parameters[name] = value;

    }
    return { mimeType, parameters };

};
