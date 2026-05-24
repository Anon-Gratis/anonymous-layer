// Operator-facing local logger.
//
// SPEC § 9.4: implementations MAY log packet-processing failures to a
// LOCAL log and SHOULD distinguish failure causes for operator
// debugging. Logs MUST NOT be transmitted over the wire by the
// protocol. This logger writes to a caller-provided stream (default
// stderr); operator-grade log shipping is out of scope.
//
// Guardrail: log messages are formatted from a fixed set of fields
// (level, ts, msg, plus a flat object of small scalars). We never
// stringify Uint8Array payloads or onion/identity secret keys, even
// at debug. Callers that try to log a Uint8Array get its length and a
// truncated hex preview instead — useful for fingerprints / nonces,
// safe-by-default for payloads.

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

const renderValue = (v) => {

    if (v === null || v === undefined) return String(v);
    if (typeof v === 'string') return v;
    if (typeof v === 'number' || typeof v === 'boolean' || typeof v === 'bigint') {

        return String(v);

    }
    if (v instanceof Uint8Array) {

        // Always summarise; never dump a full byte array.
        const preview = Buffer.from(v.subarray(0, Math.min(8, v.length))).toString('hex');
        return `<bytes len=${v.length} prefix=${preview}>`;

    }
    // Anything else — render a short JSON tag rather than the full object,
    // to keep log lines bounded and avoid surprising large dumps.
    try {

        const s = JSON.stringify(v);
        return s.length > 80 ? `${s.slice(0, 77)}...` : s;

    } catch {

        return '<unprintable>';

    }

};

const formatLine = (level, msg, fields, now) => {

    const ts = new Date(now).toISOString();
    const parts = [ts, level.toUpperCase().padEnd(5), msg];
    if (fields && typeof fields === 'object') {

        for (const k of Object.keys(fields)) {

            parts.push(`${k}=${renderValue(fields[k])}`);

        }

    }
    return `${parts.join(' ')}\n`;

};

export const createLogger = ({
    level = 'info',
    out = process.stderr,
    now = () => Date.now(),
} = {}) => {

    if (!(level in LEVELS)) throw new Error(`unknown log level: ${level}`);
    const threshold = LEVELS[level];

    const emit = (lvl, msg, fields) => {

        if (LEVELS[lvl] < threshold) return;
        out.write(formatLine(lvl, msg, fields, now()));

    };

    return {
        debug: (msg, fields) => emit('debug', msg, fields),
        info:  (msg, fields) => emit('info',  msg, fields),
        warn:  (msg, fields) => emit('warn',  msg, fields),
        error: (msg, fields) => emit('error', msg, fields),
    };

};
