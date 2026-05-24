import { REPLAY_MIN_ENTRIES, REPLAY_MIN_SECONDS } from './constants.mjs';

// SPEC § 5.6: sliding-window replay log keyed by (ephPk, nonce).
//
// Storage choice: a Map<string, number> where the key is the 44-byte
// (ephPk ‖ nonce) encoded as hex and the value is the insertion
// timestamp in seconds. Hex keys are 88 characters; for 8192 entries
// that's roughly 1 MB of strings — acceptable for v0.1. A Uint8Array-
// keyed structure would be denser but would require either a custom
// hash table or composite indexing; the spec is explicit that
// implementations MAY retain more than the minima, so simplicity wins.
//
// Eviction policy: on insert, walk old entries from the head of an
// insertion-ordered queue and remove those older than `minSeconds`
// *only* when the total size exceeds `minEntries`. This guarantees
// the SPEC § 5.6 minima ("MUST retain at least the most recent 8192
// entries even if doing so requires extending the time window") while
// bounding memory growth on high-rate links.

const KEY_BYTE_LEN = 44;

const toKey = (ephPk, nonce) => {

    if (ephPk.length !== 32 || nonce.length !== 12) {

        // Programmer error — the wire path guarantees these lengths.
        throw new Error('replay key requires ephPk(32) || nonce(12)');

    }
    const buf = new Uint8Array(KEY_BYTE_LEN);
    buf.set(ephPk, 0);
    buf.set(nonce, 32);
    return Buffer.from(buf).toString('hex');

};

export const createReplayLog = ({
    minEntries = REPLAY_MIN_ENTRIES,
    minSeconds = REPLAY_MIN_SECONDS,
    now = () => Math.floor(Date.now() / 1000),
} = {}) => {

    // Map preserves insertion order; we exploit that for eviction.
    const seen = new Map();

    const check = (ephPk, nonce) => seen.has(toKey(ephPk, nonce));

    const insert = (ephPk, nonce, timestamp = null) => {

        const ts = timestamp !== null ? timestamp : now();
        seen.set(toKey(ephPk, nonce), ts);
        evict(ts);

    };

    const evict = (nowTs) => {

        // SPEC § 5.6: never evict below `minEntries` even if entries
        // would otherwise be past their age cutoff. Stop as soon as we
        // hit a young-enough entry (Map insertion order ≈ chronological
        // order for monotonic clocks).
        if (seen.size <= minEntries) return;
        const cutoff = nowTs - minSeconds;
        for (const [key, ts] of seen) {

            if (seen.size <= minEntries) break;
            if (ts > cutoff) break;
            seen.delete(key);

        }

    };

    const size = () => seen.size;

    return { check, insert, size };

};
