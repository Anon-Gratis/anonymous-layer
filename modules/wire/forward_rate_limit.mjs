// SPEC § 6.5.1: forward-rate limiting. Closes AUDIT_PREP finding H3,
// the open-amplification primitive in the pre-spec router.
//
// Three concurrent limits, all over a 60-second sliding window:
//
//   per-source        32 FORWARD requests per ephemeral source key
//   per-destination   64 FORWARD requests per next-hop fingerprint
//   global            4096 FORWARD requests, period
//
// "Per source" really means "per recently-seen ephemeral key" — the
// network is anonymous at the source by construction, and each legit
// packet uses a fresh ephPk. The limit therefore caps how many times
// any one captured (ephPk, _) tuple can be replayed within the window,
// not how many requests a long-lived attacker can issue.
//
// Implementation: each tracked bucket is a Map<key, number[]> of
// timestamps. On every checkAndCount, we discard timestamps older than
// the window from the queried bucket before deciding. This keeps
// memory bounded by recent activity rather than total observed
// (sourceEphPk, destFingerprint) pairs.

const PER_SOURCE_LIMIT = 32;
const PER_DESTINATION_LIMIT = 64;
const GLOBAL_LIMIT = 4096;
const WINDOW_SECONDS = 60;

const evict = (timestamps, cutoff) => {

    // timestamps is kept in insertion order, which is non-decreasing.
    // Drop from the front while head is at or below the cutoff.
    let drop = 0;
    while (drop < timestamps.length && timestamps[drop] <= cutoff) drop += 1;
    if (drop > 0) timestamps.splice(0, drop);

};

const sourceKey = (sourceEphPk) => Buffer.from(sourceEphPk).toString('hex');
const destKey = (destFingerprint) => Buffer.from(destFingerprint).toString('hex');

export const createForwardRateLimiter = ({
    now = () => Math.floor(Date.now() / 1000),
    perSourceLimit = PER_SOURCE_LIMIT,
    perDestinationLimit = PER_DESTINATION_LIMIT,
    globalLimit = GLOBAL_LIMIT,
    windowSeconds = WINDOW_SECONDS,
} = {}) => {

    const sourceLog = new Map();      // hex(sourceEphPk) -> number[]
    const destLog = new Map();        // hex(destFingerprint) -> number[]
    const globalLog = [];

    const cleanupBucket = (log, key, cutoff) => {

        const ts = log.get(key);
        if (!ts) return [];
        evict(ts, cutoff);
        if (ts.length === 0) {

            log.delete(key);
            return [];

        }
        return ts;

    };

    // Returns true if the FORWARD request is within all three limits
    // and was counted; false if the request was dropped (any limit
    // exceeded). On rejection nothing is counted — a dropped packet
    // should not consume budget for subsequent decisions.
    const checkAndCount = ({ sourceEphPk, destFingerprint }) => {

        const ts = now();
        const cutoff = ts - windowSeconds;

        const sk = sourceKey(sourceEphPk);
        const dk = destKey(destFingerprint);

        const sourceTs = cleanupBucket(sourceLog, sk, cutoff);
        const destTs = cleanupBucket(destLog, dk, cutoff);
        evict(globalLog, cutoff);

        if (sourceTs.length >= perSourceLimit) return false;
        if (destTs.length >= perDestinationLimit) return false;
        if (globalLog.length >= globalLimit) return false;

        // Accept — record the timestamp in all three logs.
        if (!sourceLog.has(sk)) sourceLog.set(sk, sourceTs);
        sourceTs.push(ts);
        if (!destLog.has(dk)) destLog.set(dk, destTs);
        destTs.push(ts);
        globalLog.push(ts);

        return true;

    };

    const stats = () => ({
        sources: sourceLog.size,
        destinations: destLog.size,
        global: globalLog.length,
    });

    return { checkAndCount, stats };

};
