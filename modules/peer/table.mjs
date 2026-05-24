import { verifyCertificate } from '../crypto/cert.mjs';
import { fingerprint } from '../crypto/fingerprint.mjs';
import { zeroize } from '../crypto/zeroize.mjs';

// SPEC § 7.4: peer table data structure with eviction policy.
//
// Eviction triggers:
//   - expired key certificate
//   - inner-validation failure on a packet that reached AEAD success
//     (§ 5.7 step 7 or 8) — markInnerValidationFailed evicts immediately
//   - unreachable on every advertised transport for ≥ 1 hour of
//     attempted contact — prune() applies this
//   - operator command — remove()
//
// Critically, this module exposes NO method that evicts based on pre-
// AEAD failure. § 7.4 forbids that, because any on-path adversary can
// induce a pre-AEAD failure for a packet that names an arbitrary
// sender and would otherwise be a trivial poisoning vector.
//
// Per-entry book-keeping:
//   idPk, fingerprint, certBytes, transports
//   expirySeconds       — parsed from the cert
//   connected           — currently dialed
//   lastReachableAt     — most recent successful contact (or null)
//   firstUnreachableAt  — start of the current unreachable run (or null)
//   keyCertSentTo       — Set<receiverFp> we've sent KEY_CERTIFICATE to
//   lastAnnouncedAt     — Map<receiverFp, timestamp> last ANNOUNCE_PEER
//                         we emitted about this peer to that receiver

const UNREACHABLE_EVICT_SECONDS = 3600; // SPEC § 7.4

export const createPeerTable = ({ now = () => Math.floor(Date.now() / 1000) } = {}) => {

    // keyed by hex(fingerprint) for Map compatibility.
    const peers = new Map();

    const keyOf = (fp) => Buffer.from(fp).toString('hex');

    // Wipe a peer record's byte buffers before the Map entry is dropped.
    // The buffers themselves are not strictly secret — idPk, onionPk,
    // and the cert are wire-public — but zeroizing them on the way out
    // is a useful invariant (matches the contract described in
    // modules/crypto/zeroize.mjs) and shortens the time identifying
    // bytes remain reachable from JS land after eviction.
    const wipeEntry = (entry) => {

        if (!entry) return;
        zeroize(entry.idPk);
        zeroize(entry.fingerprint);
        zeroize(entry.certBytes);
        if (entry.onionPk) zeroize(entry.onionPk);
        if (entry.transports) {

            for (const t of entry.transports) zeroize(t.address);

        }

    };

    const addOrUpdate = ({ idPk, certBytes, transports, nowSeconds = null }) => {

        const ts = nowSeconds !== null ? nowSeconds : now();
        const cert = verifyCertificate(certBytes, idPk, ts);
        if (cert === null) return false;

        const fp = fingerprint(idPk);
        const key = keyOf(fp);
        const existing = peers.get(key);

        // Refresh existing entry: keep liveness state, update cert + transports.
        if (existing) {

            existing.certBytes = new Uint8Array(certBytes);
            existing.expirySeconds = cert.expirySeconds;
            existing.onionPk = new Uint8Array(cert.onionPk);
            existing.transports = transports.map((t) => ({
                type: t.type,
                address: new Uint8Array(t.address),
            }));
            return true;

        }

        peers.set(key, {
            idPk: new Uint8Array(idPk),
            fingerprint: fp,
            certBytes: new Uint8Array(certBytes),
            expirySeconds: cert.expirySeconds,
            onionPk: new Uint8Array(cert.onionPk),
            transports: transports.map((t) => ({
                type: t.type,
                address: new Uint8Array(t.address),
            })),
            connected: false,
            lastReachableAt: null,
            firstUnreachableAt: null,
            keyCertSentTo: new Set(),
            lastAnnouncedAt: new Map(),
        });
        return true;

    };

    const get = (fp) => peers.get(keyOf(fp)) || null;

    const list = () => Array.from(peers.values());

    const remove = (fp) => {

        const key = keyOf(fp);
        const entry = peers.get(key);
        if (!entry) return false;
        wipeEntry(entry);
        peers.delete(key);
        return true;

    };

    const markInnerValidationFailed = (fp) => {

        // SPEC § 7.4: evict on first occurrence of a post-AEAD inner-
        // validation failure (§ 5.7 step 7 or 8). The wire-layer
        // distinguishes these from pre-AEAD failures; only this
        // attribution-safe path is exposed.
        const key = keyOf(fp);
        const entry = peers.get(key);
        if (!entry) return;
        wipeEntry(entry);
        peers.delete(key);

    };

    const markConnected = (fp) => {

        const p = get(fp);
        if (p) {

            p.connected = true;
            p.firstUnreachableAt = null;

        }

    };

    const markDisconnected = (fp) => {

        const p = get(fp);
        if (p) p.connected = false;

    };

    const markReachable = (fp, nowSeconds = null) => {

        const p = get(fp);
        if (!p) return;
        p.lastReachableAt = nowSeconds !== null ? nowSeconds : now();
        p.firstUnreachableAt = null;

    };

    const markUnreachable = (fp, nowSeconds = null) => {

        const p = get(fp);
        if (!p) return;
        const ts = nowSeconds !== null ? nowSeconds : now();
        if (p.firstUnreachableAt === null) {

            p.firstUnreachableAt = ts;

        }
        p.connected = false;

    };

    const markAnnouncedTo = (receiverFp, subjectFp, nowSeconds = null) => {

        const subject = get(subjectFp);
        if (!subject) return;
        subject.lastAnnouncedAt.set(keyOf(receiverFp), nowSeconds !== null ? nowSeconds : now());

    };

    const markKeyCertSentTo = (receiverFp) => {

        // We track this on the receiver side: each peer record holds
        // the set of receivers it has been advertised to as "self."
        // For self-announcement dedup we just need a set of receiver
        // fingerprints we've sent OUR KEY_CERTIFICATE to. That set is
        // a property of the local node, not of any peer record. Store
        // it on a sentinel key for simplicity.
        let selfRecord = peers.get('__self__');
        if (!selfRecord) {

            selfRecord = { keyCertSentTo: new Set() };
            peers.set('__self__', selfRecord);

        }
        selfRecord.keyCertSentTo.add(keyOf(receiverFp));

    };

    const hasSentKeyCertTo = (receiverFp) => {

        const selfRecord = peers.get('__self__');
        return !!(selfRecord && selfRecord.keyCertSentTo.has(keyOf(receiverFp)));

    };

    const prune = (nowSeconds = null) => {

        const ts = nowSeconds !== null ? nowSeconds : now();
        let evicted = 0;
        for (const [key, p] of peers) {

            if (key === '__self__') continue;
            if (p.expirySeconds <= ts) {

                wipeEntry(p);
                peers.delete(key);
                evicted += 1;
                continue;

            }
            if (
                p.firstUnreachableAt !== null
                && !p.connected
                && ts - p.firstUnreachableAt >= UNREACHABLE_EVICT_SECONDS
            ) {

                wipeEntry(p);
                peers.delete(key);
                evicted += 1;

            }

        }
        return evicted;

    };

    const connectedFingerprints = () => {

        const out = [];
        for (const [key, p] of peers) {

            if (key === '__self__') continue;
            if (p.connected) out.push(p.fingerprint);

        }
        return out;

    };

    // SPEC § 7.3: announce subjects are uniformly random not-currently-
    // connected peers, weighted to prefer least-recently-announced to
    // this receiver. Implementation: bucket candidates by (no record /
    // oldest announce / newest announce), pick uniformly from the
    // oldest non-empty bucket. Simple, deterministic, no global sort.
    const pickAnnouncementSubject = (receiverFp) => {

        const receiverKey = keyOf(receiverFp);
        let neverAnnounced = [];
        let oldest = [];
        let oldestTimestamp = Infinity;

        for (const [key, p] of peers) {

            if (key === '__self__') continue;
            if (p.connected) continue;
            if (key === receiverKey) continue;
            const lastAt = p.lastAnnouncedAt.get(receiverKey);
            if (lastAt === undefined) {

                neverAnnounced.push(p);
                continue;

            }
            if (lastAt < oldestTimestamp) {

                oldestTimestamp = lastAt;
                oldest = [p];

            } else if (lastAt === oldestTimestamp) {

                oldest.push(p);

            }

        }

        const pool = neverAnnounced.length > 0 ? neverAnnounced : oldest;
        if (pool.length === 0) return null;
        const choice = pool[Math.floor(Math.random() * pool.length)];
        return choice.fingerprint;

    };

    const peerCount = () => {

        let n = 0;
        for (const key of peers.keys()) {

            if (key !== '__self__') n += 1;

        }
        return n;

    };

    return {
        addOrUpdate,
        get,
        list,
        remove,
        markInnerValidationFailed,
        markConnected,
        markDisconnected,
        markReachable,
        markUnreachable,
        markAnnouncedTo,
        markKeyCertSentTo,
        hasSentKeyCertTo,
        prune,
        connectedFingerprints,
        pickAnnouncementSubject,
        peerCount,
    };

};
