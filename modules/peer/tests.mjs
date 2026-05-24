import { expect } from 'chai';

import { generateIdentity, identityFingerprint } from '../crypto/identity.mjs';
import { generateOnion } from '../crypto/onion.mjs';
import { buildCertificate } from '../crypto/cert.mjs';
import { TRANSPORT_WEBSOCKET_IPV4 } from '../wire/transport.mjs';

import {
    buildSeedRecord,
    parseSeedRecord,
    parseSeedList,
    verifySeedRecord,
} from './seed.mjs';
import { createPeerTable } from './table.mjs';
import { loadSeedList, pickBootstrapDials, mustRefuseTraffic } from './bootstrap.mjs';
import { planAnnounces, planKeyCertificateSends } from './gossip.mjs';

const makeParty = () => {

    const id = generateIdentity();
    const onion = generateOnion();
    return {
        idPk: id.idPk,
        idSk: id.idSk,
        onionPk: onion.onionPk,
        onionSk: onion.onionSk,
        fingerprint: identityFingerprint(id.idPk),
    };

};

const makeCert = (party, expirySeconds) => buildCertificate({
    idSk: party.idSk,
    onionPk: party.onionPk,
    expirySeconds,
});

const makeRecord = (party, expirySeconds, transports = []) => ({
    idPk: party.idPk,
    certBytes: makeCert(party, expirySeconds),
    transports,
});

const sampleTransports = () => [{
    type: TRANSPORT_WEBSOCKET_IPV4,
    address: new Uint8Array([127, 0, 0, 1, 0x1F, 0x90]),
}];

describe('peer/seed', () => {

    const now = () => Math.floor(Date.now() / 1000);

    it('round-trips a single seed record with transports', () => {

        const party = makeParty();
        const rec = makeRecord(party, now() + 86400, sampleTransports());
        const buf = buildSeedRecord(rec);
        const parsed = parseSeedRecord(buf, 0);
        expect(parsed).to.not.equal(null);
        expect(Buffer.from(parsed.record.idPk).equals(Buffer.from(party.idPk))).to.equal(true);
        expect(Buffer.from(parsed.record.certBytes).equals(Buffer.from(rec.certBytes))).to.equal(true);
        expect(parsed.record.transports.length).to.equal(1);
        expect(parsed.consumed).to.equal(buf.length);

    });

    it('parseSeedList walks multiple concatenated records', () => {

        const a = makeParty();
        const b = makeParty();
        const c = makeParty();
        const exp = now() + 86400;
        const buf = Buffer.concat([
            Buffer.from(buildSeedRecord(makeRecord(a, exp, []))),
            Buffer.from(buildSeedRecord(makeRecord(b, exp, sampleTransports()))),
            Buffer.from(buildSeedRecord(makeRecord(c, exp, []))),
        ]);
        const list = parseSeedList(new Uint8Array(buf));
        expect(list.length).to.equal(3);
        expect(Buffer.from(list[1].idPk).equals(Buffer.from(b.idPk))).to.equal(true);

    });

    it('parseSeedList returns [] for empty bytes', () => {

        expect(parseSeedList(new Uint8Array(0))).to.deep.equal([]);
        expect(parseSeedList(null)).to.deep.equal([]);

    });

    it('parseSeedList returns null on corrupted bytes', () => {

        expect(parseSeedList(new Uint8Array(10))).to.equal(null);

    });

    it('verifySeedRecord accepts a fresh record', () => {

        const party = makeParty();
        const rec = makeRecord(party, now() + 86400);
        expect(verifySeedRecord({ record: rec, nowSeconds: now() })).to.equal(true);

    });

    it('verifySeedRecord rejects an expired record', () => {

        const party = makeParty();
        const rec = makeRecord(party, now() - 1);
        expect(verifySeedRecord({ record: rec, nowSeconds: now() })).to.equal(false);

    });

    it('verifySeedRecord rejects when cert was signed by a different identity', () => {

        const a = makeParty();
        const b = makeParty();
        // Forge a record that claims a's idPk but ships b's cert.
        const rec = {
            idPk: a.idPk,
            certBytes: makeCert(b, now() + 86400),
            transports: [],
        };
        expect(verifySeedRecord({ record: rec, nowSeconds: now() })).to.equal(false);

    });

});

describe('peer/table', () => {

    const now = () => Math.floor(Date.now() / 1000);

    it('addOrUpdate accepts a valid record', () => {

        const t = createPeerTable();
        const a = makeParty();
        expect(t.addOrUpdate({
            idPk: a.idPk,
            certBytes: makeCert(a, now() + 86400),
            transports: [],
            nowSeconds: now(),
        })).to.equal(true);
        expect(t.peerCount()).to.equal(1);

    });

    it('addOrUpdate rejects a cert signed by a different key', () => {

        const t = createPeerTable();
        const a = makeParty();
        const b = makeParty();
        expect(t.addOrUpdate({
            idPk: a.idPk,
            certBytes: makeCert(b, now() + 86400),
            transports: [],
            nowSeconds: now(),
        })).to.equal(false);

    });

    it('addOrUpdate rejects an expired cert', () => {

        const t = createPeerTable();
        const a = makeParty();
        expect(t.addOrUpdate({
            idPk: a.idPk,
            certBytes: makeCert(a, now() - 1),
            transports: [],
            nowSeconds: now(),
        })).to.equal(false);

    });

    it('get returns null for an unknown peer', () => {

        const t = createPeerTable();
        const a = makeParty();
        expect(t.get(a.fingerprint)).to.equal(null);

    });

    it('addOrUpdate refreshes an existing entry without losing liveness state', () => {

        const t = createPeerTable();
        const a = makeParty();
        t.addOrUpdate({
            idPk: a.idPk,
            certBytes: makeCert(a, now() + 86400),
            transports: [],
            nowSeconds: now(),
        });
        t.markConnected(a.fingerprint);
        t.markReachable(a.fingerprint, now());

        // Update with a new cert (longer expiry).
        t.addOrUpdate({
            idPk: a.idPk,
            certBytes: makeCert(a, now() + 172800),
            transports: sampleTransports(),
            nowSeconds: now(),
        });
        const p = t.get(a.fingerprint);
        expect(p.connected).to.equal(true);
        expect(p.lastReachableAt).to.not.equal(null);
        expect(p.transports.length).to.equal(1);

    });

    it('markInnerValidationFailed evicts immediately (§ 7.4)', () => {

        const t = createPeerTable();
        const a = makeParty();
        t.addOrUpdate({
            idPk: a.idPk,
            certBytes: makeCert(a, now() + 86400),
            transports: [],
            nowSeconds: now(),
        });
        expect(t.peerCount()).to.equal(1);
        t.markInnerValidationFailed(a.fingerprint);
        expect(t.peerCount()).to.equal(0);

    });

    it('prune evicts expired certs', () => {

        const t = createPeerTable();
        const a = makeParty();
        const b = makeParty();
        t.addOrUpdate({
            idPk: a.idPk,
            certBytes: makeCert(a, 1_000_100),
            transports: [],
            nowSeconds: 1_000_000,
        });
        t.addOrUpdate({
            idPk: b.idPk,
            certBytes: makeCert(b, 2_000_000),
            transports: [],
            nowSeconds: 1_000_000,
        });
        expect(t.peerCount()).to.equal(2);
        const evicted = t.prune(1_500_000);
        expect(evicted).to.equal(1);
        expect(t.peerCount()).to.equal(1);
        expect(t.get(a.fingerprint)).to.equal(null);

    });

    it('prune evicts peers unreachable for ≥ 1 hour', () => {

        const t = createPeerTable();
        const a = makeParty();
        const b = makeParty();
        t.addOrUpdate({
            idPk: a.idPk,
            certBytes: makeCert(a, 2_000_000),
            transports: [],
            nowSeconds: 1_000_000,
        });
        t.addOrUpdate({
            idPk: b.idPk,
            certBytes: makeCert(b, 2_000_000),
            transports: [],
            nowSeconds: 1_000_000,
        });
        t.markUnreachable(a.fingerprint, 1_000_000);
        t.markUnreachable(b.fingerprint, 1_000_000);
        // Reach b again so its unreachable run is reset.
        t.markReachable(b.fingerprint, 1_000_500);
        // Advance one hour.
        const evicted = t.prune(1_000_000 + 3600);
        expect(evicted).to.equal(1);
        expect(t.get(a.fingerprint)).to.equal(null);
        expect(t.get(b.fingerprint)).to.not.equal(null);

    });

    it('prune does NOT evict a connected peer (§ 7.4 unreachable rule applies to disconnected only)', () => {

        const t = createPeerTable();
        const a = makeParty();
        t.addOrUpdate({
            idPk: a.idPk,
            certBytes: makeCert(a, 2_000_000),
            transports: [],
            nowSeconds: 1_000_000,
        });
        t.markUnreachable(a.fingerprint, 1_000_000);
        // Imagine we reconnected after some failures.
        t.markConnected(a.fingerprint);
        // Pruning shouldn't evict — connected peers shouldn't be touched.
        const evicted = t.prune(1_000_000 + 10000);
        expect(evicted).to.equal(0);

    });

    it('eviction zeroizes the entry buffers (zeroize-on-evict invariant)', () => {

        const t = createPeerTable();
        const a = makeParty();
        t.addOrUpdate({
            idPk: a.idPk,
            certBytes: makeCert(a, now() + 86400),
            transports: [{
                type: 0x01,
                address: new Uint8Array([10, 0, 0, 1, 0x1F, 0x90]),
            }],
            nowSeconds: now(),
        });
        // Capture the internal buffers before eviction.
        const p = t.get(a.fingerprint);
        const idPkRef = p.idPk;
        const fingerprintRef = p.fingerprint;
        const certBytesRef = p.certBytes;
        const onionPkRef = p.onionPk;
        const addressRef = p.transports[0].address;
        // Non-trivial values before.
        expect(idPkRef.some((b) => b !== 0)).to.equal(true);
        expect(certBytesRef.some((b) => b !== 0)).to.equal(true);
        expect(addressRef.some((b) => b !== 0)).to.equal(true);

        t.remove(a.fingerprint);

        // All captured buffers should now be filled with zeros.
        expect(idPkRef.every((b) => b === 0)).to.equal(true);
        expect(fingerprintRef.every((b) => b === 0)).to.equal(true);
        expect(certBytesRef.every((b) => b === 0)).to.equal(true);
        expect(onionPkRef.every((b) => b === 0)).to.equal(true);
        expect(addressRef.every((b) => b === 0)).to.equal(true);

    });

    it('markInnerValidationFailed also zeroizes the entry', () => {

        const t = createPeerTable();
        const a = makeParty();
        t.addOrUpdate({
            idPk: a.idPk,
            certBytes: makeCert(a, now() + 86400),
            transports: [],
            nowSeconds: now(),
        });
        const idPkRef = t.get(a.fingerprint).idPk;
        expect(idPkRef.some((b) => b !== 0)).to.equal(true);
        t.markInnerValidationFailed(a.fingerprint);
        expect(idPkRef.every((b) => b === 0)).to.equal(true);

    });

    it('prune zeroizes expired entries', () => {

        const t = createPeerTable();
        const a = makeParty();
        t.addOrUpdate({
            idPk: a.idPk,
            certBytes: makeCert(a, 1_000_100),
            transports: [],
            nowSeconds: 1_000_000,
        });
        const idPkRef = t.get(a.fingerprint).idPk;
        expect(idPkRef.some((b) => b !== 0)).to.equal(true);
        t.prune(1_500_000); // past expiry
        expect(idPkRef.every((b) => b === 0)).to.equal(true);

    });

    it('remove deletes by operator command', () => {

        const t = createPeerTable();
        const a = makeParty();
        t.addOrUpdate({
            idPk: a.idPk,
            certBytes: makeCert(a, now() + 86400),
            transports: [],
            nowSeconds: now(),
        });
        expect(t.remove(a.fingerprint)).to.equal(true);
        expect(t.peerCount()).to.equal(0);

    });

    it('does NOT expose any path to evict on pre-AEAD failure (§ 7.4)', () => {

        const t = createPeerTable();
        // Confidence check: the public API is exactly what we expect; no
        // method named anything like "markOuterHeaderFailed" exists.
        const methods = Object.keys(t);
        for (const m of methods) {

            expect(m).to.not.match(/outerheader|preaead|prefix.*fail|wireheader/i);

        }
        // Sanity check the actual public surface.
        expect(methods.sort()).to.deep.equal([
            'addOrUpdate',
            'connectedFingerprints',
            'get',
            'hasSentKeyCertTo',
            'list',
            'markAnnouncedTo',
            'markConnected',
            'markDisconnected',
            'markInnerValidationFailed',
            'markKeyCertSentTo',
            'markReachable',
            'markUnreachable',
            'peerCount',
            'pickAnnouncementSubject',
            'prune',
            'remove',
        ]);

    });

    it('pickAnnouncementSubject prefers never-announced peers, then oldest', () => {

        const t = createPeerTable();
        const receiver = makeParty();
        const a = makeParty();
        const b = makeParty();
        for (const p of [receiver, a, b]) {

            t.addOrUpdate({
                idPk: p.idPk,
                certBytes: makeCert(p, now() + 86400),
                transports: [],
                nowSeconds: now(),
            });

        }
        // None connected, none announced — both a and b are eligible.
        const seen = new Set();
        for (let i = 0; i < 30; i += 1) {

            const fp = t.pickAnnouncementSubject(receiver.fingerprint);
            expect(fp).to.not.equal(null);
            seen.add(Buffer.from(fp).toString('hex'));

        }
        // 30 random picks should hit both a and b.
        expect(seen.size).to.equal(2);

        // Mark a as announced; subsequent picks should prefer b (never).
        t.markAnnouncedTo(receiver.fingerprint, a.fingerprint, now());
        const next = t.pickAnnouncementSubject(receiver.fingerprint);
        expect(Buffer.from(next).equals(Buffer.from(b.fingerprint))).to.equal(true);

    });

    it('pickAnnouncementSubject skips connected and the receiver itself', () => {

        const t = createPeerTable();
        const receiver = makeParty();
        const connected = makeParty();
        const candidate = makeParty();
        for (const p of [receiver, connected, candidate]) {

            t.addOrUpdate({
                idPk: p.idPk,
                certBytes: makeCert(p, now() + 86400),
                transports: [],
                nowSeconds: now(),
            });

        }
        t.markConnected(connected.fingerprint);
        for (let i = 0; i < 20; i += 1) {

            const fp = t.pickAnnouncementSubject(receiver.fingerprint);
            expect(Buffer.from(fp).equals(Buffer.from(candidate.fingerprint))).to.equal(true);

        }

    });

    it('pickAnnouncementSubject returns null when no eligible candidates', () => {

        const t = createPeerTable();
        const only = makeParty();
        t.addOrUpdate({
            idPk: only.idPk,
            certBytes: makeCert(only, now() + 86400),
            transports: [],
            nowSeconds: now(),
        });
        // The only peer is the receiver itself — nothing to announce.
        expect(t.pickAnnouncementSubject(only.fingerprint)).to.equal(null);

    });

    it('markKeyCertSentTo / hasSentKeyCertTo round-trip', () => {

        const t = createPeerTable();
        const peer = makeParty();
        expect(t.hasSentKeyCertTo(peer.fingerprint)).to.equal(false);
        t.markKeyCertSentTo(peer.fingerprint);
        expect(t.hasSentKeyCertTo(peer.fingerprint)).to.equal(true);

    });

});

describe('peer/bootstrap', () => {

    const now = () => Math.floor(Date.now() / 1000);

    it('loadSeedList accepts a list with all-valid records', () => {

        const t = createPeerTable();
        const parties = [makeParty(), makeParty(), makeParty()];
        const buf = Buffer.concat(parties.map((p) => Buffer.from(buildSeedRecord(makeRecord(p, now() + 86400)))));
        const n = loadSeedList(new Uint8Array(buf), t, now());
        expect(n).to.equal(3);
        expect(t.peerCount()).to.equal(3);

    });

    it('loadSeedList silently drops records whose certs fail to verify', () => {

        const t = createPeerTable();
        const good = makeParty();
        const evil = makeParty();
        const cross = makeParty();
        const buf = Buffer.concat([
            Buffer.from(buildSeedRecord(makeRecord(good, now() + 86400))),
            // Record claims cross's idPk but ships evil's cert — verify must fail.
            Buffer.from(buildSeedRecord({
                idPk: cross.idPk,
                certBytes: makeCert(evil, now() + 86400),
                transports: [],
            })),
        ]);
        const n = loadSeedList(new Uint8Array(buf), t, now());
        expect(n).to.equal(1);
        expect(t.peerCount()).to.equal(1);

    });

    it('loadSeedList returns -1 on corrupted bytes', () => {

        const t = createPeerTable();
        expect(loadSeedList(new Uint8Array([1, 2, 3]), t, now())).to.equal(-1);

    });

    it('loadSeedList on empty input accepts zero', () => {

        const t = createPeerTable();
        expect(loadSeedList(new Uint8Array(0), t, now())).to.equal(0);
        expect(t.peerCount()).to.equal(0);

    });

    it('pickBootstrapDials caps at K and prefers not-connected', () => {

        const t = createPeerTable();
        const parties = new Array(12).fill(0).map(() => makeParty());
        for (const p of parties) {

            t.addOrUpdate({
                idPk: p.idPk,
                certBytes: makeCert(p, now() + 86400),
                transports: [],
                nowSeconds: now(),
            });

        }
        const dials = pickBootstrapDials(t, 8);
        expect(dials.length).to.equal(8);
        // Mark a few connected; they should be skipped on the next pick.
        for (let i = 0; i < 4; i += 1) {

            t.markConnected(parties[i].fingerprint);

        }
        const next = pickBootstrapDials(t, 8);
        for (const fp of next) {

            const p = t.get(fp);
            expect(p.connected).to.equal(false);

        }

    });

    it('mustRefuseTraffic is true while no peers are connected', () => {

        const t = createPeerTable();
        const a = makeParty();
        t.addOrUpdate({
            idPk: a.idPk,
            certBytes: makeCert(a, now() + 86400),
            transports: [],
            nowSeconds: now(),
        });
        expect(mustRefuseTraffic(t)).to.equal(true);
        t.markConnected(a.fingerprint);
        expect(mustRefuseTraffic(t)).to.equal(false);

    });

});

describe('peer/gossip', () => {

    const now = () => Math.floor(Date.now() / 1000);

    it('planAnnounces enforces 30s cadence per recipient', () => {

        const t = createPeerTable();
        const receiver = makeParty();
        const subject = makeParty();
        for (const p of [receiver, subject]) {

            t.addOrUpdate({
                idPk: p.idPk,
                certBytes: makeCert(p, now() + 86400),
                transports: [],
                nowSeconds: now(),
            });

        }
        t.markConnected(receiver.fingerprint);

        const cadenceLog = new Map();
        const ts0 = 1_000_000;
        const plan1 = planAnnounces(t, cadenceLog, ts0, 30);
        expect(plan1.length).to.equal(1);
        cadenceLog.set(Buffer.from(receiver.fingerprint).toString('hex'), ts0);

        // 29s later — too soon, no plan emitted.
        const plan2 = planAnnounces(t, cadenceLog, ts0 + 29, 30);
        expect(plan2.length).to.equal(0);

        // 30s later — emitted again.
        const plan3 = planAnnounces(t, cadenceLog, ts0 + 30, 30);
        expect(plan3.length).to.equal(1);

    });

    it('planAnnounces skips recipients without an eligible subject', () => {

        const t = createPeerTable();
        const only = makeParty();
        t.addOrUpdate({
            idPk: only.idPk,
            certBytes: makeCert(only, now() + 86400),
            transports: [],
            nowSeconds: now(),
        });
        t.markConnected(only.fingerprint);
        // No other peers — pickAnnouncementSubject returns null.
        const plan = planAnnounces(t, new Map(), now(), 30);
        expect(plan.length).to.equal(0);

    });

    it('planKeyCertificateSends omits already-sent recipients', () => {

        const t = createPeerTable();
        const a = makeParty();
        const b = makeParty();
        for (const p of [a, b]) {

            t.addOrUpdate({
                idPk: p.idPk,
                certBytes: makeCert(p, now() + 86400),
                transports: [],
                nowSeconds: now(),
            });
            t.markConnected(p.fingerprint);

        }
        expect(planKeyCertificateSends(t).length).to.equal(2);
        t.markKeyCertSentTo(a.fingerprint);
        const next = planKeyCertificateSends(t);
        expect(next.length).to.equal(1);
        expect(Buffer.from(next[0]).equals(Buffer.from(b.fingerprint))).to.equal(true);

    });

});
