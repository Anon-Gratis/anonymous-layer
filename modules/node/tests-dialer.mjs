import { expect } from 'chai';

import { createDialer } from './dialer.mjs';
import { createNode } from './node.mjs';
import { createNodeIdentity, currentCertificate } from './identity.mjs';
import { createIdentityCache } from './identity_cache.mjs';
import { createPeerTable } from '../peer/table.mjs';

// Fake transport: no I/O, but exposes a manual `forceClose()` so the
// test can simulate the peer dropping. Mirrors the Transport interface
// used by node.attach.
const makeFakeTransport = () => {

    const state = {
        _onMessage: null,
        _onClose: null,
        _closed: false,
        forceClose: () => {

            if (state._closed) return;
            state._closed = true;
            if (state._onClose) state._onClose();

        },
    };
    state.send = () => { /* no-op */ };
    state.onMessage = (h) => { state._onMessage = h; };
    state.onClose = (h) => { state._onClose = h; };
    state.close = () => { state.forceClose(); };
    return state;

};

const makeNode = () => {

    const identity = createNodeIdentity();
    const cert = currentCertificate({ identity, expirySeconds: 9_999_999_999 });
    const peerTable = createPeerTable();
    const identityCache = createIdentityCache();
    const node = createNode({
        identity,
        peerTable,
        identityCache,
        currentCertBytes: cert,
        onData: () => {},
    });
    return { identity, peerTable, node };

};

const dummyLogger = () => ({
    debug: () => {},
    info: () => {},
    warn: () => {},
    error: () => {},
});

describe('node/dialer', () => {

    it('dials once on connect; redials after disconnect with backoff', () => {

        const local = makeNode();
        const remote = makeNode();
        // Pre-seed local's peer table with remote so attach/detach work.
        local.peerTable.addOrUpdate({
            idPk: remote.identity.idPk,
            certBytes: currentCertificate({ identity: remote.identity, expirySeconds: 9_999_999_999 }),
            transports: [],
            nowSeconds: 0,
        });

        const createdTransports = [];
        const scheduled = [];
        const dialer = createDialer({
            node: local.node,
            logger: dummyLogger(),
            transportFactory: () => {

                const t = makeFakeTransport();
                createdTransports.push(t);
                return t;

            },
            schedule: (cb, ms) => {

                const handle = { cb, ms, cancelled: false };
                scheduled.push(handle);
                return handle;

            },
            cancel: (handle) => { handle.cancelled = true; },
            baseDelayMs: 100,
            maxDelayMs: 1000,
        });

        dialer.connect({
            fingerprint: remote.identity.fingerprint,
            host: '203.0.113.1',
            port: 8443,
        });
        expect(createdTransports.length).to.equal(1);
        expect(dialer.inspect(remote.identity.fingerprint).connected).to.equal(true);

        // Simulate the peer dropping.
        createdTransports[0].forceClose();
        expect(dialer.inspect(remote.identity.fingerprint).connected).to.equal(false);
        // attempts was incremented to 1 by the initial tryDial; the first
        // retry-after-disconnect computes delay for attempts=1 → 200 ms
        // ± 20% jitter → [160, 240].
        expect(scheduled.length).to.equal(1);
        expect(scheduled[0].ms).to.be.within(160, 240);

        // Fire the retry — a new transport should be created.
        scheduled[0].cb();
        expect(createdTransports.length).to.equal(2);
        expect(dialer.inspect(remote.identity.fingerprint).connected).to.equal(true);

    });

    it('attempts grow exponentially until maxDelayMs', () => {

        const local = makeNode();
        const remote = makeNode();
        local.peerTable.addOrUpdate({
            idPk: remote.identity.idPk,
            certBytes: currentCertificate({ identity: remote.identity, expirySeconds: 9_999_999_999 }),
            transports: [],
            nowSeconds: 0,
        });

        const transports = [];
        const scheduled = [];
        const dialer = createDialer({
            node: local.node,
            logger: dummyLogger(),
            transportFactory: () => {

                const t = makeFakeTransport();
                transports.push(t);
                return t;

            },
            schedule: (cb, ms) => {

                const handle = { cb, ms };
                scheduled.push(handle);
                return handle;

            },
            cancel: () => {},
            baseDelayMs: 100,
            maxDelayMs: 1000,
        });
        dialer.connect({
            fingerprint: remote.identity.fingerprint,
            host: '203.0.113.1',
            port: 8443,
        });

        // Cycle: close, fire retry, close, fire retry, ... and observe
        // the scheduled delays grow until they hit the cap.
        const observed = [];
        for (let i = 0; i < 6; i += 1) {

            const t = transports[transports.length - 1];
            t.forceClose();
            const last = scheduled[scheduled.length - 1];
            observed.push(last.ms);
            last.cb();

        }
        // attempts at each close are 1, 2, 3, 4, 5, 6 (incremented by
        // tryDial before the connect/close cycle that triggers it).
        // Ideal delays before cap: 200, 400, 800, 1600(→1000 cap),
        // 3200(→1000), 6400(→1000). Jitter is computed against the
        // UNCAPPED ideal, so when the cap binds the jitter band is still
        // ±20% of `ideal` — i.e. delay = min(ideal, cap) + jitter(ideal).
        // Our computeBackoff applies the cap BEFORE jitter, so capped
        // attempts use 1000 ± 200 → [800, 1200].
        expect(observed[0]).to.be.within(160, 240);
        expect(observed[1]).to.be.within(320, 480);
        expect(observed[2]).to.be.within(640, 960);
        for (let i = 3; i < 6; i += 1) {

            expect(observed[i]).to.be.within(800, 1200);

        }

    });

    it('disconnect cancels pending retries and detaches', () => {

        const local = makeNode();
        const remote = makeNode();
        local.peerTable.addOrUpdate({
            idPk: remote.identity.idPk,
            certBytes: currentCertificate({ identity: remote.identity, expirySeconds: 9_999_999_999 }),
            transports: [],
            nowSeconds: 0,
        });

        const transports = [];
        const scheduled = [];
        const dialer = createDialer({
            node: local.node,
            logger: dummyLogger(),
            transportFactory: () => {

                const t = makeFakeTransport();
                transports.push(t);
                return t;

            },
            schedule: (cb, ms) => {

                const handle = { cb, ms, cancelled: false };
                scheduled.push(handle);
                return handle;

            },
            cancel: (h) => { h.cancelled = true; },
        });
        dialer.connect({
            fingerprint: remote.identity.fingerprint,
            host: '203.0.113.1',
            port: 8443,
        });
        transports[0].forceClose(); // schedules retry
        expect(scheduled[0].cancelled).to.equal(false);

        dialer.disconnect(remote.identity.fingerprint);
        expect(scheduled[0].cancelled).to.equal(true);
        expect(dialer.inspect(remote.identity.fingerprint)).to.equal(null);

    });

    it('stop cancels all pending retries across multiple peers', () => {

        const local = makeNode();
        const remote1 = makeNode();
        const remote2 = makeNode();
        for (const r of [remote1, remote2]) {

            local.peerTable.addOrUpdate({
                idPk: r.identity.idPk,
                certBytes: currentCertificate({ identity: r.identity, expirySeconds: 9_999_999_999 }),
                transports: [],
                nowSeconds: 0,
            });

        }

        const transports = [];
        const scheduled = [];
        const dialer = createDialer({
            node: local.node,
            logger: dummyLogger(),
            transportFactory: () => {

                const t = makeFakeTransport();
                transports.push(t);
                return t;

            },
            schedule: (cb, ms) => {

                const handle = { cb, ms, cancelled: false };
                scheduled.push(handle);
                return handle;

            },
            cancel: (h) => { h.cancelled = true; },
        });
        dialer.connect({ fingerprint: remote1.identity.fingerprint, host: '203.0.113.1', port: 8443 });
        dialer.connect({ fingerprint: remote2.identity.fingerprint, host: '203.0.113.2', port: 8444 });
        transports[0].forceClose();
        transports[1].forceClose();
        expect(scheduled.length).to.equal(2);

        dialer.stop();
        expect(scheduled.every((s) => s.cancelled)).to.equal(true);
        expect(dialer.inspect(remote1.identity.fingerprint)).to.equal(null);
        expect(dialer.inspect(remote2.identity.fingerprint)).to.equal(null);

    });

});
