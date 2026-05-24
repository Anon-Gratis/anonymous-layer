import { expect } from 'chai';

import { createNodeIdentity, currentCertificate } from './identity.mjs';
import { createIdentityCache } from './identity_cache.mjs';
import { createPeerTable } from '../peer/table.mjs';
import { createNode } from './node.mjs';
import {
    dialWebSocket,
    createWebSocketListener,
} from './transport_websocket.mjs';

// Helper to build a fully-wired Node. Mirrors the helper in tests.mjs
// but returns enough handles for an async, transport-aware test.
const makeNode = ({ clock }) => {

    const identity = createNodeIdentity();
    const now = () => clock.t;
    const cert = currentCertificate({ identity, expirySeconds: clock.t + 86400 });
    const peerTable = createPeerTable({ now });
    const identityCache = createIdentityCache();
    const received = [];
    const node = createNode({
        identity,
        peerTable,
        identityCache,
        currentCertBytes: cert,
        onData: (msg) => received.push(msg),
        nowSeconds: now,
    });
    return { identity, peerTable, identityCache, certBytes: cert, node, received };

};

// Pre-seed B's peer-table-and-identity-cache with A's identity so B
// can encode the very first KEY_CERTIFICATE to A — i.e., simulate
// what the seed list would have done. (A doesn't need pre-seeding;
// it learns about B from the inbound KEY_CERTIFICATE.)
const seedDialerWithListener = (dialer, listener) => {

    dialer.peerTable.addOrUpdate({
        idPk: listener.identity.idPk,
        certBytes: listener.certBytes,
        transports: [],
        nowSeconds: 0,
    });
    dialer.identityCache.set(listener.identity.idPk);

};

// Tiny polling helper — Mocha-friendly, no timer cleanup needed.
const awaitUntil = async (predicate, { intervalMs = 10, timeoutMs = 1000 } = {}) => {

    const start = Date.now();
    while (Date.now() - start < timeoutMs) {

        if (predicate()) return true;
        await new Promise((r) => setTimeout(r, intervalMs));

    }
    return false;

};

describe('node — WebSocket transport', function () {

    // Several tests bind ephemeral ports + handshake — generous timeout
    // to avoid CI flakes.
    this.timeout(5000);

    let listenerHandle = null;
    const dialerNodes = [];

    afterEach(async () => {

        // Detach all dialer-side transports so the WebSockets close.
        for (const { node, otherFp } of dialerNodes) {

            try { node.detach(otherFp); } catch { /* ignore */ }

        }
        dialerNodes.length = 0;

        if (listenerHandle) {

            await listenerHandle.close();
            listenerHandle = null;

        }

    });

    const registerDialer = (node, otherFp) => dialerNodes.push({ node, otherFp });

    it('two nodes complete a KEY_CERTIFICATE handshake over a real WS connection', async () => {

        const clock = { t: 1_000_000 };
        const alice = makeNode({ clock }); // listener
        const bob = makeNode({ clock });   // dialer

        listenerHandle = createWebSocketListener({ port: 0 }, (transport) => {

            alice.node.acceptInbound(transport);

        });
        await listenerHandle.ready;
        const port = listenerHandle.port;

        seedDialerWithListener(bob, alice);
        const transport = dialWebSocket({ host: '127.0.0.1', port });
        bob.node.attach(alice.identity.fingerprint, transport);

        // Bob's first tick sends KEY_CERTIFICATE to alice. Alice's
        // dispatcher promotes the inbound transport once verify succeeds.
        bob.node.tick();

        const handshook = await awaitUntil(
            () => alice.peerTable.get(bob.identity.fingerprint) !== null,
        );
        expect(handshook).to.equal(true);
        expect(alice.peerTable.get(bob.identity.fingerprint).connected).to.equal(true);

    });

    it('DATA exchange works in both directions after handshake', async () => {

        const clock = { t: 1_000_000 };
        const alice = makeNode({ clock });
        const bob = makeNode({ clock });

        listenerHandle = createWebSocketListener({ port: 0 }, (transport) => {

            alice.node.acceptInbound(transport);

        });
        await listenerHandle.ready;

        seedDialerWithListener(bob, alice);
        const transport = dialWebSocket({ host: '127.0.0.1', port: listenerHandle.port });
        bob.node.attach(alice.identity.fingerprint, transport);
        registerDialer(bob.node, alice.identity.fingerprint);
        bob.node.tick();
        await awaitUntil(() => alice.peerTable.get(bob.identity.fingerprint) !== null);

        // Alice ticks so she sends her KEY_CERTIFICATE to bob; bob's
        // identity cache already had alice (seeded), but the tick also
        // confirms alice has the keyCertSentTo state correct.
        alice.node.tick();
        // Bob already knows alice from the seed; both onion keys present.

        // Bob → Alice.
        const tagBA = new Uint8Array(16).fill(0xBA);
        bob.node.send({
            recipientFp: alice.identity.fingerprint,
            conversationTag: tagBA,
            sequenceNumber: 1n,
            payload: new Uint8Array([0xB0, 0xB1]),
        });
        const aliceGot = await awaitUntil(() => alice.received.length >= 1);
        expect(aliceGot).to.equal(true);
        expect(alice.received[0].sequenceNumber).to.equal(1n);
        expect(Buffer.from(alice.received[0].payload).equals(Buffer.from([0xB0, 0xB1]))).to.equal(true);

        // Alice → Bob.
        const tagAB = new Uint8Array(16).fill(0xAB);
        alice.node.send({
            recipientFp: bob.identity.fingerprint,
            conversationTag: tagAB,
            sequenceNumber: 2n,
            payload: new Uint8Array([0xA0, 0xA1, 0xA2]),
        });
        const bobGot = await awaitUntil(() => bob.received.length >= 1);
        expect(bobGot).to.equal(true);
        expect(bob.received[0].sequenceNumber).to.equal(2n);
        expect(Buffer.from(bob.received[0].payload).equals(Buffer.from([0xA0, 0xA1, 0xA2]))).to.equal(true);

    });

    it('closing one side marks the peer disconnected on the other side', async () => {

        const clock = { t: 1_000_000 };
        const alice = makeNode({ clock });
        const bob = makeNode({ clock });

        let bobsTransportOnAlice = null;
        listenerHandle = createWebSocketListener({ port: 0 }, (transport) => {

            bobsTransportOnAlice = transport;
            alice.node.acceptInbound(transport);

        });
        await listenerHandle.ready;

        seedDialerWithListener(bob, alice);
        const transport = dialWebSocket({ host: '127.0.0.1', port: listenerHandle.port });
        bob.node.attach(alice.identity.fingerprint, transport);
        registerDialer(bob.node, alice.identity.fingerprint);
        bob.node.tick();
        await awaitUntil(() => alice.peerTable.get(bob.identity.fingerprint) !== null);
        expect(alice.peerTable.get(bob.identity.fingerprint).connected).to.equal(true);

        // Bob closes his side.
        bob.node.detach(alice.identity.fingerprint);

        const disconnected = await awaitUntil(
            () => {

                const p = alice.peerTable.get(bob.identity.fingerprint);
                return p !== null && p.connected === false;

            },
        );
        expect(disconnected).to.equal(true);

    });

    it('listener.close() shuts down the server and existing connections', async () => {

        const clock = { t: 1_000_000 };
        const alice = makeNode({ clock });
        const bob = makeNode({ clock });

        const handle = createWebSocketListener({ port: 0 }, (transport) => {

            alice.node.acceptInbound(transport);

        });
        await handle.ready;

        seedDialerWithListener(bob, alice);
        const transport = dialWebSocket({ host: '127.0.0.1', port: handle.port });
        bob.node.attach(alice.identity.fingerprint, transport);
        registerDialer(bob.node, alice.identity.fingerprint);
        bob.node.tick();
        await awaitUntil(() => alice.peerTable.get(bob.identity.fingerprint) !== null);

        await handle.close();

        // After close, bob's transport should disconnect.
        const bobDisconnected = await awaitUntil(
            () => {

                const p = bob.peerTable.get(alice.identity.fingerprint);
                return p !== null && p.connected === false;

            },
        );
        expect(bobDisconnected).to.equal(true);
        // listenerHandle is intentionally null here — we already closed it.

    });

});
