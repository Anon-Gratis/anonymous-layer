import { expect } from 'chai';

import { createNodeIdentity, currentCertificate } from './identity.mjs';
import { createIdentityCache } from './identity_cache.mjs';
import { createPeerTable } from '../peer/table.mjs';
import { createTransportPair } from './transport_inmemory.mjs';
import { createNode } from './node.mjs';

import { TRANSPORT_WEBSOCKET_IPV4 } from '../wire/transport.mjs';
import { encodePacket } from '../wire/packet.mjs';
import { TYPE_DATA } from '../wire/constants.mjs';
import { buildDataPayload } from '../wire/data.mjs';

// Helper: assemble a fully-wired Node along with a recording onData
// callback. The clock is shared (passed in) so tests can advance time
// deterministically across nodes.
const makeNode = ({ clock, expirySeconds = null }) => {

    const identity = createNodeIdentity();
    const now = () => clock.t;
    const exp = expirySeconds !== null ? expirySeconds : clock.t + 86400;
    const cert = currentCertificate({ identity, expirySeconds: exp });
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

// Helper: connect two nodes via an in-memory transport pair AND
// pre-seed each side's peer table with the other's certificate so they
// can encode packets to each other. (In normal operation each side
// learns the other's cert via KEY_CERTIFICATE — but the very first
// KEY_CERTIFICATE has to be sent by attach + tick, which means at
// least one side must already know the other's onionPk to encode
// even that bootstrap packet. The dial-bootstrap channel is responsible
// for the initial seeding — modeled here as pre-seeding the peer
// table from the seed list.)
const connect = (a, b) => {

    const [tA, tB] = createTransportPair();
    a.peerTable.addOrUpdate({
        idPk: b.identity.idPk,
        certBytes: b.certBytes,
        transports: [],
        nowSeconds: 0,
    });
    a.identityCache.set(b.identity.idPk);
    b.peerTable.addOrUpdate({
        idPk: a.identity.idPk,
        certBytes: a.certBytes,
        transports: [],
        nowSeconds: 0,
    });
    b.identityCache.set(a.identity.idPk);
    a.node.attach(b.identity.fingerprint, tA);
    b.node.attach(a.identity.fingerprint, tB);
    return [tA, tB];

};

describe('node — DATA exchange', () => {

    it('two nodes exchange DATA after connect', () => {

        const clock = { t: 1_000_000 };
        const alice = makeNode({ clock });
        const bob = makeNode({ clock });
        connect(alice, bob);

        const tag = new Uint8Array(16).fill(0xCA);
        alice.node.send({
            recipientFp: bob.identity.fingerprint,
            conversationTag: tag,
            sequenceNumber: 7n,
            payload: new Uint8Array([0xDE, 0xAD]),
        });

        expect(bob.received.length).to.equal(1);
        expect(Buffer.from(bob.received[0].senderFingerprint).equals(Buffer.from(alice.identity.fingerprint))).to.equal(true);
        expect(bob.received[0].sequenceNumber).to.equal(7n);
        expect(Buffer.from(bob.received[0].conversationTag).equals(Buffer.from(tag))).to.equal(true);
        expect(Buffer.from(bob.received[0].payload).equals(Buffer.from([0xDE, 0xAD]))).to.equal(true);

    });

    it('send() returns false when no peers are connected', () => {

        const clock = { t: 1_000_000 };
        const alice = makeNode({ clock });
        const result = alice.node.send({
            recipientFp: new Uint8Array(32),
            conversationTag: new Uint8Array(16),
            sequenceNumber: 0n,
            payload: new Uint8Array([1]),
        });
        expect(result).to.equal(false);

    });

    it('send() returns false for an unknown recipient even with other peers connected', () => {

        const clock = { t: 1_000_000 };
        const alice = makeNode({ clock });
        const bob = makeNode({ clock });
        connect(alice, bob);
        const stranger = createNodeIdentity();
        const ok = alice.node.send({
            recipientFp: stranger.fingerprint,
            conversationTag: new Uint8Array(16),
            sequenceNumber: 0n,
            payload: new Uint8Array([1]),
        });
        expect(ok).to.equal(false);

    });

    it('detach disables future sends to that peer', () => {

        const clock = { t: 1_000_000 };
        const alice = makeNode({ clock });
        const bob = makeNode({ clock });
        connect(alice, bob);
        alice.node.detach(bob.identity.fingerprint);
        const ok = alice.node.send({
            recipientFp: bob.identity.fingerprint,
            conversationTag: new Uint8Array(16),
            sequenceNumber: 0n,
            payload: new Uint8Array([1]),
        });
        expect(ok).to.equal(false);

    });

});

describe('node — KEY_CERTIFICATE handshake', () => {

    it('sendKeyCertificate populates the recipient identity cache', () => {

        const clock = { t: 1_000_000 };
        const alice = makeNode({ clock });
        const bob = makeNode({ clock });
        connect(alice, bob);

        alice.node.sendKeyCertificate(bob.identity.fingerprint);
        // bob should now have alice in identity cache and peer table.
        expect(bob.identityCache.has(alice.identity.fingerprint)).to.equal(true);
        const p = bob.peerTable.get(alice.identity.fingerprint);
        expect(p).to.not.equal(null);

    });

    it('tick() sends KEY_CERTIFICATE to connected peers exactly once', () => {

        const clock = { t: 1_000_000 };
        const alice = makeNode({ clock });
        const bob = makeNode({ clock });
        connect(alice, bob);

        alice.node.tick();
        expect(alice.peerTable.hasSentKeyCertTo(bob.identity.fingerprint)).to.equal(true);
        const before = bob.received.length;
        alice.node.tick();
        // A second tick should not re-send the cert to bob.
        expect(bob.received.length).to.equal(before);

    });

});

describe('node — ANNOUNCE_PEER gossip', () => {

    it('three-node gossip: A→B announces C, B learns C', () => {

        const clock = { t: 1_000_000 };
        const alice = makeNode({ clock });
        const bob = makeNode({ clock });
        const carol = makeNode({ clock });

        // Alice knows everyone (seed-list bootstrap simulated).
        for (const peer of [bob, carol]) {

            alice.peerTable.addOrUpdate({
                idPk: peer.identity.idPk,
                certBytes: peer.certBytes,
                transports: [{
                    type: TRANSPORT_WEBSOCKET_IPV4,
                    address: new Uint8Array([10, 0, 0, 1, 0x1F, 0x90]),
                }],
                nowSeconds: clock.t,
            });
            alice.identityCache.set(peer.identity.idPk);

        }

        // Bob and Alice are connected; Alice and Carol are connected;
        // Bob and Carol are NOT — Bob should learn about Carol from
        // Alice's gossip.
        const [tAB, tBA] = createTransportPair();
        bob.peerTable.addOrUpdate({
            idPk: alice.identity.idPk,
            certBytes: alice.certBytes,
            transports: [],
            nowSeconds: clock.t,
        });
        bob.identityCache.set(alice.identity.idPk);
        alice.node.attach(bob.identity.fingerprint, tAB);
        bob.node.attach(alice.identity.fingerprint, tBA);

        // Alice needs Carol in her peer table as "not connected" so
        // pickAnnouncementSubject considers her — she's already in,
        // and not connected. Good.

        // Before bob can verify ANNOUNCE_PEER about carol, bob needs
        // carol's idPk in his identity cache. SPEC § 6.6 expects an
        // earlier KEY_CERTIFICATE to have populated it; in this test
        // we just pre-populate.
        bob.identityCache.set(carol.identity.idPk);

        // Alice ticks — should plan an announce to bob about carol.
        alice.node.tick();
        // (Alice also sends KEY_CERTIFICATE on tick; we don't care.)

        expect(bob.peerTable.get(carol.identity.fingerprint)).to.not.equal(null);

    });

    it('ANNOUNCE_PEER for an unknown announced idPk is silently dropped', () => {

        const clock = { t: 1_000_000 };
        const alice = makeNode({ clock });
        const bob = makeNode({ clock });
        const carol = makeNode({ clock });

        for (const peer of [bob, carol]) {

            alice.peerTable.addOrUpdate({
                idPk: peer.identity.idPk,
                certBytes: peer.certBytes,
                transports: [],
                nowSeconds: clock.t,
            });
            alice.identityCache.set(peer.identity.idPk);

        }
        bob.peerTable.addOrUpdate({
            idPk: alice.identity.idPk,
            certBytes: alice.certBytes,
            transports: [],
            nowSeconds: clock.t,
        });
        bob.identityCache.set(alice.identity.idPk);
        const [tAB, tBA] = createTransportPair();
        alice.node.attach(bob.identity.fingerprint, tAB);
        bob.node.attach(alice.identity.fingerprint, tBA);

        // Deliberately do NOT populate bob.identityCache with carol.
        alice.node.sendAnnouncePeer(bob.identity.fingerprint, carol.identity.fingerprint);

        // Bob never learned about carol because he couldn't verify.
        expect(bob.peerTable.get(carol.identity.fingerprint)).to.equal(null);

    });

});

describe('node — FORWARD relay', () => {

    it('A→B→C delivers an inner packet without B decrypting it', () => {

        const clock = { t: 1_000_000 };
        const alice = makeNode({ clock });
        const bob = makeNode({ clock });
        const carol = makeNode({ clock });

        // Alice knows bob (forwarder) and carol (destination). Carol
        // knows alice (so AEAD ciphertext-prefix matches). Bob is
        // the only one connected to both.
        connect(alice, bob);
        connect(bob, carol);

        // Build the inner packet: alice → carol, addressed by carol's
        // identity. Alice needs carol's onionPk to construct it.
        alice.peerTable.addOrUpdate({
            idPk: carol.identity.idPk,
            certBytes: carol.certBytes,
            transports: [],
            nowSeconds: clock.t,
        });
        alice.identityCache.set(carol.identity.idPk);
        carol.peerTable.addOrUpdate({
            idPk: alice.identity.idPk,
            certBytes: alice.certBytes,
            transports: [],
            nowSeconds: clock.t,
        });
        carol.identityCache.set(alice.identity.idPk);

        const tag = new Uint8Array(16).fill(0xEE);
        const dataPayload = buildDataPayload({
            conversationTag: tag,
            sequenceNumber: 1n,
            payload: new Uint8Array([0x99]),
        });
        const innerPacket = encodePacket({
            recipientIdPk: carol.identity.idPk,
            recipientOnionPk: alice.peerTable.get(carol.identity.fingerprint).onionPk,
            senderFingerprint: alice.identity.fingerprint,
            packetType: TYPE_DATA,
            payload: dataPayload,
        });

        // Alice asks bob (forwarder) to deliver to carol (next-hop).
        alice.node.forward({
            forwarderFp: bob.identity.fingerprint,
            nextHopFp: carol.identity.fingerprint,
            transports: [],
            innerPacket,
        });

        // Carol should have received the DATA, with alice as the
        // attributed sender (because the DATA packet was encoded
        // by alice).
        expect(carol.received.length).to.equal(1);
        expect(Buffer.from(carol.received[0].senderFingerprint).equals(Buffer.from(alice.identity.fingerprint))).to.equal(true);

        // Bob never received DATA — only the FORWARD wrapper.
        expect(bob.received.length).to.equal(0);

    });

});

describe('node — silent-drop discipline (§ 9.1)', () => {

    it('replayed inbound packet evicts the sender via inner-validation-fail attribution', () => {

        const clock = { t: 1_000_000 };
        const alice = makeNode({ clock });
        const bob = makeNode({ clock });
        const [tAB] = connect(alice, bob);

        // Encode a real DATA packet alice → bob, then deliver it twice
        // through bob's live transport. The second delivery hits the
        // wire-layer replayLog; the dispatcher's onPostAeadFailure
        // routes that to peerTable.markInnerValidationFailed.
        const bobOnion = alice.peerTable.get(bob.identity.fingerprint).onionPk;
        const packet = encodePacket({
            recipientIdPk: bob.identity.idPk,
            recipientOnionPk: bobOnion,
            senderFingerprint: alice.identity.fingerprint,
            packetType: TYPE_DATA,
            payload: buildDataPayload({
                conversationTag: new Uint8Array(16),
                sequenceNumber: 0n,
                payload: new Uint8Array([0xAA]),
            }),
        });

        // First delivery — bob accepts.
        tAB.send(packet);
        expect(bob.received.length).to.equal(1);
        expect(bob.peerTable.get(alice.identity.fingerprint)).to.not.equal(null);

        // Second delivery — bob's replay log rejects, dispatcher evicts.
        tAB.send(packet);
        expect(bob.received.length).to.equal(1); // no new DATA delivered
        expect(bob.peerTable.get(alice.identity.fingerprint)).to.equal(null);

    });

    it('malformed DATA payload (< 24 bytes) evicts the sender', () => {

        const clock = { t: 1_000_000 };
        const alice = makeNode({ clock });
        const bob = makeNode({ clock });
        const [tAB] = connect(alice, bob);

        // Hand-craft a DATA packet with a 10-byte payload — below the
        // 24-byte minimum required by SPEC § 6.3. AEAD will succeed
        // because we encrypted it properly; the dispatcher must catch
        // the structural failure post-AEAD and evict.
        const bobOnion = alice.peerTable.get(bob.identity.fingerprint).onionPk;
        const packet = encodePacket({
            recipientIdPk: bob.identity.idPk,
            recipientOnionPk: bobOnion,
            senderFingerprint: alice.identity.fingerprint,
            packetType: TYPE_DATA,
            payload: new Uint8Array(10), // too short for DATA
        });

        expect(bob.peerTable.get(alice.identity.fingerprint)).to.not.equal(null);
        tAB.send(packet);
        expect(bob.received.length).to.equal(0);
        expect(bob.peerTable.get(alice.identity.fingerprint)).to.equal(null);

    });

    it('packet from an off-path attacker addressed to a different recipient is silently dropped without eviction', () => {

        const clock = { t: 1_000_000 };
        const alice = makeNode({ clock });
        const bob = makeNode({ clock });
        const eve = makeNode({ clock });
        const [tAB] = connect(alice, bob);

        // Eve constructs a packet addressed to herself, then sends it
        // through alice's transport to bob. Bob's prefix-filter
        // mismatches (pre-AEAD failure per SPEC § 5.7 step 4) —
        // attribution is unavailable, so bob MUST NOT evict alice.
        const ePacket = encodePacket({
            recipientIdPk: eve.identity.idPk,
            recipientOnionPk: eve.identity.onionPk,
            senderFingerprint: eve.identity.fingerprint,
            packetType: TYPE_DATA,
            payload: buildDataPayload({
                conversationTag: new Uint8Array(16),
                sequenceNumber: 0n,
                payload: new Uint8Array([1]),
            }),
        });
        expect(bob.peerTable.get(alice.identity.fingerprint)).to.not.equal(null);
        tAB.send(ePacket);
        expect(bob.received.length).to.equal(0);
        // CRITICAL § 7.4 property: pre-AEAD failures must not evict.
        expect(bob.peerTable.get(alice.identity.fingerprint)).to.not.equal(null);

    });

});
