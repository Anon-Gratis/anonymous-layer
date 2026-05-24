import { expect } from 'chai';

import { TYPE_DATA, BUCKET_SMALL, BUCKET_MEDIUM, BUCKET_LARGE, bucketSize } from './constants.mjs';
import { buildDataPayload, parseDataPayload, LEN_DATA_PREFIX } from './data.mjs';
import {
    serializeTransports,
    parseTransports,
    TRANSPORT_WEBSOCKET_IPV4,
    TRANSPORT_WEBSOCKET_IPV6,
    MAX_TRANSPORT_COUNT,
} from './transport.mjs';
import {
    buildAnnouncePeerPayload,
    parseAnnouncePeerPayload,
    verifyAnnouncePeer,
    ANNOUNCE_PEER_MIN_LENGTH,
} from './announce.mjs';
import {
    buildKeyCertificatePayload,
    parseKeyCertificatePayload,
    verifyKeyCertificate,
    KEY_CERTIFICATE_LENGTH,
} from './key_certificate.mjs';
import { buildForwardPayload, parseForwardPayload } from './forward.mjs';
import { createForwardRateLimiter } from './forward_rate_limit.mjs';
import { encodePacket } from './packet.mjs';

import { generateIdentity, identityFingerprint } from '../crypto/identity.mjs';
import { generateOnion } from '../crypto/onion.mjs';
import { buildCertificate } from '../crypto/cert.mjs';

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

describe('wire/data', () => {

    it('round-trips a non-empty payload', () => {

        const tag = new Uint8Array(16).fill(0xA0);
        const seq = 0x0123456789ABCDEFn;
        const payload = new Uint8Array([1, 2, 3, 4, 5]);
        const buf = buildDataPayload({ conversationTag: tag, sequenceNumber: seq, payload });
        expect(buf.length).to.equal(LEN_DATA_PREFIX + payload.length);

        const parsed = parseDataPayload(buf);
        expect(parsed).to.not.equal(null);
        expect(Buffer.from(parsed.conversationTag).equals(Buffer.from(tag))).to.equal(true);
        expect(parsed.sequenceNumber).to.equal(seq);
        expect(Buffer.from(parsed.payload).equals(Buffer.from(payload))).to.equal(true);

    });

    it('round-trips with zero application bytes (real_length == 24)', () => {

        const tag = new Uint8Array(16);
        const buf = buildDataPayload({ conversationTag: tag, sequenceNumber: 0n, payload: new Uint8Array(0) });
        expect(buf.length).to.equal(24);
        const parsed = parseDataPayload(buf);
        expect(parsed.payload.length).to.equal(0);
        expect(parsed.sequenceNumber).to.equal(0n);

    });

    it('parseDataPayload returns null on undersized payload', () => {

        expect(parseDataPayload(new Uint8Array(23))).to.equal(null);
        expect(parseDataPayload(new Uint8Array(0))).to.equal(null);
        expect(parseDataPayload(null)).to.equal(null);

    });

    it('buildDataPayload throws on wrong-sized tag', () => {

        expect(() => buildDataPayload({
            conversationTag: new Uint8Array(15),
            sequenceNumber: 0n,
            payload: new Uint8Array(0),
        })).to.throw();

    });

});

describe('wire/transport', () => {

    it('round-trips zero transports', () => {

        const buf = serializeTransports([]);
        expect(buf.length).to.equal(1);
        expect(buf[0]).to.equal(0);
        const parsed = parseTransports(buf, 0);
        expect(parsed.transports).to.deep.equal([]);
        expect(parsed.consumed).to.equal(1);

    });

    it('round-trips known transport types with correct lengths', () => {

        const v4 = new Uint8Array([10, 0, 0, 1, 0x1F, 0x90]); // 10.0.0.1:8080
        const v6 = new Uint8Array(18); v6.fill(0xAB);
        const buf = serializeTransports([
            { type: TRANSPORT_WEBSOCKET_IPV4, address: v4 },
            { type: TRANSPORT_WEBSOCKET_IPV6, address: v6 },
        ]);
        const parsed = parseTransports(buf, 0);
        expect(parsed.transports.length).to.equal(2);
        expect(parsed.transports[0].type).to.equal(TRANSPORT_WEBSOCKET_IPV4);
        expect(Buffer.from(parsed.transports[0].address).equals(Buffer.from(v4))).to.equal(true);
        expect(parsed.transports[1].type).to.equal(TRANSPORT_WEBSOCKET_IPV6);
        expect(Buffer.from(parsed.transports[1].address).equals(Buffer.from(v6))).to.equal(true);
        expect(parsed.consumed).to.equal(buf.length);

    });

    it('passes through unknown transport types', () => {

        const unknownAddr = new Uint8Array([1, 2, 3, 4, 5]);
        const buf = serializeTransports([{ type: 0x7F, address: unknownAddr }]);
        const parsed = parseTransports(buf, 0);
        expect(parsed.transports[0].type).to.equal(0x7F);
        expect(Buffer.from(parsed.transports[0].address).equals(Buffer.from(unknownAddr))).to.equal(true);

    });

    it('serializeTransports throws on canonical-length mismatch for known types', () => {

        expect(() => serializeTransports([
            { type: TRANSPORT_WEBSOCKET_IPV4, address: new Uint8Array(5) },
        ])).to.throw();

    });

    it('serializeTransports throws above MAX_TRANSPORT_COUNT', () => {

        const too_many = new Array(MAX_TRANSPORT_COUNT + 1).fill(0).map(() => ({
            type: 0x7F,
            address: new Uint8Array(0),
        }));
        expect(() => serializeTransports(too_many)).to.throw();

    });

    it('parseTransports returns null on truncated record', () => {

        // count says 1, but no record bytes follow
        expect(parseTransports(new Uint8Array([1]), 0)).to.equal(null);
        // header present, address length says 10, only 5 follow
        expect(parseTransports(new Uint8Array([1, 0x7F, 10, 0, 0, 0, 0, 0]), 0)).to.equal(null);

    });

    it('parseTransports rejects wrong-length address for known type', () => {

        // type=WEBSOCKET_IPV4 (0x01), length=5 (should be 6) — must reject
        const buf = new Uint8Array([1, TRANSPORT_WEBSOCKET_IPV4, 5, 0, 0, 0, 0, 0]);
        expect(parseTransports(buf, 0)).to.equal(null);

    });

    it('parseTransports returns null on out-of-range offset', () => {

        expect(parseTransports(new Uint8Array(0), 0)).to.equal(null);
        expect(parseTransports(new Uint8Array(5), 6)).to.equal(null);

    });

});

describe('wire/announce', () => {

    const now = () => Math.floor(Date.now() / 1000);

    it('round-trips an ANNOUNCE_PEER payload with two transports', () => {

        const announced = makeParty();
        const cert = makeCert(announced, now() + 86400);
        const v4 = new Uint8Array([192, 168, 0, 1, 0x1F, 0x90]);
        const v6 = new Uint8Array(18).fill(0x11);
        const buf = buildAnnouncePeerPayload({
            announcedFingerprint: announced.fingerprint,
            certBytes: cert,
            transports: [
                { type: TRANSPORT_WEBSOCKET_IPV4, address: v4 },
                { type: TRANSPORT_WEBSOCKET_IPV6, address: v6 },
            ],
        });
        expect(buf.length).to.be.greaterThan(ANNOUNCE_PEER_MIN_LENGTH);

        const parsed = parseAnnouncePeerPayload(buf);
        expect(parsed).to.not.equal(null);
        expect(Buffer.from(parsed.announcedFingerprint).equals(Buffer.from(announced.fingerprint))).to.equal(true);
        expect(Buffer.from(parsed.certBytes).equals(Buffer.from(cert))).to.equal(true);
        expect(parsed.transports.length).to.equal(2);

    });

    it('parseAnnouncePeerPayload rejects undersized payloads', () => {

        expect(parseAnnouncePeerPayload(new Uint8Array(ANNOUNCE_PEER_MIN_LENGTH - 1))).to.equal(null);
        expect(parseAnnouncePeerPayload(null)).to.equal(null);

    });

    it('parseAnnouncePeerPayload rejects trailing bytes after transport list', () => {

        const announced = makeParty();
        const cert = makeCert(announced, now() + 86400);
        const ok = buildAnnouncePeerPayload({
            announcedFingerprint: announced.fingerprint,
            certBytes: cert,
            transports: [],
        });
        // append a junk byte
        const tampered = new Uint8Array(ok.length + 1);
        tampered.set(ok);
        expect(parseAnnouncePeerPayload(tampered)).to.equal(null);

    });

    it('verifyAnnouncePeer succeeds for a valid announce', () => {

        const announced = makeParty();
        const cert = makeCert(announced, now() + 86400);
        const buf = buildAnnouncePeerPayload({
            announcedFingerprint: announced.fingerprint,
            certBytes: cert,
            transports: [],
        });
        const parsed = parseAnnouncePeerPayload(buf);
        expect(verifyAnnouncePeer({
            parsed,
            announcedIdPk: announced.idPk,
            nowSeconds: now(),
        })).to.equal(true);

    });

    it('verifyAnnouncePeer rejects fingerprint that does not match idPk', () => {

        const announced = makeParty();
        const impostor = makeParty();
        const cert = makeCert(announced, now() + 86400);
        // Wire format claims impostor's fingerprint but cert is for announced
        const buf = buildAnnouncePeerPayload({
            announcedFingerprint: impostor.fingerprint,
            certBytes: cert,
            transports: [],
        });
        const parsed = parseAnnouncePeerPayload(buf);
        // Try to verify under announced's idPk: H(announced.idPk) != claimed fp
        expect(verifyAnnouncePeer({
            parsed,
            announcedIdPk: announced.idPk,
            nowSeconds: now(),
        })).to.equal(false);
        // Try under impostor's idPk: fingerprint matches but cert was
        // signed by announced — signature verification fails.
        expect(verifyAnnouncePeer({
            parsed,
            announcedIdPk: impostor.idPk,
            nowSeconds: now(),
        })).to.equal(false);

    });

    it('verifyAnnouncePeer rejects an expired certificate', () => {

        const announced = makeParty();
        const cert = makeCert(announced, now() - 1);
        const buf = buildAnnouncePeerPayload({
            announcedFingerprint: announced.fingerprint,
            certBytes: cert,
            transports: [],
        });
        const parsed = parseAnnouncePeerPayload(buf);
        expect(verifyAnnouncePeer({
            parsed,
            announcedIdPk: announced.idPk,
            nowSeconds: now(),
        })).to.equal(false);

    });

});

describe('wire/key_certificate', () => {

    const now = () => Math.floor(Date.now() / 1000);

    it('payload is exactly 137 bytes', () => {

        const party = makeParty();
        const cert = makeCert(party, now() + 86400);
        const buf = buildKeyCertificatePayload({ idPk: party.idPk, certBytes: cert });
        expect(buf.length).to.equal(KEY_CERTIFICATE_LENGTH);
        expect(buf.length).to.equal(137);

    });

    it('round-trips', () => {

        const party = makeParty();
        const cert = makeCert(party, now() + 86400);
        const buf = buildKeyCertificatePayload({ idPk: party.idPk, certBytes: cert });
        const parsed = parseKeyCertificatePayload(buf);
        expect(parsed).to.not.equal(null);
        expect(Buffer.from(parsed.idPk).equals(Buffer.from(party.idPk))).to.equal(true);
        expect(Buffer.from(parsed.certBytes).equals(Buffer.from(cert))).to.equal(true);

    });

    it('parseKeyCertificatePayload rejects wrong-length payload', () => {

        expect(parseKeyCertificatePayload(new Uint8Array(136))).to.equal(null);
        expect(parseKeyCertificatePayload(new Uint8Array(138))).to.equal(null);
        expect(parseKeyCertificatePayload(null)).to.equal(null);

    });

    it('verifyKeyCertificate succeeds for a valid pair', () => {

        const party = makeParty();
        const cert = makeCert(party, now() + 86400);
        const buf = buildKeyCertificatePayload({ idPk: party.idPk, certBytes: cert });
        const parsed = parseKeyCertificatePayload(buf);
        expect(verifyKeyCertificate({
            parsed,
            senderFingerprint: party.fingerprint,
            nowSeconds: now(),
        })).to.equal(true);

    });

    it('verifyKeyCertificate rejects a mismatched sender fingerprint', () => {

        const party = makeParty();
        const other = makeParty();
        const cert = makeCert(party, now() + 86400);
        const buf = buildKeyCertificatePayload({ idPk: party.idPk, certBytes: cert });
        const parsed = parseKeyCertificatePayload(buf);
        expect(verifyKeyCertificate({
            parsed,
            senderFingerprint: other.fingerprint,
            nowSeconds: now(),
        })).to.equal(false);

    });

    it('verifyKeyCertificate rejects an expired certificate', () => {

        const party = makeParty();
        const cert = makeCert(party, now() - 1);
        const buf = buildKeyCertificatePayload({ idPk: party.idPk, certBytes: cert });
        const parsed = parseKeyCertificatePayload(buf);
        expect(verifyKeyCertificate({
            parsed,
            senderFingerprint: party.fingerprint,
            nowSeconds: now(),
        })).to.equal(false);

    });

});

describe('wire/forward', () => {

    // Forge a minimal valid inner packet for the forward path: build a
    // real one by encoding a DATA packet to a fresh recipient.
    const makeInnerPacket = (nextHop, payloadSize = 4) => encodePacket({
        recipientIdPk: nextHop.idPk,
        recipientOnionPk: nextHop.onionPk,
        senderFingerprint: nextHop.fingerprint, // arbitrary
        packetType: TYPE_DATA,
        payload: new Uint8Array(payloadSize),
    });

    it('round-trips a FORWARD payload with a real inner packet', () => {

        const sender = makeParty();
        const nextHop = makeParty();
        const inner = makeInnerPacket(nextHop);
        expect(inner.length).to.equal(256);

        const buf = buildForwardPayload({
            nextHopFingerprint: nextHop.fingerprint,
            transports: [{
                type: TRANSPORT_WEBSOCKET_IPV4,
                address: new Uint8Array([127, 0, 0, 1, 0x1F, 0x90]),
            }],
            innerPacket: inner,
        });

        const parsed = parseForwardPayload(buf);
        expect(parsed).to.not.equal(null);
        expect(Buffer.from(parsed.nextHopFingerprint).equals(Buffer.from(nextHop.fingerprint))).to.equal(true);
        expect(parsed.transports.length).to.equal(1);
        expect(Buffer.from(parsed.innerPacket).equals(Buffer.from(inner))).to.equal(true);

    });

    it('round-trips with each of the three inner bucket sizes', () => {

        const nextHop = makeParty();
        for (const size of [256, 1024, 4096]) {

            // Picked above each bucket's predecessor capacity:
            //   256 → 4   (≤ 151 fits in BUCKET_SMALL)
            //   1024 → 200 (152..919 fits in BUCKET_MEDIUM)
            //   4096 → 1000 (920..3991 fits in BUCKET_LARGE)
            const innerPayloadSize = size === 256 ? 4 : (size === 1024 ? 200 : 1000);
            const inner = makeInnerPacket(nextHop, innerPayloadSize);
            expect(inner.length).to.equal(size);
            const buf = buildForwardPayload({
                nextHopFingerprint: nextHop.fingerprint,
                transports: [],
                innerPacket: inner,
            });
            const parsed = parseForwardPayload(buf);
            expect(parsed).to.not.equal(null);
            expect(parsed.innerPacket.length).to.equal(size);

        }

    });

    it('buildForwardPayload throws on a non-bucket inner packet length', () => {

        const nextHop = makeParty();
        expect(() => buildForwardPayload({
            nextHopFingerprint: nextHop.fingerprint,
            transports: [],
            innerPacket: new Uint8Array(500),
        })).to.throw();

    });

    it('parseForwardPayload rejects a non-bucket inner packet length', () => {

        // Craft a payload by hand: fp + 0 transports + 500-byte "inner"
        const nextHop = makeParty();
        const transportBytes = serializeTransports([]);
        const innerFake = new Uint8Array(500);
        const buf = new Uint8Array(32 + transportBytes.length + innerFake.length);
        buf.set(nextHop.fingerprint, 0);
        buf.set(transportBytes, 32);
        buf.set(innerFake, 32 + transportBytes.length);
        expect(parseForwardPayload(buf)).to.equal(null);

    });

    it('parseForwardPayload rejects when inner recipient_prefix does not match next-hop fingerprint', () => {

        const nextHop = makeParty();
        const wrongHop = makeParty();
        const inner = makeInnerPacket(nextHop); // prefix from nextHop's fingerprint
        // Build a forward whose declared next-hop is wrongHop but whose
        // inner packet targets nextHop.
        const buf = buildForwardPayload({
            nextHopFingerprint: wrongHop.fingerprint,
            transports: [],
            innerPacket: inner,
        });
        expect(parseForwardPayload(buf)).to.equal(null);

    });

    it('parseForwardPayload returns null on undersized input', () => {

        expect(parseForwardPayload(new Uint8Array(10))).to.equal(null);
        expect(parseForwardPayload(null)).to.equal(null);

    });

});

describe('wire/forward_rate_limit', () => {

    const eph = (b) => new Uint8Array(32).fill(b);
    const fp = (b) => new Uint8Array(32).fill(b);

    it('accepts within all three limits', () => {

        const rl = createForwardRateLimiter();
        for (let i = 0; i < 10; i += 1) {

            expect(rl.checkAndCount({ sourceEphPk: eph(i), destFingerprint: fp(0) })).to.equal(true);

        }

    });

    it('enforces per-source limit (32 / 60s)', () => {

        let clock = 1_000_000;
        const rl = createForwardRateLimiter({ now: () => clock });
        for (let i = 0; i < 32; i += 1) {

            expect(rl.checkAndCount({ sourceEphPk: eph(1), destFingerprint: fp(i) })).to.equal(true);

        }
        // 33rd request from the same source within the window — drop.
        expect(rl.checkAndCount({ sourceEphPk: eph(1), destFingerprint: fp(99) })).to.equal(false);
        // A different source is still fine.
        expect(rl.checkAndCount({ sourceEphPk: eph(2), destFingerprint: fp(99) })).to.equal(true);
        // After the window advances, the source is allowed again.
        clock += 61;
        expect(rl.checkAndCount({ sourceEphPk: eph(1), destFingerprint: fp(99) })).to.equal(true);

    });

    it('enforces per-destination limit (64 / 60s)', () => {

        let clock = 1_000_000;
        const rl = createForwardRateLimiter({ now: () => clock });
        for (let i = 0; i < 64; i += 1) {

            expect(rl.checkAndCount({ sourceEphPk: eph(i), destFingerprint: fp(7) })).to.equal(true);

        }
        // 65th request to the same destination — drop.
        expect(rl.checkAndCount({ sourceEphPk: eph(200), destFingerprint: fp(7) })).to.equal(false);
        // Different destination still works.
        expect(rl.checkAndCount({ sourceEphPk: eph(200), destFingerprint: fp(8) })).to.equal(true);
        // After the window advances, drained.
        clock += 61;
        expect(rl.checkAndCount({ sourceEphPk: eph(200), destFingerprint: fp(7) })).to.equal(true);

    });

    it('enforces global limit (4096 / 60s)', () => {

        // Use a low global limit so the test is fast.
        let clock = 1_000_000;
        const rl = createForwardRateLimiter({
            now: () => clock,
            globalLimit: 100,
            perSourceLimit: 100,
            perDestinationLimit: 100,
        });
        for (let i = 0; i < 100; i += 1) {

            // Spread across sources and destinations so only the global cap binds.
            expect(rl.checkAndCount({ sourceEphPk: eph(i & 0xFF), destFingerprint: fp((i + 50) & 0xFF) })).to.equal(true);

        }
        expect(rl.checkAndCount({ sourceEphPk: eph(123), destFingerprint: fp(231) })).to.equal(false);
        clock += 61;
        expect(rl.checkAndCount({ sourceEphPk: eph(123), destFingerprint: fp(231) })).to.equal(true);

    });

    it('rejected requests do not consume budget', () => {

        let clock = 1_000_000;
        const rl = createForwardRateLimiter({ now: () => clock });
        for (let i = 0; i < 32; i += 1) {

            rl.checkAndCount({ sourceEphPk: eph(1), destFingerprint: fp(i) });

        }
        // Hammer with rejections.
        for (let i = 0; i < 10; i += 1) {

            expect(rl.checkAndCount({ sourceEphPk: eph(1), destFingerprint: fp(99) })).to.equal(false);

        }
        // After the window advances, the per-source bucket should be
        // exactly empty — those 10 rejections must not have consumed
        // budget, so we can do 32 fresh requests.
        clock += 61;
        for (let i = 0; i < 32; i += 1) {

            expect(rl.checkAndCount({ sourceEphPk: eph(1), destFingerprint: fp(i) })).to.equal(true);

        }

    });

});
