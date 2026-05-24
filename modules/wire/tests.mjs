import { expect } from 'chai';

import {
    WIRE_VERSION,
    BUCKET_SMALL,
    BUCKET_MEDIUM,
    BUCKET_LARGE,
    BUCKET_SIZE_SMALL,
    BUCKET_SIZE_MEDIUM,
    BUCKET_SIZE_LARGE,
    LEN_OUTER_HEADER,
    LEN_AEAD_TAG,
    LEN_FRAMING,
    LEN_INNER_PREFIX,
    bucketSize,
    bucketForSize,
    innerLengthForBucket,
    maxPayloadForBucket,
} from './constants.mjs';
import { buildOuterHeader, parseOuterHeader } from './header.mjs';
import { buildInnerPlaintext, parseInnerPlaintext } from './inner.mjs';
import { encodePacket, decodePacket } from './packet.mjs';
import { createReplayLog } from './replay.mjs';

import { TYPE_DATA } from './constants.mjs';
import { generateIdentity, identityFingerprint } from '../crypto/identity.mjs';
import { generateOnion } from '../crypto/onion.mjs';

describe('wire/constants', () => {

    it('outer header is 54 bytes; framing is 70 bytes', () => {

        expect(LEN_OUTER_HEADER).to.equal(54);
        expect(LEN_AEAD_TAG).to.equal(16);
        expect(LEN_FRAMING).to.equal(70);

    });

    it('inner prefix is 35 bytes (type + real_length + fingerprint)', () => {

        expect(LEN_INNER_PREFIX).to.equal(35);

    });

    it('bucketSize maps codes to canonical sizes', () => {

        expect(bucketSize(BUCKET_SMALL)).to.equal(256);
        expect(bucketSize(BUCKET_MEDIUM)).to.equal(1024);
        expect(bucketSize(BUCKET_LARGE)).to.equal(4096);
        expect(bucketSize(0x00)).to.equal(0);
        expect(bucketSize(0x04)).to.equal(0);
        expect(bucketSize(0xFF)).to.equal(0);

    });

    it('bucketForSize picks the smallest bucket that fits', () => {

        expect(bucketForSize(0)).to.equal(BUCKET_SMALL);
        expect(bucketForSize(256)).to.equal(BUCKET_SMALL);
        expect(bucketForSize(257)).to.equal(BUCKET_MEDIUM);
        expect(bucketForSize(1024)).to.equal(BUCKET_MEDIUM);
        expect(bucketForSize(1025)).to.equal(BUCKET_LARGE);
        expect(bucketForSize(4096)).to.equal(BUCKET_LARGE);
        expect(bucketForSize(4097)).to.equal(0);

    });

    it('innerLengthForBucket = size - 70', () => {

        expect(innerLengthForBucket(BUCKET_SMALL)).to.equal(BUCKET_SIZE_SMALL - 70);
        expect(innerLengthForBucket(BUCKET_MEDIUM)).to.equal(BUCKET_SIZE_MEDIUM - 70);
        expect(innerLengthForBucket(BUCKET_LARGE)).to.equal(BUCKET_SIZE_LARGE - 70);
        expect(innerLengthForBucket(0x00)).to.equal(0);

    });

    it('maxPayloadForBucket = size - 70 - 35', () => {

        expect(maxPayloadForBucket(BUCKET_SMALL)).to.equal(256 - 70 - 35);
        expect(maxPayloadForBucket(BUCKET_MEDIUM)).to.equal(1024 - 70 - 35);
        expect(maxPayloadForBucket(BUCKET_LARGE)).to.equal(4096 - 70 - 35);

    });

});

describe('wire/header', () => {

    const sampleHeaderInputs = () => ({
        version: WIRE_VERSION,
        bucket: BUCKET_SMALL,
        recipientPrefix: new Uint8Array([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]),
        ephPk: new Uint8Array(32).fill(0xAA),
        nonce: new Uint8Array(12).fill(0xBB),
    });

    it('builds a 54-byte buffer with fields at the expected offsets', () => {

        const header = buildOuterHeader(sampleHeaderInputs());
        expect(header.length).to.equal(LEN_OUTER_HEADER);
        expect(header[0]).to.equal(WIRE_VERSION);
        expect(header[1]).to.equal(BUCKET_SMALL);
        // recipient prefix at [2..10)
        for (let i = 0; i < 8; i += 1) {

            expect(header[2 + i]).to.equal(0x10 + i);

        }
        // ephPk fill at [10..42)
        for (let i = 10; i < 42; i += 1) {

            expect(header[i]).to.equal(0xAA);

        }
        // nonce fill at [42..54)
        for (let i = 42; i < 54; i += 1) {

            expect(header[i]).to.equal(0xBB);

        }

    });

    it('round-trips via parseOuterHeader', () => {

        const inputs = sampleHeaderInputs();
        const header = buildOuterHeader(inputs);
        const parsed = parseOuterHeader(header);
        expect(parsed).to.not.equal(null);
        expect(parsed.version).to.equal(inputs.version);
        expect(parsed.bucket).to.equal(inputs.bucket);
        expect(Buffer.from(parsed.recipientPrefix).equals(Buffer.from(inputs.recipientPrefix))).to.equal(true);
        expect(Buffer.from(parsed.ephPk).equals(Buffer.from(inputs.ephPk))).to.equal(true);
        expect(Buffer.from(parsed.nonce).equals(Buffer.from(inputs.nonce))).to.equal(true);

    });

    it('parseOuterHeader returns null on undersized input', () => {

        expect(parseOuterHeader(null)).to.equal(null);
        expect(parseOuterHeader(new Uint8Array(0))).to.equal(null);
        expect(parseOuterHeader(new Uint8Array(53))).to.equal(null);

    });

    it('parseOuterHeader does NOT validate semantics (version/bucket pass through)', () => {

        const inputs = sampleHeaderInputs();
        inputs.version = 0x99;
        inputs.bucket = 0xFE;
        const parsed = parseOuterHeader(buildOuterHeader(inputs));
        expect(parsed.version).to.equal(0x99);
        expect(parsed.bucket).to.equal(0xFE);

    });

    it('buildOuterHeader throws on wrong-sized inputs', () => {

        const ok = sampleHeaderInputs();
        expect(() => buildOuterHeader({ ...ok, recipientPrefix: new Uint8Array(7) })).to.throw();
        expect(() => buildOuterHeader({ ...ok, ephPk: new Uint8Array(31) })).to.throw();
        expect(() => buildOuterHeader({ ...ok, nonce: new Uint8Array(13) })).to.throw();

    });

});

describe('wire/inner', () => {

    const fingerprint = new Uint8Array(32).fill(0x77);

    it('round-trips a non-empty payload at every bucket size', () => {

        for (const bucket of [BUCKET_SMALL, BUCKET_MEDIUM, BUCKET_LARGE]) {

            const payload = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
            const inner = buildInnerPlaintext({
                bucket,
                packetType: TYPE_DATA,
                senderFingerprint: fingerprint,
                payload,
            });
            expect(inner.length).to.equal(innerLengthForBucket(bucket));

            const parsed = parseInnerPlaintext(inner, bucket);
            expect(parsed).to.not.equal(null);
            expect(parsed.packetType).to.equal(TYPE_DATA);
            expect(parsed.realLength).to.equal(payload.length);
            expect(Buffer.from(parsed.senderFingerprint).equals(Buffer.from(fingerprint))).to.equal(true);
            expect(Buffer.from(parsed.payload).equals(Buffer.from(payload))).to.equal(true);

        }

    });

    it('round-trips an empty payload (real_length = 0)', () => {

        const inner = buildInnerPlaintext({
            bucket: BUCKET_SMALL,
            packetType: TYPE_DATA,
            senderFingerprint: fingerprint,
            payload: new Uint8Array(0),
        });
        const parsed = parseInnerPlaintext(inner, BUCKET_SMALL);
        expect(parsed.realLength).to.equal(0);
        expect(parsed.payload.length).to.equal(0);

    });

    it('round-trips a payload that exactly fills the bucket', () => {

        const max = maxPayloadForBucket(BUCKET_SMALL);
        const payload = new Uint8Array(max);
        for (let i = 0; i < max; i += 1) payload[i] = i & 0xFF;
        const inner = buildInnerPlaintext({
            bucket: BUCKET_SMALL,
            packetType: TYPE_DATA,
            senderFingerprint: fingerprint,
            payload,
        });
        const parsed = parseInnerPlaintext(inner, BUCKET_SMALL);
        expect(parsed.realLength).to.equal(max);
        expect(Buffer.from(parsed.payload).equals(Buffer.from(payload))).to.equal(true);

    });

    it('padding region is zero after build', () => {

        const max = maxPayloadForBucket(BUCKET_SMALL);
        const payload = new Uint8Array(max - 5).fill(0xAB);
        const inner = buildInnerPlaintext({
            bucket: BUCKET_SMALL,
            packetType: TYPE_DATA,
            senderFingerprint: fingerprint,
            payload,
        });
        // last 5 bytes are padding and must be zero
        for (let i = inner.length - 5; i < inner.length; i += 1) {

            expect(inner[i]).to.equal(0x00);

        }

    });

    it('buildInnerPlaintext throws on oversized payload', () => {

        const max = maxPayloadForBucket(BUCKET_SMALL);
        expect(() => buildInnerPlaintext({
            bucket: BUCKET_SMALL,
            packetType: TYPE_DATA,
            senderFingerprint: fingerprint,
            payload: new Uint8Array(max + 1),
        })).to.throw();

    });

    it('buildInnerPlaintext throws on unknown bucket code', () => {

        expect(() => buildInnerPlaintext({
            bucket: 0xFF,
            packetType: TYPE_DATA,
            senderFingerprint: fingerprint,
            payload: new Uint8Array(0),
        })).to.throw();

    });

    it('buildInnerPlaintext throws on wrong-sized fingerprint', () => {

        expect(() => buildInnerPlaintext({
            bucket: BUCKET_SMALL,
            packetType: TYPE_DATA,
            senderFingerprint: new Uint8Array(31),
            payload: new Uint8Array(0),
        })).to.throw();

    });

    it('parseInnerPlaintext returns null on wrong total length', () => {

        const innerOk = buildInnerPlaintext({
            bucket: BUCKET_SMALL,
            packetType: TYPE_DATA,
            senderFingerprint: fingerprint,
            payload: new Uint8Array(0),
        });
        // truncate one byte
        expect(parseInnerPlaintext(innerOk.subarray(0, innerOk.length - 1), BUCKET_SMALL)).to.equal(null);
        // extend one byte
        const extended = new Uint8Array(innerOk.length + 1);
        extended.set(innerOk);
        expect(parseInnerPlaintext(extended, BUCKET_SMALL)).to.equal(null);
        // null input
        expect(parseInnerPlaintext(null, BUCKET_SMALL)).to.equal(null);

    });

    it('parseInnerPlaintext returns null on unknown bucket', () => {

        const innerOk = buildInnerPlaintext({
            bucket: BUCKET_SMALL,
            packetType: TYPE_DATA,
            senderFingerprint: fingerprint,
            payload: new Uint8Array(0),
        });
        expect(parseInnerPlaintext(innerOk, 0xFF)).to.equal(null);

    });

    it('parseInnerPlaintext returns null when real_length exceeds capacity', () => {

        const inner = buildInnerPlaintext({
            bucket: BUCKET_SMALL,
            packetType: TYPE_DATA,
            senderFingerprint: fingerprint,
            payload: new Uint8Array(0),
        });
        const tampered = new Uint8Array(inner);
        const oversized = maxPayloadForBucket(BUCKET_SMALL) + 1;
        tampered[1] = (oversized >>> 8) & 0xFF;
        tampered[2] = oversized & 0xFF;
        expect(parseInnerPlaintext(tampered, BUCKET_SMALL)).to.equal(null);

    });

    it('parseInnerPlaintext returns null when any padding byte is non-zero', () => {

        const max = maxPayloadForBucket(BUCKET_SMALL);
        const payload = new Uint8Array(max - 4).fill(0xCC);
        const inner = buildInnerPlaintext({
            bucket: BUCKET_SMALL,
            packetType: TYPE_DATA,
            senderFingerprint: fingerprint,
            payload,
        });
        // flip first padding byte
        const tampered = new Uint8Array(inner);
        tampered[inner.length - 4] = 0x01;
        expect(parseInnerPlaintext(tampered, BUCKET_SMALL)).to.equal(null);
        // and the last padding byte
        const tampered2 = new Uint8Array(inner);
        tampered2[inner.length - 1] = 0x01;
        expect(parseInnerPlaintext(tampered2, BUCKET_SMALL)).to.equal(null);

    });

});

describe('wire/packet', () => {

    // Helper: a (sender, recipient) pair with both identity and onion keys.
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

    it('round-trips a small payload between two parties', () => {

        const sender = makeParty();
        const recipient = makeParty();
        const payload = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);

        const packet = encodePacket({
            recipientIdPk: recipient.idPk,
            recipientOnionPk: recipient.onionPk,
            senderFingerprint: sender.fingerprint,
            packetType: TYPE_DATA,
            payload,
        });
        // Small bucket: 4 bytes of payload fit easily.
        expect(packet.length).to.equal(256);

        const decoded = decodePacket(packet, {
            myIdPk: recipient.idPk,
            myOnionSk: recipient.onionSk,
        });
        expect(decoded).to.not.equal(null);
        expect(decoded.bucket).to.equal(BUCKET_SMALL);
        expect(decoded.packetType).to.equal(TYPE_DATA);
        expect(Buffer.from(decoded.senderFingerprint).equals(Buffer.from(sender.fingerprint))).to.equal(true);
        expect(Buffer.from(decoded.payload).equals(Buffer.from(payload))).to.equal(true);

    });

    it('selects the right bucket by payload size', () => {

        const sender = makeParty();
        const recipient = makeParty();

        // Fits in 256 (max ~151).
        const small = encodePacket({
            recipientIdPk: recipient.idPk,
            recipientOnionPk: recipient.onionPk,
            senderFingerprint: sender.fingerprint,
            packetType: TYPE_DATA,
            payload: new Uint8Array(maxPayloadForBucket(BUCKET_SMALL)),
        });
        expect(small.length).to.equal(256);

        // 1 byte over BUCKET_SMALL capacity → BUCKET_MEDIUM.
        const medium = encodePacket({
            recipientIdPk: recipient.idPk,
            recipientOnionPk: recipient.onionPk,
            senderFingerprint: sender.fingerprint,
            packetType: TYPE_DATA,
            payload: new Uint8Array(maxPayloadForBucket(BUCKET_SMALL) + 1),
        });
        expect(medium.length).to.equal(1024);

        // 1 byte over BUCKET_MEDIUM capacity → BUCKET_LARGE.
        const large = encodePacket({
            recipientIdPk: recipient.idPk,
            recipientOnionPk: recipient.onionPk,
            senderFingerprint: sender.fingerprint,
            packetType: TYPE_DATA,
            payload: new Uint8Array(maxPayloadForBucket(BUCKET_MEDIUM) + 1),
        });
        expect(large.length).to.equal(4096);

    });

    it('encodePacket throws when payload exceeds BUCKET_LARGE', () => {

        const sender = makeParty();
        const recipient = makeParty();
        expect(() => encodePacket({
            recipientIdPk: recipient.idPk,
            recipientOnionPk: recipient.onionPk,
            senderFingerprint: sender.fingerprint,
            packetType: TYPE_DATA,
            payload: new Uint8Array(maxPayloadForBucket(BUCKET_LARGE) + 1),
        })).to.throw();

    });

    it('decodePacket returns null on wrong recipient (prefix mismatch)', () => {

        const sender = makeParty();
        const recipient = makeParty();
        const eavesdropper = makeParty();
        const packet = encodePacket({
            recipientIdPk: recipient.idPk,
            recipientOnionPk: recipient.onionPk,
            senderFingerprint: sender.fingerprint,
            packetType: TYPE_DATA,
            payload: new Uint8Array([1, 2, 3]),
        });
        const decoded = decodePacket(packet, {
            myIdPk: eavesdropper.idPk,
            myOnionSk: eavesdropper.onionSk,
        });
        expect(decoded).to.equal(null);

    });

    it('decodePacket returns null on non-bucket length', () => {

        // Synthetic — any length not in {256, 1024, 4096} is rejected.
        const recipient = makeParty();
        for (const len of [0, 1, 55, 100, 257, 1023, 1025, 4095, 4097, 8192]) {

            expect(decodePacket(new Uint8Array(len), {
                myIdPk: recipient.idPk,
                myOnionSk: recipient.onionSk,
            })).to.equal(null);

        }

    });

    it('decodePacket returns null on wrong version byte', () => {

        const sender = makeParty();
        const recipient = makeParty();
        const packet = encodePacket({
            recipientIdPk: recipient.idPk,
            recipientOnionPk: recipient.onionPk,
            senderFingerprint: sender.fingerprint,
            packetType: TYPE_DATA,
            payload: new Uint8Array([1]),
        });
        const tampered = new Uint8Array(packet);
        tampered[0] = 0x02; // bump version
        expect(decodePacket(tampered, {
            myIdPk: recipient.idPk,
            myOnionSk: recipient.onionSk,
        })).to.equal(null);

    });

    it('decodePacket returns null on bucket-vs-length mismatch', () => {

        const sender = makeParty();
        const recipient = makeParty();
        const packet = encodePacket({
            recipientIdPk: recipient.idPk,
            recipientOnionPk: recipient.onionPk,
            senderFingerprint: sender.fingerprint,
            packetType: TYPE_DATA,
            payload: new Uint8Array([1]),
        });
        expect(packet.length).to.equal(256);
        const tampered = new Uint8Array(packet);
        tampered[1] = BUCKET_MEDIUM; // claims medium but only 256 bytes long
        expect(decodePacket(tampered, {
            myIdPk: recipient.idPk,
            myOnionSk: recipient.onionSk,
        })).to.equal(null);

    });

    it('decodePacket returns null on tampered AAD (any outer-header byte flipped)', () => {

        const sender = makeParty();
        const recipient = makeParty();
        const packet = encodePacket({
            recipientIdPk: recipient.idPk,
            recipientOnionPk: recipient.onionPk,
            senderFingerprint: sender.fingerprint,
            packetType: TYPE_DATA,
            payload: new Uint8Array([1, 2, 3, 4]),
        });
        // Flip a byte inside the ephPk region — passes the prefix
        // filter (we don't touch [2..10)) but changes AAD, so AEAD must
        // reject. (Note: flipping ephPk also changes the X25519 result,
        // so AEAD failure is double-locked here; both are correct.)
        const tampered = new Uint8Array(packet);
        tampered[20] ^= 0x01;
        expect(decodePacket(tampered, {
            myIdPk: recipient.idPk,
            myOnionSk: recipient.onionSk,
        })).to.equal(null);

        // Flip a byte inside the nonce region — passes prefix filter,
        // KX still succeeds, but AAD has changed and so has the nonce
        // passed to AEAD_DEC. AEAD must reject.
        const tampered2 = new Uint8Array(packet);
        tampered2[45] ^= 0x01;
        expect(decodePacket(tampered2, {
            myIdPk: recipient.idPk,
            myOnionSk: recipient.onionSk,
        })).to.equal(null);

    });

    it('decodePacket returns null on tampered ciphertext or tag', () => {

        const sender = makeParty();
        const recipient = makeParty();
        const packet = encodePacket({
            recipientIdPk: recipient.idPk,
            recipientOnionPk: recipient.onionPk,
            senderFingerprint: sender.fingerprint,
            packetType: TYPE_DATA,
            payload: new Uint8Array([0xAA, 0xBB]),
        });
        // Flip a byte inside the ciphertext.
        const tampered = new Uint8Array(packet);
        tampered[100] ^= 0x01;
        expect(decodePacket(tampered, {
            myIdPk: recipient.idPk,
            myOnionSk: recipient.onionSk,
        })).to.equal(null);

        // Flip a byte inside the tag (last 16 bytes).
        const tampered2 = new Uint8Array(packet);
        tampered2[packet.length - 1] ^= 0x01;
        expect(decodePacket(tampered2, {
            myIdPk: recipient.idPk,
            myOnionSk: recipient.onionSk,
        })).to.equal(null);

    });

    it('each encode produces a fresh ephemeral key and a fresh nonce', () => {

        const sender = makeParty();
        const recipient = makeParty();
        const a = encodePacket({
            recipientIdPk: recipient.idPk,
            recipientOnionPk: recipient.onionPk,
            senderFingerprint: sender.fingerprint,
            packetType: TYPE_DATA,
            payload: new Uint8Array([1]),
        });
        const b = encodePacket({
            recipientIdPk: recipient.idPk,
            recipientOnionPk: recipient.onionPk,
            senderFingerprint: sender.fingerprint,
            packetType: TYPE_DATA,
            payload: new Uint8Array([1]),
        });
        // ephPk at [10..42), nonce at [42..54) — both must differ across
        // packets even when the payload is identical (defeats the
        // deterministic-encryption flaw of the pre-spec Twofish chain).
        expect(Buffer.from(a.subarray(10, 42)).equals(Buffer.from(b.subarray(10, 42)))).to.equal(false);
        expect(Buffer.from(a.subarray(42, 54)).equals(Buffer.from(b.subarray(42, 54)))).to.equal(false);
        // Two identical-payload packets should not produce identical ciphertexts.
        expect(Buffer.from(a).equals(Buffer.from(b))).to.equal(false);

    });

    it('encodePacket throws when recipient onionPk is a low-order point', () => {

        const sender = makeParty();
        const recipient = makeParty();
        expect(() => encodePacket({
            recipientIdPk: recipient.idPk,
            recipientOnionPk: new Uint8Array(32), // all-zero is a low-order point
            senderFingerprint: sender.fingerprint,
            packetType: TYPE_DATA,
            payload: new Uint8Array([1]),
        })).to.throw();

    });

});

describe('wire/replay', () => {

    const ephOf = (b) => new Uint8Array(32).fill(b);
    const nonceOf = (b) => new Uint8Array(12).fill(b);

    it('check returns false for an absent key', () => {

        const log = createReplayLog();
        expect(log.check(ephOf(1), nonceOf(2))).to.equal(false);

    });

    it('check returns true after insert', () => {

        const log = createReplayLog();
        log.insert(ephOf(1), nonceOf(2));
        expect(log.check(ephOf(1), nonceOf(2))).to.equal(true);
        // distinct keys are still absent
        expect(log.check(ephOf(3), nonceOf(2))).to.equal(false);
        expect(log.check(ephOf(1), nonceOf(4))).to.equal(false);

    });

    it('keys are exactly (ephPk, nonce) — neither alone collides', () => {

        const log = createReplayLog();
        log.insert(ephOf(1), nonceOf(2));
        log.insert(ephOf(1), nonceOf(3));
        log.insert(ephOf(2), nonceOf(2));
        expect(log.check(ephOf(1), nonceOf(2))).to.equal(true);
        expect(log.check(ephOf(1), nonceOf(3))).to.equal(true);
        expect(log.check(ephOf(2), nonceOf(2))).to.equal(true);
        expect(log.check(ephOf(2), nonceOf(3))).to.equal(false);

    });

    it('does NOT evict old entries while size <= minEntries (SPEC § 5.6)', () => {

        let clock = 1_000_000;
        const log = createReplayLog({
            minEntries: 4,
            minSeconds: 10,
            now: () => clock,
        });
        // Three entries inserted at t=0, then time advances a long way.
        log.insert(ephOf(1), nonceOf(1), clock);
        log.insert(ephOf(2), nonceOf(2), clock);
        log.insert(ephOf(3), nonceOf(3), clock);
        clock += 10_000;
        // Insert a fourth entry. Size (4) still <= minEntries (4) so
        // nothing should be evicted, even though three entries are
        // 10,000 s past the 10 s cutoff.
        log.insert(ephOf(4), nonceOf(4), clock);
        expect(log.size()).to.equal(4);
        expect(log.check(ephOf(1), nonceOf(1))).to.equal(true);

    });

    it('evicts entries older than minSeconds once size exceeds minEntries', () => {

        let clock = 1_000_000;
        const log = createReplayLog({
            minEntries: 2,
            minSeconds: 10,
            now: () => clock,
        });
        log.insert(ephOf(1), nonceOf(1), clock); // t=1_000_000
        log.insert(ephOf(2), nonceOf(2), clock); // t=1_000_000
        clock += 100;
        log.insert(ephOf(3), nonceOf(3), clock); // t=1_000_100
        // Size is 3 > minEntries(2). cutoff = 1_000_090. Entries 1 and 2
        // are at 1_000_000 (older than cutoff) and should evict — but
        // only down to minEntries. So one of {1, 2} is evicted (the
        // older — by Map insertion order, entry 1) and entry 2 is
        // retained because size has reached minEntries.
        expect(log.size()).to.equal(2);
        expect(log.check(ephOf(1), nonceOf(1))).to.equal(false);
        expect(log.check(ephOf(2), nonceOf(2))).to.equal(true);
        expect(log.check(ephOf(3), nonceOf(3))).to.equal(true);

    });

    it('young entries are never evicted', () => {

        let clock = 1_000_000;
        const log = createReplayLog({
            minEntries: 0,
            minSeconds: 100,
            now: () => clock,
        });
        log.insert(ephOf(1), nonceOf(1), clock);
        clock += 50;
        log.insert(ephOf(2), nonceOf(2), clock);
        // No advance — entry 1 is at age 50, well under cutoff(100). Even
        // with minEntries=0, nothing should evict.
        expect(log.size()).to.equal(2);

    });

    it('an entry inserted exactly at the cutoff is retained', () => {

        let clock = 1_000_000;
        const log = createReplayLog({
            minEntries: 1,
            minSeconds: 100,
            now: () => clock,
        });
        log.insert(ephOf(1), nonceOf(1), clock); // t=1_000_000
        clock += 100; // age == minSeconds exactly
        log.insert(ephOf(2), nonceOf(2), clock); // triggers eviction with cutoff=1_000_000
        // entry 1 has ts == cutoff; "ts > cutoff" is false, so it
        // qualifies for eviction — but minEntries=1, and after evicting
        // the head we'd have size=1, which is not strictly greater than
        // minEntries. Eviction stops. Entry 1 is removed because
        // size(2) > minEntries(1) at the start of the loop.
        expect(log.size()).to.equal(1);
        expect(log.check(ephOf(2), nonceOf(2))).to.equal(true);

    });

});

describe('wire/packet + replay integration (SPEC § 5.7 steps 8-9)', () => {

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

    it('replays are silently rejected on the second decode', () => {

        const sender = makeParty();
        const recipient = makeParty();
        const replayLog = createReplayLog();

        const packet = encodePacket({
            recipientIdPk: recipient.idPk,
            recipientOnionPk: recipient.onionPk,
            senderFingerprint: sender.fingerprint,
            packetType: TYPE_DATA,
            payload: new Uint8Array([0x01, 0x02, 0x03]),
        });

        const first = decodePacket(packet, {
            myIdPk: recipient.idPk,
            myOnionSk: recipient.onionSk,
            replayLog,
        });
        expect(first).to.not.equal(null);

        // Second decode of the exact same bytes — captured-and-replayed
        // attack — must return null.
        const second = decodePacket(packet, {
            myIdPk: recipient.idPk,
            myOnionSk: recipient.onionSk,
            replayLog,
        });
        expect(second).to.equal(null);

    });

    it('distinct packets do not collide in the replay log', () => {

        const sender = makeParty();
        const recipient = makeParty();
        const replayLog = createReplayLog();

        for (let i = 0; i < 5; i += 1) {

            const packet = encodePacket({
                recipientIdPk: recipient.idPk,
                recipientOnionPk: recipient.onionPk,
                senderFingerprint: sender.fingerprint,
                packetType: TYPE_DATA,
                payload: new Uint8Array([i]),
            });
            const decoded = decodePacket(packet, {
                myIdPk: recipient.idPk,
                myOnionSk: recipient.onionSk,
                replayLog,
            });
            expect(decoded).to.not.equal(null);

        }
        expect(replayLog.size()).to.equal(5);

    });

    it('decode without a replayLog still accepts duplicates (test-mode determinism)', () => {

        const sender = makeParty();
        const recipient = makeParty();
        const packet = encodePacket({
            recipientIdPk: recipient.idPk,
            recipientOnionPk: recipient.onionPk,
            senderFingerprint: sender.fingerprint,
            packetType: TYPE_DATA,
            payload: new Uint8Array([0xFF]),
        });
        const opts = { myIdPk: recipient.idPk, myOnionSk: recipient.onionSk };
        expect(decodePacket(packet, opts)).to.not.equal(null);
        expect(decodePacket(packet, opts)).to.not.equal(null);

    });

    it('onPostAeadFailure fires with reason=replay on a captured-and-replayed packet', () => {

        const sender = makeParty();
        const recipient = makeParty();
        const replayLog = createReplayLog();
        const packet = encodePacket({
            recipientIdPk: recipient.idPk,
            recipientOnionPk: recipient.onionPk,
            senderFingerprint: sender.fingerprint,
            packetType: TYPE_DATA,
            payload: new Uint8Array([1]),
        });
        const opts = { myIdPk: recipient.idPk, myOnionSk: recipient.onionSk, replayLog };
        expect(decodePacket(packet, opts)).to.not.equal(null);

        const failures = [];
        decodePacket(packet, {
            ...opts,
            onPostAeadFailure: (f) => failures.push(f),
        });
        expect(failures.length).to.equal(1);
        expect(failures[0].reason).to.equal('replay');
        expect(Buffer.from(failures[0].senderFingerprint).equals(Buffer.from(sender.fingerprint))).to.equal(true);

    });

    it('onPostAeadFailure does NOT fire on pre-AEAD failures', () => {

        const sender = makeParty();
        const recipient = makeParty();
        const eavesdropper = makeParty();
        const packet = encodePacket({
            recipientIdPk: recipient.idPk,
            recipientOnionPk: recipient.onionPk,
            senderFingerprint: sender.fingerprint,
            packetType: TYPE_DATA,
            payload: new Uint8Array([1]),
        });

        // Wrong recipient (prefix mismatch — pre-AEAD).
        const failures = [];
        decodePacket(packet, {
            myIdPk: eavesdropper.idPk,
            myOnionSk: eavesdropper.onionSk,
            onPostAeadFailure: (f) => failures.push(f),
        });
        // Tampered AAD.
        const tampered = new Uint8Array(packet);
        tampered[20] ^= 0x01;
        decodePacket(tampered, {
            myIdPk: recipient.idPk,
            myOnionSk: recipient.onionSk,
            onPostAeadFailure: (f) => failures.push(f),
        });
        // Wrong version.
        const wrongVersion = new Uint8Array(packet);
        wrongVersion[0] = 0x02;
        decodePacket(wrongVersion, {
            myIdPk: recipient.idPk,
            myOnionSk: recipient.onionSk,
            onPostAeadFailure: (f) => failures.push(f),
        });
        expect(failures.length).to.equal(0);

    });

});
