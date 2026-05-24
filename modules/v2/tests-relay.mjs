// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

import { expect } from 'chai';

import { LEN_CELL_PAYLOAD, CMD_DESTROY, parseCell } from './cells.mjs';
import {
    LEN_RELAY_PREFIX,
    MAX_RELAY_DATA,
    OFFSET_DIGEST,
    OFFSET_RELAY_DATA,
    RELAY_DATA,
    RELAY_BEGIN,
    STREAM_ID_CIRCUIT,
    createDigestState,
    buildRelayPayload,
    tryConsumeRelayPayload,
    buildDestroyCell,
    parseDestroyCell,
    DESTROY_REASON_PROTOCOL,
} from './relay.mjs';

const sampleSeed = (fill = 0xAA) => new Uint8Array(32).fill(fill);

describe('v2/relay — constants', () => {

    it('prefix is 9 bytes (cmd+sid+dig+len)', () => {

        expect(LEN_RELAY_PREFIX).to.equal(9);

    });

    it('max data is 499 (508 - 9)', () => {

        expect(MAX_RELAY_DATA).to.equal(LEN_CELL_PAYLOAD - LEN_RELAY_PREFIX);
        expect(MAX_RELAY_DATA).to.equal(499);

    });

});

describe('v2/relay — digest construction', () => {

    it('build then verify on synced states yields a match', () => {

        const seed = sampleSeed();
        const senderState = createDigestState(seed);
        const recvState = createDigestState(seed);
        const data = new Uint8Array([1, 2, 3, 4, 5]);
        const payload = buildRelayPayload({
            relayCommand: RELAY_DATA,
            streamId: 7,
            data,
            digestState: senderState,
        });
        const verified = tryConsumeRelayPayload(payload, recvState);
        expect(verified).to.not.equal(null);
        expect(verified.match).to.equal(true);
        expect(verified.parsed.relayCommand).to.equal(RELAY_DATA);
        expect(verified.parsed.streamId).to.equal(7);
        expect(Buffer.from(verified.parsed.data).equals(Buffer.from(data))).to.equal(true);

    });

    it('mismatched seeds → digest mismatch (cell is for a later hop)', () => {

        const senderState = createDigestState(sampleSeed(0x11));
        const recvState = createDigestState(sampleSeed(0x22)); // different seed
        const payload = buildRelayPayload({
            relayCommand: RELAY_DATA,
            streamId: 1,
            data: new Uint8Array([99]),
            digestState: senderState,
        });
        const verified = tryConsumeRelayPayload(payload, recvState);
        expect(verified).to.not.equal(null);
        expect(verified.match).to.equal(false);

    });

    it('mismatched verify does NOT mutate the receiver state', () => {

        const senderState = createDigestState(sampleSeed(0x11));
        const recvState = createDigestState(sampleSeed(0x22));
        const peerCorrectState = createDigestState(sampleSeed(0x11));

        const payload = buildRelayPayload({
            relayCommand: RELAY_DATA,
            streamId: 0,
            data: new Uint8Array(0),
            digestState: senderState,
        });
        // First, recvState sees the cell, mismatches.
        const first = tryConsumeRelayPayload(payload, recvState);
        expect(first.match).to.equal(false);

        // Now the cell reaches a hop with the correct seed — it should
        // still verify, because recvState's failed attempt must not
        // have advanced any other state.
        const second = tryConsumeRelayPayload(payload, peerCorrectState);
        expect(second.match).to.equal(true);

    });

    it('consecutive cells advance both sender and receiver state in lockstep', () => {

        const seed = sampleSeed(0x55);
        const senderState = createDigestState(seed);
        const recvState = createDigestState(seed);

        for (let i = 0; i < 5; i += 1) {

            const payload = buildRelayPayload({
                relayCommand: RELAY_DATA,
                streamId: 1,
                data: new Uint8Array([i]),
                digestState: senderState,
            });
            const verified = tryConsumeRelayPayload(payload, recvState);
            expect(verified.match).to.equal(true);
            expect(verified.parsed.data[0]).to.equal(i);

        }

    });

    it('replaying an old cell fails because the running state has advanced', () => {

        const seed = sampleSeed();
        const senderState = createDigestState(seed);
        const recvState = createDigestState(seed);

        const cell1 = buildRelayPayload({
            relayCommand: RELAY_DATA,
            streamId: 1,
            data: new Uint8Array([1]),
            digestState: senderState,
        });
        const cell2 = buildRelayPayload({
            relayCommand: RELAY_DATA,
            streamId: 1,
            data: new Uint8Array([2]),
            digestState: senderState,
        });

        // Receive in order.
        const v1 = tryConsumeRelayPayload(cell1, recvState);
        expect(v1.match).to.equal(true);
        const v2 = tryConsumeRelayPayload(cell2, recvState);
        expect(v2.match).to.equal(true);

        // Now replay cell1 — the running state has moved past it.
        const replay = tryConsumeRelayPayload(cell1, recvState);
        expect(replay.match).to.equal(false);

    });

    it('a single-bit flip in the data invalidates the digest', () => {

        const seed = sampleSeed();
        const senderState = createDigestState(seed);
        const recvState = createDigestState(seed);
        const payload = buildRelayPayload({
            relayCommand: RELAY_DATA,
            streamId: 1,
            data: new Uint8Array([0xAB, 0xCD]),
            digestState: senderState,
        });
        const tampered = new Uint8Array(payload);
        tampered[OFFSET_RELAY_DATA] ^= 0x01;
        const verified = tryConsumeRelayPayload(tampered, recvState);
        expect(verified.match).to.equal(false);

    });

    it('a single-bit flip in the digest field is rejected', () => {

        const seed = sampleSeed();
        const senderState = createDigestState(seed);
        const recvState = createDigestState(seed);
        const payload = buildRelayPayload({
            relayCommand: RELAY_DATA,
            streamId: 1,
            data: new Uint8Array(0),
            digestState: senderState,
        });
        const tampered = new Uint8Array(payload);
        tampered[OFFSET_DIGEST] ^= 0x01;
        const verified = tryConsumeRelayPayload(tampered, recvState);
        expect(verified.match).to.equal(false);

    });

});

describe('v2/relay — payload bounds', () => {

    it('build at max data size succeeds', () => {

        const senderState = createDigestState(sampleSeed());
        const data = new Uint8Array(MAX_RELAY_DATA);
        const payload = buildRelayPayload({
            relayCommand: RELAY_DATA,
            streamId: 1,
            data,
            digestState: senderState,
        });
        expect(payload.length).to.equal(LEN_CELL_PAYLOAD);

    });

    it('build throws on oversized data', () => {

        expect(() => buildRelayPayload({
            relayCommand: RELAY_DATA,
            streamId: 1,
            data: new Uint8Array(MAX_RELAY_DATA + 1),
            digestState: createDigestState(sampleSeed()),
        })).to.throw();

    });

    it('tryConsumeRelayPayload returns null on wrong total length', () => {

        const state = createDigestState(sampleSeed());
        expect(tryConsumeRelayPayload(new Uint8Array(507), state)).to.equal(null);
        expect(tryConsumeRelayPayload(new Uint8Array(509), state)).to.equal(null);
        expect(tryConsumeRelayPayload(null, state)).to.equal(null);

    });

    it('tryConsumeRelayPayload returns null when padding bytes are non-zero', () => {

        const seed = sampleSeed();
        const senderState = createDigestState(seed);
        const recvState = createDigestState(seed);
        const payload = buildRelayPayload({
            relayCommand: RELAY_DATA,
            streamId: 1,
            data: new Uint8Array([1]),
            digestState: senderState,
        });
        // Pollute a padding byte BEFORE the receiver verifies.
        // The digest WAS computed with the zeroed (clean) cell, so if
        // the cell is tampered with a non-padding-byte the digest must
        // already mismatch. But if we tamper with padding only, the
        // digest is over the WHOLE payload-with-zeroed-digest; flipping
        // a padding byte also corrupts the digest. So the right way to
        // test "non-zero padding rejected" is to build a cell with our
        // own cooperating sender that legitimately has non-zero
        // padding — which buildRelayPayload doesn't do — and verify it.
        // Simulate by building a cell, then patching the digest to
        // match a non-zero-padding version.
        const malformed = new Uint8Array(payload);
        const polluteIdx = OFFSET_RELAY_DATA + 1 + 5; // a padding byte
        malformed[polluteIdx] = 0xFF;
        // Recompute the "correct" digest for this malformed payload by
        // running it through a fresh sender state. This simulates a
        // peer that violates the "padding MUST be zero" rule.
        const compromiseState = createDigestState(seed);
        const zeroedMalformed = new Uint8Array(malformed);
        zeroedMalformed[OFFSET_DIGEST]     = 0;
        zeroedMalformed[OFFSET_DIGEST + 1] = 0;
        zeroedMalformed[OFFSET_DIGEST + 2] = 0;
        zeroedMalformed[OFFSET_DIGEST + 3] = 0;
        compromiseState.update(zeroedMalformed);
        const fakeDigest = compromiseState.clone().digest().subarray(0, 4);
        malformed.set(fakeDigest, OFFSET_DIGEST);
        // Now: a malformed cell with a valid digest (sent by a hostile
        // peer who shares our key). tryConsume MUST reject on the
        // non-zero-padding structural check.
        const result = tryConsumeRelayPayload(malformed, recvState);
        expect(result).to.equal(null);

    });

});

describe('v2/relay — DESTROY cell', () => {

    it('build and parse round-trip carries reason byte', () => {

        const cell = buildDestroyCell({ circuitId: 42, reason: DESTROY_REASON_PROTOCOL });
        const parsed = parseDestroyCell(cell);
        expect(parsed).to.not.equal(null);
        expect(parsed.circuitId).to.equal(42);
        expect(parsed.reason).to.equal(DESTROY_REASON_PROTOCOL);

    });

    it('parseDestroyCell returns null on non-DESTROY cell', () => {

        // Build a cell with a different command code.
        const fake = new Uint8Array(514);
        fake[0] = 0x02; // version
        fake[5] = 0x03; // CMD_RELAY
        expect(parseDestroyCell(fake)).to.equal(null);

    });

});
