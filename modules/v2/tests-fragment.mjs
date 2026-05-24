// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

import { expect } from 'chai';

import { LEN_CELL_PAYLOAD } from './cells.mjs';
import {
    FRAGMENT_PAYLOAD_CAPACITY,
    LEN_FRAGMENT_HEADER,
    fragmentMessage,
    createReassembler,
} from './fragment.mjs';

const makeMessage = (len, seed = 0) => {

    const out = new Uint8Array(len);
    for (let i = 0; i < len; i += 1) out[i] = (i + seed) & 0xFF;
    return out;

};

describe('v2/fragment — constants', () => {

    it('fragment header is 8 bytes', () => {

        expect(LEN_FRAGMENT_HEADER).to.equal(8);

    });

    it('per-fragment payload capacity is cell minus header = 500', () => {

        expect(FRAGMENT_PAYLOAD_CAPACITY).to.equal(LEN_CELL_PAYLOAD - LEN_FRAGMENT_HEADER);
        expect(FRAGMENT_PAYLOAD_CAPACITY).to.equal(500);

    });

});

describe('v2/fragment — fragmentation', () => {

    it('1216-byte hybrid CREATE fits in 3 fragments', () => {

        const msg = makeMessage(1216);
        const fragments = fragmentMessage({ message: msg, handshakeId: 0x12345678 });
        expect(fragments.length).to.equal(3);
        // First two should be full; last is 216 bytes.
        for (let i = 0; i < 2; i += 1) {

            // payload_len field at offset 6
            const view = new DataView(fragments[i].buffer);
            expect(view.getUint16(6, false)).to.equal(FRAGMENT_PAYLOAD_CAPACITY);

        }
        const lastView = new DataView(fragments[2].buffer);
        expect(lastView.getUint16(6, false)).to.equal(216);

    });

    it('1152-byte hybrid CREATED fits in 3 fragments', () => {

        const msg = makeMessage(1152);
        const fragments = fragmentMessage({ message: msg, handshakeId: 1 });
        expect(fragments.length).to.equal(3);

    });

    it('throws on empty message', () => {

        expect(() => fragmentMessage({ message: new Uint8Array(0), handshakeId: 1 }))
            .to.throw();

    });

    it('throws on out-of-range handshakeId', () => {

        expect(() => fragmentMessage({ message: new Uint8Array(10), handshakeId: -1 }))
            .to.throw();
        expect(() => fragmentMessage({ message: new Uint8Array(10), handshakeId: 2 ** 32 }))
            .to.throw();

    });

    it('a 500-byte message fits in 1 fragment', () => {

        const fragments = fragmentMessage({ message: makeMessage(500), handshakeId: 9 });
        expect(fragments.length).to.equal(1);

    });

    it('a 501-byte message produces 2 fragments', () => {

        const fragments = fragmentMessage({ message: makeMessage(501), handshakeId: 9 });
        expect(fragments.length).to.equal(2);

    });

});

describe('v2/fragment — reassembly', () => {

    it('reassembles in-order fragments back to the original message', () => {

        const msg = makeMessage(1216, 7);
        const fragments = fragmentMessage({ message: msg, handshakeId: 42 });
        const r = createReassembler();
        let result;
        for (const f of fragments) result = r.ingest(f);
        expect(result.complete).to.equal(true);
        expect(Buffer.from(result.message).equals(Buffer.from(msg))).to.equal(true);

    });

    it('reassembles out-of-order fragments', () => {

        const msg = makeMessage(1152, 13);
        const fragments = fragmentMessage({ message: msg, handshakeId: 99 });
        // Shuffle: 2, 0, 1.
        const r = createReassembler();
        expect(r.ingest(fragments[2]).complete).to.equal(false);
        expect(r.ingest(fragments[0]).complete).to.equal(false);
        const done = r.ingest(fragments[1]);
        expect(done.complete).to.equal(true);
        expect(Buffer.from(done.message).equals(Buffer.from(msg))).to.equal(true);

    });

    it('two concurrent handshakes (different IDs) reassemble independently', () => {

        const r = createReassembler();
        const a = fragmentMessage({ message: makeMessage(1216, 1), handshakeId: 100 });
        const b = fragmentMessage({ message: makeMessage(1216, 2), handshakeId: 200 });
        // Interleave fragments from both.
        r.ingest(a[0]);
        r.ingest(b[0]);
        r.ingest(b[1]);
        r.ingest(a[1]);
        const aDone = r.ingest(a[2]);
        const bDone = r.ingest(b[2]);
        expect(aDone.complete).to.equal(true);
        expect(bDone.complete).to.equal(true);
        expect(aDone.message[0]).to.equal(1);
        expect(bDone.message[0]).to.equal(2);

    });

    it('duplicate-index fragment is rejected and the reassembly aborted', () => {

        const msg = makeMessage(1216);
        const fragments = fragmentMessage({ message: msg, handshakeId: 5 });
        const r = createReassembler();
        r.ingest(fragments[0]);
        r.ingest(fragments[1]);
        const dup = r.ingest(fragments[1]); // duplicate index 1
        expect(dup).to.equal(null);
        // After rejection the reassembly is dropped; ingesting the
        // legitimate remaining fragment should NOT complete (the entry
        // was deleted and a new one starts, but with only fragment 2
        // we never reach count=3).
        const final = r.ingest(fragments[2]);
        expect(final.complete).to.equal(false);

    });

    it('mismatched fragment_count across fragments is rejected', () => {

        const a = fragmentMessage({ message: makeMessage(1216), handshakeId: 7 });
        // Forge a "fragment 0 of 5" with the same handshakeId.
        const evil = new Uint8Array(a[0]);
        evil[1] = 5; // change count
        const r = createReassembler();
        r.ingest(a[0]); // initialises entry with count=3
        const conflict = r.ingest(evil);
        expect(conflict).to.equal(null);

    });

    it('fragment with count == 0 is rejected', () => {

        const a = fragmentMessage({ message: makeMessage(10), handshakeId: 1 });
        const bad = new Uint8Array(a[0]);
        bad[1] = 0;
        const r = createReassembler();
        expect(r.ingest(bad)).to.equal(null);

    });

    it('fragment with index >= count is rejected', () => {

        const a = fragmentMessage({ message: makeMessage(1216), handshakeId: 1 });
        const bad = new Uint8Array(a[0]);
        bad[0] = 5; // index 5 of count 3
        const r = createReassembler();
        expect(r.ingest(bad)).to.equal(null);

    });

    it('fragment with non-zero padding bytes is rejected', () => {

        const a = fragmentMessage({ message: makeMessage(10), handshakeId: 1 });
        const bad = new Uint8Array(a[0]);
        // payload is 10 bytes at offset 8..18; padding starts at 18.
        bad[18] = 0xFF;
        const r = createReassembler();
        expect(r.ingest(bad)).to.equal(null);

    });

    it('fragment with payload_len > capacity is rejected', () => {

        const a = fragmentMessage({ message: makeMessage(10), handshakeId: 1 });
        const bad = new Uint8Array(a[0]);
        new DataView(bad.buffer).setUint16(6, FRAGMENT_PAYLOAD_CAPACITY + 1, false);
        const r = createReassembler();
        expect(r.ingest(bad)).to.equal(null);

    });

    it('non-final fragment with short payload_len is rejected', () => {

        const a = fragmentMessage({ message: makeMessage(1216), handshakeId: 1 });
        const bad = new Uint8Array(a[0]); // index 0 of 3
        // Shrink its payload_len; fragment 0 isn't the last so this is invalid.
        new DataView(bad.buffer).setUint16(6, 200, false);
        // Need to also zero-fill the bytes 8+200..508 to maintain
        // padding-zero invariant; for the test we just check that the
        // header check rejects.
        const r = createReassembler();
        expect(r.ingest(bad)).to.equal(null);

    });

    it('sweep drops timed-out partial reassemblies', () => {

        let clock = 1_000_000;
        const r = createReassembler({ timeoutMs: 1000, now: () => clock });
        const a = fragmentMessage({ message: makeMessage(1216), handshakeId: 99 });
        r.ingest(a[0]);
        expect(r.size()).to.equal(1);
        clock += 1500;
        const dropped = r.sweep();
        expect(dropped).to.equal(1);
        expect(r.size()).to.equal(0);

    });

    it('maxConcurrent caps the in-flight count', () => {

        const r = createReassembler({ maxConcurrent: 2 });
        for (let i = 0; i < 5; i += 1) {

            const frag = fragmentMessage({ message: makeMessage(1216), handshakeId: 100 + i });
            r.ingest(frag[0]);

        }
        // Only the most-recent 2 should remain.
        expect(r.size()).to.equal(2);

    });

});
