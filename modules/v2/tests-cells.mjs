// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

import { expect } from 'chai';
import fc from 'fast-check';

import {
    CELL_BYTES,
    WIRE_VERSION_V2,
    LEN_CELL_PAYLOAD,
    CMD_PADDING,
    CMD_CREATE,
    CMD_CREATED,
    CMD_RELAY,
    CMD_DESTROY,
    buildCell,
    parseCell,
    isValidTopLevelCommand,
    buildLayerIV,
    applyLayer,
    LAYER_KEY_BYTES,
} from './cells.mjs';

describe('v2/cells — constants', () => {

    it('cell is exactly 514 bytes', () => {

        expect(CELL_BYTES).to.equal(514);

    });

    it('version + circuit_id + command + payload sums to 514', () => {

        expect(1 + 4 + 1 + LEN_CELL_PAYLOAD).to.equal(CELL_BYTES);

    });

    it('isValidTopLevelCommand accepts the 7 defined commands and rejects others', () => {

        for (const c of [CMD_PADDING, CMD_CREATE, CMD_CREATED, CMD_RELAY, CMD_DESTROY, 0x05, 0x06]) {

            expect(isValidTopLevelCommand(c)).to.equal(true);

        }
        for (const c of [0x07, 0x7F, 0x80, 0xFF]) {

            expect(isValidTopLevelCommand(c)).to.equal(false);

        }

    });

});

describe('v2/cells — build/parse', () => {

    it('builds a 514-byte cell with fields at expected offsets', () => {

        const payload = new Uint8Array([1, 2, 3, 4, 5]);
        const cell = buildCell({
            circuitId: 0xDEADBEEF,
            command: CMD_RELAY,
            payload,
        });
        expect(cell.length).to.equal(CELL_BYTES);
        expect(cell[0]).to.equal(WIRE_VERSION_V2);
        // circuit_id at offset 1, big-endian
        expect(cell[1]).to.equal(0xDE);
        expect(cell[2]).to.equal(0xAD);
        expect(cell[3]).to.equal(0xBE);
        expect(cell[4]).to.equal(0xEF);
        expect(cell[5]).to.equal(CMD_RELAY);
        // payload at offset 6
        expect(cell[6]).to.equal(1);
        expect(cell[10]).to.equal(5);
        // remaining bytes are zero
        for (let i = 11; i < CELL_BYTES; i += 1) {

            expect(cell[i]).to.equal(0);

        }

    });

    it('parse round-trips build', () => {

        const payload = new Uint8Array(LEN_CELL_PAYLOAD).fill(0xAB);
        const cell = buildCell({ circuitId: 42, command: CMD_DESTROY, payload });
        const parsed = parseCell(cell);
        expect(parsed).to.not.equal(null);
        expect(parsed.version).to.equal(WIRE_VERSION_V2);
        expect(parsed.circuitId).to.equal(42);
        expect(parsed.command).to.equal(CMD_DESTROY);
        expect(parsed.payload.length).to.equal(LEN_CELL_PAYLOAD);
        expect(parsed.payload[0]).to.equal(0xAB);
        expect(parsed.payload[LEN_CELL_PAYLOAD - 1]).to.equal(0xAB);

    });

    it('parse returns null on wrong-sized input', () => {

        expect(parseCell(null)).to.equal(null);
        expect(parseCell(new Uint8Array(0))).to.equal(null);
        expect(parseCell(new Uint8Array(513))).to.equal(null);
        expect(parseCell(new Uint8Array(515))).to.equal(null);

    });

    it('build throws on oversized payload', () => {

        expect(() => buildCell({
            circuitId: 0,
            command: CMD_PADDING,
            payload: new Uint8Array(LEN_CELL_PAYLOAD + 1),
        })).to.throw();

    });

    it('build throws on out-of-range circuitId', () => {

        expect(() => buildCell({ circuitId: -1, command: CMD_PADDING })).to.throw();
        expect(() => buildCell({ circuitId: 2 ** 32, command: CMD_PADDING })).to.throw();
        expect(() => buildCell({ circuitId: 1.5, command: CMD_PADDING })).to.throw();

    });

    it('build with no payload produces an all-zero payload region', () => {

        const cell = buildCell({ circuitId: 0, command: CMD_PADDING });
        for (let i = 6; i < CELL_BYTES; i += 1) expect(cell[i]).to.equal(0);

    });

    it('property: build → parse round-trips for arbitrary valid inputs', () => {

        fc.assert(
            fc.property(
                fc.integer({ min: 0, max: 0xFFFFFFFF }),
                fc.integer({ min: 0, max: 255 }),
                fc.uint8Array({ minLength: 0, maxLength: LEN_CELL_PAYLOAD }),
                (circuitId, command, payload) => {

                    const cell = buildCell({ circuitId, command, payload });
                    const parsed = parseCell(cell);
                    if (parsed === null) return false;
                    if (parsed.circuitId !== circuitId) return false;
                    if (parsed.command !== command) return false;
                    // payload is the full 508-byte region (input + zero-pad)
                    for (let i = 0; i < payload.length; i += 1) {

                        if (parsed.payload[i] !== payload[i]) return false;

                    }
                    for (let i = payload.length; i < LEN_CELL_PAYLOAD; i += 1) {

                        if (parsed.payload[i] !== 0) return false;

                    }
                    return true;

                },
            ),
            { numRuns: 500 },
        );

    });

    it('property: parseCell on arbitrary bytes never throws', () => {

        fc.assert(
            fc.property(
                fc.uint8Array({ minLength: 0, maxLength: 1024 }),
                (raw) => {

                    try {

                        const result = parseCell(raw);
                        if (result !== null) {

                            if (typeof result.circuitId !== 'number') return false;
                            if (typeof result.command !== 'number') return false;
                            if (!(result.payload instanceof Uint8Array)) return false;

                        }
                        return true;

                    } catch {

                        return false;

                    }

                },
            ),
            { numRuns: 500 },
        );

    });

});

describe('v2/cells — layer encryption', () => {

    it('buildLayerIV produces 16-byte IV with big-endian counter prefix', () => {

        const iv = buildLayerIV(0x0102030405060708n);
        expect(iv.length).to.equal(16);
        expect(iv[0]).to.equal(0x01);
        expect(iv[1]).to.equal(0x02);
        expect(iv[7]).to.equal(0x08);
        for (let i = 8; i < 16; i += 1) expect(iv[i]).to.equal(0);

    });

    it('applyLayer is symmetric (XOR-based stream cipher)', () => {

        const key = new Uint8Array(LAYER_KEY_BYTES).fill(0x11);
        const iv = buildLayerIV(0);
        const plaintext = new Uint8Array(LEN_CELL_PAYLOAD).fill(0x55);
        const encrypted = applyLayer(key, iv, plaintext);
        const decrypted = applyLayer(key, iv, encrypted);
        expect(Buffer.from(decrypted).equals(Buffer.from(plaintext))).to.equal(true);

    });

    it('applyLayer with different counters produces different output', () => {

        const key = new Uint8Array(LAYER_KEY_BYTES).fill(0x11);
        const plaintext = new Uint8Array(LEN_CELL_PAYLOAD).fill(0x55);
        const c0 = applyLayer(key, buildLayerIV(0), plaintext);
        const c1 = applyLayer(key, buildLayerIV(1), plaintext);
        expect(Buffer.from(c0).equals(Buffer.from(c1))).to.equal(false);

    });

    it('applyLayer with different keys produces different output', () => {

        const k1 = new Uint8Array(LAYER_KEY_BYTES).fill(0x11);
        const k2 = new Uint8Array(LAYER_KEY_BYTES).fill(0x22);
        const iv = buildLayerIV(0);
        const plaintext = new Uint8Array(LEN_CELL_PAYLOAD).fill(0x55);
        const a = applyLayer(k1, iv, plaintext);
        const b = applyLayer(k2, iv, plaintext);
        expect(Buffer.from(a).equals(Buffer.from(b))).to.equal(false);

    });

    it('layered encryption: N applications with N keys are reversible in reverse order', () => {

        // Simulate three layers (3-hop circuit).
        const keys = [
            new Uint8Array(LAYER_KEY_BYTES).fill(0xA1),
            new Uint8Array(LAYER_KEY_BYTES).fill(0xB2),
            new Uint8Array(LAYER_KEY_BYTES).fill(0xC3),
        ];
        const iv = buildLayerIV(0);
        const plaintext = new Uint8Array(LEN_CELL_PAYLOAD);
        for (let i = 0; i < plaintext.length; i += 1) plaintext[i] = i & 0xFF;

        // Encrypt: client applies layers in order 0, 1, 2.
        let encrypted = plaintext;
        for (const k of keys) {

            encrypted = applyLayer(k, iv, encrypted);

        }

        // Decrypt: each hop peels in order, so hop 0 peels first, then 1, then 2.
        let decrypted = encrypted;
        for (const k of keys) {

            decrypted = applyLayer(k, iv, decrypted);

        }
        expect(Buffer.from(decrypted).equals(Buffer.from(plaintext))).to.equal(true);

    });

    it('applyLayer throws on wrong-sized key', () => {

        expect(() => applyLayer(
            new Uint8Array(31),
            buildLayerIV(0),
            new Uint8Array(10),
        )).to.throw();

    });

    it('applyLayer throws on wrong-sized IV', () => {

        expect(() => applyLayer(
            new Uint8Array(LAYER_KEY_BYTES),
            new Uint8Array(15),
            new Uint8Array(10),
        )).to.throw();

    });

});
