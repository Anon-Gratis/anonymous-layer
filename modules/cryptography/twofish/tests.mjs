import TwofishCryptography from './index.mjs';

import { expect } from 'chai';

describe('TwofishCryptography', () => {

    const BLOCK_SIZE = 16; // octets, also known as "bytes". 128 bits.
    const KEY_SIZE = 16; // octets, also known as "bytes". 128 bits.

    const { encrypt128, decrypt128 } = TwofishCryptography;

    const TEST_CASES_128BITS = Object.freeze([
        {
            key: Uint8Array.from([
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]),
            textPlain: Uint8Array.from([
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]),
            textCipher: Uint8Array.from([
                0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32,
                0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A,
            ]),
        },
        {
            key: Uint8Array.from([
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]),
            textPlain: Uint8Array.from([
                0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32,
                0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A,
            ]),
            textCipher: Uint8Array.from([
                0xD4, 0x91, 0xDB, 0x16, 0xE7, 0xB1, 0xC3, 0x9E,
                0x86, 0xCB, 0x08, 0x6B, 0x78, 0x9F, 0x54, 0x19, 
            ]),
        },
        {
            key: Uint8Array.from([
                0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32,
                0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A,
            ]),
            textPlain: Uint8Array.from([
                0xD4, 0x91, 0xDB, 0x16, 0xE7, 0xB1, 0xC3, 0x9E,
                0x86, 0xCB, 0x08, 0x6B, 0x78, 0x9F, 0x54, 0x19,
            ]),
            textCipher: Uint8Array.from([
                0x01, 0x9F, 0x98, 0x09, 0xDE, 0x17, 0x11, 0x85,
                0x8F, 0xAA, 0xC3, 0xA3, 0xBA, 0x20, 0xFB, 0xC3,
            ]),
        },
        {
            key: Uint8Array.from([
                0xD4, 0x91, 0xDB, 0x16, 0xE7, 0xB1, 0xC3, 0x9E,
                0x86, 0xCB, 0x08, 0x6B, 0x78, 0x9F, 0x54, 0x19,
            ]),
            textPlain: Uint8Array.from([
                0x01, 0x9F, 0x98, 0x09, 0xDE, 0x17, 0x11, 0x85,
                0x8F, 0xAA, 0xC3, 0xA3, 0xBA, 0x20, 0xFB, 0xC3,
            ]),
            textCipher: Uint8Array.from([
                0x63, 0x63, 0x97, 0x7D, 0xE8, 0x39, 0x48, 0x62,
                0x97, 0xE6, 0x61, 0xC6, 0xC9, 0xD6, 0x68, 0xEB,
            ]),
        },
        {
            key: Uint8Array.from([
                0x01, 0x9F, 0x98, 0x09, 0xDE, 0x17, 0x11, 0x85,
                0x8F, 0xAA, 0xC3, 0xA3, 0xBA, 0x20, 0xFB, 0xC3,
            ]),
            textPlain: Uint8Array.from([
                0x63, 0x63, 0x97, 0x7D, 0xE8, 0x39, 0x48, 0x62,
                0x97, 0xE6, 0x61, 0xC6, 0xC9, 0xD6, 0x68, 0xEB,
            ]),
            textCipher: Uint8Array.from([
                0x81, 0x6D, 0x5B, 0xD0, 0xFA, 0xE3, 0x53, 0x42,
                0xBF, 0x2A, 0x74, 0x12, 0xC2, 0x46, 0xF7, 0x52,
            ]),
        },
        {
            key: Uint8Array.from([
                0x63, 0x63, 0x97, 0x7D, 0xE8, 0x39, 0x48, 0x62,
                0x97, 0xE6, 0x61, 0xC6, 0xC9, 0xD6, 0x68, 0xEB,
            ]),
            textPlain: Uint8Array.from([
                0x81, 0x6D, 0x5B, 0xD0, 0xFA, 0xE3, 0x53, 0x42,
                0xBF, 0x2A, 0x74, 0x12, 0xC2, 0x46, 0xF7, 0x52,
            ]),
            textCipher: Uint8Array.from([
                0x54, 0x49, 0xEC, 0xA0, 0x08, 0xFF, 0x59, 0x21,
                0x15, 0x5F, 0x59, 0x8A, 0xF4, 0xCE, 0xD4, 0xD0,
            ]),
        },
        {
            key: Uint8Array.from([
                0x81, 0x6D, 0x5B, 0xD0, 0xFA, 0xE3, 0x53, 0x42,
                0xBF, 0x2A, 0x74, 0x12, 0xC2, 0x46, 0xF7, 0x52,
            ]),
            textPlain: Uint8Array.from([
                0x54, 0x49, 0xEC, 0xA0, 0x08, 0xFF, 0x59, 0x21,
                0x15, 0x5F, 0x59, 0x8A, 0xF4, 0xCE, 0xD4, 0xD0,
            ]),
            textCipher: Uint8Array.from([
                0x66, 0x00, 0x52, 0x2E, 0x97, 0xAE, 0xB3, 0x09,
                0x4E, 0xD5, 0xF9, 0x2A, 0xFC, 0xBC, 0xDD, 0x10,
            ]),
        },
    ]);

    it('should encrypt using 128-bits keys', () => {

        const textCipherB = new Uint8Array(BLOCK_SIZE);

        for (const test of TEST_CASES_128BITS) {

            const { key, textPlain, textCipher: textCipherA } = test;

            encrypt128(key, textPlain, textCipherB);

            let index = 0;
            while (index < BLOCK_SIZE) {

                expect(textCipherA[index]).equal(textCipherB[index]);
                index = (index + 1) | 0;

            }

        }

    });

    it('should decrypt using 128-bits keys', () => {

        const textPlainB = new Uint8Array(BLOCK_SIZE);

        for (const test of TEST_CASES_128BITS) {

            const { key, textPlain: textPlainA, textCipher } = test;

            decrypt128(key, textCipher, textPlainB);

            let index = 0;
            while (index < BLOCK_SIZE) {

                expect(textPlainA[index]).equal(textPlainB[index]);
                index = (index + 1) | 0;

            }

        }

    });

    const { encrypt128Chain, decrypt128Chain } = TwofishCryptography;

    it('should encrypt and decrypt a chain of blocks', () => {

        const COUNT_BLOCKS = 7;
        const LIMIT_TEXT = BLOCK_SIZE * COUNT_BLOCKS;

        const initialVector = new Uint8Array(KEY_SIZE);

        const nextVector = () => {

            let index = 0;
            while (index < KEY_SIZE) {

                initialVector[index] = (initialVector[index] + 1) & 0xFF;
                if (initialVector[index] !== 0) {

                    break;

                }

                index = (index + 1) | 0;

            }

        };

        const key = new Uint8Array(KEY_SIZE);
        key.fill(0x5A);

        const textPlainA = new Uint8Array(LIMIT_TEXT);
        textPlainA.fill(0xA5);

        const textCipherA = new Uint8Array(LIMIT_TEXT);
        for (let indexA = 0; indexA < COUNT_BLOCKS; indexA = (indexA + 1) | 0) {

            for (let indexB = 0; indexB < KEY_SIZE; indexB = (indexB + 1) | 0) {

                key[indexB] = key[indexB] ^ initialVector[indexB];

            }

            const offset = indexA << 4;
            const chunkPlain = textPlainA.subarray(offset, (offset + BLOCK_SIZE));
            const chunkCipher = textCipherA.subarray(offset, (offset + BLOCK_SIZE));
            encrypt128(key, chunkPlain, chunkCipher);

            for (let indexB = 0; indexB < KEY_SIZE; indexB = (indexB + 1) | 0) {

                key[indexB] = key[indexB] ^ initialVector[indexB];

            }

            nextVector();

        }

        const textCipherB = new Uint8Array(LIMIT_TEXT);
        encrypt128Chain(key, textPlainA, textCipherB);
        for (let indexA = 0; indexA < LIMIT_TEXT; indexA = (indexA + 1) | 0) {

            expect(textCipherA[indexA]).equal(textCipherB[indexA]);
            indexA = (indexA + 1) | 0;

        }

        const textPlainB = new Uint8Array(LIMIT_TEXT);
        decrypt128Chain(key, textCipherB, textPlainB);
        for (let indexA = 0; indexA < LIMIT_TEXT; indexA = (indexA + 1) | 0) {

            expect(textPlainA[indexA]).equal(textPlainB[indexA]);
            indexA = (indexA + 1) | 0;

        }

    });

});
