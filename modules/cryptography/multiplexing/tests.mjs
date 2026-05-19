import MultiplexingCryptography from "./index.mjs";
import RandomGenerator from '../../random/index.mjs';

import {
    LENGHT_HANDSHAKE,
    LENGTH_SHARED_REMAINDER,
    LENGTH_SHARED_SECRET,
    MODULUS_SHARED_SECRET,
} from "../../constants/index.mjs";

import {
    POLYNOMIAL_MODULUS_BUFFER_LONG,
} from "../../utilities/index.mjs";

import { expect } from 'chai';

const LIMIT_TESTS_RANDOM = 128;

describe('MultiplexingCryptography', () => {

    it('should check if a handshake matches a given shared secret', () => {

        const TEST_CASES_TRIVIAL = () => {

            // trivial cases:
            // shared secret: 0
            // remainder: 0
            // handshake: multiples of MODULUS_SHARED_SECRET

            const sharedSecret = new Uint8Array(LENGTH_SHARED_SECRET);
            const remainder = new Uint8Array(LENGTH_SHARED_REMAINDER);
            const handshake = new Uint8Array(LENGTH_SHARED_SECRET);

            let count = 0;
            while (count < 7) {

                handshake.fill(0);

                let indexA = 0;
                let indexB = count;
                while (indexA < MODULUS_SHARED_SECRET.length) {

                    handshake[indexB] = MODULUS_SHARED_SECRET[indexA];

                    indexA = (indexA + 1) | 0;
                    indexB = (indexB + 1) | 0;

                }

                const result = MultiplexingCryptography.match(sharedSecret, remainder, handshake);
                expect(result).to.be.equal(true);

                count = (count + 1) | 0;

            }

        };

        const TEST_CASES_RANDOM = () => {

            RandomGenerator.seed(performance.now() | 0);

            let count = 0;
            while (count < LIMIT_TESTS_RANDOM) {

                const sharedSecret = new Uint8Array(LENGTH_SHARED_SECRET);
                const remainder = new Uint8Array(LENGTH_SHARED_REMAINDER);
                const handshake = new Uint8Array(LENGTH_SHARED_SECRET);
                const polynomialSum = new Uint8Array(LENGTH_SHARED_SECRET);

                RandomGenerator.fill(sharedSecret);
                RandomGenerator.fill(remainder);
                RandomGenerator.fill(handshake);

                let index = 0;
                while (index < LENGTH_SHARED_SECRET) {

                    polynomialSum[index] = sharedSecret[index] ^ handshake[index];
                    index = (index + 1) | 0;

                }

                // the randomly chosen "handshake" is never correct, so we have to calculate
                // the difference between "remainderA" (the reference one) and "remainderB"
                // to adjust "handshake" to yield "remainderA".

                const difference = new Uint8Array(LENGTH_SHARED_REMAINDER);
                POLYNOMIAL_MODULUS_BUFFER_LONG(
                    polynomialSum,
                    0,
                    polynomialSum.length,
                    MODULUS_SHARED_SECRET,
                    difference,
                );

                index = 0;
                while (index < LENGTH_SHARED_REMAINDER) {

                    difference[index] = difference[index] ^ remainder[index];
                    index = (index + 1) | 0;

                }

                let indexA = difference.length;
                let indexB = handshake.length;
                while (indexA > 0 && indexB > 0) {

                    indexA = (indexA - 1) | 0;
                    indexB = (indexB - 1) | 0;

                    handshake[indexB] = handshake[indexB] ^ difference[indexA];

                }

                index = 0;
                while (index < LENGTH_SHARED_SECRET) {

                    polynomialSum[index] = sharedSecret[index] ^ handshake[index];
                    index = (index + 1) | 0;

                }

                POLYNOMIAL_MODULUS_BUFFER_LONG(
                    polynomialSum,
                    0,
                    polynomialSum.length,
                    MODULUS_SHARED_SECRET,
                    difference,
                );

                const result = MultiplexingCryptography.match(sharedSecret, remainder, handshake);
                expect(result).to.be.equal(true);

                count = (count + 1) | 0;

            }

        };

        TEST_CASES_TRIVIAL();
        TEST_CASES_RANDOM();

    });

    it('should generate handshakes for a given shared secret and remainder', () => {

        RandomGenerator.seed(performance.now() | 0);

        const sharedSecret = new Uint8Array(LENGTH_SHARED_SECRET);
        const remainder = new Uint8Array(LENGTH_SHARED_REMAINDER);
        const handshake = new Uint8Array(LENGHT_HANDSHAKE);

        let count = 0;
        while (count < LIMIT_TESTS_RANDOM) {

            RandomGenerator.fill(sharedSecret);
            RandomGenerator.fill(remainder);

            MultiplexingCryptography.generate(sharedSecret, remainder, handshake);

            const result = MultiplexingCryptography.match(sharedSecret, remainder, handshake);
            expect(result).to.be.equal(true);

            count = (count + 1) | 0;

        }

    });

});
