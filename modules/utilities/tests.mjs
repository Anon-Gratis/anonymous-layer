import {
    LENGTH_SHARED_REMAINDER,
    LENGTH_SHARED_SECRET,
    MODULUS_SHARED_SECRET,
} from "../constants/index.mjs";

import {
    POLYNOMIAL_MODULUS_BUFFER_LONG,
} from './index.mjs';

import RandomGenerator from "../random/index.mjs";
import { expect } from "chai";

const TO_BIG_INTEGER = (buffer) => {

    let accumulator = 0n;

    let index = 0;
    while (index < buffer.length) {

        const octet = BigInt(buffer[index]);
        accumulator = (accumulator << 8n) | octet;

        index = (index + 1) | 0;

    }

    return accumulator;

};

const POLYNOMIAL_DEGREE_BIG_INTEGER = (integer) => {

    let degree = 0;

    while (integer > 0) {

        integer = integer >> 1n;
        degree = (degree + 1) | 0;

    }

    return degree;

};

const POLYNOMIAL_MODULUS_BIG_INTEGER = (dividend, divisor) => {

    const degreeDivisor = POLYNOMIAL_DEGREE_BIG_INTEGER(divisor);
    let degreeDividend = POLYNOMIAL_DEGREE_BIG_INTEGER(dividend);
    while (degreeDividend >= degreeDivisor) {

        const shift = BigInt(degreeDividend - degreeDivisor);
        const subtractor = divisor << shift;
        dividend = dividend ^ subtractor;

        degreeDividend = POLYNOMIAL_DEGREE_BIG_INTEGER(dividend);

    }

    return dividend;

};

const LIMIT_TESTS_RANDOM = 256;

const integerModulus = TO_BIG_INTEGER(MODULUS_SHARED_SECRET);

describe('POLYNOMIAL_MODULUS_BUFFER_LONG', () => {

    it('should calculate polynomial remainders of arbitrary length', () => {

        const TEST_CASES_TRIVIAL = () => {

            // trivial cases:
            // polynomialSum: multiples of MODULUS_SHARED_SECRET
            // expected remainder: 0

            const polynomialSum = new Uint8Array(LENGTH_SHARED_SECRET);
            const remainder = new Uint8Array(LENGTH_SHARED_REMAINDER);

            let count = 0;
            while (count < 7) {

                polynomialSum.fill(0);

                let indexA = 0;
                let indexB = count;
                while (indexA < MODULUS_SHARED_SECRET.length) {

                    polynomialSum[indexB] = MODULUS_SHARED_SECRET[indexA];

                    indexA = (indexA + 1) | 0;
                    indexB = (indexB + 1) | 0;

                }

                const integerPolynomialSum = TO_BIG_INTEGER(polynomialSum);

                const remainderA = POLYNOMIAL_MODULUS_BIG_INTEGER(
                    integerPolynomialSum,
                    integerModulus,
                );

                POLYNOMIAL_MODULUS_BUFFER_LONG(
                    polynomialSum,
                    0,
                    polynomialSum.length,
                    MODULUS_SHARED_SECRET,
                    remainder,
                );

                const remainderB = TO_BIG_INTEGER(remainder);

                expect(remainderA).to.be.equal(remainderB);

                count = (count + 1) | 0;

            }

        };

        const TEST_CASES_RANDOM = () => {

            let count = 0;
            while (count < LIMIT_TESTS_RANDOM) {

                const polynomialSum = new Uint8Array(LENGTH_SHARED_SECRET);
                const remainder = new Uint8Array(LENGTH_SHARED_REMAINDER);

                RandomGenerator.fill(polynomialSum);
                const integerPolynomialSum = TO_BIG_INTEGER(polynomialSum);

                const remainderA = POLYNOMIAL_MODULUS_BIG_INTEGER(
                    integerPolynomialSum,
                    integerModulus,
                );

                POLYNOMIAL_MODULUS_BUFFER_LONG(
                    polynomialSum,
                    0,
                    polynomialSum.length,
                    MODULUS_SHARED_SECRET,
                    remainder,
                );

                const remainderB = TO_BIG_INTEGER(remainder);

                expect(remainderA).to.be.equal(remainderB);

                count = (count + 1) | 0;

            }

        };

        TEST_CASES_TRIVIAL();
        TEST_CASES_RANDOM();

    });

});
