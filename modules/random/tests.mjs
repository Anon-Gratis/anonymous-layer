import RandomGenerator from './index.mjs';

import { expect } from 'chai';

const POPULATION_COUNT = (buffer) => {

    let count = 0;

    const { length } = buffer;
    let index = 0;
    while (index < length) {

        let octet = buffer[index];
        index = (index + 1) | 0;

        while (octet !== 0) {

            octet = octet & ((octet - 1) | 0);
            count = (count + 1) | 0;

        }

    }

    return count;

};

const LIMIT_TESTS = 2048;

// if the population count of bits is within 40%~60%, let's call it a pass.
const EXPECTED_RANGE_A = 819;
const EXPECTED_RANGE_B = 1229;

describe('RandomGenerator', () => {

    it('should generate bits with equal probability', () => {

        RandomGenerator.seed(performance.now() | 0);
        const buffer = new Uint8Array(256);

        let test = 0;
        while (test < LIMIT_TESTS) {

            test = (test + 1) | 0;

            RandomGenerator.fill(buffer);

            const populationCount = POPULATION_COUNT(buffer);
            expect(populationCount).to.be.greaterThan(EXPECTED_RANGE_A);
            expect(populationCount).to.be.lessThan(EXPECTED_RANGE_B);

        }

    });

});
