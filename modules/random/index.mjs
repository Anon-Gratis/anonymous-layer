import { randomFillSync } from 'node:crypto';

// Cryptographically-secure randomness sourced from the operating system's
// entropy pool. The previous implementation (a custom 4-word PRNG seeded
// from Math.random()) is removed: V8's Math.random is not CSPRNG-grade,
// and the custom state machine had no security analysis.
//
// The `seed` and `setup` exports are retained as no-ops so existing call
// sites do not have to be changed in this pass. They are scheduled for
// removal once all callers are audited.

const fill = (buffer) => {

    randomFillSync(buffer);

};

const seed = (_number) => {};

const setup = () => {};

const RandomGenerator = Object.freeze({
    fill,
    seed,
    setup,
});

export default RandomGenerator;
