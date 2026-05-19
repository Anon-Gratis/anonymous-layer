// ElGamal Cryptography in a nutshell:
// m * g^{xy} * g^{-xy} = m (mod p)

// largest safe prime (see "Sophie Germain" primes) below 2^2048
const PRIME_MODULUS = (2n ** 2048n) - 1942289n;

// the count of how many elements in the modular group for the safe prime above
const GROUP_SIZE = PRIME_MODULUS - 1n;

// GENERATOR is the "g" in the g^{xy}
// computers use binary, so this should make calculations slightly easier
const GENERATOR = 2n;

// calculates base^{exponent} (mod PRIME_MODULUS), square-and-multiply method
const MODULAR_EXPONENTIATION = (base, exponent) => {

    let result = 1n;
    while (exponent > 0) {

        if ((exponent & 1n) !== 0n) {

            result = (result * base) % PRIME_MODULUS;

        }

        base = (base * base) % PRIME_MODULUS;
        exponent = exponent >> 1n;

    }

    return result;

};

const CALCULATE_KEY = (exponent) => {

    const key = MODULAR_EXPONENTIATION(GENERATOR, exponent);
    return key;

};

const CALCULATE_SHARED_SECRET = (key, exponent) => {

    const sharedSecret = MODULAR_EXPONENTIATION(key, exponent);
    return sharedSecret;

};

// keyPublic is g^{x}, keySender is g^{y}
// sharedSecret is the g^{xy} that originates from (g^{x})^y or (g^{y})^x
const ENCRYPT = (textPlain, keyPublic, exponentSender) => {

    const keySender = CALCULATE_KEY(exponentSender);
    const sharedSecret = CALCULATE_SHARED_SECRET(keyPublic, exponentSender);
    const textCipher = (textPlain * sharedSecret) % PRIME_MODULUS;
    return [textCipher, keySender];

};

const DECRYPT = (textCipher, keySender, exponentPrivate) => {

    const exponentOpposite = GROUP_SIZE - exponentPrivate;
    const secretOpposite = MODULAR_EXPONENTIATION(keySender, exponentOpposite);
    const textPlain = (textCipher * secretOpposite) % PRIME_MODULUS;
    return textPlain;

};

const LIMIT_BITS2048 = 256; // octets of bits

const INPUT_BITS2048 = (buffer) => {

    let accumulator = 0n;

    let index = buffer.length | 0;
    if (index === 0) {

        return accumulator;

    }

    do {

        index = (index - 1) | 0;
        accumulator = accumulator << 8n;
        accumulator = accumulator + BigInt(buffer[index]);

    } while (index !== 0);

    return accumulator;

};

const OUTPUT_BITS2048 = (integer, buffer) => {

    let index = 0;
    while (index !== LIMIT_BITS2048) {

        buffer[index] = Number(integer & 0xFFn);
        integer = integer >> 8n;
        index = (index + 1) | 0;

    }

};

export const encrypt2048 = (
    bufferKeyPublic,
    bufferExponentSender,
    bufferTextPlain,
    bufferTextCipher,
    bufferKeySender,
) => {

    const keyPublic = INPUT_BITS2048(bufferKeyPublic);
    const exponentSender = INPUT_BITS2048(bufferExponentSender);
    const textPlain = INPUT_BITS2048(bufferTextPlain);
    const [textCipher, keySender] = ENCRYPT(textPlain, keyPublic, exponentSender);
    OUTPUT_BITS2048(textCipher, bufferTextCipher);
    OUTPUT_BITS2048(keySender, bufferKeySender);

};

export const decrypt2048 = (
    bufferExponentPrivate,
    bufferKeySender,
    bufferTextCipher,
    bufferTextPlain,
) => {

    const exponentPrivate = INPUT_BITS2048(bufferExponentPrivate);
    const keySender = INPUT_BITS2048(bufferKeySender);
    const textCipher = INPUT_BITS2048(bufferTextCipher);
    const textPlain = DECRYPT(textCipher, keySender, exponentPrivate);
    OUTPUT_BITS2048(textPlain, bufferTextPlain);

};

export const calculateKey2048 = (bufferExponent, bufferKey) => {

    const exponent = INPUT_BITS2048(bufferExponent);
    const key = CALCULATE_KEY(exponent);
    OUTPUT_BITS2048(key, bufferKey);

};

const ElGamalCryptography = Object.freeze({
    calculateKey2048,
    encrypt2048,
    decrypt2048,
});

export default ElGamalCryptography;
