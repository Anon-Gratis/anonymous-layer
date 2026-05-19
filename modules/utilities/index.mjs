import {
    LENGTH_COORDINATION_HEADER,
    LENGTH_HOST_IPV6,
    MODULUS_PACKET_CHECKSUM,
    OFFSET_POLYNOMIAL,
} from '../constants/index.mjs';

////////////////////////////////////////////////////////////////////////
// EXTRACTION                                                         //
////////////////////////////////////////////////////////////////////////

export const EXTRACT_HOST_IPV6 = (buffer, offset) => {

    const chunks = [];

    const limit = (offset + LENGTH_HOST_IPV6) | 0;
    let index = offset;
    while (index < limit) {

        let word = 0;
        word = word | (buffer[index | 0] << 8);
        word = word | (buffer[index | 1] << 0);

        index = (index + 2) | 0;

        const chunk = word.toString(16).padStart(4, '0');
        chunks.push(chunk);

    }

    const address = chunks.join(':');
    return address;

};

export const EXTRACT_SUBARRAY = (buffer, offset, length) => {

    return buffer.subarray(offset, (offset + length) | 0);

}

// uses network byte order (big-endian) for integers
export const EXTRACT_UINT16 = (buffer, offset) => {

    let accumulator = 0;
    accumulator = accumulator | ((buffer[(offset + 0) | 0]) << 8);
    accumulator = accumulator | ((buffer[(offset + 1) | 0]) << 0);

    return accumulator;

};

export const EXTRACT_UINT32 = (buffer, offset) => {

    let accumulator = 0;
    accumulator = accumulator | ((buffer[(offset + 0) | 0]) << 24);
    accumulator = accumulator | ((buffer[(offset + 1) | 0]) << 16);
    accumulator = accumulator | ((buffer[(offset + 2) | 0]) <<  8);
    accumulator = accumulator | ((buffer[(offset + 3) | 0]) <<  0);

    accumulator = accumulator >>> 0;

    return accumulator;

};

////////////////////////////////////////////////////////////////////////
// INSERTION                                                          //
////////////////////////////////////////////////////////////////////////

export const INSERT_HOST_IPV6 = (binary, offset, host) => {

    binary.fill(0, offset, (offset + LENGTH_HOST_IPV6) | 0);

    const [partA, partB] = host.split('::');

    if (partA) {

        const chunks = partA.split(':');
        let subOffset = offset;

        const { length } = chunks;
        let index = 0;
        while (index < length) {

            const chunk = chunks[index];
            const integer = Number.parseInt(chunk, 16);
            INSERT_UINT16(binary, subOffset, integer);

            index = (index + 1) | 0;
            subOffset = (subOffset + 2) | 0;

        }

    }

    if (partB) {

        const chunks = partB.split(':');
        let subOffset = (offset + LENGTH_HOST_IPV6) | 0;

        const { length } = chunks;
        let index = length;
        while (index > 0) {

            index = (index - 1) | 0;
            subOffset = (subOffset - 2) | 0;

            const chunk = chunks[index];
            const integer = Number.parseInt(chunk, 16);
            INSERT_UINT16(binary, subOffset, integer);

        }

    }

};

export const INSERT_UINT16 = (binary, offset, integer) => {

    binary[(offset + 0) | 0] = (integer >> 8) & 0xFF;
    binary[(offset + 1) | 0] = (integer >> 0) & 0xFF;

};

export const INSERT_UINT32 = (binary, offset, integer) => {

    binary[(offset + 0) | 0] = (integer >> 24) & 0xFF;
    binary[(offset + 1) | 0] = (integer >> 16) & 0xFF;
    binary[(offset + 2) | 0] = (integer >>  8) & 0xFF;
    binary[(offset + 3) | 0] = (integer >>  0) & 0xFF;

};

////////////////////////////////////////////////////////////////////////
// POLYNOMIAL ARITHMETIC                                              //
////////////////////////////////////////////////////////////////////////

export const POLYNOMIAL_DEGREE = (polynomial) => (31 - Math.clz32(polynomial)) | 0;

export const POLYNOMIAL_MODULUS_BUFFER = (buffer, offset, length, modulus) => {

    const degreeModulus = POLYNOMIAL_DEGREE(modulus);

    let accumulator = 0;
    let index = offset;
    while (index < length) {

        accumulator = (accumulator << 8) | buffer[index];

        let degreePolynomial = POLYNOMIAL_DEGREE(accumulator);
        while (degreePolynomial >= degreeModulus) {

            const shift = (degreePolynomial - degreeModulus) | 0;
            const subtractor = modulus << shift;
            accumulator = accumulator ^ subtractor;

            degreePolynomial = POLYNOMIAL_DEGREE(accumulator);

        }

        index = (index + 1) | 0;

    }

    return accumulator;

};

export const POLYNOMIAL_DEGREE_LONG = (buffer) => {

    let degree = 0;

    let index = 0;
    while (index < buffer.length) {

        const octet = buffer[index];
        index = (index + 1) | 0;

        if (octet === 0) {

            continue;

        }

        degree = (31 - Math.clz32(octet)) | 0;
        break;

    }

    const extra = (buffer.length - index) | 0;
    degree = (degree + (extra << 3)) | 0;

    return degree;

};

export const POLYNOMIAL_MODULUS_BUFFER_LONG = (buffer, offset, length, modulus, remainder) => {

    let indexA = 0;
    let indexB = 0;
    let indexC = 0;

    const degreeModulus = POLYNOMIAL_DEGREE_LONG(modulus);

    const accumulator = new Uint8Array(modulus.length << 1);

    indexA = offset;
    while (indexA < length) {

        indexB = 0;
        while (accumulator[indexB] === 0 && indexB < accumulator.length) {

            indexB = (indexB + 1) | 0;

        }

        const shift = Math.min((length - indexA) | 0, indexB);

        indexC = (indexB - shift) | 0;
        while (indexB < accumulator.length) {

            accumulator[indexC] = accumulator[indexB];

            indexB = (indexB + 1) | 0;
            indexC = (indexC + 1) | 0;

        }

        while (indexC < accumulator.length && indexA < length) {

            accumulator[indexC] = buffer[indexA];

            indexA = (indexA + 1) | 0;
            indexC = (indexC + 1) | 0;

        }

        while (true) {

            const degreeAccumulator = POLYNOMIAL_DEGREE_LONG(accumulator);

            if (degreeAccumulator < degreeModulus) {

                break;

            }

            const difference = (degreeAccumulator - degreeModulus) | 0;
            let stride = ((difference >>> 3) + modulus.length) | 0;

            let shift = difference & 0b111;

            if (shift === 0) {

                indexB = (accumulator.length - stride) | 0;
                indexC = 0;
                while (indexC < modulus.length) {

                    const octet = modulus[indexC];
                    indexC = (indexC + 1) | 0;

                    accumulator[indexB] = accumulator[indexB] ^ octet;
                    indexB = (indexB + 1) | 0;

                }

            } else {

                indexB = (accumulator.length - stride) | 0;
                indexC = 0;
                while (indexC < modulus.length) {

                    const octet = modulus[indexC];
                    indexC = (indexC + 1) | 0;

                    const addend = octet << shift;

                    accumulator[indexB] = accumulator[indexB] ^ addend;
                    indexB = (indexB + 1) | 0;

                }

                shift = (8 - shift) | 0;
                stride = (stride + 1) | 0;

                indexB = (accumulator.length - stride) | 0;
                indexC = 0;
                while (indexC < modulus.length) {

                    const octet = modulus[indexC];
                    indexC = (indexC + 1) | 0;

                    const addend = octet >>> shift;

                    accumulator[indexB] = accumulator[indexB] ^ addend;
                    indexB = (indexB + 1) | 0;

                }

            }

        }

    }

    indexA = accumulator.length;
    indexB = remainder.length;
    while (indexA > 0 && indexB > 0) {

        indexA = (indexA - 1) | 0;
        indexB = (indexB - 1) | 0;

        remainder[indexB] = accumulator[indexA];

    }

};

export const POLYNOMIAL_HEADER_CHECKSUM = (buffer) => {

    let accumulator = 0;
    let index = OFFSET_POLYNOMIAL;
    while (index < LENGTH_COORDINATION_HEADER) {

        accumulator = (accumulator << 8) | buffer[index];

        const degreeModulus = POLYNOMIAL_DEGREE(MODULUS_PACKET_CHECKSUM);
        let degreePolynomial = POLYNOMIAL_DEGREE(accumulator);
        while (degreePolynomial >= degreeModulus) {

            const shift = (degreePolynomial - degreeModulus) | 0;
            const subtractor = MODULUS_PACKET_CHECKSUM << shift;
            accumulator = accumulator ^ subtractor;

            degreePolynomial = POLYNOMIAL_DEGREE(accumulator);

        }

        index = (index + 1) | 0;

    }

    return accumulator;

};
