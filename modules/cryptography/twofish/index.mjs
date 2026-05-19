// https://www.schneier.com/wp-content/uploads/2016/02/paper-twofish-paper.pdf

////////////////////////////////////////////////////////////////////////
// HELPERS FOR MANIPULATION OF GROUPS OF BITS                         //
////////////////////////////////////////////////////////////////////////

const ROTATE_LEFT = (x, n) => ((x << n) | (x >>> ((32 - n) | 0))) >>> 0;
const ROTATE_RIGHT = (x, n) =>  ((x >>> n) | (x << ((32 - n) | 0))) >>> 0;

const UINT32_FROM_UINT8_GROUP = (a, b, c, d) => {

    let word = 0;
    word = word | (a << 24);
    word = word | (b << 16);
    word = word | (c <<  8);
    word = word | (d <<  0);

    return word;

};

const UINT32_BYTE3 = (x) =>  (x >>> 24) & 0xFF;
const UINT32_BYTE2 = (x) =>  (x >>> 16) & 0xFF;
const UINT32_BYTE1 = (x) =>  (x >>>  8) & 0xFF;
const UINT32_BYTE0 = (x) =>  (x >>>  0) & 0xFF;

////////////////////////////////////////////////////////////////////////
// HELPERS FOR POLYNOMIAL ARITHMETIC                                  //
/////////////////////////////////////////const//////////////////////////

// polynomial modulus for MDS matrix multiplication:
// expression: x^8 + x^6 + x^5 + x^3 + 1
// binary: 0b101101001
const TWOFISH_MDS_MODULUS = 0b101101001;

// polynomial modulus for RS matrix multiplication:
// expression: x^8 + x^6 + x^3 + x^2 + 1
// binary: 0b101001101
const TWOFISH_RS_MODULUS = 0b101001101;

const POLYNOMIAL_DEGREE = (polynomial) => (31 - Math.clz32(polynomial)) | 0;

const POLYNOMIAL_MULTIPLICATION = (polynomialA, polynomialB) => {

    let accumulator = 0;
    while (polynomialA !== 0) {

        const lowestBitSet = (polynomialA & 1) !== 0;
        if (lowestBitSet) {

            accumulator = accumulator ^ polynomialB;

        }

        polynomialA = polynomialA >>> 1;
        polynomialB = polynomialB << 1;

    }

    return accumulator;

};

const POLYNOMIAL_MODULUS = (polynomial, modulus) => {

    const degreeModulus = POLYNOMIAL_DEGREE(modulus);
    let degreePolynomial = POLYNOMIAL_DEGREE(polynomial);
    while (degreePolynomial >= degreeModulus) {

        const shift = (degreePolynomial - degreeModulus) | 0;
        const subtractor = modulus << shift;
        polynomial = polynomial ^ subtractor;

        degreePolynomial = POLYNOMIAL_DEGREE(polynomial);

    }

    return polynomial;

};

const MDS = Uint8Array.from([
    0x01, 0xEF, 0x5B, 0x5B,
    0x5B, 0xEF, 0xEF, 0x01,
    0xEF, 0x5B, 0x01, 0xEF,
    0xEF, 0x01, 0xEF, 0x5B,
]);

const MDS_MATRIX_HEIGHT = 4;
const MDS_MATRIX_WIDTH = 4;

const MDS_INDEX = (a, b) => ((a << 2) + b) | 0;

const MATRIX_MULTIPLY_MDS = (vectorY, vectorZ) => {

    let index = 0;
    while (index < MDS_MATRIX_HEIGHT) {

        const a0 = POLYNOMIAL_MULTIPLICATION(
            MDS[MDS_INDEX(index, 0)],
            vectorY[0],
        );

        const a1 = POLYNOMIAL_MULTIPLICATION(
            MDS[MDS_INDEX(index, 1)],
            vectorY[1],
        );

        const a2 = POLYNOMIAL_MULTIPLICATION(
            MDS[MDS_INDEX(index, 2)],
            vectorY[2],
        );

        const a3 = POLYNOMIAL_MULTIPLICATION(
            MDS[MDS_INDEX(index, 3)],
            vectorY[3],
        );

        vectorZ[index] = POLYNOMIAL_MODULUS(
            a0 ^ a1 ^ a2 ^ a3,
            TWOFISH_MDS_MODULUS,
        );

        index = (index + 1) | 0;

    }

};

const RS = Uint8Array.from([
    0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E,
    0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5,
    0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19,
    0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03,
]);

const RS_MATRIX_WIDTH = 8;
const RS_MATRIX_HEIGHT = 4;

const RS_INDEX = (a, b) => ((a << 3) + b) | 0;

const MATRIX_MULTIPLY_RS = (vectorM, vectorS, offsetM, offsetS) => {

    let baseRS = 0;

    let indexA = 0;
    while (indexA < RS_MATRIX_HEIGHT) {

        let accumulator = 0;

        let baseM = offsetM;
        let indexB = 0;
        while (indexB < RS_MATRIX_WIDTH) {

            const product = POLYNOMIAL_MULTIPLICATION(
                RS[baseRS],
                vectorM[baseM],
            );

            accumulator = accumulator ^ product;

            baseRS = (baseRS + 1) | 0;
            baseM = (baseM + 1) | 0;

            indexB = (indexB + 1) | 0;

        }

        vectorS[offsetS] = POLYNOMIAL_MODULUS(
            accumulator,
            TWOFISH_RS_MODULUS,
        );

        offsetS = (offsetS + 1) | 0;

        indexA = (indexA + 1) | 0;

    }

};

const TABLE_MULTIPLES_0x5B = Uint8Array.from([
   0x00, 0x5B, 0xB6, 0xED, 0x05, 0x5E, 0xB3, 0xE8,
   0x0A, 0x51, 0xBC, 0xE7, 0x0F, 0x54, 0xB9, 0xE2,
   0x14, 0x4F, 0xA2, 0xF9, 0x11, 0x4A, 0xA7, 0xFC,
   0x1E, 0x45, 0xA8, 0xF3, 0x1B, 0x40, 0xAD, 0xF6,
   0x28, 0x73, 0x9E, 0xC5, 0x2D, 0x76, 0x9B, 0xC0,
   0x22, 0x79, 0x94, 0xCF, 0x27, 0x7C, 0x91, 0xCA,
   0x3C, 0x67, 0x8A, 0xD1, 0x39, 0x62, 0x8F, 0xD4,
   0x36, 0x6D, 0x80, 0xDB, 0x33, 0x68, 0x85, 0xDE,
   0x50, 0x0B, 0xE6, 0xBD, 0x55, 0x0E, 0xE3, 0xB8,
   0x5A, 0x01, 0xEC, 0xB7, 0x5F, 0x04, 0xE9, 0xB2,
   0x44, 0x1F, 0xF2, 0xA9, 0x41, 0x1A, 0xF7, 0xAC,
   0x4E, 0x15, 0xF8, 0xA3, 0x4B, 0x10, 0xFD, 0xA6,
   0x78, 0x23, 0xCE, 0x95, 0x7D, 0x26, 0xCB, 0x90,
   0x72, 0x29, 0xC4, 0x9F, 0x77, 0x2C, 0xC1, 0x9A,
   0x6C, 0x37, 0xDA, 0x81, 0x69, 0x32, 0xDF, 0x84,
   0x66, 0x3D, 0xD0, 0x8B, 0x63, 0x38, 0xD5, 0x8E,
   0xA0, 0xFB, 0x16, 0x4D, 0xA5, 0xFE, 0x13, 0x48,
   0xAA, 0xF1, 0x1C, 0x47, 0xAF, 0xF4, 0x19, 0x42,
   0xB4, 0xEF, 0x02, 0x59, 0xB1, 0xEA, 0x07, 0x5C,
   0xBE, 0xE5, 0x08, 0x53, 0xBB, 0xE0, 0x0D, 0x56,
   0x88, 0xD3, 0x3E, 0x65, 0x8D, 0xD6, 0x3B, 0x60,
   0x82, 0xD9, 0x34, 0x6F, 0x87, 0xDC, 0x31, 0x6A,
   0x9C, 0xC7, 0x2A, 0x71, 0x99, 0xC2, 0x2F, 0x74,
   0x96, 0xCD, 0x20, 0x7B, 0x93, 0xC8, 0x25, 0x7E,
   0xF0, 0xAB, 0x46, 0x1D, 0xF5, 0xAE, 0x43, 0x18,
   0xFA, 0xA1, 0x4C, 0x17, 0xFF, 0xA4, 0x49, 0x12,
   0xE4, 0xBF, 0x52, 0x09, 0xE1, 0xBA, 0x57, 0x0C,
   0xEE, 0xB5, 0x58, 0x03, 0xEB, 0xB0, 0x5D, 0x06,
   0xD8, 0x83, 0x6E, 0x35, 0xDD, 0x86, 0x6B, 0x30,
   0xD2, 0x89, 0x64, 0x3F, 0xD7, 0x8C, 0x61, 0x3A,
   0xCC, 0x97, 0x7A, 0x21, 0xC9, 0x92, 0x7F, 0x24,
   0xC6, 0x9D, 0x70, 0x2B, 0xC3, 0x98, 0x75, 0x2E,
]);

const TABLE_MULTIPLES_0xEF = Uint8Array.from([
   0x00, 0xEF, 0xB7, 0x58, 0x07, 0xE8, 0xB0, 0x5F,
   0x0E, 0xE1, 0xB9, 0x56, 0x09, 0xE6, 0xBE, 0x51,
   0x1C, 0xF3, 0xAB, 0x44, 0x1B, 0xF4, 0xAC, 0x43,
   0x12, 0xFD, 0xA5, 0x4A, 0x15, 0xFA, 0xA2, 0x4D,
   0x38, 0xD7, 0x8F, 0x60, 0x3F, 0xD0, 0x88, 0x67,
   0x36, 0xD9, 0x81, 0x6E, 0x31, 0xDE, 0x86, 0x69,
   0x24, 0xCB, 0x93, 0x7C, 0x23, 0xCC, 0x94, 0x7B,
   0x2A, 0xC5, 0x9D, 0x72, 0x2D, 0xC2, 0x9A, 0x75,
   0x70, 0x9F, 0xC7, 0x28, 0x77, 0x98, 0xC0, 0x2F,
   0x7E, 0x91, 0xC9, 0x26, 0x79, 0x96, 0xCE, 0x21,
   0x6C, 0x83, 0xDB, 0x34, 0x6B, 0x84, 0xDC, 0x33,
   0x62, 0x8D, 0xD5, 0x3A, 0x65, 0x8A, 0xD2, 0x3D,
   0x48, 0xA7, 0xFF, 0x10, 0x4F, 0xA0, 0xF8, 0x17,
   0x46, 0xA9, 0xF1, 0x1E, 0x41, 0xAE, 0xF6, 0x19,
   0x54, 0xBB, 0xE3, 0x0C, 0x53, 0xBC, 0xE4, 0x0B,
   0x5A, 0xB5, 0xED, 0x02, 0x5D, 0xB2, 0xEA, 0x05,
   0xE0, 0x0F, 0x57, 0xB8, 0xE7, 0x08, 0x50, 0xBF,
   0xEE, 0x01, 0x59, 0xB6, 0xE9, 0x06, 0x5E, 0xB1,
   0xFC, 0x13, 0x4B, 0xA4, 0xFB, 0x14, 0x4C, 0xA3,
   0xF2, 0x1D, 0x45, 0xAA, 0xF5, 0x1A, 0x42, 0xAD,
   0xD8, 0x37, 0x6F, 0x80, 0xDF, 0x30, 0x68, 0x87,
   0xD6, 0x39, 0x61, 0x8E, 0xD1, 0x3E, 0x66, 0x89,
   0xC4, 0x2B, 0x73, 0x9C, 0xC3, 0x2C, 0x74, 0x9B,
   0xCA, 0x25, 0x7D, 0x92, 0xCD, 0x22, 0x7A, 0x95,
   0x90, 0x7F, 0x27, 0xC8, 0x97, 0x78, 0x20, 0xCF,
   0x9E, 0x71, 0x29, 0xC6, 0x99, 0x76, 0x2E, 0xC1,
   0x8C, 0x63, 0x3B, 0xD4, 0x8B, 0x64, 0x3C, 0xD3,
   0x82, 0x6D, 0x35, 0xDA, 0x85, 0x6A, 0x32, 0xDD,
   0xA8, 0x47, 0x1F, 0xF0, 0xAF, 0x40, 0x18, 0xF7,
   0xA6, 0x49, 0x11, 0xFE, 0xA1, 0x4E, 0x16, 0xF9,
   0xB4, 0x5B, 0x03, 0xEC, 0xB3, 0x5C, 0x04, 0xEB,
   0xBA, 0x55, 0x0D, 0xE2, 0xBD, 0x52, 0x0A, 0xE5,
]);

////////////////////////////////////////////////////////////////////////
// HELPERS FOR GENERATION OF KEYS                                     //
////////////////////////////////////////////////////////////////////////

const KEY_EXPANDED = new Uint32Array(40);
const KEY_FULL = new Uint32Array(4 * 256);

const KEY_FULL_INDEX = (a, b) => ((b << 2) + a) | 0;

const TWOFISH_BITS128_K = 2;
const TWOFISH_BITS192_K = 3;
const TWOFISH_BITS256_K = 4;

const KEY_DEPENDENT_SBOX = (selectorK, vectorM, vectorS) => {

    let offsetM = 0;
    let offsetS = (selectorK * RS_MATRIX_HEIGHT) | 0;

    let index = 0;
    while (index < selectorK) {

        offsetS = (offsetS - RS_MATRIX_HEIGHT) | 0;

        MATRIX_MULTIPLY_RS(
            vectorM, vectorS,
            offsetM, offsetS,
        );

        offsetM = (offsetM + RS_MATRIX_WIDTH) | 0;

        index = (index + 1) | 0;

    }

};

const Q0 = Uint8Array.from([
   0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76,
   0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
   0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C,
   0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
   0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23,
   0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
   0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C,
   0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
   0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B,
   0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
   0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66,
   0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
   0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA,
   0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
   0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8,
   0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
   0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2,
   0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
   0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB,
   0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
   0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B,
   0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
   0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A,
   0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
   0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02,
   0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
   0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72,
   0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
   0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8,
   0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
   0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00,
   0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0,
]);

const Q1 = Uint8Array.from([
   0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8,
   0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
   0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1,
   0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
   0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D,
   0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
   0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3,
   0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
   0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96,
   0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
   0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70,
   0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
   0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC,
   0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
   0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9,
   0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
   0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3,
   0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
   0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49,
   0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
   0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01,
   0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
   0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19,
   0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
   0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5,
   0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
   0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E,
   0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
   0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB,
   0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
   0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2,
   0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91,
]);

const LIST_INDEX = (a, b) => ((a << 2) + b) | 0;

const TWOFISH_BITS128_H = (vectorX, list) => {

    const vectorY = new Uint8Array(4);
    const vectorZ = new Uint8Array(4);

    vectorY[0] = UINT32_BYTE0(vectorX);
    vectorY[1] = UINT32_BYTE1(vectorX);
    vectorY[2] = UINT32_BYTE2(vectorX);
    vectorY[3] = UINT32_BYTE3(vectorX);

    vectorY[0] = Q1[ Q0 [ Q0[vectorY[0]] ^ list[LIST_INDEX(1, 0)] ] ^ list[LIST_INDEX(0, 0)] ];
    vectorY[1] = Q0[ Q0 [ Q1[vectorY[1]] ^ list[LIST_INDEX(1, 1)] ] ^ list[LIST_INDEX(0, 1)] ];
    vectorY[2] = Q1[ Q1 [ Q0[vectorY[2]] ^ list[LIST_INDEX(1, 2)] ] ^ list[LIST_INDEX(0, 2)] ];
    vectorY[3] = Q0[ Q1 [ Q1[vectorY[3]] ^ list[LIST_INDEX(1, 3)] ] ^ list[LIST_INDEX(0, 3)] ];

    MATRIX_MULTIPLY_MDS(
        vectorY,
        vectorZ,
    );

    return UINT32_FROM_UINT8_GROUP(
        vectorZ[3],
        vectorZ[2],
        vectorZ[1],
        vectorZ[0],
    );

};

const TWOFISH_BITS192_H = (vectorX, list) => {

    const vectorY = new Uint8Array(4);
    const vectorZ = new Uint8Array(4);

    vectorY[0] = UINT32_BYTE0(vectorX);
    vectorY[1] = UINT32_BYTE1(vectorX);
    vectorY[2] = UINT32_BYTE2(vectorX);
    vectorY[3] = UINT32_BYTE3(vectorX);

    vectorY[0] = Q1[vectorY[0]] ^ list[LIST_INDEX(2, 0)];
    vectorY[1] = Q1[vectorY[1]] ^ list[LIST_INDEX(2, 1)];
    vectorY[2] = Q0[vectorY[2]] ^ list[LIST_INDEX(2, 2)];
    vectorY[3] = Q0[vectorY[3]] ^ list[LIST_INDEX(2, 3)];

    vectorY[0] = Q1[ Q0 [ Q0[vectorY[0]] ^ list[LIST_INDEX(1, 0)] ] ^ list[LIST_INDEX(0, 0)] ];
    vectorY[1] = Q0[ Q0 [ Q1[vectorY[1]] ^ list[LIST_INDEX(1, 1)] ] ^ list[LIST_INDEX(0, 1)] ];
    vectorY[2] = Q1[ Q1 [ Q0[vectorY[2]] ^ list[LIST_INDEX(1, 2)] ] ^ list[LIST_INDEX(0, 2)] ];
    vectorY[3] = Q0[ Q1 [ Q1[vectorY[3]] ^ list[LIST_INDEX(1, 3)] ] ^ list[LIST_INDEX(0, 3)] ];

    MATRIX_MULTIPLY_MDS(
        vectorY,
        vectorZ,
    );

    return UINT32_FROM_UINT8_GROUP(
        vectorZ[3],
        vectorZ[2],
        vectorZ[1],
        vectorZ[0],
    );

};

const TWOFISH_BITS256_H = (vectorX, list) => {

    const vectorY = new Uint8Array(4);
    const vectorZ = new Uint8Array(4);

    vectorY[0] = UINT32_BYTE0(vectorX);
    vectorY[1] = UINT32_BYTE1(vectorX);
    vectorY[2] = UINT32_BYTE2(vectorX);
    vectorY[3] = UINT32_BYTE3(vectorX);

    vectorY[0] = Q1[vectorY[0]] ^ list[LIST_INDEX(3, 0)];
    vectorY[1] = Q0[vectorY[1]] ^ list[LIST_INDEX(3, 1)];
    vectorY[2] = Q0[vectorY[2]] ^ list[LIST_INDEX(3, 2)];
    vectorY[3] = Q1[vectorY[3]] ^ list[LIST_INDEX(3, 3)];

    vectorY[0] = Q1[vectorY[0]] ^ list[LIST_INDEX(2, 0)];
    vectorY[1] = Q1[vectorY[1]] ^ list[LIST_INDEX(2, 1)];
    vectorY[2] = Q0[vectorY[2]] ^ list[LIST_INDEX(2, 2)];
    vectorY[3] = Q0[vectorY[3]] ^ list[LIST_INDEX(2, 3)];

    vectorY[0] = Q1[ Q0 [ Q0[vectorY[0]] ^ list[LIST_INDEX(1, 0)] ] ^ list[LIST_INDEX(0, 0)] ];
    vectorY[1] = Q0[ Q0 [ Q1[vectorY[1]] ^ list[LIST_INDEX(1, 1)] ] ^ list[LIST_INDEX(0, 1)] ];
    vectorY[2] = Q1[ Q1 [ Q0[vectorY[2]] ^ list[LIST_INDEX(1, 2)] ] ^ list[LIST_INDEX(0, 2)] ];
    vectorY[3] = Q0[ Q1 [ Q1[vectorY[3]] ^ list[LIST_INDEX(1, 3)] ] ^ list[LIST_INDEX(0, 3)] ];

    MATRIX_MULTIPLY_MDS(
        vectorY,
        vectorZ,
    );

    return UINT32_FROM_UINT8_GROUP(
        vectorZ[3],
        vectorZ[2],
        vectorZ[1],
        vectorZ[0],
    );

};

const RHO = 0x01010101;

const KEY_EXPANSION_BITS128 = (vectorME, vectorMO, keyExpanded) => {

    let base = 0;

    let indexA = 0;
    let indexB = 0;
    while (indexB < 20) {

        let a = TWOFISH_BITS128_H(
            (base * RHO) | 0,
            vectorME,
        );

        base = (base + 1) | 0;

        let b = TWOFISH_BITS128_H(
            (base * RHO) | 0,
            vectorMO,
        );

        b = ROTATE_LEFT(b, 8);

        base = (base + 1) | 0;

        keyExpanded[indexA] = (a + b) | 0;
        indexA = (indexA + 1) | 0;

        keyExpanded[indexA] = ROTATE_LEFT((a + (2 * b)) | 0, 9);
        indexA = (indexA + 1) | 0;

        indexB = (indexB + 1) | 0;

    }

};

const KEY_FULL_BITS128 = (list, keyFull) => {

    let indexKey = 0;

    let index = 0;
    while (index < 256) {

        // inline version of "TWOFISH_BITS128_H" using multiplication tables

        let y0 = index;
        let y1 = index;
        let y2 = index;
        let y3 = index;

        y0 = Q1[Q0[Q0[y0] ^ list[LIST_INDEX(1, 0)]] ^ list[LIST_INDEX(0, 0)]];
        y1 = Q0[Q0[Q1[y1] ^ list[LIST_INDEX(1, 1)]] ^ list[LIST_INDEX(0, 1)]];
        y2 = Q1[Q1[Q0[y2] ^ list[LIST_INDEX(1, 2)]] ^ list[LIST_INDEX(0, 2)]];
        y3 = Q0[Q1[Q1[y3] ^ list[LIST_INDEX(1, 3)]] ^ list[LIST_INDEX(0, 3)]];

        let z0 = 0;
        let z1 = 0;
        let z2 = 0;
        let z3 = 0;

        z0 = TABLE_MULTIPLES_0xEF[y0];
        z1 = TABLE_MULTIPLES_0xEF[y0];
        z2 = TABLE_MULTIPLES_0x5B[y0];
        z3 = y0;

        keyFull[indexKey] = UINT32_FROM_UINT8_GROUP(z0, z1, z2, z3);
        indexKey = (indexKey + 1) | 0;

        z0 = y1;
        z1 = TABLE_MULTIPLES_0x5B[y1];
        z2 = TABLE_MULTIPLES_0xEF[y1];
        z3 = TABLE_MULTIPLES_0xEF[y1];

        keyFull[indexKey] = UINT32_FROM_UINT8_GROUP(z0, z1, z2, z3);
        indexKey = (indexKey + 1) | 0;

        z0 = TABLE_MULTIPLES_0xEF[y2];
        z1 = y2;
        z2 = TABLE_MULTIPLES_0xEF[y2];
        z3 = TABLE_MULTIPLES_0x5B[y2];

        keyFull[indexKey] = UINT32_FROM_UINT8_GROUP(z0, z1, z2, z3);
        indexKey = (indexKey + 1) | 0;

        z0 = TABLE_MULTIPLES_0x5B[y3];
        z1 = TABLE_MULTIPLES_0xEF[y3];
        z2 = y3;
        z3 = TABLE_MULTIPLES_0x5B[y3];

        keyFull[indexKey] = UINT32_FROM_UINT8_GROUP(z0, z1, z2, z3);
        indexKey = (indexKey + 1) | 0;

        index = index + 1 | 0;

    }

};

////////////////////////////////////////////////////////////////////////
// ENCRYPTION AND DECRYPTION COMMON TO ALL KEY SIZES                  //
////////////////////////////////////////////////////////////////////////

const VECTOR_ME = new Uint8Array(4 * 4);
const VECTOR_MO = new Uint8Array(4 * 4);
const VECTOR_M = new Uint8Array(4 * 8);
const VECTOR_S = new Uint8Array(4 * 4);

const COMMON_VECTOR_SPLITTING = (selectorK, key, vectorME, vectorMO) => {

    const fillVector = (vectorA, vectorB, offsetA, offsetB) => {

        vectorA[(offsetA + 0) | 0] = vectorB[(offsetB + 0) | 0];
        vectorA[(offsetA + 1) | 0] = vectorB[(offsetB + 1) | 0];
        vectorA[(offsetA + 2) | 0] = vectorB[(offsetB + 2) | 0];
        vectorA[(offsetA + 3) | 0] = vectorB[(offsetB + 3) | 0];

    };

    let offsetME = 0;
    let offsetMO = 0;

    let sourceME = 0;
    let sourceMO = 4;

    let index = 0;
    while (index < selectorK) {

        fillVector(vectorME, key, offsetME, sourceME);
        fillVector(vectorMO, key, offsetMO, sourceMO);

        offsetME = (offsetME + 4) | 0;
        offsetMO = (offsetMO + 4) | 0;

        sourceME = (sourceME + 8) | 0;
        sourceMO = (sourceMO + 8) | 0;

        index = (index + 1) | 0;

    }

};

const COMMON_VECTOR_JOINING = (selectorK, vectorME, vectorMO, vectorM) => {

    const LIMIT_M = selectorK << 3;

    let indexME = 0;
    let indexMO = 0;

    let indexM = 0;
    while (indexM < LIMIT_M) {

        for (let counter = 0; counter < 4; counter = (counter + 1) | 0) {

            vectorM[indexM] = vectorME[indexME];
            indexME = (indexME + 1) | 0;
            indexM = (indexM + 1) | 0;

        }

        for (let counter = 0; counter < 4; counter = (counter + 1) | 0) {

            vectorM[indexM] = vectorMO[indexMO];
            indexMO = (indexMO + 1) | 0;
            indexM = (indexM + 1) | 0;

        }

    }

}

const COMMON_ENCRYPT = (keyExpanded, keyFull, textPlain, textCipher) => {

    let r0 = 0;
    let r1 = 0;
    let r2 = 0;
    let r3 = 0;

    let t0 = 0;
    let t1 = 0;
    let t2 = 0;
    let t3 = 0;

    const swapWords = () => {

        t0 = r0;
        t1 = r1;
        t2 = r2;
        t3 = r3;

        r0 = t2;
        r1 = t3;
        r2 = t0;
        r3 = t1;

    };

    r0 = keyExpanded[0] ^ UINT32_FROM_UINT8_GROUP(
        textPlain[ 3],
        textPlain[ 2],
        textPlain[ 1],
        textPlain[ 0],
    );

    r1 = keyExpanded[1] ^ UINT32_FROM_UINT8_GROUP(
        textPlain[ 7],
        textPlain[ 6],
        textPlain[ 5],
        textPlain[ 4],
    );

    r2 = keyExpanded[2] ^ UINT32_FROM_UINT8_GROUP(
        textPlain[11],
        textPlain[10],
        textPlain[ 9],
        textPlain[ 8],
    );

    r3 = keyExpanded[3] ^ UINT32_FROM_UINT8_GROUP(
        textPlain[15],
        textPlain[14],
        textPlain[13],
        textPlain[12],
    );

    let round = 0;

    do {

        const roundBase = ((round << 1) + 8) | 0;
        const oddRound = (round & 1) !== 0;

        if (oddRound) {

            swapWords();

        }

        t0 = 0;
        t0 = t0 ^ keyFull[KEY_FULL_INDEX(0, UINT32_BYTE0(r0))];
        t0 = t0 ^ keyFull[KEY_FULL_INDEX(1, UINT32_BYTE1(r0))];
        t0 = t0 ^ keyFull[KEY_FULL_INDEX(2, UINT32_BYTE2(r0))];
        t0 = t0 ^ keyFull[KEY_FULL_INDEX(3, UINT32_BYTE3(r0))];

        t2 = ROTATE_LEFT(r1, 8);

        t1 = 0;
        t1 = t1 ^ keyFull[KEY_FULL_INDEX(0, UINT32_BYTE0(t2))];
        t1 = t1 ^ keyFull[KEY_FULL_INDEX(1, UINT32_BYTE1(t2))];
        t1 = t1 ^ keyFull[KEY_FULL_INDEX(2, UINT32_BYTE2(t2))];
        t1 = t1 ^ keyFull[KEY_FULL_INDEX(3, UINT32_BYTE3(t2))];

        t2 = keyExpanded[(roundBase + 0) | 0];
        t2 = (t2 + t0) | 0;
        t2 = (t2 + t1) | 0;
        t2 = t2 ^ r2;
        t2 = ROTATE_RIGHT(t2, 1);
        r2 = t2;

        t3 = keyExpanded[(roundBase + 1) | 0];
        t3 = (t3 + t0) | 0;
        t3 = (t3 + (t1 << 1)) | 0;
        t3 = t3 ^ ROTATE_LEFT(r3, 1);
        r3 = t3;

        if (oddRound) {

            swapWords();

        }

        round = (round + 1) | 0;

    } while (round != 16);

    r0 = r0 ^ keyExpanded[6];
    r1 = r1 ^ keyExpanded[7];
    r2 = r2 ^ keyExpanded[4];
    r3 = r3 ^ keyExpanded[5];

    textCipher[ 0] = UINT32_BYTE0(r2);
    textCipher[ 1] = UINT32_BYTE1(r2);
    textCipher[ 2] = UINT32_BYTE2(r2);
    textCipher[ 3] = UINT32_BYTE3(r2);

    textCipher[ 4] = UINT32_BYTE0(r3);
    textCipher[ 5] = UINT32_BYTE1(r3);
    textCipher[ 6] = UINT32_BYTE2(r3);
    textCipher[ 7] = UINT32_BYTE3(r3);

    textCipher[ 8] = UINT32_BYTE0(r0);
    textCipher[ 9] = UINT32_BYTE1(r0);
    textCipher[10] = UINT32_BYTE2(r0);
    textCipher[11] = UINT32_BYTE3(r0);

    textCipher[12] = UINT32_BYTE0(r1);
    textCipher[13] = UINT32_BYTE1(r1);
    textCipher[14] = UINT32_BYTE2(r1);
    textCipher[15] = UINT32_BYTE3(r1);

};

const COMMON_DECRYPT = (keyExpanded, keyFull, textCipher, textPlain) => {

    let r0 = 0;
    let r1 = 0;
    let r2 = 0;
    let r3 = 0;

    let t0 = 0;
    let t1 = 0;
    let t2 = 0;
    let t3 = 0;

    const swapWords = () => {

        t0 = r0;
        t1 = r1;
        t2 = r2;
        t3 = r3;

        r0 = t2;
        r1 = t3;
        r2 = t0;
        r3 = t1;

    };

    r0 = keyExpanded[4] ^ UINT32_FROM_UINT8_GROUP(
        textCipher[ 3],
        textCipher[ 2],
        textCipher[ 1],
        textCipher[ 0],
    );

    r1 = keyExpanded[5] ^ UINT32_FROM_UINT8_GROUP(
        textCipher[ 7],
        textCipher[ 6],
        textCipher[ 5],
        textCipher[ 4],
    );

    r2 = keyExpanded[6] ^ UINT32_FROM_UINT8_GROUP(
        textCipher[11],
        textCipher[10],
        textCipher[ 9],
        textCipher[ 8],
    );

    r3 = keyExpanded[7] ^ UINT32_FROM_UINT8_GROUP(
        textCipher[15],
        textCipher[14],
        textCipher[13],
        textCipher[12],
    );

    let round = 16;

    do {

        round = (round - 1) | 0;

        const roundBase = ((round << 1) + 8) | 0;
        const evenRound = (round & 1) === 0;

        if (evenRound) {

            swapWords();

        }

        t0 = 0;
        t0 = t0 ^ keyFull[KEY_FULL_INDEX(0, UINT32_BYTE0(r0))];
        t0 = t0 ^ keyFull[KEY_FULL_INDEX(1, UINT32_BYTE1(r0))];
        t0 = t0 ^ keyFull[KEY_FULL_INDEX(2, UINT32_BYTE2(r0))];
        t0 = t0 ^ keyFull[KEY_FULL_INDEX(3, UINT32_BYTE3(r0))];

        t2 = ROTATE_LEFT(r1, 8);

        t1 = 0;
        t1 = t1 ^ keyFull[KEY_FULL_INDEX(0, UINT32_BYTE0(t2))];
        t1 = t1 ^ keyFull[KEY_FULL_INDEX(1, UINT32_BYTE1(t2))];
        t1 = t1 ^ keyFull[KEY_FULL_INDEX(2, UINT32_BYTE2(t2))];
        t1 = t1 ^ keyFull[KEY_FULL_INDEX(3, UINT32_BYTE3(t2))];

        t2 = keyExpanded[(roundBase + 0) | 0];
        t2 = (t2 + t1) | 0;
        t2 = (t2 + t0) | 0;
        t2 = t2 ^ ROTATE_LEFT(r2, 1);
        r2 = t2;

        t3 = keyExpanded[(roundBase + 1) | 0];
        t3 = (t3 + (t1 << 1)) | 0;
        t3 = (t3 + t0) | 0;
        t3 = t3 ^ r3;
        t3 = ROTATE_RIGHT(t3, 1);
        r3 = t3;

        if (evenRound) {

            swapWords();

        }

    } while (round != 0);

    r0 = r0 ^ keyExpanded[2];
    r1 = r1 ^ keyExpanded[3];
    r2 = r2 ^ keyExpanded[0];
    r3 = r3 ^ keyExpanded[1];

    textPlain[ 0] = UINT32_BYTE0(r2);
    textPlain[ 1] = UINT32_BYTE1(r2);
    textPlain[ 2] = UINT32_BYTE2(r2);
    textPlain[ 3] = UINT32_BYTE3(r2);

    textPlain[ 4] = UINT32_BYTE0(r3);
    textPlain[ 5] = UINT32_BYTE1(r3);
    textPlain[ 6] = UINT32_BYTE2(r3);
    textPlain[ 7] = UINT32_BYTE3(r3);

    textPlain[ 8] = UINT32_BYTE0(r0);
    textPlain[ 9] = UINT32_BYTE1(r0);
    textPlain[10] = UINT32_BYTE2(r0);
    textPlain[11] = UINT32_BYTE3(r0);

    textPlain[12] = UINT32_BYTE0(r1);
    textPlain[13] = UINT32_BYTE1(r1);
    textPlain[14] = UINT32_BYTE2(r1);
    textPlain[15] = UINT32_BYTE3(r1);

};

////////////////////////////////////////////////////////////////////////
// ENCRYPTION AND DECRYPTION GIVEN SPECIFIC KEY SIZES                 //
////////////////////////////////////////////////////////////////////////

export const encrypt128 = (key, textPlain, textCipher) => {

    COMMON_VECTOR_SPLITTING(
        TWOFISH_BITS128_K,
        key,
        VECTOR_ME,
        VECTOR_MO,
    );

    KEY_EXPANSION_BITS128(
        VECTOR_ME,
        VECTOR_MO,
        KEY_EXPANDED,
    );

    COMMON_VECTOR_JOINING(
        TWOFISH_BITS128_K,
        VECTOR_ME,
        VECTOR_MO,
        VECTOR_M,
    );

    KEY_DEPENDENT_SBOX(
        TWOFISH_BITS128_K,
        VECTOR_M,
        VECTOR_S,
    );

    KEY_FULL_BITS128(
        VECTOR_S,
        KEY_FULL,
    );

    COMMON_ENCRYPT(
        KEY_EXPANDED,
        KEY_FULL,
        textPlain,
        textCipher,
    );

};

export const decrypt128 = (key, textCipher, textPlain) => {

    COMMON_VECTOR_SPLITTING(
        TWOFISH_BITS128_K,
        key,
        VECTOR_ME,
        VECTOR_MO,
    );

    KEY_EXPANSION_BITS128(
        VECTOR_ME,
        VECTOR_MO,
        KEY_EXPANDED,
    );

    COMMON_VECTOR_JOINING(
        TWOFISH_BITS128_K,
        VECTOR_ME,
        VECTOR_MO,
        VECTOR_M,
    );

    KEY_DEPENDENT_SBOX(
        TWOFISH_BITS128_K,
        VECTOR_M,
        VECTOR_S,
    );

    KEY_FULL_BITS128(
        VECTOR_S,
        KEY_FULL,
    );

    COMMON_DECRYPT(
        KEY_EXPANDED,
        KEY_FULL,
        textCipher,
        textPlain,
    );

};

export const encrypt128Chain = (key, textPlain, textCipher) => {

    const LENGTH_KEY = 16; // octets, also known as "bytes".
    const LENGTH_BLOCK = 16; // octets, also known as "bytes".

    const initialVector = new Uint8Array(LENGTH_KEY);
    const nextVector = () => {

        let index = 0;
        while (index < LENGTH_KEY) {

            initialVector[index] = (initialVector[index] + 1) & 0xFF;
            if (initialVector[index] !== 0) {

                break;

            }

            index = (index + 1) | 0;

        }

    };

    const keyBlock = new Uint8Array(LENGTH_KEY);

    const limitA = textPlain.length;
    const limitB = textCipher.length;

    let offsetA = 0;
    let offsetB = LENGTH_BLOCK;
    while (offsetB <= limitA && offsetB <= limitB) {

        const chunkPlain = textPlain.subarray(offsetA, offsetB);
        const chunkCipher = textCipher.subarray(offsetA, offsetB);

        let index = 0;
        while (index < LENGTH_KEY) {

            keyBlock[index] = initialVector[index] ^ key[index];
            index = (index + 1) | 0;

        }

        encrypt128(keyBlock, chunkPlain, chunkCipher);
        nextVector();

        offsetA = (offsetA + LENGTH_BLOCK) | 0;
        offsetB = (offsetB + LENGTH_BLOCK) | 0;

    }

};

export const decrypt128Chain = (key, textCipher, textPlain) => {

    const LENGTH_KEY = 16; // octets, also known as "bytes".
    const LENGTH_BLOCK = 16; // octets, also known as "bytes".

    const initialVector = new Uint8Array(LENGTH_KEY);
    const nextVector = () => {

        let index = 0;
        while (index < LENGTH_KEY) {

            initialVector[index] = (initialVector[index] + 1) & 0xFF;
            if (initialVector[index] !== 0) {

                break;

            }

            index = (index + 1) | 0;

        }

    };

    const keyBlock = new Uint8Array(LENGTH_KEY);

    const limitA = textCipher.length;
    const limitB = textPlain.length;

    let offsetA = 0;
    let offsetB = LENGTH_BLOCK;
    while (offsetB <= limitA && offsetB <= limitB) {

        const chunkCipher = textCipher.subarray(offsetA, offsetB);
        const chunkPlain = textPlain.subarray(offsetA, offsetB);

        let index = 0;
        while (index < LENGTH_KEY) {

            keyBlock[index] = initialVector[index] ^ key[index];
            index = (index + 1) | 0;

        }

        decrypt128(keyBlock, chunkCipher, chunkPlain);
        nextVector();

        offsetA = (offsetA + LENGTH_BLOCK) | 0;
        offsetB = (offsetB + LENGTH_BLOCK) | 0;

    }

};

const TwofishCryptography = Object.freeze({
    encrypt128,
    decrypt128,
    encrypt128Chain,
    decrypt128Chain,
});

export default TwofishCryptography;
