// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

// Hybrid X25519 + ML-KEM-768 ntor handshake for SPEC-v0.2-draft § 3.7.
//
// The hybrid construction folds BOTH a classical (X25519) and a post-
// quantum (ML-KEM-768) shared secret into KEY_SEED. Compromising the
// session requires breaking both primitives — defends against
// harvest-now-decrypt-later quantum attacks on circuit traffic.
//
// This module covers the cryptographic operations only: it produces
// and consumes the assembled handshake byte strings (1216 bytes for
// CREATE-side, 1152 bytes for CREATED-side). Multi-cell fragmentation
// of these byte strings is the responsibility of modules/v2/fragment.mjs.

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import { sharedSecret, kdf } from '../crypto/onion.mjs';
import { generateOnion } from '../crypto/onion.mjs';

// ----- Protocol constants -----

const PROTOID = new TextEncoder().encode('anon-layer-pq-ntor-v1');
const KEY_SEED_INFO = 'anon-layer/v2/pq-handshake-extract';
const AUTH_INFO = 'anon-layer/v2/pq-handshake-auth';
const HOP_KEYS_INFO = 'anon-layer/v2/hop-keys';
const SERVER_TAG = new TextEncoder().encode('Server');

// ML-KEM-768 byte sizes (FIPS 203 § 8).
export const MLKEM_PK_BYTES = 1184;
export const MLKEM_SK_BYTES = 2400;
export const MLKEM_CT_BYTES = 1088;

// Assembled handshake message sizes.
export const CREATE_MSG_BYTES = 32 + MLKEM_PK_BYTES;          // 1216
export const CREATED_MSG_BYTES = 32 + MLKEM_CT_BYTES + 32;    // 1152

const KEY_SEED_BYTES = 32;
const AUTH_BYTES = 32;
const HOP_KEYS_TOTAL = 32 * 4; // Kf, Kb, Kdf, Kdb

// ----- Helpers -----

const concat = (...arrays) => {

    let total = 0;
    for (const a of arrays) total += a.length;
    const out = new Uint8Array(total);
    let o = 0;
    for (const a of arrays) { out.set(a, o); o += a.length; }
    return out;

};

const constantTimeEqual = (a, b) => {

    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
    return diff === 0;

};

// ----- Client side -----

// Generate ephemeral state for a new handshake. Returns:
//   { x, X, kemSk, kemPk, createMsg }
// where createMsg is the 1216-byte assembled bytes to send to the relay.
export const clientInit = () => {

    const xPair = generateOnion();
    const kPair = ml_kem768.keygen();
    const createMsg = concat(xPair.onionPk, kPair.publicKey);
    return {
        x: xPair.onionSk,
        X: xPair.onionPk,
        kemSk: kPair.secretKey,
        kemPk: kPair.publicKey,
        createMsg,
    };

};

// Parse the relay's response (assembled CREATED bytes: Y || ct || AUTH)
// and complete the handshake. Returns the 32-byte KEY_SEED on success,
// or null on any failure (AUTH mismatch, wrong-sized inputs, KEM
// decapsulation error, low-order X25519 point).
export const clientFinish = ({ ntorState, B_pk, ID_R, createdMsg }) => {

    if (!createdMsg || createdMsg.length !== CREATED_MSG_BYTES) return null;
    if (B_pk.length !== 32) return null;
    if (ID_R.length !== 32) return null;

    const Y    = createdMsg.subarray(0, 32);
    const ct   = createdMsg.subarray(32, 32 + MLKEM_CT_BYTES);
    const AUTH = createdMsg.subarray(32 + MLKEM_CT_BYTES);

    // Decapsulate the PQ shared secret.
    let shared_pq;
    try {

        shared_pq = ml_kem768.decapsulate(ct, ntorState.kemSk);

    } catch {

        return null;

    }
    if (!shared_pq || shared_pq.length !== 32) return null;

    // Classical shared secrets.
    const shared_x_y = sharedSecret(ntorState.x, Y);
    const shared_b_x = sharedSecret(ntorState.x, B_pk);
    if (shared_x_y === null || shared_b_x === null) return null;

    const secret_input = concat(
        shared_x_y, shared_b_x, shared_pq,
        ID_R, B_pk, ntorState.X, ntorState.kemPk, Y, ct, PROTOID,
    );
    const KEY_SEED = kdf(secret_input, KEY_SEED_INFO, KEY_SEED_BYTES);

    const auth_input = concat(
        secret_input,
        ID_R, B_pk, Y, ct, PROTOID, SERVER_TAG,
    );
    const AUTH_check = kdf(auth_input, AUTH_INFO, AUTH_BYTES);

    if (!constantTimeEqual(AUTH, AUTH_check)) return null;

    return KEY_SEED;

};

// ----- Relay side -----

// Process the client's assembled CREATE message (1216 bytes: X || K_pk)
// against the relay's identity-onion key and fingerprint. Returns:
//   { createdMsg, KEY_SEED } | null
// where createdMsg is the 1152-byte response (Y || ct || AUTH).
export const relayResponse = ({ createMsg, B_sk, B_pk, ID_R }) => {

    if (!createMsg || createMsg.length !== CREATE_MSG_BYTES) return null;
    if (B_sk.length !== 32) return null;
    if (B_pk.length !== 32) return null;
    if (ID_R.length !== 32) return null;

    const X    = createMsg.subarray(0, 32);
    const K_pk = createMsg.subarray(32);

    // PQ encapsulation against the client's K_pk.
    let kemResult;
    try {

        kemResult = ml_kem768.encapsulate(K_pk);

    } catch {

        return null;

    }
    const ct = kemResult.cipherText;
    const shared_pq = kemResult.sharedSecret;
    if (!ct || ct.length !== MLKEM_CT_BYTES) return null;
    if (!shared_pq || shared_pq.length !== 32) return null;

    // Classical: relay generates its own ephemeral.
    const ephemeral = generateOnion();
    const y = ephemeral.onionSk;
    const Y = ephemeral.onionPk;

    const shared_x_y = sharedSecret(y, X);
    const shared_b_x = sharedSecret(B_sk, X);
    if (shared_x_y === null || shared_b_x === null) return null;

    const secret_input = concat(
        shared_x_y, shared_b_x, shared_pq,
        ID_R, B_pk, X, K_pk, Y, ct, PROTOID,
    );
    const KEY_SEED = kdf(secret_input, KEY_SEED_INFO, KEY_SEED_BYTES);

    const auth_input = concat(
        secret_input,
        ID_R, B_pk, Y, ct, PROTOID, SERVER_TAG,
    );
    const AUTH = kdf(auth_input, AUTH_INFO, AUTH_BYTES);

    const createdMsg = concat(Y, ct, AUTH);
    return { createdMsg, KEY_SEED };

};

// ----- Key derivation -----

export const deriveHopKeys = (KEY_SEED) => {

    if (KEY_SEED.length !== KEY_SEED_BYTES) throw new Error('KEY_SEED must be 32 bytes');
    const material = kdf(KEY_SEED, HOP_KEYS_INFO, HOP_KEYS_TOTAL);
    return {
        Kf:  new Uint8Array(material.subarray(0, 32)),
        Kb:  new Uint8Array(material.subarray(32, 64)),
        Kdf: new Uint8Array(material.subarray(64, 96)),
        Kdb: new Uint8Array(material.subarray(96, 128)),
    };

};

export const NTOR_KEY_SEED_BYTES = KEY_SEED_BYTES;
export const NTOR_AUTH_BYTES = AUTH_BYTES;
