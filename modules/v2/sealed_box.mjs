// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

// Hybrid sealed-box (SPEC-v0.2-draft § 9.4).
//
// Asymmetric one-shot encryption to a recipient holding a paired
// (X25519, ML-KEM-768) keypair. Combines ephemeral X25519 +
// ML-KEM-768 encapsulation, derives a ChaCha20-Poly1305 key via HKDF
// over BOTH shared secrets. Resists harvest-now-decrypt-later
// quantum attacks: breaking only one of the primitives leaves the
// other intact.
//
// Used to encrypt INTRODUCE1's inner payload to a hidden service so
// the introduction point cannot read the rendezvous cookie or the
// embedded handshake material.

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import {
    sharedSecret,
    kdf,
    generateNonce,
    aeadEncrypt,
    aeadDecrypt,
    generateOnion,
} from '../crypto/onion.mjs';
import { zeroize } from '../crypto/zeroize.mjs';

const SEALED_BOX_INFO = 'anon-layer/v2/sealed-box';

export const LEN_SEAL_X25519_PK = 32;
export const LEN_SEAL_MLKEM_CT = 1088;
export const LEN_SEAL_NONCE = 12;
export const LEN_SEAL_TAG = 16;
export const LEN_SEAL_ENVELOPE_OVERHEAD = LEN_SEAL_X25519_PK + LEN_SEAL_MLKEM_CT
    + LEN_SEAL_NONCE + LEN_SEAL_TAG; // 1148

const OFFSET_EPHEMERAL_X = 0;
const OFFSET_MLKEM_CT    = LEN_SEAL_X25519_PK;
const OFFSET_NONCE       = OFFSET_MLKEM_CT + LEN_SEAL_MLKEM_CT;
const OFFSET_CIPHERTEXT  = OFFSET_NONCE + LEN_SEAL_NONCE;

const concat = (...arrays) => {

    let total = 0;
    for (const a of arrays) total += a.length;
    const out = new Uint8Array(total);
    let o = 0;
    for (const a of arrays) { out.set(a, o); o += a.length; }
    return out;

};

// Seal `plaintext` to the recipient's hybrid public-key pair.
// Returns the envelope bytes:
//   E (32) || ct (1088) || nonce (12) || ciphertext (plaintext.length) || tag (16)
//
// Throws on programmer errors (wrong-sized public keys).
export const seal = ({ plaintext, recipientX25519Pk, recipientMlkemPk }) => {

    if (recipientX25519Pk.length !== LEN_SEAL_X25519_PK) {

        throw new Error('recipientX25519Pk must be 32 bytes');

    }
    if (recipientMlkemPk.length !== 1184) {

        throw new Error('recipientMlkemPk must be 1184 bytes');

    }

    const ephemeral = generateOnion();
    const E = ephemeral.onionPk;
    const eSk = ephemeral.onionSk;

    const shared_x = sharedSecret(eSk, recipientX25519Pk);
    if (shared_x === null) {

        zeroize(eSk);
        throw new Error('recipientX25519Pk is a low-order point');

    }

    let kemResult;
    try {

        kemResult = ml_kem768.encapsulate(recipientMlkemPk);

    } catch (err) {

        zeroize(eSk);
        zeroize(shared_x);
        throw err;

    }
    const ct = kemResult.cipherText;
    const shared_pq = kemResult.sharedSecret;

    const ikm = concat(shared_x, shared_pq);
    const K = kdf(ikm, SEALED_BOX_INFO, 32);

    const nonce = generateNonce();
    const { ciphertext, tag } = aeadEncrypt(K, nonce, new Uint8Array(0), plaintext);

    // Wipe ephemerals.
    zeroize(eSk);
    zeroize(shared_x);
    zeroize(shared_pq);
    zeroize(ikm);
    zeroize(K);

    const envelope = new Uint8Array(LEN_SEAL_ENVELOPE_OVERHEAD + ciphertext.length);
    envelope.set(E, OFFSET_EPHEMERAL_X);
    envelope.set(ct, OFFSET_MLKEM_CT);
    envelope.set(nonce, OFFSET_NONCE);
    envelope.set(ciphertext, OFFSET_CIPHERTEXT);
    envelope.set(tag, OFFSET_CIPHERTEXT + ciphertext.length);
    return envelope;

};

// Unseal an envelope using the recipient's secret-key pair. Returns
// the plaintext on success, or null on any failure (silent-drop
// discipline — wrong size, AEAD tag mismatch, low-order point in E,
// ML-KEM decapsulation error).
export const unseal = ({ envelope, recipientX25519Sk, recipientMlkemSk }) => {

    if (!envelope || envelope.length < LEN_SEAL_ENVELOPE_OVERHEAD) return null;
    if (recipientX25519Sk.length !== 32) return null;

    const E         = envelope.subarray(OFFSET_EPHEMERAL_X, OFFSET_MLKEM_CT);
    const ct        = envelope.subarray(OFFSET_MLKEM_CT, OFFSET_NONCE);
    const nonce     = envelope.subarray(OFFSET_NONCE, OFFSET_CIPHERTEXT);
    const ctxAndTag = envelope.subarray(OFFSET_CIPHERTEXT);
    if (ctxAndTag.length < LEN_SEAL_TAG) return null;
    const ciphertext = ctxAndTag.subarray(0, ctxAndTag.length - LEN_SEAL_TAG);
    const tag        = ctxAndTag.subarray(ctxAndTag.length - LEN_SEAL_TAG);

    const shared_x = sharedSecret(recipientX25519Sk, E);
    if (shared_x === null) return null;

    let shared_pq;
    try {

        shared_pq = ml_kem768.decapsulate(ct, recipientMlkemSk);

    } catch {

        zeroize(shared_x);
        return null;

    }
    if (!shared_pq || shared_pq.length !== 32) {

        zeroize(shared_x);
        return null;

    }

    const ikm = concat(shared_x, shared_pq);
    const K = kdf(ikm, SEALED_BOX_INFO, 32);

    const plaintext = aeadDecrypt(K, nonce, new Uint8Array(0), ciphertext, tag);

    zeroize(shared_x);
    zeroize(shared_pq);
    zeroize(ikm);
    zeroize(K);

    return plaintext; // null on AEAD failure

};
