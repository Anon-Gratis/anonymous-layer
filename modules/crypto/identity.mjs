import { ed25519 } from '@noble/curves/ed25519.js';

import { fingerprint } from './fingerprint.mjs';

// SPEC § 4.1: Ed25519 long-term identity keypair.
// Returns { idSk: Uint8Array(32), idPk: Uint8Array(32) }.
// The secret key is the 32-byte seed; the public key is derived.
export const generateIdentity = () => {

    const idSk = ed25519.utils.randomSecretKey();
    const idPk = ed25519.getPublicKey(idSk);
    return { idSk, idPk };

};

// Derive the public key from a stored secret seed.
export const publicFromSecret = (idSk) => ed25519.getPublicKey(idSk);

// SPEC § 3.6: Ed25519 sign / verify with deterministic nonce (RFC 8032).
// Constant-time by the underlying implementation.
export const sign = (message, idSk) => ed25519.sign(message, idSk);

export const verify = (signature, message, idPk) => {

    // Catch malformed inputs from any source: noble throws on
    // wrong-sized buffers; we want the silent-drop discipline of
    // SPEC § 9 instead, so we return false.
    try {

        return ed25519.verify(signature, message, idPk);

    } catch {

        return false;

    }

};

// Convenience: identity fingerprint of a given identity public key.
export const identityFingerprint = (idPk) => fingerprint(idPk);
