import { x25519 } from '@noble/curves/ed25519.js';
import { hkdfSync, randomFillSync, createCipheriv, createDecipheriv, timingSafeEqual } from 'node:crypto';

// SPEC § 4.2: X25519 onion keypair.
// Returns { onionSk: Uint8Array(32), onionPk: Uint8Array(32) }.
export const generateOnion = () => {

    const onionSk = x25519.utils.randomSecretKey();
    const onionPk = x25519.getPublicKey(onionSk);
    return { onionSk, onionPk };

};

// SPEC § 3.2: X25519 key agreement.
// Returns the 32-byte shared secret, or null on small-subgroup attack
// (all-zero output, per RFC 7748 § 5 and SPEC § 3.2).
export const sharedSecret = (sk, peerPk) => {

    let shared;
    try {

        shared = x25519.getSharedSecret(sk, peerPk);

    } catch {

        return null;

    }

    if (shared.length !== 32) {

        return null;

    }

    // Constant-time all-zero check against the 32-byte zero vector.
    const zero = new Uint8Array(32);
    if (timingSafeEqual(shared, zero)) {

        return null;

    }

    return shared;

};

// SPEC § 3.5: HKDF-SHA-256 extract+expand.
// Returns a `length`-byte Uint8Array.
export const kdf = (ikm, info, length) => {

    // Empty salt per RFC 5869: HKDF-Extract(salt=zero, IKM=ikm).
    const salt = new Uint8Array(0);
    const infoBytes = (typeof info === 'string')
        ? new TextEncoder().encode(info)
        : info;
    return new Uint8Array(hkdfSync('sha256', ikm, salt, infoBytes, length));

};

// SPEC § 3.5 standardised info string for v0.1 packet AEAD key derivation.
const INFO_AEAD = 'anon-layer/v1/aead';

// SPEC § 5.3 step 4: derive the per-packet AEAD key from a shared secret.
export const deriveAeadKey = (shared) => kdf(shared, INFO_AEAD, 32);

// SPEC § 5.3 step 5: 12-byte random nonce.
export const generateNonce = () => {

    const nonce = new Uint8Array(12);
    randomFillSync(nonce);
    return nonce;

};

// SPEC § 3.3: ChaCha20-Poly1305 AEAD encrypt.
// Returns { ciphertext: Uint8Array, tag: Uint8Array(16) } on success.
// Throws only on programmer error (wrong-sized inputs); legitimate
// AEAD failures only occur on decrypt.
export const aeadEncrypt = (key, nonce, aad, plaintext) => {

    if (key.length !== 32) throw new Error('aead key must be 32 bytes');
    if (nonce.length !== 12) throw new Error('aead nonce must be 12 bytes');

    const cipher = createCipheriv('chacha20-poly1305', key, nonce, {
        authTagLength: 16,
    });
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    // Copy to fresh Uint8Arrays rather than aliasing the underlying
    // Buffer. Node's Buffer.getAuthTag() and small Buffer.concat()
    // results may sit in the shared 8 KB Buffer pool; aliasing them
    // exposes pool memory to callers that retain the returned slice.
    // The copy is ~one memcpy per encrypt — negligible next to AEAD.
    return {
        ciphertext: Uint8Array.from(ciphertext),
        tag: Uint8Array.from(tag),
    };

};

// SPEC § 3.3: ChaCha20-Poly1305 AEAD decrypt.
// Returns the plaintext on success, or null on any failure (silent-drop
// discipline per SPEC § 9). All inputs are treated as untrusted.
export const aeadDecrypt = (key, nonce, aad, ciphertext, tag) => {

    if (key.length !== 32) return null;
    if (nonce.length !== 12) return null;
    if (tag.length !== 16) return null;

    let decipher;
    try {

        decipher = createDecipheriv('chacha20-poly1305', key, nonce, {
            authTagLength: 16,
        });
        decipher.setAAD(aad);
        decipher.setAuthTag(tag);
        const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        // Copy to a fresh Uint8Array — see aeadEncrypt for rationale.
        return Uint8Array.from(plaintext);

    } catch {

        return null;

    }

};
