import { expect } from 'chai';

import { blake2b256, fingerprint } from './fingerprint.mjs';
import {
    generateIdentity,
    publicFromSecret,
    sign,
    verify,
    identityFingerprint,
} from './identity.mjs';
import {
    generateOnion,
    sharedSecret,
    kdf,
    deriveAeadKey,
    generateNonce,
    aeadEncrypt,
    aeadDecrypt,
} from './onion.mjs';
import {
    buildCertificate,
    verifyCertificate,
    CERT_BYTES,
} from './cert.mjs';

describe('crypto/fingerprint', () => {

    it('produces 32-byte Blake2b-256 output', () => {

        const h = blake2b256(new Uint8Array([0x01, 0x02, 0x03]));
        expect(h).to.be.instanceOf(Uint8Array);
        expect(h.length).to.equal(32);

    });

    it('is the RFC 7693 known-answer for the empty input', () => {

        // Blake2b-256("") known answer.
        // Reference: https://www.blake2.net/ test vectors with nn=32.
        const h = blake2b256(new Uint8Array(0));
        const expected = Buffer.from(
            '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8',
            'hex',
        );
        expect(Buffer.from(h).equals(expected)).to.equal(true);

    });

    it('fingerprint of an identity pubkey is 32 bytes', () => {

        const { idPk } = generateIdentity();
        const fp = fingerprint(idPk);
        expect(fp.length).to.equal(32);

    });

});

describe('crypto/identity', () => {

    it('generates 32-byte Ed25519 keypair', () => {

        const { idSk, idPk } = generateIdentity();
        expect(idSk.length).to.equal(32);
        expect(idPk.length).to.equal(32);

    });

    it('derives the same public key deterministically from the secret seed', () => {

        const { idSk, idPk } = generateIdentity();
        const idPk2 = publicFromSecret(idSk);
        expect(Buffer.from(idPk).equals(Buffer.from(idPk2))).to.equal(true);

    });

    it('signs and verifies correctly (RFC 8032)', () => {

        const { idSk, idPk } = generateIdentity();
        const message = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);
        const signature = sign(message, idSk);
        expect(signature.length).to.equal(64);
        expect(verify(signature, message, idPk)).to.equal(true);

    });

    it('rejects a tampered message', () => {

        const { idSk, idPk } = generateIdentity();
        const message = new Uint8Array([1, 2, 3, 4, 5]);
        const signature = sign(message, idSk);
        const tampered = new Uint8Array([1, 2, 3, 4, 6]);
        expect(verify(signature, tampered, idPk)).to.equal(false);

    });

    it('rejects a signature from a different key', () => {

        const a = generateIdentity();
        const b = generateIdentity();
        const message = new Uint8Array([9, 9, 9]);
        const sigA = sign(message, a.idSk);
        expect(verify(sigA, message, b.idPk)).to.equal(false);

    });

    it('returns false (not throws) on malformed signature input', () => {

        const { idPk } = generateIdentity();
        expect(verify(new Uint8Array(0), new Uint8Array(0), idPk)).to.equal(false);
        expect(verify(new Uint8Array(63), new Uint8Array(0), idPk)).to.equal(false);

    });

    it('identityFingerprint equals fingerprint(idPk)', () => {

        const { idPk } = generateIdentity();
        const a = identityFingerprint(idPk);
        const b = fingerprint(idPk);
        expect(Buffer.from(a).equals(Buffer.from(b))).to.equal(true);

    });

});

describe('crypto/onion', () => {

    it('generates 32-byte X25519 keypair', () => {

        const { onionSk, onionPk } = generateOnion();
        expect(onionSk.length).to.equal(32);
        expect(onionPk.length).to.equal(32);

    });

    it('produces a 32-byte shared secret in both directions', () => {

        const a = generateOnion();
        const b = generateOnion();
        const sa = sharedSecret(a.onionSk, b.onionPk);
        const sb = sharedSecret(b.onionSk, a.onionPk);
        expect(sa).to.not.equal(null);
        expect(sb).to.not.equal(null);
        expect(Buffer.from(sa).equals(Buffer.from(sb))).to.equal(true);

    });

    it('returns null on small-subgroup attack (all-zero shared)', () => {

        const a = generateOnion();
        // Curve25519 low-order point that produces all-zero shared:
        // 32 bytes of zero is a known low-order point.
        const zeroPk = new Uint8Array(32);
        const result = sharedSecret(a.onionSk, zeroPk);
        expect(result).to.equal(null);

    });

    it('returns null on malformed peer pubkey length', () => {

        const a = generateOnion();
        expect(sharedSecret(a.onionSk, new Uint8Array(31))).to.equal(null);
        expect(sharedSecret(a.onionSk, new Uint8Array(33))).to.equal(null);

    });

    it('HKDF derives requested-length output', () => {

        const ikm = new Uint8Array(32);
        ikm.fill(0xAB);
        const out16 = kdf(ikm, 'anon-layer/v1/test', 16);
        const out32 = kdf(ikm, 'anon-layer/v1/test', 32);
        const out64 = kdf(ikm, 'anon-layer/v1/test', 64);
        expect(out16.length).to.equal(16);
        expect(out32.length).to.equal(32);
        expect(out64.length).to.equal(64);

    });

    it('HKDF is deterministic for fixed (ikm, info)', () => {

        const ikm = new Uint8Array(32);
        ikm.fill(0x42);
        const a = kdf(ikm, 'anon-layer/v1/test', 32);
        const b = kdf(ikm, 'anon-layer/v1/test', 32);
        expect(Buffer.from(a).equals(Buffer.from(b))).to.equal(true);

    });

    it('HKDF differentiates by info string', () => {

        const ikm = new Uint8Array(32);
        ikm.fill(0x42);
        const a = kdf(ikm, 'info-a', 32);
        const b = kdf(ikm, 'info-b', 32);
        expect(Buffer.from(a).equals(Buffer.from(b))).to.equal(false);

    });

    it('deriveAeadKey returns 32 bytes', () => {

        const a = generateOnion();
        const b = generateOnion();
        const shared = sharedSecret(a.onionSk, b.onionPk);
        const k = deriveAeadKey(shared);
        expect(k.length).to.equal(32);

    });

    it('generateNonce returns 12 fresh bytes', () => {

        const a = generateNonce();
        const b = generateNonce();
        expect(a.length).to.equal(12);
        expect(b.length).to.equal(12);
        // Birthday: two RAND(12) values are essentially never equal.
        expect(Buffer.from(a).equals(Buffer.from(b))).to.equal(false);

    });

    it('AEAD round-trips plaintext correctly', () => {

        const key = new Uint8Array(32);
        key.fill(0x11);
        const nonce = new Uint8Array(12);
        nonce.fill(0x22);
        const aad = new Uint8Array([0x01, 0x02, 0x03]);
        const plaintext = new Uint8Array([0x99, 0x88, 0x77, 0x66, 0x55]);

        const { ciphertext, tag } = aeadEncrypt(key, nonce, aad, plaintext);
        expect(ciphertext.length).to.equal(plaintext.length);
        expect(tag.length).to.equal(16);

        const recovered = aeadDecrypt(key, nonce, aad, ciphertext, tag);
        expect(recovered).to.not.equal(null);
        expect(Buffer.from(recovered).equals(Buffer.from(plaintext))).to.equal(true);

    });

    it('AEAD decrypt returns null on tampered ciphertext', () => {

        const key = new Uint8Array(32);
        key.fill(0x11);
        const nonce = new Uint8Array(12);
        nonce.fill(0x22);
        const aad = new Uint8Array(0);
        const plaintext = new Uint8Array([0x01, 0x02, 0x03, 0x04]);

        const { ciphertext, tag } = aeadEncrypt(key, nonce, aad, plaintext);
        const tampered = new Uint8Array(ciphertext);
        tampered[0] ^= 0x01;
        expect(aeadDecrypt(key, nonce, aad, tampered, tag)).to.equal(null);

    });

    it('AEAD decrypt returns null on tampered AAD', () => {

        const key = new Uint8Array(32);
        key.fill(0x11);
        const nonce = new Uint8Array(12);
        nonce.fill(0x22);
        const aad = new Uint8Array([0x01, 0x02, 0x03]);
        const plaintext = new Uint8Array([0x01, 0x02, 0x03, 0x04]);

        const { ciphertext, tag } = aeadEncrypt(key, nonce, aad, plaintext);
        const tamperedAad = new Uint8Array([0x01, 0x02, 0xFF]);
        expect(aeadDecrypt(key, nonce, tamperedAad, ciphertext, tag)).to.equal(null);

    });

    it('AEAD decrypt returns null on wrong key', () => {

        const k1 = new Uint8Array(32); k1.fill(0x11);
        const k2 = new Uint8Array(32); k2.fill(0x22);
        const nonce = new Uint8Array(12);
        const aad = new Uint8Array(0);
        const plaintext = new Uint8Array([0xAA]);

        const { ciphertext, tag } = aeadEncrypt(k1, nonce, aad, plaintext);
        expect(aeadDecrypt(k2, nonce, aad, ciphertext, tag)).to.equal(null);

    });

    it('AEAD decrypt returns null on wrong-length inputs', () => {

        const k = new Uint8Array(32);
        const n = new Uint8Array(12);
        const t = new Uint8Array(16);
        expect(aeadDecrypt(new Uint8Array(31), n, new Uint8Array(0), new Uint8Array(0), t)).to.equal(null);
        expect(aeadDecrypt(k, new Uint8Array(11), new Uint8Array(0), new Uint8Array(0), t)).to.equal(null);
        expect(aeadDecrypt(k, n, new Uint8Array(0), new Uint8Array(0), new Uint8Array(15))).to.equal(null);

    });

});

describe('crypto/cert', () => {

    it('builds a 105-byte certificate', () => {

        const { idSk } = generateIdentity();
        const { onionPk } = generateOnion();
        const cert = buildCertificate({
            idSk,
            onionPk,
            expirySeconds: Math.floor(Date.now() / 1000) + 86400,
        });
        expect(cert.length).to.equal(CERT_BYTES);
        expect(cert.length).to.equal(105);

    });

    it('verifies a freshly-built certificate', () => {

        const { idSk, idPk } = generateIdentity();
        const { onionPk } = generateOnion();
        const expirySeconds = Math.floor(Date.now() / 1000) + 86400;
        const cert = buildCertificate({ idSk, onionPk, expirySeconds });

        const parsed = verifyCertificate(cert, idPk, Math.floor(Date.now() / 1000));
        expect(parsed).to.not.equal(null);
        expect(Buffer.from(parsed.onionPk).equals(Buffer.from(onionPk))).to.equal(true);
        expect(parsed.expirySeconds).to.equal(expirySeconds);

    });

    it('rejects a certificate signed by a different identity', () => {

        const a = generateIdentity();
        const b = generateIdentity();
        const { onionPk } = generateOnion();
        const expirySeconds = Math.floor(Date.now() / 1000) + 86400;
        const cert = buildCertificate({ idSk: a.idSk, onionPk, expirySeconds });

        // Verify with b's pubkey — should fail.
        expect(verifyCertificate(cert, b.idPk, Math.floor(Date.now() / 1000))).to.equal(null);

    });

    it('rejects an expired certificate', () => {

        const { idSk, idPk } = generateIdentity();
        const { onionPk } = generateOnion();
        const now = Math.floor(Date.now() / 1000);
        const cert = buildCertificate({ idSk, onionPk, expirySeconds: now - 1 });
        expect(verifyCertificate(cert, idPk, now)).to.equal(null);

    });

    it('rejects a certificate with wrong version byte', () => {

        const { idSk, idPk } = generateIdentity();
        const { onionPk } = generateOnion();
        const cert = buildCertificate({
            idSk,
            onionPk,
            expirySeconds: Math.floor(Date.now() / 1000) + 86400,
        });
        // Bump version; re-sign to keep signature valid but version invalid.
        const tampered = new Uint8Array(cert);
        tampered[0] = 0x02;
        // Re-sign the modified prefix.
        const newSig = sign(tampered.subarray(0, 41), idSk);
        tampered.set(newSig, 41);
        expect(verifyCertificate(tampered, idPk, Math.floor(Date.now() / 1000))).to.equal(null);

    });

    it('rejects a certificate of wrong length', () => {

        const { idPk } = generateIdentity();
        expect(verifyCertificate(new Uint8Array(104), idPk, 0)).to.equal(null);
        expect(verifyCertificate(new Uint8Array(106), idPk, 0)).to.equal(null);
        expect(verifyCertificate(null, idPk, 0)).to.equal(null);

    });

    it('rejects a certificate with tampered onion key', () => {

        const { idSk, idPk } = generateIdentity();
        const { onionPk } = generateOnion();
        const cert = buildCertificate({
            idSk,
            onionPk,
            expirySeconds: Math.floor(Date.now() / 1000) + 86400,
        });
        const tampered = new Uint8Array(cert);
        tampered[1] ^= 0x01;
        expect(verifyCertificate(tampered, idPk, Math.floor(Date.now() / 1000))).to.equal(null);

    });

});
