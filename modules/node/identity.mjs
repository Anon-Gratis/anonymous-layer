import { generateIdentity, publicFromSecret, identityFingerprint } from '../crypto/identity.mjs';
import { generateOnion } from '../crypto/onion.mjs';
import { x25519 } from '@noble/curves/ed25519.js';
import { buildCertificate, CERT_BYTES } from '../crypto/cert.mjs';

// A node identity is the long-lived (idPk, idSk) pair plus the
// short-lived (onionPk, onionSk) pair. The on-disk persistence form is
// just the two 32-byte secrets — public keys derive from them. The
// fingerprint is cached because it's used on every send-path call.

export const createNodeIdentity = () => {

    const id = generateIdentity();
    const onion = generateOnion();
    return {
        idPk: id.idPk,
        idSk: id.idSk,
        onionPk: onion.onionPk,
        onionSk: onion.onionSk,
        fingerprint: identityFingerprint(id.idPk),
    };

};

export const loadNodeIdentity = ({ idSk, onionSk }) => {

    if (idSk.length !== 32) throw new Error('idSk must be 32 bytes');
    if (onionSk.length !== 32) throw new Error('onionSk must be 32 bytes');
    const idPk = publicFromSecret(idSk);
    const onionPk = x25519.getPublicKey(onionSk);
    return {
        idPk,
        idSk: new Uint8Array(idSk),
        onionPk,
        onionSk: new Uint8Array(onionSk),
        fingerprint: identityFingerprint(idPk),
    };

};

// SPEC § 4.4 / § 6.6: build a fresh certificate over the node's
// current onionPk, valid until `expirySeconds`. Operators rotate the
// onion key periodically by generating a new (onionPk, onionSk) pair
// and issuing a new cert; v0.1 does not specify a rotation cadence,
// so this stays in operator policy.
export const currentCertificate = ({ identity, expirySeconds }) => buildCertificate({
    idSk: identity.idSk,
    onionPk: identity.onionPk,
    expirySeconds,
});

export { CERT_BYTES };
