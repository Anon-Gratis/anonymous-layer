import { fingerprint } from '../crypto/fingerprint.mjs';

// Identity cache: a Map<fingerprint, idPk> populated by KEY_CERTIFICATE
// handlers and consumed by ANNOUNCE_PEER verification.
//
// Ed25519 raw signatures don't embed the public key, so the receiver
// of an ANNOUNCE_PEER packet needs the announced peer's idPk to verify
// the certificate. KEY_CERTIFICATE is the channel that supplies it
// (SPEC § 6.6); this module is the in-memory cache.

export const createIdentityCache = () => {

    const cache = new Map();
    const keyOf = (fp) => Buffer.from(fp).toString('hex');

    const set = (idPk) => {

        if (idPk.length !== 32) throw new Error('idPk must be 32 bytes');
        const fp = fingerprint(idPk);
        cache.set(keyOf(fp), new Uint8Array(idPk));

    };

    const get = (fp) => cache.get(keyOf(fp)) || null;

    const has = (fp) => cache.has(keyOf(fp));

    const size = () => cache.size;

    return { set, get, has, size };

};
