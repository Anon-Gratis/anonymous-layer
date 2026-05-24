// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE
//
// Reference v0.2 runtime, see docs/SPEC-v0.2-draft.md.
// The draft has open architectural questions; the code has not been
// audited. Do not rely on this for anonymity.

// Persistent identity store for v0.2 relays.
//
// On-disk format: exactly 64 bytes — idSk(32) || B_sk(32).
//   idSk   Ed25519 secret seed for the node's long-term identity key.
//          Public key is derivable; not stored.
//   B_sk   X25519 secret for the node's identity-onion key (the
//          long-term key the ntor handshake reaches; SPEC § 4.2).
//
// Permissions: file is created mode 0600 (owner-read-write). loadIdentity
// refuses any file with group- or world-readable bits set on Unix. On
// Windows the check is skipped.
//
// Writes are atomic: write to ${path}.tmp, fsync, rename onto target.

import { readFile, writeFile, rename, chmod, stat, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

import { generateIdentity } from '../crypto/identity.mjs';
import { generateOnion } from '../crypto/onion.mjs';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { fingerprint as blake2bFingerprint } from '../crypto/fingerprint.mjs';

const IDENTITY_BYTES = 64;
const IDENTITY_FILE_MODE = 0o600;
const IS_WINDOWS = process.platform === 'win32';

const buildIdentityFromSecrets = ({ idSk, B_sk }) => ({
    idSk: new Uint8Array(idSk),
    idPk: ed25519.getPublicKey(idSk),
    B_sk: new Uint8Array(B_sk),
    B_pk: x25519.getPublicKey(B_sk),
    fingerprint: blake2bFingerprint(ed25519.getPublicKey(idSk)),
});

export const createNodeIdentity = () => {

    const id = generateIdentity();
    const onion = generateOnion();
    return buildIdentityFromSecrets({ idSk: id.idSk, B_sk: onion.onionSk });

};

export const exists = async (path) => {

    try {

        await stat(path);
        return true;

    } catch (err) {

        if (err.code === 'ENOENT') return false;
        throw err;

    }

};

export const saveIdentity = async (path, { idSk, B_sk }) => {

    if (idSk.length !== 32) throw new Error('idSk must be 32 bytes');
    if (B_sk.length !== 32) throw new Error('B_sk must be 32 bytes');

    const buf = new Uint8Array(IDENTITY_BYTES);
    buf.set(idSk, 0);
    buf.set(B_sk, 32);

    await mkdir(dirname(path), { recursive: true });
    const tmp = `${path}.tmp`;
    await writeFile(tmp, buf, { mode: IDENTITY_FILE_MODE });
    await chmod(tmp, IDENTITY_FILE_MODE);
    await rename(tmp, path);

};

export const loadIdentity = async (path) => {

    const st = await stat(path);

    if (!IS_WINDOWS) {

        const PERMISSIVE_MASK = 0o077;
        if ((st.mode & PERMISSIVE_MASK) !== 0) {

            throw new Error(
                `identity file ${path} has overly permissive mode `
                + `${(st.mode & 0o777).toString(8)}; must be 0600`,
            );

        }

    }

    const buf = await readFile(path);
    if (buf.length !== IDENTITY_BYTES) {

        throw new Error(`identity file ${path} is ${buf.length} bytes, expected ${IDENTITY_BYTES}`);

    }
    return buildIdentityFromSecrets({
        idSk: buf.subarray(0, 32),
        B_sk: buf.subarray(32, 64),
    });

};

// Load if exists, otherwise create + save + return. Returns
// { identity, created } so the caller can distinguish.
export const loadOrCreateIdentity = async (path) => {

    if (await exists(path)) {

        return { identity: await loadIdentity(path), created: false };

    }
    const identity = createNodeIdentity();
    await saveIdentity(path, { idSk: identity.idSk, B_sk: identity.B_sk });
    return { identity, created: true };

};
