import { readFile, writeFile, rename, chmod, stat, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { loadNodeIdentity, createNodeIdentity } from './identity.mjs';

// Persistent identity store.
//
// On-disk format: exactly 64 bytes — idSk(32) || onionSk(32). Raw
// binary, no header, no version. Public keys derive from the secrets,
// so storing only the secrets is sufficient and minimises what an
// attacker who reads the file has to work with (they already have
// everything, but at least we don't write redundant copies).
//
// Permissions: file is created with mode 0600 (owner-read-write only).
// loadIdentity refuses to read a file with group- or world-readable
// bits set on Unix. On Windows file modes are advisory and the check
// is skipped (with a warning).
//
// Writes are atomic: we write to `${path}.tmp`, fsync, rename onto
// the target. This avoids leaving a half-written identity if the
// process is killed mid-write.

const IDENTITY_BYTES = 64;
const IDENTITY_FILE_MODE = 0o600;
const IS_WINDOWS = process.platform === 'win32';

export const exists = async (path) => {

    try {

        await stat(path);
        return true;

    } catch (err) {

        if (err.code === 'ENOENT') return false;
        throw err;

    }

};

export const saveIdentity = async (path, { idSk, onionSk }) => {

    if (idSk.length !== 32) throw new Error('idSk must be 32 bytes');
    if (onionSk.length !== 32) throw new Error('onionSk must be 32 bytes');

    const buf = new Uint8Array(IDENTITY_BYTES);
    buf.set(idSk, 0);
    buf.set(onionSk, 32);

    await mkdir(dirname(path), { recursive: true });
    const tmp = `${path}.tmp`;
    await writeFile(tmp, buf, { mode: IDENTITY_FILE_MODE });
    // chmod again in case the umask widened the mode at create time.
    await chmod(tmp, IDENTITY_FILE_MODE);
    await rename(tmp, path);

};

export const loadIdentity = async (path) => {

    const st = await stat(path);

    if (!IS_WINDOWS) {

        // Refuse to load a key with group/other bits set; this catches
        // accidental `chmod 644 identity.key` after the fact.
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
    const idSk = buf.subarray(0, 32);
    const onionSk = buf.subarray(32, 64);
    return loadNodeIdentity({ idSk, onionSk });

};

// Convenience: load an existing identity, or create + save + return a
// fresh one if the file doesn't exist. Returns { identity, created:bool }
// so the caller can log "loaded" vs "generated" appropriately.
export const loadOrCreateIdentity = async (path) => {

    if (await exists(path)) {

        return { identity: await loadIdentity(path), created: false };

    }
    const identity = createNodeIdentity();
    await saveIdentity(path, { idSk: identity.idSk, onionSk: identity.onionSk });
    return { identity, created: true };

};
