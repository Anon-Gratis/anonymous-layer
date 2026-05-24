// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE
//
// Reference v0.2 runtime, see docs/SPEC-v0.2-draft.md.

// Persistent service-identity store (v3, hybrid PQ).
//
// On-disk file layout (7712 bytes, fixed; mode 0600):
//   SVC_sk_ed               (32)    Ed25519 service identity secret
//   SVC_sk_mldsa            (4032)  ML-DSA-65 service identity secret
//                                    (NEW — hybrid identity per SPEC § 11.5
//                                    closure; pairs with SVC_sk_ed to bind
//                                    the address-derivation hash to BOTH
//                                    pubkeys.)
//   serviceIntroSk          (32)    Ed25519 per-IP intro auth secret
//   serviceEncX25519Sk      (32)    X25519 per-IP sealed-box recipient secret
//   serviceEncMlkemSk       (2400)  ML-KEM-768 per-IP secret
//   serviceEncMlkemPk       (1184)  ML-KEM-768 per-IP public (cached;
//                                    cheaper than re-deriving on each load)
//
// All other public keys are derived at load time from their secret
// counterparts. The bundle's `onionAddress` is the v3 hybrid-derived
// address (encodeOnionAddressV3).
//
// Backwards compatibility: old 3680-byte v2 identity files are
// REJECTED with a clear "please re-init" message. The v0 testnet has
// no migration story; operators re-init service identities and
// hand out the new onion address.
//
// This v0.2 reference layout supports ONE service identity with ONE
// IP. Multi-IP is a future-work item; the layout can be extended by
// appending additional per-IP key blocks.
//
// Auditor note (key derivation): SVC_sk_ed and SVC_sk_mldsa are
// generated from INDEPENDENT entropy, not derived from a shared
// seed. See modules/crypto/hybrid_sign.mjs::hybridKeygen for the
// design rationale. Backup is two separate blobs; loss of either
// half makes the identity non-recoverable as a hybrid identity.

import { readFile, writeFile, rename, chmod, stat, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import { fingerprint as blake2bFingerprint } from '../crypto/fingerprint.mjs';
import { encodeOnionAddressV3 } from '../v2/onion_address.mjs';
import {
    MLDSA_SK_BYTES,
    MLDSA_PK_BYTES,
} from '../crypto/hybrid_sign.mjs';

const LEN_SVC_SK_ED      = 32;
const LEN_SVC_SK_MLDSA   = MLDSA_SK_BYTES;        // 4032
const LEN_INTRO_SK       = 32;
const LEN_ENC_X25519_SK  = 32;
const LEN_ENC_MLKEM_SK   = 2400;
const LEN_ENC_MLKEM_PK   = 1184;

const LEN_FILE = LEN_SVC_SK_ED + LEN_SVC_SK_MLDSA + LEN_INTRO_SK
    + LEN_ENC_X25519_SK + LEN_ENC_MLKEM_SK + LEN_ENC_MLKEM_PK;          // 7712

// Old v2 file length, retained for clearer "please re-init" message.
const LEN_FILE_V2_LEGACY = 32 + 32 + 32 + 2400 + 1184;                  // 3680

const FILE_MODE = 0o600;
const IS_WINDOWS = process.platform === 'win32';

const exists = async (path) => {

    try { await stat(path); return true; }
    catch (err) { if (err.code === 'ENOENT') return false; throw err; }

};

// Derive the full identity bundle from the stored secrets. Returns:
//   {
//     // hybrid identity (v3) — these are what bind to the onion address
//     SVC_sk_ed,    SVC_pk_ed,            // 32 + 32 bytes (Ed25519)
//     SVC_sk_mldsa, SVC_pk_mldsa,         // 4032 + 1952 bytes (ML-DSA-65)
//     onionAddress,                       // v3 base32(hash(edPk||mldsaPk))
//     descriptorLookupKey,                // Blake2b fingerprint of edPk
//                                          // (HSDir lookup key; v0 keeps
//                                          // the v2 derivation for now)
//
//     // legacy alias — many call sites still use SVC_sk / SVC_pk;
//     // both point at the Ed25519 half of the hybrid identity.
//     SVC_sk, SVC_pk,
//
//     // per-IP keys (unchanged from v2)
//     serviceIntroSk, serviceIntroPk,
//     serviceEncX25519Sk, serviceEncX25519Pk,
//     serviceEncMlkemSk,  serviceEncMlkemPk,
//   }
const deriveFromSecrets = ({
    SVC_sk_ed, SVC_sk_mldsa,
    serviceIntroSk, serviceEncX25519Sk,
    serviceEncMlkemSk, serviceEncMlkemPk,
}) => {

    const SVC_pk_ed = ed25519.getPublicKey(SVC_sk_ed);
    // ml_dsa65.getPublicKey derives the pubkey from the secret key
    // (which encodes everything needed) — no separate derivation needed.
    const SVC_pk_mldsa = ml_dsa65.getPublicKey(SVC_sk_mldsa);
    const serviceIntroPk = ed25519.getPublicKey(serviceIntroSk);
    const serviceEncX25519Pk = x25519.getPublicKey(serviceEncX25519Sk);
    return {
        // hybrid identity
        SVC_sk_ed:    new Uint8Array(SVC_sk_ed),
        SVC_pk_ed,
        SVC_sk_mldsa: new Uint8Array(SVC_sk_mldsa),
        SVC_pk_mldsa,
        // address derived from BOTH pubkeys (v3, quantum-safe identity binding)
        onionAddress: encodeOnionAddressV3(SVC_pk_ed, SVC_pk_mldsa),
        // HSDir lookup key — v0 keeps the v2 derivation (Blake2b of
        // Ed25519 pk). Auditor note: this means HSDir lookups don't
        // benefit from the hybrid identity yet; an attacker who
        // forges Ed25519 cannot make HSDirs return a forged
        // descriptor because the responsible-set calculation is keyed
        // by a hash, but they CAN serve their forged descriptor at
        // the same lookup key. The verifier rejects it at descriptor
        // verification time (hybrid sig check). Future v0.3 will
        // rebase the lookup key on the hybrid identity hash.
        descriptorLookupKey: blake2bFingerprint(SVC_pk_ed),
        // legacy aliases
        SVC_sk: new Uint8Array(SVC_sk_ed),
        SVC_pk: SVC_pk_ed,
        // per-IP keys
        serviceIntroSk: new Uint8Array(serviceIntroSk),
        serviceIntroPk,
        serviceEncX25519Sk: new Uint8Array(serviceEncX25519Sk),
        serviceEncX25519Pk,
        serviceEncMlkemSk: new Uint8Array(serviceEncMlkemSk),
        serviceEncMlkemPk: new Uint8Array(serviceEncMlkemPk),
    };

};

export const createServiceIdentityBundle = () => {

    const SVC_sk_ed = ed25519.utils.randomSecretKey();
    // ml_dsa65.keygen(seed) — 32-byte seed, returns {publicKey, secretKey}
    const mldsaSeed = ed25519.utils.randomSecretKey();
    const dsaKp = ml_dsa65.keygen(mldsaSeed);
    const serviceIntroSk = ed25519.utils.randomSecretKey();
    const serviceEncX25519Sk = x25519.utils.randomSecretKey();
    const kem = ml_kem768.keygen();
    return deriveFromSecrets({
        SVC_sk_ed, SVC_sk_mldsa: dsaKp.secretKey,
        serviceIntroSk, serviceEncX25519Sk,
        serviceEncMlkemSk: kem.secretKey,
        serviceEncMlkemPk: kem.publicKey,
    });

};

export const saveServiceIdentity = async (path, bundle) => {

    if (bundle.SVC_sk_ed.length    !== LEN_SVC_SK_ED)    throw new Error('SVC_sk_ed wrong size');
    if (bundle.SVC_sk_mldsa.length !== LEN_SVC_SK_MLDSA) throw new Error(`SVC_sk_mldsa wrong size (${bundle.SVC_sk_mldsa.length} vs ${LEN_SVC_SK_MLDSA})`);
    if (bundle.serviceIntroSk.length !== LEN_INTRO_SK) throw new Error('serviceIntroSk wrong size');
    if (bundle.serviceEncX25519Sk.length !== LEN_ENC_X25519_SK) throw new Error('serviceEncX25519Sk wrong size');
    if (bundle.serviceEncMlkemSk.length !== LEN_ENC_MLKEM_SK) throw new Error(`serviceEncMlkemSk wrong size (${bundle.serviceEncMlkemSk.length} vs ${LEN_ENC_MLKEM_SK})`);
    if (bundle.serviceEncMlkemPk.length !== LEN_ENC_MLKEM_PK) throw new Error('serviceEncMlkemPk wrong size');

    const buf = new Uint8Array(LEN_FILE);
    let off = 0;
    buf.set(bundle.SVC_sk_ed, off);          off += LEN_SVC_SK_ED;
    buf.set(bundle.SVC_sk_mldsa, off);       off += LEN_SVC_SK_MLDSA;
    buf.set(bundle.serviceIntroSk, off);     off += LEN_INTRO_SK;
    buf.set(bundle.serviceEncX25519Sk, off); off += LEN_ENC_X25519_SK;
    buf.set(bundle.serviceEncMlkemSk, off);  off += LEN_ENC_MLKEM_SK;
    buf.set(bundle.serviceEncMlkemPk, off);

    await mkdir(dirname(path), { recursive: true });
    const tmp = `${path}.tmp`;
    await writeFile(tmp, buf, { mode: FILE_MODE });
    await chmod(tmp, FILE_MODE);
    await rename(tmp, path);

};

export const loadServiceIdentity = async (path) => {

    const st = await stat(path);
    if (!IS_WINDOWS) {

        if ((st.mode & 0o077) !== 0) {

            throw new Error(`service identity ${path} has overly permissive mode `
                + `${(st.mode & 0o777).toString(8)}; must be 0600`);

        }

    }
    const buf = await readFile(path);

    if (buf.length === LEN_FILE_V2_LEGACY) {

        throw new Error(
            `service identity ${path} is a legacy v2 (Ed25519-only) `
            + `identity (${buf.length} bytes); the network is now hybrid (v3). `
            + `Delete this file and re-run \`anon-service init\` to mint a `
            + `fresh hybrid identity. (The onion address WILL change.)`,
        );

    }
    if (buf.length !== LEN_FILE) {

        throw new Error(`service identity ${path} has length ${buf.length}; expected ${LEN_FILE}`);

    }
    let off = 0;
    const SVC_sk_ed          = buf.subarray(off, off + LEN_SVC_SK_ED);          off += LEN_SVC_SK_ED;
    const SVC_sk_mldsa       = buf.subarray(off, off + LEN_SVC_SK_MLDSA);       off += LEN_SVC_SK_MLDSA;
    const serviceIntroSk     = buf.subarray(off, off + LEN_INTRO_SK);           off += LEN_INTRO_SK;
    const serviceEncX25519Sk = buf.subarray(off, off + LEN_ENC_X25519_SK);      off += LEN_ENC_X25519_SK;
    const serviceEncMlkemSk  = buf.subarray(off, off + LEN_ENC_MLKEM_SK);       off += LEN_ENC_MLKEM_SK;
    const serviceEncMlkemPk  = buf.subarray(off, off + LEN_ENC_MLKEM_PK);
    return deriveFromSecrets({
        SVC_sk_ed, SVC_sk_mldsa,
        serviceIntroSk, serviceEncX25519Sk, serviceEncMlkemSk, serviceEncMlkemPk,
    });

};

export const loadOrCreateServiceIdentity = async (path) => {

    if (await exists(path)) {

        return { bundle: await loadServiceIdentity(path), created: false };

    }
    const bundle = createServiceIdentityBundle();
    await saveServiceIdentity(path, bundle);
    return { bundle, created: true };

};
