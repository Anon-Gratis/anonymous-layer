// Hybrid digital signatures: Ed25519 (classical) + ML-DSA-65 (PQ).
//
// The idiom: every signed object carries BOTH a classical Ed25519
// signature AND an ML-DSA-65 signature. A verifier accepts the object
// iff BOTH signatures verify against their respective public keys.
//
// === Threat model this closes ===
//
// A quantum adversary who recovers an Ed25519 secret key from its
// public key (Shor's algorithm) can forge Ed25519 signatures. With
// classical-only signing, that's a complete identity break: they can
// publish forged service descriptors, link certs, etc., that
// indistinguishably look like the genuine owner.
//
// With hybrid signatures, that same adversary still cannot forge a
// hybrid signature without also forging an ML-DSA-65 signature, which
// requires breaking ML-DSA-65. The two schemes have INDEPENDENT
// security assumptions (lattice problems vs. ECDLP), so a break in
// one does not transfer to the other. Conservative composition.
//
// === Why "AND" not "OR" ===
//
// An OR-of-signatures scheme (accept iff either verifies) would be
// strictly weaker than the weaker of the two primitives. AND-of-
// signatures is strictly stronger than the stronger of the two. We
// want strength, not graceful degradation. Auditor note: this is
// the intentional choice; reviewers who object should read NIST PQC
// transition guidance § 5.2 ("Hybrid Modes for Authentication").
//
// === Why ML-DSA-65 (not -44 or -87) ===
//
// NIST claim-3 security level (≈ AES-192 classical, ≈ 128-bit PQ).
// Matches the security claim of the X25519+ML-KEM-768 KEM we already
// use in the rendezvous handshake. -44 would be weaker than our
// KEM (mismatched), -87 stronger but with 50% larger keys + sigs
// for no protocol-coherent reason. Same-level-everywhere is a
// classical security-engineering hygiene call.
//
// === Why concatenation, not a unified composite signature ===
//
// We could nest the two into a "hybrid signature" blob via some
// encoding (length-prefix, ASN.1, etc.). We don't: we keep the two
// signatures as separate fields in the containing structure
// (descriptor, cert, etc.). The containing structure already needs
// length-prefixed framing; an extra encoding layer just adds an
// attack surface without buying any new property. Each schema's
// serializer is responsible for laying out (edSig || mldsaSig) in
// its own order, with its own field tags.
//
// === Transcript construction ===
//
// Both signatures are computed over THE SAME transcript bytes.
// Domain-separation strings live in the containing protocol's
// signed region (e.g. "anon-layer/v2/descriptor"), so neither sig
// can be lifted to another context. We do NOT prepend a "hybrid:"
// tag to the input — the spec layer already has unambiguous domain
// separation.
//
// === What this module is NOT ===
//
// - It is NOT a key-binding cert builder. The containing protocol
//   embeds both public keys in its signed payload, and the verifier
//   trusts the address-derivation to bind the two. See
//   modules/v2/onion_address.mjs and modules/v2/descriptor.mjs.
// - It is NOT an X.509-style certificate. There is no chain, no CA,
//   no validity-window. Trust comes from the address (which encodes
//   both pubkeys) and the spec layer (which carries them).

import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import { sign as edSign, verify as edVerify } from './identity.mjs';

// ----- Sizes (audit-checkable constants) -----

export const ED25519_PK_BYTES   = 32;
export const ED25519_SK_BYTES   = 32;
export const ED25519_SIG_BYTES  = 64;

export const MLDSA_PK_BYTES     = 1952;
export const MLDSA_SK_BYTES     = 4032;
export const MLDSA_SIG_BYTES    = 3309;

export const HYBRID_PK_BYTES    = ED25519_PK_BYTES  + MLDSA_PK_BYTES;   // 1984
export const HYBRID_SIG_BYTES   = ED25519_SIG_BYTES + MLDSA_SIG_BYTES;  // 3373

// ----- Keygen -----

// Generate a fresh hybrid identity. Returns:
//   {
//     edSk:    Uint8Array(32),
//     edPk:    Uint8Array(32),
//     mldsaSk: Uint8Array(4032),
//     mldsaPk: Uint8Array(1952),
//   }
//
// The two keypairs are independent — no shared seed. Auditor note: we
// considered deriving them both from a single 32-byte master seed via
// HKDF (smaller backup, deterministic). We rejected it for v0 because
// it adds a custom KDF construction the schemes weren't designed for;
// independent fresh entropy is conservative.
export const hybridKeygen = () => {

    const edSk = ed25519.utils.randomSecretKey();
    const edPk = ed25519.getPublicKey(edSk);

    // ML-DSA keygen takes a 32-byte seed (xi in FIPS 204). We give it
    // fresh randomness from the same RNG the curves library uses.
    const seed = ed25519.utils.randomSecretKey();
    const mldsaKp = ml_dsa65.keygen(seed);

    return {
        edSk,
        edPk,
        mldsaSk: mldsaKp.secretKey,
        mldsaPk: mldsaKp.publicKey,
    };

};

// ----- Sign / verify -----

// Sign `message` with both keys. Returns { edSig, mldsaSig }.
// Caller is responsible for transcript construction (domain
// separation, length framing, etc.) BEFORE handing bytes in.
export const hybridSign = (message, { edSk, mldsaSk }) => {

    if (!(message instanceof Uint8Array)) {

        throw new TypeError('hybridSign: message must be Uint8Array');

    }
    return {
        edSig:    edSign(message, edSk),
        mldsaSig: ml_dsa65.sign(message, mldsaSk),
    };

};

// Verify both signatures. Returns true iff BOTH verify (AND, not OR).
// Returns false on any malformed input — no exceptions thrown
// (matches the silent-drop discipline used elsewhere in modules/crypto/).
export const hybridVerify = (message, { edPk, mldsaPk }, { edSig, mldsaSig }) => {

    if (!(message instanceof Uint8Array)) return false;
    if (!(edPk    instanceof Uint8Array) || edPk.length    !== ED25519_PK_BYTES)  return false;
    if (!(mldsaPk instanceof Uint8Array) || mldsaPk.length !== MLDSA_PK_BYTES)    return false;
    if (!(edSig   instanceof Uint8Array) || edSig.length   !== ED25519_SIG_BYTES) return false;
    if (!(mldsaSig instanceof Uint8Array) || mldsaSig.length !== MLDSA_SIG_BYTES) return false;

    // Check both. We intentionally do NOT short-circuit on the first
    // false: while functionally equivalent, evaluating both gives
    // constant-time leakage characteristics closer to what auditors
    // want from a hybrid construction. (The underlying libraries are
    // not promised to be constant-time across success/failure, but
    // forcing both calls avoids one degree of timing asymmetry.)
    const okEd    = edVerify(edSig, message, edPk);
    const okMldsa = (() => {
        // ml_dsa65.verify signature: (sig, msg, publicKey). Caught
        // me out — auditor double-check this arg order on every
        // dependency bump (@noble/post-quantum versions).
        try { return ml_dsa65.verify(mldsaSig, message, mldsaPk); }
        catch { return false; }
    })();

    return okEd && okMldsa;

};
