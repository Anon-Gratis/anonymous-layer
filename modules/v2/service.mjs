// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

// Hidden-service identity helpers for SPEC-v0.2-draft § 4.3 / § 4.4.
//
// A hidden service has a long-lived Ed25519 keypair (SVC_pk, SVC_sk)
// distinct from any node identity. The service's onion address derives
// from SVC_pk; service descriptors are signed with SVC_sk.

import { ed25519 } from '@noble/curves/ed25519.js';

import { fingerprint } from '../crypto/fingerprint.mjs';
import { encodeOnionAddress } from './onion_address.mjs';

// Generate a fresh service identity. Returns:
//   {
//     SVC_sk    Ed25519 secret seed (32 bytes)
//     SVC_pk    Ed25519 public key (32 bytes)
//     onionAddress         canonical .anon address derived from SVC_pk
//     descriptorLookupKey  H(SVC_pk) — used as the directory-side key
//                          when fetching this service's descriptor
//   }
export const createServiceIdentity = () => {

    const SVC_sk = ed25519.utils.randomSecretKey();
    const SVC_pk = ed25519.getPublicKey(SVC_sk);
    return {
        SVC_sk,
        SVC_pk,
        onionAddress: encodeOnionAddress(SVC_pk),
        descriptorLookupKey: fingerprint(SVC_pk),
    };

};

// Reconstruct a service identity from a stored SVC_sk (e.g., loaded
// from disk on operator startup). Returns the same shape as
// createServiceIdentity.
export const loadServiceIdentity = (SVC_sk) => {

    if (!(SVC_sk instanceof Uint8Array) || SVC_sk.length !== 32) {

        throw new Error('SVC_sk must be a 32-byte Uint8Array');

    }
    const SVC_pk = ed25519.getPublicKey(SVC_sk);
    return {
        SVC_sk: new Uint8Array(SVC_sk),
        SVC_pk,
        onionAddress: encodeOnionAddress(SVC_pk),
        descriptorLookupKey: fingerprint(SVC_pk),
    };

};
