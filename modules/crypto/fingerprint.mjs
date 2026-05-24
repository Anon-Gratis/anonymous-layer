import { blake2b } from '@noble/hashes/blake2.js';

// SPEC § 3.4: Blake2b configured for 32-byte output (NOT truncated
// Blake2b-512). The dkLen parameter is part of the Blake2b construction
// per RFC 7693; truncating Blake2b-512 to 32 bytes would produce a
// different value.
export const blake2b256 = (input) => blake2b(input, { dkLen: 32 });

// SPEC § 4.3: node fingerprint = Blake2b-256(idPk).
export const fingerprint = (idPk) => blake2b256(idPk);
