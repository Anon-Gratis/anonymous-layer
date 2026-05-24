import {
    WIRE_VERSION,
    LEN_OUTER_HEADER,
    LEN_AEAD_TAG,
    LEN_RECIPIENT_PREFIX,
    LEN_SENDER_FINGERPRINT,
    OFFSET_SENDER_FINGERPRINT,
    bucketSize,
    bucketForSize,
    innerLengthForBucket,
    maxPayloadForBucket,
} from './constants.mjs';
import { buildOuterHeader, parseOuterHeader } from './header.mjs';
import { buildInnerPlaintext, parseInnerPlaintext } from './inner.mjs';
import {
    generateOnion,
    sharedSecret,
    deriveAeadKey,
    generateNonce,
    aeadEncrypt,
    aeadDecrypt,
} from '../crypto/onion.mjs';
import { fingerprint } from '../crypto/fingerprint.mjs';
import { zeroize } from '../crypto/zeroize.mjs';

const MAX_EPH_RETRIES = 8;

// SPEC § 5.8 — send-path.
//
// Inputs:
//   recipientIdPk      Ed25519 public key of the recipient (used only
//                      to derive the 8-byte recipient prefix).
//   recipientOnionPk   X25519 public key of the recipient (KX target).
//   senderFingerprint  Blake2b-256(idPk) of the sender, embedded inside
//                      the AEAD per SPEC § 5.4.
//   packetType         One of the codes in SPEC § 6.1.
//   payload            Up to maxPayloadForBucket(BUCKET_LARGE) bytes.
//
// Returns a Uint8Array whose length is exactly one of 256/1024/4096.
//
// Throws if the payload is larger than BUCKET_LARGE can hold (the
// application layer must fragment), if the recipient's onion public
// key is a low-order point (X25519 returns all-zero regardless of
// ephemeral key — see RFC 7748 § 5), or if any input is wrong-sized.
export const encodePacket = ({
    recipientIdPk,
    recipientOnionPk,
    senderFingerprint,
    packetType,
    payload,
}) => {

    const bucket = bucketForSize(LEN_OUTER_HEADER + 35 + payload.length + LEN_AEAD_TAG);
    if (bucket === 0) {

        throw new Error('payload exceeds BUCKET_LARGE capacity; fragment at the application layer');

    }

    const recipientPrefix = fingerprint(recipientIdPk).subarray(0, LEN_RECIPIENT_PREFIX);

    // SPEC § 5.8 step 3: abort + retry on all-zero shared. In practice
    // an all-zero shared means recipientOnionPk is a low-order point,
    // which is independent of our ephemeral key — retrying never
    // helps. We retry the spec-mandated number of times anyway, then
    // throw to surface the bad recipient key.
    let ephSk;
    let ephPk;
    let shared = null;
    for (let attempt = 0; attempt < MAX_EPH_RETRIES; attempt += 1) {

        const eph = generateOnion();
        ephSk = eph.onionSk;
        ephPk = eph.onionPk;
        shared = sharedSecret(ephSk, recipientOnionPk);
        if (shared !== null) break;

    }
    if (shared === null) {

        throw new Error('recipient onion key produces all-zero X25519 shared (low-order point)');

    }

    const aeadKey = deriveAeadKey(shared);
    const nonce = generateNonce();

    const inner = buildInnerPlaintext({
        bucket,
        packetType,
        senderFingerprint,
        payload,
    });

    const outerHeader = buildOuterHeader({
        version: WIRE_VERSION,
        bucket,
        recipientPrefix,
        ephPk,
        nonce,
    });

    const { ciphertext, tag } = aeadEncrypt(aeadKey, nonce, outerHeader, inner);

    // SPEC § 5.8 step 9: zeroize ephemeral material. We can zero our
    // local copies of ephSk, shared, and aeadKey; once the function
    // returns they are no longer reachable, but explicit zeroization
    // shortens the window during which sensitive bytes sit in the heap.
    zeroize(ephSk);
    zeroize(shared);
    zeroize(aeadKey);

    const packet = new Uint8Array(bucketSize(bucket));
    packet.set(outerHeader, 0);
    packet.set(ciphertext, LEN_OUTER_HEADER);
    packet.set(tag, LEN_OUTER_HEADER + ciphertext.length);
    return packet;

};

// SPEC § 5.7 — receive-path (steps 1-9).
//
// Inputs:
//   raw                  The exact bytes received from the wire.
//   myIdPk               Receiver's Ed25519 public key (prefix filter).
//   myOnionSk            Receiver's X25519 private key (KX).
//   replayLog            Optional sliding-window log. If omitted, the
//                        replay check is skipped (useful for tests).
//   onPostAeadFailure    Optional callback ({senderFingerprint, reason})
//                        invoked when AEAD succeeded but inner validation
//                        failed. SPEC § 7.4 distinguishes these
//                        attributable failures from pre-AEAD failures
//                        for peer-eviction purposes. `reason` is one of
//                        'real_length', 'padding', 'replay'. Pre-AEAD
//                        failures (length, version, bucket, prefix,
//                        all-zero shared, AEAD tag mismatch) do NOT
//                        invoke this callback because they aren't
//                        attributable.
//
// Returns null per silent-drop discipline (SPEC § 9) on any failure.
// On success, returns the parsed packet:
//   { bucket, packetType, senderFingerprint, payload, ephPk, nonce }
export const decodePacket = (raw, { myIdPk, myOnionSk, replayLog = null, onPostAeadFailure = null } = {}) => {

    // Step 1: length check.
    if (!raw) return null;
    const bucket = bucketForSize(raw.length);
    if (bucket === 0 || raw.length !== bucketSize(bucket)) {

        return null;

    }

    // Parse outer header (does not validate semantics).
    const outer = parseOuterHeader(raw);
    if (outer === null) return null;

    // Step 2: version check.
    if (outer.version !== WIRE_VERSION) return null;

    // Step 3: bucket-vs-length consistency check.
    if (outer.bucket !== bucket) return null;

    // Step 4: fingerprint-prefix filter (advisory).
    const myPrefix = fingerprint(myIdPk).subarray(0, LEN_RECIPIENT_PREFIX);
    let prefixMatches = true;
    for (let i = 0; i < LEN_RECIPIENT_PREFIX; i += 1) {

        if (outer.recipientPrefix[i] !== myPrefix[i]) {

            prefixMatches = false;
            break;

        }

    }
    if (!prefixMatches) return null;

    // Step 5: AEAD decrypt.
    const shared = sharedSecret(myOnionSk, outer.ephPk);
    if (shared === null) return null;
    const aeadKey = deriveAeadKey(shared);

    const innerLen = innerLengthForBucket(bucket);
    const ciphertext = raw.subarray(LEN_OUTER_HEADER, LEN_OUTER_HEADER + innerLen);
    const tag = raw.subarray(LEN_OUTER_HEADER + innerLen, LEN_OUTER_HEADER + innerLen + LEN_AEAD_TAG);

    // AAD is the outer header verbatim.
    const aad = raw.subarray(0, LEN_OUTER_HEADER);
    const plaintext = aeadDecrypt(aeadKey, outer.nonce, aad, ciphertext, tag);

    // Zeroize key material derived from shared.
    zeroize(shared);
    zeroize(aeadKey);

    if (plaintext === null) return null;

    // Steps 6 + 7: padding + real_length sanity (handled inside
    // parseInnerPlaintext). On failure we can attribute to the sender
    // because AEAD success already authenticated the inner plaintext —
    // the 32 bytes at OFFSET_SENDER_FINGERPRINT are sender-asserted
    // and AEAD-authenticated, regardless of the structural defect.
    const inner = parseInnerPlaintext(plaintext, bucket);
    if (inner === null) {

        if (onPostAeadFailure !== null && plaintext.length >= OFFSET_SENDER_FINGERPRINT + LEN_SENDER_FINGERPRINT) {

            const claimedFp = new Uint8Array(plaintext.subarray(OFFSET_SENDER_FINGERPRINT, OFFSET_SENDER_FINGERPRINT + LEN_SENDER_FINGERPRINT));
            // Discriminate the two parseInnerPlaintext failure modes
            // so the caller can record the right reason.
            const claimedRealLength = (plaintext[1] << 8) | plaintext[2];
            const maxPayload = bucketSize(bucket) - LEN_OUTER_HEADER - LEN_AEAD_TAG - 35;
            const reason = claimedRealLength > maxPayload ? 'real_length' : 'padding';
            onPostAeadFailure({ senderFingerprint: claimedFp, reason });

        }
        return null;

    }

    // Steps 8 + 9: replay check + insert. Skipped if no log is supplied.
    if (replayLog !== null) {

        if (replayLog.check(outer.ephPk, outer.nonce)) {

            if (onPostAeadFailure !== null) {

                onPostAeadFailure({
                    senderFingerprint: new Uint8Array(inner.senderFingerprint),
                    reason: 'replay',
                });

            }
            return null;

        }
        replayLog.insert(outer.ephPk, outer.nonce);

    }

    return {
        bucket,
        packetType: inner.packetType,
        senderFingerprint: inner.senderFingerprint,
        payload: inner.payload,
        ephPk: new Uint8Array(outer.ephPk),
        nonce: new Uint8Array(outer.nonce),
    };

};

export { maxPayloadForBucket };
