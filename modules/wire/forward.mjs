import { serializeTransports, parseTransports } from './transport.mjs';
import {
    LEN_RECIPIENT_PREFIX,
    OFFSET_RECIPIENT_PREFIX,
    bucketSize,
    bucketForSize,
} from './constants.mjs';

// SPEC § 6.5: FORWARD payload.
//
//   next-hop fingerprint (32) ‖ transport list ‖ inner packet
//
// The inner packet is an opaque, fully-formed anon-layer packet of
// length 256, 1024, or 4096 bytes. The forwarder MUST NOT modify it in
// any way. Per § 6.5, the forwarder also:
//   - confirms the inner packet length is one of the three buckets;
//   - confirms the inner packet's recipient_prefix matches the first
//     8 bytes of the supplied next-hop fingerprint;
//   - applies the rate limits of § 6.5.1 (forward_rate_limit.mjs).

const LEN_NEXT_HOP_FINGERPRINT = 32;
const OFFSET_NEXT_HOP_FINGERPRINT = 0;
const OFFSET_TRANSPORTS = 32;

export const FORWARD_MIN_LENGTH = LEN_NEXT_HOP_FINGERPRINT + 1 + 256; // fp + zero transports + smallest bucket

export const buildForwardPayload = ({ nextHopFingerprint, transports, innerPacket }) => {

    if (nextHopFingerprint.length !== LEN_NEXT_HOP_FINGERPRINT) {

        throw new Error('nextHopFingerprint must be 32 bytes');

    }

    const innerBucket = bucketForSize(innerPacket.length);
    if (innerBucket === 0 || innerPacket.length !== bucketSize(innerBucket)) {

        throw new Error('innerPacket length must be exactly one of 256, 1024, or 4096');

    }

    const transportBytes = serializeTransports(transports);
    const buf = new Uint8Array(OFFSET_TRANSPORTS + transportBytes.length + innerPacket.length);
    buf.set(nextHopFingerprint, OFFSET_NEXT_HOP_FINGERPRINT);
    buf.set(transportBytes, OFFSET_TRANSPORTS);
    buf.set(innerPacket, OFFSET_TRANSPORTS + transportBytes.length);
    return buf;

};

// Structural parse + the two pre-rate-limit checks from § 6.5:
//   - inner packet length is a valid bucket size
//   - inner packet recipient_prefix matches the next-hop fingerprint prefix
// Returns null per silent-drop discipline on any failure.
//
// Rate limiting is the caller's responsibility (forward_rate_limit.mjs);
// keeping it separate lets the rate limiter be tested without a
// payload buffer and lets the parser stay deterministic.
export const parseForwardPayload = (payload) => {

    if (!payload || payload.length < FORWARD_MIN_LENGTH) {

        return null;

    }

    const nextHopFingerprint = new Uint8Array(payload.subarray(OFFSET_NEXT_HOP_FINGERPRINT, OFFSET_TRANSPORTS));

    const parsedTransports = parseTransports(payload, OFFSET_TRANSPORTS);
    if (parsedTransports === null) return null;

    const innerStart = OFFSET_TRANSPORTS + parsedTransports.consumed;
    const innerLength = payload.length - innerStart;
    const innerBucket = bucketForSize(innerLength);
    if (innerBucket === 0 || innerLength !== bucketSize(innerBucket)) {

        return null;

    }

    const innerPacket = payload.subarray(innerStart, innerStart + innerLength);

    // SPEC § 6.5 step 2: inner recipient_prefix must match the
    // first 8 bytes of the supplied next-hop fingerprint.
    for (let i = 0; i < LEN_RECIPIENT_PREFIX; i += 1) {

        if (innerPacket[OFFSET_RECIPIENT_PREFIX + i] !== nextHopFingerprint[i]) {

            return null;

        }

    }

    return {
        nextHopFingerprint,
        transports: parsedTransports.transports,
        // Copy out so the returned packet can outlive the payload buffer.
        innerPacket: new Uint8Array(innerPacket),
    };

};
