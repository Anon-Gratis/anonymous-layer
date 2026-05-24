import { expect } from 'chai';
import fc from 'fast-check';

import { encodePacket, decodePacket } from './packet.mjs';
import { buildInnerPlaintext, parseInnerPlaintext } from './inner.mjs';
import { buildOuterHeader, parseOuterHeader } from './header.mjs';
import { buildDataPayload, parseDataPayload } from './data.mjs';
import { serializeTransports, parseTransports, TRANSPORT_WEBSOCKET_IPV4 } from './transport.mjs';
import {
    buildAnnouncePeerPayload,
    parseAnnouncePeerPayload,
} from './announce.mjs';
import { buildKeyCertificatePayload, parseKeyCertificatePayload } from './key_certificate.mjs';
import { buildForwardPayload, parseForwardPayload } from './forward.mjs';
import {
    BUCKET_SMALL,
    BUCKET_MEDIUM,
    BUCKET_LARGE,
    TYPE_DATA,
    maxPayloadForBucket,
} from './constants.mjs';
import { parseSeedList } from '../peer/seed.mjs';

import { generateIdentity, identityFingerprint } from '../crypto/identity.mjs';
import { generateOnion } from '../crypto/onion.mjs';
import { buildCertificate } from '../crypto/cert.mjs';

const NUM_RUNS = 1000;

const arbUint8 = fc.integer({ min: 0, max: 255 });
const arbBytes = (length) => fc.uint8Array({ minLength: length, maxLength: length });
const arbBytesUpTo = (max) => fc.uint8Array({ minLength: 0, maxLength: max });
const arbAnyBytes = fc.uint8Array({ minLength: 0, maxLength: 8192 });

const makeParty = () => {

    const id = generateIdentity();
    const o = generateOnion();
    return {
        idPk: id.idPk,
        idSk: id.idSk,
        onionPk: o.onionPk,
        onionSk: o.onionSk,
        fingerprint: identityFingerprint(id.idPk),
    };

};

// Cache a single sender/recipient pair so the property-based tests
// don't burn through identity generations.
const senderCached = makeParty();
const recipientCached = makeParty();

describe('wire/packet — property-based', function () {

    this.timeout(20000);

    it('encode → decode round-trip preserves payload, packetType, senderFingerprint', () => {

        // Heavy: each iteration does keygen + X25519 + AEAD. Constrain
        // payload size and run count to keep CI under ~10s.
        fc.assert(
            fc.property(
                arbBytesUpTo(512),
                (payload) => {

                    const packet = encodePacket({
                        recipientIdPk: recipientCached.idPk,
                        recipientOnionPk: recipientCached.onionPk,
                        senderFingerprint: senderCached.fingerprint,
                        packetType: TYPE_DATA,
                        payload,
                    });
                    const decoded = decodePacket(packet, {
                        myIdPk: recipientCached.idPk,
                        myOnionSk: recipientCached.onionSk,
                    });
                    if (decoded === null) return false;
                    if (decoded.packetType !== TYPE_DATA) return false;
                    if (!Buffer.from(decoded.senderFingerprint).equals(Buffer.from(senderCached.fingerprint))) return false;
                    if (!Buffer.from(decoded.payload).equals(Buffer.from(payload))) return false;
                    return true;

                },
            ),
            { numRuns: 200 },
        );

    });

    it('decodePacket on arbitrary bytes never throws; returns null OR a structurally valid packet', () => {

        fc.assert(
            fc.property(
                fc.uint8Array({ minLength: 0, maxLength: 5000 }),
                (raw) => {

                    let result;
                    try {

                        result = decodePacket(raw, {
                            myIdPk: recipientCached.idPk,
                            myOnionSk: recipientCached.onionSk,
                        });

                    } catch (err) {

                        return false; // any throw fails the property

                    }
                    if (result === null) return true;
                    // Structural sanity if we got something back.
                    if (!(result.payload instanceof Uint8Array)) return false;
                    if (!(result.senderFingerprint instanceof Uint8Array)) return false;
                    if (result.senderFingerprint.length !== 32) return false;
                    if (typeof result.packetType !== 'number') return false;
                    return true;

                },
            ),
            { numRuns: NUM_RUNS },
        );

    });

});

describe('wire/header — property-based', function () {

    this.timeout(10000);

    it('build → parse round-trip', () => {

        fc.assert(
            fc.property(
                arbUint8,
                arbUint8,
                arbBytes(8),
                arbBytes(32),
                arbBytes(12),
                (version, bucket, prefix, ephPk, nonce) => {

                    const header = buildOuterHeader({
                        version, bucket,
                        recipientPrefix: prefix,
                        ephPk, nonce,
                    });
                    const parsed = parseOuterHeader(header);
                    return parsed !== null
                        && parsed.version === version
                        && parsed.bucket === bucket
                        && Buffer.from(parsed.recipientPrefix).equals(Buffer.from(prefix))
                        && Buffer.from(parsed.ephPk).equals(Buffer.from(ephPk))
                        && Buffer.from(parsed.nonce).equals(Buffer.from(nonce));

                },
            ),
            { numRuns: NUM_RUNS },
        );

    });

    it('parseOuterHeader on arbitrary bytes never throws', () => {

        fc.assert(
            fc.property(arbAnyBytes, (raw) => {

                try {

                    parseOuterHeader(raw);
                    return true;

                } catch {

                    return false;

                }

            }),
            { numRuns: NUM_RUNS },
        );

    });

});

describe('wire/inner — property-based', function () {

    this.timeout(10000);

    it('parseInnerPlaintext on arbitrary bytes never throws', () => {

        fc.assert(
            fc.property(
                arbAnyBytes,
                fc.constantFrom(BUCKET_SMALL, BUCKET_MEDIUM, BUCKET_LARGE, 0x00, 0x7F),
                (raw, bucket) => {

                    try {

                        const r = parseInnerPlaintext(raw, bucket);
                        if (r !== null) {

                            if (!(r.senderFingerprint instanceof Uint8Array)) return false;
                            if (r.senderFingerprint.length !== 32) return false;

                        }
                        return true;

                    } catch {

                        return false;

                    }

                },
            ),
            { numRuns: NUM_RUNS },
        );

    });

    it('build → parse round-trip for valid inputs', () => {

        const buckets = [BUCKET_SMALL, BUCKET_MEDIUM, BUCKET_LARGE];
        fc.assert(
            fc.property(
                fc.constantFrom(...buckets),
                arbUint8,
                arbBytes(32),
                fc.uint8Array({ minLength: 0, maxLength: 100 }),
                (bucket, packetType, senderFp, payload) => {

                    const inner = buildInnerPlaintext({
                        bucket,
                        packetType,
                        senderFingerprint: senderFp,
                        payload,
                    });
                    const parsed = parseInnerPlaintext(inner, bucket);
                    return parsed !== null
                        && parsed.packetType === packetType
                        && Buffer.from(parsed.senderFingerprint).equals(Buffer.from(senderFp))
                        && Buffer.from(parsed.payload).equals(Buffer.from(payload));

                },
            ),
            { numRuns: NUM_RUNS },
        );

    });

});

describe('wire/data — property-based', () => {

    it('parseDataPayload on arbitrary bytes never throws', () => {

        fc.assert(
            fc.property(arbAnyBytes, (raw) => {

                try {

                    parseDataPayload(raw);
                    return true;

                } catch {

                    return false;

                }

            }),
            { numRuns: NUM_RUNS },
        );

    });

    it('build → parse round-trip', () => {

        fc.assert(
            fc.property(
                arbBytes(16),
                fc.bigInt({ min: 0n, max: 0xFFFFFFFFFFFFFFFFn }),
                fc.uint8Array({ minLength: 0, maxLength: 100 }),
                (tag, seq, payload) => {

                    const buf = buildDataPayload({
                        conversationTag: tag,
                        sequenceNumber: seq,
                        payload,
                    });
                    const parsed = parseDataPayload(buf);
                    return parsed !== null
                        && Buffer.from(parsed.conversationTag).equals(Buffer.from(tag))
                        && parsed.sequenceNumber === seq
                        && Buffer.from(parsed.payload).equals(Buffer.from(payload));

                },
            ),
            { numRuns: NUM_RUNS },
        );

    });

});

describe('wire/transport — property-based', () => {

    it('parseTransports on arbitrary bytes never throws', () => {

        fc.assert(
            fc.property(
                arbAnyBytes,
                fc.integer({ min: 0, max: 256 }),
                (raw, offset) => {

                    try {

                        parseTransports(raw, offset);
                        return true;

                    } catch {

                        return false;

                    }

                },
            ),
            { numRuns: NUM_RUNS },
        );

    });

    it('parseAnnouncePeerPayload on arbitrary bytes never throws', () => {

        fc.assert(
            fc.property(arbAnyBytes, (raw) => {

                try {

                    parseAnnouncePeerPayload(raw);
                    return true;

                } catch {

                    return false;

                }

            }),
            { numRuns: NUM_RUNS },
        );

    });

    it('parseForwardPayload on arbitrary bytes never throws', () => {

        fc.assert(
            fc.property(arbAnyBytes, (raw) => {

                try {

                    parseForwardPayload(raw);
                    return true;

                } catch {

                    return false;

                }

            }),
            { numRuns: NUM_RUNS },
        );

    });

    it('parseKeyCertificatePayload on arbitrary bytes never throws', () => {

        fc.assert(
            fc.property(arbAnyBytes, (raw) => {

                try {

                    parseKeyCertificatePayload(raw);
                    return true;

                } catch {

                    return false;

                }

            }),
            { numRuns: NUM_RUNS },
        );

    });

});

describe('peer/seed — property-based', () => {

    it('parseSeedList on arbitrary bytes never throws', () => {

        fc.assert(
            fc.property(arbAnyBytes, (raw) => {

                try {

                    parseSeedList(raw);
                    return true;

                } catch {

                    return false;

                }

            }),
            { numRuns: NUM_RUNS },
        );

    });

});
