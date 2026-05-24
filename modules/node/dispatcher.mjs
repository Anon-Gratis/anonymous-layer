import { decodePacket } from '../wire/packet.mjs';
import {
    TYPE_RESERVED,
    TYPE_DATA,
    TYPE_ANNOUNCE_PEER,
    TYPE_FORWARD,
    TYPE_KEY_CERTIFICATE,
} from '../wire/constants.mjs';
import { parseDataPayload } from '../wire/data.mjs';
import { parseAnnouncePeerPayload, verifyAnnouncePeer } from '../wire/announce.mjs';
import { parseForwardPayload } from '../wire/forward.mjs';
import { parseKeyCertificatePayload, verifyKeyCertificate } from '../wire/key_certificate.mjs';

// SPEC § 5.7 step 10 + § 6: inbound packet dispatcher. Receives the
// raw bytes from a transport, runs the receive path, and routes by
// packet type to the appropriate handler. All failures are silent
// drops per § 9.1.
//
// Construction wires the dispatcher to the node's shared state:
//
//   identity            Local node identity { idPk, onionSk, ... }.
//   peerTable           Shared peer table (peer/table.mjs).
//   identityCache       fp → idPk learned from KEY_CERTIFICATE.
//   replayLog           Wire-layer sliding-window log.
//   forwardRateLimiter  § 6.5.1 forward rate limiter.
//   onData              ({senderFingerprint, conversationTag, sequenceNumber, payload}) => void
//                       Invoked on every successfully-decoded DATA packet.
//   forwardSend         ({nextHopFingerprint, transports, innerPacket}) => void
//                       Asks the node to dispatch a verbatim FORWARD.
//                       The dispatcher does NOT touch transports; it just
//                       hands off after the rate-limit check.
//   learnPeerOnTransport (peerFp, senderTransport) => void
//                       Invoked from the KEY_CERTIFICATE handler after
//                       successful verify. Lets the node "promote" an
//                       anonymous inbound transport into the live
//                       transports map once it knows who's on the other
//                       end. Idempotent on the node side.
//   nowSeconds          () => number — clock for cert verification.

export const createDispatcher = ({
    identity,
    peerTable,
    identityCache,
    replayLog,
    forwardRateLimiter,
    onData,
    forwardSend,
    learnPeerOnTransport = null,
    nowSeconds = () => Math.floor(Date.now() / 1000),
}) => {

    const onInbound = (rawBytes, senderTransport = null) => {

        const onPostAeadFailure = ({ senderFingerprint /*, reason */ }) => {

            // § 7.4: post-AEAD failures are attributable; evict.
            peerTable.markInnerValidationFailed(senderFingerprint);

        };

        const packet = decodePacket(rawBytes, {
            myIdPk: identity.idPk,
            myOnionSk: identity.onionSk,
            replayLog,
            onPostAeadFailure,
        });
        if (packet === null) return;

        switch (packet.packetType) {

            case TYPE_RESERVED:
                // SPEC § 6.2: never valid. Drop.
                return;

            case TYPE_DATA: {

                const data = parseDataPayload(packet.payload);
                if (data === null) {

                    // SPEC § 6.3: DATA shorter than 24 bytes — silent drop +
                    // attribution: the sender clearly violated the protocol,
                    // and AEAD passed so we know who they are.
                    peerTable.markInnerValidationFailed(packet.senderFingerprint);
                    return;

                }
                onData({
                    senderFingerprint: packet.senderFingerprint,
                    conversationTag: data.conversationTag,
                    sequenceNumber: data.sequenceNumber,
                    payload: data.payload,
                });
                return;

            }

            case TYPE_KEY_CERTIFICATE: {

                const parsed = parseKeyCertificatePayload(packet.payload);
                if (parsed === null) {

                    peerTable.markInnerValidationFailed(packet.senderFingerprint);
                    return;

                }
                const ok = verifyKeyCertificate({
                    parsed,
                    senderFingerprint: packet.senderFingerprint,
                    nowSeconds: nowSeconds(),
                });
                if (!ok) {

                    // SPEC § 6.6: receiver MUST drop on verification
                    // failure. The sender lied about who they are or their
                    // certificate is bad — both attributable.
                    peerTable.markInnerValidationFailed(packet.senderFingerprint);
                    return;

                }
                // Cache the (idPk, cert) pair for future ANNOUNCE_PEER
                // verification, and seed the peer table.
                identityCache.set(parsed.idPk);
                peerTable.addOrUpdate({
                    idPk: parsed.idPk,
                    certBytes: parsed.certBytes,
                    transports: [],
                    nowSeconds: nowSeconds(),
                });
                // If this packet arrived over an anonymous inbound
                // transport, the node can now bind it to the verified
                // sender fingerprint.
                if (learnPeerOnTransport !== null && senderTransport !== null) {

                    learnPeerOnTransport(packet.senderFingerprint, senderTransport);

                }
                return;

            }

            case TYPE_ANNOUNCE_PEER: {

                const parsed = parseAnnouncePeerPayload(packet.payload);
                if (parsed === null) {

                    peerTable.markInnerValidationFailed(packet.senderFingerprint);
                    return;

                }
                // Look up the announced peer's idPk in the cache. If
                // we don't have it, we cannot verify the embedded
                // certificate — silently drop the announce. (The
                // announcer is not at fault; we just don't yet have
                // the key. A future KEY_CERTIFICATE from the announced
                // peer will populate the cache.)
                const announcedIdPk = identityCache.get(parsed.announcedFingerprint);
                if (announcedIdPk === null) return;

                const ok = verifyAnnouncePeer({
                    parsed,
                    announcedIdPk,
                    nowSeconds: nowSeconds(),
                });
                if (!ok) {

                    // SPEC § 6.4: drop on any verification failure.
                    // The announcer asserted a (fingerprint, cert) pair
                    // that does not check out — attributable.
                    peerTable.markInnerValidationFailed(packet.senderFingerprint);
                    return;

                }
                peerTable.addOrUpdate({
                    idPk: announcedIdPk,
                    certBytes: parsed.certBytes,
                    transports: parsed.transports,
                    nowSeconds: nowSeconds(),
                });
                // Record that the announcer told us about this subject;
                // useful if we ever want to avoid re-announcing it back.
                peerTable.markAnnouncedTo(identity.fingerprint, parsed.announcedFingerprint, nowSeconds());
                return;

            }

            case TYPE_FORWARD: {

                const parsed = parseForwardPayload(packet.payload);
                if (parsed === null) {

                    // SPEC § 6.5: structural or prefix-mismatch failure.
                    // Attributable: the sender constructed a FORWARD that
                    // doesn't satisfy the spec.
                    peerTable.markInnerValidationFailed(packet.senderFingerprint);
                    return;

                }
                // SPEC § 6.5.1: rate limit before any further work.
                const accepted = forwardRateLimiter.checkAndCount({
                    sourceEphPk: packet.ephPk,
                    destFingerprint: parsed.nextHopFingerprint,
                });
                if (!accepted) return; // silent drop, no attribution
                forwardSend({
                    nextHopFingerprint: parsed.nextHopFingerprint,
                    transports: parsed.transports,
                    innerPacket: parsed.innerPacket,
                });
                return;

            }

            default:
                // SPEC § 6.1: 0x05-0xFF reserved; drop.
                return;

        }

    };

    return { onInbound };

};
