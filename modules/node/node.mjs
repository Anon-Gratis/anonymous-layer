import { encodePacket } from '../wire/packet.mjs';
import { createReplayLog } from '../wire/replay.mjs';
import { createForwardRateLimiter } from '../wire/forward_rate_limit.mjs';
import {
    TYPE_DATA,
    TYPE_ANNOUNCE_PEER,
    TYPE_FORWARD,
    TYPE_KEY_CERTIFICATE,
} from '../wire/constants.mjs';
import { buildDataPayload } from '../wire/data.mjs';
import { buildAnnouncePeerPayload } from '../wire/announce.mjs';
import { buildKeyCertificatePayload } from '../wire/key_certificate.mjs';
import { buildForwardPayload } from '../wire/forward.mjs';
import { createDispatcher } from './dispatcher.mjs';
import { planAnnounces, planKeyCertificateSends } from '../peer/gossip.mjs';
import { mustRefuseTraffic } from '../peer/bootstrap.mjs';

// Top-level Node: ties identity, peer table, identity cache, wire
// state, dispatcher, and live transports together.
//
// Construction:
//   identity         createNodeIdentity() result
//   peerTable        createPeerTable() instance
//   identityCache    createIdentityCache() instance
//   currentCertBytes Most recent KEY_CERTIFICATE bytes for self
//   onData           ({senderFingerprint, conversationTag, sequenceNumber, payload}) => void
//   nowSeconds       () => number — clock
//
// Surface:
//   attach(peerFp, transport)  Register a live connection.
//   detach(peerFp)             Tear down a live connection.
//   send({...})                Send a DATA packet. Returns false if
//                              the recipient is unreachable.
//   sendKeyCertificate(fp)     Push our cert to a connected peer.
//   sendAnnouncePeer(rfp,sfp)  Gossip an ANNOUNCE_PEER about sfp to rfp.
//   forward({nextHopFp, innerPacket, transports})
//                              Outbound forward (we are the originator).
//   tick()                     Scheduler pass: gossip + cert sends.

const lastAnnounceAtPerRecipient = () => new Map();

export const createNode = ({
    identity,
    peerTable,
    identityCache,
    currentCertBytes,
    onData,
    onPeerConnected = null,
    onPeerDisconnected = null,
    nowSeconds = () => Math.floor(Date.now() / 1000),
} = {}) => {

    const replayLog = createReplayLog();
    const forwardRateLimiter = createForwardRateLimiter({ now: nowSeconds });
    const transports = new Map(); // hex(fp) → Transport
    const pendingTransports = new Set();
    // Transports that have completed a verified KEY_CERTIFICATE
    // handshake. We only fire onPeerConnected once we know who's on
    // the other end — a successful TCP/WS connect is not enough.
    const verifiedTransports = new WeakSet();
    // Peers we have advertised as connected via onPeerConnected. Used
    // to gate onPeerDisconnected so we never emit a disconnect for a
    // peer that was never reported as connected (e.g. a dial that
    // failed before the handshake).
    const advertisedConnected = new Set();
    const announceCadence = lastAnnounceAtPerRecipient();

    const keyOf = (fp) => Buffer.from(fp).toString('hex');

    const emitDisconnect = (peerFp) => {

        const key = keyOf(peerFp);
        if (!advertisedConnected.has(key)) return;
        advertisedConnected.delete(key);
        if (onPeerDisconnected) onPeerDisconnected(peerFp);

    };

    // Always-on: cache our own identity in the identity cache so we can
    // dispatch our own ANNOUNCE_PEER about other peers later.
    identityCache.set(identity.idPk);

    // forwardSend is given to the dispatcher so it can hand off
    // received FORWARD packets to the relay path.
    const forwardSend = ({ nextHopFingerprint, /* transports, */ innerPacket }) => {

        const peerTransport = transports.get(keyOf(nextHopFingerprint));
        if (!peerTransport) {

            // SPEC § 8.3 / § 6.5: forwarder doesn't dial new connections
            // mid-FORWARD in v0.1. If we don't have a live transport
            // to the next-hop, drop silently.
            return;

        }
        peerTransport.send(innerPacket);

    };

    // Forward-declare so dispatcher can call back into promote.
    let promotePending;

    const dispatcher = createDispatcher({
        identity,
        peerTable,
        identityCache,
        replayLog,
        forwardRateLimiter,
        onData,
        forwardSend,
        learnPeerOnTransport: (fp, transport) => promotePending(fp, transport),
        nowSeconds,
    });

    // attach is called for OUTBOUND connections where we already know
    // the peer's fingerprint (from the seed list). The WS open does
    // not by itself prove we're talking to *that* identity — the peer
    // could be a different node squatting on the address. We don't
    // fire onPeerConnected here; that happens when the peer's
    // KEY_CERTIFICATE arrives and verifies (see promotePending below).
    const attach = (peerFp, transport) => {

        const key = keyOf(peerFp);
        transports.set(key, transport);
        transport.onMessage((bytes) => dispatcher.onInbound(bytes, transport));
        transport.onClose(() => {

            if (transports.get(key) === transport) {

                transports.delete(key);
                peerTable.markDisconnected(peerFp);
                emitDisconnect(peerFp);

            }

        });
        peerTable.markConnected(peerFp);
        peerTable.markReachable(peerFp, nowSeconds());

    };

    // Accept an inbound transport whose peer fingerprint is not yet
    // known. The transport stays in `pendingTransports` until its
    // first valid KEY_CERTIFICATE arrives, at which point
    // promotePending binds it to the verified fingerprint.
    const acceptInbound = (transport) => {

        pendingTransports.add(transport);
        transport.onMessage((bytes) => dispatcher.onInbound(bytes, transport));
        transport.onClose(() => {

            pendingTransports.delete(transport);
            // A pending transport that closes before its KEY_CERTIFICATE
            // arrives leaves no peer-table state to clean up.

        });

    };

    // promotePending is the verified-handshake hook. The dispatcher
    // calls it from inside the KEY_CERTIFICATE handler after the cert
    // verifies. It serves two flows:
    //   - inbound: transport is in pendingTransports; promote it
    //   - outbound: transport is already in transports[fp] from attach();
    //     this is the moment we learn the remote really is `peerFp`
    // Either way, fire onPeerConnected at most once per transport.
    promotePending = (peerFp, transport) => {

        if (verifiedTransports.has(transport)) return;
        verifiedTransports.add(transport);

        const key = keyOf(peerFp);
        const existing = transports.get(key);

        if (existing !== transport) {

            // Either the transport was pending (no map entry yet) or
            // a different transport claimed this fp before (most often:
            // both sides dialed each other simultaneously). We prefer
            // the newly-verified transport for outbound sends but do
            // NOT close the existing one — closing it would cascade
            // through the other side's promote and tear down their
            // primary socket too. The orphaned transport stays open
            // until the peer closes it; its onMessage continues to
            // feed the dispatcher and any duplicate packets are
            // rejected by the replay log. A future Phase 5 hardening
            // can introduce a deterministic tiebreaker (e.g. compare
            // fingerprints) to converge to a single socket.
            pendingTransports.delete(transport);
            transports.set(key, transport);
            transport.onClose(() => {

                if (transports.get(key) === transport) {

                    transports.delete(key);
                    peerTable.markDisconnected(peerFp);
                    emitDisconnect(peerFp);

                }

            });

        }

        peerTable.markConnected(peerFp);
        peerTable.markReachable(peerFp, nowSeconds());

        if (!advertisedConnected.has(key)) {

            advertisedConnected.add(key);
            if (onPeerConnected) onPeerConnected(peerFp);

        }

    };

    const detach = (peerFp) => {

        const key = keyOf(peerFp);
        const t = transports.get(key);
        if (t) {

            t.close();
            transports.delete(key);

        }
        peerTable.markDisconnected(peerFp);
        emitDisconnect(peerFp);

    };

    // Build + send a packet of arbitrary type to a peer. Returns false
    // when the peer is unreachable (no live transport, or unknown).
    const sendTyped = ({ recipientFp, packetType, payload }) => {

        const peer = peerTable.get(recipientFp);
        if (!peer || !peer.onionPk) return false;
        const t = transports.get(keyOf(recipientFp));
        if (!t) return false;
        const packet = encodePacket({
            recipientIdPk: peer.idPk,
            recipientOnionPk: peer.onionPk,
            senderFingerprint: identity.fingerprint,
            packetType,
            payload,
        });
        t.send(packet);
        return true;

    };

    const send = ({ recipientFp, conversationTag, sequenceNumber, payload }) => {

        if (mustRefuseTraffic(peerTable)) return false;
        const dataPayload = buildDataPayload({ conversationTag, sequenceNumber, payload });
        return sendTyped({ recipientFp, packetType: TYPE_DATA, payload: dataPayload });

    };

    const sendKeyCertificate = (recipientFp) => {

        const payload = buildKeyCertificatePayload({
            idPk: identity.idPk,
            certBytes: currentCertBytes,
        });
        const ok = sendTyped({ recipientFp, packetType: TYPE_KEY_CERTIFICATE, payload });
        if (ok) peerTable.markKeyCertSentTo(recipientFp);
        return ok;

    };

    const sendAnnouncePeer = (recipientFp, subjectFp) => {

        const subject = peerTable.get(subjectFp);
        if (!subject) return false;
        const payload = buildAnnouncePeerPayload({
            announcedFingerprint: subject.fingerprint,
            certBytes: subject.certBytes,
            transports: subject.transports,
        });
        const ok = sendTyped({ recipientFp, packetType: TYPE_ANNOUNCE_PEER, payload });
        if (ok) {

            peerTable.markAnnouncedTo(recipientFp, subjectFp, nowSeconds());
            announceCadence.set(keyOf(recipientFp), nowSeconds());

        }
        return ok;

    };

    // Originate a FORWARD as the sender (not as a relay).
    // forwarderFp is the peer who will receive the FORWARD and relay
    // its inner packet onward; nextHopFp is the ultimate destination
    // named in the FORWARD payload. The inner packet must already be
    // encrypted to nextHopFp (its recipient_prefix is checked against
    // nextHopFp by parseForwardPayload per SPEC § 6.5).
    const forward = ({ forwarderFp, nextHopFp, transports: hopTransports, innerPacket }) => {

        const payload = buildForwardPayload({
            nextHopFingerprint: nextHopFp,
            transports: hopTransports,
            innerPacket,
        });
        return sendTyped({ recipientFp: forwarderFp, packetType: TYPE_FORWARD, payload });

    };

    // Scheduler pass. Should be called periodically (e.g. every 1-5s).
    const tick = () => {

        for (const recipientFp of planKeyCertificateSends(peerTable)) {

            sendKeyCertificate(recipientFp);

        }
        const announces = planAnnounces(peerTable, announceCadence, nowSeconds());
        for (const { recipientFp, subjectFp } of announces) {

            sendAnnouncePeer(recipientFp, subjectFp);

        }

    };

    return {
        attach,
        acceptInbound,
        detach,
        send,
        sendKeyCertificate,
        sendAnnouncePeer,
        forward,
        tick,
    };

};
