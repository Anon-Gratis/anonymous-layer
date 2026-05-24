// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE
//
// Reference v0.2 runtime, see docs/SPEC-v0.2-draft.md.
// The draft has open architectural questions; the code has not been
// audited. Do not rely on this for anonymity.

// LinkManager — tracks active LINK_AUTH-verified links by peer
// fingerprint, deduplicates simultaneous opens, and dispatches
// post-handshake cells to a single onCell callback.
//
// Lifecycle:
//   - `acceptLink({ peerIdPk, transport })` registers a verified link
//     (called by the listener after `createLinkListener`'s onLink).
//   - `ensureLink({ peerIdPk, host, port })` returns an existing link
//     to a peer, or dials a new one and registers it. Used by the
//     circuit-extending side to make sure a link to the next-hop
//     relay is available before sending CREATE through it.
//   - `getLink(peerFingerprint)` returns the active link or null.
//   - `closeAll()` closes every active link (used during shutdown).

import { fingerprint as blake2bFingerprint } from '../crypto/fingerprint.mjs';
import { dialLink } from './link_transport_ws.mjs';

const fpKey = (idPk) => Buffer.from(blake2bFingerprint(idPk)).toString('hex');

export const createLinkManager = ({
    identity,
    onCell,         // (link, cell) — incoming cell on any established link
    onLinkOpen = () => {},
    onLinkClose = () => {},
    dialTimeoutMs = 15000,
}) => {

    // fpKey → { transport, peerIdPk, openedAt }
    const links = new Map();
    // fpKey → Promise<link> (pending dials, to dedupe simultaneous opens)
    const dialing = new Map();

    const installLink = ({ peerIdPk, transport }) => {

        const key = fpKey(peerIdPk);

        // Deduplicate: if a link to this peer already exists, prefer
        // the existing one and close the new one. The convention
        // matches Tor's "use the link with the lower fingerprint
        // breaking ties" approach but for simplicity v0.2 just keeps
        // the first one.
        if (links.has(key)) {

            try { transport.close(); } catch { /* ignore */ }
            return links.get(key);

        }

        const link = {
            peerIdPk: new Uint8Array(peerIdPk),
            peerFingerprintHex: key,
            transport,
            openedAt: Date.now(),
            sendCell: (cell) => transport.sendCell(cell),
            close: () => {

                try { transport.close(); } catch { /* ignore */ }

            },
        };

        transport.onCell((cell) => {

            try { onCell(link, cell); } catch {

                // A handler error should not kill the link; log if you
                // care, but proceed.

            }

        });

        transport.onClose(() => {

            links.delete(key);
            try { onLinkClose(link); } catch { /* ignore */ }

        });

        links.set(key, link);
        try { onLinkOpen(link); } catch { /* ignore */ }
        return link;

    };

    // Called by the listener's onLink callback for each verified
    // inbound connection.
    const acceptLink = ({ peerIdPk, transport }) => installLink({ peerIdPk, transport });

    // Get an existing link to a peer (by their idPk). Returns null if none.
    const getLink = (peerIdPk) => links.get(fpKey(peerIdPk)) || null;

    // Ensure a link exists to a peer by dialing if needed. Returns
    // the link. If a dial to this peer is already in flight, awaits it.
    const ensureLink = async ({ peerIdPk, host, port }) => {

        const key = fpKey(peerIdPk);
        const existing = links.get(key);
        if (existing) return existing;
        const inFlight = dialing.get(key);
        if (inFlight) return inFlight;

        const promise = (async () => {

            try {

                const { peerIdPk: verifiedIdPk, transport } = await dialLink({
                    host, port, identity, expectedPeerIdPk: peerIdPk,
                    timeoutMs: dialTimeoutMs,
                });
                return installLink({ peerIdPk: verifiedIdPk, transport });

            } finally {

                dialing.delete(key);

            }

        })();
        dialing.set(key, promise);
        return promise;

    };

    const getLinkCount = () => links.size;

    const closeAll = () => {

        for (const link of links.values()) {

            try { link.close(); } catch { /* ignore */ }

        }
        links.clear();

    };

    return {
        acceptLink,
        ensureLink,
        getLink,
        getLinkCount,
        closeAll,

    };

};
