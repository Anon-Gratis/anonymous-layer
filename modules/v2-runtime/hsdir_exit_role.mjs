// v2-runtime — HSDir exit role (Phase 1.5).
//
// Handles RELAY_DESCFETCH cells arriving at a relay's exit-side. Does
// an HTTPS GET against a hardcoded HSDir URL (the DA) and streams the
// response back as RELAY_DESCFETCH_REPLY cells, terminated by
// RELAY_DESCFETCH_END.
//
// Privacy: the relay learns which address-body the client requested
// (this is unavoidable — the lookup key is the question). But:
//   - The client's identity is hidden behind the 3-hop circuit; this
//     relay sees only its preceding hop, not the client.
//   - The destination is hardcoded; this role does NOT grant the
//     relay any general internet egress.
//   - The DA-side observer sees an HTTPS request from the relay, not
//     the client.
//
// Wired into the dispatcher's `onExitData` callback alongside the
// existing stream / RP / IP role handlers.

import {
    CMD_RELAY,
    buildCell,
} from '../v2/cells.mjs';
import {
    RELAY_DESCFETCH,
    RELAY_DESCFETCH_REPLY,
    RELAY_DESCFETCH_END,
    MAX_RELAY_DATA,
    buildRelayPayload,
} from '../v2/relay.mjs';
import { relayWrapBackward } from '../v2/circuit.mjs';

// Mirror of streams.mjs:sendBackwardFromExit. Wraps + sends a single
// backward cell on the inbound link.
const sendBackward = ({ circuit, relayCommand, streamId, data }) => {

    const relayPayload = buildRelayPayload({
        relayCommand, streamId, data,
        digestState: circuit.relayHop.backwardDigest,
    });
    const wrapped = relayWrapBackward(circuit.relayHop, relayPayload);
    circuit.inbound.link.sendCell(buildCell({
        circuitId: circuit.inbound.circuitId,
        command: CMD_RELAY,
        payload: wrapped,
    }));

};

// Validate the address-body the client supplied. Must match the same
// shape Caddy enforces server-side: 16–64 chars, [A-Za-z0-9_-].
const KEY_RE = /^[A-Za-z0-9_-]{16,64}$/;

const REPLY_HEADER_BYTES = 8; // 4-byte status + 4-byte total length

// Build the reply cells for a single fetch. Returns an iterable of
// `{ relayCommand, data }` objects in the order they should be sent.
// Caller wraps + transmits each one.
const buildReplyCells = ({ httpStatus, body }) => {

    const cells = [];
    const totalLen = body ? body.length : 0;
    const first = Buffer.alloc(REPLY_HEADER_BYTES + Math.min(totalLen, MAX_RELAY_DATA - REPLY_HEADER_BYTES));
    first.writeUInt32BE(httpStatus, 0);
    first.writeUInt32BE(totalLen, 4);
    let off = 0;
    if (totalLen > 0) {

        const room = MAX_RELAY_DATA - REPLY_HEADER_BYTES;
        const take = Math.min(totalLen, room);
        body.copy(first, REPLY_HEADER_BYTES, 0, take);
        off = take;

    }
    cells.push({ relayCommand: RELAY_DESCFETCH_REPLY, data: first });

    while (off < totalLen) {

        const take = Math.min(totalLen - off, MAX_RELAY_DATA);
        const chunk = Buffer.alloc(take);
        body.copy(chunk, 0, off, off + take);
        cells.push({ relayCommand: RELAY_DESCFETCH_REPLY, data: chunk });
        off += take;

    }
    cells.push({ relayCommand: RELAY_DESCFETCH_END, data: Buffer.alloc(0) });
    return cells;

};

// Configure the role. `daBaseUrl` is the HSDir endpoint the relay
// fetches from (e.g. https://da1.anon.gratis). `fetchImpl` is
// dependency-injected for tests; defaults to global fetch.
//
// Returns:
//   {
//     handleData({ circuit, streamId, relayCommand, data })
//                    — call from onExitData; dispatches DESCFETCH only.
//     stats: () => { fetched, failed, lastError }
//   }
export const createHsdirExitRole = ({
    daBaseUrl,
    fetchImpl = (typeof fetch === 'function' ? fetch : null),
    fetchTimeoutMs = 10000,
    logger = () => {},
}) => {

    if (!daBaseUrl) throw new Error('createHsdirExitRole: daBaseUrl required');
    if (!fetchImpl) throw new Error('createHsdirExitRole: fetch implementation required');

    let fetched = 0;
    let failed = 0;
    let lastError = null;

    const handleDescfetch = async ({ circuit, streamId, data }) => {

        const key = Buffer.from(data).toString('utf8');
        if (!KEY_RE.test(key)) {

            failed += 1;
            lastError = `malformed key: ${key.slice(0, 32)}`;
            logger(`DESCFETCH reject malformed: ${key.slice(0, 32)}`);
            for (const c of buildReplyCells({ httpStatus: 0, body: null })) {

                sendBackward({
                    circuit,
                    relayCommand: c.relayCommand,
                    streamId,
                    data: c.data,
                });

            }
            return;

        }

        const url = `${daBaseUrl.replace(/\/+$/, '')}/hsdir/${key}`;
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), fetchTimeoutMs);

        let httpStatus = 0;
        let body = Buffer.alloc(0);
        try {

            const resp = await fetchImpl(url, { signal: ctrl.signal, cache: 'no-store' });
            httpStatus = resp.status;
            if (resp.ok) {

                const ab = await resp.arrayBuffer();
                body = Buffer.from(ab);

            }
            fetched += 1;
            logger(`DESCFETCH ${key} → HTTP ${httpStatus} (${body.length} bytes)`);

        } catch (e) {

            failed += 1;
            lastError = e.message;
            httpStatus = 0;
            logger(`DESCFETCH ${key} fetch failed: ${e.message}`);

        } finally {

            clearTimeout(timer);

        }

        for (const c of buildReplyCells({ httpStatus, body })) {

            sendBackward({
                circuit,
                relayCommand: c.relayCommand,
                streamId,
                data: c.data,
            });

        }

    };

    const handleData = (d) => {

        if (d.relayCommand !== RELAY_DESCFETCH) return; // not for us
        // Fire-and-forget; errors are surfaced to the client via the
        // synthetic-status reply cell.
        handleDescfetch(d).catch((err) => {

            failed += 1;
            lastError = err.message;
            logger(`DESCFETCH handler crashed: ${err.message}`);

        });

    };

    return {
        handleData,
        stats: () => ({ fetched, failed, lastError }),
    };

};

// Helper: parse a sequence of RELAY_DESCFETCH_REPLY cells (in order)
// followed by RELAY_DESCFETCH_END into { httpStatus, body }. Throws on
// inconsistency (short cells, length mismatch, missing END).
//
// Used by clients accumulating cells before they decide whether to
// trust the body. NOT used by the role itself.
export const parseDescfetchReplyStream = (replyCells, endCell) => {

    if (!Array.isArray(replyCells) || replyCells.length === 0) {

        throw new Error('parseDescfetchReplyStream: no reply cells');

    }
    if (!endCell || endCell.relayCommand !== RELAY_DESCFETCH_END) {

        throw new Error('parseDescfetchReplyStream: missing END terminator');

    }
    const first = replyCells[0].data;
    if (first.length < REPLY_HEADER_BYTES) {

        throw new Error('parseDescfetchReplyStream: first cell too short');

    }
    const httpStatus = first.readUInt32BE(0);
    const totalLen   = first.readUInt32BE(4);
    const collected  = Buffer.alloc(totalLen);
    let off = 0;
    // First cell may carry the start of the body in the same payload.
    const firstBody = first.subarray(REPLY_HEADER_BYTES);
    firstBody.copy(collected, off);
    off += firstBody.length;
    for (let i = 1; i < replyCells.length; i += 1) {

        replyCells[i].data.copy(collected, off);
        off += replyCells[i].data.length;

    }
    if (off !== totalLen) {

        throw new Error(`parseDescfetchReplyStream: length mismatch (got ${off}, want ${totalLen})`);

    }
    return { httpStatus, body: collected };

};
