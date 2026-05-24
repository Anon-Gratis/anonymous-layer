// v2-runtime — circuit-routed HSDir descriptor fetcher (Phase 1.5).
//
// Builds a 3-hop circuit, sends a RELAY_DESCFETCH cell carrying the
// address body to the exit relay, collects RELAY_DESCFETCH_REPLY cells
// in order until RELAY_DESCFETCH_END arrives, and assembles the
// response body. Equivalent privacy property to Tor's directory
// tunnels: the DA only sees a fetch from the exit relay, not from
// the actual client.
//
// Usage:
//   const fetchDescriptor = createDescfetchOverCircuit({
//       circuitBuilder, buildPath,
//   });
//   const { httpStatus, body } = await fetchDescriptor({
//       address: 'anona4y4....anon',
//   });
//
// Returns null body on httpStatus 0 (relay-side synthetic error) or
// non-2xx HTTP status; caller checks httpStatus before parsing body.
// Throws on circuit-build failure, timeout, or malformed reply cells.

import {
    CMD_RELAY,           // unused at call-site; kept for parity
    buildCell,           // ditto
} from '../v2/cells.mjs';
import {
    RELAY_DESCFETCH,
    RELAY_DESCFETCH_REPLY,
    RELAY_DESCFETCH_END,
    MAX_RELAY_DATA,
    buildRelayPayload,
} from '../v2/relay.mjs';
import { encryptOutbound } from '../v2/circuit.mjs';
import { ONION_ADDR_SUFFIX } from '../v2/onion_address.mjs';
import { parseDescfetchReplyStream } from './hsdir_exit_role.mjs';

const DESCFETCH_STREAM_ID = 0x0042; // arbitrary; not multiplexed

const lookupKeyForAddress = (address) => {

    const a = String(address || '').trim().toLowerCase();
    if (!a.endsWith(ONION_ADDR_SUFFIX)) {

        throw new Error(`address missing ${ONION_ADDR_SUFFIX} suffix: ${address}`);

    }
    const body = a.slice(0, -ONION_ADDR_SUFFIX.length);
    if (!/^[a-z2-7]{16,64}$/.test(body)) {

        throw new Error(`malformed .anon address body: ${body}`);

    }
    return body;

};

// Send a single relay-payload forward through `circuit` via its
// entry-link. Mirrors the sendForward used in rendezvous_client.mjs.
const sendForward = ({ circuit, entryLink, relayCommand, streamId, data }) => {

    const exitHop = circuit.hops[circuit.hops.length - 1];
    const relayPayload = buildRelayPayload({
        relayCommand, streamId, data,
        digestState: exitHop.forwardDigest,
    });
    const cipher = encryptOutbound(circuit, relayPayload);
    entryLink.sendCell(buildCell({
        circuitId: circuit.circuitId,
        command: CMD_RELAY,
        payload: cipher,
    }));

};

// Factory. Returns a fetchDescriptor function.
//
// `circuitBuilder` — instance from createCircuitBuilder
// `buildPath`     — () => { guard, middle, exit } RSEs. Caller chooses
//                  the policy (random, exit-flagged, etc.); we don't
//                  care which relay is the exit as long as it supports
//                  the DESCFETCH role.
// `requestTimeoutMs` — total time budget per fetch (circuit + request).
export const createDescfetchOverCircuit = ({
    circuitBuilder,
    buildPath,
    requestTimeoutMs = 15000,
    logger = () => {},
}) => {

    if (typeof circuitBuilder?.buildCircuit !== 'function') {

        throw new Error('createDescfetchOverCircuit: circuitBuilder required');

    }
    if (typeof buildPath !== 'function') {

        throw new Error('createDescfetchOverCircuit: buildPath required');

    }

    const fetchDescriptor = async ({ address }) => {

        const key = lookupKeyForAddress(address);
        const path = buildPath();

        const replies = [];
        let endCell = null;
        let settle = null;
        const settled = new Promise((res, rej) => { settle = { res, rej }; });
        // Defensive no-op catch: prevents an unhandled-rejection process
        // crash if the descfetch timer (or onDestroy) fires after the
        // caller has already abandoned the await chain (e.g., circuit
        // teardown error before sendForward, or the consumer threw on
        // an earlier await). The real consumer at `await settled` below
        // still throws as expected — multiple handlers on a promise all
        // fire, and this one just silently satisfies Node's "is anyone
        // listening?" check.
        settled.catch(() => {});

        const timer = setTimeout(() => {

            settle.rej(new Error('descfetch timeout'));

        }, requestTimeoutMs);

        const onData = (d) => {

            if (d.relayCommand === RELAY_DESCFETCH_REPLY) {

                replies.push({ relayCommand: d.relayCommand, data: Buffer.from(d.data) });
                return;

            }
            if (d.relayCommand === RELAY_DESCFETCH_END) {

                endCell = { relayCommand: d.relayCommand, data: Buffer.from(d.data) };
                clearTimeout(timer);
                try {

                    const { httpStatus, body } = parseDescfetchReplyStream(replies, endCell);
                    settle.res({ httpStatus, body });

                } catch (e) {

                    settle.rej(e);

                }
                return;

            }
            // Other RELAY_* commands on this circuit are unexpected; ignore.

        };

        const onDestroy = (reason) => {

            clearTimeout(timer);
            settle.rej(new Error(`circuit destroyed: ${reason}`));

        };

        logger(`descfetch ${key} via circuit ${path.guard.fingerprint.slice(0, 4).toString('hex')}…/${path.middle.fingerprint.slice(0, 4).toString('hex')}…/${path.exit.fingerprint.slice(0, 4).toString('hex')}…`);

        const built = await circuitBuilder.buildCircuit({ path, onData, onDestroy });

        // Send the DESCFETCH cell now that the circuit is live.
        sendForward({
            circuit: built.circuit,
            entryLink: built.entryLink,
            relayCommand: RELAY_DESCFETCH,
            streamId: DESCFETCH_STREAM_ID,
            data: Buffer.from(key, 'utf8'),
        });

        const result = await settled;
        // Tear down the circuit — this was a one-shot request.
        try { built.circuit.destroy && built.circuit.destroy(); } catch { /* ignore */ }
        return result;

    };

    return fetchDescriptor;

};
