import { dialWebSocket } from './transport_websocket.mjs';

// Outbound connection manager. Maintains one outbound transport per
// known peer, redialing on close with exponential backoff + jitter.
//
// Construction:
//   node          createNode() instance
//   logger        local logger (modules/node/logger.mjs)
//   nowMs         () => number — for deterministic tests
//   baseDelayMs   first retry delay (default 1000)
//   maxDelayMs    cap on exponential growth (default 300_000 = 5 min)
//   transportFactory  (host, port) => Transport — overridable for tests
//                     that don't want real WebSockets
//
// Surface:
//   connect(peer)     start dialing { fingerprint, host, port }
//   disconnect(fp)    stop dialing, detach
//   stop()            cancel all pending retries, detach all
//   state(fp)         { attempts, nextRetryAt } | null — for tests
//
// Reconnect schedule: attempt N is scheduled at min(baseDelay * 2^N,
// maxDelay), jittered by ±20%. Successful connections reset the
// attempt counter (next disconnect starts at baseDelay again).

const DEFAULT_BASE_DELAY_MS = 1000;
const DEFAULT_MAX_DELAY_MS = 300_000;
const JITTER_FRACTION = 0.2;

const computeBackoff = (attempt, baseDelayMs, maxDelayMs) => {

    const ideal = Math.min(baseDelayMs * (2 ** attempt), maxDelayMs);
    const jitter = ideal * JITTER_FRACTION * (Math.random() * 2 - 1);
    return Math.max(0, Math.floor(ideal + jitter));

};

export const createDialer = ({
    node,
    logger,
    nowMs = () => Date.now(),
    baseDelayMs = DEFAULT_BASE_DELAY_MS,
    maxDelayMs = DEFAULT_MAX_DELAY_MS,
    transportFactory = ({ host, port }) => dialWebSocket({ host, port }),
    schedule = (cb, ms) => setTimeout(cb, ms),
    cancel = (handle) => clearTimeout(handle),
} = {}) => {

    // hex(fp) → { peer, attempts, timer, transport, stopped }
    const state = new Map();
    const keyOf = (fp) => Buffer.from(fp).toString('hex');

    const tryDial = (entry) => {

        if (entry.stopped) return;

        entry.attempts += 1;
        logger.info('dialer dialing', {
            host: entry.peer.host,
            port: entry.peer.port,
            attempt: entry.attempts,
        });

        const transport = transportFactory({ host: entry.peer.host, port: entry.peer.port });
        entry.transport = transport;

        // node.attach installs its own onMessage and onClose. We
        // overwrite onClose afterwards with our retry-aware handler
        // that also performs attach's bookkeeping (via node.detach).
        node.attach(entry.peer.fingerprint, transport);

        transport.onClose(() => {

            node.detach(entry.peer.fingerprint);
            entry.transport = null;
            if (entry.stopped) return;
            const delay = computeBackoff(entry.attempts, baseDelayMs, maxDelayMs);
            logger.info('dialer disconnected; will retry', {
                host: entry.peer.host,
                port: entry.peer.port,
                delayMs: delay,
            });
            entry.timer = schedule(() => tryDial(entry), delay);

        });

    };

    const connect = (peer) => {

        const key = keyOf(peer.fingerprint);
        if (state.has(key)) return; // already dialing
        const entry = {
            peer,
            attempts: 0,
            timer: null,
            transport: null,
            stopped: false,
        };
        state.set(key, entry);
        tryDial(entry);

    };

    const disconnect = (fp) => {

        const entry = state.get(keyOf(fp));
        if (!entry) return;
        entry.stopped = true;
        if (entry.timer) {

            cancel(entry.timer);
            entry.timer = null;

        }
        if (entry.transport) {

            try { entry.transport.close(); } catch { /* ignore */ }

        }
        node.detach(fp);
        state.delete(keyOf(fp));

    };

    const stop = () => {

        for (const key of Array.from(state.keys())) {

            const entry = state.get(key);
            entry.stopped = true;
            if (entry.timer) cancel(entry.timer);
            if (entry.transport) {

                try { entry.transport.close(); } catch { /* ignore */ }

            }
            // Reconstruct fp from hex key for the detach call.
            const fp = Buffer.from(key, 'hex');
            node.detach(fp);

        }
        state.clear();

    };

    const inspect = (fp) => {

        const entry = state.get(keyOf(fp));
        if (!entry) return null;
        return { attempts: entry.attempts, connected: entry.transport !== null };

    };

    return { connect, disconnect, stop, inspect };

};
