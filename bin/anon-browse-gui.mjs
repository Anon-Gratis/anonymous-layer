#!/usr/bin/env node
// anon-browse-gui — graphical browser for the anon-layer network.
//
// Architecture:
//   1. This binary starts the anon-layer runtime (LinkManager,
//      CircuitBuilder, etc.) — same as bin/anon-browse.mjs.
//   2. It also starts a tiny HTTP server on 127.0.0.1.
//   3. The server serves an HTML/CSS/JS UI; the UI calls a JSON API
//      (/api/fetch?url=...) which fetches via the anon-layer runtime
//      and returns parsed text/anon as a structured line array.
//   4. The user opens http://127.0.0.1:<port>/?token=<...> in their
//      existing browser. JS in the page renders to DOM.
//
// Trade-offs vs a standalone GUI app (Electron / Tauri):
//   PROS:
//     - ~500 LOC, no Chromium bundle, no Rust toolchain, no per-
//       platform packaging.
//     - The anon-layer runtime stays in plain Node, easy to audit.
//   CONS:
//     - Your existing browser is the renderer. Its history,
//       fingerprinting, cache concerns apply.
//     - Bind is 127.0.0.1 by default + session token gates the API,
//       but a malicious local process on your machine can still see
//       the API exists.
//
// For real anonymity needs today, use Tor. This is reference
// software, not a production tool.

import { createServer as createHttpServer } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { createConnection } from 'node:net';
import { randomBytes } from 'node:crypto';
import { writeFile, rename } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { queryTorCircuitForHost } from '../modules/v2-runtime/tor_controller.mjs';

// Resolve where the bundled tor's runtime dir lives so the
// /api/tor-circuit handler can authenticate to its control port.
// Install layout: AnonLayer/bridge/bin/anon-browse-gui.mjs ─→
//                 AnonLayer/tor/run/{torrc, data/control_auth_cookie}
// Override via ANON_TOR_RUNTIME for dev / non-bundled runs.
const TOR_RUNTIME_DIR = process.env.ANON_TOR_RUNTIME
  || join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'tor', 'run');

import { fetchOnce } from '../modules/v2-site/client.mjs';
import {
    parseSuccessMeta, isSuccess, isRedirect, isInput,
} from '../modules/v2-site/response.mjs';
import { parseDocument } from '../modules/v2-site/text_anon.mjs';
import { createNodeIdentity } from '../modules/v2-runtime/persistence.mjs';
import { createLinkManager } from '../modules/v2-runtime/link_manager.mjs';
import { createCircuitDispatcher } from '../modules/v2-runtime/circuit_dispatcher.mjs';
import { createCellRouter } from '../modules/v2-runtime/cell_router.mjs';
import { createPeerResolver } from '../modules/v2-runtime/peer_resolver.mjs';
import { createCircuitBuilder } from '../modules/v2-runtime/circuit_builder.mjs';
import { openHiddenService } from '../modules/v2-runtime/rendezvous_client.mjs';
import { StreamDuplex } from '../modules/v2-runtime/stream_duplex.mjs';
import {
    loadConsensus, loadDaTrustSet,
} from '../modules/v2-runtime/consensus_loader.mjs';
import { createDescriptorIndex } from '../modules/v2-runtime/descriptor_index.mjs';
import { createHsdirClient } from '../modules/v2-runtime/hsdir_client.mjs';
import { createDescfetchOverCircuit } from '../modules/v2-runtime/hsdir_circuit_fetch.mjs';
import {
    selectMiddle,
    FLAG_GUARD, FLAG_RUNNING, FLAG_VALID,
} from '../modules/v2/consensus.mjs';

const USAGE = `\
anon-browse-gui — GUI browser via your local browser

Modes:
  --connect HOST:PORT                Dial TCP directly (dev).
  --consensus P --da-trust P
      ( --descriptor P | --descriptor-dir D | both )
                                     Real rendezvous. Descriptors index by
                                     onion address; the per-URL .anon host
                                     selects which service to rendezvous
                                     with. --descriptor is a single .bin
                                     file; --descriptor-dir is a directory
                                     whose *.bin files all load at startup.
                                     Pass both for back-compat with single-
                                     descriptor configs.
  [--allow-co-located]               Testnet path-diversity relaxation.

Server flags:
  --listen HOST                      Bind address. Default 127.0.0.1.
  --port N                           Listen port. Default: random (printed at startup).
  --open                             Print the URL prefixed for easy
                                     terminal-click (no actual browser launch;
                                     a v1.0 future-work item).
  --no-token                         Skip the session-token gate. ONLY safe when
                                     --listen is 127.0.0.1/::1 and you control the
                                     full process tree (e.g. the launcher script
                                     for the bundled Anon Browser). Refuses to
                                     start if --listen is non-loopback.
  --refresh-from URL1,URL2,...       DA HTTPS endpoints to download a fresh
                                     consensus.bin from before startup and
                                     periodically while running. Atomically
                                     overwrites --consensus. If every URL
                                     fails, the existing on-disk file is used
                                     as-is. No-op if --consensus isn't set.
  --refresh-interval-sec N           How often to re-fetch from --refresh-from
                                     while the bridge runs. Default 1200 (20 min).
                                     0 = startup-only, no periodic.
`;

const die = (msg, code = 1) => { process.stderr.write(`error: ${msg}\n`); process.exit(code); };
const log = (msg) => process.stderr.write(`[${new Date().toISOString()}] ${msg}\n`);

const parseArgs = () => {

    const args = process.argv.slice(2);
    if (args.length === 0) { process.stdout.write(USAGE); process.exit(0); }
    const opts = {
        connect: null,
        consensusPath: null, daTrustPath: null,
        descriptorPath: null, descriptorDir: null,
        hsdirUrl: null,
        listen: '127.0.0.1', port: 0,
        skipAntiCorrelation: false, open: false, noToken: false,
        // --refresh-from <url1,url2,...>: if set, try to download a
        // fresh consensus.bin from each URL (in order) before loading
        // the on-disk consensus, and then re-download every
        // refreshIntervalSec while running. Falls back silently to the
        // cached file if every URL fails. Set refreshIntervalSec=0 to
        // disable the periodic refresh and only refresh once at startup.
        refreshFrom: [],
        refreshIntervalSec: 20 * 60,  // 20 min
    };
    for (let i = 0; i < args.length; i += 1) {

        const a = args[i];
        if (a === '--help' || a === '-h') { process.stdout.write(USAGE); process.exit(0); }
        if (a === '--connect')          { opts.connect = args[i + 1]; i += 1; continue; }
        if (a === '--consensus')        { opts.consensusPath = args[i + 1]; i += 1; continue; }
        if (a === '--da-trust')         { opts.daTrustPath = args[i + 1]; i += 1; continue; }
        if (a === '--descriptor')       { opts.descriptorPath = args[i + 1]; i += 1; continue; }
        if (a === '--descriptor-dir')   { opts.descriptorDir = args[i + 1]; i += 1; continue; }
        if (a === '--hsdir-url')        { opts.hsdirUrl = args[i + 1]; i += 1; continue; }
        if (a === '--listen')           { opts.listen = args[i + 1]; i += 1; continue; }
        if (a === '--port')             { opts.port = parseInt(args[i + 1], 10); i += 1; continue; }
        if (a === '--refresh-from')     {
            opts.refreshFrom = String(args[i + 1] || '')
                .split(',').map((s) => s.trim()).filter((s) => s.length);
            i += 1; continue;
        }
        if (a === '--refresh-interval-sec') {
            opts.refreshIntervalSec = parseInt(args[i + 1], 10);
            i += 1; continue;
        }
        if (a === '--allow-co-located') { opts.skipAntiCorrelation = true; continue; }
        if (a === '--open')             { opts.open = true; continue; }
        if (a === '--no-token')         { opts.noToken = true; continue; }
        if (a.startsWith('--')) die(`unknown option: ${a}`);
        die(`unexpected argument: ${a}`);

    }
    if (opts.noToken) {

        const isLoopback = opts.listen === '127.0.0.1'
            || opts.listen === '::1'
            || opts.listen === 'localhost'
            || /^127\.\d+\.\d+\.\d+$/.test(opts.listen);
        if (!isLoopback) {

            die(`--no-token refuses to bind a non-loopback address (got ${opts.listen}). `
                + 'The token gate is the only thing keeping LAN-reachable clients out.');

        }

    }
    const hasDirect = opts.connect !== null;
    const hasDescriptorSrc = opts.descriptorPath !== null
        || opts.descriptorDir !== null
        || opts.hsdirUrl !== null;
    const hasRendezvous = opts.consensusPath || opts.daTrustPath || hasDescriptorSrc;
    if (hasDirect && hasRendezvous) die('pick --connect OR rendezvous flags, not both');
    if (!hasDirect && !hasRendezvous) {
        die('one mode required: --connect or --consensus/--da-trust/(at least one descriptor source)');
    }
    if (hasRendezvous && !(opts.consensusPath && opts.daTrustPath && hasDescriptorSrc)) {

        die('rendezvous mode requires --consensus, --da-trust, and at least one descriptor source '
            + '(--descriptor, --descriptor-dir, or --hsdir-url)');

    }
    if (hasDirect) {

        const [h, ps] = opts.connect.split(':');
        const p = parseInt(ps, 10);
        if (!h || !Number.isInteger(p)) die(`bad --connect value: ${opts.connect}`);
        opts.connectHost = h; opts.connectPort = p;

    }
    return { ...opts, mode: hasDirect ? 'connect' : 'rendezvous' };

};

// ----- Backend: build an `acquireSocket` based on mode (mirrors anon-browse) -----
//
// Contract: acquireSocket(url) → Duplex/Socket for a single fetch.
// The URL is passed through so the rendezvous acquirer can route by
// `.anon` host. The direct acquirer ignores the URL — single pinned
// destination.

const buildDirectAcquirer = ({ host, port }) => async (_url) => new Promise((res, rej) => {

    const s = createConnection({ host, port });
    s.once('connect', () => res(s));
    s.once('error', rej);

});

// Extract the `.anon` host from an anon:// URL. Returns null if the
// URL is malformed or non-anon-scheme.
const extractAnonHost = (url) => {

    if (typeof url !== 'string') return null;
    const ANON = 'anon://';
    if (!url.startsWith(ANON)) return null;
    const rest = url.slice(ANON.length);
    const stop = rest.search(/[\/?#]/);
    const host = stop === -1 ? rest : rest.slice(0, stop);
    return host.toLowerCase() || null;

};

// Fetch a fresh consensus.bin from one of the configured DA HTTPS
// endpoints and atomically write it to `dest`. Mirrors the launcher's
// `fetch_consensus()` so a manual `node anon-browse-gui.mjs` restart
// gets the same fresh-on-startup behavior as `./anonymous`. Returns
// true if any URL succeeded, false if all failed (in which case the
// existing on-disk consensus is left untouched — stale-but-cached
// beats hard failure).
const fetchConsensus = ({ urls, dest, timeoutMs = 15_000 }) => new Promise((resolve) => {

    if (!urls.length || !dest) { resolve(false); return; }
    let i = 0;
    const tryNext = () => {

        if (i >= urls.length) {

            log(`refresh: all DAs failed; keeping cached ${dest}`);
            resolve(false);
            return;

        }
        const u = urls[i]; i += 1;
        const cleaned = u.replace(/\/+$/, '');
        let target;
        try { target = new URL(cleaned + '/consensus.bin'); }
        catch { log(`refresh: bad URL ${u}`); tryNext(); return; }

        log(`refresh: fetching consensus from ${cleaned}`);
        const req = httpsRequest({
            hostname: target.hostname,
            port: target.port || 443,
            path: target.pathname,
            method: 'GET',
            headers: { 'user-agent': 'anon-bridge/1' },
        }, (response) => {

            if (response.statusCode !== 200) {

                log(`refresh: ${cleaned} → HTTP ${response.statusCode}`);
                response.resume();
                tryNext(); return;

            }
            const chunks = [];
            response.on('data', (c) => chunks.push(c));
            response.on('error', (e) => { log(`refresh: ${cleaned} stream error: ${e.message}`); tryNext(); });
            response.on('end', async () => {

                const body = Buffer.concat(chunks);
                if (body.length === 0) { log(`refresh: ${cleaned} returned 0 bytes`); tryNext(); return; }
                try {

                    const tmp = `${dest}.tmp.${process.pid}`;
                    await writeFile(tmp, body);
                    await rename(tmp, dest);
                    log(`refresh: wrote ${body.length} bytes from ${cleaned}`);
                    resolve(true);

                } catch (e) {

                    log(`refresh: write to ${dest} failed: ${e.message}`);
                    tryNext();

                }

            });

        });
        req.on('error', (e) => { log(`refresh: ${cleaned}: ${e.message}`); tryNext(); });
        req.setTimeout(timeoutMs, () => req.destroy(new Error('timeout')));
        req.end();

    };
    tryNext();

});

const buildRendezvousAcquirer = async ({
    consensusPath, daTrustPath,
    descriptorPath, descriptorDir, hsdirUrl,
    skipAntiCorrelation,
}) => {

    const daTrust = await loadDaTrustSet(daTrustPath);
    const consensus = await loadConsensus({ path: consensusPath, daTrustSet: daTrust });

    // Local index is allowed to be empty when --hsdir-url is set; we
    // can fetch descriptors on demand. Otherwise it's required (the
    // bridge has nothing to route to).
    let index = null;
    const haveLocal = descriptorPath || descriptorDir;
    if (haveLocal) {
        index = await createDescriptorIndex({
            paths: descriptorPath ? [descriptorPath] : [],
            dir: descriptorDir,
            logger: (m) => log(`  ${m}`),
        });
        log(`descriptor index ready (${index.size} service${index.size === 1 ? '' : 's'})`);
    } else {
        log('no local descriptor source; relying on HSDir fallback');
    }

    const clientIdentity = createNodeIdentity();
    const peerResolver = createPeerResolver({ consensus });
    const routerHolder = { router: null };
    const linkMgr = createLinkManager({
        identity: clientIdentity,
        onCell: (link, cell) => { if (routerHolder.router) routerHolder.router.onCell(link, cell); },
    });
    const dispatcher = createCircuitDispatcher({
        identity: clientIdentity, linkManager: linkMgr, peerResolver,
    });
    routerHolder.router = createCellRouter({ relayDispatcher: dispatcher });
    const circuitBuilder = createCircuitBuilder({
        linkManager: linkMgr, cellRouter: routerHolder.router, peerResolver,
        logger: (m) => log(`  [v2-build] ${m}`),
    });

    // hsdir client uses circuitBuilder for circuit-routed lookups —
    // construct it after the builder exists.
    const hsdir = hsdirUrl
        ? createHsdirClient({
            daBaseUrl: hsdirUrl,
            // Circuit-routed fetch: a 3-hop circuit terminating at an
            // exit relay that runs createHsdirExitRole. Falls back to
            // direct HTTPS inside the hsdir client if any step fails.
            circuitFetcher: createDescfetchOverCircuit({
                circuitBuilder,
                buildPath: () => {

                    // Random 3-hop path; any relay can answer DESCFETCH
                    // (assuming the operator armed --hsdir-url on it).
                    const guards = consensus.rses.filter((r) => (
                        (r.flags & (FLAG_RUNNING | FLAG_VALID | FLAG_GUARD)) === (FLAG_RUNNING | FLAG_VALID | FLAG_GUARD)
                    ));
                    if (guards.length === 0) throw new Error('no guard candidates');
                    const guard = guards[Math.floor(Math.random() * guards.length)];
                    const others = consensus.rses.filter((r) => !fpEq(r.fingerprint, guard.fingerprint));
                    if (others.length < 2) throw new Error('not enough relays for a 3-hop circuit');
                    const exit = others[Math.floor(Math.random() * others.length)];
                    const middle = selectMiddle({
                        consensus,
                        excludeFps: [guard.fingerprint, exit.fingerprint],
                        coLocateAvoid: skipAntiCorrelation ? [] : [guard, exit],
                    });
                    if (!middle) throw new Error('no middle candidate');
                    return { guard, middle, exit };

                },
                logger: (m) => log(`  ${m}`),
            }),
            logger: (m) => log(`  ${m}`),
        })
        : null;
    if (hsdir) log(`hsdir armed: ${hsdirUrl} (circuit-routed + direct fallback)`);

    const fpEq = (a, b) => Buffer.from(a).equals(Buffer.from(b));
    const pickRand = (arr) => arr[Math.floor(Math.random() * arr.length)];
    const buildPath = ({ exitFingerprint }) => {

        const exitRse = consensus.rses.find((r) => fpEq(r.fingerprint, exitFingerprint));
        if (!exitRse) throw new Error('exit fingerprint not in consensus');
        const guardCandidates = consensus.rses.filter((r) => (
            (r.flags & (FLAG_RUNNING | FLAG_VALID | FLAG_GUARD)) === (FLAG_RUNNING | FLAG_VALID | FLAG_GUARD)
            && !fpEq(r.fingerprint, exitFingerprint)
        ));
        if (guardCandidates.length === 0) throw new Error('no guard candidate distinct from forced exit');
        const guard = pickRand(guardCandidates);
        const middle = selectMiddle({
            consensus,
            excludeFps: [guard.fingerprint, exitFingerprint],
            coLocateAvoid: skipAntiCorrelation ? [] : [guard, exitRse],
        });
        if (!middle) throw new Error('no middle candidate');
        return { guard, middle, exit: exitRse };

    };

    // Per-host connection cache. The rendezvous handshake is
    // expensive (4-hop circuit + ntor); once a service has a live
    // connection we reuse it for subsequent streams.
    const connByHost = new Map();
    const inFlight   = new Map(); // host → promise<conn>; coalesces concurrent first-loads

    // Per-host circuit topology cache. Populated as a side effect of
    // rpPathFn / ipPathFn so /api/circuit can answer "what's the path
    // to this .anon right now?" without re-running selection. Stored
    // in insertion order; latest paths are at the end of the arrays.
    const circuitByHost = new Map(); // host → { descriptor, rpPaths[], ipPaths[], firstSeenAt }

    // Compact, JSON-safe relay summary. We expose nickname + short
    // fingerprint; the user's browser is going to show this back to
    // them anyway and the relay is already paid-for in this circuit,
    // so there is no privacy gain in hiding it.
    const relaySummary = (rse) => {
        if (!rse) return null;
        const fpBuf = rse.fingerprint ? Buffer.from(rse.fingerprint) : null;
        return {
            nick:   rse.nickname || '(unnamed)',
            fp:     fpBuf ? fpBuf.toString('hex').slice(0, 8).toUpperCase() : '',
            addr:   rse.address || null,
            port:   typeof rse.port === 'number' ? rse.port : null,
            flags:  typeof rse.flags === 'number' ? rse.flags : null,
        };
    };

    const ensureConnFor = async (host) => {

        if (connByHost.has(host)) return connByHost.get(host);
        if (inFlight.has(host))   return inFlight.get(host);

        // Look-up order: (1) local index, (2) HSDir fallback.
        let descriptor = index ? index.lookup(host) : null;
        if (!descriptor && hsdir) {

            log(`descriptor not in local index; querying HSDir for ${host}`);
            descriptor = await hsdir.lookup(host);

        }
        if (!descriptor) {

            const localKnown = index ? index.addresses().slice(0, 3).join(', ') : '';
            throw new Error(
                `no descriptor known for ${host}. `
                + (hsdir ? `Tried local index + HSDir (${hsdirUrl}). ` : 'No HSDir configured. ')
                + (localKnown ? `Local: ${localKnown}.` : '')
            );

        }

        // Initialize the topology entry up front so concurrent
        // /api/circuit requests during the handshake see "building"
        // state rather than 404.
        const topo = {
            descriptor: {
                host,
                addr_fp: descriptor.fingerprint
                    ? Buffer.from(descriptor.fingerprint).toString('hex').slice(0, 16).toUpperCase()
                    : '',
            },
            rpPaths: [],
            ipPaths: [],
            firstSeenAt: Date.now(),
            state: 'building',
        };
        circuitByHost.set(host, topo);

        const tapPath = (path, bucket) => {
            try {
                bucket.push({
                    ts:     Date.now(),
                    guard:  relaySummary(path.guard),
                    middle: relaySummary(path.middle),
                    exit:   relaySummary(path.exit),
                });
                // Bound to last 8 paths per direction so a long-lived
                // service doesn't accrete unbounded history.
                while (bucket.length > 8) bucket.shift();
            } catch (e) {
                process.stderr.write(`[bridge] tapPath threw: ${e.message}\n`);
            }
            return path;
        };

        const opening = openHiddenService({
            descriptor,
            SVC_pk: descriptor.SVC_pk_ed || descriptor.SVC_pk,
            consensus,
            rpPathFn: ({ rpRse }) =>
                tapPath(buildPath({ exitFingerprint: rpRse.fingerprint }), topo.rpPaths),
            ipPathFn: ({ ipFingerprint }) =>
                tapPath(buildPath({ exitFingerprint: ipFingerprint }), topo.ipPaths),
            circuitBuilder,
        }).then((conn) => {

            connByHost.set(host, conn);
            inFlight.delete(host);
            topo.state = 'open';
            return conn;

        }, (err) => {

            inFlight.delete(host);
            topo.state = 'failed';
            topo.error = err.message;
            throw err;

        });
        inFlight.set(host, opening);
        return opening;

    };

    const acquire = async (url) => {

        const host = extractAnonHost(url);
        if (!host) throw new Error(`acquireSocket: not an anon:// URL: ${url}`);
        const c = await ensureConnFor(host);
        const stream = await c.openStream({ port: 80 });
        return new StreamDuplex(stream);

    };
    acquire._cleanup = () => {

        for (const [, c] of connByHost) {

            try { c.close(); } catch { /* ignore */ }

        }
        connByHost.clear();
        try { dispatcher.closeAll(); } catch { /* ignore */ }
        try { linkMgr.closeAll(); } catch { /* ignore */ }

    };
    // Drop a single host's cached connection. Called by /api/fetch on
    // any error so the next attempt re-rendezvouses instead of reusing
    // a circuit whose intro points may already be dead.
    //
    // Also clears the in-flight promise — if a fetch fails *during* a
    // first-time handshake, leaving that promise lingering would make
    // the next request resolve to the same dead conn.
    //
    // Topology entry is kept for /api/circuit forensics — only the live
    // connection state is reset.
    acquire._evict = (host) => {

        const c = connByHost.get(host);
        if (c) {
            try { c.close(); } catch { /* ignore */ }
            connByHost.delete(host);
            log(`evicted cached conn for ${host}`);
        }
        if (inFlight.has(host)) inFlight.delete(host);

    };
    // Expose the per-host circuit topology so the HTTP layer can
    // answer /api/circuit. Returns a structural-clone-safe snapshot.
    acquire._circuitFor = (host) => {

        const t = circuitByHost.get(host);
        if (!t) return null;
        // Shallow clone; inner relay summaries are already primitives.
        return {
            host,
            descriptor: { ...t.descriptor },
            firstSeenAt: t.firstSeenAt,
            state:       t.state || 'unknown',
            error:       t.error || null,
            rpPaths:     t.rpPaths.map((p) => ({ ...p })),
            ipPaths:     t.ipPaths.map((p) => ({ ...p })),
        };

    };
    acquire._allCircuits = () => Array.from(circuitByHost.keys());
    return acquire;

};

// ----- Fetch a URL via the acquirer + parse text/anon -----

const fetchUrl = async ({ url, acquireSocket }) => {

    let socket;
    try {
        socket = await acquireSocket(url);
    } catch (acqErr) {
        // acquireSocket failures imply the rendezvous/handshake itself
        // failed — evict any stale cache entry so the next attempt
        // re-rendezvouses with a freshly-fetched descriptor.
        try {
            const host = extractAnonHost(url);
            if (host && typeof acquireSocket._evict === 'function') {
                acquireSocket._evict(host);
            }
        } catch { /* ignore */ }
        throw acqErr;
    }

    let response;
    let fetchErr = null;
    try {

        response = await fetchOnce({ socket, url, timeoutMs: 30000 });

    } catch (e) {

        // fetchOnce timeout almost always means the cached connection
        // is half-dead: rendezvous succeeded but the service-side
        // intro point has rotated, so no stream bytes flow. Evicting
        // forces the next /api/fetch to do a fresh rendezvous.
        fetchErr = e;

    } finally {

        try { socket.end(); } catch { /* ignore */ }

    }
    if (fetchErr) {
        try {
            const host = extractAnonHost(url);
            if (host && typeof acquireSocket._evict === 'function') {
                acquireSocket._evict(host);
            }
        } catch { /* ignore */ }
        throw fetchErr;
    }

    const result = { status: response.status, meta: response.meta, url };

    if (isRedirect(response.status)) {

        result.kind = 'redirect';
        result.target = response.meta.trim();
        return result;

    }
    if (isInput(response.status)) {

        result.kind = 'input';
        result.prompt = response.meta;
        return result;

    }
    if (!isSuccess(response.status) || response.body === null) {

        result.kind = 'error';
        result.message = response.meta;
        return result;

    }

    const mime = parseSuccessMeta(response.meta);
    const mimeType = mime ? mime.mimeType : 'application/octet-stream';
    result.mimeType = mimeType;

    if (mimeType === 'text/anon') {

        const text = new TextDecoder('utf-8', { fatal: false }).decode(response.body);
        result.kind = 'document';
        result.lines = parseDocument(text);
        return result;

    }
    if (mimeType.startsWith('text/')) {

        const text = new TextDecoder('utf-8', { fatal: false }).decode(response.body);
        result.kind = 'plain';
        result.text = text;
        return result;

    }
    result.kind = 'binary';
    result.byteLength = response.body.length;
    return result;

};

// ----- Server-side rendering helpers (mirror of the client JS) -----
//
// The bundled browser ships a "Safest" security tier that disables
// JavaScript, which would break the client-side auto-fetch path that
// the landing page uses to render anon:// content. The /  route below
// detects ?url= and pre-renders the document so SSR clients (no-JS,
// curl, search-engine-style fetchers, etc.) get usable HTML directly.
//
// Keep these renderers byte-for-byte aligned with their counterparts
// in HTML_UI's <script> block — see renderDocument() in there.

const ssrEscape = (s) => String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const ssrRenderLines = (lines) => {

    const parts = [];
    let linkN = 0;
    for (const line of lines) {

        switch (line.type) {

            case 'heading1': parts.push('<h1 class="h1">' + ssrEscape(line.text) + '</h1>'); break;
            case 'heading2': parts.push('<h2 class="h2">' + ssrEscape(line.text) + '</h2>'); break;
            case 'heading3': parts.push('<h3 class="h3">' + ssrEscape(line.text) + '</h3>'); break;
            case 'plain':    parts.push('<p class="plain">' + ssrEscape(line.text) + '</p>'); break;
            case 'blank':    parts.push('<div class="blank"></div>'); break;
            case 'listItem':
                parts.push('<div class="list"><span class="list-bullet">•</span> ' + ssrEscape(line.text) + '</div>');
                break;
            case 'blockquote':
                parts.push('<div class="bq">' + ssrEscape(line.text) + '</div>');
                break;
            case 'codeFence': break;
            case 'code':
                parts.push('<div class="code">' + ssrEscape(line.text) + '</div>');
                break;
            case 'link': {

                linkN += 1;
                const targetUrl = line.url;
                const display = line.description !== null && line.description !== undefined
                    ? line.description : line.url;
                const inNetwork = targetUrl.startsWith('anon://')
                    || targetUrl.startsWith('/')
                    || targetUrl.startsWith('?');
                const cls = inNetwork ? '' : 'ext';
                const marker = inNetwork ? '[' + linkN + ']' : '[' + linkN + '↗]';
                // SSR links use real hrefs so the host browser routes them
                // natively (URL-bar hook handles anon:// redirects to the
                // bridge). External links open as the user clicks them.
                const href = inNetwork
                    ? (targetUrl.startsWith('anon://')
                        ? targetUrl
                        : ('/?url=' + encodeURIComponent('anon://__RESOLVE__' + targetUrl)))
                    : targetUrl;
                parts.push(
                    '<div class="link">'
                    + '<span class="marker">' + marker + '</span>'
                    + '<a class="' + cls + '" href="' + ssrEscape(href) + '"'
                        + (inNetwork ? '' : ' target="_blank" rel="noopener noreferrer"')
                    + '>' + ssrEscape(display) + '</a>'
                    + '<span class="hint">' + ssrEscape(targetUrl) + '</span>'
                    + '</div>'
                );
                break;

            }
            default: parts.push('<p class="plain">' + ssrEscape(line.text || '') + '</p>');

        }

    }
    return parts.join('');

};

// Resolve relative in-network links to absolute anon:// URLs based on
// the current anon-host context. Mirrors the client's resolveUrl().
const ssrResolveLinks = (html, currentAnonUrl) => {

    if (!currentAnonUrl || !currentAnonUrl.startsWith('anon://')) return html;
    const after = currentAnonUrl.slice(7);
    const slashIdx = after.indexOf('/');
    const qIdx = after.indexOf('?');
    let hostEnd = after.length;
    if (slashIdx !== -1) hostEnd = Math.min(hostEnd, slashIdx);
    if (qIdx !== -1) hostEnd = Math.min(hostEnd, qIdx);
    const host = after.slice(0, hostEnd);
    const path = slashIdx === -1 ? '/' : after.slice(slashIdx, qIdx === -1 ? undefined : qIdx);
    const lastSlash = path.lastIndexOf('/');
    const base = lastSlash === -1 ? '/' : path.slice(0, lastSlash + 1);

    // The placeholder is emitted as the value of a URL-encoded href
    // (see ssrRenderLines: `?url=` + encodeURIComponent('anon://__RESOLVE__'+...)),
    // so what actually lands in the HTML is `anon%3A%2F%2F__RESOLVE__<encoded-rel>`.
    // Match that form, not the bare `anon://__RESOLVE__`.
    return html.replace(/anon%3A%2F%2F__RESOLVE__([^"]+)/g, (_, rel) => {

        // rel was URL-encoded; decode for matching, re-encode for href
        let decoded;
        try { decoded = decodeURIComponent(rel); } catch { decoded = rel; }
        let resolved;
        if (decoded.startsWith('/')) resolved = 'anon://' + host + decoded;
        else if (decoded.startsWith('?')) resolved = 'anon://' + host + path + decoded;
        else resolved = 'anon://' + host + base + decoded;
        return encodeURIComponent(resolved);

    });

};

const ssrRenderResult = (result, anonUrl) => {

    if (!result || result.error) {

        const msg = result && result.error ? result.error : 'no result';
        return '<div class="error-box">Error: ' + ssrEscape(msg) + '</div>';

    }
    if (result.kind === 'document') {

        let body = ssrRenderLines(result.lines || []);
        body = ssrResolveLinks(body, anonUrl);
        return body;

    }
    if (result.kind === 'plain') {

        return '<div class="code">' + ssrEscape(result.text || '') + '</div>';

    }
    if (result.kind === 'redirect') {

        const target = result.target || '';
        return '<div class="plain">Redirect: <a href="/?url=' + encodeURIComponent(target)
            + '">' + ssrEscape(target) + '</a></div>';

    }
    if (result.kind === 'input') {

        return '<div class="plain">'
            + '<p>Input requested: ' + ssrEscape(result.meta || '') + '</p>'
            + '<form method="GET" action="/">'
            + '<input type="hidden" name="url" value="' + ssrEscape(anonUrl) + '">'
            + '<input type="text" name="i" placeholder="response" style="width: 100%; padding: 8px;">'
            + '<button type="submit" style="margin-top: 8px;">Submit</button>'
            + '</form></div>';

    }
    if (result.kind === 'binary') {

        return '<div class="plain">'
            + 'Binary content (' + (result.byteLength || 0) + ' bytes, '
            + ssrEscape(result.mimeType || 'application/octet-stream') + ')</div>';

    }
    return '<div class="code">' + ssrEscape(JSON.stringify(result, null, 2)) + '</div>';

};

const ssrPageShell = ({ title, anonUrl, contentHtml }) => `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${ssrEscape(title)}</title>
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; connect-src 'none';">
<style>
:root {
  --bg: #000;
  --panel: #0a0a0c;
  --fg: #e8e3d8;
  --muted: #6b6b6b;
  --accent: #d4a574;
  --accent-bright: #f0c890;
  --accent-dim: rgba(212, 165, 116, 0.55);
  --accent-glow: rgba(212, 165, 116, 0.30);
  --accent-faint: rgba(212, 165, 116, 0.18);
  --danger: #c97b6b;
  --code-bg: #0f0d0a;
  --code-border: rgba(212, 165, 116, 0.15);
  --link-anon: #d4a574;
  --link-ext: #8aa7c4;
  --mono: ui-monospace, "JetBrains Mono", "Cascadia Code", "Fira Code", "Courier New", monospace;
}
* { box-sizing: border-box; }
html, body { min-height: 100%; }
body {
  margin: 0;
  background: #000;
  color: var(--fg);
  font-family: var(--mono);
  font-size: 14px;
  line-height: 1.6;
  letter-spacing: 0.01em;
  position: relative;
  overflow-x: hidden;
}
/* CRT scanlines */
body::before {
  content: ""; position: fixed; inset: 0; pointer-events: none; z-index: 100;
  background: repeating-linear-gradient(
    to bottom,
    rgba(255,255,255,0.018) 0,
    rgba(255,255,255,0.018) 1px,
    transparent 1px,
    transparent 3px);
}
/* Vignette */
body::after {
  content: ""; position: fixed; inset: 0; pointer-events: none; z-index: 99;
  background: radial-gradient(ellipse at center, transparent 40%, rgba(0,0,0,0.55) 100%);
}
header {
  position: sticky; top: 0; z-index: 50;
  background: linear-gradient(to bottom, rgba(0,0,0,0.94), rgba(0,0,0,0.80));
  backdrop-filter: blur(2px);
  border-bottom: 1px solid var(--accent-faint);
  padding: 12px 22px;
  font-size: 12px; color: var(--muted); letter-spacing: 0.08em;
  display: flex; align-items: center; gap: 14px;
  box-shadow: 0 0 18px rgba(212, 165, 116, 0.08);
}
header .brand {
  color: var(--accent); font-weight: 700; letter-spacing: 0.18em;
  text-shadow: 0 0 8px var(--accent-glow);
  white-space: nowrap;
}
header .sep { color: var(--accent-dim); }
header .url {
  color: var(--fg); flex: 1;
  text-shadow: 0 0 1px var(--accent-faint);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
header .cursor {
  display: inline-block; width: 9px; height: 14px;
  background: var(--accent); vertical-align: -3px; margin-left: 4px;
  box-shadow: 0 0 6px var(--accent-glow);
  animation: cursor-blink 1.2s steps(1, end) infinite;
}
@keyframes cursor-blink { 50% { background: transparent; box-shadow: none; } }
header a {
  color: var(--accent); text-decoration: none;
  transition: color 200ms, text-shadow 200ms;
}
header a:hover { color: var(--accent-bright); text-shadow: 0 0 8px var(--accent-glow); }

/* Main with 4 CRT corner brackets framing the content */
main {
  position: relative; z-index: 1;
  max-width: 880px; margin: 32px auto;
  padding: 44px 32px 60px;
}
.frame { position: absolute; width: 36px; height: 36px; border: 2px solid var(--accent); pointer-events: none; }
.frame.tl { top: 0;    left: 0;  border-right: none;  border-bottom: none; }
.frame.tr { top: 0;    right: 0; border-left:  none;  border-bottom: none; }
.frame.bl { bottom: 0; left: 0;  border-right: none;  border-top:    none; }
.frame.br { bottom: 0; right: 0; border-left:  none;  border-top:    none; }

h1.h1 {
  color: var(--accent); font-size: 22px; margin: 22px 0 12px;
  text-shadow: 0 0 10px var(--accent-glow); letter-spacing: 0.02em;
}
h1.h1::before { content: "// "; color: var(--accent-bright); opacity: 0.8; }
h2.h2 {
  color: var(--accent); font-size: 17px; margin: 18px 0 8px;
  text-shadow: 0 0 6px var(--accent-glow);
}
h3.h3 { color: var(--accent-bright); font-size: 14px; margin: 14px 0 4px; }
p.plain { margin: 0 0 14px; color: var(--fg); }
.blank { height: 10px; }
.list { margin: 0 0 4px; padding-left: 8px; }
.list-bullet { color: #5fc97f; text-shadow: 0 0 4px rgba(95,201,127,0.3); }
.bq {
  color: var(--muted);
  border-left: 3px solid var(--accent-dim);
  background: rgba(212, 165, 116, 0.04);
  padding: 10px 14px; margin: 10px 0;
}
.code {
  font-family: var(--mono); font-size: 13px;
  background: var(--code-bg);
  padding: 12px 14px;
  border-radius: 4px;
  border: 1px solid var(--code-border);
  box-shadow: inset 0 0 12px rgba(0,0,0,0.6);
  white-space: pre-wrap; word-break: break-all;
}
.link { margin: 6px 0; }
.link a {
  color: var(--link-anon); text-decoration: none;
  border-bottom: 1px dotted var(--link-anon);
  transition: color 200ms, border-color 200ms, text-shadow 200ms;
}
.link a.ext { color: var(--link-ext); border-color: var(--link-ext); }
.link a:hover {
  border-bottom-style: solid;
  color: var(--accent-bright);
  text-shadow: 0 0 8px var(--accent-glow);
}
.link a.ext:hover { color: #b3cee9; text-shadow: 0 0 6px rgba(138,167,196,0.35); }
.link .marker { color: var(--accent-dim); font-size: 12px; margin-right: 6px; }
.link .hint { color: var(--muted); font-size: 11px; margin-left: 6px; }
.error-box {
  padding: 18px 20px; border-radius: 4px;
  background: rgba(201, 123, 107, 0.08);
  border: 1px solid #5a2a31; color: var(--danger);
}
</style>
</head>
<body>
<header>
  <span class="brand">// ANON BROWSER</span>
  <span class="sep">&#9656;</span>
  <span class="url">${ssrEscape(anonUrl)}<span class="cursor"></span></span>
  <span class="sep">&#9656;</span>
  <a href="/">[ &larr; landing ]</a>
</header>
<main>
  <span class="frame tl"></span>
  <span class="frame tr"></span>
  <span class="frame bl"></span>
  <span class="frame br"></span>
  ${contentHtml}
</main>
</body>
</html>`;

// ----- The HTML UI (inline) -----

const HTML_UI = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>anon-browse</title>
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self';">
<style>
:root {
  --bg: #0c0c0d;
  --panel: #141416;
  --fg: #e8e3d8;
  --muted: #6b6b6b;
  --accent: #d4a574;       /* pale amber */
  --accent-dim: #8a6d4b;
  --warn: #d4a574;
  --danger: #c97b6b;
  --rule: #1f1f22;
  --code: #07070a;
  --link-anon: #d4a574;
  --link-ext: #7a8b9e;
  --mono: "JetBrains Mono", "Cascadia Code", "Fira Code",
          ui-monospace, Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; background: var(--bg); color: var(--fg);
  font-family: var(--mono);
  font-size: 14px; line-height: 1.55; }
header {
  display: flex; align-items: center; gap: 8px;
  padding: 10px 14px; background: var(--panel);
  border-bottom: 1px solid var(--rule);
  position: sticky; top: 0; z-index: 10;
}
header button {
  background: transparent; color: var(--fg); border: 1px solid var(--rule);
  border-radius: 6px; padding: 6px 10px; cursor: pointer;
  font-size: 13px;
}
header button:hover { background: #2a2e35; }
header button:disabled { color: var(--muted); cursor: not-allowed; }
#url { flex: 1; background: var(--bg); color: var(--fg);
  border: 1px solid var(--rule); border-radius: 6px;
  padding: 8px 12px; font-family: ui-monospace, monospace; font-size: 13px;
}
#url:focus { outline: 2px solid var(--accent); }
#status {
  padding: 6px 14px; font-size: 12px; color: var(--muted);
  background: var(--panel); border-bottom: 1px solid var(--rule);
}
#status.error { color: var(--danger); }
main {
  max-width: 720px; margin: 0 auto; padding: 24px 24px 80px;
}
h1.h1 { font-size: 24px; margin: 18px 0 12px;
  padding-left: 12px; border-left: 2px solid var(--accent);
  color: var(--accent); font-weight: 700; letter-spacing: 0.02em; }
h2.h2 { font-size: 18px; margin: 24px 0 8px; font-weight: 700;
  color: var(--fg); letter-spacing: 0.02em; }
h3.h3 { font-size: 14px; margin: 16px 0 4px; color: var(--muted);
  font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; }

/* ----- [ ANONYMOUS ] landing page (shown when no ?url= bootstrap) ----- */
#landing {
  min-height: calc(100vh - 80px);
  display: flex; flex-direction: column; align-items: center;
  justify-content: center; gap: 32px;
  padding: 48px 24px;
}
#landing.hidden { display: none; }
.lockup { display: flex; align-items: baseline; gap: 14px;
  font-family: var(--mono); user-select: none;
}
.lockup .bracket {
  font-size: 36px; color: var(--accent-dim); opacity: 0.7;
  font-weight: 300;
}
.lockup .wordmark {
  font-size: 36px; font-weight: 700; color: var(--fg);
  letter-spacing: 0.32em; padding-left: 0.08em;
}
.lockup .tag {
  font-size: 11px; color: var(--muted);
  letter-spacing: 0.4em; text-transform: uppercase;
  margin-top: 8px;
}
#anon-search {
  width: 100%; max-width: 560px; display: flex; align-items: center;
  gap: 0; border: 1px solid var(--rule);
  background: var(--panel); border-radius: 2px;
  transition: border-color 120ms ease;
}
#anon-search:focus-within {
  border-color: var(--accent);
}
#anon-search .prefix {
  padding: 12px 4px 12px 14px; color: var(--accent-dim);
  font-family: var(--mono); font-size: 14px; user-select: none;
}
#anon-search-input {
  flex: 1; background: transparent; color: var(--fg);
  border: 0; outline: none;
  font-family: var(--mono); font-size: 14px;
  padding: 12px 12px 12px 6px; letter-spacing: 0.01em;
}
#anon-search-input::placeholder { color: var(--muted); }
#anon-search .submit {
  background: transparent; color: var(--accent-dim); border: 0;
  font-family: var(--mono); font-size: 14px; padding: 0 14px;
  cursor: pointer;
}
#anon-search:focus-within .submit { color: var(--accent); }
.recent {
  width: 100%; max-width: 560px;
}
.recent-label {
  color: var(--muted); font-size: 11px;
  letter-spacing: 0.3em; text-transform: uppercase;
  text-align: center; margin-bottom: 12px;
}
.recent-list { list-style: none; margin: 0; padding: 0; }
.recent-list li { margin: 4px 0; }
.recent-list a {
  display: block; color: var(--fg); text-decoration: none;
  font-family: var(--mono); font-size: 13px;
  padding: 6px 12px; border-left: 2px solid transparent;
  transition: border-color 120ms ease, color 120ms ease;
}
.recent-list a:hover {
  color: var(--accent); border-left-color: var(--accent);
}
.recent-list .dot { color: var(--accent-dim); margin-right: 10px; }
.landing-foot {
  position: absolute; bottom: 20px; left: 0; right: 0;
  text-align: center; color: var(--muted); font-size: 10px;
  letter-spacing: 0.2em; text-transform: uppercase;
}
.plain { margin: 0 0 12px; }
.blank { height: 8px; }
.list { margin: 0 0 4px; padding-left: 6px; }
.list-bullet { color: #5fc97f; }
.bq { color: var(--muted); border-left: 3px solid var(--rule);
  padding: 4px 10px; margin: 4px 0; }
.code { font-family: ui-monospace, monospace; font-size: 13px;
  background: var(--code); padding: 8px 12px; border-radius: 6px;
  white-space: pre-wrap; word-break: break-all; }
.link { display: block; margin: 4px 0; }
.link a { color: var(--link-anon); text-decoration: none; border-bottom: 1px dotted var(--link-anon); }
.link a.ext { color: var(--link-ext); border-color: var(--link-ext); }
.link a:hover { border-bottom-style: solid; }
.link .marker { color: var(--muted); font-family: ui-monospace, monospace;
  font-size: 12px; margin-right: 4px; }
.link .hint { color: var(--muted); font-size: 11px; margin-left: 6px; font-family: ui-monospace, monospace; }
.error-box { padding: 16px; border-radius: 8px; background: #341d20;
  border: 1px solid #5a2a31; color: var(--danger); }
.banner-pre {
  background: #2a2e35; color: var(--muted); padding: 8px 12px;
  font-size: 12px; font-family: ui-monospace, monospace; text-align: center;
  border-bottom: 1px solid var(--rule);
}
</style>
</head>
<body>
<!-- In-page URL bar removed: the host browser's native URL bar
     (Firefox + mozilla.cfg URL-bar interception) is the single source
     of truth for the address. -->
<div id="status" hidden>ready</div>
<div id="landing">
  <div class="lockup">
    <span class="bracket">[</span>
    <span class="wordmark">ANONYMOUS</span>
    <span class="bracket">]</span>
  </div>
  <form id="anon-search" autocomplete="off">
    <span class="prefix">▸</span>
    <input id="anon-search-input" type="text"
           placeholder="anon://&hellip;  or  search"
           autocapitalize="off" autocorrect="off" spellcheck="false">
    <button type="submit" class="submit">&#9166;</button>
  </form>
  <div class="recent">
    <div class="recent-label">── recent ──</div>
    <ul class="recent-list">
      <li><a href="?url=anon%3A%2F%2Fpd7oljno3rdtsrtludnwesh362veu3mtawnjx6ozn7uso7gh7k4nq5ad.anon"><span class="dot">·</span>anon://demo.anon</a></li>
      <li><a href="?url=anon%3A%2F%2Fanona4y4gpit3bbuunqhvubajjgmnvuhupka4gqibkdldpby64ujtkqd.anon"><span class="dot">·</span>anon://anonymous.anon</a></li>
    </ul>
  </div>
  <div class="landing-foot">post-quantum hidden-service network</div>
</div>
<main id="content"></main>
<script>
(() => {
  // Session token injected via the URL when the bridge runs with the
  // token gate enabled. The bundled launcher runs the bridge with
  // --no-token (loopback-only), in which case the token query param
  // is omitted; we send an empty string and the server accepts it.
  const TOKEN = new URLSearchParams(window.location.search).get('token') || '';

  const history = [];      // back stack of URLs
  const future = [];       // forward stack
  let currentUrl = null;

  // Null-safe lookup: the in-page header was removed in favor of the
  // host browser's native URL bar, so back/fwd/reload/url/go may not
  // exist. Return a stub so existing handlers no-op cleanly.
  const NOOP_EL = { disabled: false, value: '',
                    addEventListener: () => {}, focus: () => {},
                    classList: { add: () => {}, remove: () => {} } };
  const $ = (id) => document.getElementById(id) || NOOP_EL;
  const back = $('back'), fwd = $('fwd'), reload = $('reload');
  const url  = $('url'),  go   = $('go'),  content = $('content'), status = $('status');

  const setStatus = (text, isError) => {
    status.textContent = text;
    status.className = isError ? 'error' : '';
  };

  const setNavButtons = () => {
    back.disabled = history.length === 0;
    fwd.disabled  = future.length === 0;
  };

  const escape = (s) => s
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

  // Resolve relative anon-network URLs against currentUrl.
  const resolveUrl = (target) => {
    if (target.startsWith('anon://')) return target;
    if (!currentUrl || !currentUrl.startsWith('anon://')) return target;
    const after = currentUrl.slice(7);
    const slash = after.indexOf('/'), query = after.indexOf('?');
    let hostEnd = after.length;
    if (slash !== -1) hostEnd = Math.min(hostEnd, slash);
    if (query !== -1) hostEnd = Math.min(hostEnd, query);
    const host = after.slice(0, hostEnd);
    const path = slash === -1 ? '/'
      : after.slice(slash, query === -1 ? undefined : query);
    if (target.startsWith('/')) return 'anon://' + host + target;
    if (target.startsWith('?')) return 'anon://' + host + path + target;
    const lastSlash = path.lastIndexOf('/');
    const base = lastSlash === -1 ? '/' : path.slice(0, lastSlash + 1);
    return 'anon://' + host + base + target;
  };

  const renderDocument = (lines) => {
    const parts = [];
    let linkN = 0;
    for (const line of lines) {
      switch (line.type) {
        case 'heading1': parts.push('<h1 class="h1">' + escape(line.text) + '</h1>'); break;
        case 'heading2': parts.push('<h2 class="h2">' + escape(line.text) + '</h2>'); break;
        case 'heading3': parts.push('<h3 class="h3">' + escape(line.text) + '</h3>'); break;
        case 'plain':    parts.push('<p class="plain">' + escape(line.text) + '</p>'); break;
        case 'blank':    parts.push('<div class="blank"></div>'); break;
        case 'listItem':
          parts.push('<div class="list"><span class="list-bullet">•</span> ' + escape(line.text) + '</div>');
          break;
        case 'blockquote':
          parts.push('<div class="bq">' + escape(line.text) + '</div>');
          break;
        case 'codeFence': break; // fence itself isn't rendered
        case 'code':
          parts.push('<div class="code">' + escape(line.text) + '</div>');
          break;
        case 'link': {
          linkN += 1;
          const targetUrl = line.url;
          const display = line.description !== null ? line.description : line.url;
          const inNetwork = targetUrl.startsWith('anon://') || targetUrl.startsWith('/') || targetUrl.startsWith('?');
          const cls = inNetwork ? '' : 'ext';
          const marker = inNetwork ? '[' + linkN + ']' : '[' + linkN + '↗]';
          parts.push(
            '<div class="link">' +
              '<span class="marker">' + marker + '</span>' +
              '<a class="' + cls + '" data-target="' + escape(targetUrl) + '" data-innet="' + inNetwork + '" href="#">' +
                escape(display) +
              '</a>' +
              '<span class="hint">' + escape(targetUrl) + '</span>' +
            '</div>'
          );
          break;
        }
        default: parts.push('<p class="plain">' + escape(line.text || '') + '</p>');
      }
    }
    return parts.join('');
  };

  const navigate = async (targetUrl, options = {}) => {
    // Hide the landing page once the user navigates anywhere.
    const _landing = document.getElementById('landing');
    if (_landing) _landing.classList.add('hidden');
    const resolved = resolveUrl(targetUrl);
    if (!options.fromHistory) {
      if (currentUrl !== null) history.push(currentUrl);
      future.length = 0;
    }
    currentUrl = resolved;
    url.value = resolved;
    setNavButtons();
    setStatus('Loading ' + resolved + '…');
    try {
      const resp = await fetch('/api/fetch?token=' + encodeURIComponent(TOKEN)
        + '&url=' + encodeURIComponent(resolved));
      const data = await resp.json();
      if (data.error) {
        content.innerHTML = '<div class="error-box">' + escape(data.error) + '</div>';
        setStatus(data.error, true);
        return;
      }
      setStatus(data.status + ' ' + data.meta);
      if (data.kind === 'document') {
        content.innerHTML = renderDocument(data.lines);
        // Wire link clicks.
        for (const a of content.querySelectorAll('a[data-target]')) {
          a.addEventListener('click', (e) => {
            e.preventDefault();
            const t = a.getAttribute('data-target');
            const innet = a.getAttribute('data-innet') === 'true';
            if (innet) navigate(t);
            else if (confirm('Off-network link:\\n' + t + '\\n\\nThis will leave the anon-network. Continue?')) {
              window.open(t, '_blank', 'noopener,noreferrer');
            }
          });
        }
      } else if (data.kind === 'plain') {
        content.innerHTML = '<pre class="code">' + escape(data.text) + '</pre>';
      } else if (data.kind === 'redirect') {
        content.innerHTML = '<div class="error-box">Redirect ' + data.status
          + ' to <a class="" data-target="' + escape(data.target) + '" href="#">' + escape(data.target) + '</a></div>';
        const a = content.querySelector('a');
        a.addEventListener('click', (e) => { e.preventDefault(); navigate(data.target); });
      } else if (data.kind === 'binary') {
        content.innerHTML = '<div class="error-box">Binary content: ' + escape(data.mimeType)
          + ', ' + data.byteLength + ' bytes. anon-browse-gui v1 does not render non-text content.</div>';
      } else if (data.kind === 'error') {
        content.innerHTML = '<div class="error-box">Error ' + data.status + ': ' + escape(data.message) + '</div>';
        setStatus('Error ' + data.status + ': ' + data.message, true);
      } else if (data.kind === 'input') {
        content.innerHTML = '<div class="error-box">Server requests input: ' + escape(data.prompt) + '<br><br>'
          + 'v1 does not yet prompt for input. Append ?your-answer to the URL and reload.</div>';
      }
    } catch (err) {
      content.innerHTML = '<div class="error-box">Fetch failed: ' + escape(err.message) + '</div>';
      setStatus('Fetch failed: ' + err.message, true);
    }
  };

  back.addEventListener('click', () => {
    if (history.length === 0) return;
    future.push(currentUrl);
    const u = history.pop();
    navigate(u, { fromHistory: true });
  });
  fwd.addEventListener('click', () => {
    if (future.length === 0) return;
    history.push(currentUrl);
    const u = future.pop();
    navigate(u, { fromHistory: true });
  });
  reload.addEventListener('click', () => {
    if (currentUrl) navigate(currentUrl, { fromHistory: true });
  });
  go.addEventListener('click', () => { if (url.value) navigate(url.value); });
  url.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && url.value) navigate(url.value);
  });

  setStatus('ready · pick a URL or click Go');

  // ----- Landing page (shown when no ?url= bootstrap) -----
  // navigate() hides the landing automatically on first call.
  const landing = document.getElementById('landing');
  const showLanding = () => { if (landing) landing.classList.remove('hidden'); };

  // Wire the landing's search input.
  const searchForm = document.getElementById('anon-search');
  const searchInput = document.getElementById('anon-search-input');
  if (searchForm && searchInput) {
    searchForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const v = searchInput.value.trim();
      if (!v) return;
      // anon://X or X.anon → bridge navigate.
      if (v.startsWith('anon://') || /\.anon($|[/?#])/i.test(v)) {
        const u = v.startsWith('anon://') ? v : ('anon://' + v);
        navigate(u);
        return;
      }
      // Else: assume clearnet search via the host browser (Tor PAC routes it).
      window.location.href = 'https://duckduckgo.com/?q=' + encodeURIComponent(v);
    });
    // Autofocus the search input on landing.
    setTimeout(() => searchInput.focus(), 50);
  }

  // Bootstrap from ?url=... query parameter so external URL-bar
  // interception (mozilla.cfg http-on-modify-request observer, or the
  // legacy WebExtension) can redirect here with an .anon target and
  // have the page auto-navigate on load.
  try {
    const q = new URLSearchParams(window.location.search);
    const initial = q.get('url') || q.get('u');
    if (initial) {
      // Strip leading whitespace; bridge accepts both anon:// and bare-host forms.
      navigate(initial.trim());
    } else {
      showLanding();
    }
  } catch { showLanding(); }
})();
</script>
</body>
</html>`;

// ----- HTTP server + main -----

const main = async () => {

    const opts = parseArgs();

    // Self-refresh consensus before initial load (no-op if --refresh-from
    // wasn't passed). Removes the manual restart footgun where a stale
    // on-disk consensus.bin makes the bridge refuse to start.
    if (opts.refreshFrom.length > 0 && opts.consensusPath) {

        await fetchConsensus({ urls: opts.refreshFrom, dest: opts.consensusPath });

    }

    const acquireSocket = opts.mode === 'connect'
        ? buildDirectAcquirer({ host: opts.connectHost, port: opts.connectPort })
        : await buildRendezvousAcquirer({
            consensusPath: opts.consensusPath,
            daTrustPath: opts.daTrustPath,
            descriptorPath: opts.descriptorPath,
            descriptorDir: opts.descriptorDir,
            hsdirUrl: opts.hsdirUrl,
            skipAntiCorrelation: opts.skipAntiCorrelation,
        });

    // Keep the on-disk consensus fresh for the NEXT bridge start. The
    // running bridge does NOT hot-reload its in-memory consensus, but
    // periodic refreshes mean a long-running bridge that gets restarted
    // later never hits the stale-consensus startup failure.
    if (opts.refreshFrom.length > 0 && opts.consensusPath && opts.refreshIntervalSec > 0) {

        const tick = setInterval(
            () => { fetchConsensus({ urls: opts.refreshFrom, dest: opts.consensusPath }); },
            opts.refreshIntervalSec * 1000,
        );
        // Unref so this timer never holds the process open on its own.
        tick.unref();
        log(`consensus auto-refresh armed: every ${opts.refreshIntervalSec}s from [${opts.refreshFrom.join(', ')}]`);

    }

    const token = opts.noToken ? null : randomBytes(16).toString('hex');
    const tokenOk = (supplied) => token === null || supplied === token;

    // Headers added to every JSON / API response so the WebExtension
    // renderer (origin moz-extension://...) can call us. The session
    // token does the actual auth — CORS just unblocks the browser's
    // same-origin check.
    // Belt-and-suspenders no-cache: modern (cache-control) + legacy
    // (pragma, expires). Local dev bridge serves dynamic content for
    // anon:// rendering — caching anywhere is wrong.
    const NO_CACHE = {
        'cache-control': 'no-store, no-cache, must-revalidate, max-age=0',
        'pragma': 'no-cache',
        'expires': '0',
    };

    const corsJson = {
        'content-type': 'application/json; charset=utf-8',
        ...NO_CACHE,
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET, OPTIONS',
        'access-control-allow-headers': 'content-type',
        'access-control-max-age': '600',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
    };

    const server = createHttpServer(async (req, res) => {

        const url = new URL(req.url, 'http://internal');
        const path = url.pathname;

        // CORS preflight — the renderer never sends one (GET with
        // standard headers), but be polite to future callers.
        if (req.method === 'OPTIONS') {

            res.writeHead(204, corsJson);
            res.end();
            return;

        }

        // GET /  — serve the UI (token check via query)
        if (path === '/' || path === '/index.html') {

            if (!tokenOk(url.searchParams.get('token'))) {

                res.writeHead(403, { 'content-type': 'text/plain', ...NO_CACHE });
                res.end('forbidden: missing or wrong session token');
                return;

            }

            // SSR path: when ?url= is set, render content server-side so
            // the page works even when the host browser has JavaScript
            // disabled (Safest tier in the bundled mozilla.cfg). The
            // client-JS auto-fetch in HTML_UI would otherwise be the only
            // way to populate the content area.
            const targetUrl = url.searchParams.get('url');
            if (targetUrl && /^anon:\/\//i.test(targetUrl)) {

                let result;
                try {

                    result = await fetchUrl({ url: targetUrl, acquireSocket });

                } catch (err) {

                    process.stderr.write(
                        `[bridge] SSR fetch url=${targetUrl} threw: ${err.message}\n`,
                    );
                    result = { error: err.message };

                }
                const html = ssrPageShell({
                    title: targetUrl,
                    anonUrl: targetUrl,
                    contentHtml: ssrRenderResult(result, targetUrl),
                });
                res.writeHead(200, {
                    'content-type': 'text/html; charset=utf-8',
                    ...NO_CACHE,
                    'x-content-type-options': 'nosniff',
                    'referrer-policy': 'no-referrer',
                });
                res.end(html);
                return;

            }

            // No ?url= → serve the original JS-driven landing shell.
            // Search box + recent list. JS may or may not work; the
            // search box is a plain <form> so it submits regardless,
            // landing on the SSR path above on next request.
            res.writeHead(200, {
                'content-type': 'text/html; charset=utf-8',
                ...NO_CACHE,
                'x-content-type-options': 'nosniff',
                'referrer-policy': 'no-referrer',
            });
            res.end(HTML_UI);
            return;

        }

        // GET /api/health?token=...  — lightweight reachability probe
        // used by the WebExtension's options page to verify the bridge
        // is up and the token matches.
        if (path === '/api/health') {

            if (!tokenOk(url.searchParams.get('token'))) {

                res.writeHead(403, corsJson);
                res.end(JSON.stringify({ error: 'forbidden: bad session token' }));
                return;

            }
            res.writeHead(200, corsJson);
            res.end(JSON.stringify({
                ok:        true,
                version:   '0.2.0-pre',
                mode:      opts.mode,
                listen:    `${opts.listen}:${server.address().port}`,
                tokenGate: token !== null,
            }));
            return;

        }

        // GET /api/circuit?url=anon://host&token=...
        //
        // Returns the current 3-hop topology for the rendezvous and
        // intro circuits feeding a given .anon host. Used by the
        // browser's chrome-side "circuit display" popup (mozilla.cfg
        // wires the Tor-status button to fetch this and render).
        //
        // Returns 200 with { error: 'no circuit' } if the host has
        // never been opened — easier for the UI than handling 404.
        if (path === '/api/circuit') {

            if (!tokenOk(url.searchParams.get('token'))) {

                res.writeHead(403, corsJson);
                res.end(JSON.stringify({ error: 'forbidden: bad session token' }));
                return;

            }
            const target = url.searchParams.get('url');
            if (!target) {

                res.writeHead(400, corsJson);
                res.end(JSON.stringify({ error: 'missing ?url=' }));
                return;

            }
            try {

                const host = extractAnonHost(target);
                if (!host) {
                    res.writeHead(200, corsJson);
                    res.end(JSON.stringify({ error: 'not an anon:// URL', url: target }));
                    return;
                }
                if (typeof acquireSocket._circuitFor !== 'function') {
                    res.writeHead(200, corsJson);
                    res.end(JSON.stringify({
                        error: 'mode does not expose circuit info', mode: opts.mode,
                    }));
                    return;
                }
                const info = acquireSocket._circuitFor(host);
                if (!info) {
                    res.writeHead(200, corsJson);
                    res.end(JSON.stringify({
                        error:  'no circuit',
                        host,
                        known:  acquireSocket._allCircuits
                            ? acquireSocket._allCircuits()
                            : [],
                    }));
                    return;
                }
                res.writeHead(200, corsJson);
                res.end(JSON.stringify(info));

            } catch (err) {

                process.stderr.write(
                    `[bridge] /api/circuit url=${target} threw: ${err.stack || err.message}\n`,
                );
                res.writeHead(200, corsJson);
                res.end(JSON.stringify({ error: err.message }));

            }
            return;

        }

        // GET /api/tor-circuit?host=<host>&token=...
        //
        // Returns the live Tor 3-hop circuit currently serving the
        // given host. Talks to the bundled tor's control port via
        // cookie auth — no extra config needed; the bridge reads
        // torrc + control_auth_cookie from AnonLayer/tor/run.
        //
        // For *.onion hosts the chrome side calls this on click of
        // the "Circuit" toolbar button. For *.anon hosts the existing
        // /api/circuit endpoint (above) returns the anon rendezvous
        // path instead — different transports, different shape.
        if (path === '/api/tor-circuit') {

            if (!tokenOk(url.searchParams.get('token'))) {

                res.writeHead(403, corsJson);
                res.end(JSON.stringify({ error: 'forbidden: bad session token' }));
                return;

            }
            const host = url.searchParams.get('host');
            if (!host) {

                res.writeHead(400, corsJson);
                res.end(JSON.stringify({ error: 'missing ?host=' }));
                return;

            }
            try {

                const fallback = url.searchParams.get('fallback') === 'latest';
                const result = await queryTorCircuitForHost(
                    host, TOR_RUNTIME_DIR, { fallbackToLatest: fallback },
                );
                if (!result) {
                    res.writeHead(200, corsJson);
                    res.end(JSON.stringify({
                        error: 'no tor circuit',
                        host,
                        hint:  'tor has no BUILT circuits — likely still bootstrapping or this build does not route the host through tor',
                    }));
                    return;
                }
                res.writeHead(200, corsJson);
                res.end(JSON.stringify(result));

            } catch (err) {

                process.stderr.write(
                    `[bridge] /api/tor-circuit host=${host} threw: ${err.stack || err.message}\n`,
                );
                res.writeHead(200, corsJson);
                res.end(JSON.stringify({ error: err.message, host }));

            }
            return;

        }

        // GET /api/fetch?url=...&token=...
        if (path === '/api/fetch') {

            if (!tokenOk(url.searchParams.get('token'))) {

                res.writeHead(403, corsJson);
                res.end(JSON.stringify({ error: 'forbidden: bad session token' }));
                return;

            }
            const target = url.searchParams.get('url');
            if (!target) {

                res.writeHead(400, corsJson);
                res.end(JSON.stringify({ error: 'missing ?url=' }));
                return;

            }
            try {

                const result = await fetchUrl({ url: target, acquireSocket });
                res.writeHead(200, corsJson);
                res.end(JSON.stringify(result));

            } catch (err) {

                process.stderr.write(
                    `[bridge] /api/fetch url=${target} threw: ${err.stack || err.message}\n`,
                );
                res.writeHead(200, corsJson);
                res.end(JSON.stringify({ error: err.message }));

            }
            return;

        }

        res.writeHead(404, { 'content-type': 'text/plain', ...NO_CACHE });
        res.end('not found');

    });

    server.on('error', (err) => die(`HTTP server: ${err.message}`));
    server.listen(opts.port, opts.listen, () => {

        const addr = server.address();
        const openUrl = token === null
            ? `http://${addr.address}:${addr.port}/`
            : `http://${addr.address}:${addr.port}/?token=${token}`;
        process.stderr.write([
            '',
            '================================================================',
            '              ANONYMOUS LAYER — GUI BROWSER                    ',
            '================================================================',
            '',
            token === null
                ? `Bridge URL (no token gate — loopback only):`
                : `Open this URL in your browser:`,
            ``,
            `    ${openUrl}`,
            ``,
            `Mode: ${opts.mode === 'connect' ? `direct → ${opts.connectHost}:${opts.connectPort}`
                : `rendezvous → descriptor at ${opts.descriptorPath}`}`,
            `Listen: ${addr.address}:${addr.port}`,
            `Session token gates the API. Ctrl-C to shut down.`,
            '',
        ].join('\n'));

    });

    const shutdown = () => {

        log('shutting down…');
        try { acquireSocket._cleanup && acquireSocket._cleanup(); } catch { /* ignore */ }
        server.close(() => process.exit(0));

    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

};

main().catch((err) => die(err.stack || err.message));
