#!/usr/bin/env node
// anon-rendezvous-proxy — listen on a local TCP port; per-accepted
// connection, rendezvous to a fixed `.anon` target address and pipe
// bytes between the local socket and the resulting stream.
//
// Use case: a chained hidden-service deployment. An outer publisher
// wants its `--local-host`/`--local-port` to route to another hidden
// service (the "inner" content host) rather than a clearnet TCP
// endpoint. The outer publisher dials this proxy on localhost; the
// proxy does the rendezvous; the inner publisher serves the request
// loopback to its own anon-site-server. No clearnet hop between the
// two hosts is observable.
//
// Architecture:
//
//   outer publisher    ──── plain TCP localhost ────►   anon-rendezvous-proxy
//   (relay3, anona4y4)                                  (relay3, this binary)
//                                                              │
//                                                              │ rendezvous to inner address
//                                                              │ through the anon network
//                                                              ▼
//                                                       inner publisher
//                                                       (anonymous.gratis,
//                                                        private address)
//                                                              │
//                                                              │ loopback
//                                                              ▼
//                                                       anon-site-server

import { createServer, createConnection } from 'node:net';
import { readFile } from 'node:fs/promises';

import { createNodeIdentity } from '../modules/v2-runtime/persistence.mjs';
import { createLinkManager } from '../modules/v2-runtime/link_manager.mjs';
import { createCircuitDispatcher } from '../modules/v2-runtime/circuit_dispatcher.mjs';
import { createCellRouter } from '../modules/v2-runtime/cell_router.mjs';
import { createPeerResolver } from '../modules/v2-runtime/peer_resolver.mjs';
import { createCircuitBuilder } from '../modules/v2-runtime/circuit_builder.mjs';
import { openHiddenService } from '../modules/v2-runtime/rendezvous_client.mjs';
import { StreamDuplex } from '../modules/v2-runtime/stream_duplex.mjs';
import { loadConsensus, loadDaTrustSet } from '../modules/v2-runtime/consensus_loader.mjs';
import { parseServiceDescriptorAny } from '../modules/v2/descriptor.mjs';
import {
    selectMiddle,
    FLAG_GUARD, FLAG_RUNNING, FLAG_VALID,
} from '../modules/v2/consensus.mjs';
import { encodeOnionAddress, encodeOnionAddressV3 } from '../modules/v2/onion_address.mjs';

const USAGE = `\
anon-rendezvous-proxy — local TCP → anon-network hidden-service tunnel

Usage:
  anon-rendezvous-proxy --listen H:P --target ADDR
        --consensus PATH --da-trust PATH --descriptor PATH
        [--allow-co-located] [--target-port N] [--quiet]

  --listen H:P       Local TCP bind (e.g. 127.0.0.1:31960).
  --target ADDR      The .anon address to rendezvous TO.
  --target-port N    Port to open inside the rendezvous stream (default 80;
                     matches what anon-site-server treats as ignored).
  --descriptor PATH  Service descriptor for the target.
  --consensus PATH   Network consensus.
  --da-trust  PATH   DA-trust file.
  --allow-co-located Testnet path-diversity relaxation.
  --quiet            Suppress per-connection logging.
`;

const die = (m, c = 1) => { process.stderr.write(`error: ${m}\n`); process.exit(c); };
const log = (m) => process.stderr.write(`[${new Date().toISOString()}] ${m}\n`);

const splitHostPort = (s) => {
    const i = s.lastIndexOf(':');
    if (i < 0) return null;
    const host = s.slice(0, i);
    const port = parseInt(s.slice(i + 1), 10);
    if (!host || !Number.isInteger(port)) return null;
    return { host, port };
};

const parseArgs = () => {

    const args = process.argv.slice(2);
    if (args.length === 0) { process.stdout.write(USAGE); process.exit(0); }
    const opts = {
        listen: null, target: null, targetPort: 80,
        consensusPath: null, daTrustPath: null, descriptorPath: null,
        skipAntiCorrelation: false, quiet: false,
    };
    for (let i = 0; i < args.length; i += 1) {

        const a = args[i];
        if (a === '--help' || a === '-h') { process.stdout.write(USAGE); process.exit(0); }
        if (a === '--listen')           { opts.listen = splitHostPort(args[i + 1]); i += 1; continue; }
        if (a === '--target')           { opts.target = args[i + 1]; i += 1; continue; }
        if (a === '--target-port')      { opts.targetPort = parseInt(args[i + 1], 10); i += 1; continue; }
        if (a === '--descriptor')       { opts.descriptorPath = args[i + 1]; i += 1; continue; }
        if (a === '--consensus')        { opts.consensusPath = args[i + 1]; i += 1; continue; }
        if (a === '--da-trust')         { opts.daTrustPath = args[i + 1]; i += 1; continue; }
        if (a === '--allow-co-located') { opts.skipAntiCorrelation = true; continue; }
        if (a === '--quiet')            { opts.quiet = true; continue; }
        die(`unknown option: ${a}`);

    }
    if (!opts.listen) die('--listen H:P required');
    if (!opts.target) die('--target ADDR required');
    if (!opts.descriptorPath) die('--descriptor PATH required');
    if (!opts.consensusPath) die('--consensus PATH required');
    if (!opts.daTrustPath) die('--da-trust PATH required');
    return opts;

};

const fpEq = (a, b) => Buffer.from(a).equals(Buffer.from(b));
const pickRand = (arr) => arr[Math.floor(Math.random() * arr.length)];

const main = async () => {

    const opts = parseArgs();
    const out = opts.quiet ? () => {} : log;

    const daTrust = await loadDaTrustSet(opts.daTrustPath);
    const consensus = await loadConsensus({ path: opts.consensusPath, daTrustSet: daTrust });

    const descriptorBytes = await readFile(opts.descriptorPath);
    const descriptor = parseServiceDescriptorAny(new Uint8Array(descriptorBytes));
    if (!descriptor) die(`could not parse descriptor at ${opts.descriptorPath}`);

    const computed = descriptor.version === 0x03
        ? encodeOnionAddressV3(descriptor.SVC_pk_ed, descriptor.SVC_pk_mldsa)
        : encodeOnionAddress(descriptor.SVC_pk);
    if (computed !== opts.target) {

        die(`--target ${opts.target} doesn't match descriptor address ${computed}`);

    }
    out(`target: ${opts.target}`);

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
    });

    const buildPath = ({ exitFingerprint }) => {

        const exitRse = consensus.rses.find((r) => fpEq(r.fingerprint, exitFingerprint));
        if (!exitRse) throw new Error('exit fingerprint not in consensus');
        const guardCandidates = consensus.rses.filter((r) => (
            (r.flags & (FLAG_RUNNING | FLAG_VALID | FLAG_GUARD)) === (FLAG_RUNNING | FLAG_VALID | FLAG_GUARD)
            && !fpEq(r.fingerprint, exitFingerprint)
        ));
        if (guardCandidates.length === 0) throw new Error('no guard candidate distinct from exit');
        const guard = pickRand(guardCandidates);
        const middle = selectMiddle({
            consensus,
            excludeFps: [guard.fingerprint, exitFingerprint],
            coLocateAvoid: opts.skipAntiCorrelation ? [] : [guard, exitRse],
        });
        if (!middle) throw new Error('no middle candidate');
        return { guard, middle, exit: exitRse };

    };

    // Cache the rendezvous connection to the inner. Rendezvous handshake
    // is expensive; reuse it for many streams.
    let conn = null;
    let opening = null;
    const ensureConn = async () => {

        if (conn) return conn;
        if (opening) return opening;
        opening = openHiddenService({
            descriptor,
            SVC_pk: descriptor.SVC_pk_ed || descriptor.SVC_pk,
            consensus,
            rpPathFn: ({ rpRse }) => buildPath({ exitFingerprint: rpRse.fingerprint }),
            ipPathFn: ({ ipFingerprint }) => buildPath({ exitFingerprint: ipFingerprint }),
            circuitBuilder,
        }).then((c) => { conn = c; opening = null; return c; }, (e) => { opening = null; throw e; });
        return opening;

    };

    let nextId = 1;

    const server = createServer((local) => {

        const id = nextId++;
        out(`#${id} accept ${local.remoteAddress}:${local.remotePort}`);

        local.pause();
        let stream = null;
        let duplex = null;
        let closed = false;
        let l2sBytes = 0;
        let s2lBytes = 0;

        const teardown = (reason) => {

            if (closed) return;
            closed = true;
            out(`#${id} close: ${reason}  (local→stream=${l2sBytes}, stream→local=${s2lBytes})`);
            try { local.destroy(); } catch { /* ignore */ }
            try { duplex && duplex.destroy(); } catch { /* ignore */ }

        };
        local.once('error', (e) => teardown(`local error ${e.code || e.message}`));
        local.once('close', () => teardown('local closed'));

        (async () => {

            try {

                const c = await ensureConn();
                if (closed) return;
                stream = await c.openStream({ port: opts.targetPort });
                if (closed) { try { stream && stream.end && stream.end(); } catch { /* ignore */ } return; }
                duplex = new StreamDuplex(stream);
                out(`#${id} stream open`);

                duplex.once('error', (e) => teardown(`stream error ${e.code || e.message}`));
                duplex.once('close', () => teardown('stream closed'));
                duplex.once('end', () => out(`#${id} stream end (server EOF)`));

                local.on('data', (chunk) => {

                    l2sBytes += chunk.length;
                    duplex.write(chunk);

                });
                duplex.on('data', (chunk) => {

                    s2lBytes += chunk.length;
                    local.write(chunk);

                });
                local.resume();

            } catch (err) {

                teardown(`rendezvous failed: ${err.message}`);

            }

        })();

    });

    server.on('error', (err) => die(`listener error: ${err.message}`));
    server.listen(opts.listen.port, opts.listen.host, () => {

        const a = server.address();
        out(`listening ${a.address}:${a.port} → rendezvous://${opts.target}`);

    });

    const shutdown = () => {

        try { server.close(); } catch { /* ignore */ }
        try { conn && conn.close && conn.close(); } catch { /* ignore */ }
        try { dispatcher.closeAll(); } catch { /* ignore */ }
        try { linkMgr.closeAll(); } catch { /* ignore */ }
        setTimeout(() => process.exit(0), 300);

    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

};

main().catch((err) => die(err.stack || err.message));
