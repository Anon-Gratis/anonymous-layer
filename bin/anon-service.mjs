#!/usr/bin/env node
// Reference v0.2 hidden-service daemon (PRE-AUDIT EXPERIMENTAL).
//
// Subcommands:
//   init    Generate service identity + per-IP keys + descriptor.
//   info    Print onion address, descriptor path, IP fingerprint.
//   publish Long-lived daemon: build IP circuit, ESTABLISH_INTRO,
//           handle INTRODUCE2, bridge spliced streams to a local TCP
//           destination.

import { resolve, join } from 'node:path';
import { homedir } from 'node:os';
import { readFile, writeFile, mkdir } from 'node:fs/promises';

import {
    loadOrCreateIdentity,
    loadIdentity as loadNodeIdentity,
} from '../modules/v2-runtime/persistence.mjs';
import {
    loadOrCreateServiceIdentity,
    loadServiceIdentity,
    saveServiceIdentity,
} from '../modules/v2-runtime/service_persistence.mjs';
import { createLinkManager } from '../modules/v2-runtime/link_manager.mjs';
import { createCircuitDispatcher } from '../modules/v2-runtime/circuit_dispatcher.mjs';
import { createCellRouter } from '../modules/v2-runtime/cell_router.mjs';
import { createPeerResolver } from '../modules/v2-runtime/peer_resolver.mjs';
import { createCircuitBuilder } from '../modules/v2-runtime/circuit_builder.mjs';
import { createServicePublisher } from '../modules/v2-runtime/service_publisher.mjs';
import {
    loadConsensus, loadDaTrustSet,
} from '../modules/v2-runtime/consensus_loader.mjs';
import { buildServiceDescriptorV3 } from '../modules/v2/descriptor.mjs';
import {
    pickPath,
    selectMiddle,
    FLAG_GUARD,
    FLAG_RUNNING,
    FLAG_VALID,
} from '../modules/v2/consensus.mjs';

const USAGE = `\
anon-service — v0.2 hidden-service daemon (PRE-AUDIT EXPERIMENTAL)

Subcommands:
  anon-service init    --data-dir DIR --ip-fingerprint HEX
                       --consensus PATH --da-trust PATH
                       [--lifetime-seconds N]
  anon-service info    --data-dir DIR
  anon-service publish --data-dir DIR --local-port N [--local-host H]
                       --consensus PATH --da-trust PATH
                       --i-understand-this-is-experimental

Options:
  --data-dir DIR        Directory for persistent service state.
                        Default: \$ANON_SERVICE_HOME or ~/.anon-service
  --ip-fingerprint HEX  Hex Blake2b-256 fingerprint of the relay to use
                        as the service's introduction point.
  --consensus PATH      Binary consensus file.
  --da-trust PATH       JSON DA-trust file.
  --local-port N        TCP port on --local-host to forward client
                        streams to. Default --local-host: 127.0.0.1
  --lifetime-seconds N  Descriptor lifetime. Default 3600 (1 hour).
  --allow-co-located    Skip anti-correlation between path hops. Use
                        ONLY on testnets where all relays share an IP.
                        Weakens anonymity in real deployments.
  --i-understand-this-is-experimental  Required for "publish".

After init, the descriptor lives at DIR/descriptor.bin. Distribute
that file to clients out-of-band (HSDir is not yet implemented).
`;

const die = (msg, code = 1) => {

    process.stderr.write(`error: ${msg}\n`);
    process.exit(code);

};

const log = (msg) => process.stderr.write(`[${new Date().toISOString()}] ${msg}\n`);
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const defaultDataDir = () => process.env.ANON_SERVICE_HOME || join(homedir(), '.anon-service');

const parseArgs = () => {

    const args = process.argv.slice(2);
    if (args.length === 0) return null;
    const opts = {
        subcommand: args[0],
        dataDir: defaultDataDir(),
        ipFingerprint: null,
        consensusPath: null,
        daTrustPath: null,
        localHost: '127.0.0.1',
        localPort: null,
        lifetimeSeconds: 3600,
        skipAntiCorrelation: false,
        ack: false,
    };
    for (let i = 1; i < args.length; i += 1) {

        const a = args[i];
        if (a === '--data-dir')        { opts.dataDir = args[i + 1]; i += 1; continue; }
        if (a === '--ip-fingerprint')  { opts.ipFingerprint = args[i + 1]; i += 1; continue; }
        if (a === '--consensus')       { opts.consensusPath = args[i + 1]; i += 1; continue; }
        if (a === '--da-trust')        { opts.daTrustPath = args[i + 1]; i += 1; continue; }
        if (a === '--local-host')      { opts.localHost = args[i + 1]; i += 1; continue; }
        if (a === '--local-port')      { opts.localPort = parseInt(args[i + 1], 10); i += 1; continue; }
        if (a === '--lifetime-seconds') { opts.lifetimeSeconds = parseInt(args[i + 1], 10); i += 1; continue; }
        if (a === '--allow-co-located') { opts.skipAntiCorrelation = true; continue; }
        if (a === '--i-understand-this-is-experimental') { opts.ack = true; continue; }
        if (a === '--help' || a === '-h') return null;
        if (a.startsWith('--')) die(`unknown option: ${a}`);
        die(`unexpected argument: ${a}`);

    }
    return opts;

};

const findRseByFp = (consensus, fpHex) => consensus.rses.find(
    (r) => Buffer.from(r.fingerprint).toString('hex').toLowerCase() === fpHex.toLowerCase(),
);

const cmdInit = async (opts) => {

    if (!opts.ipFingerprint) die('--ip-fingerprint HEX is required');
    if (!opts.consensusPath) die('--consensus PATH is required');
    if (!opts.daTrustPath)   die('--da-trust PATH is required');
    if (!/^[0-9a-fA-F]{64}$/.test(opts.ipFingerprint)) {

        die(`--ip-fingerprint must be 64 hex chars; got "${opts.ipFingerprint}"`);

    }

    const dir = resolve(opts.dataDir);
    const idPath = join(dir, 'identity.bin');
    const descPath = join(dir, 'descriptor.bin');

    const daTrust = await loadDaTrustSet(opts.daTrustPath);
    const consensus = await loadConsensus({
        path: opts.consensusPath, daTrustSet: daTrust,
    });

    const ipRse = findRseByFp(consensus, opts.ipFingerprint);
    if (!ipRse) die(`IP fingerprint ${opts.ipFingerprint} is not in the consensus`);

    await mkdir(dir, { recursive: true });
    const { bundle, created } = await loadOrCreateServiceIdentity(idPath);

    const publishEpoch = Math.floor(Date.now() / 1000);
    const descriptorBytes = buildServiceDescriptorV3({
        SVC_sk_ed:    bundle.SVC_sk_ed,
        SVC_pk_ed:    bundle.SVC_pk_ed,
        SVC_sk_mldsa: bundle.SVC_sk_mldsa,
        SVC_pk_mldsa: bundle.SVC_pk_mldsa,
        publishEpoch,
        lifetimeSeconds: opts.lifetimeSeconds,
        introPoints: [{
            fingerprint: ipRse.fingerprint,
            ipOnionPk: ipRse.onionPk,
            serviceIntroKey: bundle.serviceIntroPk,
            serviceEncX25519Pk: bundle.serviceEncX25519Pk,
            serviceEncMlkemPk: bundle.serviceEncMlkemPk,
        }],
    });
    await writeFile(descPath, descriptorBytes);

    process.stdout.write(`${created ? 'generated' : 'loaded'} service identity → ${idPath}\n`);
    process.stdout.write(`wrote descriptor (${descriptorBytes.length} bytes, ${opts.lifetimeSeconds}s lifetime) → ${descPath}\n`);
    process.stdout.write(`onion address: ${bundle.onionAddress}\n`);
    process.stdout.write(`IP fingerprint: ${opts.ipFingerprint}\n`);

};

const cmdInfo = async (opts) => {

    const dir = resolve(opts.dataDir);
    const idPath = join(dir, 'identity.bin');
    const descPath = join(dir, 'descriptor.bin');
    let bundle;
    try { bundle = await loadServiceIdentity(idPath); }
    catch (err) { die(`could not load ${idPath}: ${err.message}`); }
    process.stdout.write(`data-dir:        ${dir}\n`);
    process.stdout.write(`onion address:   ${bundle.onionAddress}\n`);
    process.stdout.write(`SVC_pk (hex):    ${hex(bundle.SVC_pk)}\n`);
    process.stdout.write(`descriptor:      ${descPath}\n`);

};

const cmdPublish = async (opts) => {

    if (!opts.ack) {

        die('refusing to start without --i-understand-this-is-experimental.\n'
            + 'this is PRE-AUDIT experimental code; it does not provide anonymity.');

    }
    if (!opts.localPort)      die('--local-port N is required');
    if (!opts.consensusPath)  die('--consensus PATH is required');
    if (!opts.daTrustPath)    die('--da-trust PATH is required');

    const dir = resolve(opts.dataDir);
    const idPath = join(dir, 'identity.bin');
    const descPath = join(dir, 'descriptor.bin');
    const nodeIdPath = join(dir, 'node-identity.key');

    const serviceBundle = await loadServiceIdentity(idPath);
    const descriptorBytes = await readFile(descPath);
    const daTrust = await loadDaTrustSet(opts.daTrustPath);
    const consensus = await loadConsensus({
        path: opts.consensusPath, daTrustSet: daTrust,
    });

    // The service needs its OWN node identity for the LinkManager
    // handshakes. This is separate from the service identity.
    const { identity: nodeIdentity, created: nodeCreated } = await loadOrCreateIdentity(nodeIdPath);

    log(`onion: ${serviceBundle.onionAddress}`);
    log(`node-identity ${nodeCreated ? 'generated' : 'loaded'}: ${hex(nodeIdentity.fingerprint).slice(0, 16)}…`);
    log(`local destination: ${opts.localHost}:${opts.localPort}`);

    // Parse the descriptor to find the IP fingerprint we registered with.
    const { parseServiceDescriptorAny } = await import('../modules/v2/descriptor.mjs');
    const parsedDesc = parseServiceDescriptorAny(new Uint8Array(descriptorBytes));
    if (!parsedDesc || parsedDesc.introPoints.length === 0) {

        die(`descriptor at ${descPath} has no intro points; re-run "anon-service init"`);

    }
    const introPointRecord = parsedDesc.introPoints[0];

    // Build the introduction-point bundle for the publisher.
    const introductionPoint = {
        fingerprint: introPointRecord.fingerprint,
        ipOnionPk: introPointRecord.ipOnionPk,
        serviceIntroSk: serviceBundle.serviceIntroSk,
        serviceIntroPk: serviceBundle.serviceIntroPk,
        serviceEncX25519Sk: serviceBundle.serviceEncX25519Sk,
        serviceEncX25519Pk: serviceBundle.serviceEncX25519Pk,
        serviceEncMlkemSk: serviceBundle.serviceEncMlkemSk,
        serviceEncMlkemPk: serviceBundle.serviceEncMlkemPk,
    };

    const peerResolver = createPeerResolver({ consensus });

    // Set up the runtime (LinkManager + dispatcher + cell router + builder).
    const routerHolder = { router: null };
    const linkMgr = createLinkManager({
        identity: nodeIdentity,
        onCell: (link, cell) => { if (routerHolder.router) routerHolder.router.onCell(link, cell); },
    });
    const dispatcher = createCircuitDispatcher({
        identity: nodeIdentity, linkManager: linkMgr, peerResolver,
    });
    routerHolder.router = createCellRouter({ relayDispatcher: dispatcher });
    const circuitBuilder = createCircuitBuilder({
        linkManager: linkMgr,
        cellRouter: routerHolder.router,
        peerResolver,
        logger: (msg) => log(`  builder: ${msg}`),
    });

    // Path selection. The service needs a 3-hop path that exits at a
    // specific relay (the IP for the long-lived circuit; the RP for
    // each rendezvous). Custom selection rather than naive `pickPath`
    // → swap-exit, because pickPath might pick the forced exit as its
    // guard or middle, causing a self-dial loop when the middle hop
    // tries to EXTEND to the exit.
    const fpEq = (a, b) => Buffer.from(a).equals(Buffer.from(b));
    const pickRand = (arr) => arr[Math.floor(Math.random() * arr.length)];

    const pickPathForExit = (exitRse) => {

        // Guard candidates: RUNNING + VALID + GUARD, not the exit.
        const guardCandidates = consensus.rses.filter((r) => (
            (r.flags & (FLAG_RUNNING | FLAG_VALID | FLAG_GUARD)) === (FLAG_RUNNING | FLAG_VALID | FLAG_GUARD)
            && !fpEq(r.fingerprint, exitRse.fingerprint)
        ));
        if (guardCandidates.length === 0) {

            throw new Error(`no guard candidate distinct from forced exit ${Buffer.from(exitRse.fingerprint).toString('hex').slice(0, 16)}…`);

        }
        const guard = pickRand(guardCandidates);

        const middle = selectMiddle({
            consensus,
            excludeFps: [guard.fingerprint, exitRse.fingerprint],
            coLocateAvoid: opts.skipAntiCorrelation ? [] : [guard, exitRse],
        });
        if (!middle) throw new Error('no middle candidate');

        return { guard, middle, exit: exitRse };

    };

    const ipPath = ({ ipFingerprint }) => {

        const ipRse = consensus.rses.find((r) => fpEq(r.fingerprint, ipFingerprint));
        if (!ipRse) throw new Error('IP not in consensus');
        return pickPathForExit(ipRse);

    };
    const rpPath = ({ rpRse }) => pickPathForExit(rpRse);

    const publisher = createServicePublisher({
        SVC_pk: serviceBundle.SVC_pk,
        introductionPoint,
        rpPath,
        ipPath,
        consensus,
        peerResolver,
        linkManager: linkMgr,
        cellRouter: routerHolder.router,
        circuitBuilder,
        localDestination: { host: opts.localHost, port: opts.localPort },
        logger: (msg) => log(`  svc: ${msg}`),
    });

    try {

        await publisher.start();
        log('service published — accepting introductions');

    } catch (err) {

        die(`publish failed: ${err.message}`);

    }

    const shutdown = async () => {

        log('shutting down…');
        publisher.stop();
        dispatcher.closeAll();
        linkMgr.closeAll();
        process.exit(0);

    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

};

const main = async () => {

    const opts = parseArgs();
    if (opts === null) { process.stdout.write(USAGE); process.exit(0); }

    switch (opts.subcommand) {

        case 'init':    await cmdInit(opts); break;
        case 'info':    await cmdInfo(opts); break;
        case 'publish': await cmdPublish(opts); break;
        default: die(`unknown subcommand: ${opts.subcommand}`);

    }

};

main().catch((err) => die(err.stack || err.message));
