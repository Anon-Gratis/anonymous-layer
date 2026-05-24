#!/usr/bin/env node
// v0.2 — PRE-AUDIT EXPERIMENTAL BINARY
//
// SOCKS5 server that exposes a tunnel factory to clients. Currently
// only the `direct` tunnel factory is wired up (transparent TCP — NOT
// anonymous). The `anon-layer` factory is the future integration with
// the v0.2 runtime and refuses to start until that runtime exists.

import net from 'node:net';
import { resolve, join } from 'node:path';
import { homedir } from 'node:os';

import { requireAck } from '../modules/v2/banner.mjs';
import {
    handleSocksConnection,
    directTcpTunnelFactory,
    refusingTunnelFactory,
} from '../modules/v2/socks.mjs';
import { loadOrCreateIdentity } from '../modules/v2-runtime/persistence.mjs';
import { createLinkManager } from '../modules/v2-runtime/link_manager.mjs';
import { createCircuitDispatcher } from '../modules/v2-runtime/circuit_dispatcher.mjs';
import { createCellRouter } from '../modules/v2-runtime/cell_router.mjs';
import { createPeerResolver } from '../modules/v2-runtime/peer_resolver.mjs';
import { createCircuitBuilder } from '../modules/v2-runtime/circuit_builder.mjs';
import { createAnonLayerTunnelFactory } from '../modules/v2-runtime/anon_layer_tunnel.mjs';
import {
    loadConsensus,
    loadDaTrustSet,
} from '../modules/v2-runtime/consensus_loader.mjs';

const USAGE = `\
anon-socks — SOCKS5 server with pluggable tunnel factory

Usage:
  anon-socks --tunnel <direct|anon-layer|none> [--port N] [--host H] \\
             [--data-dir DIR] [--consensus PATH] [--da-trust PATH] \\
             --i-understand-this-is-experimental

  --tunnel direct       Direct TCP. NOT ANONYMOUS — works like a
                        regular transparent SOCKS proxy. Useful for
                        validating the SOCKS5 plumbing.
  --tunnel anon-layer   Routes through v0.2 circuits. Requires
                        --consensus and --da-trust paths; uses a
                        persistent client identity under --data-dir.
  --tunnel none         Refuses to route. Useful for testing rejection.
  --port N              Listen port (default 1080).
  --host H              Listen address (default 127.0.0.1).
  --data-dir DIR        Persistent state directory. Default
                        ~/.anon-node-v2 (anon-layer mode only).
  --consensus PATH      Path to a consensus bytes file (anon-layer mode).
  --da-trust PATH       Path to a DA trust-set JSON file (anon-layer mode).
`;

const die = (msg, code = 1) => {

    process.stderr.write(`error: ${msg}\n`);
    process.exit(code);

};

const parseArgs = (argv) => {

    let tunnel = null;
    let port = 1080;
    let host = '127.0.0.1';
    let dataDir = process.env.ANON_NODE_V2_HOME || join(homedir(), '.anon-node-v2');
    let consensusPath = null;
    let daTrustPath = null;
    for (let i = 0; i < argv.length; i += 1) {

        const a = argv[i];
        if (a === '--tunnel')    { tunnel = argv[i + 1]; i += 1; continue; }
        if (a === '--port')      { port = parseInt(argv[i + 1], 10); i += 1; continue; }
        if (a === '--host')      { host = argv[i + 1]; i += 1; continue; }
        if (a === '--data-dir')  { dataDir = argv[i + 1]; i += 1; continue; }
        if (a === '--consensus') { consensusPath = argv[i + 1]; i += 1; continue; }
        if (a === '--da-trust')  { daTrustPath = argv[i + 1]; i += 1; continue; }
        if (a === '--i-understand-this-is-experimental') continue;
        die(`unknown argument: ${a}`);

    }
    if (tunnel === null) die('--tunnel <direct|anon-layer|none> is required');
    if (!Number.isInteger(port) || port < 0 || port > 65535) die(`bad --port value`);
    return { tunnel, port, host, dataDir, consensusPath, daTrustPath };

};

// Build the anon-layer tunnel: load identity + consensus, instantiate
// the runtime, return both the tunnelFactory and a `close` function
// that tears down the runtime on shutdown.
const buildAnonLayerRuntime = async ({ dataDir, consensusPath, daTrustPath }) => {

    if (!consensusPath) die('--consensus PATH is required for --tunnel anon-layer');
    if (!daTrustPath)   die('--da-trust PATH is required for --tunnel anon-layer');

    const identityPath = join(resolve(dataDir), 'identity.key');
    const { identity, created } = await loadOrCreateIdentity(identityPath);
    process.stderr.write(
        `[${new Date().toISOString()}] anon-layer identity ${created ? 'generated' : 'loaded'}: `
        + `${Buffer.from(identity.fingerprint).toString('hex').slice(0, 16)}…\n`,
    );

    const daTrust = await loadDaTrustSet(daTrustPath);
    const consensus = await loadConsensus({ path: consensusPath, daTrustSet: daTrust });
    process.stderr.write(
        `[${new Date().toISOString()}] consensus loaded: ${consensus.rses.length} relays\n`,
    );

    const peerResolver = createPeerResolver({ consensus });
    const routerHolder = { router: null };
    const linkMgr = createLinkManager({
        identity,
        onCell: (link, cell) => {

            if (routerHolder.router) routerHolder.router.onCell(link, cell);

        },
    });
    const dispatcher = createCircuitDispatcher({
        identity, linkManager: linkMgr, peerResolver,
    });
    routerHolder.router = createCellRouter({ relayDispatcher: dispatcher });
    const builder = createCircuitBuilder({
        linkManager: linkMgr, cellRouter: routerHolder.router, peerResolver,
        logger: (msg) => process.stderr.write(`[${new Date().toISOString()}]   ${msg}\n`),
    });

    const { tunnelFactory, closeStandby } = createAnonLayerTunnelFactory({
        consensus, circuitBuilder: builder,
        logger: (msg) => process.stderr.write(`[${new Date().toISOString()}]   ${msg}\n`),
    });

    return {
        tunnelFactory,
        close: () => {

            try { closeStandby(); } catch { /* ignore */ }
            try { dispatcher.closeAll(); } catch { /* ignore */ }
            try { linkMgr.closeAll(); } catch { /* ignore */ }

        },
    };

};

const pickTunnelFactory = async ({ tunnel, dataDir, consensusPath, daTrustPath }) => {

    if (tunnel === 'direct') return { tunnelFactory: directTcpTunnelFactory, close: () => {} };
    if (tunnel === 'none')   return { tunnelFactory: refusingTunnelFactory, close: () => {} };
    if (tunnel === 'anon-layer') {

        return buildAnonLayerRuntime({ dataDir, consensusPath, daTrustPath });

    }
    die(`unknown --tunnel: ${tunnel}`);
    return null;

};

const main = async () => {

    const args = process.argv.slice(2);
    if (args.length === 0) { process.stdout.write(USAGE); process.exit(0); }
    requireAck(args);

    const parsed = parseArgs(args);
    const { tunnelFactory, close: closeTunnel } = await pickTunnelFactory(parsed);

    // allowHalfOpen: true so the SOCKS server can write its REPLY after
    // the client half-closes (same lesson as chunk 9.3 for anon-site).
    const server = net.createServer({ allowHalfOpen: true }, (socket) => {

        const remote = `${socket.remoteAddress}:${socket.remotePort}`;
        handleSocksConnection({ socket, tunnelFactory }).then((status) => {

            process.stderr.write(`[${new Date().toISOString()}] socks ${remote} ${status}\n`);

        });

    });
    server.on('error', (err) => die(`listener error: ${err.message}`));
    server.listen(parsed.port, parsed.host, () => {

        const addr = server.address();
        process.stderr.write(
            `[${new Date().toISOString()}] socks5 listener on ${addr.address}:${addr.port}, `
            + `tunnel=${parsed.tunnel}\n`,
        );
        if (parsed.tunnel === 'direct') {

            process.stderr.write(
                'WARNING: --tunnel direct is a TRANSPARENT PROXY. There is no anonymity.\n',
            );

        }
        if (parsed.tunnel === 'anon-layer') {

            process.stderr.write(
                'NOTE: anon-layer in v0.2 reference does CLIENT-SIDE DNS resolution for\n'
                + '  hostname destinations. This leaks the DNS lookup to your local\n'
                + '  resolver. Exit-side resolution is a future-work item.\n',
            );

        }

    });

    const shutdown = () => {

        process.stderr.write(`\n[${new Date().toISOString()}] shutting down\n`);
        try { closeTunnel(); } catch { /* ignore */ }
        server.close(() => process.exit(0));

    };
    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);

};

main().catch((err) => die(err.stack || err.message));
