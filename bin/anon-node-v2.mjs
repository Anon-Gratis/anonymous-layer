#!/usr/bin/env node
// Reference v0.2 anon-node (PRE-AUDIT EXPERIMENTAL).
//
// First sub-chunk: persistent identity + listener that accepts inbound
// link connections and verifies the LINK_AUTH handshake. Cells beyond
// the handshake are logged and dropped (circuit dispatch lands in 9.4b).
//
// This is intentionally a thin shell over modules/v2-runtime/. The
// goal is operator UX: `init` to generate identity, `run` to start
// listening, `info` to print fingerprint. Sensible defaults; minimal
// flags.

import { resolve, join } from 'node:path';
import { homedir } from 'node:os';
import { readFile, writeFile, mkdir } from 'node:fs/promises';

import {
    loadIdentity,
    loadOrCreateIdentity,
    exists,
} from '../modules/v2-runtime/persistence.mjs';
import {
    createLinkListener,
} from '../modules/v2-runtime/link_transport_ws.mjs';
import {
    loadOrCreateLinkCert,
} from '../modules/v2-runtime/self_signed_cert.mjs';
import {
    createLinkManager,
} from '../modules/v2-runtime/link_manager.mjs';
import {
    createCircuitDispatcher,
} from '../modules/v2-runtime/circuit_dispatcher.mjs';
import {
    createExitStreamHandler,
} from '../modules/v2-runtime/streams.mjs';
import {
    createIpRole,
} from '../modules/v2-runtime/ip_role.mjs';
import {
    createRpRole,
} from '../modules/v2-runtime/rp_role.mjs';
import {
    createHsdirExitRole,
} from '../modules/v2-runtime/hsdir_exit_role.mjs';
import {
    POLICY_REJECT_ALL,
    POLICY_REDUCED_EXIT,
    POLICY_STANDARD_EXIT,
    parsePolicy,
} from '../modules/v2/exit_policy.mjs';
import {
    loadConsensus,
    loadDaTrustSet,
} from '../modules/v2-runtime/consensus_loader.mjs';
import { createPeerResolver } from '../modules/v2-runtime/peer_resolver.mjs';

const USAGE = `\
anon-node-v2 — reference v0.2 relay daemon (PRE-AUDIT EXPERIMENTAL)

This is a development/testing build of the v0.2 anon-layer protocol.
It does NOT YET provide anonymity. Do not use against any real-world
threat model.

Usage:
  anon-node-v2 init   [--data-dir DIR]
  anon-node-v2 info   [--data-dir DIR]
  anon-node-v2 run    [--data-dir DIR] [--port N] [--host H]
                      [--exit-policy <reject|reduced|standard|file:PATH>]
                      [--i-understand-this-is-experimental]

Subcommands:
  init    Generate a fresh identity and write it to DIR/identity.key
          (refuses if the file already exists).
  info    Print this node's Ed25519 fingerprint, public keys, and the
          listen address baked into its config (if any).
  run     Start the listener. Requires --i-understand-this-is-experimental
          to acknowledge the warning.

Options:
  --data-dir DIR        Directory for persistent state. Default ~/.anon-node-v2
  --port N              Listen port. Default 9001
  --host H              Bind address. Default 127.0.0.1
  --consensus PATH      Binary consensus file. Optional but required to
                        dispatch RELAY_EXTEND (without it, this relay
                        can only serve as a one-hop circuit endpoint).
  --da-trust PATH       JSON DA trust set. Required if --consensus is set.
  --exit-policy <mode>  How this node acts when it's the exit hop of a
                        circuit. Default 'reject' — NEVER acts as exit.
                          reject      Refuse all RELAY_BEGIN. Safe default.
                          reduced     Web + DNS only (HTTPS/HTTP/DNS).
                          standard    Tor-style broad exit policy.
                          file:PATH   Load a wire-format policy from disk
                                      (modules/v2/exit_policy.mjs's
                                      buildPolicy output).
                        Operating as an exit incurs legal/operational
                        responsibility (your IP appears as the source of
                        all traffic for circuits ending here). Don't
                        enable it without understanding what that means.
`;

const die = (msg, code = 1) => {

    process.stderr.write(`error: ${msg}\n`);
    process.exit(code);

};

const log = (msg) => {

    process.stderr.write(`[${new Date().toISOString()}] ${msg}\n`);

};

const hex = (bytes) => Buffer.from(bytes).toString('hex');

const defaultDataDir = () => process.env.ANON_NODE_V2_HOME
    || join(homedir(), '.anon-node-v2');

const parseArgs = (argv) => {

    const args = argv.slice(2);
    if (args.length === 0) return null;
    const subcommand = args[0];
    const opts = {
        subcommand,
        dataDir: defaultDataDir(),
        port: 9001,
        host: '127.0.0.1',
        consensusPath: null,
        daTrustPath: null,
        exitPolicyMode: 'reject',
        ack: false,
    };
    for (let i = 1; i < args.length; i += 1) {

        const a = args[i];
        if (a === '--data-dir') { opts.dataDir = args[i + 1]; i += 1; continue; }
        if (a === '--port') { opts.port = parseInt(args[i + 1], 10); i += 1; continue; }
        if (a === '--host') { opts.host = args[i + 1]; i += 1; continue; }
        if (a === '--consensus') { opts.consensusPath = args[i + 1]; i += 1; continue; }
        if (a === '--da-trust')  { opts.daTrustPath = args[i + 1]; i += 1; continue; }
        if (a === '--exit-policy') { opts.exitPolicyMode = args[i + 1]; i += 1; continue; }
        if (a === '--hsdir-url')   { opts.hsdirUrl = args[i + 1]; i += 1; continue; }
        if (a === '--i-understand-this-is-experimental') { opts.ack = true; continue; }
        if (a === '--help' || a === '-h') return null;
        if (a.startsWith('--')) die(`unknown option: ${a}`);
        die(`unexpected argument: ${a}`);

    }
    return opts;

};

// Resolve --exit-policy <mode> to a parsed policy (array of rule objects).
// Returns { policy, label } where label is a short description for logs.
const resolveExitPolicy = async (mode) => {

    if (mode === 'reject')   return { policy: POLICY_REJECT_ALL,    label: 'reject (no exit)' };
    if (mode === 'reduced')  return { policy: POLICY_REDUCED_EXIT,  label: `reduced (${POLICY_REDUCED_EXIT.length} accept rules + implicit reject)` };
    if (mode === 'standard') return { policy: POLICY_STANDARD_EXIT, label: `standard (${POLICY_STANDARD_EXIT.length} accept rules + implicit reject)` };
    if (mode.startsWith('file:')) {

        const path = mode.slice('file:'.length);
        let bytes;
        try { bytes = await readFile(path); }
        catch (err) { die(`could not read --exit-policy file ${path}: ${err.message}`); }
        const parsed = parsePolicy(new Uint8Array(bytes));
        if (parsed === null) die(`--exit-policy file ${path} did not parse as a valid policy`);
        return { policy: parsed, label: `file:${path} (${parsed.length} rules)` };

    }
    die(`unknown --exit-policy: ${mode}`);
    return null;

};

const cmdInit = async (opts) => {

    const dir = resolve(opts.dataDir);
    const path = join(dir, 'identity.key');
    if (await exists(path)) {

        die(`identity already exists at ${path}; refuse to overwrite`);

    }
    await mkdir(dir, { recursive: true });
    const { identity } = await loadOrCreateIdentity(path);
    process.stdout.write(`identity written to ${path}\n`);
    process.stdout.write(`fingerprint: ${hex(identity.fingerprint)}\n`);
    process.stdout.write(`idPk:        ${hex(identity.idPk)}\n`);
    process.stdout.write(`B_pk:        ${hex(identity.B_pk)}\n`);

};

const cmdInfo = async (opts) => {

    const dir = resolve(opts.dataDir);
    const path = join(dir, 'identity.key');
    if (!await exists(path)) {

        die(`no identity at ${path}; run "anon-node-v2 init" first`);

    }
    const identity = await loadIdentity(path);
    process.stdout.write(`data-dir:    ${dir}\n`);
    process.stdout.write(`fingerprint: ${hex(identity.fingerprint)}\n`);
    process.stdout.write(`idPk:        ${hex(identity.idPk)}\n`);
    process.stdout.write(`B_pk:        ${hex(identity.B_pk)}\n`);

};

const cmdRun = async (opts) => {

    if (!opts.ack) {

        die(
            'refusing to start without --i-understand-this-is-experimental.\n'
            + 'this is PRE-AUDIT experimental code; it does not provide anonymity.',
        );

    }

    const dir = resolve(opts.dataDir);
    const path = join(dir, 'identity.key');
    if (!await exists(path)) {

        die(`no identity at ${path}; run "anon-node-v2 init" first`);

    }
    const identity = await loadIdentity(path);

    process.stderr.write([
        '',
        '================================================================',
        '            ANONYMOUS LAYER v0.2 — PRE-AUDIT BUILD              ',
        '================================================================',
        'This implementation is built against a DRAFT protocol spec that ',
        'has not been reviewed by an independent cryptographer. The      ',
        'implementation has not been audited.                            ',
        '----------------------------------------------------------------',
        '',
    ].join('\n'));

    log(`fingerprint: ${hex(identity.fingerprint)}`);

    const { policy: exitPolicy, label: exitPolicyLabel } = await resolveExitPolicy(opts.exitPolicyMode);
    log(`exit-policy: ${exitPolicyLabel}`);

    // Optional consensus loading. Without it, this relay can serve as
    // a 1-hop circuit endpoint but can't dispatch RELAY_EXTEND (no way
    // to look up next-hop transport info).
    let peerResolver = () => null;
    if (opts.consensusPath) {

        if (!opts.daTrustPath) die('--consensus requires --da-trust');
        const daTrust = await loadDaTrustSet(opts.daTrustPath);
        const consensus = await loadConsensus({
            path: opts.consensusPath, daTrustSet: daTrust,
        });
        peerResolver = createPeerResolver({ consensus });
        log(`consensus loaded: ${consensus.rses.length} relays`);

    } else {

        log('no --consensus supplied; RELAY_EXTEND will be rejected (1-hop only)');

    }

    const exitHandler = createExitStreamHandler({
        exitPolicy,
        logger: (msg) => log(`  exit: ${msg}`),
    });
    // Every v0.2 relay supports the rendezvous-point and introduction-
    // point roles. They're protocol-only and impose no exit-policy
    // questions on the operator (no TCP egress involved), so they're
    // always on.
    const ipRole = createIpRole({ identity, logger: (msg) => log(`  ip: ${msg}`) });
    const rpRole = createRpRole({ logger: (msg) => log(`  rp: ${msg}`) });
    // Narrow HSDir-fetch role: when --hsdir-url is configured, the
    // relay accepts RELAY_DESCFETCH and proxies an HTTPS GET to that
    // hardcoded HSDir endpoint on the client's behalf. No general
    // egress; the URL is operator-set, not client-set.
    const hsdirRole = opts.hsdirUrl
        ? createHsdirExitRole({
            daBaseUrl: opts.hsdirUrl,
            logger: (msg) => log(`  hsdir: ${msg}`),
        })
        : null;
    if (hsdirRole) log(`hsdir-fetch role armed (DA: ${opts.hsdirUrl})`);

    const linkMgr = createLinkManager({
        identity,
        onCell: (link, cell) => dispatcher.onCell(link, cell),
        onLinkOpen: (link) => {

            log(`+link from peer ${link.peerFingerprintHex.slice(0, 16)}…  (${linkMgr.getLinkCount()} active)`);

        },
        onLinkClose: (link) => {

            log(`-link from peer ${link.peerFingerprintHex.slice(0, 16)}…  (${linkMgr.getLinkCount()} active)`);

        },
    });

    // The dispatcher needs to know how to dial next-hop relays for
    // RELAY_EXTEND. Without a consensus loaded in this binary, the
    // peerResolver returns null and EXTEND fails cleanly (the circuit
    // is destroyed and the client sees a failure). A future revision
    // could add a --consensus flag to anon-node-v2 so a single binary
    // can act as both relay and client; for now `bin/anon-socks.mjs`
    // is the client entry point that loads consensus.
    const dispatcher = createCircuitDispatcher({
        identity,
        linkManager: linkMgr,
        peerResolver,
        onExitData: (d) => {

            // Multiple roles consume the same dispatched payload; each
            // filters by relayCommand so they don't conflict.
            exitHandler.handleData(d);
            ipRole.handleData(d);
            rpRole.handleData(d);
            if (hsdirRole) hsdirRole.handleData(d);

        },
        logger: (msg) => log(`  ${msg}`),
    });

    // Link-transport TLS (SPEC § 11.1): self-signed cert, persistent
    // across restarts in the data dir. Cert is NOT identity (LINK_AUTH
    // is) — see modules/v2-runtime/self_signed_cert.mjs for the
    // documented design choices.
    const { certPem, keyPem } = loadOrCreateLinkCert(opts.dataDir);

    const listener = await createLinkListener({
        port: opts.port, host: opts.host, identity,
        tlsCert: certPem, tlsKey: keyPem,
        onLink: (link) => linkMgr.acceptLink(link),
    });

    log(`listening on wss://${listener.address}:${listener.port}`);
    log('Ctrl-C to shut down');

    const shutdown = async () => {

        log('shutting down…');
        ipRole.clear();
        rpRole.clear();
        exitHandler.closeAll();
        dispatcher.closeAll();
        linkMgr.closeAll();
        await listener.close();
        process.exit(0);

    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

};

const main = async () => {

    const opts = parseArgs(process.argv);
    if (opts === null) { process.stdout.write(USAGE); process.exit(0); }

    if (!Number.isInteger(opts.port) || opts.port < 0 || opts.port > 65535) {

        die(`bad --port: ${opts.port}`);

    }

    switch (opts.subcommand) {

        case 'init': await cmdInit(opts); break;
        case 'info': await cmdInfo(opts); break;
        case 'run':  await cmdRun(opts); break;
        default: die(`unknown subcommand: ${opts.subcommand}`);

    }

};

main().catch((err) => die(err.stack || err.message));
