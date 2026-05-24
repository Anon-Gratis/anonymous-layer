#!/usr/bin/env node
import { loadConfig, writeConfig, writeSeedList, readSeedList } from '../modules/node/config.mjs';
import { loadOrCreateIdentity, loadIdentity, exists } from '../modules/node/persistence.mjs';
import { currentCertificate } from '../modules/node/identity.mjs';
import { createIdentityCache } from '../modules/node/identity_cache.mjs';
import { createPeerTable } from '../modules/peer/table.mjs';
import { createNode } from '../modules/node/node.mjs';
import { createWebSocketListener } from '../modules/node/transport_websocket.mjs';
import { createDialer } from '../modules/node/dialer.mjs';
import { createLogger } from '../modules/node/logger.mjs';
import { TRANSPORT_WEBSOCKET_IPV4 } from '../modules/wire/transport.mjs';
import { buildSeedRecord, parseSeedRecord } from '../modules/peer/seed.mjs';
import { fingerprint as fingerprintOf } from '../modules/crypto/fingerprint.mjs';

const USAGE = `\
anon-node — Anonymous Layer reference daemon

Usage:
  anon-node init <config-path> [--port N]
      Generate identity, write default config, write empty seed list.
      Files are created next to the config path unless absolute paths
      are given. Default listen port is 8443; --port overrides.
  anon-node info <config-path>
      Print identity fingerprint, listen address, and seed count.
  anon-node share <config-path>
      Print this node's seed record as hex. Hand to peers who should
      know about this node.
  anon-node add-seed <config-path> <hex>
      Append a peer's seed record (as hex) to this config's seed list.
      Refuses duplicates by fingerprint.
  anon-node run <config-path>
      Start the daemon: identity, listener, dialer, tick scheduler.
      Stops cleanly on SIGTERM/SIGINT.
`;

const hex = (bytes) => Buffer.from(bytes).toString('hex');

const die = (msg, code = 1) => {

    process.stderr.write(`error: ${msg}\n`);
    process.exit(code);

};

const cmdInit = async (configPath, { port = 8443 } = {}) => {

    if (await exists(configPath)) die(`refusing to overwrite existing config at ${configPath}`);

    // Derive companion paths from the config filename so two configs
    // in the same directory don't end up sharing an identity / seed
    // list. `./node.json` → `./node.identity.key`, `./node.seeds.bin`.
    const dir = configPath.replace(/\/[^/]*$/, '') || '.';
    const base = (configPath.split('/').pop() || configPath).replace(/\.(json|conf|cfg)$/, '');
    const identityPath = `${dir}/${base}.identity.key`;
    const seedListPath = `${dir}/${base}.seeds.bin`;

    const { identity, created } = await loadOrCreateIdentity(identityPath);
    await writeConfig(configPath, {
        identity: { path: identityPath },
        listen: { host: '127.0.0.1', port },
        seedList: { path: seedListPath },
        tickIntervalMs: 5000,
        logLevel: 'info',
    });
    // Empty seed list — operator populates manually.
    await writeSeedList(seedListPath, []);

    process.stdout.write(`config:      ${configPath}\n`);
    process.stdout.write(`identity:    ${identityPath} (${created ? 'generated' : 'existing'})\n`);
    process.stdout.write(`seed list:   ${seedListPath} (empty)\n`);
    process.stdout.write(`listen:      127.0.0.1:${port}\n`);
    process.stdout.write(`fingerprint: ${hex(identity.fingerprint)}\n`);

};

// IPv4 dotted-quad → 4-byte big-endian array. Returns null if `s` is
// not a literal IPv4 address (hostnames not supported by v0.1
// WEBSOCKET_IPV4 transport, per SPEC § 6.4.1).
const parseIPv4 = (s) => {

    const parts = s.split('.');
    if (parts.length !== 4) return null;
    const out = new Uint8Array(4);
    for (let i = 0; i < 4; i += 1) {

        const n = parseInt(parts[i], 10);
        if (!Number.isInteger(n) || n < 0 || n > 255 || String(n) !== parts[i]) return null;
        out[i] = n;

    }
    return out;

};

const cmdShare = async (configPath) => {

    const cfg = await loadConfig(configPath);
    const identity = await loadIdentity(cfg.identity.path);
    const ip = parseIPv4(cfg.listen.host);
    if (ip === null) die(`config.listen.host must be a literal IPv4 address for v0.1 share (got "${cfg.listen.host}")`);
    const certExpiry = Math.floor(Date.now() / 1000) + (30 * 24 * 3600);
    const cert = currentCertificate({ identity, expirySeconds: certExpiry });
    const address = new Uint8Array(6);
    address.set(ip, 0);
    address[4] = (cfg.listen.port >>> 8) & 0xFF;
    address[5] = cfg.listen.port & 0xFF;
    const record = buildSeedRecord({
        idPk: identity.idPk,
        certBytes: cert,
        transports: [{ type: TRANSPORT_WEBSOCKET_IPV4, address }],
    });
    process.stdout.write(`${hex(record)}\n`);

};

const cmdAddSeed = async (configPath, hexInput) => {

    const cfg = await loadConfig(configPath);
    let recordBytes;
    try {

        recordBytes = Uint8Array.from(Buffer.from(hexInput, 'hex'));

    } catch {

        die('hex argument did not parse');

    }
    if (recordBytes.length === 0) die('empty seed record');
    const parsed = parseSeedRecord(recordBytes, 0);
    if (parsed === null || parsed.consumed !== recordBytes.length) {

        die('seed record did not parse cleanly');

    }
    const incomingFp = fingerprintOf(parsed.record.idPk);

    // Read existing list, refuse duplicate-by-fingerprint, append.
    let existing = [];
    try {

        existing = await readSeedList(cfg.seedList.path) || [];

    } catch (err) {

        if (err.code !== 'ENOENT') throw err;

    }
    for (const e of existing) {

        const fp = fingerprintOf(e.idPk);
        if (Buffer.from(fp).equals(Buffer.from(incomingFp))) {

            die('a seed record with that fingerprint already exists');

        }

    }
    await writeSeedList(cfg.seedList.path, [...existing, parsed.record]);
    process.stdout.write(`added: ${hex(incomingFp)}\n`);
    process.stdout.write(`total seeds: ${existing.length + 1}\n`);

};

const cmdInfo = async (configPath) => {

    const cfg = await loadConfig(configPath);
    const identity = await loadIdentity(cfg.identity.path);
    let seedCount = 0;
    try {

        const records = await readSeedList(cfg.seedList.path);
        seedCount = records === null ? -1 : records.length;

    } catch (err) {

        if (err.code !== 'ENOENT') throw err;

    }
    process.stdout.write(`fingerprint:  ${hex(identity.fingerprint)}\n`);
    process.stdout.write(`onion pubkey: ${hex(identity.onionPk)}\n`);
    process.stdout.write(`listen:       ${cfg.listen.host}:${cfg.listen.port}\n`);
    process.stdout.write(`seed list:    ${cfg.seedList.path} `
        + `(${seedCount === -1 ? 'malformed' : `${seedCount} records`})\n`);

};

// Heuristic: try every WEBSOCKET_IPV4 transport in the seed record.
// SPEC § 6.4.1: IPV4 transport = 4 bytes IP + 2 bytes BE port.
const pickDialAddresses = (transports) => {

    const out = [];
    for (const t of transports) {

        if (t.type !== TRANSPORT_WEBSOCKET_IPV4) continue;
        if (t.address.length !== 6) continue;
        const host = `${t.address[0]}.${t.address[1]}.${t.address[2]}.${t.address[3]}`;
        const port = (t.address[4] << 8) | t.address[5];
        out.push({ host, port });

    }
    return out;

};

const cmdRun = async (configPath) => {

    const cfg = await loadConfig(configPath);
    const logger = createLogger({ level: cfg.logLevel });

    const identity = await loadIdentity(cfg.identity.path);
    const now = () => Math.floor(Date.now() / 1000);
    const certExpiry = now() + (30 * 24 * 3600); // 30 days
    const certBytes = currentCertificate({ identity, expirySeconds: certExpiry });

    const peerTable = createPeerTable({ now });
    const identityCache = createIdentityCache();

    const node = createNode({
        identity,
        peerTable,
        identityCache,
        currentCertBytes: certBytes,
        nowSeconds: now,
        onData: ({ senderFingerprint, conversationTag, sequenceNumber, payload }) => {

            logger.info('data received', {
                from: hex(senderFingerprint).slice(0, 16),
                tag: hex(conversationTag),
                seq: sequenceNumber,
                bytes: payload.length,
            });

        },
        onPeerConnected: (fp) => logger.info('peer connected', { fp: hex(fp).slice(0, 16) }),
        onPeerDisconnected: (fp) => logger.info('peer disconnected', { fp: hex(fp).slice(0, 16) }),
    });

    // Load seed list into peer table + identity cache.
    let seeds = [];
    try {

        const records = await readSeedList(cfg.seedList.path);
        if (records === null) {

            logger.error('seed list malformed; refusing to start', { path: cfg.seedList.path });
            process.exit(2);

        }
        seeds = records;

    } catch (err) {

        if (err.code !== 'ENOENT') throw err;
        logger.warn('no seed list found; running with empty peer table', { path: cfg.seedList.path });

    }

    for (const seed of seeds) {

        const ok = peerTable.addOrUpdate({
            idPk: seed.idPk,
            certBytes: seed.certBytes,
            transports: seed.transports,
            nowSeconds: now(),
        });
        if (ok) identityCache.set(seed.idPk);
        else logger.warn('seed record rejected', { fp: hex(seed.idPk).slice(0, 16) });

    }
    logger.info('seed list loaded', { count: peerTable.peerCount() });

    // Listener.
    const listener = createWebSocketListener(cfg.listen, (transport) => {

        node.acceptInbound(transport);
        logger.info('inbound connection accepted');

    });
    await listener.ready;
    logger.info('listening', { host: cfg.listen.host, port: listener.port });

    // Dialer — connect to each seed.
    const dialer = createDialer({ node, logger });
    for (const seed of seeds) {

        const addresses = pickDialAddresses(seed.transports);
        if (addresses.length === 0) {

            logger.warn('seed has no dialable IPV4 transports', { fp: hex(seed.idPk).slice(0, 16) });
            continue;

        }
        // v0.1 dialer is single-address-per-peer; pick the first.
        const { host, port } = addresses[0];
        dialer.connect({
            fingerprint: peerTable.list().find(
                (p) => Buffer.from(p.idPk).equals(Buffer.from(seed.idPk)),
            ).fingerprint,
            host,
            port,
        });

    }

    // Tick scheduler.
    const tickHandle = setInterval(() => {

        try {

            node.tick();

        } catch (err) {

            logger.error('tick threw', { err: err.message });

        }

    }, cfg.tickIntervalMs);

    // Clean shutdown.
    let shuttingDown = false;
    const shutdown = async (signal) => {

        if (shuttingDown) return;
        shuttingDown = true;
        logger.info('shutdown requested', { signal });
        clearInterval(tickHandle);
        dialer.stop();
        await listener.close();
        logger.info('shutdown complete');
        process.exit(0);

    };
    process.on('SIGTERM', () => { shutdown('SIGTERM'); });
    process.on('SIGINT',  () => { shutdown('SIGINT');  });

};

const main = async () => {

    const [, , subcommand, ...args] = process.argv;
    if (!subcommand) { process.stdout.write(USAGE); process.exit(0); }

    if (subcommand === 'init') {

        // Accept `<config-path> [--port N]` in any order.
        let configPath = null;
        let port = 8443;
        for (let i = 0; i < args.length; i += 1) {

            if (args[i] === '--port') {

                const n = parseInt(args[i + 1], 10);
                if (!Number.isInteger(n) || n < 0 || n > 65535) {

                    die(`--port requires an integer 0..65535 (got "${args[i + 1]}")`);

                }
                port = n;
                i += 1;
                continue;

            }
            if (configPath === null) { configPath = args[i]; continue; }
            die('usage: anon-node init <config-path> [--port N]');

        }
        if (configPath === null) die('usage: anon-node init <config-path> [--port N]');
        await cmdInit(configPath, { port });
        return;

    }
    if (subcommand === 'info') {

        if (args.length !== 1) die('usage: anon-node info <config-path>');
        await cmdInfo(args[0]);
        return;

    }
    if (subcommand === 'share') {

        if (args.length !== 1) die('usage: anon-node share <config-path>');
        await cmdShare(args[0]);
        return;

    }
    if (subcommand === 'add-seed') {

        if (args.length !== 2) die('usage: anon-node add-seed <config-path> <hex>');
        await cmdAddSeed(args[0], args[1]);
        return;

    }
    if (subcommand === 'run') {

        if (args.length !== 1) die('usage: anon-node run <config-path>');
        await cmdRun(args[0]);
        return;

    }
    process.stderr.write(USAGE);
    process.exit(1);

};

main().catch((err) => die(err.stack || err.message));
