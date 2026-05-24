#!/usr/bin/env node
import { createInterface } from 'node:readline';
import { randomBytes } from 'node:crypto';

import { loadConfig, readSeedList } from '../modules/node/config.mjs';
import { loadIdentity } from '../modules/node/persistence.mjs';
import { currentCertificate } from '../modules/node/identity.mjs';
import { createIdentityCache } from '../modules/node/identity_cache.mjs';
import { createPeerTable } from '../modules/peer/table.mjs';
import { createNode } from '../modules/node/node.mjs';
import { createWebSocketListener } from '../modules/node/transport_websocket.mjs';
import { createDialer } from '../modules/node/dialer.mjs';
import { createLogger } from '../modules/node/logger.mjs';
import { TRANSPORT_WEBSOCKET_IPV4 } from '../modules/wire/transport.mjs';

const USAGE = `\
anon-chat — interactive chat over Anonymous Layer

Usage:
  anon-chat <config-path> <peer-fingerprint-hex>

The peer fingerprint (64 hex chars) must already be in the config's
seed list (use anon-node share / add-seed to populate it first). Both
sides must run anon-chat simultaneously. Type lines and press Enter
to send; Ctrl-D / Ctrl-C to exit.

This replaces \`anon-node run\` for the duration of the session — they
listen on the same port and cannot run together against one config.
`;

const hex = (b) => Buffer.from(b).toString('hex');

const die = (msg, code = 1) => {

    process.stderr.write(`error: ${msg}\n`);
    process.exit(code);

};

const parseFingerprint = (s) => {

    if (!/^[0-9a-f]{64}$/i.test(s)) return null;
    return Uint8Array.from(Buffer.from(s, 'hex'));

};

// SPEC § 6.4.1: WEBSOCKET_IPV4 transport = 4-byte IP + 2-byte BE port.
const pickDialAddress = (transports) => {

    for (const t of transports) {

        if (t.type !== TRANSPORT_WEBSOCKET_IPV4) continue;
        if (t.address.length !== 6) continue;
        return {
            host: `${t.address[0]}.${t.address[1]}.${t.address[2]}.${t.address[3]}`,
            port: (t.address[4] << 8) | t.address[5],
        };

    }
    return null;

};

const main = async () => {

    const [, , configPath, peerFpHex] = process.argv;
    if (!configPath || !peerFpHex) { process.stdout.write(USAGE); process.exit(1); }

    const peerFp = parseFingerprint(peerFpHex);
    if (!peerFp) die('peer fingerprint must be 64 hex characters');

    const cfg = await loadConfig(configPath);
    const identity = await loadIdentity(cfg.identity.path);
    const now = () => Math.floor(Date.now() / 1000);
    const certBytes = currentCertificate({
        identity,
        expirySeconds: now() + (30 * 24 * 3600),
    });

    const peerTable = createPeerTable({ now });
    const identityCache = createIdentityCache();

    // Per-session conversation identity. The recipient can use these
    // to demultiplex concurrent chats from the same sender. v0.1's
    // DATA packet (SPEC § 6.3) defines both as opaque to the network.
    const conversationTag = new Uint8Array(randomBytes(16));
    let sequenceNumber = 0n;

    // readline reference is set up after the node so message callbacks
    // can refresh the prompt safely.
    let rl = null;

    // Print above the readline prompt. The carriage-return + clear-line
    // sequence wipes whatever the user has typed so far; rl.prompt(true)
    // redraws it underneath the printed message.
    const printAbovePrompt = (text) => {

        process.stdout.write(`\r\x1b[2K${text}\n`);
        if (rl) rl.prompt(true);

    };

    let peerConnected = false;
    const ourFpShort = hex(identity.fingerprint).slice(0, 16);
    const peerFpShort = hex(peerFp).slice(0, 16);

    const logger = createLogger({ level: 'error' });

    const node = createNode({
        identity,
        peerTable,
        identityCache,
        currentCertBytes: certBytes,
        nowSeconds: now,
        onData: ({ senderFingerprint, payload }) => {

            // Only display messages from the configured chat peer.
            // DATA from anyone else is silently dropped at the UX
            // layer (still accepted at the protocol layer — the spec
            // makes no distinction).
            if (!Buffer.from(senderFingerprint).equals(Buffer.from(peerFp))) return;
            const text = Buffer.from(payload).toString('utf8');
            printAbovePrompt(`<${peerFpShort}> ${text}`);

        },
        onPeerConnected: (fp) => {

            if (!Buffer.from(fp).equals(Buffer.from(peerFp))) return;
            peerConnected = true;
            printAbovePrompt(`* connected to ${peerFpShort}`);

        },
        onPeerDisconnected: (fp) => {

            if (!Buffer.from(fp).equals(Buffer.from(peerFp))) return;
            peerConnected = false;
            printAbovePrompt(`* disconnected from ${peerFpShort}`);

        },
    });

    // Load + verify the seed list. Refuse to start if the chat peer
    // isn't in it — the chat client doesn't accept ad-hoc trust.
    let seeds = [];
    try {

        seeds = await readSeedList(cfg.seedList.path) || [];

    } catch (err) {

        if (err.code !== 'ENOENT') throw err;

    }

    let peerInList = false;
    for (const seed of seeds) {

        const ok = peerTable.addOrUpdate({
            idPk: seed.idPk,
            certBytes: seed.certBytes,
            transports: seed.transports,
            nowSeconds: now(),
        });
        if (!ok) continue;
        identityCache.set(seed.idPk);
        const record = peerTable.list().find(
            (p) => Buffer.from(p.idPk).equals(Buffer.from(seed.idPk)),
        );
        if (record && Buffer.from(record.fingerprint).equals(Buffer.from(peerFp))) {

            peerInList = true;

        }

    }
    if (!peerInList) {

        die(`peer ${peerFpShort} is not in seed list at ${cfg.seedList.path}.\n`
            + 'Use \`anon-node add-seed\` to add their seed record first.');

    }

    // Listener.
    const listener = createWebSocketListener(cfg.listen, (transport) => {

        node.acceptInbound(transport);

    });
    await listener.ready;

    // Dial every seed we know — the chat peer is one of them; the
    // others (if any) join the peer table and serve future gossip.
    const dialer = createDialer({ node, logger });
    for (const p of peerTable.list()) {

        const addr = pickDialAddress(p.transports);
        if (addr === null) continue;
        dialer.connect({ fingerprint: p.fingerprint, host: addr.host, port: addr.port });

    }

    const tickHandle = setInterval(() => {

        try { node.tick(); } catch (err) { logger.error('tick threw', { err: err.message }); }

    }, cfg.tickIntervalMs);

    // Banner.
    process.stdout.write(`anon-chat\n`);
    process.stdout.write(`  you : ${ourFpShort}\n`);
    process.stdout.write(`  peer: ${peerFpShort}\n`);
    process.stdout.write(`  tag : ${hex(conversationTag).slice(0, 16)}\n`);
    process.stdout.write(`  type to send. ctrl-d / ctrl-c to exit.\n`);
    process.stdout.write('\n');

    // Set up readline AFTER the banner so initial draw is clean.
    rl = createInterface({
        input: process.stdin,
        output: process.stdout,
        prompt: '> ',
    });
    rl.prompt();

    rl.on('line', (line) => {

        if (line.length === 0) { rl.prompt(); return; }
        if (!peerConnected) {

            printAbovePrompt('* not connected yet — message dropped');
            return;

        }
        const payload = new Uint8Array(Buffer.from(line, 'utf8'));
        const ok = node.send({
            recipientFp: peerFp,
            conversationTag,
            sequenceNumber,
            payload,
        });
        if (!ok) {

            printAbovePrompt('* send failed (peer unreachable)');

        } else {

            sequenceNumber += 1n;

        }
        rl.prompt();

    });

    let shuttingDown = false;
    const shutdown = async () => {

        if (shuttingDown) return;
        shuttingDown = true;
        process.stdout.write('\n* exiting\n');
        clearInterval(tickHandle);
        dialer.stop();
        await listener.close();
        process.exit(0);

    };
    rl.on('close', shutdown);
    process.on('SIGTERM', () => rl.close());
    process.on('SIGINT', () => rl.close());

};

main().catch((err) => die(err.stack || err.message));
