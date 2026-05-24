#!/usr/bin/env node
// anon-mkconsensus — directory-authority side CLI for v0.2 testnets.
//
// Subcommands:
//   init          Generate a fresh DA Ed25519 keypair. Writes a
//                 32-byte secret (mode 0600) and a JSON da-trust
//                 file ready for relay/client distribution.
//   relay-info    Print this DA's fingerprint + idPk.
//   build         Sign a consensus from a JSON relay-descriptor file.

import { resolve, join } from 'node:path';
import { homedir } from 'node:os';
import { readFile, writeFile, rename, chmod, mkdir, stat } from 'node:fs/promises';

import { ed25519 } from '@noble/curves/ed25519.js';

import { fingerprint as blake2bFingerprint } from '../modules/crypto/fingerprint.mjs';
import {
    FLAG_EXIT,
    FLAG_GUARD,
    FLAG_RUNNING,
    FLAG_STABLE,
    FLAG_FAST,
    FLAG_HSDIR,
    FLAG_VALID,
    FLAG_AUTHORITY,
    FLAG_BAD_EXIT,
    buildConsensus,
} from '../modules/v2/consensus.mjs';
import {
    POLICY_REJECT_ALL,
    POLICY_REDUCED_EXIT,
    POLICY_STANDARD_EXIT,
    buildPolicy,
} from '../modules/v2/exit_policy.mjs';

const USAGE = `\
anon-mkconsensus — DA-side consensus generation for v0.2 testnets

Subcommands:
  anon-mkconsensus init       [--data-dir DIR]
  anon-mkconsensus relay-info [--data-dir DIR]
  anon-mkconsensus build      [--data-dir DIR] [--lifetime-seconds N]
                              --relays RELAYS.json
                              --output-consensus consensus.bin
                              --output-trust    da-trust.json

Options:
  --data-dir DIR        DA's persistent-state directory.
                        Default: \$ANON_MKCONSENSUS_HOME or ~/.anon-mkconsensus

RELAYS.json schema (used by "build"):
  [
    {
      "fingerprint": "<64 hex chars>",
      "idPk":        "<64 hex chars>",
      "B_pk":        "<64 hex chars>",
      "host":        "127.0.0.1",
      "port":        9001,
      "flags":       ["GUARD", "EXIT"],       // RUNNING + VALID always added
      "exit_policy": "reject" | "reduced" | "standard" | "file:PATH"
    },
    ...
  ]

The DA-trust file output is plain JSON, ready for use as the
--da-trust input to anon-node-v2 / anon-service / anon-browse:
  { "<da-fingerprint-hex>": "<da-idPk-hex>" }
`;

const die = (msg, code = 1) => {

    process.stderr.write(`error: ${msg}\n`);
    process.exit(code);

};

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const fromHex = (h) => Uint8Array.from(Buffer.from(h, 'hex'));
const defaultDataDir = () => process.env.ANON_MKCONSENSUS_HOME || join(homedir(), '.anon-mkconsensus');

const parseArgs = () => {

    const args = process.argv.slice(2);
    if (args.length === 0) return null;
    const opts = {
        subcommand: args[0],
        dataDir: defaultDataDir(),
        lifetimeSeconds: 3600,
        relaysPath: null,
        outConsensus: null,
        outTrust: null,
    };
    for (let i = 1; i < args.length; i += 1) {

        const a = args[i];
        if (a === '--data-dir')          { opts.dataDir = args[i + 1]; i += 1; continue; }
        if (a === '--lifetime-seconds')  { opts.lifetimeSeconds = parseInt(args[i + 1], 10); i += 1; continue; }
        if (a === '--relays')            { opts.relaysPath = args[i + 1]; i += 1; continue; }
        if (a === '--output-consensus')  { opts.outConsensus = args[i + 1]; i += 1; continue; }
        if (a === '--output-trust')      { opts.outTrust = args[i + 1]; i += 1; continue; }
        if (a === '--help' || a === '-h') return null;
        if (a.startsWith('--')) die(`unknown option: ${a}`);
        die(`unexpected argument: ${a}`);

    }
    return opts;

};

// ----- DA identity persistence -----

const exists = async (path) => {

    try { await stat(path); return true; }
    catch (err) { if (err.code === 'ENOENT') return false; throw err; }

};

const saveDaSecret = async (path, idSk) => {

    if (idSk.length !== 32) throw new Error('idSk must be 32 bytes');
    await mkdir(resolve(path, '..'), { recursive: true });
    const tmp = `${path}.tmp`;
    await writeFile(tmp, idSk, { mode: 0o600 });
    await chmod(tmp, 0o600);
    await rename(tmp, path);

};

const loadDaSecret = async (path) => {

    const st = await stat(path);
    if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) {

        throw new Error(`DA identity ${path} has overly permissive mode `
            + `${(st.mode & 0o777).toString(8)}; must be 0600`);

    }
    const buf = await readFile(path);
    if (buf.length !== 32) {

        throw new Error(`DA identity ${path} is ${buf.length} bytes; expected 32`);

    }
    return new Uint8Array(buf);

};

const loadOrCreateDa = async (dataDir) => {

    const idPath = join(dataDir, 'da-identity.bin');
    if (await exists(idPath)) {

        const idSk = await loadDaSecret(idPath);
        const idPk = ed25519.getPublicKey(idSk);
        const fp = blake2bFingerprint(idPk);
        return { idSk, idPk, fingerprint: fp, path: idPath, created: false };

    }
    const idSk = ed25519.utils.randomSecretKey();
    await saveDaSecret(idPath, idSk);
    const idPk = ed25519.getPublicKey(idSk);
    const fp = blake2bFingerprint(idPk);
    return { idSk, idPk, fingerprint: fp, path: idPath, created: true };

};

const writeTrustFile = async (path, da) => {

    const obj = { [hex(da.fingerprint)]: hex(da.idPk) };
    await writeFile(path, `${JSON.stringify(obj, null, 2)}\n`);

};

// ----- Relay JSON → RSE -----

const FLAG_BY_NAME = {
    EXIT: FLAG_EXIT, GUARD: FLAG_GUARD, RUNNING: FLAG_RUNNING,
    STABLE: FLAG_STABLE, FAST: FLAG_FAST, HSDIR: FLAG_HSDIR,
    VALID: FLAG_VALID, AUTHORITY: FLAG_AUTHORITY, BAD_EXIT: FLAG_BAD_EXIT,
};

const flagsFromNames = (names) => {

    let bits = FLAG_RUNNING | FLAG_VALID; // always added
    if (!Array.isArray(names)) return bits;
    for (const n of names) {

        const bit = FLAG_BY_NAME[n.toUpperCase()];
        if (bit === undefined) die(`unknown flag name: ${n}`);
        bits |= bit;

    }
    return bits;

};

const resolveExitPolicyBytes = async (spec) => {

    if (!spec || spec === 'reject')   return buildPolicy(POLICY_REJECT_ALL);
    if (spec === 'reduced')  return buildPolicy(POLICY_REDUCED_EXIT);
    if (spec === 'standard') return buildPolicy(POLICY_STANDARD_EXIT);
    if (spec.startsWith('file:')) {

        const buf = await readFile(spec.slice('file:'.length));
        return new Uint8Array(buf);

    }
    die(`unknown exit_policy: ${spec}`);
    return null;

};

const parseHostPort = (host, port) => {

    // IPv4 only for v0.2 reference.
    const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) die(`only IPv4 hosts supported in v0.2 reference: got "${host}"`);
    const bytes = new Uint8Array(6);
    for (let i = 0; i < 4; i += 1) {

        const n = parseInt(m[i + 1], 10);
        if (n < 0 || n > 255) die(`bad IPv4 octet in ${host}`);
        bytes[i] = n;

    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {

        die(`bad port: ${port}`);

    }
    bytes[4] = (port >> 8) & 0xFF;
    bytes[5] = port & 0xFF;
    return bytes;

};

const buildRseFromJson = async (r) => {

    if (typeof r.fingerprint !== 'string' || !/^[0-9a-fA-F]{64}$/.test(r.fingerprint)) {

        die('relay.fingerprint must be 64 hex chars');

    }
    if (typeof r.idPk !== 'string' || !/^[0-9a-fA-F]{64}$/.test(r.idPk)) {

        die('relay.idPk must be 64 hex chars');

    }
    if (typeof r.B_pk !== 'string' || !/^[0-9a-fA-F]{64}$/.test(r.B_pk)) {

        die('relay.B_pk must be 64 hex chars');

    }
    return {
        fingerprint: fromHex(r.fingerprint),
        idPk:        fromHex(r.idPk),
        onionPk:     fromHex(r.B_pk),
        ipv4:        parseHostPort(r.host, r.port),
        ipv6:        null,
        flags:       flagsFromNames(r.flags || []),
        exitPolicyBytes: await resolveExitPolicyBytes(r.exit_policy),
    };

};

// ----- Subcommands -----

const cmdInit = async (opts) => {

    const dir = resolve(opts.dataDir);
    const da = await loadOrCreateDa(dir);
    const trustPath = join(dir, 'da-trust.json');
    await writeTrustFile(trustPath, da);
    process.stdout.write(`${da.created ? 'generated' : 'loaded'} DA identity → ${da.path}\n`);
    process.stdout.write(`wrote DA-trust file              → ${trustPath}\n`);
    process.stdout.write(`fingerprint: ${hex(da.fingerprint)}\n`);
    process.stdout.write(`idPk:        ${hex(da.idPk)}\n`);

};

const cmdRelayInfo = async (opts) => {

    const dir = resolve(opts.dataDir);
    const idPath = join(dir, 'da-identity.bin');
    if (!await exists(idPath)) {

        die(`no DA identity at ${idPath}; run "anon-mkconsensus init" first`);

    }
    const idSk = await loadDaSecret(idPath);
    const idPk = ed25519.getPublicKey(idSk);
    const fp = blake2bFingerprint(idPk);
    process.stdout.write(`data-dir:    ${dir}\n`);
    process.stdout.write(`fingerprint: ${hex(fp)}\n`);
    process.stdout.write(`idPk:        ${hex(idPk)}\n`);

};

const cmdBuild = async (opts) => {

    if (!opts.relaysPath)   die('--relays PATH is required');
    if (!opts.outConsensus) die('--output-consensus PATH is required');
    if (!opts.outTrust)     die('--output-trust PATH is required');
    if (!Number.isInteger(opts.lifetimeSeconds) || opts.lifetimeSeconds < 60) {

        die(`--lifetime-seconds must be ≥ 60; got ${opts.lifetimeSeconds}`);

    }

    const dir = resolve(opts.dataDir);
    const da = await loadOrCreateDa(dir);

    let relaysJson;
    try { relaysJson = JSON.parse(await readFile(opts.relaysPath, 'utf-8')); }
    catch (err) { die(`could not parse ${opts.relaysPath}: ${err.message}`); }
    if (!Array.isArray(relaysJson)) die(`${opts.relaysPath} must be a JSON array`);
    if (relaysJson.length === 0)    die(`${opts.relaysPath} contains no relays`);

    const rses = [];
    for (const r of relaysJson) rses.push(await buildRseFromJson(r));

    const now = Math.floor(Date.now() / 1000);
    const consensusBytes = buildConsensus({
        validAfter: now - 60,
        freshUntil: now + Math.floor(opts.lifetimeSeconds / 2),
        validUntil: now + opts.lifetimeSeconds,
        rses,
        daSigners: [da],
    });

    await writeFile(opts.outConsensus, consensusBytes);
    await writeTrustFile(opts.outTrust, da);

    process.stdout.write(`signed ${rses.length} relays into consensus (${consensusBytes.length} bytes)\n`);
    process.stdout.write(`  → ${opts.outConsensus}\n`);
    process.stdout.write(`  → ${opts.outTrust}\n`);
    process.stdout.write(`valid for ${opts.lifetimeSeconds} seconds (signed by DA ${hex(da.fingerprint).slice(0, 16)}…)\n`);

};

const main = async () => {

    const opts = parseArgs();
    if (opts === null) { process.stdout.write(USAGE); process.exit(0); }

    switch (opts.subcommand) {

        case 'init':       await cmdInit(opts); break;
        case 'relay-info': await cmdRelayInfo(opts); break;
        case 'build':      await cmdBuild(opts); break;
        default: die(`unknown subcommand: ${opts.subcommand}`);

    }

};

main().catch((err) => die(err.stack || err.message));
