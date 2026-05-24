import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { parseSeedList, buildSeedRecord } from '../peer/seed.mjs';

// Operator-facing configuration loader.
//
// File format: JSON. Schema:
//   {
//     "identity":      { "path": "string" },        required
//     "listen":        { "host": "string", "port": int },  port required
//     "seedList":      { "path": "string" },        required
//     "tickIntervalMs": int                          optional (default 5000)
//     "logLevel":      "debug"|"info"|"warn"|"error"  optional (default "info")
//   }
//
// Seed-list file format: the raw bytes of `concat(buildSeedRecord(r))`
// for each record `r`. No header, no wrapper. Implementation-defined
// per SPEC § 7.1; we just pick "raw bytes" as the canonical
// representation for this implementation. Operators distributing seed
// lists publicly are expected to wrap them in PEM-style armor or
// publish hex strings out of band, then convert to raw bytes for
// loading.

const DEFAULTS = {
    listen: { host: '127.0.0.1' },
    tickIntervalMs: 5000,
    logLevel: 'info',
};

const LOG_LEVELS = new Set(['debug', 'info', 'warn', 'error']);

const requirePath = (obj, key) => {

    if (!obj || typeof obj.path !== 'string' || obj.path.length === 0) {

        throw new Error(`config.${key}.path is required`);

    }

};

export const loadConfig = async (path) => {

    const text = await readFile(path, 'utf8');
    let parsed;
    try {

        parsed = JSON.parse(text);

    } catch (err) {

        throw new Error(`config ${path} is not valid JSON: ${err.message}`);

    }
    return applyDefaults(parsed);

};

export const applyDefaults = (cfg) => {

    requirePath(cfg.identity, 'identity');
    requirePath(cfg.seedList, 'seedList');

    if (!cfg.listen || typeof cfg.listen.port !== 'number') {

        throw new Error('config.listen.port is required (integer)');

    }
    const port = cfg.listen.port | 0;
    if (port < 0 || port > 65535) {

        throw new Error(`config.listen.port out of range: ${port}`);

    }

    const tickIntervalMs = cfg.tickIntervalMs !== undefined
        ? (cfg.tickIntervalMs | 0)
        : DEFAULTS.tickIntervalMs;
    if (tickIntervalMs < 50) {

        throw new Error('config.tickIntervalMs must be ≥ 50');

    }

    const logLevel = cfg.logLevel || DEFAULTS.logLevel;
    if (!LOG_LEVELS.has(logLevel)) {

        throw new Error(`config.logLevel invalid: ${logLevel}`);

    }

    return {
        identity: { path: cfg.identity.path },
        listen: {
            host: cfg.listen.host || DEFAULTS.listen.host,
            port,
        },
        seedList: { path: cfg.seedList.path },
        tickIntervalMs,
        logLevel,
    };

};

export const writeConfig = async (path, cfg) => {

    const validated = applyDefaults(cfg);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${JSON.stringify(validated, null, 2)}\n`);

};

// Seed-list helpers — operate on raw on-disk format (concatenated
// canonical seed records per SPEC § 7.1).
export const writeSeedList = async (path, records) => {

    const buf = Buffer.concat(records.map((r) => Buffer.from(buildSeedRecord(r))));
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, buf);

};

// Returns the parsed records array, or null if the file is structurally
// malformed (mirrors parseSeedList's null-on-corrupt semantics).
export const readSeedList = async (path) => {

    const buf = await readFile(path);
    return parseSeedList(new Uint8Array(buf));

};
