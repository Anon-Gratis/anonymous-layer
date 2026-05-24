// v2-runtime — descriptor index.
//
// Loads service descriptors from disk and exposes lookup by onion
// address. The bridge uses this to route a per-URL `.anon` host to
// the right descriptor: each `/api/fetch` request extracts the host,
// looks it up here, and rendezvouses with that specific service.
//
// Supports both v2 (legacy Ed25519-only) and v3 (PQ hybrid) descriptors.
// The onion address is recomputed from the descriptor's pubkeys at
// load time, so a misnamed file (or a descriptor that doesn't actually
// hash to the address claimed in its filename) is indexed by its
// real address; the operator can't accidentally route to the wrong
// service by misnaming a file.
//
// This is a stopgap before proper HSDir lookups. In production the
// client would fetch descriptors on demand from the HSDir; for the
// PRE-AUDIT testnet, we ship a directory of descriptors and route
// against that.

import { readFile, readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';

import { parseServiceDescriptorAny } from '../v2/descriptor.mjs';
import { encodeOnionAddress, encodeOnionAddressV3, ONION_ADDR_SUFFIX } from '../v2/onion_address.mjs';

const DESCRIPTOR_VERSION    = 0x02;
const DESCRIPTOR_VERSION_PQ = 0x03;

// Derive the onion address (without scheme) from a parsed descriptor.
// Returns null for an unknown/unsupported version.
const addressForDescriptor = (descriptor) => {

    if (!descriptor || typeof descriptor.version !== 'number') return null;
    if (descriptor.version === DESCRIPTOR_VERSION) {

        if (!descriptor.SVC_pk) return null;
        return encodeOnionAddress(descriptor.SVC_pk);

    }
    if (descriptor.version === DESCRIPTOR_VERSION_PQ) {

        if (!descriptor.SVC_pk_ed || !descriptor.SVC_pk_mldsa) return null;
        return encodeOnionAddressV3(descriptor.SVC_pk_ed, descriptor.SVC_pk_mldsa);

    }
    return null;

};

// Normalise a hostname for index lookup. Onion addresses are
// case-insensitive base32; we compare in lowercase, with any
// surrounding scheme/path/query stripped by the caller.
const normaliseHost = (host) => String(host || '').trim().toLowerCase();

// Try to read & parse a single descriptor file. Returns
// `{ ok: true, descriptor, address }` or `{ ok: false, reason }`.
const tryLoadDescriptor = async (path) => {

    let bytes;
    try { bytes = await readFile(path); }
    catch (err) { return { ok: false, reason: `read failed: ${err.message}` }; }

    const descriptor = parseServiceDescriptorAny(new Uint8Array(bytes));
    if (!descriptor) return { ok: false, reason: 'parse failed (bad format / wrong version byte)' };

    const address = addressForDescriptor(descriptor);
    if (!address) return { ok: false, reason: `cannot derive onion address from v${descriptor.version} descriptor` };

    return { ok: true, descriptor, address };

};

// Build a descriptor index from an explicit list of file paths plus
// (optionally) a directory of `*.descriptor.bin` / `*.bin` files.
//
//   createDescriptorIndex({ paths: [...], dir: '/path/to/dir', logger })
//
// `logger` is called with single-line strings; omit to silence.
//
// Returns:
//   {
//     size,                  // number of descriptors successfully loaded
//     addresses(),           // array of "<base32>.anon" strings
//     lookup(host),          // → descriptor | null. `host` may be the
//                            //   bare onion (with or without `.anon`),
//                            //   case-insensitive.
//     descriptors(),         // array of parsed descriptor objects
//   }
//
// Throws if zero descriptors load — an empty index is never useful
// and silently starting that way would mask a deployment mistake.
export const createDescriptorIndex = async ({ paths = [], dir = null, logger = null } = {}) => {

    const log = (msg) => { if (typeof logger === 'function') logger(msg); };
    const byAddress = new Map();
    const addOne = (path, descriptor, address) => {

        const norm = normaliseHost(address);
        if (byAddress.has(norm)) {

            log(`descriptor index: duplicate address ${address} (already loaded; ignoring ${path})`);
            return;

        }
        byAddress.set(norm, descriptor);
        log(`descriptor index: + ${address}  (v${descriptor.version}, from ${path})`);

    };

    const allPaths = [...paths];
    if (dir) {

        let entries;
        try {

            entries = await readdir(dir);

        } catch (err) {

            throw new Error(`descriptor dir not readable: ${dir}: ${err.message}`);

        }
        for (const name of entries) {

            if (!name.endsWith('.bin')) continue;
            const full = join(dir, name);
            try {

                const s = await stat(full);
                if (!s.isFile()) continue;

            } catch { continue; }
            allPaths.push(full);

        }

    }

    for (const path of allPaths) {

        const loaded = await tryLoadDescriptor(path);
        if (!loaded.ok) {

            log(`descriptor index: skipping ${path}: ${loaded.reason}`);
            continue;

        }
        addOne(path, loaded.descriptor, loaded.address);

    }

    if (byAddress.size === 0) {

        throw new Error(
            'descriptor index is empty — no descriptors loaded. '
            + (dir ? `Check that ${dir} contains valid *.bin descriptors. ` : '')
            + 'Refusing to start; the bridge has nothing to route to.',
        );

    }

    const stripSuffix = (host) => {

        const h = normaliseHost(host);
        return h.endsWith(ONION_ADDR_SUFFIX) ? h.slice(0, -ONION_ADDR_SUFFIX.length) : h;

    };

    return {
        size: byAddress.size,
        addresses: () => Array.from(byAddress.keys()),
        descriptors: () => Array.from(byAddress.values()),
        lookup: (host) => {

            // Try the full host first, then with the `.anon` suffix
            // stripped (in case caller already passed just the body).
            const full = normaliseHost(host);
            if (byAddress.has(full)) return byAddress.get(full);
            const body = stripSuffix(full);
            const reAdded = body + ONION_ADDR_SUFFIX;
            if (byAddress.has(reAdded)) return byAddress.get(reAdded);
            return null;

        },
    };

};
