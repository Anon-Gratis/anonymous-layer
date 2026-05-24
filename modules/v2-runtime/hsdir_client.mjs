// v2-runtime — HSDir client (Phase 1: DA-fronted HTTPS).
//
// Bridge uses this to fetch service descriptors by `.anon` address
// when the local descriptor index doesn't have one.
//
// Lookup-key derivation for Phase 1: the address body itself (the
// 56-char base32 string, minus the `.anon` suffix) IS the key. It's
// already uniquely-identifying per service, deterministic from the
// address with zero crypto, and URL-safe (lowercase base32 charset
// is a subset of Caddy's [A-Za-z0-9_-] guard). The publisher's
// uploader uses the same derivation.
//
// Phase 1 trust model:
//   - DA stores opaque descriptor bytes; never substitutes / forges.
//   - Client verifies the address-to-pubkeys binding
//     (Blake2b(SVC_pk_ed || SVC_pk_mldsa) == address's identityHash)
//     before trusting any returned descriptor.
//   - DA can deny (DoS), can NOT silently substitute.
//
// Phase 1.5 replaces the direct HTTPS GET with a circuit-routed
// RELAY_DESCFETCH/REPLY exchange so the DA can't see which address
// was queried.

import { blake2b } from '@noble/hashes/blake2.js';

import { parseServiceDescriptorAny } from '../v2/descriptor.mjs';
import {
    decodeOnionAddress,
    ONION_ADDR_SUFFIX,
    ONION_VERSION,
    ONION_VERSION_PQ,
} from '../v2/onion_address.mjs';

// Strip the `.anon` suffix from an address and return the 56-char
// base32 body. The publisher's uploader does the same.
export const lookupKeyForAddress = (address) => {

    const a = String(address || '').trim().toLowerCase();
    if (!a.endsWith(ONION_ADDR_SUFFIX)) {

        throw new Error(`address missing ${ONION_ADDR_SUFFIX} suffix: ${address}`);

    }
    const body = a.slice(0, -ONION_ADDR_SUFFIX.length);
    if (!/^[a-z2-7]{16,64}$/.test(body)) {

        throw new Error(`malformed .anon address body: ${body}`);

    }
    return body;

};

const blake2bFingerprint = (pk) => blake2b(pk, { dkLen: 32 });

// Fetch + verify a descriptor for `address` from the HSDir.
//
// Returns the parsed descriptor on success; throws on:
//   - network failure
//   - HTTP non-2xx
//   - parse failure
//   - address-binding mismatch (descriptor's pubkeys don't hash to
//     the queried address)
//
// Caller decides what to do on failure (typically fall back to
// DESCRIPTOR_DIR, or surface the error).
export const fetchDescriptorFromHsdir = async ({ daBaseUrl, address, timeoutMs = 10000 }) => {

    const key = lookupKeyForAddress(address);
    const url = `${daBaseUrl.replace(/\/+$/, '')}/hsdir/${key}`;

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    let resp;
    try {

        resp = await fetch(url, { signal: ctrl.signal, cache: 'no-store' });

    } catch (e) {

        throw new Error(`HSDir GET ${url} failed: ${e.message}`);

    } finally {

        clearTimeout(timer);

    }
    if (!resp.ok) throw new Error(`HSDir GET ${url}: HTTP ${resp.status}`);

    const buf = new Uint8Array(await resp.arrayBuffer());
    if (buf.length === 0 || buf.length > 65536) {

        throw new Error(`HSDir descriptor for ${address}: bad size ${buf.length}`);

    }

    const descriptor = parseServiceDescriptorAny(buf);
    if (!descriptor) {

        throw new Error(`HSDir descriptor for ${address}: parse failed`);

    }

    // Verify the descriptor binds back to the queried address —
    // i.e. that the DA didn't substitute someone else's descriptor.
    // For v3 the identity is hash(SVC_pk_ed || SVC_pk_mldsa); the
    // decoded address already contains that hash, so we recompute
    // and compare.
    const decoded = decodeOnionAddress(address);
    if (decoded.version === ONION_VERSION_PQ) {

        if (!descriptor.SVC_pk_ed || !descriptor.SVC_pk_mldsa) {

            throw new Error(`HSDir descriptor for ${address}: v3 descriptor missing hybrid pubkeys`);

        }
        const recomputed = blake2bFingerprint(
            new Uint8Array([...descriptor.SVC_pk_ed, ...descriptor.SVC_pk_mldsa]),
        );
        const mismatch = recomputed.some((b, i) => b !== decoded.identityHash[i]);
        if (mismatch) {

            throw new Error(`HSDir descriptor for ${address}: pubkey binding mismatch (DA may have substituted)`);

        }

    } else if (decoded.version === ONION_VERSION) {

        if (!descriptor.SVC_pk) {

            throw new Error(`HSDir descriptor for ${address}: v2 descriptor missing SVC_pk`);

        }
        const mismatch = descriptor.SVC_pk.some((b, i) => b !== decoded.svcPk[i]);
        if (mismatch) {

            throw new Error(`HSDir descriptor for ${address}: SVC_pk mismatch`);

        }

    }

    return descriptor;

};

// In-memory cache. Entries expire when the descriptor's own publishEpoch
// + lifetimeSeconds elapses (we don't re-fetch sooner; HSDir refresh on
// the publisher side keeps the descriptor fresh).
//
// createHsdirClient returns:
//   {
//     lookup(address)      — async, returns descriptor or null
//     invalidate(address)  — drop the cache entry
//     size()
//   }
export const createHsdirClient = ({
    daBaseUrl,
    circuitFetcher = null,      // optional: createDescfetchOverCircuit(...) instance
    logger = null,
    nowSeconds = () => Math.floor(Date.now() / 1000),
}) => {

    const log = (m) => { if (typeof logger === 'function') logger(m); };
    const cache = new Map(); // address (lowercase) → { descriptor, expiresAt }
    const inFlight = new Map(); // coalesce concurrent fetches

    const norm = (a) => String(a || '').trim().toLowerCase();

    // Prefer circuit-routed fetch when available; falls back to direct
    // HTTPS if the circuit fetcher fails (privacy degrades to direct
    // HTTPS, but the lookup still succeeds).
    const doFetch = async (address) => {

        if (circuitFetcher) {

            try {

                const { httpStatus, body } = await circuitFetcher({ address });
                if (httpStatus < 200 || httpStatus > 299) {

                    throw new Error(`circuit-routed HSDir GET → HTTP ${httpStatus}`);

                }
                // Parse + verify the same way as direct HTTPS path.
                const { parseServiceDescriptorAny } = await import('../v2/descriptor.mjs');
                const { decodeOnionAddress, ONION_VERSION, ONION_VERSION_PQ } = await import('../v2/onion_address.mjs');
                const descriptor = parseServiceDescriptorAny(new Uint8Array(body));
                if (!descriptor) throw new Error('circuit-routed: descriptor parse failed');
                const decoded = decodeOnionAddress(address);
                if (decoded.version === ONION_VERSION_PQ) {

                    const recomputed = blake2bFingerprint(
                        new Uint8Array([...descriptor.SVC_pk_ed, ...descriptor.SVC_pk_mldsa]),
                    );
                    const mismatch = recomputed.some((b, i) => b !== decoded.identityHash[i]);
                    if (mismatch) throw new Error('circuit-routed: pubkey binding mismatch');

                } else if (decoded.version === ONION_VERSION) {

                    const mismatch = descriptor.SVC_pk.some((b, i) => b !== decoded.svcPk[i]);
                    if (mismatch) throw new Error('circuit-routed: SVC_pk mismatch');

                }
                log(`hsdir: fetched ${address} via circuit (${body.length} bytes)`);
                return descriptor;

            } catch (e) {

                log(`hsdir: circuit-routed lookup failed (${e.message}); falling back to direct HTTPS`);
                // fall through to direct HTTPS

            }

        }

        return fetchDescriptorFromHsdir({ daBaseUrl, address });

    };

    const lookup = async (address) => {

        const key = norm(address);
        const fresh = cache.get(key);
        if (fresh && fresh.expiresAt > nowSeconds()) return fresh.descriptor;
        if (inFlight.has(key)) return inFlight.get(key);

        const fetching = (async () => {

            try {

                const descriptor = await doFetch(address);
                const expiresAt = (descriptor.publishEpoch ?? nowSeconds())
                    + (descriptor.lifetimeSeconds ?? 3600);
                cache.set(key, { descriptor, expiresAt });
                log(`hsdir: cached ${address} (expires in ${expiresAt - nowSeconds()}s)`);
                return descriptor;

            } catch (e) {

                log(`hsdir: lookup ${address} failed: ${e.message}`);
                return null;

            } finally {

                inFlight.delete(key);

            }

        })();
        inFlight.set(key, fetching);
        return fetching;

    };

    return {
        lookup,
        invalidate: (a) => { cache.delete(norm(a)); },
        size: () => cache.size,
    };

};
