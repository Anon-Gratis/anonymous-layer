// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

// Directory consensus client for SPEC-v0.2-draft § 10.
//
// The consensus document is the canonical list of relays the network
// agrees on, signed by a quorum of directory authorities (DAs). This
// module:
//
//   - Parses the consensus byte format (§ 10.3a)
//   - Verifies the DA-signature quorum against an operator-configured
//     DA trust set
//   - Parses RSEs (§ 10.3) including embedded exit policies (§ 8.1)
//   - Provides path-selection helpers used by the circuit-building
//     runtime: selectGuard / selectMiddle / selectExit / pickPath
//
// What this module DOES NOT do:
//   - Fetch consensus bytes — that's the runtime's job (raw HTTP from
//     a DA mirror, or distributed via gossip in a future revision)
//   - Cache or expire consensus on disk
//   - Vote / produce consensus — DA-side work (separate document)
//   - HSDir lookup (deferred to chunk 7.7)

import { sign, verify } from '../crypto/identity.mjs';
import { parsePolicy, evaluate, ADDR_TYPE_IPV4, ADDR_TYPE_IPV6 } from './exit_policy.mjs';

// ----- Flag bits (SPEC § 10.3) -----

export const FLAG_EXIT      = 0x0001;
export const FLAG_GUARD     = 0x0002;
export const FLAG_RUNNING   = 0x0004;
export const FLAG_STABLE    = 0x0008;
export const FLAG_FAST      = 0x0010;
export const FLAG_HSDIR     = 0x0020;
export const FLAG_VALID     = 0x0040;
export const FLAG_AUTHORITY = 0x0080;
export const FLAG_BAD_EXIT  = 0x0100;

// ----- Constants -----

export const CONSENSUS_VERSION = 0x02;

const LEN_VERSION = 1;
const LEN_TIMESTAMP = 8;
const LEN_DA_SIG_COUNT = 1;
const LEN_DA_SIG_ENTRY = 96; // 32 fp + 64 sig
const LEN_RSE_COUNT = 4;

const LEN_FINGERPRINT = 32;
const LEN_ID_PK = 32;
const LEN_ONION_PK = 32;
const LEN_IPV4_ADDR = 6; // 4 IP + 2 port
const LEN_IPV6_ADDR = 18; // 16 IP + 2 port
const LEN_FLAGS = 2;
const LEN_POLICY_LEN = 2;

const LEN_RSE_FIXED_PREFIX = LEN_FINGERPRINT + LEN_ID_PK + LEN_ONION_PK
    + LEN_IPV4_ADDR + LEN_IPV6_ADDR + LEN_FLAGS + LEN_POLICY_LEN; // 124

const LEN_HEADER_BEFORE_DA = LEN_VERSION + LEN_TIMESTAMP * 3 + LEN_DA_SIG_COUNT;

// ----- Helpers -----

const writeBigUint64BE = (buf, off, value) => {

    new DataView(buf.buffer, buf.byteOffset, buf.byteLength).setBigUint64(off, BigInt(value), false);

};

const readBigUint64BE = (buf, off) => {

    return Number(new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getBigUint64(off, false));

};

const isZeroAddr = (buf) => {

    for (let i = 0; i < buf.length; i += 1) if (buf[i] !== 0) return false;
    return true;

};

// ----- RSE codec -----

const buildRse = (rse) => {

    const policyLen = rse.exitPolicyBytes ? rse.exitPolicyBytes.length : 0;
    const total = LEN_RSE_FIXED_PREFIX + policyLen;
    const buf = new Uint8Array(total);
    const view = new DataView(buf.buffer);
    let off = 0;
    buf.set(rse.fingerprint, off); off += LEN_FINGERPRINT;
    buf.set(rse.idPk, off);        off += LEN_ID_PK;
    buf.set(rse.onionPk, off);     off += LEN_ONION_PK;
    if (rse.ipv4) buf.set(rse.ipv4, off);
    off += LEN_IPV4_ADDR;
    if (rse.ipv6) buf.set(rse.ipv6, off);
    off += LEN_IPV6_ADDR;
    view.setUint16(off, rse.flags, false); off += LEN_FLAGS;
    view.setUint16(off, policyLen, false); off += LEN_POLICY_LEN;
    if (policyLen > 0) buf.set(rse.exitPolicyBytes, off);
    return buf;

};

// Parse one RSE starting at `off`. Returns { rse, consumed } | null.
const parseRse = (buf, off) => {

    if (buf.length < off + LEN_RSE_FIXED_PREFIX) return null;
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    let p = off;
    const fingerprint = new Uint8Array(buf.subarray(p, p + LEN_FINGERPRINT)); p += LEN_FINGERPRINT;
    const idPk = new Uint8Array(buf.subarray(p, p + LEN_ID_PK)); p += LEN_ID_PK;
    const onionPk = new Uint8Array(buf.subarray(p, p + LEN_ONION_PK)); p += LEN_ONION_PK;
    const ipv4Raw = new Uint8Array(buf.subarray(p, p + LEN_IPV4_ADDR)); p += LEN_IPV4_ADDR;
    const ipv6Raw = new Uint8Array(buf.subarray(p, p + LEN_IPV6_ADDR)); p += LEN_IPV6_ADDR;
    const flags = view.getUint16(p, false); p += LEN_FLAGS;
    const policyLen = view.getUint16(p, false); p += LEN_POLICY_LEN;
    if (buf.length < p + policyLen) return null;
    const exitPolicyBytes = policyLen > 0
        ? new Uint8Array(buf.subarray(p, p + policyLen))
        : new Uint8Array(0);
    p += policyLen;

    const exitPolicy = policyLen > 0 ? parsePolicy(exitPolicyBytes) : [];
    if (exitPolicy === null) return null;

    return {
        rse: {
            fingerprint,
            idPk,
            onionPk,
            ipv4: isZeroAddr(ipv4Raw) ? null : ipv4Raw,
            ipv6: isZeroAddr(ipv6Raw) ? null : ipv6Raw,
            flags,
            exitPolicy,
            exitPolicyBytes,
        },
        consumed: p - off,
    };

};

// ----- Consensus codec -----

// Build the consensus's "signed-bytes view" — the concatenation of
// version || valid_after || fresh_until || valid_until || da_sig_count
// || rse_count || rses. Excludes the da_signatures block.
const buildSignedBytes = ({ version, validAfter, freshUntil, validUntil, daSignerCount, rsesBytes }) => {

    const len = LEN_VERSION + LEN_TIMESTAMP * 3 + LEN_DA_SIG_COUNT + LEN_RSE_COUNT + rsesBytes.length;
    const out = new Uint8Array(len);
    const view = new DataView(out.buffer);
    let off = 0;
    out[off] = version; off += LEN_VERSION;
    writeBigUint64BE(out, off, validAfter); off += LEN_TIMESTAMP;
    writeBigUint64BE(out, off, freshUntil); off += LEN_TIMESTAMP;
    writeBigUint64BE(out, off, validUntil); off += LEN_TIMESTAMP;
    out[off] = daSignerCount; off += LEN_DA_SIG_COUNT;
    view.setUint32(off, (rsesBytes._rseCount !== undefined ? rsesBytes._rseCount : 0), false); off += LEN_RSE_COUNT;
    out.set(rsesBytes, off);
    return out;

};

// SPEC § 10.3a: build a consensus document. Used in tests and by
// directory authorities (whose voting protocol is out of scope here).
//
// Inputs:
//   validAfter, freshUntil, validUntil   Unix seconds
//   rses                                  array of RSE objects
//   daSigners                             array of { idPk, idSk, fingerprint }
//                                         to produce DA signatures
export const buildConsensus = ({ validAfter, freshUntil, validUntil, rses, daSigners }) => {

    // First, serialise the RSE block.
    const rseParts = rses.map((r) => buildRse(r));
    let rseTotal = 0;
    for (const r of rseParts) rseTotal += r.length;
    const rsesBytes = new Uint8Array(rseTotal);
    {

        let off = 0;
        for (const r of rseParts) { rsesBytes.set(r, off); off += r.length; }

    }
    // Stash the count on the buffer so buildSignedBytes can write the
    // count field correctly. (A bit clunky — works for the test/dev
    // path we use.)
    rsesBytes._rseCount = rses.length;

    const signed = buildSignedBytes({
        version: CONSENSUS_VERSION,
        validAfter, freshUntil, validUntil,
        daSignerCount: daSigners.length,
        rsesBytes,
    });

    // Sign with each DA.
    const sigBlock = new Uint8Array(daSigners.length * LEN_DA_SIG_ENTRY);
    for (let i = 0; i < daSigners.length; i += 1) {

        const da = daSigners[i];
        sigBlock.set(da.fingerprint, i * LEN_DA_SIG_ENTRY);
        const signature = sign(signed, da.idSk);
        sigBlock.set(signature, i * LEN_DA_SIG_ENTRY + LEN_FINGERPRINT);

    }

    // Final assembly: header + signatures + rse_count + rses.
    const out = new Uint8Array(
        LEN_VERSION + LEN_TIMESTAMP * 3 + LEN_DA_SIG_COUNT
        + sigBlock.length
        + LEN_RSE_COUNT + rsesBytes.length,
    );
    let off = 0;
    out[off] = CONSENSUS_VERSION; off += LEN_VERSION;
    writeBigUint64BE(out, off, validAfter); off += LEN_TIMESTAMP;
    writeBigUint64BE(out, off, freshUntil); off += LEN_TIMESTAMP;
    writeBigUint64BE(out, off, validUntil); off += LEN_TIMESTAMP;
    out[off] = daSigners.length; off += LEN_DA_SIG_COUNT;
    out.set(sigBlock, off); off += sigBlock.length;
    new DataView(out.buffer).setUint32(off, rses.length, false); off += LEN_RSE_COUNT;
    out.set(rsesBytes, off);
    return out;

};

// SPEC § 10.3a: parse + verify a consensus document.
//
// Inputs:
//   buf            consensus bytes
//   daTrustSet     Map<hex(fingerprint), idPk>  — the DAs the client trusts
//   nowSeconds     for validity-window check
//
// Returns { validAfter, freshUntil, validUntil, rses } | null.
// Rejects (returns null) on:
//   - any structural defect
//   - now outside [valid_after, valid_until]
//   - fewer than ⌊|daTrustSet| / 2⌋ + 1 verified signatures from known DAs
export const parseConsensus = (buf, { daTrustSet, nowSeconds }) => {

    if (!buf || buf.length < LEN_HEADER_BEFORE_DA) return null;
    if (buf[0] !== CONSENSUS_VERSION) return null;

    const validAfter = readBigUint64BE(buf, 1);
    const freshUntil = readBigUint64BE(buf, 9);
    const validUntil = readBigUint64BE(buf, 17);
    const daCount = buf[25];

    if (nowSeconds < validAfter || nowSeconds > validUntil) return null;

    const sigBlockStart = LEN_HEADER_BEFORE_DA;
    const sigBlockEnd = sigBlockStart + daCount * LEN_DA_SIG_ENTRY;
    if (buf.length < sigBlockEnd + LEN_RSE_COUNT) return null;

    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const rseCount = view.getUint32(sigBlockEnd, false);

    const rsesStart = sigBlockEnd + LEN_RSE_COUNT;
    const rsesBytes = buf.subarray(rsesStart);

    // Reconstruct the signed-bytes view: everything except the signatures.
    const signedBytes = new Uint8Array(
        LEN_HEADER_BEFORE_DA + LEN_RSE_COUNT + rsesBytes.length,
    );
    signedBytes.set(buf.subarray(0, LEN_HEADER_BEFORE_DA), 0);
    signedBytes.set(
        buf.subarray(sigBlockEnd, sigBlockEnd + LEN_RSE_COUNT + rsesBytes.length),
        LEN_HEADER_BEFORE_DA,
    );

    // Verify signatures: for each (fp, sig) pair in the block, look up
    // the DA in the trust set; if known, verify; count successes.
    let verifiedCount = 0;
    const seenFps = new Set();
    for (let i = 0; i < daCount; i += 1) {

        const base = sigBlockStart + i * LEN_DA_SIG_ENTRY;
        const fp = buf.subarray(base, base + LEN_FINGERPRINT);
        const sig = buf.subarray(base + LEN_FINGERPRINT, base + LEN_DA_SIG_ENTRY);
        const fpKey = Buffer.from(fp).toString('hex');
        if (seenFps.has(fpKey)) continue; // duplicate signer; ignore
        seenFps.add(fpKey);
        const trustedIdPk = daTrustSet.get(fpKey);
        if (!trustedIdPk) continue;
        if (verify(sig, signedBytes, trustedIdPk)) verifiedCount += 1;

    }

    const required = Math.floor(daTrustSet.size / 2) + 1;
    if (verifiedCount < required) return null;

    // Parse RSEs.
    const rses = [];
    let p = rsesStart;
    for (let i = 0; i < rseCount; i += 1) {

        const r = parseRse(buf, p);
        if (r === null) return null;
        rses.push(r.rse);
        p += r.consumed;

    }
    if (p !== buf.length) return null;

    return { validAfter, freshUntil, validUntil, rses };

};

// ----- Path selection -----

const hasAllFlags = (rse, flags) => (rse.flags & flags) === flags;
const hasAnyFlag = (rse, flags) => (rse.flags & flags) !== 0;

// SPEC § 6.1: distinct subnets. Two relays "co-located" if they share
// the same /16 IPv4 prefix or /48 IPv6 prefix.
const coLocated = (a, b) => {

    if (a.ipv4 && b.ipv4 && a.ipv4[0] === b.ipv4[0] && a.ipv4[1] === b.ipv4[1]) {

        return true;

    }
    if (a.ipv6 && b.ipv6) {

        for (let i = 0; i < 6; i += 1) {

            if (a.ipv6[i] !== b.ipv6[i]) return { same: false };

        }
        return true;

    }
    return false;

};

// Pick a random element from an array. Returns null if empty. Uses
// Math.random — acceptable for path selection because the security
// of the protocol does not depend on the unpredictability of any
// single relay choice (it depends on the network being diverse).
const pickRandom = (arr) => {

    if (arr.length === 0) return null;
    return arr[Math.floor(Math.random() * arr.length)];

};

const usableRelay = (rse) => hasAllFlags(rse, FLAG_RUNNING | FLAG_VALID);

// Filter candidates: usable, not in `exclude` (by fingerprint), not
// co-located with any relay in `coLocateAvoid`.
const filterCandidates = (rses, { extraFlags = 0, exclude = [], coLocateAvoid = [] } = {}) => {

    const excludeFps = new Set(exclude.map((fp) => Buffer.from(fp).toString('hex')));
    return rses.filter((r) => {

        if (!usableRelay(r)) return false;
        if (extraFlags !== 0 && !hasAllFlags(r, extraFlags)) return false;
        if (hasAnyFlag(r, FLAG_BAD_EXIT)) return false;
        if (excludeFps.has(Buffer.from(r.fingerprint).toString('hex'))) return false;
        for (const other of coLocateAvoid) if (coLocated(r, other)) return false;
        return true;

    });

};

// Pick an entry guard. Operators are expected to persist guards
// across restarts (anti-de-anonymisation property); this helper
// returns a fresh guard ONLY when the supplied `existingGuards` set
// is empty or all of its members have left the consensus.
export const selectGuard = ({ consensus, existingGuards = [] }) => {

    const stillValid = existingGuards.filter(
        (fp) => consensus.rses.find(
            (r) => Buffer.from(r.fingerprint).equals(Buffer.from(fp)) && usableRelay(r),
        ),
    );
    if (stillValid.length > 0) {

        // Return the first still-valid existing guard's RSE.
        const fp = stillValid[0];
        return consensus.rses.find(
            (r) => Buffer.from(r.fingerprint).equals(Buffer.from(fp)),
        );

    }
    const candidates = filterCandidates(consensus.rses, { extraFlags: FLAG_GUARD });
    return pickRandom(candidates);

};

// Pick a middle relay. Any usable, non-co-located relay.
export const selectMiddle = ({ consensus, excludeFps = [], coLocateAvoid = [] }) => {

    const candidates = filterCandidates(consensus.rses, {
        exclude: excludeFps,
        coLocateAvoid,
    });
    return pickRandom(candidates);

};

// Pick an exit whose policy accepts (addrType, addr, port).
export const selectExit = ({ consensus, destination, excludeFps = [], coLocateAvoid = [] }) => {

    const candidates = filterCandidates(consensus.rses, {
        extraFlags: FLAG_EXIT,
        exclude: excludeFps,
        coLocateAvoid,
    }).filter((r) => evaluate(r.exitPolicy, destination) === 'accept');
    return pickRandom(candidates);

};

// One-shot 3-hop path selection. Returns { guard, middle, exit } or
// null if any role couldn't be satisfied. Anti-correlation /16-/48
// is enforced between hops by default.
//
// `skipAntiCorrelation: true` disables the /16-/48 check. THIS WEAKENS
// ANONYMITY against on-network adversaries — relays in the same /16
// may share an operator or upstream provider, making traffic
// correlation easier. Intended for testnets where all relays share
// 127.0.0.1.
export const pickPath = ({
    consensus, destination, existingGuards = [],
    skipAntiCorrelation = false,
}) => {

    const guard = selectGuard({ consensus, existingGuards });
    if (!guard) return null;

    const exit = selectExit({
        consensus,
        destination,
        excludeFps: [guard.fingerprint],
        coLocateAvoid: skipAntiCorrelation ? [] : [guard],
    });
    if (!exit) return null;

    const middle = selectMiddle({
        consensus,
        excludeFps: [guard.fingerprint, exit.fingerprint],
        coLocateAvoid: skipAntiCorrelation ? [] : [guard, exit],
    });
    if (!middle) return null;

    return { guard, middle, exit };

};
