// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

import { expect } from 'chai';

import {
    CONSENSUS_VERSION,
    FLAG_EXIT,
    FLAG_GUARD,
    FLAG_RUNNING,
    FLAG_VALID,
    FLAG_BAD_EXIT,
    buildConsensus,
    parseConsensus,
    selectGuard,
    selectMiddle,
    selectExit,
    pickPath,
} from './consensus.mjs';
import {
    ADDR_TYPE_IPV4,
    ACTION_ACCEPT,
    buildPolicy,
    makeAnyRule,
    POLICY_REJECT_ALL,
} from './exit_policy.mjs';
import { generateIdentity, identityFingerprint } from '../crypto/identity.mjs';
import { generateOnion } from '../crypto/onion.mjs';

// ----- Test fixtures -----

const makeDA = () => {

    const id = generateIdentity();
    return {
        idPk: id.idPk,
        idSk: id.idSk,
        fingerprint: identityFingerprint(id.idPk),

    };

};

const trustSetOf = (das) => {

    const set = new Map();
    for (const da of das) {

        set.set(Buffer.from(da.fingerprint).toString('hex'), da.idPk);

    }
    return set;

};

const makeRelay = ({ flags, exitPolicy = null, ipv4Prefix = [10, 0, 0], ipv6Prefix = null } = {}) => {

    const id = generateIdentity();
    const onion = generateOnion();
    // Pick a random last octet so different calls produce different addrs.
    const lastOctet = (Math.random() * 256) | 0;
    const ipv4 = new Uint8Array([
        ipv4Prefix[0], ipv4Prefix[1], ipv4Prefix[2] || 0, lastOctet,
        0x1F, 0x90,
    ]);
    let ipv6 = null;
    if (ipv6Prefix) {

        ipv6 = new Uint8Array(18);
        for (let i = 0; i < ipv6Prefix.length; i += 1) ipv6[i] = ipv6Prefix[i];

    }
    return {
        fingerprint: identityFingerprint(id.idPk),
        idPk: id.idPk,
        onionPk: onion.onionPk,
        ipv4,
        ipv6,
        flags,
        exitPolicyBytes: exitPolicy
            ? buildPolicy(exitPolicy)
            : buildPolicy(POLICY_REJECT_ALL),
    };

};

const NOW = 1_500_000_000; // Unix-ish time; arbitrary in tests
const VALID_WINDOW = {
    validAfter: NOW - 60,
    freshUntil: NOW + 3600,
    validUntil: NOW + 7200,
};

// Standard exit policy used in tests: accept HTTPS only.
const POLICY_HTTPS = [
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 443, portMax: 443 }),
];

describe('v2/consensus — codec', () => {

    it('build → parse round-trip preserves RSEs in order', () => {

        const das = [makeDA(), makeDA(), makeDA()];
        const rses = [
            makeRelay({ flags: FLAG_RUNNING | FLAG_VALID | FLAG_GUARD, ipv4Prefix: [10, 1] }),
            makeRelay({ flags: FLAG_RUNNING | FLAG_VALID, ipv4Prefix: [10, 2] }),
            makeRelay({
                flags: FLAG_RUNNING | FLAG_VALID | FLAG_EXIT,
                exitPolicy: POLICY_HTTPS,
                ipv4Prefix: [10, 3],
            }),
        ];
        const buf = buildConsensus({
            ...VALID_WINDOW,
            rses, daSigners: das,
        });
        const parsed = parseConsensus(buf, {
            daTrustSet: trustSetOf(das),
            nowSeconds: NOW,
        });
        expect(parsed).to.not.equal(null);
        expect(parsed.rses.length).to.equal(3);
        expect(parsed.validAfter).to.equal(VALID_WINDOW.validAfter);
        expect(Buffer.from(parsed.rses[0].fingerprint).equals(Buffer.from(rses[0].fingerprint))).to.equal(true);
        expect(parsed.rses[2].flags & FLAG_EXIT).to.equal(FLAG_EXIT);

    });

    it('parse rejects consensus with no signatures from trusted DAs', () => {

        const realDAs = [makeDA(), makeDA(), makeDA()];
        const impostorDA = makeDA();
        // Build with the impostor — none of its sigs are trusted.
        const rses = [makeRelay({ flags: FLAG_RUNNING | FLAG_VALID })];
        const buf = buildConsensus({
            ...VALID_WINDOW, rses, daSigners: [impostorDA],
        });
        const result = parseConsensus(buf, {
            daTrustSet: trustSetOf(realDAs), nowSeconds: NOW,
        });
        expect(result).to.equal(null);

    });

    it('parse rejects consensus with fewer than majority of DA sigs', () => {

        const das = [makeDA(), makeDA(), makeDA(), makeDA(), makeDA()]; // 5 → need 3
        const rses = [makeRelay({ flags: FLAG_RUNNING | FLAG_VALID })];
        // Only 2 of 5 sign.
        const buf = buildConsensus({
            ...VALID_WINDOW, rses,
            daSigners: [das[0], das[1]],
        });
        const result = parseConsensus(buf, {
            daTrustSet: trustSetOf(das), nowSeconds: NOW,
        });
        expect(result).to.equal(null);

    });

    it('parse accepts at the majority threshold', () => {

        const das = [makeDA(), makeDA(), makeDA(), makeDA(), makeDA()]; // 5 → need 3
        const rses = [makeRelay({ flags: FLAG_RUNNING | FLAG_VALID })];
        const buf = buildConsensus({
            ...VALID_WINDOW, rses,
            daSigners: [das[0], das[1], das[2]],
        });
        const result = parseConsensus(buf, {
            daTrustSet: trustSetOf(das), nowSeconds: NOW,
        });
        expect(result).to.not.equal(null);

    });

    it('parse rejects a tampered RSE block (signatures cover the RSEs)', () => {

        const das = [makeDA(), makeDA(), makeDA()];
        const rses = [makeRelay({ flags: FLAG_RUNNING | FLAG_VALID })];
        const buf = buildConsensus({
            ...VALID_WINDOW, rses, daSigners: das,
        });
        // Flip a byte deep in the RSE block (after sig block).
        const tampered = new Uint8Array(buf);
        tampered[tampered.length - 10] ^= 0x01;
        const result = parseConsensus(tampered, {
            daTrustSet: trustSetOf(das), nowSeconds: NOW,
        });
        expect(result).to.equal(null);

    });

    it('parse rejects when current time is before valid_after', () => {

        const das = [makeDA(), makeDA(), makeDA()];
        const buf = buildConsensus({
            ...VALID_WINDOW,
            rses: [makeRelay({ flags: FLAG_RUNNING | FLAG_VALID })],
            daSigners: das,
        });
        const result = parseConsensus(buf, {
            daTrustSet: trustSetOf(das),
            nowSeconds: VALID_WINDOW.validAfter - 1,
        });
        expect(result).to.equal(null);

    });

    it('parse rejects when current time is after valid_until', () => {

        const das = [makeDA(), makeDA(), makeDA()];
        const buf = buildConsensus({
            ...VALID_WINDOW,
            rses: [makeRelay({ flags: FLAG_RUNNING | FLAG_VALID })],
            daSigners: das,
        });
        const result = parseConsensus(buf, {
            daTrustSet: trustSetOf(das),
            nowSeconds: VALID_WINDOW.validUntil + 1,
        });
        expect(result).to.equal(null);

    });

    it('parse rejects wrong version byte', () => {

        const das = [makeDA(), makeDA(), makeDA()];
        const buf = buildConsensus({
            ...VALID_WINDOW,
            rses: [makeRelay({ flags: FLAG_RUNNING | FLAG_VALID })],
            daSigners: das,
        });
        const tampered = new Uint8Array(buf);
        tampered[0] = 0x01;
        const result = parseConsensus(tampered, {
            daTrustSet: trustSetOf(das), nowSeconds: NOW,
        });
        expect(result).to.equal(null);

    });

    it('duplicate signer fingerprint counts only once (no signature stuffing)', () => {

        const das = [makeDA(), makeDA(), makeDA()];
        const rses = [makeRelay({ flags: FLAG_RUNNING | FLAG_VALID })];
        // Build with just one DA but include their signature 3 times
        // in the block. They should count as 1 (need 2 for majority).
        const buf = buildConsensus({
            ...VALID_WINDOW, rses, daSigners: [das[0], das[0], das[0]],
        });
        const result = parseConsensus(buf, {
            daTrustSet: trustSetOf(das), nowSeconds: NOW,
        });
        expect(result).to.equal(null);

    });

});

describe('v2/consensus — path selection', () => {

    // Helper: build a "real" consensus with a mix of relay roles.
    const makePopulatedConsensus = ({ extraExits = 0, extraGuards = 2, extraMiddles = 4 } = {}) => {

        const das = [makeDA(), makeDA(), makeDA()];
        const rses = [];
        for (let i = 0; i < extraGuards; i += 1) {

            rses.push(makeRelay({
                flags: FLAG_RUNNING | FLAG_VALID | FLAG_GUARD,
                ipv4Prefix: [10, 1 + i],
            }));

        }
        for (let i = 0; i < extraMiddles; i += 1) {

            rses.push(makeRelay({
                flags: FLAG_RUNNING | FLAG_VALID,
                ipv4Prefix: [10, 100 + i],
            }));

        }
        for (let i = 0; i <= extraExits; i += 1) {

            rses.push(makeRelay({
                flags: FLAG_RUNNING | FLAG_VALID | FLAG_EXIT,
                exitPolicy: POLICY_HTTPS,
                ipv4Prefix: [10, 200 + i],
            }));

        }
        const buf = buildConsensus({
            ...VALID_WINDOW, rses, daSigners: das,
        });
        return parseConsensus(buf, {
            daTrustSet: trustSetOf(das), nowSeconds: NOW,
        });

    };

    const ipv4 = (...parts) => new Uint8Array(parts);

    it('selectGuard picks a relay with GUARD flag', () => {

        const c = makePopulatedConsensus();
        const guard = selectGuard({ consensus: c });
        expect(guard).to.not.equal(null);
        expect(guard.flags & FLAG_GUARD).to.equal(FLAG_GUARD);

    });

    it('selectGuard reuses an existing guard if it is still in consensus', () => {

        const c = makePopulatedConsensus();
        const first = selectGuard({ consensus: c });
        // 10 retries — should always pick the same.
        for (let i = 0; i < 10; i += 1) {

            const next = selectGuard({
                consensus: c,
                existingGuards: [first.fingerprint],
            });
            expect(Buffer.from(next.fingerprint).equals(Buffer.from(first.fingerprint))).to.equal(true);

        }

    });

    it('selectExit picks an exit whose policy accepts the destination', () => {

        const c = makePopulatedConsensus({ extraExits: 2 });
        const exit = selectExit({
            consensus: c,
            destination: { addrType: ADDR_TYPE_IPV4, addr: ipv4(1, 1, 1, 1), port: 443 },
        });
        expect(exit).to.not.equal(null);
        expect(exit.flags & FLAG_EXIT).to.equal(FLAG_EXIT);

    });

    it('selectExit returns null when no exit accepts the destination', () => {

        const c = makePopulatedConsensus({ extraExits: 2 });
        // Port 22 — none of our exits allow SSH.
        const exit = selectExit({
            consensus: c,
            destination: { addrType: ADDR_TYPE_IPV4, addr: ipv4(1, 1, 1, 1), port: 22 },
        });
        expect(exit).to.equal(null);

    });

    it('excludes BAD_EXIT-flagged relays from exit selection', () => {

        const das = [makeDA(), makeDA(), makeDA()];
        const goodExit = makeRelay({
            flags: FLAG_RUNNING | FLAG_VALID | FLAG_EXIT,
            exitPolicy: POLICY_HTTPS,
            ipv4Prefix: [10, 200],
        });
        const badExit = makeRelay({
            flags: FLAG_RUNNING | FLAG_VALID | FLAG_EXIT | FLAG_BAD_EXIT,
            exitPolicy: POLICY_HTTPS,
            ipv4Prefix: [10, 201],
        });
        const buf = buildConsensus({
            ...VALID_WINDOW, rses: [goodExit, badExit], daSigners: das,
        });
        const c = parseConsensus(buf, { daTrustSet: trustSetOf(das), nowSeconds: NOW });
        for (let i = 0; i < 10; i += 1) {

            const exit = selectExit({
                consensus: c,
                destination: { addrType: ADDR_TYPE_IPV4, addr: ipv4(1, 1, 1, 1), port: 443 },
            });
            expect(Buffer.from(exit.fingerprint).equals(Buffer.from(goodExit.fingerprint))).to.equal(true);

        }

    });

    it('pickPath returns three distinct relays with correct roles', () => {

        const c = makePopulatedConsensus({ extraExits: 2, extraGuards: 3, extraMiddles: 4 });
        const path = pickPath({
            consensus: c,
            destination: { addrType: ADDR_TYPE_IPV4, addr: ipv4(1, 1, 1, 1), port: 443 },
        });
        expect(path).to.not.equal(null);
        expect(path.guard.flags & FLAG_GUARD).to.equal(FLAG_GUARD);
        expect(path.exit.flags & FLAG_EXIT).to.equal(FLAG_EXIT);
        // All three distinct.
        const fps = [path.guard.fingerprint, path.middle.fingerprint, path.exit.fingerprint];
        const fpHex = fps.map((f) => Buffer.from(f).toString('hex'));
        expect(new Set(fpHex).size).to.equal(3);

    });

    it('pickPath enforces /16 anti-correlation', () => {

        // Build a consensus where the only candidate guard and the
        // only candidate exit share a /16. pickPath should fail (no
        // valid path) rather than pick co-located relays.
        const das = [makeDA(), makeDA(), makeDA()];
        const guard = makeRelay({
            flags: FLAG_RUNNING | FLAG_VALID | FLAG_GUARD,
            ipv4Prefix: [10, 5],
        });
        const exit = makeRelay({
            flags: FLAG_RUNNING | FLAG_VALID | FLAG_EXIT,
            exitPolicy: POLICY_HTTPS,
            ipv4Prefix: [10, 5], // same /16 as guard
        });
        const middle = makeRelay({
            flags: FLAG_RUNNING | FLAG_VALID,
            ipv4Prefix: [10, 7],
        });
        const buf = buildConsensus({
            ...VALID_WINDOW, rses: [guard, exit, middle], daSigners: das,
        });
        const c = parseConsensus(buf, {
            daTrustSet: trustSetOf(das), nowSeconds: NOW,
        });
        const path = pickPath({
            consensus: c,
            destination: { addrType: ADDR_TYPE_IPV4, addr: ipv4(1, 1, 1, 1), port: 443 },
        });
        expect(path).to.equal(null);

    });

    it('pickPath returns null when guard or exit absent', () => {

        const das = [makeDA(), makeDA(), makeDA()];
        // Only middles, no guard or exit.
        const rses = [
            makeRelay({ flags: FLAG_RUNNING | FLAG_VALID, ipv4Prefix: [10, 1] }),
            makeRelay({ flags: FLAG_RUNNING | FLAG_VALID, ipv4Prefix: [10, 2] }),
        ];
        const buf = buildConsensus({
            ...VALID_WINDOW, rses, daSigners: das,
        });
        const c = parseConsensus(buf, {
            daTrustSet: trustSetOf(das), nowSeconds: NOW,
        });
        const path = pickPath({
            consensus: c,
            destination: { addrType: ADDR_TYPE_IPV4, addr: ipv4(1, 1, 1, 1), port: 443 },
        });
        expect(path).to.equal(null);

    });

});
