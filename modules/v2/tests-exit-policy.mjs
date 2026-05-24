// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

import { expect } from 'chai';
import fc from 'fast-check';

import {
    ACTION_ACCEPT,
    ACTION_REJECT,
    ADDR_TYPE_IPV4,
    ADDR_TYPE_IPV6,
    ADDR_TYPE_ANY,
    makeIPv4Rule,
    makeIPv6Rule,
    makeAnyRule,
    buildPolicy,
    parsePolicy,
    evaluate,
    POLICY_REJECT_ALL,
    POLICY_REDUCED_EXIT,
    POLICY_STANDARD_EXIT,
} from './exit_policy.mjs';

const ipv4 = (...parts) => new Uint8Array(parts);
const ipv6 = (bytes) => {

    const out = new Uint8Array(16);
    out.set(bytes, 0);
    return out;

};

describe('v2/exit_policy — constructors', () => {

    it('makeAnyRule produces a rule with no net or mask', () => {

        const rule = makeAnyRule({ action: ACTION_ACCEPT, portMin: 80, portMax: 80 });
        expect(rule.addrType).to.equal(ADDR_TYPE_ANY);
        expect(rule.net).to.equal(null);
        expect(rule.maskLen).to.equal(null);

    });

    it('makeIPv4Rule rejects non-4-byte net', () => {

        expect(() => makeIPv4Rule({
            action: ACTION_ACCEPT,
            net: ipv4(10, 0, 0),
            maskLen: 24,
            portMin: 80, portMax: 80,
        })).to.throw();

    });

    it('makeIPv4Rule rejects out-of-range maskLen', () => {

        expect(() => makeIPv4Rule({
            action: ACTION_ACCEPT,
            net: ipv4(10, 0, 0, 0),
            maskLen: 33,
            portMin: 80, portMax: 80,
        })).to.throw();

    });

    it('makeIPv6Rule rejects out-of-range maskLen', () => {

        expect(() => makeIPv6Rule({
            action: ACTION_ACCEPT,
            net: ipv6([0xFE, 0x80]),
            maskLen: 129,
            portMin: 80, portMax: 80,
        })).to.throw();

    });

    it('rejects portMax < portMin', () => {

        expect(() => makeAnyRule({
            action: ACTION_ACCEPT, portMin: 100, portMax: 50,
        })).to.throw();

    });

    it('rejects invalid action codes', () => {

        expect(() => makeAnyRule({
            action: 0xFF, portMin: 80, portMax: 80,
        })).to.throw();

    });

});

describe('v2/exit_policy — evaluator', () => {

    it('empty policy rejects everything (implicit final REJECT)', () => {

        expect(evaluate(POLICY_REJECT_ALL, {
            addrType: ADDR_TYPE_IPV4, addr: ipv4(1, 1, 1, 1), port: 80,
        })).to.equal('reject');

    });

    it('REDUCED_EXIT accepts port 80 / 443 / 53 and rejects others', () => {

        const a = (port) => evaluate(POLICY_REDUCED_EXIT, {
            addrType: ADDR_TYPE_IPV4, addr: ipv4(1, 1, 1, 1), port,
        });
        expect(a(80)).to.equal('accept');
        expect(a(443)).to.equal('accept');
        expect(a(53)).to.equal('accept');
        expect(a(22)).to.equal('reject');
        expect(a(8080)).to.equal('reject');

    });

    it('REDUCED_EXIT applies the same way to IPv6', () => {

        expect(evaluate(POLICY_REDUCED_EXIT, {
            addrType: ADDR_TYPE_IPV6,
            addr: ipv6([0x20, 0x01, 0x0D, 0xB8]),
            port: 443,
        })).to.equal('accept');

    });

    it('STANDARD_EXIT accepts common services and rejects port 25', () => {

        // 25 (SMTP) is deliberately NOT in the standard exit policy.
        expect(evaluate(POLICY_STANDARD_EXIT, {
            addrType: ADDR_TYPE_IPV4, addr: ipv4(1, 2, 3, 4), port: 25,
        })).to.equal('reject');
        expect(evaluate(POLICY_STANDARD_EXIT, {
            addrType: ADDR_TYPE_IPV4, addr: ipv4(1, 2, 3, 4), port: 22,
        })).to.equal('accept'); // SSH
        expect(evaluate(POLICY_STANDARD_EXIT, {
            addrType: ADDR_TYPE_IPV4, addr: ipv4(1, 2, 3, 4), port: 443,
        })).to.equal('accept');

    });

    it('first-match-wins: explicit REJECT before ACCEPT short-circuits', () => {

        const policy = [
            makeIPv4Rule({
                action: ACTION_REJECT,
                net: ipv4(10, 0, 0, 0), maskLen: 8,
                portMin: 0, portMax: 0xFFFF,
            }),
            makeAnyRule({
                action: ACTION_ACCEPT, portMin: 0, portMax: 0xFFFF,
            }),
        ];
        // 10.0.0.5 hits the REJECT first.
        expect(evaluate(policy, {
            addrType: ADDR_TYPE_IPV4, addr: ipv4(10, 0, 0, 5), port: 80,
        })).to.equal('reject');
        // 1.1.1.1 falls through to the ACCEPT.
        expect(evaluate(policy, {
            addrType: ADDR_TYPE_IPV4, addr: ipv4(1, 1, 1, 1), port: 80,
        })).to.equal('accept');

    });

    it('IPv4 /24 prefix match is bit-exact', () => {

        const policy = [makeIPv4Rule({
            action: ACTION_ACCEPT,
            net: ipv4(192, 168, 1, 0), maskLen: 24,
            portMin: 80, portMax: 80,
        })];
        // 192.168.1.x matches.
        expect(evaluate(policy, {
            addrType: ADDR_TYPE_IPV4, addr: ipv4(192, 168, 1, 99), port: 80,
        })).to.equal('accept');
        // 192.168.2.x doesn't match.
        expect(evaluate(policy, {
            addrType: ADDR_TYPE_IPV4, addr: ipv4(192, 168, 2, 1), port: 80,
        })).to.equal('reject');

    });

    it('IPv4 /20 prefix (sub-byte boundary) matches correctly', () => {

        const policy = [makeIPv4Rule({
            action: ACTION_ACCEPT,
            net: ipv4(10, 96, 0, 0), maskLen: 12, // 10.96.0.0/12 → 10.96.0.0..10.111.255.255
            portMin: 80, portMax: 80,
        })];
        // 10.96.x.y matches.
        expect(evaluate(policy, {
            addrType: ADDR_TYPE_IPV4, addr: ipv4(10, 100, 5, 5), port: 80,
        })).to.equal('accept');
        // 10.112.x.y is outside the prefix.
        expect(evaluate(policy, {
            addrType: ADDR_TYPE_IPV4, addr: ipv4(10, 112, 0, 0), port: 80,
        })).to.equal('reject');

    });

    it('/0 prefix matches everything', () => {

        const policy = [makeIPv4Rule({
            action: ACTION_ACCEPT,
            net: ipv4(0, 0, 0, 0), maskLen: 0,
            portMin: 0, portMax: 0xFFFF,
        })];
        expect(evaluate(policy, {
            addrType: ADDR_TYPE_IPV4, addr: ipv4(255, 255, 255, 255), port: 12345,
        })).to.equal('accept');

    });

    it('ANY does not match across IPv4/IPv6 boundary by addrType (it matches either)', () => {

        const policy = [makeAnyRule({
            action: ACTION_ACCEPT, portMin: 80, portMax: 80,
        })];
        expect(evaluate(policy, {
            addrType: ADDR_TYPE_IPV4, addr: ipv4(1, 1, 1, 1), port: 80,
        })).to.equal('accept');
        expect(evaluate(policy, {
            addrType: ADDR_TYPE_IPV6, addr: ipv6([0x20, 0x01]), port: 80,
        })).to.equal('accept');

    });

    it('IPv4 rule does not match an IPv6 query', () => {

        const policy = [makeIPv4Rule({
            action: ACTION_ACCEPT,
            net: ipv4(0, 0, 0, 0), maskLen: 0,
            portMin: 80, portMax: 80,
        })];
        expect(evaluate(policy, {
            addrType: ADDR_TYPE_IPV6, addr: ipv6([0x20, 0x01]), port: 80,
        })).to.equal('reject');

    });

    it('evaluate throws on hostname query (caller must resolve first)', () => {

        expect(() => evaluate(POLICY_REDUCED_EXIT, {
            addrType: 0x03, addr: new Uint8Array([0x68, 0x69]), port: 80,
        })).to.throw();

    });

});

describe('v2/exit_policy — wire codec', () => {

    it('build → parse round-trip preserves rules in order', () => {

        const rules = [
            makeIPv4Rule({
                action: ACTION_REJECT,
                net: ipv4(127, 0, 0, 0), maskLen: 8,
                portMin: 0, portMax: 0xFFFF,
            }),
            makeAnyRule({
                action: ACTION_ACCEPT, portMin: 443, portMax: 443,
            }),
            makeIPv6Rule({
                action: ACTION_REJECT,
                net: ipv6([0xFE, 0x80]), maskLen: 10,
                portMin: 0, portMax: 0xFFFF,
            }),
        ];
        const buf = buildPolicy(rules);
        const parsed = parsePolicy(buf);
        expect(parsed).to.not.equal(null);
        expect(parsed.length).to.equal(3);
        expect(parsed[0].action).to.equal(ACTION_REJECT);
        expect(parsed[0].addrType).to.equal(ADDR_TYPE_IPV4);
        expect(parsed[0].maskLen).to.equal(8);
        expect(parsed[1].addrType).to.equal(ADDR_TYPE_ANY);
        expect(parsed[2].addrType).to.equal(ADDR_TYPE_IPV6);
        expect(parsed[2].maskLen).to.equal(10);

    });

    it('parsePolicy returns null on trailing bytes', () => {

        const buf = buildPolicy([
            makeAnyRule({ action: ACTION_ACCEPT, portMin: 80, portMax: 80 }),
        ]);
        const padded = new Uint8Array(buf.length + 1);
        padded.set(buf, 0);
        expect(parsePolicy(padded)).to.equal(null);

    });

    it('parsePolicy returns null on truncated input', () => {

        const buf = buildPolicy([
            makeIPv4Rule({
                action: ACTION_ACCEPT,
                net: ipv4(1, 2, 3, 4), maskLen: 32,
                portMin: 80, portMax: 80,
            }),
        ]);
        expect(parsePolicy(buf.subarray(0, buf.length - 1))).to.equal(null);

    });

    it('parsePolicy rejects invalid action codes', () => {

        const buf = new Uint8Array([
            0x00, 0x01,              // 1 rule
            0xFF, ADDR_TYPE_ANY,     // bad action
            0x00, 0x50, 0x00, 0x50,  // ports
        ]);
        expect(parsePolicy(buf)).to.equal(null);

    });

    it('parsePolicy rejects oversized maskLen', () => {

        const buf = new Uint8Array([
            0x00, 0x01,
            ACTION_ACCEPT, ADDR_TYPE_IPV4,
            0x0A, 0x00, 0x00, 0x00,
            0x21,                    // 33 — out of range for IPv4
            0x00, 0x50, 0x00, 0x50,
        ]);
        expect(parsePolicy(buf)).to.equal(null);

    });

    it('empty policy serialises to two zero bytes', () => {

        const buf = buildPolicy([]);
        expect(buf.length).to.equal(2);
        expect(buf[0]).to.equal(0);
        expect(buf[1]).to.equal(0);
        expect(parsePolicy(buf)).to.deep.equal([]);

    });

    it('property: parsePolicy on arbitrary bytes never throws', () => {

        fc.assert(
            fc.property(
                fc.uint8Array({ minLength: 0, maxLength: 1024 }),
                (buf) => {

                    try {

                        parsePolicy(buf);
                        return true;

                    } catch {

                        return false;

                    }

                },
            ),
            { numRuns: 500 },
        );

    });

});
