// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

import { expect } from 'chai';

import {
    LINK_PROTOCOL_VERSION,
    LINK_FLAG_IS_DIALER,
    LEN_LINK_HELLO_PAYLOAD,
    LEN_LINK_AUTH_PAYLOAD,
    HANDSHAKE_STATE_AWAITING_HELLO,
    HANDSHAKE_STATE_AWAITING_AUTH,
    HANDSHAKE_STATE_ESTABLISHED,
    HANDSHAKE_STATE_FAILED,
    buildLinkHelloPayload,
    parseLinkHelloPayload,
    buildLinkAuthPayload,
    verifyLinkAuthSignature,
    createLinkHandshake,
} from './link.mjs';
import {
    CMD_LINK_HELLO,
    CMD_LINK_AUTH,
    CMD_RELAY,
    parseCell,
    buildCell,
} from './cells.mjs';
import { generateIdentity } from '../crypto/identity.mjs';

const fixedNonce = (b) => new Uint8Array(32).fill(b);

// ----- LINK_HELLO codec -----

describe('v2/link — LINK_HELLO payload', () => {

    it('round-trips through parse', () => {

        const id = generateIdentity();
        const payload = buildLinkHelloPayload({
            idPk: id.idPk,
            nonce: fixedNonce(0xAB),
            flags: LINK_FLAG_IS_DIALER,
        });
        expect(payload.length).to.equal(LEN_LINK_HELLO_PAYLOAD);
        expect(payload[0]).to.equal(LINK_PROTOCOL_VERSION);
        expect(payload[1]).to.equal(LINK_FLAG_IS_DIALER);
        const parsed = parseLinkHelloPayload(payload);
        expect(parsed.version).to.equal(LINK_PROTOCOL_VERSION);
        expect(parsed.flags).to.equal(LINK_FLAG_IS_DIALER);
        expect(Buffer.from(parsed.nonce).equals(Buffer.from(fixedNonce(0xAB)))).to.equal(true);
        expect(Buffer.from(parsed.idPk).equals(Buffer.from(id.idPk))).to.equal(true);

    });

    it('rejects wrong-sized inputs', () => {

        expect(() => buildLinkHelloPayload({
            idPk: new Uint8Array(31), nonce: fixedNonce(0), flags: 0,
        })).to.throw();
        expect(parseLinkHelloPayload(null)).to.equal(null);
        expect(parseLinkHelloPayload(new Uint8Array(LEN_LINK_HELLO_PAYLOAD - 1))).to.equal(null);

    });

    it('reserved bytes are zero on build', () => {

        const id = generateIdentity();
        const payload = buildLinkHelloPayload({
            idPk: id.idPk, nonce: fixedNonce(0), flags: 0,
        });
        expect(payload[2]).to.equal(0);
        expect(payload[3]).to.equal(0);

    });

});

// ----- LINK_AUTH transcript + signature -----

describe('v2/link — LINK_AUTH signature', () => {

    it('signature verifies under the signer\'s idPk with matching transcript', () => {

        const a = generateIdentity();
        const b = generateIdentity();
        const aNonce = fixedNonce(0xAA);
        const bNonce = fixedNonce(0xBB);
        const sigA = buildLinkAuthPayload({
            idSk: a.idSk, idPk: a.idPk,
            myNonce: aNonce, peerNonce: bNonce, peerIdPk: b.idPk,
        });
        expect(sigA.length).to.equal(LEN_LINK_AUTH_PAYLOAD);
        // Verifier B reconstructs the transcript from B's vantage.
        expect(verifyLinkAuthSignature({
            signature: sigA,
            peerIdPk: a.idPk, peerNonce: aNonce,
            myIdPk: b.idPk, myNonce: bNonce,
        })).to.equal(true);

    });

    it('signature does NOT verify under the wrong idPk', () => {

        const a = generateIdentity();
        const impostor = generateIdentity();
        const b = generateIdentity();
        const sigA = buildLinkAuthPayload({
            idSk: a.idSk, idPk: a.idPk,
            myNonce: fixedNonce(1), peerNonce: fixedNonce(2), peerIdPk: b.idPk,
        });
        expect(verifyLinkAuthSignature({
            signature: sigA,
            peerIdPk: impostor.idPk, peerNonce: fixedNonce(1),
            myIdPk: b.idPk, myNonce: fixedNonce(2),
        })).to.equal(false);

    });

    it('signature does NOT verify when a nonce is tampered', () => {

        const a = generateIdentity();
        const b = generateIdentity();
        const sigA = buildLinkAuthPayload({
            idSk: a.idSk, idPk: a.idPk,
            myNonce: fixedNonce(1), peerNonce: fixedNonce(2), peerIdPk: b.idPk,
        });
        expect(verifyLinkAuthSignature({
            signature: sigA,
            peerIdPk: a.idPk, peerNonce: fixedNonce(3), // wrong nonce
            myIdPk: b.idPk, myNonce: fixedNonce(2),
        })).to.equal(false);

    });

});

// ----- Handshake state machine -----

// Drive both sides synchronously: each side gets the cells the other
// sends. Returns { aLink, bLink } both with state 'established' on
// success, or throws.
const runHandshake = ({ aIdentity, bIdentity, expectedAtA = null, expectedAtB = null }) => {

    const a = createLinkHandshake({
        identity: aIdentity, expectedPeerIdPk: expectedAtA, isDialer: true,
    });
    const b = createLinkHandshake({
        identity: bIdentity, expectedPeerIdPk: expectedAtB, isDialer: false,
    });

    const aHello = a.buildHelloCell();
    const bHello = b.buildHelloCell();

    // Each side ingests the other's HELLO; both produce a 'send' (AUTH).
    const aAfterB = a.ingestCell(bHello);
    const bAfterA = b.ingestCell(aHello);
    if (aAfterB === null) throw new Error(`A failed: ${a.getFailureReason()}`);
    if (bAfterA === null) throw new Error(`B failed: ${b.getFailureReason()}`);
    if (aAfterB.kind !== 'send') throw new Error('A did not produce AUTH');
    if (bAfterA.kind !== 'send') throw new Error('B did not produce AUTH');

    const aFinal = a.ingestCell(bAfterA.cell);
    const bFinal = b.ingestCell(aAfterB.cell);
    if (aFinal === null) throw new Error(`A failed at AUTH: ${a.getFailureReason()}`);
    if (bFinal === null) throw new Error(`B failed at AUTH: ${b.getFailureReason()}`);

    return { a, b, aFinal, bFinal };

};

describe('v2/link — handshake state machine', () => {

    it('two honest peers complete the handshake mutually', () => {

        const a = generateIdentity();
        const b = generateIdentity();
        const { a: linkA, b: linkB, aFinal, bFinal } = runHandshake({
            aIdentity: a, bIdentity: b,
            expectedAtA: b.idPk,  // dialer A expects to reach B
        });
        expect(aFinal.kind).to.equal('established');
        expect(bFinal.kind).to.equal('established');
        expect(linkA.getState()).to.equal(HANDSHAKE_STATE_ESTABLISHED);
        expect(linkB.getState()).to.equal(HANDSHAKE_STATE_ESTABLISHED);
        expect(Buffer.from(aFinal.peerIdPk).equals(Buffer.from(b.idPk))).to.equal(true);
        expect(Buffer.from(bFinal.peerIdPk).equals(Buffer.from(a.idPk))).to.equal(true);

    });

    it('dialer rejects when the recipient presents the wrong idPk (MITM defence)', () => {

        const aSender = generateIdentity();
        const bExpected = generateIdentity();
        const bActual = generateIdentity(); // network attacker swapped in
        expect(() => runHandshake({
            aIdentity: aSender, bIdentity: bActual,
            expectedAtA: bExpected.idPk, // A wants to talk to bExpected
        })).to.throw(/peer idPk does not match expected/);

    });

    it('handshake rejects a forged LINK_AUTH signature', () => {

        const a = generateIdentity();
        const b = generateIdentity();
        const impostor = generateIdentity();
        const linkA = createLinkHandshake({ identity: a, expectedPeerIdPk: b.idPk, isDialer: true });
        const linkB = createLinkHandshake({ identity: b, isDialer: false });
        const aHello = linkA.buildHelloCell();
        const bHello = linkB.buildHelloCell();
        const aAfterB = linkA.ingestCell(bHello);
        const bAfterA = linkB.ingestCell(aHello);
        // A receives B's AUTH — but the attacker swaps in an impostor's
        // signature crafted for the same transcript. The signature
        // verifies under the impostor's idPk, not B's, so it fails.
        const parsedAuth = parseCell(bAfterA.cell);
        const peerHelloB = parseLinkHelloPayload(parseCell(bHello).payload);
        const peerHelloA = parseLinkHelloPayload(parseCell(aHello).payload);
        const impostorSig = buildLinkAuthPayload({
            idSk: impostor.idSk, idPk: b.idPk, // signs claiming b's nonce/idPk
            myNonce: peerHelloB.nonce,
            peerNonce: peerHelloA.nonce,
            peerIdPk: a.idPk,
        });
        const forged = buildCell({
            circuitId: 0,
            command: CMD_LINK_AUTH,
            payload: impostorSig,
        });
        const aResult = linkA.ingestCell(forged);
        expect(aResult).to.equal(null);
        expect(linkA.getState()).to.equal(HANDSHAKE_STATE_FAILED);
        expect(linkA.getFailureReason()).to.match(/signature did not verify/);

    });

    it('handshake rejects a duplicate LINK_HELLO', () => {

        const a = generateIdentity();
        const b = generateIdentity();
        const linkA = createLinkHandshake({ identity: a, expectedPeerIdPk: b.idPk, isDialer: true });
        const linkB = createLinkHandshake({ identity: b, isDialer: false });
        const bHello = linkB.buildHelloCell();
        const first = linkA.ingestCell(bHello);
        expect(first.kind).to.equal('send'); // A sends AUTH
        const second = linkA.ingestCell(bHello);
        expect(second).to.equal(null);
        expect(linkA.getFailureReason()).to.match(/duplicate LINK_HELLO/);

    });

    it('handshake rejects LINK_AUTH before LINK_HELLO', () => {

        const a = generateIdentity();
        const linkA = createLinkHandshake({ identity: a, isDialer: false });
        const fakeAuth = buildCell({
            circuitId: 0,
            command: CMD_LINK_AUTH,
            payload: new Uint8Array(LEN_LINK_AUTH_PAYLOAD),
        });
        const r = linkA.ingestCell(fakeAuth);
        expect(r).to.equal(null);
        expect(linkA.getFailureReason()).to.match(/LINK_AUTH before LINK_HELLO/);

    });

    it('handshake rejects non-handshake cells before completion', () => {

        const a = generateIdentity();
        const linkA = createLinkHandshake({ identity: a, isDialer: false });
        const stray = buildCell({
            circuitId: 0, command: CMD_RELAY,
            payload: new Uint8Array(508),
        });
        const r = linkA.ingestCell(stray);
        expect(r).to.equal(null);
        expect(linkA.getFailureReason()).to.match(/unexpected cell command/);

    });

    it('handshake rejects link cells with non-zero circuit_id', () => {

        const a = generateIdentity();
        const linkA = createLinkHandshake({ identity: a, isDialer: false });
        const id = generateIdentity();
        const badHello = buildCell({
            circuitId: 999,
            command: CMD_LINK_HELLO,
            payload: buildLinkHelloPayload({
                idPk: id.idPk, nonce: fixedNonce(0), flags: 0,
            }),
        });
        expect(linkA.ingestCell(badHello)).to.equal(null);
        expect(linkA.getFailureReason()).to.match(/non-zero circuit_id/);

    });

    it('handshake rejects mismatched protocol version', () => {

        const a = generateIdentity();
        const b = generateIdentity();
        const linkA = createLinkHandshake({ identity: a, expectedPeerIdPk: b.idPk, isDialer: true });
        // Craft a HELLO with version 0x03.
        const badPayload = buildLinkHelloPayload({
            idPk: b.idPk, nonce: fixedNonce(0), flags: 0,
        });
        badPayload[0] = 0x03;
        const badHello = buildCell({
            circuitId: 0, command: CMD_LINK_HELLO, payload: badPayload,
        });
        expect(linkA.ingestCell(badHello)).to.equal(null);
        expect(linkA.getFailureReason()).to.match(/version mismatch/);

    });

    it('two independent handshakes have distinct nonces (random freshness)', () => {

        const a = generateIdentity();
        const linkA1 = createLinkHandshake({ identity: a, isDialer: false });
        const linkA2 = createLinkHandshake({ identity: a, isDialer: false });
        const hello1 = parseLinkHelloPayload(parseCell(linkA1.buildHelloCell()).payload);
        const hello2 = parseLinkHelloPayload(parseCell(linkA2.buildHelloCell()).payload);
        expect(Buffer.from(hello1.nonce).equals(Buffer.from(hello2.nonce))).to.equal(false);

    });

});
