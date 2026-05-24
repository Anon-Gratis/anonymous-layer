// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

// Link-layer handshake for SPEC-v0.2-draft § 11.
//
// Before any circuit traffic can flow between two relays, they perform
// a two-round LINK_HELLO + LINK_AUTH handshake on top of TLS. The
// handshake establishes:
//
//   - Each side's claimed Ed25519 idPk
//   - Mutual proof-of-possession of the matching idSk via signature
//   - Per-handshake nonces, defeating replay
//
// The dialer additionally verifies the recipient's idPk matches the
// expected-recipient identity (typically from the consensus); the
// acceptor accepts any peer who can authenticate to a valid idSk.

import { randomBytes } from 'node:crypto';

import { sign, verify } from '../crypto/identity.mjs';
import {
    LEN_CELL_PAYLOAD,
    CMD_LINK_HELLO,
    CMD_LINK_AUTH,
    buildCell,
    parseCell,
} from './cells.mjs';

// ----- Constants -----

export const LINK_PROTOCOL_VERSION = 0x02;

export const LINK_FLAG_IS_DIALER = 0x01;

export const LEN_LINK_HELLO_PAYLOAD = 68;
export const LEN_LINK_AUTH_PAYLOAD = 64;

const OFFSET_LINK_VERSION  = 0;
const OFFSET_LINK_FLAGS    = 1;
const OFFSET_LINK_RESERVED = 2;
const OFFSET_LINK_NONCE    = 4;
const OFFSET_LINK_IDPK     = 36;

const LINK_AUTH_CONTEXT = new TextEncoder().encode('anon-layer/v2/link-auth');

// ----- Helpers -----

const concat = (...arrays) => {

    let total = 0;
    for (const a of arrays) total += a.length;
    const out = new Uint8Array(total);
    let o = 0;
    for (const a of arrays) { out.set(a, o); o += a.length; }
    return out;

};

const constantTimeEqual = (a, b) => {

    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
    return diff === 0;

};

// ----- LINK_HELLO payload codec -----

export const buildLinkHelloPayload = ({ idPk, nonce, flags }) => {

    if (idPk.length !== 32) throw new Error('idPk must be 32 bytes');
    if (nonce.length !== 32) throw new Error('nonce must be 32 bytes');
    const buf = new Uint8Array(LEN_LINK_HELLO_PAYLOAD);
    buf[OFFSET_LINK_VERSION] = LINK_PROTOCOL_VERSION;
    buf[OFFSET_LINK_FLAGS] = flags & 0xFF;
    // bytes [2..4) are reserved, already zero
    buf.set(nonce, OFFSET_LINK_NONCE);
    buf.set(idPk, OFFSET_LINK_IDPK);
    return buf;

};

export const parseLinkHelloPayload = (payload) => {

    if (!payload || payload.length < LEN_LINK_HELLO_PAYLOAD) return null;
    const version = payload[OFFSET_LINK_VERSION];
    const flags = payload[OFFSET_LINK_FLAGS];
    const nonce = new Uint8Array(payload.subarray(OFFSET_LINK_NONCE, OFFSET_LINK_NONCE + 32));
    const idPk = new Uint8Array(payload.subarray(OFFSET_LINK_IDPK, OFFSET_LINK_IDPK + 32));
    return { version, flags, nonce, idPk };

};

// ----- LINK_AUTH transcript + signature -----

// Build the transcript that LINK_AUTH's signature covers. Each side
// substitutes its own values for *_self; this gives both sides the
// same transcript shape but distinct bytes, ensuring each signature
// is valid only under the signer's own idSk.
const buildAuthTranscript = ({
    nonceSelf, idPkSelf, noncePeer, idPkPeer,
}) => concat(
    LINK_AUTH_CONTEXT,
    nonceSelf, idPkSelf,
    noncePeer, idPkPeer,
);

export const buildLinkAuthPayload = ({
    idSk, idPk, myNonce, peerNonce, peerIdPk,
}) => {

    if (idSk.length !== 32) throw new Error('idSk must be 32 bytes');
    if (idPk.length !== 32) throw new Error('idPk must be 32 bytes');
    if (myNonce.length !== 32) throw new Error('myNonce must be 32 bytes');
    if (peerNonce.length !== 32) throw new Error('peerNonce must be 32 bytes');
    if (peerIdPk.length !== 32) throw new Error('peerIdPk must be 32 bytes');

    const transcript = buildAuthTranscript({
        nonceSelf: myNonce, idPkSelf: idPk,
        noncePeer: peerNonce, idPkPeer: peerIdPk,
    });
    return sign(transcript, idSk);

};

export const verifyLinkAuthSignature = ({
    signature, peerIdPk, peerNonce, myIdPk, myNonce,
}) => {

    if (!signature || signature.length !== LEN_LINK_AUTH_PAYLOAD) return false;
    if (peerIdPk.length !== 32) return false;
    if (peerNonce.length !== 32) return false;
    if (myIdPk.length !== 32) return false;
    if (myNonce.length !== 32) return false;

    // Reconstruct the transcript from the PEER's vantage:
    //   nonceSelf  = peerNonce  (what they sent in their HELLO)
    //   idPkSelf   = peerIdPk
    //   noncePeer  = myNonce
    //   idPkPeer   = myIdPk
    const transcript = buildAuthTranscript({
        nonceSelf: peerNonce, idPkSelf: peerIdPk,
        noncePeer: myNonce, idPkPeer: myIdPk,
    });
    return verify(signature, transcript, peerIdPk);

};

// ----- Handshake state machine -----

// Handshake states:
//   'awaiting-peer-hello'  — we've sent our HELLO; awaiting peer's
//   'awaiting-peer-auth'   — we've sent AUTH; awaiting peer's AUTH
//   'established'          — handshake complete; link authenticated
//   'failed'               — terminal failure
export const HANDSHAKE_STATE_AWAITING_HELLO = 'awaiting-peer-hello';
export const HANDSHAKE_STATE_AWAITING_AUTH  = 'awaiting-peer-auth';
export const HANDSHAKE_STATE_ESTABLISHED    = 'established';
export const HANDSHAKE_STATE_FAILED         = 'failed';

export const createLinkHandshake = ({
    identity,             // local relay identity { idPk, idSk }
    expectedPeerIdPk = null, // dialer supplies; acceptor leaves null
    isDialer,
    rng = randomBytes,
}) => {

    const myNonce = rng(32);
    let state = HANDSHAKE_STATE_AWAITING_HELLO;
    let peerHello = null;
    let myAuthSent = false;
    let failureReason = null;

    const fail = (reason) => {

        state = HANDSHAKE_STATE_FAILED;
        failureReason = reason;
        return null;

    };

    // Return the LINK_HELLO cell this side should send (the very first
    // outbound after TLS completes).
    const buildHelloCell = () => buildCell({
        circuitId: 0,
        command: CMD_LINK_HELLO,
        payload: buildLinkHelloPayload({
            idPk: identity.idPk,
            nonce: myNonce,
            flags: isDialer ? LINK_FLAG_IS_DIALER : 0,
        }),
    });

    // Ingest an incoming cell. Returns one of:
    //   { kind: 'send', cell }            — caller should send `cell`
    //   { kind: 'established', peerIdPk }  — handshake done
    //   { kind: 'wait' }                   — more cells expected, nothing to send
    //   null                                — terminal failure (caller closes link)
    const ingestCell = (cellBytes) => {

        if (state === HANDSHAKE_STATE_FAILED) return null;
        const parsed = parseCell(cellBytes);
        if (parsed === null) return fail('malformed cell');
        if (parsed.circuitId !== 0) return fail('link cell has non-zero circuit_id');

        if (parsed.command === CMD_LINK_HELLO) {

            if (peerHello !== null) return fail('duplicate LINK_HELLO');
            const hello = parseLinkHelloPayload(parsed.payload);
            if (hello === null) return fail('malformed LINK_HELLO');
            if (hello.version !== LINK_PROTOCOL_VERSION) return fail('version mismatch');
            if (expectedPeerIdPk !== null) {

                if (!constantTimeEqual(hello.idPk, expectedPeerIdPk)) {

                    return fail('peer idPk does not match expected');

                }

            }
            peerHello = hello;
            // Build our LINK_AUTH and send it.
            const authPayload = buildLinkAuthPayload({
                idSk: identity.idSk,
                idPk: identity.idPk,
                myNonce,
                peerNonce: hello.nonce,
                peerIdPk: hello.idPk,
            });
            const authCell = buildCell({
                circuitId: 0,
                command: CMD_LINK_AUTH,
                payload: authPayload,
            });
            myAuthSent = true;
            state = HANDSHAKE_STATE_AWAITING_AUTH;
            return { kind: 'send', cell: authCell };

        }

        if (parsed.command === CMD_LINK_AUTH) {

            if (peerHello === null) return fail('LINK_AUTH before LINK_HELLO');
            if (!myAuthSent) return fail('peer sent AUTH before we did');
            const signature = parsed.payload.subarray(0, LEN_LINK_AUTH_PAYLOAD);
            const ok = verifyLinkAuthSignature({
                signature,
                peerIdPk: peerHello.idPk,
                peerNonce: peerHello.nonce,
                myIdPk: identity.idPk,
                myNonce,
            });
            if (!ok) return fail('LINK_AUTH signature did not verify');
            state = HANDSHAKE_STATE_ESTABLISHED;
            return { kind: 'established', peerIdPk: peerHello.idPk };

        }

        // Any other cell before handshake completes is a protocol error.
        return fail(`unexpected cell command 0x${parsed.command.toString(16)} during handshake`);

    };

    return {
        buildHelloCell,
        ingestCell,
        getState: () => state,
        getPeerIdPk: () => peerHello ? new Uint8Array(peerHello.idPk) : null,
        getFailureReason: () => failureReason,

    };

};
