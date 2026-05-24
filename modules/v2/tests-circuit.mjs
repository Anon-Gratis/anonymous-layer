// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

import { expect } from 'chai';

import {
    LEN_CELL_PAYLOAD,
    CMD_CREATE,
    CMD_CREATED,
    CMD_RELAY,
    parseCell,
} from './cells.mjs';
import {
    CREATE_MSG_BYTES,
    CREATED_MSG_BYTES,
    EXTEND_PAYLOAD_BYTES,
    createClientCircuit,
    createRelayHop,
    addHop,
    beginCreate,
    handleCreate,
    finishCreate,
    createHandshakeReassembler,
    beginExtend,
    handleRelayAtHop,
    buildExtendedRelayCells,
    finishExtend,
    dispatchInboundRelay,
    encryptOutbound,
    decryptInbound,
    relayPeelForward,
    relayWrapBackward,
} from './circuit.mjs';
import { relayResponse, deriveHopKeys } from './ntor_hybrid.mjs';
import { generateOnion } from '../crypto/onion.mjs';
import { generateIdentity, identityFingerprint } from '../crypto/identity.mjs';
import { RELAY_DATA, buildRelayPayload, STREAM_ID_CIRCUIT } from './relay.mjs';

const makeRelay = () => {

    const id = generateIdentity();
    const onion = generateOnion();
    return {
        ID_R: identityFingerprint(id.idPk),
        B_sk: onion.onionSk,
        B_pk: onion.onionPk,
    };

};

// ----- Helper: run a complete CREATE/CREATED exchange in-memory.
//
// Returns { hopKeys, relayHop } after walking the 3-cell CREATE and
// 3-cell CREATED fragments through the stateful handlers. Used by the
// multi-hop layered-encryption tests to set up circuits without going
// through the more complex EXTEND flow.
const runCreateExchange = ({ relay, circuitId }) => {

    const begin = beginCreate({ circuitId });

    const relayReassembler = createHandshakeReassembler();
    let relayResult = null;
    for (const cell of begin.cells) {

        relayResult = handleCreate({
            cell,
            B_sk: relay.B_sk,
            B_pk: relay.B_pk,
            ID_R: relay.ID_R,
            reassembler: relayReassembler,
        });
        if (relayResult === null) throw new Error('handleCreate returned null');

    }
    if (!relayResult.complete) throw new Error('handleCreate never completed');

    const clientReassembler = createHandshakeReassembler();
    let clientResult = null;
    for (const cell of relayResult.createdCells) {

        clientResult = finishCreate({
            cell,
            ntorState: begin.ntorState,
            B_pk: relay.B_pk,
            ID_R: relay.ID_R,
            reassembler: clientReassembler,
        });
        if (clientResult === null) throw new Error('finishCreate returned null');

    }
    if (!clientResult.complete) throw new Error('finishCreate never completed');

    return { hopKeys: clientResult.hopKeys, relayHop: relayResult.relayHop };

};

// ----- Multi-cell CREATE / CREATED handshake -----

describe('v2/circuit — multi-cell hybrid CREATE/CREATED', () => {

    it('beginCreate produces exactly 3 CMD_CREATE cells', () => {

        const begin = beginCreate({ circuitId: 1 });
        expect(begin.cells.length).to.equal(3);
        for (const cell of begin.cells) {

            const parsed = parseCell(cell);
            expect(parsed.command).to.equal(CMD_CREATE);
            expect(parsed.circuitId).to.equal(1);

        }

    });

    it('client and relay derive matching keys through the multi-cell flow', () => {

        const relay = makeRelay();
        const { hopKeys, relayHop } = runCreateExchange({ relay, circuitId: 42 });

        expect(Buffer.from(hopKeys.Kf).equals(Buffer.from(relayHop.Kf))).to.equal(true);
        expect(Buffer.from(hopKeys.Kb).equals(Buffer.from(relayHop.Kb))).to.equal(true);
        expect(Buffer.from(hopKeys.Kdf).equals(Buffer.from(relayHop.Kdf))).to.equal(true);
        expect(Buffer.from(hopKeys.Kdb).equals(Buffer.from(relayHop.Kdb))).to.equal(true);
        expect(relayHop.inboundCircuitId).to.equal(42);

    });

    it('handleCreate returns {complete:false} after 1 of 3 cells, complete after the 3rd', () => {

        const relay = makeRelay();
        const begin = beginCreate({ circuitId: 1 });
        const reassembler = createHandshakeReassembler();

        const r1 = handleCreate({
            cell: begin.cells[0],
            B_sk: relay.B_sk, B_pk: relay.B_pk, ID_R: relay.ID_R, reassembler,
        });
        expect(r1.complete).to.equal(false);

        const r2 = handleCreate({
            cell: begin.cells[1],
            B_sk: relay.B_sk, B_pk: relay.B_pk, ID_R: relay.ID_R, reassembler,
        });
        expect(r2.complete).to.equal(false);

        const r3 = handleCreate({
            cell: begin.cells[2],
            B_sk: relay.B_sk, B_pk: relay.B_pk, ID_R: relay.ID_R, reassembler,
        });
        expect(r3.complete).to.equal(true);
        expect(r3.createdCells.length).to.equal(3);

    });

    it('handleCreate accepts CREATE fragments out of order', () => {

        const relay = makeRelay();
        const begin = beginCreate({ circuitId: 1 });
        const reassembler = createHandshakeReassembler();
        // Shuffled: 2, 0, 1.
        handleCreate({ cell: begin.cells[2], B_sk: relay.B_sk, B_pk: relay.B_pk, ID_R: relay.ID_R, reassembler });
        handleCreate({ cell: begin.cells[0], B_sk: relay.B_sk, B_pk: relay.B_pk, ID_R: relay.ID_R, reassembler });
        const r = handleCreate({ cell: begin.cells[1], B_sk: relay.B_sk, B_pk: relay.B_pk, ID_R: relay.ID_R, reassembler });
        expect(r.complete).to.equal(true);

    });

    it('handleCreate rejects a CMD_CREATED cell at the create reassembler', () => {

        const relay = makeRelay();
        const begin = beginCreate({ circuitId: 1 });
        const reassembler = createHandshakeReassembler();
        const r = handleCreate({
            cell: begin.cells[0],
            B_sk: relay.B_sk, B_pk: relay.B_pk, ID_R: relay.ID_R, reassembler,
        });
        expect(r.complete).to.equal(false);
        // Now feed a CMD_CREATED instead of CMD_CREATE — must reject without crashing.
        const fakeCreated = new Uint8Array(514);
        fakeCreated[0] = 0x02; // version
        fakeCreated[5] = CMD_CREATED;
        const r2 = handleCreate({
            cell: fakeCreated,
            B_sk: relay.B_sk, B_pk: relay.B_pk, ID_R: relay.ID_R, reassembler,
        });
        expect(r2).to.equal(null);

    });

    it('finishCreate rejects when the relay impersonates a different identity', () => {

        const realRelay = makeRelay();
        const impostor = makeRelay();
        const begin = beginCreate({ circuitId: 1 });
        const relayReassembler = createHandshakeReassembler();
        let relayResult;
        for (const c of begin.cells) {

            relayResult = handleCreate({
                cell: c, B_sk: realRelay.B_sk, B_pk: realRelay.B_pk, ID_R: realRelay.ID_R, reassembler: relayReassembler,
            });

        }
        // Client believes it's talking to `impostor` — AUTH must fail.
        const clientReassembler = createHandshakeReassembler();
        let clientResult;
        for (const c of relayResult.createdCells) {

            clientResult = finishCreate({
                cell: c, ntorState: begin.ntorState, B_pk: impostor.B_pk, ID_R: realRelay.ID_R, reassembler: clientReassembler,
            });
            // The last call (when reassembly completes and AUTH check runs) returns null.
            if (clientResult === null) return; // expected failure

        }
        throw new Error('clientFinish should have rejected impostor');

    });

});

// ----- Layered encryption with the per-hop counter + digest state -----

describe('v2/circuit — layered encryption', () => {

    const makeThreeHopCircuit = () => {

        const relays = [makeRelay(), makeRelay(), makeRelay()];
        const circuit = createClientCircuit({ circuitId: 99 });
        const relayHops = [];
        for (const relay of relays) {

            const { hopKeys, relayHop } = runCreateExchange({ relay, circuitId: 99 });
            addHop(circuit, hopKeys);
            relayHops.push(relayHop);

        }
        return { circuit, relayHops };

    };

    it('forward: 3 hops peel cleanly back to the original plaintext', () => {

        const { circuit, relayHops } = makeThreeHopCircuit();
        const plaintext = new Uint8Array(LEN_CELL_PAYLOAD);
        for (let i = 0; i < plaintext.length; i += 1) plaintext[i] = (i * 31 + 7) & 0xFF;

        const ciphertext = encryptOutbound(circuit, plaintext);
        let inFlight = relayPeelForward(relayHops[0], ciphertext);
        inFlight = relayPeelForward(relayHops[1], inFlight);
        const finalPlaintext = relayPeelForward(relayHops[2], inFlight);
        expect(Buffer.from(finalPlaintext).equals(Buffer.from(plaintext))).to.equal(true);

    });

    it('backward: exit wraps a reply, each hop adds a layer, client peels all', () => {

        const { circuit, relayHops } = makeThreeHopCircuit();
        const reply = new Uint8Array(LEN_CELL_PAYLOAD);
        for (let i = 0; i < reply.length; i += 1) reply[i] = (i * 17 + 5) & 0xFF;

        let inFlight = relayWrapBackward(relayHops[2], reply);
        inFlight = relayWrapBackward(relayHops[1], inFlight);
        inFlight = relayWrapBackward(relayHops[0], inFlight);
        const peeled = decryptInbound(circuit, inFlight);
        expect(Buffer.from(peeled).equals(Buffer.from(reply))).to.equal(true);

    });

    it('counters advance: subsequent forward cells use different ciphertexts', () => {

        const { circuit, relayHops } = makeThreeHopCircuit();
        const plaintext = new Uint8Array(LEN_CELL_PAYLOAD).fill(0xC9);

        const c1 = encryptOutbound(circuit, plaintext);
        const c2 = encryptOutbound(circuit, plaintext);
        expect(Buffer.from(c1).equals(Buffer.from(c2))).to.equal(false);

        // Both still decrypt at the exit (counters advance in lockstep).
        let p1 = relayPeelForward(relayHops[0], c1);
        p1 = relayPeelForward(relayHops[1], p1);
        p1 = relayPeelForward(relayHops[2], p1);
        expect(Buffer.from(p1).equals(Buffer.from(plaintext))).to.equal(true);
        let p2 = relayPeelForward(relayHops[0], c2);
        p2 = relayPeelForward(relayHops[1], p2);
        p2 = relayPeelForward(relayHops[2], p2);
        expect(Buffer.from(p2).equals(Buffer.from(plaintext))).to.equal(true);

    });

});

// ----- Multi-cell RELAY_EXTEND / RELAY_EXTENDED end-to-end -----

describe('v2/circuit — RELAY_EXTEND end-to-end (hybrid, multi-cell)', () => {

    it('client → entry (1 CREATE) → middle (1 RELAY_EXTEND) → exit (1 RELAY_EXTEND) end-to-end', function () {

        this.timeout(15000);

        const relays = [makeRelay(), makeRelay(), makeRelay()];
        const circuit = createClientCircuit({ circuitId: 7 });

        // --- Phase 1: hop 0 via direct CREATE/CREATED ---
        const { hopKeys: hop0Keys, relayHop: relayHop0 } = runCreateExchange({
            relay: relays[0], circuitId: 7,
        });
        addHop(circuit, hop0Keys);

        // --- Phase 2: hop 1 via RELAY_EXTEND through 1-hop circuit ---
        const ext1 = beginExtend({
            circuit,
            nextHopFingerprint: relays[1].ID_R,
            nextHopBpk: relays[1].B_pk,
        });
        // 1280-byte EXTEND payload at 491 bytes/fragment → 3 fragments → 3 RELAY cells.
        expect(ext1.cells.length).to.equal(3);

        // Hop 0 receives each of the 3 cells. After the third, it has
        // the complete EXTEND payload.
        let ext1Result;
        for (const cell of ext1.cells) {

            const parsed = parseCell(cell);
            ext1Result = handleRelayAtHop({
                relayHop: relayHop0,
                cellPayload: parsed.payload,
            });
            if (ext1Result === null) throw new Error('handleRelayAtHop returned null');

        }
        expect(ext1Result.kind).to.equal('extend');
        expect(Buffer.from(ext1Result.payload.nextHopFingerprint).equals(Buffer.from(relays[1].ID_R))).to.equal(true);

        // Hop 0 now runs CREATE against hop 1 (over a fresh link the
        // test doesn't actually model — we call relayResponse directly).
        const r1Response = relayResponse({
            createMsg: ext1Result.payload.handshakeMessage,
            B_sk: relays[1].B_sk,
            B_pk: relays[1].B_pk,
            ID_R: relays[1].ID_R,
        });
        expect(r1Response).to.not.equal(null);

        // Hop 0 builds RELAY_EXTENDED cells back to the client. 3
        // fragments because 1152-byte CREATED at 491 bytes/fragment.
        const extended1Cells = buildExtendedRelayCells({
            relayHop: relayHop0,
            handshakeResponse: r1Response.createdMsg,
        });
        expect(extended1Cells.length).to.equal(3);

        // Client receives. Each cell goes through decryptInbound (1
        // hop's backward layer) then dispatchInboundRelay.
        let ext1Done;
        for (const wrapped of extended1Cells) {

            const peeled = decryptInbound(circuit, wrapped);
            const d = dispatchInboundRelay({ circuit, peeledPayload: peeled });
            if (d === null) throw new Error('dispatch returned null');
            if (d.kind === 'extended') { ext1Done = d; break; }
            // else 'extend-fragment' — continue

        }
        expect(ext1Done).to.not.equal(undefined);
        expect(ext1Done.hopIndex).to.equal(0);
        expect(ext1Done.handshakeResponse.length).to.equal(CREATED_MSG_BYTES);

        const hop1Keys = finishExtend({
            handshakeResponse: ext1Done.handshakeResponse,
            ntorState: ext1.ntorState,
            nextHopBpk: relays[1].B_pk,
            nextHopFingerprint: relays[1].ID_R,
        });
        expect(hop1Keys).to.not.equal(null);
        addHop(circuit, hop1Keys);

        // Construct the relay-side hop1 state we'll need below for the
        // forward path. The relay's hopKeys come from the same KEY_SEED.
        const relayHop1 = createRelayHop({
            inboundCircuitId: 99, // placeholder — the test doesn't model the hop0↔hop1 link's circuit ID
            hopKeys: deriveHopKeys(r1Response.KEY_SEED),
        });

        // --- Phase 3: hop 2 via RELAY_EXTEND through 2-hop circuit ---
        const ext2 = beginExtend({
            circuit,
            nextHopFingerprint: relays[2].ID_R,
            nextHopBpk: relays[2].B_pk,
        });
        expect(ext2.cells.length).to.equal(3);

        // Each cell: hop 0 forwards (digest doesn't match — it's for hop 1).
        // Hop 1 reassembles.
        let ext2Result;
        for (const cell of ext2.cells) {

            const parsed = parseCell(cell);
            const r0 = handleRelayAtHop({
                relayHop: relayHop0,
                cellPayload: parsed.payload,
            });
            expect(r0.kind).to.equal('forward');
            const r1 = handleRelayAtHop({
                relayHop: relayHop1,
                cellPayload: r0.payload,
            });
            if (r1 === null) throw new Error('hop 1 returned null');
            ext2Result = r1;

        }
        expect(ext2Result.kind).to.equal('extend');

        // Hop 1 runs CREATE against hop 2.
        const r2Response = relayResponse({
            createMsg: ext2Result.payload.handshakeMessage,
            B_sk: relays[2].B_sk,
            B_pk: relays[2].B_pk,
            ID_R: relays[2].ID_R,
        });
        const relayHop2 = createRelayHop({
            inboundCircuitId: 200,
            hopKeys: deriveHopKeys(r2Response.KEY_SEED),
        });

        // Hop 1 builds RELAY_EXTENDED cells. Hop 0 wraps each in its
        // backward layer.
        const extended2HopCells = buildExtendedRelayCells({
            relayHop: relayHop1,
            handshakeResponse: r2Response.createdMsg,
        });
        const extended2Cells = extended2HopCells.map(
            (c) => relayWrapBackward(relayHop0, c),
        );

        // Client receives 3 cells. After the third, dispatchInboundRelay
        // returns kind: 'extended' from hop index 1.
        let ext2Done;
        for (const wrapped of extended2Cells) {

            const peeled = decryptInbound(circuit, wrapped);
            const d = dispatchInboundRelay({ circuit, peeledPayload: peeled });
            if (d === null) throw new Error('dispatch returned null on EXTEND2');
            if (d.kind === 'extended') { ext2Done = d; break; }

        }
        expect(ext2Done).to.not.equal(undefined);
        expect(ext2Done.hopIndex).to.equal(1);

        const hop2Keys = finishExtend({
            handshakeResponse: ext2Done.handshakeResponse,
            ntorState: ext2.ntorState,
            nextHopBpk: relays[2].B_pk,
            nextHopFingerprint: relays[2].ID_R,
        });
        expect(hop2Keys).to.not.equal(null);
        addHop(circuit, hop2Keys);

        // --- Phase 4: send a RELAY_DATA to hop 2 (exit) ---
        const message = new TextEncoder().encode('hello exit, this is the 3-hop hybrid-ntor client');
        const dataRelay = buildRelayPayload({
            relayCommand: RELAY_DATA,
            streamId: 17,
            data: message,
            digestState: circuit.hops[2].forwardDigest,
        });
        const dataOuter = encryptOutbound(circuit, dataRelay);

        const f0 = handleRelayAtHop({ relayHop: relayHop0, cellPayload: dataOuter });
        expect(f0.kind).to.equal('forward');
        const f1 = handleRelayAtHop({ relayHop: relayHop1, cellPayload: f0.payload });
        expect(f1.kind).to.equal('forward');
        const f2 = handleRelayAtHop({ relayHop: relayHop2, cellPayload: f1.payload });
        expect(f2.kind).to.equal('data');
        expect(f2.relayCommand).to.equal(RELAY_DATA);
        expect(f2.streamId).to.equal(17);
        expect(new TextDecoder().decode(f2.data)).to.equal(
            'hello exit, this is the 3-hop hybrid-ntor client',
        );

    });

});
