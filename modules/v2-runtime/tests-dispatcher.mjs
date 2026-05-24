// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE

import { expect } from 'chai';

import { createNodeIdentity } from './persistence.mjs';
import {
    createLinkListener,
    dialLink,
} from './link_transport_ws.mjs';
import { generateSelfSignedCert } from './self_signed_cert.mjs';
import { createLinkManager } from './link_manager.mjs';
import { createCircuitDispatcher } from './circuit_dispatcher.mjs';

import {
    CMD_DESTROY,
    LEN_CELL_PAYLOAD,
    buildCell,
    parseCell,
} from '../v2/cells.mjs';
import {
    beginCreate,
    createHandshakeReassembler,
    finishCreate,
} from '../v2/circuit.mjs';

// Self-signed cert for link-transport TLS (SPEC § 11.1). One per file —
// the cert isn't load-bearing for identity (LINK_AUTH does that), so
// reusing across tests in this file is intentional + faster than a
// per-test openssl spawn (~70ms saved x N tests).
const { certPem: __linkCertPem, keyPem: __linkKeyPem } = generateSelfSignedCert();


// ----- 1-hop circuit: dialing client builds a real CREATE through the dispatcher -----

describe('v2-runtime/circuit_dispatcher — 1-hop CREATE/CREATED end-to-end via real WebSocket', function () {

    this.timeout(15000);

    it('client → relay: CREATE multi-cell, relay derives matching session keys, sends CREATED', async () => {

        const relayIdentity = createNodeIdentity();
        const clientIdentity = createNodeIdentity();

        // Set up the relay side: listener + LinkManager + dispatcher.
        const linkMgr = createLinkManager({
            identity: relayIdentity,
            onCell: (link, cell) => dispatcher.onCell(link, cell),
        });
        const dispatcher = createCircuitDispatcher({
            identity: relayIdentity,
            linkManager: linkMgr,
        });

        const listener = await createLinkListener({
            tlsCert: __linkCertPem, tlsKey: __linkKeyPem,
            port: 0, host: '127.0.0.1', identity: relayIdentity,
            onLink: (link) => linkMgr.acceptLink(link),
        });

        try {

            // Client dials.
            const { transport } = await dialLink({
                host: '127.0.0.1', port: listener.port,
                identity: clientIdentity,
                expectedPeerIdPk: relayIdentity.idPk,
            });

            // Client side multi-cell CREATE.
            const begin = beginCreate({ circuitId: 17 });
            const reassembler = createHandshakeReassembler();
            const receivedCells = [];
            let clientResult = null;

            transport.onCell((cell) => {

                receivedCells.push(cell);
                if (clientResult && clientResult.complete) return;
                const r = finishCreate({
                    cell, ntorState: begin.ntorState,
                    B_pk: relayIdentity.B_pk, ID_R: relayIdentity.fingerprint,
                    reassembler,
                });
                if (r === null) throw new Error('finishCreate returned null');
                if (r.complete) clientResult = r;

            });

            for (const cell of begin.cells) transport.sendCell(cell);

            // Wait for the CREATED reassembly to complete.
            const deadline = Date.now() + 5000;
            while (!clientResult && Date.now() < deadline) {

                await new Promise((r) => setTimeout(r, 20));

            }
            expect(clientResult).to.not.equal(null);
            expect(clientResult.complete).to.equal(true);
            expect(clientResult.hopKeys.Kf.length).to.equal(32);
            expect(clientResult.hopKeys.Kb.length).to.equal(32);

            // Relay must now have exactly one established circuit.
            expect(dispatcher.getCircuitCount()).to.equal(1);
            const circuit = [...dispatcher._circuits.values()][0];
            expect(circuit.role).to.equal('established');

            // Keys derived on both sides must match.
            expect(Buffer.from(circuit.relayHop.Kf).equals(Buffer.from(clientResult.hopKeys.Kf))).to.equal(true);
            expect(Buffer.from(circuit.relayHop.Kb).equals(Buffer.from(clientResult.hopKeys.Kb))).to.equal(true);
            expect(Buffer.from(circuit.relayHop.Kdf).equals(Buffer.from(clientResult.hopKeys.Kdf))).to.equal(true);
            expect(Buffer.from(circuit.relayHop.Kdb).equals(Buffer.from(clientResult.hopKeys.Kdb))).to.equal(true);

            // Expected 3 CREATED fragments (CREATED_MSG_BYTES=1152 / 500 = ceil(1152/500) = 3).
            expect(receivedCells.length).to.equal(3);

            transport.close();

        } finally {

            dispatcher.closeAll();
            linkMgr.closeAll();
            await listener.close();

        }

    });

});

// ----- DESTROY tears down circuit state -----

describe('v2-runtime/circuit_dispatcher — DESTROY teardown', function () {

    this.timeout(15000);

    it('client sends DESTROY → relay clears circuit state, peer link still alive', async () => {

        const relayIdentity = createNodeIdentity();
        const clientIdentity = createNodeIdentity();

        const linkMgr = createLinkManager({
            identity: relayIdentity,
            onCell: (link, cell) => dispatcher.onCell(link, cell),
        });
        const dispatcher = createCircuitDispatcher({
            identity: relayIdentity, linkManager: linkMgr,
        });

        const listener = await createLinkListener({
            tlsCert: __linkCertPem, tlsKey: __linkKeyPem,
            port: 0, host: '127.0.0.1', identity: relayIdentity,
            onLink: (link) => linkMgr.acceptLink(link),
        });

        try {

            const { transport } = await dialLink({
                host: '127.0.0.1', port: listener.port,
                identity: clientIdentity,
                expectedPeerIdPk: relayIdentity.idPk,
            });

            // Complete a 1-hop handshake first.
            const begin = beginCreate({ circuitId: 42 });
            const reassembler = createHandshakeReassembler();
            let done = false;
            transport.onCell((cell) => {

                const r = finishCreate({
                    cell, ntorState: begin.ntorState,
                    B_pk: relayIdentity.B_pk, ID_R: relayIdentity.fingerprint,
                    reassembler,
                });
                if (r && r.complete) done = true;

            });
            for (const cell of begin.cells) transport.sendCell(cell);

            const deadline = Date.now() + 3000;
            while (!done && Date.now() < deadline) {

                await new Promise((r) => setTimeout(r, 20));

            }
            expect(done).to.equal(true);
            expect(dispatcher.getCircuitCount()).to.equal(1);

            // Now send DESTROY.
            transport.sendCell(buildCell({
                circuitId: 42, command: CMD_DESTROY,
                payload: new Uint8Array(LEN_CELL_PAYLOAD),
            }));
            await new Promise((r) => setTimeout(r, 100));

            expect(dispatcher.getCircuitCount()).to.equal(0);

            // The link should still be alive (DESTROY tears down the
            // circuit, not the underlying link).
            expect(linkMgr.getLinkCount()).to.equal(1);

            transport.close();

        } finally {

            dispatcher.closeAll();
            linkMgr.closeAll();
            await listener.close();

        }

    });

});

// ----- Hardening: malformed CREATE rejection, RELAY-before-CREATE rejection -----

describe('v2-runtime/circuit_dispatcher — defensive rejection', function () {

    this.timeout(10000);

    it('drops RELAY cells on a circuit that has not completed CREATE', async () => {

        const relayIdentity = createNodeIdentity();
        const clientIdentity = createNodeIdentity();

        const linkMgr = createLinkManager({
            identity: relayIdentity,
            onCell: (link, cell) => dispatcher.onCell(link, cell),
        });
        const dispatcher = createCircuitDispatcher({
            identity: relayIdentity, linkManager: linkMgr,
        });

        const listener = await createLinkListener({
            tlsCert: __linkCertPem, tlsKey: __linkKeyPem,
            port: 0, host: '127.0.0.1', identity: relayIdentity,
            onLink: (link) => linkMgr.acceptLink(link),
        });

        try {

            const { transport } = await dialLink({
                host: '127.0.0.1', port: listener.port,
                identity: clientIdentity,
                expectedPeerIdPk: relayIdentity.idPk,
            });

            // Send a RELAY cell on a circuit that doesn't exist yet.
            // No CREATE was sent first. The dispatcher should silently
            // drop (no circuit to dispatch to).
            const stray = buildCell({
                circuitId: 99, command: 0x03 /* CMD_RELAY */,
                payload: new Uint8Array(LEN_CELL_PAYLOAD).fill(0xAB),
            });
            transport.sendCell(stray);
            await new Promise((r) => setTimeout(r, 100));

            // No circuit was created.
            expect(dispatcher.getCircuitCount()).to.equal(0);
            // Link still up.
            expect(linkMgr.getLinkCount()).to.equal(1);

            transport.close();

        } finally {

            dispatcher.closeAll();
            linkMgr.closeAll();
            await listener.close();

        }

    });

    it('closeAll destroys all circuits cleanly', async () => {

        const relayIdentity = createNodeIdentity();
        const clientIdentity = createNodeIdentity();

        const linkMgr = createLinkManager({
            identity: relayIdentity,
            onCell: (link, cell) => dispatcher.onCell(link, cell),
        });
        const dispatcher = createCircuitDispatcher({
            identity: relayIdentity, linkManager: linkMgr,
        });

        const listener = await createLinkListener({
            tlsCert: __linkCertPem, tlsKey: __linkKeyPem,
            port: 0, host: '127.0.0.1', identity: relayIdentity,
            onLink: (link) => linkMgr.acceptLink(link),
        });

        try {

            const { transport } = await dialLink({
                host: '127.0.0.1', port: listener.port,
                identity: clientIdentity,
                expectedPeerIdPk: relayIdentity.idPk,
            });

            // Build two circuits.
            for (const cid of [101, 102]) {

                const begin = beginCreate({ circuitId: cid });
                const reassembler = createHandshakeReassembler();
                let done = false;
                const handler = (cell) => {

                    const r = finishCreate({
                        cell, ntorState: begin.ntorState,
                        B_pk: relayIdentity.B_pk, ID_R: relayIdentity.fingerprint,
                        reassembler,
                    });
                    if (r && r.complete) done = true;

                };
                transport.onCell(handler);
                for (const cell of begin.cells) transport.sendCell(cell);
                const deadline = Date.now() + 3000;
                while (!done && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));

            }
            expect(dispatcher.getCircuitCount()).to.equal(2);

            dispatcher.closeAll();
            expect(dispatcher.getCircuitCount()).to.equal(0);

            transport.close();

        } finally {

            linkMgr.closeAll();
            await listener.close();

        }

    });

});
