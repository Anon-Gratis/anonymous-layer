// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE

import { expect } from 'chai';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createNodeIdentity } from './persistence.mjs';
import {
    createLinkListener,
} from './link_transport_ws.mjs';
import { generateSelfSignedCert } from './self_signed_cert.mjs';
import { createLinkManager } from './link_manager.mjs';
import { createCircuitDispatcher } from './circuit_dispatcher.mjs';
import { createCellRouter } from './cell_router.mjs';
import { createPeerResolver } from './peer_resolver.mjs';
import { createCircuitBuilder } from './circuit_builder.mjs';
import { loadDaTrustSet, loadConsensus } from './consensus_loader.mjs';

import {
    FLAG_GUARD,
    FLAG_RUNNING,
    FLAG_VALID,
    FLAG_EXIT,
    buildConsensus,
    pickPath,
} from '../v2/consensus.mjs';
import {
    ACTION_ACCEPT,
    makeAnyRule,
    buildPolicy,
    POLICY_REJECT_ALL,
} from '../v2/exit_policy.mjs';
import { generateIdentity, identityFingerprint } from '../crypto/identity.mjs';

// Self-signed cert for link-transport TLS (SPEC § 11.1). One per file —
// the cert isn't load-bearing for identity (LINK_AUTH does that), so
// reusing across tests in this file is intentional + faster than a
// per-test openssl spawn (~70ms saved x N tests).
const { certPem: __linkCertPem, keyPem: __linkKeyPem } = generateSelfSignedCert();


// ----- consensus_loader -----

describe('v2-runtime/consensus_loader', () => {

    let dir;

    beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), 'anon-cl-')); });
    afterEach(async () => { if (dir) await rm(dir, { recursive: true, force: true }); });

    it('loadDaTrustSet parses a JSON map of fingerprint → idPk', async () => {

        const fp = '11'.repeat(32);
        const pk = '22'.repeat(32);
        const path = join(dir, 'das.json');
        await writeFile(path, JSON.stringify({ [fp]: pk }));
        const set = await loadDaTrustSet(path);
        expect(set.size).to.equal(1);
        expect(Buffer.from(set.get(fp)).toString('hex')).to.equal(pk);

    });

    it('loadDaTrustSet rejects malformed JSON', async () => {

        const path = join(dir, 'das.json');
        await writeFile(path, 'not json');
        let threw = false;
        try { await loadDaTrustSet(path); }
        catch (err) { threw = /not valid JSON/.test(err.message); }
        expect(threw).to.equal(true);

    });

    it('loadDaTrustSet rejects bad-shape entries', async () => {

        const path = join(dir, 'das.json');
        await writeFile(path, JSON.stringify({ 'not-hex': 'something' }));
        let threw = false;
        try { await loadDaTrustSet(path); }
        catch (err) { threw = /fingerprint hex/.test(err.message); }
        expect(threw).to.equal(true);

    });

    it('loadConsensus parses a real consensus file', async () => {

        // Build a tiny consensus.
        const da = (() => {

            const id = generateIdentity();
            return {
                idPk: id.idPk, idSk: id.idSk,
                fingerprint: identityFingerprint(id.idPk),
            };

        })();
        const consensus = buildConsensus({
            validAfter: 1_000_000,
            freshUntil: 2_000_000,
            validUntil: 3_000_000,
            rses: [],
            daSigners: [da],
        });
        const cPath = join(dir, 'consensus.bin');
        await writeFile(cPath, consensus);
        const daTrust = new Map([
            [Buffer.from(da.fingerprint).toString('hex'), da.idPk],
        ]);
        const parsed = await loadConsensus({
            path: cPath, daTrustSet: daTrust, nowSeconds: 1_500_000,
        });
        expect(parsed.validAfter).to.equal(1_000_000);

    });

});

// ----- 3-hop end-to-end via real WebSockets -----

describe('v2-runtime/circuit_builder — 3-hop circuit via 3 in-process relays', function () {

    this.timeout(30000);

    // Spin up an in-process relay. `resolverHolder.fn` is set after
    // the consensus exists (which requires all relays' identities);
    // similarly `routerHolder.router` defers cellRouter creation until
    // after the dispatcher is built. The linkMgr's onCell closure
    // dereferences both holders at call time, which lets us wire all
    // three relays + the client circularly without "you-can't-do-that"
    // construction-order problems.
    const spinUpRelayClean = async () => {

        const identity = createNodeIdentity();
        // The peerResolver is set after the consensus is built (which
        // requires all relays' identities). We use a mutable holder.
        const resolverHolder = { fn: () => null };
        const peerResolver = (q) => resolverHolder.fn(q);

        // routerHolder lets us defer cellRouter creation until the
        // dispatcher is built and lets linkMgr's onCell call into it.
        const routerHolder = { router: null };

        const linkMgr = createLinkManager({
            identity,
            onCell: (link, cell) => {

                if (routerHolder.router) routerHolder.router.onCell(link, cell);

            },
        });
        const dispatcher = createCircuitDispatcher({
            identity, linkManager: linkMgr, peerResolver,
        });
        routerHolder.router = createCellRouter({ relayDispatcher: dispatcher });

        const listener = await createLinkListener({
            tlsCert: __linkCertPem, tlsKey: __linkKeyPem,
            port: 0, host: '127.0.0.1', identity,
            onLink: (link) => linkMgr.acceptLink(link),
        });

        return {
            identity,
            host: listener.address,
            port: listener.port,
            dispatcher,
            linkMgr,
            router: routerHolder.router,
            listener,
            resolverHolder,
            close: async () => {

                dispatcher.closeAll();
                linkMgr.closeAll();
                await listener.close();

            },
        };

    };

    it('client builds a real 3-hop circuit through 3 relays; all hops establish; keys match', async () => {

        // Spin up 3 relays.
        const r0 = await spinUpRelayClean();
        const r1 = await spinUpRelayClean();
        const r2 = await spinUpRelayClean();

        // Set up a client.
        const clientIdentity = createNodeIdentity();
        const clientResolverHolder = { fn: () => null };
        const clientRouterHolder = { router: null };
        const clientLinkMgr = createLinkManager({
            identity: clientIdentity,
            onCell: (link, cell) => {

                if (clientRouterHolder.router) clientRouterHolder.router.onCell(link, cell);

            },
        });
        // The client has its own "relay-side" dispatcher (it shouldn't
        // receive CREATEs but the router still needs one).
        const clientRelayDispatcher = createCircuitDispatcher({
            identity: clientIdentity, linkManager: clientLinkMgr,
            peerResolver: (q) => clientResolverHolder.fn(q),
        });
        clientRouterHolder.router = createCellRouter({ relayDispatcher: clientRelayDispatcher });

        try {

            // Build a consensus naming all 3 relays.
            const da = (() => {

                const id = generateIdentity();
                return {
                    idPk: id.idPk, idSk: id.idSk,
                    fingerprint: identityFingerprint(id.idPk),
                };

            })();
            const now = Math.floor(Date.now() / 1000);

            const ipv4For = (port) => Uint8Array.from([127, 0, 0, 1, (port >> 8) & 0xFF, port & 0xFF]);

            const rses = [
                {
                    fingerprint: r0.identity.fingerprint,
                    idPk:        r0.identity.idPk,
                    onionPk:     r0.identity.B_pk,
                    ipv4:        ipv4For(r0.port),
                    ipv6:        null,
                    flags:       FLAG_RUNNING | FLAG_VALID | FLAG_GUARD,
                    exitPolicyBytes: buildPolicy(POLICY_REJECT_ALL),
                },
                {
                    fingerprint: r1.identity.fingerprint,
                    idPk:        r1.identity.idPk,
                    onionPk:     r1.identity.B_pk,
                    ipv4:        ipv4For(r1.port),
                    ipv6:        null,
                    flags:       FLAG_RUNNING | FLAG_VALID,
                    exitPolicyBytes: buildPolicy(POLICY_REJECT_ALL),
                },
                {
                    fingerprint: r2.identity.fingerprint,
                    idPk:        r2.identity.idPk,
                    onionPk:     r2.identity.B_pk,
                    ipv4:        ipv4For(r2.port),
                    ipv6:        null,
                    flags:       FLAG_RUNNING | FLAG_VALID | FLAG_EXIT,
                    exitPolicyBytes: buildPolicy([
                        makeAnyRule({ action: ACTION_ACCEPT, portMin: 443, portMax: 443 }),
                    ]),
                },
            ];

            const consensusBytes = buildConsensus({
                validAfter: now - 60,
                freshUntil: now + 3600,
                validUntil: now + 7200,
                rses, daSigners: [da],
            });
            // Re-parse via the loader, exercising that path too.
            const consensusPath = join(await mkdtemp(join(tmpdir(), 'anon-c-')), 'consensus.bin');
            await writeFile(consensusPath, consensusBytes);
            const consensus = await loadConsensus({
                path: consensusPath,
                daTrustSet: new Map([
                    [Buffer.from(da.fingerprint).toString('hex'), da.idPk],
                ]),
                nowSeconds: now,
            });

            // Build the peerResolver for everyone (client + all 3 relays
            // share the same view).
            const peerResolver = createPeerResolver({ consensus });
            r0.resolverHolder.fn = peerResolver;
            r1.resolverHolder.fn = peerResolver;
            r2.resolverHolder.fn = peerResolver;
            clientResolverHolder.fn = peerResolver;

            // Pick a path through the consensus, then disable anti-co-
            // location for this test (all 3 relays share 127.0.0.1).
            // For testing we just manually use the order [r0, r1, r2].
            const guardRse = consensus.rses.find(
                (r) => Buffer.from(r.fingerprint).equals(Buffer.from(r0.identity.fingerprint)),
            );
            const middleRse = consensus.rses.find(
                (r) => Buffer.from(r.fingerprint).equals(Buffer.from(r1.identity.fingerprint)),
            );
            const exitRse = consensus.rses.find(
                (r) => Buffer.from(r.fingerprint).equals(Buffer.from(r2.identity.fingerprint)),
            );

            // Build the circuit.
            const builder = createCircuitBuilder({
                linkManager: clientLinkMgr,
                cellRouter: clientRouterHolder.router,
                peerResolver,
                logger: () => {},
            });
            const result = await builder.buildCircuit({
                path: { guard: guardRse, middle: middleRse, exit: exitRse },
            });

            // Assertions: 3 hops on the client side.
            expect(result.circuit.hops.length).to.equal(3);
            for (const hop of result.circuit.hops) {

                expect(hop.Kf.length).to.equal(32);
                expect(hop.Kb.length).to.equal(32);

            }

            // Relay 0 (entry guard) should have 1 established circuit
            // (the inbound side from us, extended outbound to r1).
            expect(r0.dispatcher.getCircuitCount()).to.be.at.least(1);
            // Relay 1 (middle): 1 circuit with inbound from r0, outbound to r2.
            expect(r1.dispatcher.getCircuitCount()).to.be.at.least(1);
            // Relay 2 (exit): 1 circuit with inbound from r1, no outbound.
            expect(r2.dispatcher.getCircuitCount()).to.be.at.least(1);

            // Verify hop keys match relay-side keys.
            const r0Circuit = [...r0.dispatcher._circuits.values()][0];
            expect(Buffer.from(result.circuit.hops[0].Kf).equals(Buffer.from(r0Circuit.relayHop.Kf))).to.equal(true);

        } finally {

            await r0.close();
            await r1.close();
            await r2.close();
            clientRelayDispatcher.closeAll();
            clientLinkMgr.closeAll();

        }

    });

});
