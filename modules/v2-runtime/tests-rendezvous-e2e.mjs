// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE

import { expect } from 'chai';
import { createServer } from 'node:net';

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import { createNodeIdentity } from './persistence.mjs';
import { createLinkListener } from './link_transport_ws.mjs';
import { generateSelfSignedCert } from './self_signed_cert.mjs';
import { createLinkManager } from './link_manager.mjs';
import { createCircuitDispatcher } from './circuit_dispatcher.mjs';
import { createCellRouter } from './cell_router.mjs';
import { createPeerResolver } from './peer_resolver.mjs';
import { createCircuitBuilder } from './circuit_builder.mjs';
import { createIpRole } from './ip_role.mjs';
import { createRpRole } from './rp_role.mjs';
import { createServicePublisher } from './service_publisher.mjs';
import { openHiddenService } from './rendezvous_client.mjs';

import {
    FLAG_GUARD, FLAG_RUNNING, FLAG_VALID, FLAG_EXIT,
    buildConsensus, parseConsensus,
} from '../v2/consensus.mjs';
import {
    ACTION_ACCEPT, makeAnyRule, buildPolicy, POLICY_REJECT_ALL,
} from '../v2/exit_policy.mjs';
import { generateIdentity, identityFingerprint } from '../crypto/identity.mjs';
import { generateOnion } from '../crypto/onion.mjs';
import { createServiceIdentity } from '../v2/service.mjs';
import { buildServiceDescriptor, parseServiceDescriptor } from '../v2/descriptor.mjs';

// Self-signed cert for link-transport TLS (SPEC § 11.1). One per file —
// the cert isn't load-bearing for identity (LINK_AUTH does that), so
// reusing across tests in this file is intentional + faster than a
// per-test openssl spawn (~70ms saved x N tests).
const { certPem: __linkCertPem, keyPem: __linkKeyPem } = generateSelfSignedCert();


// Spin up a relay that hosts the standard dispatcher + RP role + IP role.
const spinUpRelay = async () => {

    const identity = createNodeIdentity();
    const resolverHolder = { fn: () => null };
    const routerHolder = { router: null };
    const ipRole = createIpRole({ identity });
    const rpRole = createRpRole({});

    const linkMgr = createLinkManager({
        identity,
        onCell: (link, cell) => { if (routerHolder.router) routerHolder.router.onCell(link, cell); },
    });
    const dispatcher = createCircuitDispatcher({
        identity, linkManager: linkMgr,
        peerResolver: (q) => resolverHolder.fn(q),
        onExitData: (d) => {

            ipRole.handleData(d);
            rpRole.handleData(d);

        },
    });
    routerHolder.router = createCellRouter({ relayDispatcher: dispatcher });

    const listener = await createLinkListener({
            tlsCert: __linkCertPem, tlsKey: __linkKeyPem,
        port: 0, host: '127.0.0.1', identity,
        onLink: (link) => linkMgr.acceptLink(link),
    });
    return {
        identity, host: listener.address, port: listener.port,
        ipRole, rpRole, dispatcher, linkMgr, listener, resolverHolder,
        close: async () => {

            ipRole.clear();
            rpRole.clear();
            dispatcher.closeAll();
            linkMgr.closeAll();
            await listener.close();

        },
    };

};

const setupClientRuntime = async (clientIdentity) => {

    const resolverHolder = { fn: () => null };
    const routerHolder = { router: null };
    const linkMgr = createLinkManager({
        identity: clientIdentity,
        onCell: (link, cell) => { if (routerHolder.router) routerHolder.router.onCell(link, cell); },
    });
    const dispatcher = createCircuitDispatcher({
        identity: clientIdentity, linkManager: linkMgr,
        peerResolver: (q) => resolverHolder.fn(q),
    });
    routerHolder.router = createCellRouter({ relayDispatcher: dispatcher });
    const builder = createCircuitBuilder({
        linkManager: linkMgr,
        cellRouter: routerHolder.router,
        peerResolver: (q) => resolverHolder.fn(q),
    });
    return {
        linkMgr, dispatcher, router: routerHolder.router, builder, resolverHolder,
        close: () => {

            dispatcher.closeAll();
            linkMgr.closeAll();

        },
    };

};

const ipv4For = (port) => Uint8Array.from([127, 0, 0, 1, (port >> 8) & 0xFF, port & 0xFF]);

describe('v2-runtime — end-to-end hidden-service rendezvous', function () {

    this.timeout(60000);

    it('client opens a stream through the rendezvous splice; "hello" round-trips', async () => {

        // ---- 1. Local "service backend" (echo TCP server) ----
        const echo = await new Promise((res) => {

            const s = createServer({ allowHalfOpen: true }, (sock) => {

                sock.on('data', (d) => sock.write(d));
                sock.on('end', () => sock.end());

            });
            s.listen(0, '127.0.0.1', () => res(s));

        });
        const echoPort = echo.address().port;

        // ---- 2. Spin up 6 relays ----
        const relays = [];
        for (let i = 0; i < 6; i += 1) relays.push(await spinUpRelay());
        const [n0, n1, n2, n3, n4, n5] = relays;

        // ---- 3. Build the consensus (any relay can be RUNNING+VALID; flag exit on n2/n5) ----
        const da = (() => {

            const id = generateIdentity();
            return { idPk: id.idPk, idSk: id.idSk, fingerprint: identityFingerprint(id.idPk) };

        })();
        const now = Math.floor(Date.now() / 1000);
        const standardFlags = FLAG_RUNNING | FLAG_VALID;
        const rejectAll = buildPolicy(POLICY_REJECT_ALL);
        const acceptEcho = buildPolicy([
            makeAnyRule({ action: ACTION_ACCEPT, portMin: echoPort, portMax: echoPort }),
        ]);

        const rseFor = (relay, flags, exitPolicyBytes) => ({
            fingerprint: relay.identity.fingerprint,
            idPk: relay.identity.idPk,
            onionPk: relay.identity.B_pk,
            ipv4: ipv4For(relay.port), ipv6: null,
            flags, exitPolicyBytes,
        });

        const rses = [
            rseFor(n0, standardFlags | FLAG_GUARD, rejectAll),
            rseFor(n1, standardFlags, rejectAll),
            rseFor(n2, standardFlags | FLAG_EXIT, acceptEcho), // RP candidate
            rseFor(n3, standardFlags | FLAG_GUARD, rejectAll),
            rseFor(n4, standardFlags, rejectAll),
            rseFor(n5, standardFlags | FLAG_EXIT, rejectAll), // IP candidate
        ];
        const consensusBytes = buildConsensus({
            validAfter: now - 60, freshUntil: now + 3600, validUntil: now + 7200,
            rses, daSigners: [da],
        });
        const consensus = parseConsensus(consensusBytes, {
            daTrustSet: new Map([[Buffer.from(da.fingerprint).toString('hex'), da.idPk]]),
            nowSeconds: now,
        });
        const peerResolver = createPeerResolver({ consensus });

        // Install on all relays + we'll install on client + service shortly.
        for (const r of relays) r.resolverHolder.fn = peerResolver;

        // ---- 4. Service identity + per-IP keys + descriptor ----
        const svc = createServiceIdentity();
        const introKeypair = generateIdentity();
        const introEncX = generateOnion();
        const introEncKem = ml_kem768.keygen();
        const introPoint = {
            fingerprint: n5.identity.fingerprint,
            ipOnionPk: n5.identity.B_pk,
            ipIdPk: n5.identity.idPk,
            serviceIntroSk: introKeypair.idSk,
            serviceIntroPk: introKeypair.idPk,
            serviceEncX25519Sk: introEncX.onionSk,
            serviceEncX25519Pk: introEncX.onionPk,
            serviceEncMlkemSk: introEncKem.secretKey,
            serviceEncMlkemPk: introEncKem.publicKey,
        };
        const descriptorBytes = buildServiceDescriptor({
            SVC_sk: svc.SVC_sk, SVC_pk: svc.SVC_pk,
            publishEpoch: now, lifetimeSeconds: 3600,
            introPoints: [{
                fingerprint: introPoint.fingerprint,
                ipOnionPk: introPoint.ipOnionPk,
                serviceIntroKey: introPoint.serviceIntroPk,
                serviceEncX25519Pk: introPoint.serviceEncX25519Pk,
                serviceEncMlkemPk: introPoint.serviceEncMlkemPk,
            }],
        });
        const descriptor = parseServiceDescriptor(descriptorBytes);

        // ---- 5. Set up the service runtime ----
        const serviceRuntime = await setupClientRuntime(createNodeIdentity());
        serviceRuntime.resolverHolder.fn = peerResolver;

        const findRse = (fp) => consensus.rses.find(
            (r) => Buffer.from(r.fingerprint).equals(Buffer.from(fp)),
        );

        // Service publishes via n5 as the IP; uses n3 → n4 → n5 for the IP circuit.
        // For the RP circuit (built after INTRODUCE2): n3 → n4 → <rp>.
        const servicePublisher = createServicePublisher({
            SVC_pk: svc.SVC_pk,
            introductionPoint: introPoint,
            consensus,
            peerResolver,
            linkManager: serviceRuntime.linkMgr,
            cellRouter: serviceRuntime.router,
            circuitBuilder: serviceRuntime.builder,
            ipPath: () => ({
                guard:  findRse(n3.identity.fingerprint),
                middle: findRse(n4.identity.fingerprint),
                exit:   findRse(n5.identity.fingerprint),
            }),
            rpPath: ({ rpRse }) => ({
                guard:  findRse(n3.identity.fingerprint),
                middle: findRse(n4.identity.fingerprint),
                exit:   rpRse,
            }),
            localDestination: { host: '127.0.0.1', port: echoPort },
        });

        // ---- 6. Set up the client runtime ----
        const clientRuntime = await setupClientRuntime(createNodeIdentity());
        clientRuntime.resolverHolder.fn = peerResolver;

        try {

            // Start the service.
            await servicePublisher.start();

            // Client opens the hidden service.
            const conn = await openHiddenService({
                descriptor,
                SVC_pk: svc.SVC_pk,
                consensus,
                rpPathFn: ({ rpRse }) => ({
                    guard:  findRse(n0.identity.fingerprint),
                    middle: findRse(n1.identity.fingerprint),
                    exit:   rpRse, // typically n2
                }),
                ipPathFn: ({ ipFingerprint }) => ({
                    guard:  findRse(n0.identity.fingerprint),
                    middle: findRse(n1.identity.fingerprint),
                    exit:   findRse(ipFingerprint),
                }),
                circuitBuilder: clientRuntime.builder,
            });

            // Open a stream and exchange data.
            const stream = await conn.openStream({ port: echoPort });
            const received = [];
            stream.onData((bytes) => received.push(Buffer.from(bytes)));

            stream.send(new TextEncoder().encode('hello'));

            const deadline = Date.now() + 15000;
            while (Buffer.concat(received).toString('utf8') !== 'hello' && Date.now() < deadline) {

                await new Promise((r) => setTimeout(r, 30));

            }
            expect(Buffer.concat(received).toString('utf8')).to.equal('hello');

            stream.end();
            await new Promise((r) => setTimeout(r, 100));

        } finally {

            servicePublisher.stop();
            serviceRuntime.close();
            clientRuntime.close();
            for (const r of relays) await r.close();
            await new Promise((r) => echo.close(r));

        }

    });

});
