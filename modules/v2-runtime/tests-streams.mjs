// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE

import { expect } from 'chai';
import { createServer, createConnection } from 'node:net';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createNodeIdentity } from './persistence.mjs';
import { createLinkListener } from './link_transport_ws.mjs';
import { generateSelfSignedCert } from './self_signed_cert.mjs';
import { createLinkManager } from './link_manager.mjs';
import { createCircuitDispatcher } from './circuit_dispatcher.mjs';
import { createCellRouter } from './cell_router.mjs';
import { createPeerResolver } from './peer_resolver.mjs';
import { createCircuitBuilder } from './circuit_builder.mjs';
import { createClientStreams, createExitStreamHandler } from './streams.mjs';
import {
    ADDR_TYPE_IPV4,
    ADDR_TYPE_IPV6,
    ADDR_TYPE_HOSTNAME,
    END_REASON_CLIENT_CLOSED,
    END_REASON_EXIT_POLICY,
    END_REASON_RESOLVE_FAIL,
    CONNECTED_STATUS_OK,
    buildBeginPayload,
    parseBeginPayload,
    buildConnectedPayload,
    parseConnectedPayload,
    buildEndPayload,
    parseEndPayload,
    ipv4ToString,
} from './stream_payloads.mjs';

import {
    FLAG_GUARD, FLAG_RUNNING, FLAG_VALID, FLAG_EXIT,
    buildConsensus,
} from '../v2/consensus.mjs';
import {
    ACTION_ACCEPT,
    makeAnyRule,
    buildPolicy,
    parsePolicy,
    POLICY_REJECT_ALL,
} from '../v2/exit_policy.mjs';
import { generateIdentity, identityFingerprint } from '../crypto/identity.mjs';

// Self-signed cert for link-transport TLS (SPEC § 11.1). One per file —
// the cert isn't load-bearing for identity (LINK_AUTH does that), so
// reusing across tests in this file is intentional + faster than a
// per-test openssl spawn (~70ms saved x N tests).
const { certPem: __linkCertPem, keyPem: __linkKeyPem } = generateSelfSignedCert();


// ----- Codec tests -----

describe('v2-runtime/stream_payloads — RELAY_BEGIN', () => {

    it('round-trip IPv4', () => {

        const addr = Uint8Array.from([192, 168, 1, 50]);
        const buf = buildBeginPayload({
            addrType: ADDR_TYPE_IPV4, addr, port: 443,
        });
        const parsed = parseBeginPayload(buf);
        expect(parsed.addrType).to.equal(ADDR_TYPE_IPV4);
        expect(Buffer.from(parsed.addr).equals(Buffer.from(addr))).to.equal(true);
        expect(parsed.port).to.equal(443);
        expect(parsed.flags).to.equal(0);
        expect(ipv4ToString(parsed.addr)).to.equal('192.168.1.50');

    });

    it('round-trip IPv6', () => {

        const addr = new Uint8Array(16);
        for (let i = 0; i < 16; i += 1) addr[i] = i + 1;
        const buf = buildBeginPayload({
            addrType: ADDR_TYPE_IPV6, addr, port: 80,
        });
        const parsed = parseBeginPayload(buf);
        expect(parsed.addrType).to.equal(ADDR_TYPE_IPV6);
        expect(Buffer.from(parsed.addr).equals(Buffer.from(addr))).to.equal(true);
        expect(parsed.port).to.equal(80);

    });

    it('round-trip hostname', () => {

        const addr = new TextEncoder().encode('example.com');
        const buf = buildBeginPayload({
            addrType: ADDR_TYPE_HOSTNAME, addr, port: 8080,
        });
        const parsed = parseBeginPayload(buf);
        expect(parsed.addrType).to.equal(ADDR_TYPE_HOSTNAME);
        expect(new TextDecoder().decode(parsed.addr)).to.equal('example.com');
        expect(parsed.port).to.equal(8080);

    });

    it('rejects bad sizes', () => {

        expect(parseBeginPayload(new Uint8Array(0))).to.equal(null);
        expect(parseBeginPayload(new Uint8Array([0x01, 0, 0, 0]))).to.equal(null); // missing port + flags
        expect(() => buildBeginPayload({
            addrType: ADDR_TYPE_IPV4, addr: new Uint8Array(3), port: 80,
        })).to.throw();

    });

});

describe('v2-runtime/stream_payloads — RELAY_CONNECTED / RELAY_END', () => {

    it('CONNECTED round-trip', () => {

        const buf = buildConnectedPayload({ status: CONNECTED_STATUS_OK });
        expect(buf.length).to.equal(1);
        expect(parseConnectedPayload(buf).status).to.equal(CONNECTED_STATUS_OK);

    });

    it('END round-trip', () => {

        const buf = buildEndPayload(END_REASON_CLIENT_CLOSED);
        expect(parseEndPayload(buf).reason).to.equal(END_REASON_CLIENT_CLOSED);

    });

});

// ----- End-to-end: client opens stream through a 3-hop circuit to an echo server -----

const spinUpRelay = async ({ resolverHolder, exitHandlerHolder, getExitPolicy }) => {

    const identity = createNodeIdentity();
    const routerHolder = { router: null };

    const linkMgr = createLinkManager({
        identity,
        onCell: (link, cell) => {

            if (routerHolder.router) routerHolder.router.onCell(link, cell);

        },
    });
    const dispatcher = createCircuitDispatcher({
        identity, linkManager: linkMgr,
        peerResolver: (q) => resolverHolder.fn(q),
        onExitData: (d) => {

            if (exitHandlerHolder.handler) exitHandlerHolder.handler.handleData(d);

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
        dispatcher, linkMgr, listener, getExitPolicy,
        close: async () => {

            dispatcher.closeAll();
            linkMgr.closeAll();
            await listener.close();

        },
    };

};

describe('v2-runtime/streams — end-to-end client stream through 3-hop circuit', function () {

    this.timeout(30000);

    it('client → 3-hop circuit → exit dials echo TCP server → "hello" round-trips', async () => {

        // 1. Echo TCP server.
        const echoConnections = [];
        const echo = await new Promise((res) => {

            const s = createServer({ allowHalfOpen: true }, (sock) => {

                echoConnections.push(sock);
                sock.on('data', (d) => sock.write(d));
                sock.on('end', () => sock.end());

            });
            s.listen(0, '127.0.0.1', () => res(s));

        });
        const echoPort = echo.address().port;

        // 2. Spin up 3 relays. The 3rd one (exit) gets a permissive
        //    exit policy that accepts 127.0.0.1 on the echo port.
        const resolverHolder = { fn: () => null };
        const handlerHolders = [
            { handler: null }, { handler: null }, { handler: null },
        ];

        const r0 = await spinUpRelay({ resolverHolder, exitHandlerHolder: handlerHolders[0] });
        const r1 = await spinUpRelay({ resolverHolder, exitHandlerHolder: handlerHolders[1] });
        const r2 = await spinUpRelay({ resolverHolder, exitHandlerHolder: handlerHolders[2] });

        // 3. Client setup.
        const clientIdentity = createNodeIdentity();
        const clientRouterHolder = { router: null };
        const clientLinkMgr = createLinkManager({
            identity: clientIdentity,
            onCell: (link, cell) => {

                if (clientRouterHolder.router) clientRouterHolder.router.onCell(link, cell);

            },
        });
        const clientRelayDispatcher = createCircuitDispatcher({
            identity: clientIdentity, linkManager: clientLinkMgr,
            peerResolver: (q) => resolverHolder.fn(q),
        });
        clientRouterHolder.router = createCellRouter({ relayDispatcher: clientRelayDispatcher });

        try {

            // 4. Build consensus.
            const da = (() => {

                const id = generateIdentity();
                return {
                    idPk: id.idPk, idSk: id.idSk,
                    fingerprint: identityFingerprint(id.idPk),
                };

            })();
            const now = Math.floor(Date.now() / 1000);
            const ipv4For = (port) => Uint8Array.from([127, 0, 0, 1, (port >> 8) & 0xFF, port & 0xFF]);

            // Exit's policy: accept the echo server's port on 127.0.0.1.
            const exitPolicyRules = [
                makeAnyRule({ action: ACTION_ACCEPT, portMin: echoPort, portMax: echoPort }),
            ];
            const exitPolicyBytes = buildPolicy(exitPolicyRules);

            const rses = [
                {
                    fingerprint: r0.identity.fingerprint, idPk: r0.identity.idPk,
                    onionPk: r0.identity.B_pk, ipv4: ipv4For(r0.port), ipv6: null,
                    flags: FLAG_RUNNING | FLAG_VALID | FLAG_GUARD,
                    exitPolicyBytes: buildPolicy(POLICY_REJECT_ALL),
                },
                {
                    fingerprint: r1.identity.fingerprint, idPk: r1.identity.idPk,
                    onionPk: r1.identity.B_pk, ipv4: ipv4For(r1.port), ipv6: null,
                    flags: FLAG_RUNNING | FLAG_VALID,
                    exitPolicyBytes: buildPolicy(POLICY_REJECT_ALL),
                },
                {
                    fingerprint: r2.identity.fingerprint, idPk: r2.identity.idPk,
                    onionPk: r2.identity.B_pk, ipv4: ipv4For(r2.port), ipv6: null,
                    flags: FLAG_RUNNING | FLAG_VALID | FLAG_EXIT,
                    exitPolicyBytes,
                },
            ];
            const consensusBytes = buildConsensus({
                validAfter: now - 60, freshUntil: now + 3600, validUntil: now + 7200,
                rses, daSigners: [da],
            });
            const { parseConsensus } = await import('../v2/consensus.mjs');
            const consensus = parseConsensus(consensusBytes, {
                daTrustSet: new Map([
                    [Buffer.from(da.fingerprint).toString('hex'), da.idPk],
                ]),
                nowSeconds: now,
            });
            resolverHolder.fn = createPeerResolver({ consensus });

            // 5. Install exit handler on r2 (the exit). Its policy is
            //    the same policy that's in the consensus.
            handlerHolders[2].handler = createExitStreamHandler({
                exitPolicy: parsePolicy(exitPolicyBytes),
            });

            // 6. Build the circuit through r0, r1, r2.
            const guardRse  = consensus.rses.find((r) => Buffer.from(r.fingerprint).equals(Buffer.from(r0.identity.fingerprint)));
            const middleRse = consensus.rses.find((r) => Buffer.from(r.fingerprint).equals(Buffer.from(r1.identity.fingerprint)));
            const exitRse   = consensus.rses.find((r) => Buffer.from(r.fingerprint).equals(Buffer.from(r2.identity.fingerprint)));

            const builder = createCircuitBuilder({
                linkManager: clientLinkMgr,
                cellRouter: clientRouterHolder.router,
                peerResolver: resolverHolder.fn,
            });

            // 7. Build the circuit with onData wired into the streams
            //    handler via a holder (streams object can't exist until
            //    after the circuit is built, but onData needs to be
            //    passed at build time — holder resolves the cycle).
            const streamsHolder = { streams: null };
            const built = await builder.buildCircuit({
                path: { guard: guardRse, middle: middleRse, exit: exitRse },
                onData: (d) => {

                    if (streamsHolder.streams) streamsHolder.streams.handleInboundRelay(d);

                },
            });
            expect(built.circuit.hops.length).to.equal(3);
            streamsHolder.streams = createClientStreams({
                circuit: built.circuit, entryLink: built.entryLink,
            });

            // 8. Open a stream to the echo server, send "hello", read back.
            const stream = await streamsHolder.streams.openStream({
                destination: {
                    addrType: ADDR_TYPE_IPV4,
                    addr: Uint8Array.from([127, 0, 0, 1]),
                    port: echoPort,
                },
            });
            const received = [];
            stream.onData((bytes) => received.push(Buffer.from(bytes)));

            stream.send(new TextEncoder().encode('hello'));

            // Wait for echo.
            const deadline = Date.now() + 5000;
            while (Buffer.concat(received).toString('utf8') !== 'hello' && Date.now() < deadline) {

                await new Promise((r) => setTimeout(r, 20));

            }
            expect(Buffer.concat(received).toString('utf8')).to.equal('hello');

            stream.end();
            await new Promise((r) => setTimeout(r, 100));

        } finally {

            clientRelayDispatcher.closeAll();
            clientLinkMgr.closeAll();
            await r0.close();
            await r1.close();
            await r2.close();
            await new Promise((r) => echo.close(r));
            for (const c of echoConnections) try { c.destroy(); } catch {}

        }

    });

});
