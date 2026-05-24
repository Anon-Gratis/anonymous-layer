// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE

import { expect } from 'chai';
import { createServer, createConnection } from 'node:net';

import { createNodeIdentity } from './persistence.mjs';
import { createLinkListener } from './link_transport_ws.mjs';
import { generateSelfSignedCert } from './self_signed_cert.mjs';
import { createLinkManager } from './link_manager.mjs';
import { createCircuitDispatcher } from './circuit_dispatcher.mjs';
import { createCellRouter } from './cell_router.mjs';
import { createPeerResolver } from './peer_resolver.mjs';
import { createCircuitBuilder } from './circuit_builder.mjs';
import { createExitStreamHandler } from './streams.mjs';
import { createAnonLayerTunnelFactory } from './anon_layer_tunnel.mjs';

import {
    FLAG_GUARD, FLAG_RUNNING, FLAG_VALID, FLAG_EXIT,
    buildConsensus,
    parseConsensus,
} from '../v2/consensus.mjs';
import {
    ACTION_ACCEPT,
    makeAnyRule,
    buildPolicy,
    parsePolicy,
    POLICY_REJECT_ALL,
} from '../v2/exit_policy.mjs';
import { generateIdentity, identityFingerprint } from '../crypto/identity.mjs';

import {
    handleSocksConnection,
} from '../v2/socks.mjs';

// Self-signed cert for link-transport TLS (SPEC § 11.1). One per file —
// the cert isn't load-bearing for identity (LINK_AUTH does that), so
// reusing across tests in this file is intentional + faster than a
// per-test openssl spawn (~70ms saved x N tests).
const { certPem: __linkCertPem, keyPem: __linkKeyPem } = generateSelfSignedCert();


const spinUpRelay = async ({ resolverHolder, exitHandlerHolder }) => {

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
        dispatcher, linkMgr, listener,
        close: async () => {

            dispatcher.closeAll();
            linkMgr.closeAll();
            await listener.close();

        },
    };

};

// Speak SOCKS5 to the given (host, port), CONNECT to dest IPv4:dport,
// send `requestBytes`, read until `expectedBytes` of application data
// have been received then close. Resolves with the received bytes.
const socks5Request = ({ socksHost, socksPort, destIPv4, destPort, requestBytes, expectedBytes }) => new Promise((resolve, reject) => {

    const sock = createConnection({ host: socksHost, port: socksPort });
    let receivedLen = 0;
    let received = Buffer.alloc(0);
    let phase = 'greet';
    let buffer = Buffer.alloc(0);
    let done = false;

    const finish = (data) => {

        if (done) return;
        done = true;
        try { sock.destroy(); } catch { /* ignore */ }
        resolve(data);

    };

    sock.on('connect', () => {

        sock.write(Buffer.from([0x05, 0x01, 0x00]));

    });
    sock.on('data', (chunk) => {

        buffer = Buffer.concat([buffer, chunk]);
        while (!done) {

            if (phase === 'greet') {

                if (buffer.length < 2) return;
                if (buffer[0] !== 0x05 || buffer[1] !== 0x00) {

                    sock.destroy();
                    return reject(new Error(`greet reply was ${buffer[0]} ${buffer[1]}`));

                }
                buffer = buffer.subarray(2);
                const dst = destIPv4.split('.').map((n) => parseInt(n, 10));
                sock.write(Buffer.from([
                    0x05, 0x01, 0x00, 0x01,
                    dst[0], dst[1], dst[2], dst[3],
                    (destPort >> 8) & 0xFF, destPort & 0xFF,
                ]));
                phase = 'reply';

            } else if (phase === 'reply') {

                if (buffer.length < 10) return;
                if (buffer[1] !== 0x00) {

                    sock.destroy();
                    return reject(new Error(`SOCKS5 CONNECT failed: REP=0x${buffer[1].toString(16)}`));

                }
                buffer = buffer.subarray(10);
                sock.write(requestBytes);
                phase = 'pipe';

            } else {

                if (buffer.length > 0) {

                    received = Buffer.concat([received, buffer]);
                    receivedLen += buffer.length;
                    buffer = Buffer.alloc(0);

                }
                if (receivedLen >= expectedBytes) return finish(received);
                return;

            }

        }

    });
    sock.on('error', (err) => { if (!done) reject(err); });
    sock.on('close', () => { if (!done) finish(received); });

});

describe('v2-runtime/anon_layer_tunnel — SOCKS5 client → anon-layer → exit TCP', function () {

    this.timeout(45000);

    it('full stack: SOCKS5 CONNECT → 3-hop circuit → exit → echo TCP server; bytes round-trip', async () => {

        // 1. Echo TCP server (the "destination" the SOCKS client wants to reach).
        const echo = await new Promise((res) => {

            const s = createServer({ allowHalfOpen: true }, (sock) => {

                sock.on('data', (d) => sock.write(d));
                sock.on('end',  () => sock.end());

            });
            s.listen(0, '127.0.0.1', () => res(s));

        });
        const echoPort = echo.address().port;

        // 2. Spin up 3 in-process relays.
        const resolverHolder = { fn: () => null };
        const handlerHolders = [{}, {}, {}].map(() => ({ handler: null }));
        const r0 = await spinUpRelay({ resolverHolder, exitHandlerHolder: handlerHolders[0] });
        const r1 = await spinUpRelay({ resolverHolder, exitHandlerHolder: handlerHolders[1] });
        const r2 = await spinUpRelay({ resolverHolder, exitHandlerHolder: handlerHolders[2] });

        // 3. Build a consensus + exit policy that permits the echo port.
        const da = (() => {

            const id = generateIdentity();
            return { idPk: id.idPk, idSk: id.idSk, fingerprint: identityFingerprint(id.idPk) };

        })();
        const now = Math.floor(Date.now() / 1000);
        const ipv4For = (port) => Uint8Array.from([127, 0, 0, 1, (port >> 8) & 0xFF, port & 0xFF]);
        const exitPolicyBytes = buildPolicy([
            makeAnyRule({ action: ACTION_ACCEPT, portMin: echoPort, portMax: echoPort }),
        ]);
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
        const consensus = parseConsensus(consensusBytes, {
            daTrustSet: new Map([[Buffer.from(da.fingerprint).toString('hex'), da.idPk]]),
            nowSeconds: now,
        });
        resolverHolder.fn = createPeerResolver({ consensus });

        // 4. Install the exit-stream handler on r2 (and rejecting ones
        //    on r0/r1 for symmetry; they should never receive exit data).
        handlerHolders[2].handler = createExitStreamHandler({
            exitPolicy: parsePolicy(exitPolicyBytes),
        });

        // 5. Client-side runtime + tunnel factory.
        const clientIdentity = createNodeIdentity();
        const clientRouterHolder = { router: null };
        const clientLinkMgr = createLinkManager({
            identity: clientIdentity,
            onCell: (link, cell) => {

                if (clientRouterHolder.router) clientRouterHolder.router.onCell(link, cell);

            },
        });
        const clientDispatcher = createCircuitDispatcher({
            identity: clientIdentity, linkManager: clientLinkMgr,
            peerResolver: resolverHolder.fn,
        });
        clientRouterHolder.router = createCellRouter({ relayDispatcher: clientDispatcher });
        const builder = createCircuitBuilder({
            linkManager: clientLinkMgr,
            cellRouter: clientRouterHolder.router,
            peerResolver: resolverHolder.fn,
        });
        // For this test all 3 relays share 127.0.0.1 (same /16), so the
        // default pickPath would reject every path under the anti-co-
        // location rule. Use an explicit ordering that mirrors what
        // pickPath would produce on a real geographically-diverse network.
        const findRse = (fp) => consensus.rses.find(
            (r) => Buffer.from(r.fingerprint).equals(Buffer.from(fp)),
        );
        const { tunnelFactory, closeStandby } = createAnonLayerTunnelFactory({
            consensus, circuitBuilder: builder,
            pathSelectorPort: echoPort,
            pickPathFn: () => ({
                guard:  findRse(r0.identity.fingerprint),
                middle: findRse(r1.identity.fingerprint),
                exit:   findRse(r2.identity.fingerprint),
            }),
        });

        // 6. SOCKS5 server in front of the tunnel factory.
        const socksServer = await new Promise((res) => {

            const s = createServer({ allowHalfOpen: true }, (socket) => {

                handleSocksConnection({ socket, tunnelFactory }).catch(() => {});

            });
            s.listen(0, '127.0.0.1', () => res(s));

        });
        const socksPort = socksServer.address().port;

        try {

            // 7. SOCKS5 client: CONNECT to echo via SOCKS, send "hello", read echo.
            const received = await socks5Request({
                socksHost: '127.0.0.1', socksPort,
                destIPv4: '127.0.0.1', destPort: echoPort,
                requestBytes: Buffer.from('hello'),
                expectedBytes: 5,
            });
            expect(received.toString('utf8')).to.equal('hello');

        } finally {

            closeStandby();
            clientDispatcher.closeAll();
            clientLinkMgr.closeAll();
            // Force-close lingering SOCKS connections (Node ≥ 18.2);
            // race the listener close with a short timeout in case any
            // sockets refuse to terminate.
            try { socksServer.closeAllConnections(); } catch { /* older Node */ }
            const unrefTimeout = (ms) => new Promise((r) => {

                const t = setTimeout(r, ms);
                t.unref();

            });
            await Promise.race([
                new Promise((r) => socksServer.close(r)),
                unrefTimeout(2000),
            ]);
            await r0.close();
            await r1.close();
            await r2.close();
            await Promise.race([
                new Promise((r) => echo.close(r)),
                unrefTimeout(2000),
            ]);

        }

    });

});
