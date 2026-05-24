// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE

import { expect } from 'chai';
import { mkdtemp, rm, stat, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
    createNodeIdentity,
    saveIdentity,
    loadIdentity,
    loadOrCreateIdentity,
} from './persistence.mjs';
import {
    dialLink,
    createLinkListener,
} from './link_transport_ws.mjs';
import { generateSelfSignedCert } from './self_signed_cert.mjs';
import {
    createLinkManager,
} from './link_manager.mjs';

// Self-signed cert for link-transport TLS (SPEC § 11.1). One per file —
// the cert isn't load-bearing for identity (LINK_AUTH does that), so
// reusing across tests in this file is intentional + faster than a
// per-test openssl spawn (~70ms saved x N tests).
const { certPem: __linkCertPem, keyPem: __linkKeyPem } = generateSelfSignedCert();


// ----- persistence.mjs -----

describe('v2-runtime/persistence', () => {

    let dir;

    beforeEach(async () => {

        dir = await mkdtemp(join(tmpdir(), 'anon-v2-runtime-'));

    });

    afterEach(async () => {

        if (dir) await rm(dir, { recursive: true, force: true });

    });

    it('createNodeIdentity returns coherent fields', () => {

        const id = createNodeIdentity();
        expect(id.idSk.length).to.equal(32);
        expect(id.idPk.length).to.equal(32);
        expect(id.B_sk.length).to.equal(32);
        expect(id.B_pk.length).to.equal(32);
        expect(id.fingerprint.length).to.equal(32);

    });

    it('save → load round-trip preserves keys', async () => {

        const id = createNodeIdentity();
        const path = join(dir, 'identity.key');
        await saveIdentity(path, { idSk: id.idSk, B_sk: id.B_sk });
        const loaded = await loadIdentity(path);
        expect(Buffer.from(loaded.idSk).equals(Buffer.from(id.idSk))).to.equal(true);
        expect(Buffer.from(loaded.idPk).equals(Buffer.from(id.idPk))).to.equal(true);
        expect(Buffer.from(loaded.B_sk).equals(Buffer.from(id.B_sk))).to.equal(true);
        expect(Buffer.from(loaded.B_pk).equals(Buffer.from(id.B_pk))).to.equal(true);
        expect(Buffer.from(loaded.fingerprint).equals(Buffer.from(id.fingerprint))).to.equal(true);

    });

    it('file is written with mode 0600', async function () {

        if (process.platform === 'win32') this.skip();
        const id = createNodeIdentity();
        const path = join(dir, 'identity.key');
        await saveIdentity(path, { idSk: id.idSk, B_sk: id.B_sk });
        const st = await stat(path);
        expect(st.mode & 0o777).to.equal(0o600);

    });

    it('loadIdentity refuses a file with overly permissive mode', async function () {

        if (process.platform === 'win32') this.skip();
        const id = createNodeIdentity();
        const path = join(dir, 'identity.key');
        await saveIdentity(path, { idSk: id.idSk, B_sk: id.B_sk });
        await chmod(path, 0o644);
        let threw = false;
        try { await loadIdentity(path); }
        catch (err) { threw = /overly permissive/.test(err.message); }
        expect(threw).to.equal(true);

    });

    it('loadOrCreateIdentity creates if missing, loads same on second call', async () => {

        const path = join(dir, 'identity.key');
        const first = await loadOrCreateIdentity(path);
        expect(first.created).to.equal(true);
        const second = await loadOrCreateIdentity(path);
        expect(second.created).to.equal(false);
        expect(Buffer.from(second.identity.idPk).equals(Buffer.from(first.identity.idPk))).to.equal(true);

    });

});

// ----- link_transport_ws.mjs + link_manager.mjs (integration) -----

describe('v2-runtime/link_transport_ws + link_manager', function () {

    this.timeout(10000);

    it('two nodes complete the LINK handshake via real WebSocket', async () => {

        const serverIdentity = createNodeIdentity();
        const clientIdentity = createNodeIdentity();

        let acceptedLink = null;
        const listener = await createLinkListener({
            tlsCert: __linkCertPem, tlsKey: __linkKeyPem,
            port: 0, host: '127.0.0.1', identity: serverIdentity,
            onLink: (link) => { acceptedLink = link; },
        });

        try {

            const { peerIdPk, transport } = await dialLink({
                host: '127.0.0.1', port: listener.port,
                identity: clientIdentity,
                expectedPeerIdPk: serverIdentity.idPk,
            });

            expect(Buffer.from(peerIdPk).equals(Buffer.from(serverIdentity.idPk))).to.equal(true);

            // Server side: give the onLink callback a microtask to fire.
            await new Promise((r) => setTimeout(r, 50));
            expect(acceptedLink).to.not.equal(null);
            expect(Buffer.from(acceptedLink.peerIdPk).equals(Buffer.from(clientIdentity.idPk))).to.equal(true);

            transport.close();

        } finally {

            await listener.close();

        }

    });

    it('dialer aborts when the server presents a different idPk than expected', async () => {

        const realServerIdentity = createNodeIdentity();
        const otherIdentity = createNodeIdentity();
        const clientIdentity = createNodeIdentity();

        const listener = await createLinkListener({
            tlsCert: __linkCertPem, tlsKey: __linkKeyPem,
            port: 0, host: '127.0.0.1', identity: realServerIdentity,
            onLink: () => {},
        });

        try {

            let threw = false;
            try {

                await dialLink({
                    host: '127.0.0.1', port: listener.port,
                    identity: clientIdentity,
                    expectedPeerIdPk: otherIdentity.idPk, // wrong!
                });

            } catch (err) {

                threw = /idPk does not match expected/.test(err.message);

            }
            expect(threw).to.equal(true);

        } finally {

            await listener.close();

        }

    });

    it('LinkManager deduplicates simultaneous accepts of the same peer', async () => {

        const serverIdentity = createNodeIdentity();
        const clientIdentity = createNodeIdentity();

        let openCount = 0;
        const linkMgr = createLinkManager({
            identity: serverIdentity,
            onCell: () => {},
            onLinkOpen: () => { openCount += 1; },
        });

        const listener = await createLinkListener({
            tlsCert: __linkCertPem, tlsKey: __linkKeyPem,
            port: 0, host: '127.0.0.1', identity: serverIdentity,
            onLink: (link) => linkMgr.acceptLink(link),
        });

        try {

            // Open two simultaneous dials from the same client identity.
            const [d1, d2] = await Promise.all([
                dialLink({
                    host: '127.0.0.1', port: listener.port,
                    identity: clientIdentity,
                    expectedPeerIdPk: serverIdentity.idPk,
                }),
                dialLink({
                    host: '127.0.0.1', port: listener.port,
                    identity: clientIdentity,
                    expectedPeerIdPk: serverIdentity.idPk,
                }),
            ]);

            // Server may receive both, but the LinkManager should
            // collapse them: only one link in its registry, only one
            // open callback.
            await new Promise((r) => setTimeout(r, 100));
            expect(linkMgr.getLinkCount()).to.equal(1);
            expect(openCount).to.equal(1);

            d1.transport.close();
            d2.transport.close();

        } finally {

            linkMgr.closeAll();
            await listener.close();

        }

    });

    it('LinkManager.ensureLink dials a new peer once and reuses the link', async () => {

        const serverIdentity = createNodeIdentity();
        const clientIdentity = createNodeIdentity();

        const serverMgr = createLinkManager({
            identity: serverIdentity,
            onCell: () => {},
        });
        const listener = await createLinkListener({
            tlsCert: __linkCertPem, tlsKey: __linkKeyPem,
            port: 0, host: '127.0.0.1', identity: serverIdentity,
            onLink: (link) => serverMgr.acceptLink(link),
        });

        const clientMgr = createLinkManager({
            identity: clientIdentity,
            onCell: () => {},
        });

        try {

            const a = await clientMgr.ensureLink({
                peerIdPk: serverIdentity.idPk,
                host: '127.0.0.1', port: listener.port,
            });
            const b = await clientMgr.ensureLink({
                peerIdPk: serverIdentity.idPk,
                host: '127.0.0.1', port: listener.port,
            });
            expect(a).to.equal(b); // same link object
            expect(clientMgr.getLinkCount()).to.equal(1);

        } finally {

            clientMgr.closeAll();
            serverMgr.closeAll();
            await listener.close();

        }

    });

    it('onCell delivers post-handshake cells to the LinkManager', async () => {

        const serverIdentity = createNodeIdentity();
        const clientIdentity = createNodeIdentity();

        const serverCells = [];
        const serverMgr = createLinkManager({
            identity: serverIdentity,
            onCell: (link, cell) => { serverCells.push({ link, cell }); },
        });

        const listener = await createLinkListener({
            tlsCert: __linkCertPem, tlsKey: __linkKeyPem,
            port: 0, host: '127.0.0.1', identity: serverIdentity,
            onLink: (link) => serverMgr.acceptLink(link),
        });

        try {

            const { transport } = await dialLink({
                host: '127.0.0.1', port: listener.port,
                identity: clientIdentity,
                expectedPeerIdPk: serverIdentity.idPk,
            });

            // Send a valid-shaped cell after handshake. (Content irrelevant
            // for this test; we just verify dispatch.)
            const stray = new Uint8Array(514);
            stray[5] = 0x04; // CMD_DESTROY — a real command code so the
            // future circuit-dispatch path will route it. For 9.4a we just
            // verify the cell arrives.
            transport.sendCell(stray);
            await new Promise((r) => setTimeout(r, 100));

            expect(serverCells.length).to.equal(1);
            expect(serverCells[0].cell.length).to.equal(514);
            expect(Buffer.from(serverCells[0].link.peerIdPk).equals(Buffer.from(clientIdentity.idPk))).to.equal(true);

            transport.close();

        } finally {

            serverMgr.closeAll();
            await listener.close();

        }

    });

});
