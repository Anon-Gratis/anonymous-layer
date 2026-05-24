// v2-runtime — tests for the HSDir client (Phase 1, HTTPS-fronted).
//
// Spins up a local HTTP server pretending to be the DA, exercises:
//   - lookup-key derivation matches address body
//   - fetch + parse on 200
//   - cache hit on repeated lookups (single network call)
//   - 404 on unknown service returns null (caller falls back)
//   - substituted-descriptor detection (DA returns bytes for a
//     DIFFERENT service; client must reject the binding mismatch)
//   - malformed-body rejection
//   - oversize-body rejection

import { expect } from 'chai';
import { createServer } from 'node:http';

import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import { buildServiceDescriptor, buildServiceDescriptorV3 } from '../v2/descriptor.mjs';
import { encodeOnionAddress, encodeOnionAddressV3, ONION_ADDR_SUFFIX } from '../v2/onion_address.mjs';
import { createServiceIdentity } from '../v2/service.mjs';
import { generateOnion } from '../crypto/onion.mjs';
import { generateIdentity, identityFingerprint } from '../crypto/identity.mjs';

import {
    lookupKeyForAddress,
    fetchDescriptorFromHsdir,
    createHsdirClient,
} from './hsdir_client.mjs';

const NOW = 1_700_000_000;

const makeIntroPoint = () => {

    const id = generateIdentity();
    const onion = generateOnion();
    const intro = generateIdentity();
    const encX = generateOnion();
    const encK = ml_kem768.keygen();
    return {
        fingerprint:        identityFingerprint(id.idPk),
        ipOnionPk:          onion.onionPk,
        serviceIntroKey:    intro.idPk,
        serviceEncX25519Pk: encX.onionPk,
        serviceEncMlkemPk:  encK.publicKey,
    };

};

const buildV2 = () => {

    const svc = createServiceIdentity();
    const buf = buildServiceDescriptor({
        SVC_sk: svc.SVC_sk,
        SVC_pk: svc.SVC_pk,
        publishEpoch: NOW,
        lifetimeSeconds: 3600,
        introPoints: [makeIntroPoint()],
    });
    return { bytes: buf, address: encodeOnionAddress(svc.SVC_pk) };

};

const buildV3 = () => {

    const SVC_sk_ed = ed25519.utils.randomSecretKey();
    const SVC_pk_ed = ed25519.getPublicKey(SVC_sk_ed);
    const seed = ed25519.utils.randomSecretKey();
    const dsa = ml_dsa65.keygen(seed);
    const buf = buildServiceDescriptorV3({
        SVC_sk_ed, SVC_pk_ed,
        SVC_sk_mldsa: dsa.secretKey, SVC_pk_mldsa: dsa.publicKey,
        publishEpoch: NOW,
        lifetimeSeconds: 3600,
        introPoints: [makeIntroPoint()],
    });
    return { bytes: buf, address: encodeOnionAddressV3(SVC_pk_ed, dsa.publicKey) };

};

// Tiny HTTP server: GET /hsdir/<key> serves whatever the test loaded
// into `store[key]`. PUT-not-supported (real DA isn't writable here
// either; uploads go via SSH/rsync).
const startMockDa = async (store) => {

    return new Promise((resolveOk) => {

        const server = createServer((req, res) => {

            const m = req.url.match(/^\/hsdir\/([A-Za-z0-9_-]+)$/);
            if (!m) { res.writeHead(404); res.end(); return; }
            const key = m[1].toLowerCase();
            const body = store.get(key);
            if (!body) { res.writeHead(404); res.end(); return; }
            res.writeHead(200, { 'content-type': 'application/octet-stream' });
            res.end(Buffer.from(body));

        });
        server.listen(0, '127.0.0.1', () => {

            const { port } = server.address();
            resolveOk({ baseUrl: `http://127.0.0.1:${port}`, server });

        });

    });

};

describe('v2-runtime/hsdir_client — lookup-key + fetch + verify', () => {

    let mock; let store;
    beforeEach(async () => {

        store = new Map();
        mock = await startMockDa(store);

    });
    afterEach(async () => {

        await new Promise((r) => mock.server.close(r));

    });

    it('lookupKeyForAddress strips the .anon suffix and lower-cases', () => {

        const v3 = buildV3();
        const key = lookupKeyForAddress(v3.address);
        expect(v3.address.endsWith(ONION_ADDR_SUFFIX)).to.equal(true);
        expect(key).to.equal(v3.address.slice(0, -ONION_ADDR_SUFFIX.length).toLowerCase());
        expect(key).to.match(/^[a-z2-7]{16,64}$/);

    });

    it('lookupKeyForAddress rejects malformed addresses', () => {

        expect(() => lookupKeyForAddress('not-an-anon-address')).to.throw(/suffix/);
        expect(() => lookupKeyForAddress('short.anon')).to.throw(/malformed/);
        expect(() => lookupKeyForAddress('!@#$%^.anon')).to.throw(/malformed/);

    });

    it('fetchDescriptorFromHsdir returns parsed descriptor on 200', async () => {

        const v3 = buildV3();
        store.set(lookupKeyForAddress(v3.address), v3.bytes);
        const d = await fetchDescriptorFromHsdir({ daBaseUrl: mock.baseUrl, address: v3.address });
        expect(d).to.not.equal(null);
        expect(d.version).to.equal(0x03);

    });

    it('fetchDescriptorFromHsdir works for v2 descriptors too', async () => {

        const v2 = buildV2();
        store.set(lookupKeyForAddress(v2.address), v2.bytes);
        const d = await fetchDescriptorFromHsdir({ daBaseUrl: mock.baseUrl, address: v2.address });
        expect(d.version).to.equal(0x02);

    });

    it('fetchDescriptorFromHsdir throws on 404 (unknown service)', async () => {

        const v3 = buildV3();
        let threw = null;
        try { await fetchDescriptorFromHsdir({ daBaseUrl: mock.baseUrl, address: v3.address }); }
        catch (e) { threw = e; }
        expect(threw).to.not.equal(null);
        expect(threw.message).to.match(/404/);

    });

    it('fetchDescriptorFromHsdir rejects substituted descriptor (binding mismatch)', async () => {

        // Two different v3 services. Store SERVICE_A's descriptor at
        // SERVICE_B's key. Client asks for SERVICE_B → gets SERVICE_A
        // bytes. Address-to-pubkey binding must catch this.
        const a = buildV3();
        const b = buildV3();
        store.set(lookupKeyForAddress(b.address), a.bytes);
        let threw = null;
        try { await fetchDescriptorFromHsdir({ daBaseUrl: mock.baseUrl, address: b.address }); }
        catch (e) { threw = e; }
        expect(threw).to.not.equal(null);
        expect(threw.message).to.match(/binding mismatch|SVC_pk mismatch/);

    });

    it('fetchDescriptorFromHsdir rejects malformed body', async () => {

        const v3 = buildV3();
        store.set(lookupKeyForAddress(v3.address), Buffer.from('not a descriptor at all'));
        let threw = null;
        try { await fetchDescriptorFromHsdir({ daBaseUrl: mock.baseUrl, address: v3.address }); }
        catch (e) { threw = e; }
        expect(threw).to.not.equal(null);
        expect(threw.message).to.match(/parse failed/);

    });

    it('createHsdirClient caches successful lookups (no second HTTP fetch)', async () => {

        const v3 = buildV3();
        store.set(lookupKeyForAddress(v3.address), v3.bytes);

        // Count requests by wrapping the server's request handler
        let requests = 0;
        const inner = mock.server.listeners('request')[0];
        mock.server.removeAllListeners('request');
        mock.server.on('request', (req, res) => { requests += 1; inner(req, res); });

        const client = createHsdirClient({ daBaseUrl: mock.baseUrl, nowSeconds: () => NOW + 1 });
        const d1 = await client.lookup(v3.address);
        const d2 = await client.lookup(v3.address);
        expect(d1).to.not.equal(null);
        expect(d2).to.not.equal(null);
        expect(requests).to.equal(1); // cached

    });

    it('createHsdirClient invalidate forces a refetch', async () => {

        const v3 = buildV3();
        store.set(lookupKeyForAddress(v3.address), v3.bytes);
        let requests = 0;
        const inner = mock.server.listeners('request')[0];
        mock.server.removeAllListeners('request');
        mock.server.on('request', (req, res) => { requests += 1; inner(req, res); });
        const client = createHsdirClient({ daBaseUrl: mock.baseUrl, nowSeconds: () => NOW + 1 });
        await client.lookup(v3.address);
        client.invalidate(v3.address);
        await client.lookup(v3.address);
        expect(requests).to.equal(2);

    });

    it('createHsdirClient.lookup returns null on 404 (caller can fall back)', async () => {

        const v3 = buildV3();
        const client = createHsdirClient({ daBaseUrl: mock.baseUrl });
        const d = await client.lookup(v3.address);
        expect(d).to.equal(null);

    });

});
