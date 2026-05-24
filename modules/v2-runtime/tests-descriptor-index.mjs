// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE
//
// Tests for descriptor_index.mjs — the per-host descriptor lookup the
// bridge uses to route `/api/fetch?url=anon://X.anon` to the right
// hidden service. Covers v2 (Ed25519-only) descriptors, v3 (PQ hybrid)
// descriptors, malformed-file tolerance, duplicates, and the
// must-have-content invariant.

import { expect } from 'chai';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import {
    buildServiceDescriptor,
    buildServiceDescriptorV3,
} from '../v2/descriptor.mjs';
import {
    encodeOnionAddress,
    encodeOnionAddressV3,
    ONION_ADDR_SUFFIX,
} from '../v2/onion_address.mjs';
import { createServiceIdentity } from '../v2/service.mjs';
import { generateOnion } from '../crypto/onion.mjs';
import { generateIdentity, identityFingerprint } from '../crypto/identity.mjs';
import { createDescriptorIndex } from './descriptor_index.mjs';

const NOW = 1_700_000_000;
const ONE_HOUR = 3600;

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
        serviceEncMlkemSk:  encK.secretKey,
        serviceEncMlkemPk:  encK.publicKey,
    };

};

const buildV2 = () => {

    const svc = createServiceIdentity();
    const buf = buildServiceDescriptor({
        SVC_sk: svc.SVC_sk,
        SVC_pk: svc.SVC_pk,
        publishEpoch: NOW,
        lifetimeSeconds: ONE_HOUR,
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
        lifetimeSeconds: ONE_HOUR,
        introPoints: [makeIntroPoint()],
    });
    return { bytes: buf, address: encodeOnionAddressV3(SVC_pk_ed, dsa.publicKey) };

};

describe('v2-runtime/descriptor_index — load + lookup', () => {

    let dir;

    beforeEach(async () => {

        dir = await mkdtemp(join(tmpdir(), 'anon-descidx-'));

    });
    afterEach(async () => {

        if (dir) await rm(dir, { recursive: true, force: true });

    });

    it('loads a single v2 descriptor from a directory and looks it up by address', async () => {

        const v2 = buildV2();
        await writeFile(join(dir, 'a.bin'), v2.bytes);
        const idx = await createDescriptorIndex({ dir });
        expect(idx.size).to.equal(1);
        expect(idx.addresses()).to.deep.equal([v2.address]);
        expect(idx.lookup(v2.address)).to.not.equal(null);
        expect(idx.lookup(v2.address).version).to.equal(0x02);

    });

    it('loads a single v3 (PQ hybrid) descriptor and indexes by v3 address', async () => {

        const v3 = buildV3();
        await writeFile(join(dir, 'b.bin'), v3.bytes);
        const idx = await createDescriptorIndex({ dir });
        expect(idx.size).to.equal(1);
        expect(idx.lookup(v3.address).version).to.equal(0x03);

    });

    it('indexes a mix of v2 and v3 descriptors by their respective addresses', async () => {

        const v2 = buildV2();
        const v3 = buildV3();
        await writeFile(join(dir, 'v2.bin'), v2.bytes);
        await writeFile(join(dir, 'v3.bin'), v3.bytes);
        const idx = await createDescriptorIndex({ dir });
        expect(idx.size).to.equal(2);
        expect(idx.lookup(v2.address).version).to.equal(0x02);
        expect(idx.lookup(v3.address).version).to.equal(0x03);

    });

    it('lookup is case-insensitive', async () => {

        const v2 = buildV2();
        await writeFile(join(dir, 'a.bin'), v2.bytes);
        const idx = await createDescriptorIndex({ dir });
        expect(idx.lookup(v2.address.toUpperCase())).to.not.equal(null);
        // also accepts the bare base32 body without the .anon suffix
        const body = v2.address.slice(0, -ONION_ADDR_SUFFIX.length);
        expect(idx.lookup(body)).to.not.equal(null);
        expect(idx.lookup(body.toUpperCase())).to.not.equal(null);

    });

    it('returns null for an unknown address', async () => {

        const v2 = buildV2();
        await writeFile(join(dir, 'a.bin'), v2.bytes);
        const idx = await createDescriptorIndex({ dir });
        // Replace the first base32 char with a known-different one to
        // produce a syntactically-valid but unindexed address.
        const replaced = (v2.address[0] === 'a' ? 'b' : 'a') + v2.address.slice(1);
        expect(idx.lookup(replaced)).to.equal(null);

    });

    it('combines explicit paths and a directory', async () => {

        const v2 = buildV2();
        const v3 = buildV3();
        const explicitPath = join(dir, 'explicit.bin');
        await writeFile(explicitPath, v2.bytes);
        const dirSub = join(dir, 'sub');
        await rm(dirSub, { recursive: true, force: true });
        await mkdtemp(join(tmpdir(), 'anon-descidx-sub-')).then(async (sub) => {

            await writeFile(join(sub, 'one.bin'), v3.bytes);
            const idx = await createDescriptorIndex({ paths: [explicitPath], dir: sub });
            expect(idx.size).to.equal(2);
            expect(idx.lookup(v2.address).version).to.equal(0x02);
            expect(idx.lookup(v3.address).version).to.equal(0x03);
            await rm(sub, { recursive: true, force: true });

        });

    });

    it('skips non-bin files and malformed files; logs the reason', async () => {

        const v2 = buildV2();
        await writeFile(join(dir, 'good.bin'),    v2.bytes);
        await writeFile(join(dir, 'bad.bin'),     Buffer.from('not a descriptor'));
        await writeFile(join(dir, 'README.txt'),  'documentation');
        const logged = [];
        const idx = await createDescriptorIndex({ dir, logger: (m) => logged.push(m) });
        expect(idx.size).to.equal(1);
        expect(idx.lookup(v2.address)).to.not.equal(null);
        expect(logged.some((m) => m.includes('bad.bin'))).to.equal(true);
        // README.txt is not *.bin and should be silently skipped (not logged)
        expect(logged.some((m) => m.includes('README.txt'))).to.equal(false);

    });

    it('drops duplicate descriptors (same onion address from two files)', async () => {

        const v2 = buildV2();
        await writeFile(join(dir, 'first.bin'),  v2.bytes);
        await writeFile(join(dir, 'second.bin'), v2.bytes);
        const logged = [];
        const idx = await createDescriptorIndex({ dir, logger: (m) => logged.push(m) });
        expect(idx.size).to.equal(1);
        expect(logged.some((m) => m.includes('duplicate'))).to.equal(true);

    });

    it('throws when zero descriptors load (empty dir)', async () => {

        let threw = null;
        try { await createDescriptorIndex({ dir }); }
        catch (e) { threw = e; }
        expect(threw).to.not.equal(null);
        expect(threw.message).to.match(/empty/i);

    });

    it('throws when the dir does not exist', async () => {

        let threw = null;
        try { await createDescriptorIndex({ dir: '/nonexistent/anon-test-dir' }); }
        catch (e) { threw = e; }
        expect(threw).to.not.equal(null);
        expect(threw.message).to.match(/not readable/i);

    });

});
