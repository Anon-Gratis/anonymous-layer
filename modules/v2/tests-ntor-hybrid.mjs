// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

import { expect } from 'chai';

import {
    CREATE_MSG_BYTES,
    CREATED_MSG_BYTES,
    MLKEM_PK_BYTES,
    MLKEM_CT_BYTES,
    NTOR_AUTH_BYTES,
    clientInit,
    relayResponse,
    clientFinish,
    deriveHopKeys,
} from './ntor_hybrid.mjs';
import { generateOnion } from '../crypto/onion.mjs';
import { generateIdentity, identityFingerprint } from '../crypto/identity.mjs';

const makeRelay = () => {

    const id = generateIdentity();
    const onion = generateOnion();
    return {
        ID_R: identityFingerprint(id.idPk),
        B_sk: onion.onionSk,
        B_pk: onion.onionPk,
    };

};

describe('v2/ntor_hybrid — sizes', () => {

    it('CREATE message is X (32) + K_pk (1184) = 1216 bytes', () => {

        expect(CREATE_MSG_BYTES).to.equal(1216);
        expect(MLKEM_PK_BYTES).to.equal(1184);

    });

    it('CREATED message is Y (32) + ct (1088) + AUTH (32) = 1152 bytes', () => {

        expect(CREATED_MSG_BYTES).to.equal(1152);
        expect(MLKEM_CT_BYTES).to.equal(1088);

    });

});

describe('v2/ntor_hybrid — handshake', () => {

    it('round-trip: client and relay derive matching KEY_SEED', () => {

        const relay = makeRelay();
        const ntorState = clientInit();
        expect(ntorState.createMsg.length).to.equal(CREATE_MSG_BYTES);

        const response = relayResponse({
            createMsg: ntorState.createMsg,
            B_sk: relay.B_sk,
            B_pk: relay.B_pk,
            ID_R: relay.ID_R,
        });
        expect(response).to.not.equal(null);
        expect(response.createdMsg.length).to.equal(CREATED_MSG_BYTES);
        expect(response.KEY_SEED.length).to.equal(32);

        const clientKeySeed = clientFinish({
            ntorState,
            B_pk: relay.B_pk,
            ID_R: relay.ID_R,
            createdMsg: response.createdMsg,
        });
        expect(clientKeySeed).to.not.equal(null);
        expect(Buffer.from(clientKeySeed).equals(Buffer.from(response.KEY_SEED))).to.equal(true);

    });

    it('rejects tampered AUTH', () => {

        const relay = makeRelay();
        const ntorState = clientInit();
        const response = relayResponse({
            createMsg: ntorState.createMsg,
            B_sk: relay.B_sk,
            B_pk: relay.B_pk,
            ID_R: relay.ID_R,
        });
        const tampered = new Uint8Array(response.createdMsg);
        // AUTH is the last 32 bytes.
        tampered[tampered.length - 1] ^= 0x01;
        expect(clientFinish({
            ntorState,
            B_pk: relay.B_pk,
            ID_R: relay.ID_R,
            createdMsg: tampered,
        })).to.equal(null);

    });

    it('rejects tampered ct (KEM decapsulation produces different shared_pq)', () => {

        const relay = makeRelay();
        const ntorState = clientInit();
        const response = relayResponse({
            createMsg: ntorState.createMsg,
            B_sk: relay.B_sk,
            B_pk: relay.B_pk,
            ID_R: relay.ID_R,
        });
        const tampered = new Uint8Array(response.createdMsg);
        // ct lives at offset 32 to 32+1088. Flip one byte.
        tampered[100] ^= 0x01;
        // Decapsulation will likely succeed but produce a DIFFERENT
        // shared_pq → AUTH won't match.
        expect(clientFinish({
            ntorState,
            B_pk: relay.B_pk,
            ID_R: relay.ID_R,
            createdMsg: tampered,
        })).to.equal(null);

    });

    it('rejects impersonation: wrong B_pk', () => {

        const realRelay = makeRelay();
        const impostor = makeRelay();
        const ntorState = clientInit();
        const response = relayResponse({
            createMsg: ntorState.createMsg,
            B_sk: realRelay.B_sk,
            B_pk: realRelay.B_pk,
            ID_R: realRelay.ID_R,
        });
        // Client believes it's talking to impostor.
        expect(clientFinish({
            ntorState,
            B_pk: impostor.B_pk,
            ID_R: realRelay.ID_R,
            createdMsg: response.createdMsg,
        })).to.equal(null);

    });

    it('rejects wrong ID_R fingerprint', () => {

        const realRelay = makeRelay();
        const other = makeRelay();
        const ntorState = clientInit();
        const response = relayResponse({
            createMsg: ntorState.createMsg,
            B_sk: realRelay.B_sk,
            B_pk: realRelay.B_pk,
            ID_R: realRelay.ID_R,
        });
        expect(clientFinish({
            ntorState,
            B_pk: realRelay.B_pk,
            ID_R: other.ID_R,
            createdMsg: response.createdMsg,
        })).to.equal(null);

    });

    it('rejects malformed CREATE on the relay side', () => {

        const relay = makeRelay();
        expect(relayResponse({
            createMsg: new Uint8Array(CREATE_MSG_BYTES - 1),
            B_sk: relay.B_sk,
            B_pk: relay.B_pk,
            ID_R: relay.ID_R,
        })).to.equal(null);

    });

    it('rejects malformed CREATED on the client side', () => {

        const relay = makeRelay();
        const ntorState = clientInit();
        expect(clientFinish({
            ntorState,
            B_pk: relay.B_pk,
            ID_R: relay.ID_R,
            createdMsg: new Uint8Array(CREATED_MSG_BYTES - 1),
        })).to.equal(null);

    });

    it('low-order X25519 point in CREATE aborts the handshake', () => {

        const relay = makeRelay();
        const ntorState = clientInit();
        // Replace X (first 32 bytes of createMsg) with the all-zero
        // low-order point.
        const malformedCreate = new Uint8Array(ntorState.createMsg);
        for (let i = 0; i < 32; i += 1) malformedCreate[i] = 0;
        expect(relayResponse({
            createMsg: malformedCreate,
            B_sk: relay.B_sk,
            B_pk: relay.B_pk,
            ID_R: relay.ID_R,
        })).to.equal(null);

    });

    it('two independent handshakes derive distinct KEY_SEEDs', () => {

        const relay = makeRelay();
        const a = clientInit();
        const b = clientInit();
        const ra = relayResponse({ createMsg: a.createMsg, B_sk: relay.B_sk, B_pk: relay.B_pk, ID_R: relay.ID_R });
        const rb = relayResponse({ createMsg: b.createMsg, B_sk: relay.B_sk, B_pk: relay.B_pk, ID_R: relay.ID_R });
        expect(Buffer.from(ra.KEY_SEED).equals(Buffer.from(rb.KEY_SEED))).to.equal(false);

    });

});

describe('v2/ntor_hybrid — key derivation', () => {

    it('deriveHopKeys returns four distinct 32-byte keys', () => {

        const relay = makeRelay();
        const ntorState = clientInit();
        const response = relayResponse({
            createMsg: ntorState.createMsg,
            B_sk: relay.B_sk,
            B_pk: relay.B_pk,
            ID_R: relay.ID_R,
        });
        const keys = deriveHopKeys(response.KEY_SEED);
        expect(keys.Kf.length).to.equal(32);
        expect(keys.Kb.length).to.equal(32);
        expect(keys.Kdf.length).to.equal(32);
        expect(keys.Kdb.length).to.equal(32);
        // Mutually distinct.
        const all = [keys.Kf, keys.Kb, keys.Kdf, keys.Kdb];
        for (let i = 0; i < all.length; i += 1) {

            for (let j = i + 1; j < all.length; j += 1) {

                expect(Buffer.from(all[i]).equals(Buffer.from(all[j]))).to.equal(false);

            }

        }

    });

});
