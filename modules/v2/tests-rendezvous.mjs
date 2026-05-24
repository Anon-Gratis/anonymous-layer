// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

import { expect } from 'chai';

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import {
    seal,
    unseal,
    LEN_SEAL_ENVELOPE_OVERHEAD,
    LEN_SEAL_X25519_PK,
    LEN_SEAL_MLKEM_CT,
} from './sealed_box.mjs';
import {
    LEN_ESTABLISH_INTRO,
    LEN_RENDEZVOUS_COOKIE,
    LEN_INTRODUCE_INNER,
    LEN_RENDEZVOUS1,
    LEN_RENDEZVOUS2,
    INTRO_ESTABLISHED_STATUS_OK,
    RENDEZVOUS_ESTABLISHED_STATUS_OK,
    INTRODUCE_ACK_STATUS_FORWARDED,
    buildEstablishIntro,
    parseAndVerifyEstablishIntro,
    buildIntroEstablished,
    parseIntroEstablished,
    buildEstablishRendezvous,
    parseEstablishRendezvous,
    buildRendezvousEstablished,
    parseRendezvousEstablished,
    buildIntroducePayload,
    parseIntroduceEnvelope,
    unsealIntroduceInner,
    buildRendezvous1,
    parseRendezvous1,
    buildRendezvous2,
    parseRendezvous2,
    buildIntroduceAck,
    parseIntroduceAck,
} from './rendezvous.mjs';
import { generateOnion } from '../crypto/onion.mjs';
import { generateIdentity, identityFingerprint } from '../crypto/identity.mjs';
import {
    CREATE_MSG_BYTES,
    CREATED_MSG_BYTES,
    clientInit,
    relayResponse,
} from './ntor_hybrid.mjs';

// ----- Test helpers -----

const makeServiceEncKeys = () => {

    const x = generateOnion();
    const k = ml_kem768.keygen();
    return {
        x25519Pk: x.onionPk,
        x25519Sk: x.onionSk,
        mlkemPk:  k.publicKey,
        mlkemSk:  k.secretKey,
    };

};

// ----- Hybrid sealed-box -----

describe('v2/sealed_box', () => {

    it('envelope-overhead sizes match the spec', () => {

        expect(LEN_SEAL_X25519_PK).to.equal(32);
        expect(LEN_SEAL_MLKEM_CT).to.equal(1088);
        expect(LEN_SEAL_ENVELOPE_OVERHEAD).to.equal(32 + 1088 + 12 + 16); // 1148

    });

    it('round-trips a typical inner payload', () => {

        const keys = makeServiceEncKeys();
        const plaintext = new Uint8Array(1300);
        for (let i = 0; i < plaintext.length; i += 1) plaintext[i] = (i * 31 + 7) & 0xFF;
        const envelope = seal({
            plaintext,
            recipientX25519Pk: keys.x25519Pk,
            recipientMlkemPk: keys.mlkemPk,
        });
        expect(envelope.length).to.equal(LEN_SEAL_ENVELOPE_OVERHEAD + plaintext.length);
        const recovered = unseal({
            envelope,
            recipientX25519Sk: keys.x25519Sk,
            recipientMlkemSk: keys.mlkemSk,
        });
        expect(recovered).to.not.equal(null);
        expect(Buffer.from(recovered).equals(Buffer.from(plaintext))).to.equal(true);

    });

    it('unseal rejects tampered ciphertext', () => {

        const keys = makeServiceEncKeys();
        const envelope = seal({
            plaintext: new Uint8Array([1, 2, 3, 4, 5]),
            recipientX25519Pk: keys.x25519Pk,
            recipientMlkemPk: keys.mlkemPk,
        });
        const tampered = new Uint8Array(envelope);
        // Flip a byte in the ciphertext region.
        tampered[1140] ^= 0x01;
        expect(unseal({
            envelope: tampered,
            recipientX25519Sk: keys.x25519Sk,
            recipientMlkemSk: keys.mlkemSk,
        })).to.equal(null);

    });

    it('unseal rejects tampered tag', () => {

        const keys = makeServiceEncKeys();
        const envelope = seal({
            plaintext: new Uint8Array([1, 2]),
            recipientX25519Pk: keys.x25519Pk,
            recipientMlkemPk: keys.mlkemPk,
        });
        const tampered = new Uint8Array(envelope);
        tampered[tampered.length - 1] ^= 0x01;
        expect(unseal({
            envelope: tampered,
            recipientX25519Sk: keys.x25519Sk,
            recipientMlkemSk: keys.mlkemSk,
        })).to.equal(null);

    });

    it('unseal rejects with the wrong X25519 secret key', () => {

        const real = makeServiceEncKeys();
        const wrong = makeServiceEncKeys();
        const envelope = seal({
            plaintext: new Uint8Array([1, 2, 3]),
            recipientX25519Pk: real.x25519Pk,
            recipientMlkemPk: real.mlkemPk,
        });
        // Wrong X25519 sk but right ML-KEM sk — AEAD will reject.
        expect(unseal({
            envelope,
            recipientX25519Sk: wrong.x25519Sk,
            recipientMlkemSk: real.mlkemSk,
        })).to.equal(null);

    });

    it('unseal rejects with the wrong ML-KEM secret key', () => {

        const real = makeServiceEncKeys();
        const wrong = makeServiceEncKeys();
        const envelope = seal({
            plaintext: new Uint8Array([1, 2, 3]),
            recipientX25519Pk: real.x25519Pk,
            recipientMlkemPk: real.mlkemPk,
        });
        // Right X25519 but wrong ML-KEM — AEAD will reject.
        expect(unseal({
            envelope,
            recipientX25519Sk: real.x25519Sk,
            recipientMlkemSk: wrong.mlkemSk,
        })).to.equal(null);

    });

    it('unseal returns null on undersized envelope', () => {

        const keys = makeServiceEncKeys();
        expect(unseal({
            envelope: new Uint8Array(LEN_SEAL_ENVELOPE_OVERHEAD - 1),
            recipientX25519Sk: keys.x25519Sk,
            recipientMlkemSk: keys.mlkemSk,
        })).to.equal(null);

    });

    it('seal throws on wrong-sized recipient keys', () => {

        expect(() => seal({
            plaintext: new Uint8Array(1),
            recipientX25519Pk: new Uint8Array(31),
            recipientMlkemPk: new Uint8Array(1184),
        })).to.throw();
        expect(() => seal({
            plaintext: new Uint8Array(1),
            recipientX25519Pk: new Uint8Array(32),
            recipientMlkemPk: new Uint8Array(1183),
        })).to.throw();

    });

});

// ----- ESTABLISH_INTRO -----

describe('v2/rendezvous — ESTABLISH_INTRO', () => {

    it('round-trip + verify with the right IP fingerprint', () => {

        const introKey = generateIdentity(); // (idSk, idPk) → use as service_intro key
        const ipId = generateIdentity();
        const ipFp = identityFingerprint(ipId.idPk);
        const now = 1_700_000_000;
        const payload = buildEstablishIntro({
            serviceIntroPk: introKey.idPk,
            serviceIntroSk: introKey.idSk,
            ipFingerprint: ipFp,
            publishEpoch: now,
        });
        expect(payload.length).to.equal(LEN_ESTABLISH_INTRO);
        const parsed = parseAndVerifyEstablishIntro({
            payload,
            ipFingerprint: ipFp,
            nowEpoch: now + 60,
        });
        expect(parsed).to.not.equal(null);
        expect(parsed.publishEpoch).to.equal(now);
        expect(Buffer.from(parsed.serviceIntroPk).equals(Buffer.from(introKey.idPk))).to.equal(true);

    });

    it('rejects when the receiver substitutes a different IP fingerprint', () => {

        const introKey = generateIdentity();
        const intendedIp = identityFingerprint(generateIdentity().idPk);
        const otherIp = identityFingerprint(generateIdentity().idPk);
        const now = 1_700_000_000;
        const payload = buildEstablishIntro({
            serviceIntroPk: introKey.idPk,
            serviceIntroSk: introKey.idSk,
            ipFingerprint: intendedIp,
            publishEpoch: now,
        });
        // Receiver who is otherIp verifying with their own fp — signature
        // doesn't cover otherIp, so this MUST fail. Defends against an
        // attacker who tries to replay ESTABLISH_INTRO at a different IP.
        expect(parseAndVerifyEstablishIntro({
            payload,
            ipFingerprint: otherIp,
            nowEpoch: now + 60,
        })).to.equal(null);

    });

    it('rejects stale ESTABLISH_INTRO (replay defence)', () => {

        const introKey = generateIdentity();
        const ipFp = identityFingerprint(generateIdentity().idPk);
        const now = 1_700_000_000;
        const payload = buildEstablishIntro({
            serviceIntroPk: introKey.idPk,
            serviceIntroSk: introKey.idSk,
            ipFingerprint: ipFp,
            publishEpoch: now,
        });
        expect(parseAndVerifyEstablishIntro({
            payload,
            ipFingerprint: ipFp,
            nowEpoch: now + 7200, // 2h later, default maxAge 1h
        })).to.equal(null);

    });

    it('rejects future-dated ESTABLISH_INTRO', () => {

        const introKey = generateIdentity();
        const ipFp = identityFingerprint(generateIdentity().idPk);
        const now = 1_700_000_000;
        const payload = buildEstablishIntro({
            serviceIntroPk: introKey.idPk,
            serviceIntroSk: introKey.idSk,
            ipFingerprint: ipFp,
            publishEpoch: now + 300, // 5 minutes in the future
        });
        expect(parseAndVerifyEstablishIntro({
            payload,
            ipFingerprint: ipFp,
            nowEpoch: now,
        })).to.equal(null);

    });

    it('rejects signature forgery', () => {

        const introKey = generateIdentity();
        const ipFp = identityFingerprint(generateIdentity().idPk);
        const now = 1_700_000_000;
        const payload = buildEstablishIntro({
            serviceIntroPk: introKey.idPk,
            serviceIntroSk: introKey.idSk,
            ipFingerprint: ipFp,
            publishEpoch: now,
        });
        const tampered = new Uint8Array(payload);
        tampered[payload.length - 1] ^= 0x01;
        expect(parseAndVerifyEstablishIntro({
            payload: tampered,
            ipFingerprint: ipFp,
            nowEpoch: now,
        })).to.equal(null);

    });

});

// ----- Simple ack/cookie cells -----

describe('v2/rendezvous — small payload codecs', () => {

    it('INTRO_ESTABLISHED round-trip', () => {

        const payload = buildIntroEstablished(INTRO_ESTABLISHED_STATUS_OK);
        expect(payload.length).to.equal(1);
        expect(parseIntroEstablished(payload).status).to.equal(INTRO_ESTABLISHED_STATUS_OK);
        expect(parseIntroEstablished(new Uint8Array(2))).to.equal(null);

    });

    it('ESTABLISH_RENDEZVOUS round-trip preserves the 20-byte cookie', () => {

        const cookie = new Uint8Array(LEN_RENDEZVOUS_COOKIE);
        for (let i = 0; i < cookie.length; i += 1) cookie[i] = i * 13 + 1;
        const payload = buildEstablishRendezvous(cookie);
        const parsed = parseEstablishRendezvous(payload);
        expect(parsed).to.not.equal(null);
        expect(Buffer.from(parsed.cookie).equals(Buffer.from(cookie))).to.equal(true);

    });

    it('ESTABLISH_RENDEZVOUS rejects wrong cookie length', () => {

        expect(parseEstablishRendezvous(new Uint8Array(19))).to.equal(null);
        expect(parseEstablishRendezvous(new Uint8Array(21))).to.equal(null);

    });

    it('RENDEZVOUS_ESTABLISHED round-trip', () => {

        expect(parseRendezvousEstablished(
            buildRendezvousEstablished(RENDEZVOUS_ESTABLISHED_STATUS_OK),
        ).status).to.equal(RENDEZVOUS_ESTABLISHED_STATUS_OK);

    });

    it('INTRODUCE_ACK round-trip', () => {

        expect(parseIntroduceAck(
            buildIntroduceAck(INTRODUCE_ACK_STATUS_FORWARDED),
        ).status).to.equal(INTRODUCE_ACK_STATUS_FORWARDED);

    });

});

// ----- INTRODUCE1 / INTRODUCE2 with sealing -----

describe('v2/rendezvous — INTRODUCE1 / INTRODUCE2', () => {

    it('full end-to-end seal → IP-forwards → service-unseals', () => {

        const introKey = generateIdentity(); // serviceIntroPk
        const enc = makeServiceEncKeys();
        const ntor = clientInit();
        const cookie = new Uint8Array(LEN_RENDEZVOUS_COOKIE).fill(0xAB);
        const rpFp = identityFingerprint(generateIdentity().idPk);
        const rpOnion = generateOnion().onionPk;

        const payload = buildIntroducePayload({
            serviceIntroPk: introKey.idPk,
            serviceEncX25519Pk: enc.x25519Pk,
            serviceEncMlkemPk: enc.mlkemPk,
            cookie,
            rpFingerprint: rpFp,
            rpOnionPk: rpOnion,
            handshakeMessage: ntor.createMsg,
        });
        // 32 (intro key) + 1148 (overhead) + 1300 (inner) = 2480
        expect(payload.length).to.equal(32 + LEN_SEAL_ENVELOPE_OVERHEAD + LEN_INTRODUCE_INNER);

        // IP-side parse — sees outer envelope only.
        const envelope = parseIntroduceEnvelope(payload);
        expect(envelope).to.not.equal(null);
        expect(Buffer.from(envelope.serviceIntroPk).equals(Buffer.from(introKey.idPk))).to.equal(true);

        // Service-side unseal.
        const inner = unsealIntroduceInner({
            sealedEnvelope: envelope.sealedEnvelope,
            serviceEncX25519Sk: enc.x25519Sk,
            serviceEncMlkemSk: enc.mlkemSk,
        });
        expect(inner).to.not.equal(null);
        expect(Buffer.from(inner.cookie).equals(Buffer.from(cookie))).to.equal(true);
        expect(Buffer.from(inner.rpFingerprint).equals(Buffer.from(rpFp))).to.equal(true);
        expect(Buffer.from(inner.handshakeMessage).equals(Buffer.from(ntor.createMsg))).to.equal(true);

    });

    it('the IP CANNOT read the inner payload (wrong keys → null)', () => {

        const introKey = generateIdentity();
        const enc = makeServiceEncKeys();
        const ntor = clientInit();
        const cookie = new Uint8Array(LEN_RENDEZVOUS_COOKIE);
        const rpFp = identityFingerprint(generateIdentity().idPk);
        const rpOnion = generateOnion().onionPk;

        const payload = buildIntroducePayload({
            serviceIntroPk: introKey.idPk,
            serviceEncX25519Pk: enc.x25519Pk,
            serviceEncMlkemPk: enc.mlkemPk,
            cookie, rpFingerprint: rpFp, rpOnionPk: rpOnion,
            handshakeMessage: ntor.createMsg,
        });
        const envelope = parseIntroduceEnvelope(payload);

        // The IP doesn't have the service's enc secrets — it cannot
        // unseal the envelope even with its own X25519 onion key.
        const ipOwnKeys = makeServiceEncKeys();
        expect(unsealIntroduceInner({
            sealedEnvelope: envelope.sealedEnvelope,
            serviceEncX25519Sk: ipOwnKeys.x25519Sk,
            serviceEncMlkemSk: ipOwnKeys.mlkemSk,
        })).to.equal(null);

    });

    it('rejects undersized INTRODUCE1 payload at the envelope parser', () => {

        expect(parseIntroduceEnvelope(new Uint8Array(100))).to.equal(null);

    });

});

// ----- RENDEZVOUS1 / RENDEZVOUS2 -----

describe('v2/rendezvous — RENDEZVOUS1 / RENDEZVOUS2', () => {

    it('RENDEZVOUS1 round-trip', () => {

        // Generate a real CREATED message via ntor-hybrid.
        const ntor = clientInit();
        const relayId = generateIdentity();
        const relayOnion = generateOnion();
        const resp = relayResponse({
            createMsg: ntor.createMsg,
            B_sk: relayOnion.onionSk,
            B_pk: relayOnion.onionPk,
            ID_R: identityFingerprint(relayId.idPk),
        });
        const cookie = new Uint8Array(LEN_RENDEZVOUS_COOKIE).fill(0xC0);
        const payload = buildRendezvous1({ cookie, handshakeResponse: resp.createdMsg });
        expect(payload.length).to.equal(LEN_RENDEZVOUS1);
        const parsed = parseRendezvous1(payload);
        expect(parsed).to.not.equal(null);
        expect(Buffer.from(parsed.cookie).equals(Buffer.from(cookie))).to.equal(true);
        expect(parsed.handshakeResponse.length).to.equal(CREATED_MSG_BYTES);

    });

    it('RENDEZVOUS2 round-trip (no cookie, just the handshake)', () => {

        const ntor = clientInit();
        const relayId = generateIdentity();
        const relayOnion = generateOnion();
        const resp = relayResponse({
            createMsg: ntor.createMsg,
            B_sk: relayOnion.onionSk,
            B_pk: relayOnion.onionPk,
            ID_R: identityFingerprint(relayId.idPk),
        });
        const payload = buildRendezvous2(resp.createdMsg);
        expect(payload.length).to.equal(LEN_RENDEZVOUS2);
        const parsed = parseRendezvous2(payload);
        expect(parsed.handshakeResponse.length).to.equal(CREATED_MSG_BYTES);

    });

    it('RENDEZVOUS2 strips the cookie — the client never sees it', () => {

        // The client uses RENDEZVOUS2 to derive session keys via ntor
        // finish, but it never learns which cookie matched on the RP
        // side. The cookie was the client's own secret to share with
        // the RP via ESTABLISH_RENDEZVOUS; it isn't carried back.
        const ntor = clientInit();
        const relayId = generateIdentity();
        const relayOnion = generateOnion();
        const resp = relayResponse({
            createMsg: ntor.createMsg,
            B_sk: relayOnion.onionSk,
            B_pk: relayOnion.onionPk,
            ID_R: identityFingerprint(relayId.idPk),
        });
        const payload = buildRendezvous2(resp.createdMsg);
        expect(payload.length).to.equal(CREATED_MSG_BYTES); // no cookie
        // (RENDEZVOUS1 is 20 bytes longer.)

    });

    it('parsers reject wrong-sized inputs', () => {

        expect(parseRendezvous1(new Uint8Array(LEN_RENDEZVOUS1 - 1))).to.equal(null);
        expect(parseRendezvous2(new Uint8Array(LEN_RENDEZVOUS2 - 1))).to.equal(null);

    });

});
