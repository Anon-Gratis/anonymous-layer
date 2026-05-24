#!/usr/bin/env node
// Receive-path timing measurement.
//
// SPEC § 9.2 mandates that the time to process a packet be statistically
// indistinguishable across accept/reject outcomes (modulo measurement
// noise). This script runs each receive-path failure mode and the
// success path through `decodePacket` many times and reports
// p50/p95/p99/max latencies. It is NOT a CI test — timing tests are
// inherently flaky — it is a developer/operator tool that produces the
// data needed to decide whether the current implementation is § 9.2-
// compliant or whether a blinding delay is needed.
//
// Usage: node bench/timing.mjs [iterations]
// Default iterations: 5000 per case.

import { createNodeIdentity } from '../modules/node/identity.mjs';
import { encodePacket, decodePacket } from '../modules/wire/packet.mjs';
import { buildDataPayload } from '../modules/wire/data.mjs';
import { TYPE_DATA, BUCKET_SIZE_SMALL } from '../modules/wire/constants.mjs';
import { createReplayLog } from '../modules/wire/replay.mjs';

const ITERATIONS = parseInt(process.argv[2] || '5000', 10);

const sender = createNodeIdentity();
const recipient = createNodeIdentity();
const stranger = createNodeIdentity();

// Helper: build a valid packet from sender → recipient.
const buildValid = (extraPayload = new Uint8Array([1, 2, 3, 4])) => encodePacket({
    recipientIdPk: recipient.idPk,
    recipientOnionPk: recipient.onionPk,
    senderFingerprint: sender.fingerprint,
    packetType: TYPE_DATA,
    payload: buildDataPayload({
        conversationTag: new Uint8Array(16),
        sequenceNumber: 0n,
        payload: extraPayload,
    }),
});

const opts = { myIdPk: recipient.idPk, myOnionSk: recipient.onionSk };

// Failure-mode generators — each returns a fresh packet per call.
const cases = {
    'success                ': () => buildValid(),
    'wrong-length-undersized': () => new Uint8Array(100),
    'wrong-length-non-bucket': () => new Uint8Array(BUCKET_SIZE_SMALL + 1),
    'wrong-version          ': () => {

        const p = buildValid();
        p[0] = 0x02;
        return p;

    },
    'bucket-length-mismatch ': () => {

        const p = buildValid();
        p[1] = 0x02; // BUCKET_MEDIUM but length is 256 bytes
        return p;

    },
    'prefix-mismatch        ': () => {

        // Packet addressed to stranger but offered to recipient.
        return encodePacket({
            recipientIdPk: stranger.idPk,
            recipientOnionPk: stranger.onionPk,
            senderFingerprint: sender.fingerprint,
            packetType: TYPE_DATA,
            payload: buildDataPayload({
                conversationTag: new Uint8Array(16),
                sequenceNumber: 0n,
                payload: new Uint8Array([1, 2]),
            }),
        });

    },
    'aead-tamper            ': () => {

        const p = buildValid();
        // Flip a byte inside the ciphertext (post-header).
        p[100] ^= 0x01;
        return p;

    },
    'padding-fail           ': () => {

        // Need a packet whose AEAD passes but padding check fails.
        // Easiest: encrypt + decrypt our own packet, manipulate the
        // inner plaintext, re-encrypt. But we don't expose encrypt-with-
        // explicit-key APIs. Skip this one for now — the AEAD-tamper
        // case dominates the post-AEAD timing anyway.
        return null;

    },
    'replay                 ': () => {

        // Pre-built packet that's already in the replay log.
        return null; // handled specially below

    },
};

// For replay we keep ONE packet and a populated replay log, then
// decodePacket it every iteration.
const replayPacket = buildValid();
const replayLog = createReplayLog();
decodePacket(replayPacket, { ...opts, replayLog });

const percentile = (sortedNanos, p) => {

    const idx = Math.min(sortedNanos.length - 1, Math.floor((p / 100) * sortedNanos.length));
    return sortedNanos[idx];

};

const measure = (label, gen, n) => {

    // Warm-up to give V8 a chance to JIT.
    for (let i = 0; i < 100; i += 1) {

        const p = gen();
        if (p !== null) decodePacket(p, opts);

    }

    const samples = new Float64Array(n);
    for (let i = 0; i < n; i += 1) {

        const p = gen();
        if (p === null) {

            samples[i] = NaN;
            continue;

        }
        const t0 = process.hrtime.bigint();
        decodePacket(p, opts);
        const t1 = process.hrtime.bigint();
        samples[i] = Number(t1 - t0);

    }
    return { label, samples };

};

const measureReplay = (n) => {

    for (let i = 0; i < 100; i += 1) {

        decodePacket(replayPacket, { ...opts, replayLog });

    }
    const samples = new Float64Array(n);
    for (let i = 0; i < n; i += 1) {

        const t0 = process.hrtime.bigint();
        decodePacket(replayPacket, { ...opts, replayLog });
        const t1 = process.hrtime.bigint();
        samples[i] = Number(t1 - t0);

    }
    return { label: 'replay                 ', samples };

};

const report = ({ label, samples }) => {

    const filtered = Array.from(samples).filter((s) => !Number.isNaN(s)).sort((a, b) => a - b);
    if (filtered.length === 0) {

        process.stdout.write(`${label}  (skipped)\n`);
        return;

    }
    const p50 = percentile(filtered, 50);
    const p95 = percentile(filtered, 95);
    const p99 = percentile(filtered, 99);
    const max = filtered[filtered.length - 1];
    const mean = filtered.reduce((a, b) => a + b, 0) / filtered.length;
    const fmt = (ns) => `${(ns / 1000).toFixed(1).padStart(8)} µs`;
    process.stdout.write(
        `${label}  n=${filtered.length}  p50=${fmt(p50)}  `
        + `p95=${fmt(p95)}  p99=${fmt(p99)}  mean=${fmt(mean)}  max=${fmt(max)}\n`,
    );

};

process.stdout.write(`# decodePacket timing — ${ITERATIONS} iterations per case\n`);
process.stdout.write(`# node ${process.version}, platform ${process.platform}\n`);
process.stdout.write('\n');
for (const [label, gen] of Object.entries(cases)) {

    if (label.startsWith('replay')) continue;
    if (gen() === null) continue; // skipped
    report(measure(label, gen, ITERATIONS));

}
report(measureReplay(ITERATIONS));
process.stdout.write('\n');
process.stdout.write('# Note: timings include the function call boundary + GC pauses.\n');
process.stdout.write('# Pre-AEAD failures (length, version, bucket, prefix) skip the\n');
process.stdout.write('# X25519 + AEAD steps and are observably faster than post-AEAD\n');
process.stdout.write('# outcomes (success, AEAD-tamper, replay). § 9.2 compliance would\n');
process.stdout.write('# require either approach (1) — always run AEAD — or approach (2) —\n');
process.stdout.write('# blinding delay on the fast paths. Phase 5 hardening decision.\n');
