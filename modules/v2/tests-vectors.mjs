// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// Test-vector verifier: loads each test-vectors/*.json file and
// asserts the reference impl reproduces the committed expected
// outputs. Drift between this codebase and the committed JSON is a
// regression — either fix the code or regenerate the vectors via
// `node bench/generate-test-vectors.mjs` (then review the diff).

import { expect } from 'chai';
import { readFile } from 'node:fs/promises';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    CMD_PADDING, CMD_CREATE, CMD_CREATED, CMD_RELAY, CMD_DESTROY,
    CMD_LINK_HELLO, CMD_LINK_AUTH,
    buildCell,
} from './cells.mjs';
import { encodeOnionAddress } from './onion_address.mjs';
import {
    ACTION_ACCEPT, ACTION_REJECT,
    ADDR_TYPE_IPV4, ADDR_TYPE_IPV6, ADDR_TYPE_ANY,
    makeIPv4Rule, makeIPv6Rule, makeAnyRule,
    buildPolicy,
} from './exit_policy.mjs';
import { fragmentMessage } from './fragment.mjs';
import {
    RELAY_BEGIN, RELAY_DATA, RELAY_END, RELAY_CONNECTED,
    createDigestState, buildRelayPayload,
} from './relay.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = resolve(__dirname, '..', '..', 'test-vectors');

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const fromHex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));

const loadVectors = async (filename) => {

    const raw = await readFile(join(VECTORS_DIR, filename), 'utf-8');
    return JSON.parse(raw);

};

// ----- cells.json -----

describe('test-vectors/cells.json', function () {

    this.timeout(5000);

    const CMD = {
        PADDING: CMD_PADDING, CREATE: CMD_CREATE, CREATED: CMD_CREATED,
        RELAY: CMD_RELAY, DESTROY: CMD_DESTROY,
        LINK_HELLO: CMD_LINK_HELLO, LINK_AUTH: CMD_LINK_AUTH,
    };

    let doc;
    before(async () => { doc = await loadVectors('cells.json'); });

    it('every vector reproduces expectedHex', () => {

        for (const v of doc.vectors) {

            const produced = hex(buildCell({
                circuitId: v.input.circuitId,
                command: CMD[v.input.command],
                payload: fromHex(v.input.payloadHex),
            }));
            expect(produced, v.name).to.equal(v.expectedHex);

        }

    });

});

// ----- onion-address.json -----

describe('test-vectors/onion-address.json', function () {

    let doc;
    before(async () => { doc = await loadVectors('onion-address.json'); });

    it('every vector reproduces expectedAddress', () => {

        for (const v of doc.vectors) {

            const produced = encodeOnionAddress(fromHex(v.input.svcPkHex));
            expect(produced, v.name).to.equal(v.expectedAddress);

        }

    });

});

// ----- exit-policy.json -----

describe('test-vectors/exit-policy.json', function () {

    let doc;
    before(async () => { doc = await loadVectors('exit-policy.json'); });

    const ADDR = { ipv4: ADDR_TYPE_IPV4, ipv6: ADDR_TYPE_IPV6, any: ADDR_TYPE_ANY };
    const ACTION = { accept: ACTION_ACCEPT, reject: ACTION_REJECT };

    const reconstructRule = (r) => {

        if (r.addrType === 'ipv4') {

            return makeIPv4Rule({
                action: ACTION[r.action],
                net: fromHex(r.netHex),
                maskLen: r.maskLen,
                portMin: r.portMin, portMax: r.portMax,
            });

        }
        if (r.addrType === 'ipv6') {

            return makeIPv6Rule({
                action: ACTION[r.action],
                net: fromHex(r.netHex),
                maskLen: r.maskLen,
                portMin: r.portMin, portMax: r.portMax,
            });

        }
        return makeAnyRule({
            action: ACTION[r.action],
            portMin: r.portMin, portMax: r.portMax,
        });

    };

    it('every vector reproduces expectedHex', () => {

        for (const v of doc.vectors) {

            const rules = v.input.rules.map(reconstructRule);
            const produced = hex(buildPolicy(rules));
            expect(produced, v.name).to.equal(v.expectedHex);

        }

    });

});

// ----- fragment.json -----

describe('test-vectors/fragment.json', function () {

    let doc;
    before(async () => { doc = await loadVectors('fragment.json'); });

    it('every vector reproduces expectedFragmentsHex', () => {

        for (const v of doc.vectors) {

            const fragments = fragmentMessage({
                message: fromHex(v.input.messageHex),
                handshakeId: v.input.handshakeId,
                payloadCapacity: v.input.payloadCapacity,
            });
            expect(fragments.length, `${v.name} count`).to.equal(v.expectedFragmentsHex.length);
            for (let i = 0; i < fragments.length; i += 1) {

                expect(hex(fragments[i]), `${v.name} fragment ${i}`).to.equal(v.expectedFragmentsHex[i]);

            }

        }

    });

});

// ----- relay-digest.json -----

describe('test-vectors/relay-digest.json', function () {

    let doc;
    before(async () => { doc = await loadVectors('relay-digest.json'); });

    const REL = {
        BEGIN: RELAY_BEGIN, DATA: RELAY_DATA, END: RELAY_END, CONNECTED: RELAY_CONNECTED,
    };

    it('every vector reproduces per-cell digest field and full payload', () => {

        for (const v of doc.vectors) {

            const digestState = createDigestState(fromHex(v.input.K_digestHex));
            for (let i = 0; i < v.input.cells.length; i += 1) {

                const cell = v.input.cells[i];
                const payload = buildRelayPayload({
                    relayCommand: REL[cell.relayCommand],
                    streamId: cell.streamId,
                    data: fromHex(cell.dataHex),
                    digestState,
                });
                expect(hex(payload.subarray(3, 7)), `${v.name} cell ${i} digest`).to.equal(v.expected.cells[i].cellDigestHex);
                expect(hex(payload), `${v.name} cell ${i} full payload`).to.equal(v.expected.cells[i].fullPayloadHex);

            }

        }

    });

});
