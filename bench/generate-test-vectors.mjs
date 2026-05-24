#!/usr/bin/env node
// Generate the canonical test-vector JSON files under test-vectors/.
//
// Usage:
//   node bench/generate-test-vectors.mjs
//
// Inputs live INSIDE this script (hardcoded). Outputs are the JSON
// files committed in test-vectors/. Re-running regenerates from the
// inputs; the diff should be reviewed if the spec or reference impl
// changes.
//
// modules/v2/tests-vectors.mjs reads the committed JSON and asserts
// the reference impl matches — drift between the two is a regression.

import { writeFile, mkdir } from 'node:fs/promises';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    CMD_PADDING, CMD_CREATE, CMD_CREATED, CMD_RELAY, CMD_DESTROY,
    CMD_LINK_HELLO, CMD_LINK_AUTH,
    LEN_CELL_PAYLOAD,
    buildCell,
} from '../modules/v2/cells.mjs';
import {
    encodeOnionAddress,
} from '../modules/v2/onion_address.mjs';
import {
    ACTION_ACCEPT, ACTION_REJECT,
    ADDR_TYPE_IPV4, ADDR_TYPE_IPV6, ADDR_TYPE_ANY,
    POLICY_REJECT_ALL, POLICY_REDUCED_EXIT, POLICY_STANDARD_EXIT,
    makeIPv4Rule, makeIPv6Rule, makeAnyRule,
    buildPolicy,
} from '../modules/v2/exit_policy.mjs';
import {
    fragmentMessage,
    FRAGMENT_PAYLOAD_CAPACITY,
    LEN_FRAGMENT_HEADER,
} from '../modules/v2/fragment.mjs';
import {
    RELAY_BEGIN, RELAY_DATA, RELAY_END, RELAY_CONNECTED,
    MAX_RELAY_DATA,
    createDigestState,
    buildRelayPayload,
} from '../modules/v2/relay.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = resolve(__dirname, '..', 'test-vectors');

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const fromHex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));

const writeVectors = async (filename, content) => {

    const path = join(VECTORS_DIR, filename);
    await writeFile(path, `${JSON.stringify(content, null, 2)}\n`);
    process.stderr.write(`  wrote ${filename}  (${content.vectors.length} vectors)\n`);

};

// ----- cells.json -----

const generateCellsVectors = () => {

    const cmdLookup = {
        PADDING: CMD_PADDING, CREATE: CMD_CREATE, CREATED: CMD_CREATED,
        RELAY: CMD_RELAY, DESTROY: CMD_DESTROY,
        LINK_HELLO: CMD_LINK_HELLO, LINK_AUTH: CMD_LINK_AUTH,
    };

    const inputs = [
        {
            name: 'PADDING cell, zero circuit_id, zero payload',
            circuitId: 0, command: 'PADDING',
            payloadHex: '00'.repeat(LEN_CELL_PAYLOAD),
        },
        {
            name: 'CREATE cell, circuit_id 1, zero payload',
            circuitId: 1, command: 'CREATE',
            payloadHex: '00'.repeat(LEN_CELL_PAYLOAD),
        },
        {
            name: 'CREATED cell, circuit_id 0x12345678, payload pattern',
            circuitId: 0x12345678, command: 'CREATED',
            payloadHex: 'ab'.repeat(LEN_CELL_PAYLOAD),
        },
        {
            name: 'RELAY cell, client-side circuit_id (high bit set)',
            circuitId: 0x80000001, command: 'RELAY',
            payloadHex: '01'.repeat(LEN_CELL_PAYLOAD),
        },
        {
            name: 'DESTROY cell, max circuit_id',
            circuitId: 0xFFFFFFFF, command: 'DESTROY',
            payloadHex: '00'.repeat(LEN_CELL_PAYLOAD),
        },
        {
            name: 'LINK_HELLO cell (link cells use circuit_id 0)',
            circuitId: 0, command: 'LINK_HELLO',
            payloadHex: '00'.repeat(64) + 'ff'.repeat(LEN_CELL_PAYLOAD - 64),
        },
        {
            name: 'LINK_AUTH cell',
            circuitId: 0, command: 'LINK_AUTH',
            payloadHex: 'de'.repeat(LEN_CELL_PAYLOAD),
        },
    ];

    const vectors = inputs.map((v) => ({
        name: v.name,
        input: {
            circuitId: v.circuitId,
            command: v.command,
            payloadHex: v.payloadHex,
        },
        expectedHex: hex(buildCell({
            circuitId: v.circuitId,
            command: cmdLookup[v.command],
            payload: fromHex(v.payloadHex),
        })),
    }));

    return {
        description: 'Cell wire format (SPEC § 5.2). buildCell({circuitId, command, payload}) → 514-byte cell. Format: version(1)=0x02 || circuit_id(4 BE) || command(1) || payload(508).',
        version: 1,
        vectors,
    };

};

// ----- onion-address.json -----

const generateOnionAddressVectors = () => {

    const inputs = [
        { name: 'all-zero SVC_pk', svcPkHex: '00'.repeat(32) },
        { name: 'all-ones SVC_pk', svcPkHex: 'ff'.repeat(32) },
        { name: 'SVC_pk filled with 0xA5', svcPkHex: 'a5'.repeat(32) },
        {
            name: 'SVC_pk: incrementing bytes 0..31',
            svcPkHex: Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, '0')).join(''),
        },
        {
            name: 'SVC_pk: derived from "anon-layer test vector 0"',
            svcPkHex: '37f4f3ca0c7d9e2c3f5b8a4e9d6c1b4f72e8a5b9d3c7f2a1b6e4d8c5f3a9b7c4',
        },
    ];

    const vectors = inputs.map((v) => ({
        name: v.name,
        input: { svcPkHex: v.svcPkHex },
        expectedAddress: encodeOnionAddress(fromHex(v.svcPkHex)),
    }));

    return {
        description: 'Onion address encoding (SPEC § 4.4). encodeOnionAddress(SVC_pk) → "<56 base32 lowercase chars>.anon" where the 35-byte body is SVC_pk(32) || checksum(2) || version(1=0x02), checksum = Blake2b-256(".anon-checksum" || SVC_pk || VERSION)[0:2].',
        version: 1,
        vectors,
    };

};

// ----- exit-policy.json -----

const generateExitPolicyVectors = () => {

    const inputs = [
        {
            name: 'POLICY_REJECT_ALL (zero rules)',
            rules: [],
        },
        {
            name: 'single ANY rule: accept port 443',
            rules: [makeAnyRule({ action: ACTION_ACCEPT, portMin: 443, portMax: 443 })],
        },
        {
            name: 'single IPv4 rule: reject 10.0.0.0/8 ports 0-65535',
            rules: [makeIPv4Rule({
                action: ACTION_REJECT,
                net: Uint8Array.from([10, 0, 0, 0]),
                maskLen: 8, portMin: 0, portMax: 65535,
            })],
        },
        {
            name: 'single IPv6 rule: accept 2001:db8::/32 port 443',
            rules: [makeIPv6Rule({
                action: ACTION_ACCEPT,
                net: Uint8Array.from([
                    0x20, 0x01, 0x0d, 0xb8,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]),
                maskLen: 32, portMin: 443, portMax: 443,
            })],
        },
        {
            name: 'reduced-exit preset',
            rules: POLICY_REDUCED_EXIT,
        },
        {
            name: 'standard-exit preset',
            rules: POLICY_STANDARD_EXIT,
        },
        {
            name: 'mixed: accept HTTPS, reject everything else',
            rules: [
                makeAnyRule({ action: ACTION_ACCEPT, portMin: 443, portMax: 443 }),
                makeAnyRule({ action: ACTION_REJECT, portMin: 0, portMax: 65535 }),
            ],
        },
    ];

    const vectors = inputs.map((v, i) => {

        const desc = v.rules.map((r) => ({
            action: r.action === ACTION_ACCEPT ? 'accept' : 'reject',
            addrType: r.addrType === ADDR_TYPE_IPV4 ? 'ipv4'
                : r.addrType === ADDR_TYPE_IPV6 ? 'ipv6'
                : 'any',
            netHex: r.net ? hex(r.net) : null,
            maskLen: r.maskLen,
            portMin: r.portMin,
            portMax: r.portMax,
        }));
        return {
            name: v.name,
            input: { rules: desc },
            expectedHex: hex(buildPolicy(v.rules)),
        };

    });

    return {
        description: 'Exit policy codec (SPEC § 8.1). Each rule = action(1) || addr_type(1) || addr_prefix(varies, see § 8.1) || port_min(2 BE) || port_max(2 BE). Multiple rules concatenated. Empty array = POLICY_REJECT_ALL.',
        version: 1,
        vectors,
    };

};

// ----- fragment.json -----

const generateFragmentVectors = () => {

    const inputs = [
        {
            name: 'single-byte message, default cell capacity',
            messageHex: '42',
            handshakeId: 0x12345678,
            payloadCapacity: FRAGMENT_PAYLOAD_CAPACITY,
        },
        {
            name: 'exactly one full fragment at default capacity',
            messageHex: 'ab'.repeat(FRAGMENT_PAYLOAD_CAPACITY),
            handshakeId: 0xCAFEBABE,
            payloadCapacity: FRAGMENT_PAYLOAD_CAPACITY,
        },
        {
            name: 'one full fragment + 1 byte = 2 fragments',
            messageHex: 'cd'.repeat(FRAGMENT_PAYLOAD_CAPACITY) + 'ef',
            handshakeId: 0xDEADBEEF,
            payloadCapacity: FRAGMENT_PAYLOAD_CAPACITY,
        },
        {
            name: 'hybrid CREATE message (1216 bytes) at cell capacity = 3 fragments',
            messageHex: Array.from({ length: 1216 }, (_, i) => (i & 0xFF).toString(16).padStart(2, '0')).join(''),
            handshakeId: 1,
            payloadCapacity: FRAGMENT_PAYLOAD_CAPACITY,
        },
        {
            name: 'hybrid CREATED message (1152 bytes) at RELAY capacity = 3 fragments',
            messageHex: Array.from({ length: 1152 }, (_, i) => ((i * 7) & 0xFF).toString(16).padStart(2, '0')).join(''),
            handshakeId: 42,
            payloadCapacity: MAX_RELAY_DATA - LEN_FRAGMENT_HEADER,
        },
    ];

    const vectors = inputs.map((v) => {

        const fragments = fragmentMessage({
            message: fromHex(v.messageHex),
            handshakeId: v.handshakeId,
            payloadCapacity: v.payloadCapacity,
        });
        return {
            name: v.name,
            input: {
                messageHex: v.messageHex,
                handshakeId: v.handshakeId,
                payloadCapacity: v.payloadCapacity,
            },
            expectedFragmentsHex: fragments.map(hex),
        };

    });

    return {
        description: 'Multi-cell handshake fragmentation (SPEC § 6.2.1). fragmentMessage({message, handshakeId, payloadCapacity}) → array of fragment buffers, each `payloadCapacity + 8` bytes. Fragment header: fragment_index(1) || fragment_count(1) || handshake_id(4 BE) || payload_len(2 BE) || data(payloadCapacity, last fragment may be padded with zeros).',
        version: 1,
        vectors,
    };

};

// ----- relay-digest.json -----

const generateRelayDigestVectors = () => {

    // Each vector is a sequence of (relayCommand, streamId, data) cells
    // built against an initial K_digest. The expected output is the
    // 4-byte digest written into each cell's header, AND the full
    // cipher-state-evolution (the running digest after each absorption).

    const relayCmd = {
        BEGIN: RELAY_BEGIN, DATA: RELAY_DATA, END: RELAY_END, CONNECTED: RELAY_CONNECTED,
    };

    const vectors = [
        {
            name: 'single DATA cell, K_digest = all zeros, empty data',
            input: {
                K_digestHex: '00'.repeat(32),
                cells: [{ relayCommand: 'DATA', streamId: 1, dataHex: '' }],
            },
        },
        {
            name: 'single DATA cell, K_digest = incrementing bytes, "hello" data',
            input: {
                K_digestHex: Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, '0')).join(''),
                cells: [{ relayCommand: 'DATA', streamId: 17, dataHex: hex(new TextEncoder().encode('hello')) }],
            },
        },
        {
            name: 'sequence of 3 cells: BEGIN, DATA, END',
            input: {
                K_digestHex: 'a5'.repeat(32),
                cells: [
                    { relayCommand: 'BEGIN', streamId: 5, dataHex: '01' + '7f000001' + '01bb' + '00' },
                    { relayCommand: 'DATA',  streamId: 5, dataHex: hex(new TextEncoder().encode('GET /\r\n\r\n')) },
                    { relayCommand: 'END',   streamId: 5, dataHex: '06' },
                ],
            },
        },
    ];

    for (const v of vectors) {

        const digestState = createDigestState(fromHex(v.input.K_digestHex));
        const cellsExpected = [];
        for (const cell of v.input.cells) {

            const payload = buildRelayPayload({
                relayCommand: relayCmd[cell.relayCommand],
                streamId: cell.streamId,
                data: fromHex(cell.dataHex),
                digestState,
            });
            // The digest field lives at offset 3 (after relay_command(1) + stream_id(2)).
            cellsExpected.push({
                cellDigestHex: hex(payload.subarray(3, 7)),
                fullPayloadHex: hex(payload),
            });

        }
        v.expected = { cells: cellsExpected };

    }

    return {
        description: 'Running BLAKE2b digest evolution per spec § 5.4.2. createDigestState(K_digest) seeds an incremental BLAKE2b state; buildRelayPayload then absorbs each cell\'s 9-byte header (with digest zeroed) + length(2) + data + padding; the resulting digest\'s first 4 bytes are written into the cell. Implementations must produce identical digests for identical sequences.',
        version: 1,
        vectors,
    };

};

// ----- main -----

const main = async () => {

    await mkdir(VECTORS_DIR, { recursive: true });
    process.stderr.write(`Generating test vectors → ${VECTORS_DIR}\n`);

    await writeVectors('cells.json', generateCellsVectors());
    await writeVectors('onion-address.json', generateOnionAddressVectors());
    await writeVectors('exit-policy.json', generateExitPolicyVectors());
    await writeVectors('fragment.json', generateFragmentVectors());
    await writeVectors('relay-digest.json', generateRelayDigestVectors());

    process.stderr.write('done.\n');

};

main().catch((err) => {

    process.stderr.write(`error: ${err.stack || err.message}\n`);
    process.exit(1);

});
