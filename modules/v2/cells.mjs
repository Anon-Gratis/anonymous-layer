// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

// Cell format codec for SPEC-v0.2-draft § 5.
//
// Every v0.2 cell on the wire is exactly 514 bytes:
//
//   version (1) ‖ circuit_id (4, BE) ‖ command (1) ‖ payload (508)
//
// The circuit ID is sender-assigned and identifies a circuit on a
// single hop-to-hop link. Different hops on the same circuit can (and
// will) use different circuit IDs — the ID is link-local, not
// circuit-global.
//
// Layer encryption uses the ChaCha20 stream cipher (no Poly1305 tag —
// integrity is provided end-to-end by the running digest field inside
// RELAY cells; see § 5.4.2 of the draft). Stream cipher means a single
// encrypt/decrypt primitive can be applied symmetrically at each hop.

import { createCipheriv } from 'node:crypto';

export const CELL_BYTES = 514;
export const WIRE_VERSION_V2 = 0x02;

export const LEN_VERSION = 1;
export const LEN_CIRCUIT_ID = 4;
export const LEN_COMMAND = 1;
export const LEN_CELL_PAYLOAD = 508;

export const OFFSET_VERSION = 0;
export const OFFSET_CIRCUIT_ID = 1;
export const OFFSET_COMMAND = 5;
export const OFFSET_CELL_PAYLOAD = 6;

// Top-level cell commands (SPEC § 5.3 corrected, plus link cells from § 11).
export const CMD_PADDING    = 0x00;
export const CMD_CREATE     = 0x01;
export const CMD_CREATED    = 0x02;
export const CMD_RELAY      = 0x03;
export const CMD_DESTROY    = 0x04;
export const CMD_LINK_HELLO = 0x05;
export const CMD_LINK_AUTH  = 0x06;

// Direction bit on circuit_id (SPEC § 5.2). The lower-fingerprint
// endpoint sets this bit to 1 on outbound circuits; the higher-
// fingerprint endpoint sets it to 0. Prevents collisions when both
// ends initiate circuits concurrently.
export const CIRCUIT_ID_DIRECTION_MASK = 0x80000000 >>> 0;

// ChaCha20 in Node's crypto uses a 32-byte key and a 16-byte IV.
// SPEC § 5.4.3 builds the IV as: counter (BE u64) ‖ 8 zero bytes.
export const LAYER_KEY_BYTES = 32;
export const LAYER_IV_BYTES = 16;

// Build the ChaCha20 IV for cell `counter` in a given direction.
// Returns a fresh Uint8Array(16). The first 8 bytes are the big-endian
// counter; the trailing 8 bytes are zero.
export const buildLayerIV = (counter) => {

    const iv = new Uint8Array(LAYER_IV_BYTES);
    const view = new DataView(iv.buffer);
    view.setBigUint64(0, BigInt(counter), false);
    return iv;

};

// Apply one layer of ChaCha20. Since ChaCha20 is a stream cipher,
// encrypt and decrypt are the same operation (XOR with the keystream).
// Throws on programmer error (wrong-sized key/IV); cell-level callers
// should never hit this because we control IV construction.
export const applyLayer = (key, iv, data) => {

    if (key.length !== LAYER_KEY_BYTES) throw new Error('layer key must be 32 bytes');
    if (iv.length !== LAYER_IV_BYTES) throw new Error('layer IV must be 16 bytes');

    const cipher = createCipheriv('chacha20', key, iv);
    const out = Buffer.concat([cipher.update(data), cipher.final()]);
    // Copy to fresh Uint8Array to avoid Buffer-pool aliasing —
    // same rationale as modules/crypto/onion.mjs.
    return Uint8Array.from(out);

};

// SPEC § 5.2: build a cell. payload may be shorter than LEN_CELL_PAYLOAD;
// remaining bytes are zero-padded. Throws if payload exceeds payload
// capacity (programmer error).
export const buildCell = ({ version = WIRE_VERSION_V2, circuitId, command, payload = new Uint8Array(0) }) => {

    if (!Number.isInteger(circuitId) || circuitId < 0 || circuitId > 0xFFFFFFFF) {

        throw new Error('circuitId must be an integer 0..2^32-1');

    }
    if (payload.length > LEN_CELL_PAYLOAD) {

        throw new Error(`payload exceeds cell capacity (${payload.length} > ${LEN_CELL_PAYLOAD})`);

    }

    const cell = new Uint8Array(CELL_BYTES);
    cell[OFFSET_VERSION] = version & 0xFF;
    cell[OFFSET_COMMAND] = command & 0xFF;
    new DataView(cell.buffer).setUint32(OFFSET_CIRCUIT_ID, circuitId >>> 0, false);
    if (payload.length > 0) cell.set(payload, OFFSET_CELL_PAYLOAD);
    // Remaining bytes are already zero from new Uint8Array.
    return cell;

};

// SPEC § 5.2: parse a cell from raw bytes. Returns
// { version, circuitId, command, payload } | null. Returns null per
// silent-drop discipline on any structural defect (wrong length).
//
// `payload` aliases into the input buffer; callers that mutate or
// retain the payload past the input's lifetime should copy.
//
// Note: parse does NOT validate version or command semantics. The
// receive path applies version + command-allowlist checks separately.
export const parseCell = (raw) => {

    if (!raw || raw.length !== CELL_BYTES) return null;

    return {
        version: raw[OFFSET_VERSION],
        circuitId: new DataView(raw.buffer, raw.byteOffset).getUint32(OFFSET_CIRCUIT_ID, false),
        command: raw[OFFSET_COMMAND],
        payload: raw.subarray(OFFSET_CELL_PAYLOAD, OFFSET_CELL_PAYLOAD + LEN_CELL_PAYLOAD),
    };

};

// Convenience: is `command` one of the valid top-level cell commands?
// Used by the receive path to drop reserved/future commands silently.
export const isValidTopLevelCommand = (command) => (
    command === CMD_PADDING
    || command === CMD_CREATE
    || command === CMD_CREATED
    || command === CMD_RELAY
    || command === CMD_DESTROY
    || command === CMD_LINK_HELLO
    || command === CMD_LINK_AUTH
);
