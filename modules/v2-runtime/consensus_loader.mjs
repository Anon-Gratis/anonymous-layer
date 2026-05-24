// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE
//
// Reference v0.2 runtime, see docs/SPEC-v0.2-draft.md.
// The draft has open architectural questions; the code has not been
// audited. Do not rely on this for anonymity.

// Consensus loader.
//
// Reads the binary consensus document from a file path and parses
// it through `modules/v2/consensus.mjs`. The DA trust set is supplied
// separately (JSON: { fingerprint_hex: idPk_hex }). Operators
// distribute these out-of-band — analogous to Tor's hardcoded
// DirAuthority list.
//
// Out of scope for 9.4c:
//   - Fetching the consensus from a DA over the network
//   - Periodic refresh / expiry handling at runtime
//   - HSDir-related secondary indices
//
// The operator supplies both files at startup; the runtime parses
// them once. Refresh-on-expiry is a future-work item.

import { readFile } from 'node:fs/promises';

import { parseConsensus } from '../v2/consensus.mjs';

// Read + parse the DA trust set. File format:
//   {
//     "<hex fingerprint>": "<hex idPk>",
//     "<hex fingerprint>": "<hex idPk>",
//     ...
//   }
// Returns a Map<hex_fingerprint, Uint8Array_idPk>.
export const loadDaTrustSet = async (path) => {

    const raw = await readFile(path, 'utf-8');
    let obj;
    try { obj = JSON.parse(raw); } catch (err) {

        throw new Error(`DA trust file ${path} is not valid JSON: ${err.message}`);

    }
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {

        throw new Error(`DA trust file ${path} must be a JSON object`);

    }
    const trustSet = new Map();
    for (const [fpHex, idPkHex] of Object.entries(obj)) {

        if (!/^[0-9a-f]{64}$/i.test(fpHex)) {

            throw new Error(`bad DA fingerprint hex: ${fpHex}`);

        }
        if (!/^[0-9a-f]{64}$/i.test(idPkHex)) {

            throw new Error(`bad DA idPk hex: ${idPkHex}`);

        }
        trustSet.set(fpHex.toLowerCase(), new Uint8Array(Buffer.from(idPkHex, 'hex')));

    }
    return trustSet;

};

// Load + parse the consensus from a binary file.
//
// Returns the parsed consensus (per modules/v2/consensus.mjs's
// parseConsensus return shape) on success, or throws on any structural
// / signature / validity-window failure.
export const loadConsensus = async ({ path, daTrustSet, nowSeconds }) => {

    const raw = await readFile(path);
    const consensus = parseConsensus(raw, {
        daTrustSet,
        nowSeconds: nowSeconds ?? Math.floor(Date.now() / 1000),
    });
    if (consensus === null) {

        throw new Error(`consensus at ${path} failed to parse / verify / validate`);

    }
    return consensus;

};
