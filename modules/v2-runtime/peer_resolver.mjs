// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE
//
// Reference v0.2 runtime, see docs/SPEC-v0.2-draft.md.

// Peer resolver — given a fingerprint (or RSE), find the connection
// info needed to dial that relay via the LinkManager.
//
// Backed by a parsed consensus (modules/v2/consensus.mjs). Decodes
// the RSE's IPv4 / IPv6 byte fields into host strings. Returns null
// if the fingerprint isn't in the consensus or the relay has no
// reachable transport entry.

// SPEC § 10.3: ipv4 = 4 bytes IP + 2 bytes BE port (all-zero if no
// IPv4 transport); ipv6 = 16 bytes IP + 2 bytes BE port (same).

const decodeIPv4 = (bytes) => {

    if (!bytes) return null;
    // Format: A.B.C.D
    const host = `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
    const port = (bytes[4] << 8) | bytes[5];
    if (port === 0) return null;
    return { host, port };

};

const decodeIPv6 = (bytes) => {

    if (!bytes) return null;
    const parts = [];
    for (let i = 0; i < 16; i += 2) {

        parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));

    }
    const host = parts.join(':');
    const port = (bytes[16] << 8) | bytes[17];
    if (port === 0) return null;
    return { host, port };

};

const fpKey = (fp) => Buffer.from(fp).toString('hex').toLowerCase();

// Build a peerResolver function over a parsed consensus.
//
// Preferences:
//   - IPv4 is preferred over IPv6 (deterministic, simple).
//   - If the relay has neither, returns null.
//
// Returns a function (suitable as the dispatcher's peerResolver
// parameter) that takes `{ fingerprint }` and returns
// `{ host, port, idPk, B_pk, fingerprint }` or null.
export const createPeerResolver = ({ consensus }) => {

    // Index by fingerprint for O(1) lookup.
    const byFingerprint = new Map();
    for (const rse of consensus.rses) {

        byFingerprint.set(fpKey(rse.fingerprint), rse);

    }

    return ({ fingerprint }) => {

        const rse = byFingerprint.get(fpKey(fingerprint));
        if (!rse) return null;
        const ipv4 = decodeIPv4(rse.ipv4);
        const ipv6 = decodeIPv6(rse.ipv6);
        const transport = ipv4 || ipv6;
        if (!transport) return null;
        return {
            host: transport.host,
            port: transport.port,
            idPk: new Uint8Array(rse.idPk),
            B_pk: new Uint8Array(rse.onionPk),
            fingerprint: new Uint8Array(rse.fingerprint),
        };

    };

};
