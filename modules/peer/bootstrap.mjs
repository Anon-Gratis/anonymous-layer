import { parseSeedList, verifySeedRecord } from './seed.mjs';

// SPEC § 7.2: bootstrap procedure.
//
// Steps 1-2 are done by loadSeedList — read the list, verify each
// record, insert verified records into the peer table.
//
// Step 3 (dial K seeds) is done by pickBootstrapDials — choose which
// K to dial; the dialer itself is owned by the router (chunk 4.5).
//
// Step 4 (send KEY_CERTIFICATE to each connected seed) is implemented
// by gossip.planKeyCertificateSends after the dialer has called
// peerTable.markConnected on the seeds it successfully reached.
//
// mustRefuseTraffic implements the § 7.2 disposition: if the seed
// list is empty AND no peers are loaded from local state AND no peers
// are connected, the implementation MUST refuse application traffic.

const DEFAULT_BOOTSTRAP_K = 8;

// Returns the number of seed records accepted into the peer table.
// Returns -1 if the seed-list bytes do not parse at all (corruption).
export const loadSeedList = (seedBytes, peerTable, nowSeconds) => {

    const records = parseSeedList(seedBytes);
    if (records === null) return -1;

    let accepted = 0;
    for (const record of records) {

        if (!verifySeedRecord({ record, nowSeconds })) continue;
        const ok = peerTable.addOrUpdate({
            idPk: record.idPk,
            certBytes: record.certBytes,
            transports: record.transports,
            nowSeconds,
        });
        if (ok) accepted += 1;

    }
    return accepted;

};

// Pick up to K not-currently-connected peers to dial. Deterministic
// order: insertion order from the peer table (peerTable.list()).
// Callers that want randomness can shuffle the result.
export const pickBootstrapDials = (peerTable, K = DEFAULT_BOOTSTRAP_K) => {

    const candidates = peerTable.list().filter((p) => !p.connected);
    return candidates.slice(0, K).map((p) => p.fingerprint);

};

// SPEC § 7.2: refuse application traffic if no peers are loaded AND
// no peers are connected. We're stricter than the spec's literal "if
// the seed list is empty and no peers" — even with a non-empty seed
// list, if every connection attempt failed, we still have nothing to
// route through.
export const mustRefuseTraffic = (peerTable) => peerTable.connectedFingerprints().length === 0;
