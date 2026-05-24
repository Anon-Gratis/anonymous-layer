// SPEC § 7.3: gossip propagation scheduler.
//
// planAnnounces produces the (recipientFp, subjectFp) pairs to emit on
// this scheduling tick. Cadence is enforced per recipient: one
// ANNOUNCE_PEER per recipient per `cadenceSeconds` (default 30 per
// § 7.3). Subject selection delegates to peerTable.pickAnnouncementSubject
// for the "least-likely-to-have-been-seen-recently" heuristic.
//
// planKeyCertificateSends produces the list of connected peers that
// have not yet been sent OUR KEY_CERTIFICATE; we use peerTable's
// hasSentKeyCertTo flag for dedup per the § 7.3 "MUST NOT announce
// itself to a peer that already has it" rule.
//
// Neither function performs I/O. They produce a plan that the router
// translates into actual packet sends.

const DEFAULT_CADENCE_SECONDS = 30;

// Returns [{recipientFp, subjectFp}]. May return fewer than one entry
// per connected peer when no eligible subject exists (e.g. a single-
// peer network where the only candidate is the recipient itself).
export const planAnnounces = (peerTable, lastAnnounceAtPerRecipient, nowSeconds, cadenceSeconds = DEFAULT_CADENCE_SECONDS) => {

    const plan = [];
    for (const recipientFp of peerTable.connectedFingerprints()) {

        const recipientKey = Buffer.from(recipientFp).toString('hex');
        const lastAt = lastAnnounceAtPerRecipient.get(recipientKey);
        if (lastAt !== undefined && nowSeconds - lastAt < cadenceSeconds) continue;

        const subjectFp = peerTable.pickAnnouncementSubject(recipientFp);
        if (subjectFp === null) continue;

        plan.push({ recipientFp, subjectFp });

    }
    return plan;

};

// Returns connected peers we have not yet sent KEY_CERTIFICATE to.
// The caller should mark them as sent via peerTable.markKeyCertSentTo
// after the send completes (not before, so we retry on transient
// transport failure).
export const planKeyCertificateSends = (peerTable) => {

    const plan = [];
    for (const recipientFp of peerTable.connectedFingerprints()) {

        if (!peerTable.hasSentKeyCertTo(recipientFp)) {

            plan.push(recipientFp);

        }

    }
    return plan;

};
