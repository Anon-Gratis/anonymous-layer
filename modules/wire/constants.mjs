// Wire-format constants for SPEC v0.1.
//
// Every value in this file is normative. Names match the field names in
// SPEC § 5 verbatim where possible. Numeric values are little-endian-
// agnostic: lengths and offsets are byte counts; multi-byte field
// encodings (e.g. expiry, real_length) are big-endian per SPEC § 2.2.

////////////////////////////////////////////////////////////////////////
// VERSION (SPEC § 5.2, § 10.1)                                        //
////////////////////////////////////////////////////////////////////////

export const WIRE_VERSION                                       = 0x01;

////////////////////////////////////////////////////////////////////////
// BUCKETS (SPEC § 5.1)                                                //
////////////////////////////////////////////////////////////////////////

export const BUCKET_SMALL                                       = 0x01;
export const BUCKET_MEDIUM                                      = 0x02;
export const BUCKET_LARGE                                       = 0x03;

export const BUCKET_SIZE_SMALL                                  = 256;
export const BUCKET_SIZE_MEDIUM                                 = 1024;
export const BUCKET_SIZE_LARGE                                  = 4096;

// Total on-wire packet length for a given bucket code, or 0 if the
// bucket code is not one of the three defined values.
export const bucketSize = (bucket) => {

    if (bucket === BUCKET_SMALL)  return BUCKET_SIZE_SMALL;
    if (bucket === BUCKET_MEDIUM) return BUCKET_SIZE_MEDIUM;
    if (bucket === BUCKET_LARGE)  return BUCKET_SIZE_LARGE;
    return 0;

};

// Reverse lookup: smallest bucket code that fits a packet of `size`
// bytes on the wire, or 0 if `size` exceeds BUCKET_SIZE_LARGE.
export const bucketForSize = (size) => {

    if (size <= BUCKET_SIZE_SMALL)  return BUCKET_SMALL;
    if (size <= BUCKET_SIZE_MEDIUM) return BUCKET_MEDIUM;
    if (size <= BUCKET_SIZE_LARGE)  return BUCKET_LARGE;
    return 0;

};

////////////////////////////////////////////////////////////////////////
// OUTER HEADER (SPEC § 5.2) — total 54 bytes, cleartext on the wire   //
////////////////////////////////////////////////////////////////////////

export const LEN_VERSION                                        = 1;
export const LEN_BUCKET                                         = 1;
export const LEN_RECIPIENT_PREFIX                               = 8;
export const LEN_EPH_PK                                         = 32;
export const LEN_NONCE                                          = 12;

export const OFFSET_VERSION                                     = 0;
export const OFFSET_BUCKET                                      = 1;
export const OFFSET_RECIPIENT_PREFIX                            = 2;
export const OFFSET_EPH_PK                                      = 10;
export const OFFSET_NONCE                                       = 42;

export const LEN_OUTER_HEADER                                   = 54;

////////////////////////////////////////////////////////////////////////
// AEAD (SPEC § 3.3, § 5.2)                                            //
////////////////////////////////////////////////////////////////////////

export const LEN_AEAD_TAG                                       = 16;
export const LEN_AEAD_KEY                                       = 32;

// `inner ciphertext length = bucket - 70` per SPEC § 5.2
// (54 outer + 16 tag = 70 fixed framing).
export const LEN_FRAMING                                        = LEN_OUTER_HEADER + LEN_AEAD_TAG;

export const innerLengthForBucket = (bucket) => {

    const size = bucketSize(bucket);
    return size === 0 ? 0 : size - LEN_FRAMING;

};

////////////////////////////////////////////////////////////////////////
// INNER PLAINTEXT (SPEC § 5.4) — 35-byte prefix + payload + padding   //
////////////////////////////////////////////////////////////////////////

export const LEN_PACKET_TYPE                                    = 1;
export const LEN_REAL_LENGTH                                    = 2;
export const LEN_SENDER_FINGERPRINT                             = 32;

export const OFFSET_PACKET_TYPE                                 = 0;
export const OFFSET_REAL_LENGTH                                 = 1;
export const OFFSET_SENDER_FINGERPRINT                          = 3;
export const OFFSET_PAYLOAD                                     = 35;

export const LEN_INNER_PREFIX                                   = 35;

// Maximum payload bytes for a given bucket code.
export const maxPayloadForBucket = (bucket) => {

    const inner = innerLengthForBucket(bucket);
    return inner === 0 ? 0 : inner - LEN_INNER_PREFIX;

};

////////////////////////////////////////////////////////////////////////
// PACKET TYPES (SPEC § 6.1)                                           //
////////////////////////////////////////////////////////////////////////

export const TYPE_RESERVED                                      = 0x00;
export const TYPE_DATA                                          = 0x01;
export const TYPE_ANNOUNCE_PEER                                 = 0x02;
export const TYPE_FORWARD                                       = 0x03;
export const TYPE_KEY_CERTIFICATE                               = 0x04;

////////////////////////////////////////////////////////////////////////
// KEY DERIVATION (SPEC § 3.5, § 5.3)                                  //
////////////////////////////////////////////////////////////////////////

export const INFO_AEAD                                          = 'anon-layer/v1/aead';

////////////////////////////////////////////////////////////////////////
// REPLAY WINDOW (SPEC § 5.6)                                          //
////////////////////////////////////////////////////////////////////////

export const REPLAY_MIN_ENTRIES                                 = 8192;
export const REPLAY_MIN_SECONDS                                 = 300;
