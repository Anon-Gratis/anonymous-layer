# Test vectors for v0.2

This directory holds canonical byte-level test vectors for the v0.2
codec layer. The reference implementation lives in JavaScript under
`modules/v2/` and `modules/v2-runtime/`, but the test vectors are
language-agnostic — independent implementations in Rust, Go, Python,
or anything else can use them to validate byte-for-byte conformance.

## Files

| File | Codec under test | SPEC reference |
|---|---|---|
| `cells.json` | `buildCell({circuitId, command, payload})` | § 5.2 |
| `onion-address.json` | `encodeOnionAddress(SVC_pk)` | § 4.4 |
| `exit-policy.json` | `buildPolicy(rules)` | § 8.1 |
| `fragment.json` | `fragmentMessage({message, handshakeId, payloadCapacity})` | § 6.2.1 |
| `relay-digest.json` | Running BLAKE2b digest + `buildRelayPayload(...)` | § 5.4.2 |

## Format

Every file is JSON with this top-level shape:

```json
{
  "description": "What this file tests.",
  "version": 1,
  "vectors": [
    {
      "name": "Human description of this case.",
      "input":    { /* codec-specific input fields */ },
      "expected…": "expected output (hex string or array)"
    }
  ]
}
```

Conventions:

- **All byte strings are lower-case hex.** No `0x` prefix, no separators.
- **All u32/u16 fields are JSON numbers** (decimal). They fit in 53 bits
  for v0.2 (32-bit max), so JSON's float representation is exact.
- **The `expected…` field name varies** by codec (e.g., `expectedHex`,
  `expectedAddress`, `expectedFragmentsHex`). Each file's
  `description` field documents its specific schema.
- **Vectors are unordered.** A conforming implementation must reproduce
  ALL of them; the order in the JSON file is for human readability.

## How implementations use these

A new v0.2 implementation in Rust would write a test like:

```rust
let doc: TestVectors = serde_json::from_str(include_str!("../test-vectors/cells.json"))?;
for v in doc.vectors {
    let bytes = build_cell(v.input.circuit_id, parse_command(&v.input.command), &hex_decode(&v.input.payload_hex));
    assert_eq!(hex_encode(&bytes), v.expected_hex, "vector: {}", v.name);
}
```

If your output bytes differ from `expected_hex`, your implementation
diverges from the reference. Either:

- Your codec has a bug (most likely)
- The spec is ambiguous and your reading differs from the reference's
- The reference has a bug (file an issue!)

## How the reference impl uses these

The reference impl runs `modules/v2/tests-vectors.mjs` as part of
`npm test`. It loads each JSON file, reproduces the input through the
reference codec, and asserts the output matches the committed `expected…`
field. Any drift between the reference impl and the committed JSON is
caught immediately.

## Regenerating

The JSON files are committed as the source of truth. To regenerate
from the inputs (e.g., after a spec change):

```bash
node bench/generate-test-vectors.mjs
```

This rewrites every JSON file. **Review the diff before committing** —
unexpected changes indicate either a reference-impl regression or a
spec change that needs to land in the spec doc first.

The inputs themselves are hardcoded in
`bench/generate-test-vectors.mjs`. To add a new vector, edit that
script's input arrays, re-run, commit the resulting JSON.

## What's covered, what isn't

**Covered** (deterministic, single-call codecs):
- Cell construction (CMD_PADDING/CREATE/CREATED/RELAY/DESTROY/LINK_HELLO/LINK_AUTH)
- Onion-address encoding with checksum
- Exit-policy build with each addr_type (IPv4/IPv6/ANY) + presets
- Multi-cell fragmentation at both cell-layer (500 byte) and RELAY-layer (491 byte) capacities
- Running BLAKE2b digest evolution across a known cell sequence

**Not covered yet** (would need a deterministic-RNG injection mechanism that the reference doesn't expose):
- ntor handshake (classical or hybrid) — uses random ephemerals
- Sealed-box (introduces ephemeral X25519 + ML-KEM)
- Consensus signing — would work in principle since Ed25519 is
  deterministic given the same secret seed, but adding signed-bytes
  vectors complicates the schema
- Service descriptor signing — same as consensus

For these, an independent implementation can verify round-trip
correctness against ITSELF (encode then decode and compare) — but
not byte-for-byte conformance with the reference. This is documented
in the spec as a known gap.

## Versioning

The `version: 1` field at the top of each JSON file is the **vector
schema version**, distinct from the v0.2 protocol version. If we ever
change the JSON structure (e.g., add a new required field), we'd bump
this number. v1 = current format.
