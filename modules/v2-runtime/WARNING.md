# v2-runtime — pre-audit experimental code

Everything under `modules/v2-runtime/` is the **reference v0.2 runtime
implementation**. It wires together the cryptographic primitives, cell
format, circuit construction, link transport, and (eventually) hidden-
service rendezvous defined in [`docs/SPEC-v0.2-draft.md`](../../docs/SPEC-v0.2-draft.md)
into a runnable daemon: `bin/anon-node-v2.mjs`.

The protocol draft has explicit open questions. The reference impl
has not been audited.

**Do not run this on the public internet against any threat model
that would harm a real human.** It is intended for:

- Protocol development and conformance testing
- Local benchmarking
- Closed testnets among consenting operators

Every file in this directory carries the warning header below in its
first 10 lines:

```js
// v2-runtime — PRE-AUDIT EXPERIMENTAL CODE
//
// Reference v0.2 runtime, see docs/SPEC-v0.2-draft.md.
// The draft has open architectural questions; the code has not been
// audited. Do not rely on this for anonymity.
```
