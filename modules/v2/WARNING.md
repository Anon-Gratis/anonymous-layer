# v0.2 — pre-audit experimental code

Everything under `modules/v2/` implements the **v0.2 draft** protocol
described in [`docs/SPEC-v0.2-draft.md`](../../docs/SPEC-v0.2-draft.md).

That draft is itself a **DRAFT** with explicit open architectural
questions (§ 15 of the draft) that have not been resolved.

The implementation has not been audited. The draft spec has not been
reviewed by an independent cryptographer.

**Do not use this code for any purpose where being de-anonymised would
harm anyone.** For real anonymity needs today, use [Tor](https://torproject.org).

The v0.1 implementation under `modules/{crypto,wire,peer,node}/` is
also pre-audit; the chat client (`bin/anon-chat.mjs`) is a peer-to-peer
toy, not a defence against any real adversary. The README's
**DO NOT DEPLOY** warning applies to all of this.

Every file in this directory MUST carry the warning header below in
its first 10 lines so anyone reading the source sees it before reading
the code:

```js
// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.
```

A CI check will be added that fails the build if a `modules/v2/*.mjs`
file lacks this header.
