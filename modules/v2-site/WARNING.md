# v2-site — pre-audit experimental code

Everything under `modules/v2-site/` implements the **anon-site
protocol** described in [`docs/SITES-v0.1.md`](../../docs/SITES-v0.1.md).

That draft is itself a **DRAFT** with explicit open questions (§ 10
of the draft) that have not been resolved.

The implementation has not been audited. The application protocol
runs INSIDE a v0.2 anon-layer session, which is also pre-audit.

**Do not use this code to serve or browse anything where being
de-anonymised or content-attribution would harm anyone.** For real
anonymity needs today, use [Tor](https://torproject.org).

Every file in this directory MUST carry the warning header below in
its first 10 lines:

```js
// v2-site — PRE-AUDIT EXPERIMENTAL CODE
//
// Anon-site protocol codec, see docs/SITES-v0.1.md.
// The draft has open architectural questions; the code has not been
// audited. Do not rely on this for anonymity or content authenticity
// beyond what the v0.2 transport already provides.
```
