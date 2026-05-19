# Contributing

This project is an experimental anonymity-network implementation in the
pre-audit / pre-spec phase. Contributions are welcome but the bar is high
because this software is intended to protect at-risk users.

## Before you contribute

1. Read [`AUDIT_PREP.md`](./AUDIT_PREP.md) for the current state of known
   issues and the production-readiness roadmap. Your contribution should
   move us forward along that roadmap.
2. Read [`SECURITY.md`](./SECURITY.md). **If you have found a
   vulnerability, do not open a public issue or pull request** — use the
   encrypted disclosure channel.
3. Skim the existing modules so you understand the wire format and
   coordination protocol before changing them.

## What to contribute

High-value contributions, roughly in order:

- **Specification drafts.** We need a written protocol spec
  (Phase 2 of the roadmap) before an external audit is possible.
- **Threat-model writing.** STRIDE-style adversary capabilities,
  anonymity-set assumptions.
- **Test coverage.** Especially: cross-implementation parity tests,
  protocol-fuzz harnesses, constant-time-property tests.
- **Standards-replacement of hand-rolled primitives.** ElGamal-2048
  and the custom Twofish chain mode are scheduled for replacement with
  X25519 + ChaCha20-Poly1305 (see `AUDIT_PREP.md` items C3 and C4).

Lower-value at this stage:

- Performance optimisations (correctness first, then audit, then perf).
- Cosmetic refactors.
- New features beyond the gap list in `AUDIT_PREP.md` § 6.

## Process

1. Open an issue first for non-trivial changes. Describe the *security*
   implication of the change, not just the functional change.
2. Branch from `main`. Keep PRs small.
3. All PRs must keep the test suite green (`npm test`).
4. Cryptographic changes require two-maintainer review and an explicit
   statement of which security property is preserved / strengthened /
   weakened.
5. Avoid adding new hand-rolled cryptographic primitives. Prefer Node's
   built-in `crypto` module or `libsodium` bindings.

## Style

- Follow the existing code style. ESM modules, `const`-by-default,
  Uint8Array buffers, explicit bit-twiddling with `| 0` and `>>> 0`
  for u32 semantics.
- No unsolicited rewrites of working modules.
- New code must include tests in the same module's `tests.mjs`.

## Code of conduct

Be honest about what you know and what you don't. Anonymity software is
hard and overclaiming safety in this domain has real human cost. If you
are not sure whether something is secure, say so.

— Anonymous Gratis
