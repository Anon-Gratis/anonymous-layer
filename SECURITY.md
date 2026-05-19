# Security Policy

## Status

**This project is pre-audit and pre-spec.** It is not yet a production
anonymity tool and must not be relied upon for safety-critical
communication. See [`AUDIT_PREP.md`](./AUDIT_PREP.md) for the current list
of known critical issues.

## Reporting a vulnerability

Send PGP-encrypted reports to:

- **Email:** `admin@anon.gratis`
- **PGP fingerprint:** _TODO — paste the maintainer's full PGP fingerprint here before any public release. The public-key block belongs in this file._

If your finding affects user anonymity, please **do not** open a public
issue or pull request, even to ask for an encrypted contact. Reach out via
the PGP-encrypted email above.

## Disclosure timeline

- **Day 0:** Encrypted report received. Acknowledgement within 72 hours.
- **Day 0–30:** Investigation, reproduction, and fix development.
- **Day 30–90:** Coordinated disclosure window. We aim to ship a fix
  within 90 days of report. If the fix requires a wire-format change, the
  window may extend by mutual agreement.
- **Day 90+:** Public advisory, CVE if applicable, credit to reporter (or
  anonymous credit at reporter's request).

If you do not hear back within 72 hours, please retry with a different
key fingerprint check — the message may have been silently dropped.

## Scope

In scope:

- Cryptographic weaknesses in the protocol or implementation.
- Anonymity-defeating attacks (de-anonymization, traffic correlation,
  fingerprinting).
- Memory-safety, parser-confusion, or denial-of-service issues in node
  software.
- Supply-chain risks affecting builds and releases.

Out of scope:

- Findings already listed in `AUDIT_PREP.md` (we know).
- Issues in third-party WebSocket or Node runtime libraries — please
  report those upstream and notify us if they impact this project.
- Social-engineering of maintainers.

## Bug-bounty

There is no monetary bounty at this stage. Once Phase 7 of the roadmap is
reached (post-audit), a public bounty will be opened. Reporters who
contribute pre-bounty will be acknowledged in release notes.

## Safe-harbour

Good-faith security research is welcomed. We will not pursue civil or
criminal action against researchers who:

- Make a good-faith effort to avoid privacy violations, destruction of
  data, and interruption or degradation of services.
- Only use accounts and resources owned by themselves or with explicit
  permission.
- Give us reasonable time to remediate before any public disclosure.

— Anonymous Gratis
