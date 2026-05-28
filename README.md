# ANONYMOUS LAYER

> **⚠️ STATUS: PRE-AUDIT, EXPERIMENTAL. DO NOT DEPLOY.**
>
> This software has not been audited. **Two protocol versions live in
> this repository**, both pre-audit:
>
> - **v0.1** — specified in [`docs/SPEC.md`](./docs/SPEC.md), implemented
>   under `modules/{crypto,wire,peer,node}/`, runnable via `bin/anon-node.mjs`
>   and `bin/anon-chat.mjs`. Single-hop forwarding. Suitable for known-peer
>   chat between adults who can read the threat model. Defeats no real
>   adversary on the open internet.
> - **v0.2** — DRAFT specified in [`docs/SPEC-v0.2-draft.md`](./docs/SPEC-v0.2-draft.md),
>   implementation in progress under `modules/v2/`. Multi-hop circuits +
>   exit policy + hidden services. The spec draft has explicit open
>   architectural questions (§ 15). Code refuses to start without an
>   `--i-understand-this-is-experimental` flag.
>
> **It must not be used by journalists, dissidents, or anyone whose
> physical safety depends on anonymity.** For safety-critical use today,
> use [Tor](https://torproject.org). The list of known limitations
> (including the documented v0.1 timing side-channel) is in
> [`AUDIT_PREP.md`](./AUDIT_PREP.md). For vulnerability disclosure, see
> [`SECURITY.md`](./SECURITY.md).

## START HERE

Pick the entry point that matches what you want to do:

- **End user — just want to browse?** Download the bundled browser at
  [anonymous.gratis/browser](https://anonymous.gratis/browser). Nothing
  else in this repo is needed.
- **Relay operator or hidden-service host?** This repository is for
  you. Read [`deploy/README.md`](./deploy/README.md) for the testnet
  operator lifecycle, then run
  [`deploy/scripts/bootstrap-relay.sh`](./deploy/scripts/bootstrap-relay.sh)
  on a fresh VPS. The headless software (daemons, CLI, library) is
  also summarized at [anonymous.gratis/node](https://anonymous.gratis/node).
- **Developer / writing a second implementation?** Start with
  [`docs/SPEC.md`](./docs/SPEC.md) (v0.1, frozen) and
  [`docs/SPEC-v0.2-draft.md`](./docs/SPEC-v0.2-draft.md) (in progress,
  open architectural questions in § 15). The reference library lives
  under [`modules/`](./modules/); the daemons under [`bin/`](./bin/)
  are thin shells over it.

## ABOUT

Anonymous Layer is a from-scratch anonymity-network protocol pitched as
an alternative to Tor. The protocol surface is intentionally small so
the spec is auditable and independent implementations are realistic to
develop. Both the spec and the reference code are AGPL-3.0+, and the
authorial intent is that participating in the network should not require
trusting any particular implementation.

v0.1 provides **sender / receiver unlinkability for short messages over
a one-hop overlay**. It does not provide circuit-level anonymity, mix-
network traffic shaping, or anti-Sybil. See `docs/SPEC.md` § 1.2 and
`docs/THREAT_MODEL.md` for the precise claims.

## QUICKSTART

```bash
npm install
node bin/anon-node.mjs init ./node.json
# share fingerprint and listen address out of band, then populate
# ./seeds.bin with the peer records you trust
node bin/anon-node.mjs run ./node.json
```

`init` generates an Ed25519 identity (stored mode-0600 at
`./node.identity.key`), an empty seed list, and a default config listening
on `127.0.0.1:8443`. `info <config>` prints the node's fingerprint and
listen address. `run` starts the listener, dials each seed, and runs
the gossip scheduler until SIGTERM/SIGINT. `share <config>` /
`add-seed <config> <hex>` are how operators exchange peer records out
of band.

## CHAT

Once two nodes know about each other (via `share` + `add-seed`), they
can hold an interactive conversation over the network:

```bash
node bin/anon-chat.mjs ./node.json <peer-fingerprint-hex>
```

Both sides run `anon-chat` at the same time. `anon-chat` replaces
`anon-node run` for the duration — it listens on the same port and
acts as both the daemon and the UI. Type lines and press Enter to
send; Ctrl-D or Ctrl-C to exit. Each session uses a random
conversation tag so concurrent chats can be demultiplexed by an
application above the network layer.

Try the scripted demos: `bash bench/demo-two-nodes.sh` (handshake
only) or `bash bench/demo-chat.sh` (handshake + message exchange).

## CONTACT

- **Email:** `admin@anon.gratis` (PGP-encrypted for security reports per
  [`SECURITY.md`](./SECURITY.md))
- **Vulnerability disclosure:** see [`SECURITY.md`](./SECURITY.md).

## DONATIONS

[$XMR](https://getmonero.org): 46kZfVBP2gE98pfnKv8pXA4ujWaTCAhkBWRpze91e6wo95FCo5JX7zSGh5odzDceqwXr9vT4Bfa2tUgB1QZWC1UvTnnFvzW

## TESTS

```
npm test
```

The test suite runs the unit tests, end-to-end node integration
(in-memory + real WebSocket), property-based fuzzing of the wire
decoders, and CLI smoke tests.

## LICENSE

This project is licensed under the GNU Affero General Public License v3.0 or
later. See [`LICENSE`](./LICENSE) for the full text.
