# Anonymous Layer Sites Protocol — v0.1 (draft)

| | |
|---|---|
| **Document** | Anonymous Layer Sites Protocol Specification |
| **Version** | 0.1 (draft) |
| **Date** | 2026-05-20 |
| **Status** | **DRAFT — companion to v0.2 transport, not yet implemented end-to-end.** |
| **Editor** | Anonymous Gratis `<admin@anon.gratis>` |
| **License** | AGPL-3.0-or-later |

> This document defines the application-layer protocol that runs INSIDE
> a hidden-service session established by the v0.2 transport
> ([`SPEC-v0.2-draft.md`](./SPEC-v0.2-draft.md) § 9). It is the
> "what comes after the rendezvous splice" — the equivalent of HTTP
> running over a TCP connection.
>
> It is intentionally minimal. The design goal is **"auditable in an
> afternoon."** Inspired by the Gemini protocol (gemini://); adapted
> for anon-layer's session semantics.

---

## Table of contents

1. [Introduction](#1-introduction)
2. [URL scheme](#2-url-scheme)
3. [Session model](#3-session-model)
4. [Wire protocol](#4-wire-protocol)
5. [Status codes](#5-status-codes)
6. [`text/anon` content format](#6-textanon-content-format)
7. [Security considerations](#7-security-considerations)
8. [Reference implementation](#8-reference-implementation)
9. [Appendix A: Design ledger](#9-appendix-a-design-ledger)
10. [Appendix B: Differences from Gemini](#10-appendix-b-differences-from-gemini)

---

## 1. Introduction

### 1.1. Purpose

The anon-site protocol is a request/response application protocol that
runs over a single bidirectional anon-layer session (a stream
established via `RELAY_BEGIN` after a rendezvous splice). It lets a
client fetch text or binary content from a hidden service.

It does NOT define:

- How to run a server (that's the operator's concern)
- How to render text/anon (that's the client/browser's concern)
- Anything about how the underlying anon-layer session works (that's
  v0.2's spec)

### 1.2. Non-goals

The following are EXPLICITLY out of scope and SHOULD NOT be added:

- **Inline media.** No `<img>`, no audio, no video embedded in pages.
  Media is reached by following a link, which the client decides
  whether to follow.
- **Client-side scripting.** No JS, no WebAssembly, no anything that
  executes server-supplied code on the client.
- **Cookies, persistent identity.** Sessions are anonymous by default;
  user-state lives in the user's local store, not in protocol headers.
- **Compression.** All bytes go over an already-encrypted anon-layer
  session; compression in the application layer would only add
  CRIME/BREACH-style oracle risks.
- **MIME-type negotiation.** Server returns one type per resource;
  no `Accept`-header negotiation.
- **Connection upgrades.** No `WebSocket`, no `HTTP/2 frames`, no
  protocol negotiation. The session speaks anon-site or it doesn't.
- **Authentication / sessions.** No cookies, no bearer tokens, no
  `Authorization` header. If a site needs user accounts, the
  application implements it visibly (with INPUT prompts, for example).

### 1.3. Conformance

`MUST` / `MUST NOT` / `SHOULD` / `SHOULD NOT` / `MAY` as in RFC 2119.
All multi-byte integers are big-endian (irrelevant here — the
protocol is entirely text-based on the wire).

---

## 2. URL scheme

Anon-site URLs have the form:

```
anon://<onion-address>[/<path>][?<query>]
```

Where:

- `<onion-address>` is a valid `.anon` address (v0.2 spec § 4.4):
  56 base32 lowercase characters followed by the `.anon` suffix.
  Example: `vfqorzcdyq2ie25o7r6xxn4w....anon` (truncated for example).
- `<path>` is a sequence of forward-slash-separated path segments.
  UTF-8; characters outside `[A-Za-z0-9._~/-]` SHOULD be
  percent-encoded.
- `<query>` is an opaque application-defined string. UTF-8;
  reserved characters percent-encoded.

A URL MUST NOT include a `<userinfo>@` component, a port, or a
fragment (`#…`). Fragments belong to the client UI; servers MUST
never see them.

A URL MUST be ≤ **1024 bytes** total (limit enforced at request
parsing — § 4.1).

> **Design decision (v0.1):** the `anon://` scheme is explicit so
> clients clearly distinguish anon-site requests from HTTP requests
> tunneled through anon-layer. A future revision MAY add a way for
> servers to declare equivalence between `anon://foo.anon/bar` and
> `https://foo.example/bar` (an `anon-Location`-equivalent), but not
> in v0.1.

---

## 3. Session model

A client wishing to fetch a resource:

1. Resolves the `.anon` address to a service descriptor (v0.2 § 9.1)
   via the HSDir mechanism.
2. Picks an introduction point from the descriptor; performs the
   rendezvous splice (v0.2 § 9.3) to obtain a bidirectional
   anon-layer session (a circuit-multiplexed stream).
3. Opens a single anon-site **session** over that stream.
4. Sends ONE request, reads ONE response. May then send another
   request, read another response. And so on.
5. Closes the session by closing the stream (sending `RELAY_END`).

The session is **persistent** until either side closes it. The
client MAY pipeline requests (send a second before the first
response arrives) but the server MUST process them in order and the
client MUST consume responses in order.

> **Design decision (v0.1):** persistent sessions, not the
> one-request-per-session model of Gemini. The rationale: setting up
> an anon-layer rendezvous session costs ~6 hops of handshake and
> several seconds of latency. Amortising that across many requests
> is anonymity-neutral (the network already sees the session
> connecting to a known service for an undisclosed duration) and a
> significant UX win for any site with more than one resource.

There is no protocol-level keepalive; an idle session MAY be closed
by either side at any time. Clients SHOULD be prepared to re-open.

---

## 4. Wire protocol

All exchanges are UTF-8 unless explicitly noted otherwise.

### 4.1. Request

A request is a single line:

```
<URL>\r\n
```

Where `<URL>` is the full URL (§ 2). The request is terminated by
the exact bytes `\r\n` (CR LF, 0x0D 0x0A). The server MUST read
until either `\r\n` is received OR 1024 bytes have been consumed
without `\r\n` — in the latter case, the server returns status `59`
(BAD_REQUEST) and closes the session.

There is no request body in v0.1. Forms are submitted via the
`INPUT` status (§ 5.1) one input at a time.

### 4.2. Response

A response is:

```
<STATUS><SP><META>\r\n
[<body bytes>]
```

Where:

- `<STATUS>` is two ASCII digits, `10` through `69`.
- `<SP>` is a single space character, 0x20.
- `<META>` is a UTF-8 string up to 1024 bytes. Its meaning depends
  on `<STATUS>` (§ 5).
- `\r\n` is CR LF.
- `<body bytes>` is present ONLY for 2x success statuses. The body
  is delivered raw — the server writes bytes, the client reads
  bytes, until the server closes its side of the stream OR sends a
  new response (in pipelined mode).

For pipelined responses, the server MUST send `<body bytes>` for the
first response in full before beginning to write the second
response's `<STATUS>` line. There is no length prefix; for binary
bodies the server SHOULD include a content length in META as
described per status (§ 5.2).

### 4.3. Stream end semantics

The server signals "end of response" by closing its write side of
the stream OR by beginning a new response (if pipelined requests
remain). Clients MUST handle both. For the persistent-session case,
this means binary bodies need a content-length in META so the client
knows when to stop reading body bytes and look for the next response.

---

## 5. Status codes

### 5.1. `1x` INPUT

Server requires a single line of input from the user before
responding. The client SHOULD prompt the user, then submit a new
request with the input encoded as the URL's `<query>` (URL-encoded).

| Code | Name | META | Notes |
|---|---|---|---|
| 10 | INPUT | prompt text shown to the user | Sensitive input MAY be redacted in the prompt; use 11 to indicate it. |
| 11 | SENSITIVE_INPUT | prompt text; client SHOULD use password-style input | Used for passwords, secrets, etc. |

### 5.2. `2x` SUCCESS

Body follows. META is the content type plus optional parameters.

| Code | Name | META | Notes |
|---|---|---|---|
| 20 | SUCCESS | `<MIME-type>` (optionally `; length=<N>`, `; charset=utf-8`) | Body bytes follow until length is reached, or until stream closes if no length. |

META examples:
- `text/anon; charset=utf-8`
- `text/plain; charset=utf-8`
- `application/octet-stream; length=4096`
- `image/png; length=12345`

For **persistent-session pipelining**, binary types MUST include
`length=<N>`. text/anon and text/plain MAY omit length only if the
session is closed at end of response (non-pipelined).

### 5.3. `3x` REDIRECT

META is the new URL. The client SHOULD follow the redirect with a
new request (after asking the user for confirmation if the
redirect crosses to a different `.anon` address).

| Code | Name | META |
|---|---|---|
| 30 | REDIRECT_TEMPORARY | new URL |
| 31 | REDIRECT_PERMANENT | new URL |

Clients SHOULD limit redirect chains (RECOMMENDED ≤ 5 hops) to
defeat infinite-loop attacks.

### 5.4. `4x` TEMPORARY FAILURE

Retry might work. META is a human-readable explanation.

| Code | Name |
|---|---|
| 40 | TEMPORARY_FAILURE |
| 41 | SERVER_UNAVAILABLE |
| 42 | CGI_ERROR (server-side application error) |
| 43 | PROXY_ERROR |
| 44 | SLOW_DOWN (rate-limited; META MAY include a retry-after time as seconds) |

### 5.5. `5x` PERMANENT FAILURE

Don't retry. META is a human-readable explanation.

| Code | Name |
|---|---|
| 50 | PERMANENT_FAILURE |
| 51 | NOT_FOUND |
| 52 | GONE |
| 53 | PROXY_REQUEST_REFUSED (anon-site servers refuse to proxy non-anon resources) |
| 59 | BAD_REQUEST |

### 5.6. `6x` (reserved)

`6x` is reserved for future client-authentication mechanisms (the
analogue of Gemini's client-certificate-required statuses). v0.1
clients receiving a 6x SHOULD treat it as `50` and display the META.

---

## 6. `text/anon` content format

`text/anon` is a line-based Markdown subset. The client renders
each line based on its type, determined entirely by its leading
characters.

### 6.1. Line types

| Prefix | Type | Notes |
|---|---|---|
| (no prefix) | Plain text | Rendered as wrapped paragraph text. Consecutive plain lines are joined into one paragraph; an empty line ends the paragraph. |
| `# ` | Heading level 1 | Top-of-page heading. |
| `## ` | Heading level 2 | |
| `### ` | Heading level 3 | Three levels only; deeper headings render as h3. |
| `=> ` | Link | Format: `=> <URL>[ <description>]`. URL can be `anon://`, `https://`, `mailto:`, etc. Clients SHOULD display non-`anon://` links with a marker indicating they leave the anon-network. |
| `* ` | List item | One per line. Nested lists not supported in v0.1. |
| `> ` | Blockquote | Single-line; for multiline use consecutive `>` lines. |
| ` ```​` | Code block fence | Toggles preformatted mode. Inside, all lines render verbatim (monospace, no wrapping). |
| (alone in toggled fence) | Code block content | |

Trailing whitespace on a line MUST be ignored. Lines longer than 4096
bytes MAY be truncated by the client.

### 6.2. Rendering guidance (non-normative)

- Plain text wraps at the viewport width.
- Headings are larger / bolder than plain text.
- Links on their own line are rendered as clickable; the optional
  description is the link text, and the URL is shown as supplementary
  information (often dimmed or on hover).
- Code blocks use a monospace font and a subtle background.
- Blockquotes use indentation and/or a left border.

> **Design decision (v0.1):** the format is intentionally MORE
> restrictive than Markdown. No inline links (every link is on its
> own line), no inline images (links to images explicit), no inline
> formatting (no `**bold**`, no `_italic_`). The motivation is
> rendering simplicity and removing whole categories of injection
> attacks. A future revision MAY add inline formatting if there's
> demand.

### 6.3. Encoding

`text/anon` MUST be UTF-8. The charset MAY be specified explicitly
in META (`text/anon; charset=utf-8`) but the default is UTF-8 in
all cases.

---

## 7. Security considerations

### 7.1. What the anon-site protocol protects

- **Server identity authentication.** The underlying v0.2 transport
  proves to the client that the bytes came from the holder of the
  service's `SVC_sk` (via the descriptor signature + rendezvous
  handshake). Anon-site itself adds nothing here.
- **End-to-end encryption.** Inherited from v0.2 cell-layer AEAD.
- **No client-side code execution.** Servers cannot ship code that
  runs in the client's context.

### 7.2. What it does NOT protect

- **Server-side application bugs.** A server SQL-injection vuln
  is a server problem; the protocol doesn't help.
- **Server-side anonymity.** A site that asks for personal info via
  INPUT learns that info; the protocol doesn't prevent that.
- **Client-side fingerprinting via response timing.** Different
  resources take different times to fetch; an on-path observer
  (entry guard, exit relay) could potentially correlate. Mitigation
  is at the transport layer (padding cells; out of scope here).
- **Link-traversal de-anonymisation.** Clicking a link to a
  clearnet `https://` URL exits the anon-network. Clients SHOULD
  prompt before following.
- **Long-living URL handles.** A URL that includes a stable
  identifier (`?session=abc123`) embedded by a server can fingerprint
  a returning user. Servers SHOULD avoid this; clients SHOULD
  display URL-query components visibly so users notice.

### 7.3. Defensive recommendations for clients

- **Reject responses with malformed status lines or oversized META.**
  Treat as a server bug.
- **Limit redirect chains.** RECOMMENDED ≤ 5.
- **Display the destination URL before following a link.** Don't
  auto-follow `3x` redirects to a different `.anon` address without
  user confirmation.
- **Highlight non-`anon://` links.** Make it visually obvious that
  clicking will exit the network.
- **Don't cache aggressively.** Cached resources reveal "this user
  previously visited X." Per-session in-memory cache only.

### 7.4. Defensive recommendations for servers

- **Reject URLs you don't recognise.** Return `51` (NOT_FOUND), not
  `40` (TEMPORARY_FAILURE), to avoid leaking which paths exist
  through response-timing differences.
- **Constant-time response times where feasible.** Particularly
  important for the `INPUT`/`SENSITIVE_INPUT` flow — answering
  "valid input" vs "invalid input" should take the same wall-clock
  time.
- **No third-party resources.** Don't embed (e.g. via redirect chains)
  resources from other `.anon` sites unless absolutely necessary.
  Each cross-site fetch is an additional anonymity surface.

---

## 8. Reference implementation

The reference codecs for request, response, and `text/anon` are
implemented in `modules/v2-site/`. A reference client (CLI) and
server (HTTP-style) are planned for a follow-on chunk; they require
the v0.2 transport runtime to actually carry anon-site bytes
end-to-end, and that runtime is not yet complete.

---

## 9. Appendix A: Design ledger

| § | Decision | Alternative considered | Rationale |
|---|---|---|---|
| 1 | "Auditable in an afternoon" goal | HTTP/1.1 subset, HTTP/2 | smaller spec = smaller attack surface = more independent implementations |
| 2 | `anon://` URL scheme | reuse `https://` | unambiguous to clients; no confusion with TLS-over-clearnet |
| 3 | Persistent sessions (multi-request) | Gemini's one-per-session | rendezvous splice is expensive (~6 hops + seconds); amortise across requests |
| 4.1 | URL only, no body | HTTP-style request body | INPUT mechanism covers form submissions; no MIME negotiation needed |
| 5.1 | INPUT for single-line input | dedicated form protocol | sufficient for v0.1; multi-field forms can use multiple INPUT exchanges |
| 6 | Markdown subset, no inline formatting | full Markdown / HTML | rendering simplicity; removes injection vectors |
| 7.2 | No protocol-level fingerprinting defence | per-request padding cells | belongs at transport layer (v0.2 spec § 5.5) |
| 7.4 | Servers SHOULD return constant-time responses | spec-level enforcement | timing depends on language/runtime; recommend, don't mandate |

---

## 10. Appendix B: Differences from Gemini

| | Gemini | Anon-Site v0.1 |
|---|---|---|
| URL scheme | `gemini://` | `anon://` |
| Address authority | DNS | `.anon` (32-byte Ed25519 pubkey + checksum) |
| Transport | TLS-over-TCP | anon-layer session (post-rendezvous) |
| Session model | one-request-per-session | persistent, multi-request |
| Server auth | TLS certificate | descriptor signature + rendezvous handshake (cryptographic) |
| Client auth | TLS client certificates | not in v0.1 (reserved `6x` status range) |
| Status codes | 2-digit, 10-69 | 2-digit, 10-69 (mirrored) |
| Content format | text/gemini (line-based Markdown subset) | text/anon (essentially identical, slightly stricter) |
| Inline media | none | none |
| Inline formatting | bold/italic recently added | none |

Anon-site is essentially Gemini with: (a) a different URL scheme and
identity authority, (b) persistent sessions to amortise rendezvous
cost, and (c) slightly stricter `text/anon` (no inline formatting).
The wire format is *almost* byte-identical so a Gemini client could
be adapted to anon-sites by swapping the transport.

---

## Document status

This is an early draft. Before reference clients/servers are built,
the following should be settled:

- Concrete byte layout for the `; length=<N>` MIME parameter.
- Whether to specify a `; charset=` token at all (UTF-8 might just be
  mandatory).
- Whether links can have a description that wraps multiple words
  cleanly, and how clients normalize whitespace.
- A concrete media-type for `application/octet-stream` downloads in
  the pipelined case.

The protocol is intentionally small. Each future addition is
spec-debt; the bar for adding features is high.
