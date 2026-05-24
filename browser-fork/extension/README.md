# WebExtension: anon-layer renderer

A Firefox / Mullvad Browser WebExtension that renders `anon://` pages
in-tab by talking to a local `anon-browse-gui` bridge process. This is
the **no-fork** path described in `docs/USING-MULLVAD-BROWSER.md` —
users get native-feeling `anon://` browsing today, without waiting for
the multi-month browser-fork plan in `docs/BROWSER-FORK.md`.

## Status

Functional MVP. The extension packages into a loadable `.xpi`, the
renderer matches the JSON contract that `bin/anon-browse-gui.mjs`
emits, and 25 smoke tests cover the parse → render path including
XSS-escape behaviour and link resolution. **Not yet AMO-signed.**

## Building

```bash
cd browser-fork/extension
./build-xpi.sh --validate
# → dist/anon-layer-<version>.xpi
```

`build-xpi.sh` will regenerate the placeholder icons via
`icons/generate.mjs` if they're missing. The `--validate` flag also
runs `validate.mjs` against the produced .xpi to catch manifest /
file-missing drift.

## Installing (temporary)

1. Open Mullvad Browser (or Firefox ≥ 115).
2. Navigate to `about:debugging`.
3. Click **This Firefox** → **Load Temporary Add-on…**.
4. Pick the `.xpi` from `dist/`.

The extension will live until the browser restarts. For permanent
installation, the `.xpi` must be signed by AMO
(`addons.mozilla.org`) — see § AMO submission below.

## Configuring

1. Start the bridge from a terminal:

   ```bash
   bin/anon-browse-gui.mjs \
     --consensus tests/consensus.bin \
     --da-trust  tests/da-trust.txt \
     --descriptor tests/descriptor.bin \
     --listen 127.0.0.1 --port 1081
   ```

   The bridge prints a URL like `http://127.0.0.1:1081/?token=…`.

2. Click the Anon Layer toolbar icon → **Settings** (or
   `about:addons` → Anon Layer → Preferences).

3. Paste the printed URL into the **paste-the-full-URL** field, click
   **Parse**, then **Save**. The token field will auto-fill.

4. Click **Test connection** to verify reachability.

## Entry points

The browser doesn't natively know about `anon://`, and a WebExtension
can't register it (only `web+`-prefixed schemes can be registered via
`navigator.registerProtocolHandler`; the manifest `protocol_handlers`
field can't target `moz-extension://`). The extension instead offers
four routes into the renderer:

| Entry point | How to use |
|---|---|
| Toolbar icon | Click → popup → enter URL → Go |
| Omnibox keyword | Type `anon foo.anon/bar` in the URL bar |
| Context menu (link) | Right-click any `anon://` link → "Open with Anon Layer" |
| Context menu (selection) | Highlight text that looks like an anon URL → right-click |
| Click intercept | Clicking `<a href="anon://…">` on any page is intercepted by a content script |
| `web+anon://` | Registers via `protocol_handlers`; users can click `web+anon://…` links anywhere |

## Architecture

```
User wants to visit anon://foo.anon/bar
        │
        ▼
Any entry point above
        │
        ▼
background.js (or popup.js) opens
moz-extension://<id>/render.html?u=anon%3A%2F%2Ffoo.anon%2Fbar
        │
        ▼
render.js
  1. Reads ?u= from query string
  2. Reads bridge URL + token from chrome.storage
  3. fetch(bridge + /api/fetch?url=…&token=…)
  4. Renders JSON (lines[]) to DOM via lib/render-doc.mjs
  5. Wires in-network link clicks (history.pushState; no full reload)
  6. Off-network link clicks: confirm + window.open(_, '_blank')
```

The renderer never speaks the anon-layer protocol itself — that lives
in the Node bridge (`bin/anon-browse-gui.mjs`). The extension is a
presentation-layer concern; treating the side-car as the only place
the protocol runs keeps the auditable surface area in plain Node and
lets the extension stay tiny (~40 KB unpacked).

## File layout

```
manifest.json          Manifest V3 declaration
background.js          Entry-point router (omnibox, context menu, messages)
content/intercept.js   Click-intercept content script for anon:// hyperlinks
popup.html / popup.js  Toolbar action popup
options.html / .js     Settings (bridge URL, token, test connection)
render.html / .js      In-tab renderer for anon:// URLs
lib/render-doc.mjs     Shared pure functions (renderDocument, resolveUrl, …)
common.css             Shared theme (matches anon-browse-gui)
icons/icon-{48,96,256}.png    Placeholder branding
icons/generate.mjs     Deterministic icon generator (pure Node, no deps)
build-xpi.sh           Packager → dist/*.xpi
validate.mjs           Sanity check for manifest ↔ filesystem drift
tests-extension.mjs    Smoke tests for the renderer (run via npm test)
```

## Tests

```bash
# From the repo root:
npm test
# (last block: "25 passed, 0 failed" — the extension's smoke tests)

# Or run only the extension tests:
node browser-fork/extension/tests-extension.mjs
```

Tests cover the parse → render contract (every line type in the
text/anon spec), URL canonicalization, relative-URL resolution, and
XSS escaping. They share the actual renderer code via
`lib/render-doc.mjs` — there's no second implementation to drift.

## Security

- Bridge URL is constrained to `127.0.0.1` / `::1` / `localhost`. The
  options page refuses any other host: if a user typo'd a LAN IP, all
  of their traffic would route off-machine.
- The bridge requires a session token; the extension never transmits
  the token to anything but the configured bridge URL.
- CORS on the bridge is `*` because the token is the actual auth — a
  malicious DNS-rebinding page that reaches `127.0.0.1:1081` still
  can't read responses without the token.
- The renderer escapes all text-anon content before insertion via
  `innerHTML`; the smoke tests include XSS payloads to catch
  regressions.
- Content Security Policy on `render.html`:
  `default-src 'none'; script-src 'self'; style-src 'self';
  connect-src http://127.0.0.1:* http://localhost:*; img-src 'self' data:`.
- No external network access, no analytics, no third-party scripts.

## AMO submission (for signed .xpi)

1. Pick a permanent extension ID. The current placeholder is
   `anon-layer@anon.gratis`; that's fine if you control `anon.gratis`,
   otherwise pick a domain you control.
2. Bump `version` in `manifest.json`.
3. `./build-xpi.sh`.
4. Upload `dist/anon-layer-<version>.xpi` to
   `https://addons.mozilla.org/developers/addon/submit/`. Choose
   "self-distribute" if you do not want it listed on AMO.
5. After signing, distribute the signed `.xpi` from your own URL. The
   browser will install it without "load temporary" if signed.

## Known limits

- Address bar still shows `moz-extension://<id>/render.html?u=…`
  rather than `anon://…`. A real fork (Phase 3 of `BROWSER-FORK.md`)
  can fix this; a WebExtension cannot.
- Binary `text/anon` responses other than text are not rendered;
  binary previews and download flow are TODO.
- Input-prompt responses (status 10/11) are surfaced but not
  interactive; the user has to append `?answer` to the URL manually.
- Bookmarks / history-in-network do not work natively; the browser's
  history records the extension URL, not the anon URL.

## License

AGPL-3.0-or-later — matches the parent project.
