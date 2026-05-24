#!/usr/bin/env node
// anon-browse — terminal-UI browser for the anon-layer network.
// PRE-AUDIT EXPERIMENTAL.
//
// Single file, no GUI dependencies. Renders text/anon to the terminal
// with ANSI escapes. Numbered links. Back/forward history. Scroll
// navigation. Help screen.
//
// In this build the browser dials a fixed TCP target supplied via
// `--connect host:port`. Once the v0.2 rendezvous protocol is wired
// (chunk 7.7c), it will resolve `anon://<onion>.anon/` natively
// through the network and `--connect` becomes a development override.

import { createConnection } from 'node:net';
import { readFile } from 'node:fs/promises';

import { fetchOnce } from '../modules/v2-site/client.mjs';
import {
    parseSuccessMeta,
    isSuccess,
    isRedirect,
    isInput,
} from '../modules/v2-site/response.mjs';
import { parseDocument } from '../modules/v2-site/text_anon.mjs';
import { createNodeIdentity } from '../modules/v2-runtime/persistence.mjs';
import { createLinkManager } from '../modules/v2-runtime/link_manager.mjs';
import { createCircuitDispatcher } from '../modules/v2-runtime/circuit_dispatcher.mjs';
import { createCellRouter } from '../modules/v2-runtime/cell_router.mjs';
import { createPeerResolver } from '../modules/v2-runtime/peer_resolver.mjs';
import { createCircuitBuilder } from '../modules/v2-runtime/circuit_builder.mjs';
import { openHiddenService } from '../modules/v2-runtime/rendezvous_client.mjs';
import { StreamDuplex } from '../modules/v2-runtime/stream_duplex.mjs';
import {
    loadConsensus, loadDaTrustSet,
} from '../modules/v2-runtime/consensus_loader.mjs';
import { parseServiceDescriptorAny } from '../modules/v2/descriptor.mjs';
import {
    selectMiddle,
    FLAG_GUARD,
    FLAG_RUNNING,
    FLAG_VALID,
} from '../modules/v2/consensus.mjs';

// ----- CLI arg parsing -----

const USAGE = `\
anon-browse — TUI browser for the anon-layer network (PRE-AUDIT)

Usage:
  Direct (development) mode — dial a TCP target for every fetch:
    anon-browse [URL] --connect host:port [--no-color] [--dump]

  Rendezvous mode — resolve anon:// URLs via real hidden-service rendezvous:
    anon-browse [URL] --consensus PATH --da-trust PATH --descriptor PATH
                      [--no-color] [--dump]

Arguments:
  URL                  Starting URL. Required if --dump; otherwise the
                       TUI prompts on launch.

Mode flags (pick exactly one mode):
  --connect host:port  Direct TCP dial. Useful for development against
                       a local anon-site-server.
  --consensus PATH     Binary consensus file.
  --da-trust PATH      JSON DA-trust file.
  --descriptor PATH    Service descriptor file (one per hidden service).
                       The browser uses the consensus + descriptor +
                       openHiddenService to resolve anon:// URLs.
  --allow-co-located   Skip /16-anti-correlation between path hops
                       (testnet only — weakens anonymity).

Other flags:
  --no-color           Disable ANSI colour. Useful for dumb terminals.
  --dump               Fetch the URL, render once to stdout, exit. No
                       TUI; non-interactive. Useful for scripts and CI.

Keys (view mode):
  j / ↓               Scroll down one line
  k / ↑               Scroll up one line
  Space / PgDn        Scroll down one page
  PgUp                Scroll up one page
  g g / Home          Jump to top
  G   / End           Jump to bottom
  g                   Open URL bar
  1 2 3 …             Follow numbered link (single-digit shortcut)
  :                   Open link selector (multi-digit)
  b                   Go back
  f                   Go forward
  r                   Reload current URL
  ?                   Show help
  q                   Quit
`;

const die = (msg, code = 1) => {

    process.stderr.write(`error: ${msg}\n`);
    process.exit(code);

};

const parseArgs = () => {

    const args = process.argv.slice(2);
    let url = null;
    let connect = null;
    let consensusPath = null;
    let daTrustPath = null;
    let descriptorPath = null;
    let color = process.stdout.isTTY === true;
    let dump = false;
    let skipAntiCorrelation = false;
    for (let i = 0; i < args.length; i += 1) {

        const a = args[i];
        if (a === '--help' || a === '-h') { process.stdout.write(USAGE); process.exit(0); }
        if (a === '--connect')    { connect = args[i + 1]; i += 1; continue; }
        if (a === '--consensus')  { consensusPath = args[i + 1]; i += 1; continue; }
        if (a === '--da-trust')   { daTrustPath = args[i + 1]; i += 1; continue; }
        if (a === '--descriptor') { descriptorPath = args[i + 1]; i += 1; continue; }
        if (a === '--no-color')   { color = false; continue; }
        if (a === '--dump')       { dump = true; continue; }
        if (a === '--allow-co-located') { skipAntiCorrelation = true; continue; }
        if (a.startsWith('--'))   die(`unknown option: ${a}`);
        if (url === null)         { url = a; continue; }
        die(`unexpected argument: ${a}`);

    }
    const hasDirect = connect !== null;
    const hasRendezvous = consensusPath || daTrustPath || descriptorPath;
    if (hasDirect && hasRendezvous) {

        die('use --connect OR rendezvous flags (--consensus/--da-trust/--descriptor), not both');

    }
    if (!hasDirect && !hasRendezvous) {

        die('one mode required: --connect HOST:PORT  OR  --consensus PATH --da-trust PATH --descriptor PATH');

    }
    if (hasRendezvous && !(consensusPath && daTrustPath && descriptorPath)) {

        die('rendezvous mode requires all three of --consensus, --da-trust, --descriptor');

    }
    if (dump && url === null) die('--dump requires a URL argument');

    let host = null;
    let port = null;
    if (hasDirect) {

        const parts = connect.split(':');
        host = parts[0]; port = parseInt(parts[1], 10);
        if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {

            die(`bad --connect value: ${connect}`);

        }

    }
    return {
        url, color, dump,
        mode: hasDirect ? 'connect' : 'rendezvous',
        host, port, consensusPath, daTrustPath, descriptorPath,
        skipAntiCorrelation,
    };

};

// ----- ANSI -----

const ESC = '\x1b[';
const RESET = `${ESC}0m`;
const ANSI = {
    clear:      `${ESC}2J`,
    cursorTo:   (row, col) => `${ESC}${row};${col}H`,
    cursorHide: `${ESC}?25l`,
    cursorShow: `${ESC}?25h`,
    clearLine:  `${ESC}2K`,
    eraseToEnd: `${ESC}0K`,
};

const styles = (enabled) => {

    if (!enabled) return {
        bold: (s) => s, dim: (s) => s, underline: (s) => s,
        cyan: (s) => s, yellow: (s) => s, green: (s) => s,
        red: (s) => s, blue: (s) => s,
        reverse: (s) => s, statusBar: (s) => s,
    };
    return {
        bold:      (s) => `${ESC}1m${s}${RESET}`,
        dim:       (s) => `${ESC}2m${s}${RESET}`,
        underline: (s) => `${ESC}4m${s}${RESET}`,
        cyan:      (s) => `${ESC}36m${s}${RESET}`,
        yellow:    (s) => `${ESC}33m${s}${RESET}`,
        green:     (s) => `${ESC}32m${s}${RESET}`,
        red:       (s) => `${ESC}31m${s}${RESET}`,
        blue:      (s) => `${ESC}34m${s}${RESET}`,
        reverse:   (s) => `${ESC}7m${s}${RESET}`,
        statusBar: (s) => `${ESC}30;47m${s}${RESET}`,
    };

};

// ----- Layout: lay out a parsed text/anon document into render rows -----
//
// Each line of the doc becomes 1+ display rows depending on viewport
// width. Links get assigned sequential numbers; the result includes
// a `links` array mapping link number → URL for the input handler.

const STRIP_ANSI = /\x1b\[[0-9;]*m/g;
const visibleWidth = (s) => s.replace(STRIP_ANSI, '').length;

const wrapLine = (text, width) => {

    if (text.length === 0) return [''];
    const out = [];
    const words = text.split(/(\s+)/); // keep separators
    let cur = '';
    for (const tok of words) {

        if (cur.length + tok.length <= width) {

            cur += tok;

        } else if (tok.length > width) {

            // Long token; hard-break.
            if (cur.length > 0) { out.push(cur); cur = ''; }
            for (let i = 0; i < tok.length; i += width) {

                const piece = tok.slice(i, i + width);
                if (piece.length === width) out.push(piece);
                else cur = piece;

            }

        } else {

            if (cur.length > 0) out.push(cur);
            cur = tok.trimStart();

        }

    }
    if (cur.length > 0) out.push(cur);
    return out;

};

const layoutDocument = ({ doc, width, st }) => {

    const rows = [];
    const links = []; // index 1-based when rendered
    let inCode = false;

    for (const line of doc) {

        switch (line.type) {

            case 'heading1': {

                const text = st.bold(st.yellow(`▎ ${line.text}`));
                rows.push(''); rows.push(text); rows.push('');
                break;

            }
            case 'heading2': {

                rows.push('');
                rows.push(st.bold(`  ${line.text}`));
                break;

            }
            case 'heading3': {

                rows.push(st.bold(st.dim(`    ${line.text}`)));
                break;

            }
            case 'link': {

                links.push({ url: line.url, description: line.description });
                const n = links.length;
                const display = line.description !== null ? line.description : line.url;
                // Same-network: anon:// (absolute) or starts with '/'
                // (relative same-site, resolved at navigate time).
                const inNetwork = line.url.startsWith('anon://') || line.url.startsWith('/');
                const marker = inNetwork ? st.cyan(`[${n}]`) : st.yellow(`[${n}↗]`);
                const linkText = st.underline(display);
                const hint = st.dim(`(${line.url})`);
                const full = `${marker} ${linkText} ${hint}`;
                // For wrapping, we strip the styled wrapper from
                // calculations but keep it in output. Simplest: don't
                // wrap link lines; truncate if longer than viewport.
                if (visibleWidth(full) <= width) rows.push(full);
                else rows.push(full.slice(0, width)); // approximation
                break;

            }
            case 'listItem': {

                const inner = wrapLine(line.text, width - 4);
                for (let i = 0; i < inner.length; i += 1) {

                    if (i === 0) rows.push(`  ${st.green('•')} ${inner[i]}`);
                    else rows.push(`    ${inner[i]}`);

                }
                break;

            }
            case 'blockquote': {

                const inner = wrapLine(line.text, width - 4);
                for (const p of inner) rows.push(st.dim(`  │ ${p}`));
                break;

            }
            case 'codeFence':
                inCode = !inCode;
                // Don't render the fence itself; visual separation comes
                // from the indent style of the code lines.
                break;

            case 'code': {

                rows.push(`    ${st.dim(line.text)}`);
                break;

            }
            case 'blank':
                rows.push('');
                break;

            case 'plain':
            default: {

                const wrapped = wrapLine(line.text, width);
                for (const p of wrapped) rows.push(p);
                break;

            }

        }

    }
    return { rows, links };

};

// ----- Browser state -----

const createBrowserState = ({ initialUrl }) => ({
    mode: 'view',           // view | input | help
    inputContext: null,     // 'url' | 'link'
    inputBuffer: '',
    currentUrl: initialUrl,
    currentPage: null,      // { rows: [...], links: [...] } or null
    pageStatus: null,       // last response status code
    pageMeta: null,         // last response META
    scrollOffset: 0,
    history: [],            // URLs visited before currentUrl
    future: [],             // URLs popped via 'b'; pushed via 'f'
    statusMessage: null,    // ephemeral line at the bottom
    fetching: false,
    error: null,            // user-facing error to display
});

// ----- Fetching -----

const fetchAndRender = async ({ state, url, acquireSocket, st, width }) => {

    state.fetching = true;
    state.statusMessage = `Loading ${url}…`;
    state.error = null;
    repaint(state, st, width);

    try {

        // `acquireSocket` either dials a TCP target (--connect mode) or
        // opens a new stream on an existing rendezvous (--descriptor
        // mode). Both return a Node-Duplex-compatible socket-like object.
        const socket = await acquireSocket();
        let response;
        try {

            response = await fetchOnce({ socket, url, timeoutMs: 30000 });

        } finally {

            try { socket.end(); } catch { /* ignore */ }

        }

        state.pageStatus = response.status;
        state.pageMeta = response.meta;
        state.statusMessage = null;

        if (isRedirect(response.status)) {

            const next = response.meta.trim();
            state.statusMessage = `→ ${response.status} ${response.meta}`;
            // For simplicity v1 doesn't auto-follow; user can press
            // a numbered link if the redirect URL was given to them.
            state.currentPage = {
                rows: [
                    '',
                    st.yellow(`Redirect ${response.status}: ${response.meta}`),
                    '',
                    st.dim('  Press g to enter the redirect URL.'),
                    '',
                ],
                links: next.startsWith('anon://') ? [{ url: next, description: 'Follow redirect' }] : [],
            };

        } else if (isInput(response.status)) {

            state.currentPage = {
                rows: [
                    '',
                    st.yellow(`Server requests input: ${response.meta}`),
                    '',
                    st.dim('  v1 of anon-browse does not yet prompt for input. Re-issue'),
                    st.dim('  the URL with the input encoded as ?query.'),
                    '',
                ],
                links: [],
            };

        } else if (!isSuccess(response.status) || response.body === null) {

            state.currentPage = {
                rows: [
                    '',
                    st.red(`Error ${response.status}: ${response.meta}`),
                    '',
                ],
                links: [],
            };

        } else {

            const mime = parseSuccessMeta(response.meta);
            const mimeType = mime ? mime.mimeType : 'application/octet-stream';
            if (mimeType === 'text/anon') {

                const text = new TextDecoder('utf-8', { fatal: false }).decode(response.body);
                const doc = parseDocument(text);
                state.currentPage = layoutDocument({ doc, width, st });

            } else if (mimeType.startsWith('text/')) {

                const text = new TextDecoder('utf-8', { fatal: false }).decode(response.body);
                const rows = [];
                for (const line of text.split('\n')) {

                    const wrapped = wrapLine(line, width);
                    for (const p of wrapped) rows.push(p);

                }
                state.currentPage = { rows, links: [] };

            } else {

                state.currentPage = {
                    rows: [
                        '',
                        st.yellow(`Binary content: ${mimeType}, ${response.body.length} bytes`),
                        '',
                        st.dim('  anon-browse v1 does not render non-text content. Use the'),
                        st.dim('  CLI client (bin/anon-site-client.mjs) with --raw to download.'),
                        '',
                    ],
                    links: [],
                };

            }

        }

        state.scrollOffset = 0;

    } catch (err) {

        state.error = err.message;
        state.currentPage = {
            rows: ['', st.red(`Fetch failed: ${err.message}`), ''],
            links: [],
        };
        state.scrollOffset = 0;

    } finally {

        state.fetching = false;
        state.statusMessage = null;

    }

};

// ----- Navigation -----

// Resolve a possibly-relative URL against the current page's URL.
// Relative formats supported:
//   /path           → same host, replace path
//   ?query          → same host + path, replace query
//   path or ./path  → relative-to-current-path
// Absolute anon:// passes through unchanged.
const resolveUrl = (currentUrl, target) => {

    if (target.startsWith('anon://')) return target;
    if (!currentUrl || !currentUrl.startsWith('anon://')) return target;

    const after = currentUrl.slice('anon://'.length);
    const slashIdx = after.indexOf('/');
    const queryIdx = after.indexOf('?');
    let hostEnd = after.length;
    if (slashIdx !== -1) hostEnd = Math.min(hostEnd, slashIdx);
    if (queryIdx !== -1) hostEnd = Math.min(hostEnd, queryIdx);
    const host = after.slice(0, hostEnd);
    const path = slashIdx === -1 ? '/'
        : after.slice(slashIdx, queryIdx === -1 ? undefined : queryIdx);

    if (target.startsWith('/')) {

        return `anon://${host}${target}`;

    }
    if (target.startsWith('?')) {

        return `anon://${host}${path}${target}`;

    }
    // Plain relative: replace the last path segment.
    const lastSlash = path.lastIndexOf('/');
    const base = lastSlash === -1 ? '/' : path.slice(0, lastSlash + 1);
    return `anon://${host}${base}${target}`;

};

const navigateTo = async (state, target, ctx) => {

    const url = resolveUrl(state.currentUrl, target);
    if (state.currentUrl !== null) state.history.push(state.currentUrl);
    state.future = [];
    state.currentUrl = url;
    await fetchAndRender({ state, url, ...ctx });

};

const goBack = async (state, ctx) => {

    if (state.history.length === 0) return;
    state.future.push(state.currentUrl);
    state.currentUrl = state.history.pop();
    await fetchAndRender({ state, url: state.currentUrl, ...ctx });

};

const goForward = async (state, ctx) => {

    if (state.future.length === 0) return;
    state.history.push(state.currentUrl);
    state.currentUrl = state.future.pop();
    await fetchAndRender({ state, url: state.currentUrl, ...ctx });

};

// ----- Render -----

const HELP_TEXT = [
    '',
    ' Keys (view mode):',
    '   j / ↓             scroll down one line',
    '   k / ↑             scroll up one line',
    '   Space / PgDn      scroll down one page',
    '   PgUp              scroll up one page',
    '   g (then g)        jump to top',
    '   G                 jump to bottom',
    '   g                 open URL bar',
    '   1 2 3 …           follow numbered link (single-digit)',
    '   :                 open link selector (multi-digit)',
    '   b                 go back',
    '   f                 go forward',
    '   r                 reload current URL',
    '   ?                 toggle this help',
    '   q                 quit',
    '',
    ' In URL/link entry:',
    '   Enter             submit',
    '   Esc               cancel',
    '   Backspace         delete last character',
    '',
    ' Press any key to return to the page.',
    '',
];

const repaint = (state, st, width) => {

    // Don't repaint to stdout if we're in --dump mode (non-TTY) — the
    // loading-cursor frames would corrupt the dump output.
    if (!process.stdout.isTTY) return;
    const rows = process.stdout.rows || 24;

    // Build the full screen.
    let out = ANSI.cursorHide;
    out += ANSI.clear;

    // Header: URL line (row 1).
    out += ANSI.cursorTo(1, 1);
    const urlLabel = state.fetching ? '...' : '   ';
    const urlText = state.currentUrl || '(no page)';
    out += st.statusBar(` ${urlLabel} ${urlText} `.padEnd(width));

    // Content area: rows 2 .. rows-2.
    const contentTop = 2;
    const contentBottom = rows - 1;
    const contentHeight = contentBottom - contentTop + 1;

    let displayRows;
    if (state.mode === 'help') {

        displayRows = HELP_TEXT;

    } else if (state.currentPage) {

        displayRows = state.currentPage.rows;

    } else {

        displayRows = [
            '',
            ' anon-browse v0.1 — press g to enter a URL, ? for help, q to quit.',
            '',
        ];

    }
    const start = Math.max(0, Math.min(state.scrollOffset, Math.max(0, displayRows.length - contentHeight)));
    state.scrollOffset = start;
    for (let i = 0; i < contentHeight; i += 1) {

        out += ANSI.cursorTo(contentTop + i, 1);
        const row = displayRows[start + i] !== undefined ? displayRows[start + i] : '';
        out += row;
        out += ANSI.eraseToEnd;

    }

    // Footer: row rows-0 (last row, status / input prompt).
    out += ANSI.cursorTo(rows, 1);
    let footer;
    if (state.mode === 'input' && state.inputContext === 'url') {

        footer = `${st.bold('url:')} ${state.inputBuffer}_`;

    } else if (state.mode === 'input' && state.inputContext === 'link') {

        footer = `${st.bold('link #')} ${state.inputBuffer}_`;

    } else if (state.error) {

        footer = st.red(state.error);

    } else if (state.statusMessage) {

        footer = st.dim(state.statusMessage);

    } else {

        const linkCount = state.currentPage ? state.currentPage.links.length : 0;
        footer = st.dim(
            `${linkCount} link${linkCount === 1 ? '' : 's'}  `
            + `· j/k scroll · g url · 1-9 follow · b back · f fwd · ? help · q quit`,
        );

    }
    out += footer;
    out += ANSI.eraseToEnd;

    process.stdout.write(out);

};

// ----- Input -----

const setupRawInput = (onKey) => {

    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (data) => {

        for (const ch of data) onKey(ch);

    });

};

// ----- Main loop -----

// One-shot fetch + render to stdout. Used by `--dump` and by scripts /
// CI that want the layout output but not the TUI.
const runDump = async ({ url, acquireSocket, color }) => {

    const st = styles(color);
    const width = process.stdout.columns || 80;
    const state = createBrowserState({ initialUrl: url });
    await fetchAndRender({ state, url, acquireSocket, st, width });
    if (state.error) {

        process.stderr.write(`error: ${state.error}\n`);
        process.exit(1);

    }
    process.stdout.write(`URL:    ${url}\n`);
    if (state.pageStatus) {

        process.stdout.write(`STATUS: ${state.pageStatus} ${state.pageMeta || ''}\n`);

    }
    process.stdout.write('\n');
    for (const row of (state.currentPage ? state.currentPage.rows : [])) {

        process.stdout.write(`${row}\n`);

    }
    if (state.currentPage && state.currentPage.links.length > 0) {

        process.stdout.write('\nLinks:\n');
        for (let i = 0; i < state.currentPage.links.length; i += 1) {

            const link = state.currentPage.links[i];
            const desc = link.description !== null ? link.description : link.url;
            process.stdout.write(`  [${i + 1}] ${desc} ${st.dim(`(${link.url})`)}\n`);

        }

    }
    process.exit(state.pageStatus && state.pageStatus < 40 ? 0 : 1);

};

// Build an `acquireSocket` function for direct (TCP) mode.
const buildDirectSocketAcquirer = ({ host, port }) => async () => new Promise((res, rej) => {

    const s = createConnection({ host, port });
    s.once('connect', () => res(s));
    s.once('error', rej);

});

// Build an `acquireSocket` function for rendezvous mode. Lazily opens
// the hidden service on first use (which builds two circuits + does
// the full rendezvous handshake) and caches the conn. Subsequent
// fetches reuse the same circuit via additional streams.
const buildRendezvousSocketAcquirer = async ({ consensusPath, daTrustPath, descriptorPath, skipAntiCorrelation }) => {

    const daTrust = await loadDaTrustSet(daTrustPath);
    const consensus = await loadConsensus({ path: consensusPath, daTrustSet: daTrust });
    const descriptorBytes = await readFile(descriptorPath);
    const descriptor = parseServiceDescriptorAny(new Uint8Array(descriptorBytes));
    if (!descriptor) throw new Error(`could not parse descriptor at ${descriptorPath}`);

    const clientIdentity = createNodeIdentity();
    const peerResolver = createPeerResolver({ consensus });
    const routerHolder = { router: null };
    const linkMgr = createLinkManager({
        identity: clientIdentity,
        onCell: (link, cell) => { if (routerHolder.router) routerHolder.router.onCell(link, cell); },
    });
    const dispatcher = createCircuitDispatcher({
        identity: clientIdentity, linkManager: linkMgr, peerResolver,
    });
    routerHolder.router = createCellRouter({ relayDispatcher: dispatcher });
    const circuitBuilder = createCircuitBuilder({
        linkManager: linkMgr, cellRouter: routerHolder.router, peerResolver,
    });

    // Build a path that exits at the specified relay. Custom
    // selection (rather than pickPath + swap-exit) so guard and middle
    // never collide with the forced exit — a collision causes a
    // self-dial loop when the middle hop tries to EXTEND.
    const fpEq = (a, b) => Buffer.from(a).equals(Buffer.from(b));
    const pickRand = (arr) => arr[Math.floor(Math.random() * arr.length)];
    const buildPath = ({ exitFingerprint }) => {

        const exitRse = consensus.rses.find((r) => fpEq(r.fingerprint, exitFingerprint));
        if (!exitRse) throw new Error('exit fingerprint not in consensus');
        const guardCandidates = consensus.rses.filter((r) => (
            (r.flags & (FLAG_RUNNING | FLAG_VALID | FLAG_GUARD)) === (FLAG_RUNNING | FLAG_VALID | FLAG_GUARD)
            && !fpEq(r.fingerprint, exitFingerprint)
        ));
        if (guardCandidates.length === 0) throw new Error('no guard candidate distinct from forced exit');
        const guard = pickRand(guardCandidates);
        const middle = selectMiddle({
            consensus,
            excludeFps: [guard.fingerprint, exitFingerprint],
            coLocateAvoid: skipAntiCorrelation ? [] : [guard, exitRse],
        });
        if (!middle) throw new Error('no middle candidate');
        return { guard, middle, exit: exitRse };

    };

    let conn = null;
    const ensureConn = async () => {

        if (conn) return conn;
        conn = await openHiddenService({
            descriptor,
            SVC_pk: descriptor.SVC_pk_ed || descriptor.SVC_pk,
            consensus,
            rpPathFn: ({ rpRse }) => buildPath({ exitFingerprint: rpRse.fingerprint }),
            ipPathFn: ({ ipFingerprint }) => buildPath({ exitFingerprint: ipFingerprint }),
            circuitBuilder,
        });
        return conn;

    };

    const acquire = async () => {

        const c = await ensureConn();
        const stream = await c.openStream({ port: 80 });
        return new StreamDuplex(stream);

    };
    acquire._cleanup = () => {

        try { conn && conn.close(); } catch { /* ignore */ }
        try { dispatcher.closeAll(); } catch { /* ignore */ }
        try { linkMgr.closeAll(); } catch { /* ignore */ }

    };
    return acquire;

};

const main = async () => {

    const parsed = parseArgs();
    const { url: initialUrl, color, dump, mode } = parsed;
    const st = styles(color);

    const acquireSocket = mode === 'connect'
        ? buildDirectSocketAcquirer({ host: parsed.host, port: parsed.port })
        : await buildRendezvousSocketAcquirer({
            consensusPath: parsed.consensusPath,
            daTrustPath: parsed.daTrustPath,
            descriptorPath: parsed.descriptorPath,
            skipAntiCorrelation: parsed.skipAntiCorrelation,
        });

    if (dump) {

        try { await runDump({ url: initialUrl, acquireSocket, color }); }
        finally { acquireSocket._cleanup && acquireSocket._cleanup(); }
        return;

    }

    if (!process.stdout.isTTY) {

        die('anon-browse requires a TTY for interactive input. For one-shot fetches pass --dump.');

    }

    let width = process.stdout.columns || 80;
    process.stdout.on('resize', () => {

        width = process.stdout.columns || 80;
        repaint(state, st, width);

    });

    const state = createBrowserState({ initialUrl });
    const ctx = { acquireSocket, st, get width() { return width; } };

    // Initial fetch (if URL supplied).
    if (initialUrl) {

        await fetchAndRender({ state, url: initialUrl, acquireSocket, st, width });

    }
    repaint(state, st, width);

    let pendingG = false; // for 'gg' (jump-to-top)

    const onKey = async (key) => {

        // Universal: Ctrl-C, q in view, anything in help dismisses help.
        if (key === '') return quit();
        if (state.mode === 'help') { state.mode = 'view'; repaint(state, st, width); return; }

        if (state.mode === 'view') {

            switch (key) {

                case 'q': return quit();
                case '?': state.mode = 'help'; state.scrollOffset = 0; return repaint(state, st, width);
                case 'j':
                case '[B':
                    state.scrollOffset += 1; return repaint(state, st, width);
                case 'k':
                case '[A':
                    state.scrollOffset = Math.max(0, state.scrollOffset - 1); return repaint(state, st, width);
                case ' ':
                case '[6~':
                    state.scrollOffset += Math.max(1, (process.stdout.rows || 24) - 4); return repaint(state, st, width);
                case '[5~':
                    state.scrollOffset = Math.max(0, state.scrollOffset - ((process.stdout.rows || 24) - 4)); return repaint(state, st, width);
                case 'G':
                case '[F':
                    if (state.currentPage) state.scrollOffset = Math.max(0, state.currentPage.rows.length - 1);
                    return repaint(state, st, width);
                case 'b': await goBack(state, { acquireSocket, st, width }); return repaint(state, st, width);
                case 'f': await goForward(state, { acquireSocket, st, width }); return repaint(state, st, width);
                case 'r':
                    if (state.currentUrl) {

                        await fetchAndRender({ state, url: state.currentUrl, host, port, st, width });

                    }
                    return repaint(state, st, width);
                case ':':
                    state.mode = 'input'; state.inputContext = 'link'; state.inputBuffer = '';
                    return repaint(state, st, width);
                default:
                    // gg: jump to top
                    if (key === 'g' && pendingG) {

                        pendingG = false;
                        state.scrollOffset = 0;
                        return repaint(state, st, width);

                    }
                    if (key === 'g' && !pendingG) {

                        pendingG = true;
                        setTimeout(() => { pendingG = false; }, 500);
                        // Also open URL bar if user follows 'g' with anything else.
                        // We handle this by checking pendingG on next key.
                        // For simplest UX, treat single 'g' as URL bar via a delay:
                        // here we don't open URL bar immediately; user can press
                        // 'g' a second time to scroll to top OR... ugh, conflict.
                        // Resolution: pressing 'g' opens URL bar. Use 'H' for top.
                        pendingG = false;
                        state.mode = 'input'; state.inputContext = 'url';
                        state.inputBuffer = state.currentUrl || 'anon://';
                        return repaint(state, st, width);

                    }
                    if (key >= '1' && key <= '9') {

                        const n = parseInt(key, 10);
                        if (state.currentPage && state.currentPage.links[n - 1]) {

                            const link = state.currentPage.links[n - 1];
                            const inNetwork = link.url.startsWith('anon://')
                                || link.url.startsWith('/')
                                || link.url.startsWith('?');
                            if (inNetwork) {

                                await navigateTo(state, link.url, { acquireSocket, st, width });

                            } else {

                                state.statusMessage = `Won't follow off-network link: ${link.url}`;

                            }

                        }
                        return repaint(state, st, width);

                    }
                    return; // unknown key

            }

        }

        if (state.mode === 'input') {

            if (key === '\r' || key === '\n') {

                // Submit.
                const submitted = state.inputBuffer;
                const ctx2 = state.inputContext;
                state.mode = 'view';
                state.inputContext = null;
                state.inputBuffer = '';
                if (ctx2 === 'url') {

                    if (submitted.length > 0) {

                        await navigateTo(state, submitted, { acquireSocket, st, width });

                    }

                } else if (ctx2 === 'link') {

                    const n = parseInt(submitted, 10);
                    if (Number.isInteger(n) && state.currentPage && state.currentPage.links[n - 1]) {

                        const link = state.currentPage.links[n - 1];
                        const inNetwork = link.url.startsWith('anon://')
                            || link.url.startsWith('/')
                            || link.url.startsWith('?');
                        if (inNetwork) {

                            await navigateTo(state, link.url, { acquireSocket, st, width });

                        } else {

                            state.statusMessage = `Won't follow off-network link: ${link.url}`;

                        }

                    } else {

                        state.statusMessage = `No link #${submitted}`;

                    }

                }
                return repaint(state, st, width);

            }
            if (key === '') {

                // Esc: cancel.
                state.mode = 'view'; state.inputContext = null; state.inputBuffer = '';
                return repaint(state, st, width);

            }
            if (key === '' || key === '\b') {

                state.inputBuffer = state.inputBuffer.slice(0, -1);
                return repaint(state, st, width);

            }
            if (key.length === 1 && key >= ' ') {

                state.inputBuffer += key;
                return repaint(state, st, width);

            }
            return;

        }

    };

    setupRawInput((key) => {

        onKey(key).catch((err) => {

            state.error = err.message;
            repaint(state, st, width);

        });

    });

};

const quit = () => {

    process.stdout.write(ANSI.cursorShow);
    process.stdout.write(ANSI.cursorTo(process.stdout.rows || 24, 1));
    process.stdout.write('\n');
    if (process.stdin.isTTY) process.stdin.setRawMode(false);
    process.exit(0);

};

process.on('SIGTERM', quit);
process.on('SIGINT', quit);

main().catch((err) => die(err.stack || err.message));
