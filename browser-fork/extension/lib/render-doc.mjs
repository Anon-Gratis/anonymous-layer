// render-doc.mjs — pure functions for rendering text/anon JSON to HTML.
//
// Lives here so render.js (in the extension) and tests-extension.mjs
// (Node) share the same implementation. The function returns HTML as a
// string; the caller is responsible for innerHTML insertion + wiring
// click handlers on the resulting <a data-target> nodes.

const escape = (s) => String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

export const escapeHtml = escape;

// Resolve a possibly-relative anon-network target against a base URL.
// Handles absolute anon:// URLs, host-relative paths ('/foo'), query
// strings ('?q'), and same-dir relative paths ('bar').
export const resolveUrl = (target, base) => {

    if (typeof target !== 'string') return '';
    if (target.startsWith('anon://') || target.startsWith('web+anon://')
        || /^(https?|ftp|mailto|gemini):/i.test(target)) {
        return target;
    }
    if (!base || !base.startsWith('anon://')) return target;
    const after = base.slice(7);
    const slash = after.indexOf('/');
    const query = after.indexOf('?');
    let hostEnd = after.length;
    if (slash !== -1) hostEnd = Math.min(hostEnd, slash);
    if (query !== -1) hostEnd = Math.min(hostEnd, query);
    const host = after.slice(0, hostEnd);
    const path = slash === -1 ? '/'
        : after.slice(slash, query === -1 ? undefined : query);
    if (target.startsWith('/')) return 'anon://' + host + target;
    if (target.startsWith('?')) return 'anon://' + host + path + target;
    const lastSlash = path.lastIndexOf('/');
    const baseDir = lastSlash === -1 ? '/' : path.slice(0, lastSlash + 1);
    return 'anon://' + host + baseDir + target;

};

// Normalize "web+anon://..." → "anon://..." (the shareable variant
// resolves to the real scheme for the bridge).
export const normalizeAnon = (u) => {

    if (typeof u !== 'string') return '';
    if (u.startsWith('web+anon://')) return 'anon://' + u.slice('web+anon://'.length);
    return u;

};

// Build a canonical anon:// URL from raw user text. Accepts:
//   anon://foo.anon/bar           → as-is
//   web+anon://foo.anon/bar       → anon://foo.anon/bar
//   foo.anon[/bar]                → anon://foo.anon[/bar]
//   "anon foo.anon/bar"           → anon://foo.anon/bar  (omnibox style)
// Returns null for empty/whitespace input.
export const canonicalAnonUrl = (raw) => {

    let s = String(raw || '').trim();
    if (s === '') return null;
    if (s.startsWith('web+anon://')) return 'anon://' + s.slice('web+anon://'.length);
    if (s.startsWith('anon://')) return s;
    if (s.startsWith('anon ')) s = s.slice(5).trim();
    return 'anon://' + s.replace(/^\/+/, '');

};

// Strict counterpart to canonicalAnonUrl: return a canonical anon://
// URL only if the input is *recognisably* a .anon target — i.e. a
// hostname whose final label is "anon", with each label a valid DNS
// label. Used by the URL-bar / search-engine interceptor so ordinary
// text like "hello world" or "anonymous donation" is not misclassified
// as an anon-network address. Strips http(s):// and web+anon:// to
// catch fixup-rewritten URLs too.
export const looksLikeAnonHost = (raw) => {

    let s = String(raw || '').trim();
    if (s === '') return null;

    const lower = s.toLowerCase();
    for (const prefix of ['web+anon://', 'anon://', 'https://', 'http://']) {
        if (lower.startsWith(prefix)) {
            s = s.slice(prefix.length);
            break;
        }
    }

    const sep = s.search(/[\/?#]/);
    const host = sep === -1 ? s : s.slice(0, sep);
    const rest = sep === -1 ? '' : s.slice(sep);

    const portIdx = host.indexOf(':');
    const hostNoPort = portIdx === -1 ? host : host.slice(0, portIdx);

    const labels = hostNoPort.split('.');
    if (labels.length < 2) return null;
    if (labels[labels.length - 1].toLowerCase() !== 'anon') return null;
    for (const label of labels) {
        if (!/^[a-z0-9][a-z0-9-]{0,62}$/i.test(label)) return null;
    }

    return 'anon://' + host + rest;

};

// Render a text/anon line array (as produced by
// modules/v2-site/text_anon.mjs's parseDocument) to an HTML string.
// Output uses class hooks defined in common.css.
export const renderDocument = (lines) => {

    if (!Array.isArray(lines)) return '';

    const parts = [];
    let linkN = 0;
    for (const line of lines) {

        switch (line && line.type) {

            case 'heading1': parts.push('<h1 class="h1">' + escape(line.text) + '</h1>'); break;
            case 'heading2': parts.push('<h2 class="h2">' + escape(line.text) + '</h2>'); break;
            case 'heading3': parts.push('<h3 class="h3">' + escape(line.text) + '</h3>'); break;
            case 'plain':    parts.push('<p class="plain">' + escape(line.text) + '</p>'); break;
            case 'blank':    parts.push('<div class="blank"></div>'); break;
            case 'listItem':
                parts.push('<div class="list"><span class="list-bullet">•</span> '
                    + escape(line.text) + '</div>');
                break;
            case 'blockquote':
                parts.push('<div class="bq">' + escape(line.text) + '</div>');
                break;
            case 'codeFence': break;
            case 'code':
                parts.push('<div class="code">' + escape(line.text) + '</div>');
                break;
            case 'link': {
                linkN += 1;
                const targetUrl = line.url || '';
                const display =
                    line.description !== null && line.description !== undefined
                        ? line.description : targetUrl;
                const inNetwork =
                    targetUrl.startsWith('anon://')
                    || targetUrl.startsWith('web+anon://')
                    || targetUrl.startsWith('/')
                    || targetUrl.startsWith('?');
                const cls = inNetwork ? '' : 'ext';
                const marker = inNetwork ? '[' + linkN + ']' : '[' + linkN + '↗]';
                parts.push(
                    '<div class="link">'
                        + '<span class="marker">' + marker + '</span>'
                        + '<a class="' + cls + '"'
                            + ' data-target="' + escape(targetUrl) + '"'
                            + ' data-innet="' + (inNetwork ? '1' : '0') + '"'
                            + ' href="#">'
                            + escape(display)
                        + '</a>'
                        + '<span class="hint">' + escape(targetUrl) + '</span>'
                    + '</div>'
                );
                break;
            }

            default:
                parts.push('<p class="plain">' + escape((line && line.text) || '') + '</p>');

        }

    }
    return parts.join('');

};
