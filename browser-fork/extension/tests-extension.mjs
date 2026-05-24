#!/usr/bin/env node
// tests-extension.mjs — smoke tests for the WebExtension's renderer.
//
// Asserts that the renderer (extension/lib/render-doc.mjs) and the
// canonical text/anon parser (modules/v2-site/text_anon.mjs) form a
// contract that produces the expected HTML for representative input.
//
// Run with: node browser-fork/extension/tests-extension.mjs
//
// These are NOT a substitute for loading the .xpi in Mullvad Browser
// and clicking through. They protect against silent breakage of the
// JSON-shape contract between bin/anon-browse-gui.mjs (which produces
// the JSON) and the extension (which consumes it).

import assert from 'node:assert/strict';
import { parseDocument } from '../../modules/v2-site/text_anon.mjs';
import {
    renderDocument,
    resolveUrl,
    normalizeAnon,
    canonicalAnonUrl,
    looksLikeAnonHost,
    escapeHtml,
} from './lib/render-doc.mjs';

let passed = 0;
let failed = 0;
const run = (name, fn) => {
    try {
        fn();
        process.stdout.write(`ok   ${name}\n`);
        passed += 1;
    } catch (err) {
        process.stdout.write(`FAIL ${name}\n`);
        process.stdout.write('     ' + (err.stack || err.message).replace(/\n/g, '\n     ') + '\n');
        failed += 1;
    }
};

// ---------- escapeHtml ----------

run('escapeHtml escapes the five XML-significant characters', () => {
    const input  = `<script>alert("x&y'z")</script>`;
    const output = `&lt;script&gt;alert(&quot;x&amp;y&#39;z&quot;)&lt;/script&gt;`;
    assert.equal(escapeHtml(input), output);
});

// ---------- canonicalAnonUrl ----------

run('canonicalAnonUrl: anon:// passes through', () => {
    assert.equal(canonicalAnonUrl('anon://foo.anon/bar'), 'anon://foo.anon/bar');
});
run('canonicalAnonUrl: web+anon:// is rewritten to anon://', () => {
    assert.equal(canonicalAnonUrl('web+anon://foo.anon/bar'), 'anon://foo.anon/bar');
});
run('canonicalAnonUrl: bare host gets anon:// prefix', () => {
    assert.equal(canonicalAnonUrl('foo.anon/bar'), 'anon://foo.anon/bar');
});
run('canonicalAnonUrl: omnibox `anon foo.anon/bar` → anon://foo.anon/bar', () => {
    assert.equal(canonicalAnonUrl('anon foo.anon/bar'), 'anon://foo.anon/bar');
});
run('canonicalAnonUrl: empty / whitespace → null', () => {
    assert.equal(canonicalAnonUrl(''), null);
    assert.equal(canonicalAnonUrl('   '), null);
});

// ---------- looksLikeAnonHost ----------
//
// Strict variant used by the URL-bar / search-engine interceptor:
// must return null for non-.anon text so plain searches still work,
// and must return a canonical anon:// URL for genuine .anon inputs.

run('looksLikeAnonHost: bare host → anon://host', () => {
    assert.equal(looksLikeAnonHost('foo.anon'), 'anon://foo.anon');
});
run('looksLikeAnonHost: host + path is preserved', () => {
    assert.equal(looksLikeAnonHost('foo.anon/bar/baz'), 'anon://foo.anon/bar/baz');
});
run('looksLikeAnonHost: http:// prefix is stripped', () => {
    assert.equal(looksLikeAnonHost('http://foo.anon/x'), 'anon://foo.anon/x');
});
run('looksLikeAnonHost: https:// prefix is stripped', () => {
    assert.equal(looksLikeAnonHost('https://foo.anon/x'), 'anon://foo.anon/x');
});
run('looksLikeAnonHost: subdomain on .anon is accepted', () => {
    assert.equal(looksLikeAnonHost('sub.foo.anon/x'), 'anon://sub.foo.anon/x');
});
run('looksLikeAnonHost: query string is preserved', () => {
    assert.equal(looksLikeAnonHost('foo.anon/x?y=1'), 'anon://foo.anon/x?y=1');
});
run('looksLikeAnonHost: case in TLD is tolerated', () => {
    assert.equal(looksLikeAnonHost('Foo.ANON/x'), 'anon://Foo.ANON/x');
});
run('looksLikeAnonHost: plain text → null (no false positive)', () => {
    assert.equal(looksLikeAnonHost('hello world'), null);
    assert.equal(looksLikeAnonHost('cat photos'), null);
    assert.equal(looksLikeAnonHost('anonymous donation'), null);
});
run('looksLikeAnonHost: wrong TLD → null', () => {
    assert.equal(looksLikeAnonHost('foo.com'), null);
    assert.equal(looksLikeAnonHost('foo.onion'), null);
});
run('looksLikeAnonHost: malformed labels → null', () => {
    assert.equal(looksLikeAnonHost('hello world.anon'), null);  // space in label
    assert.equal(looksLikeAnonHost('.anon'), null);              // empty label
    assert.equal(looksLikeAnonHost('-bad.anon'), null);          // leading hyphen
});
run('looksLikeAnonHost: single label "anon" → null', () => {
    assert.equal(looksLikeAnonHost('anon'), null);
});
run('looksLikeAnonHost: empty / whitespace → null', () => {
    assert.equal(looksLikeAnonHost(''), null);
    assert.equal(looksLikeAnonHost('   '), null);
});

// ---------- normalizeAnon ----------

run('normalizeAnon: web+anon → anon', () => {
    assert.equal(normalizeAnon('web+anon://x.anon/'), 'anon://x.anon/');
});
run('normalizeAnon: anon stays', () => {
    assert.equal(normalizeAnon('anon://x.anon/'), 'anon://x.anon/');
});

// ---------- resolveUrl ----------

const BASE = 'anon://foo.anon/dir/page';

run('resolveUrl: absolute anon:// stays', () => {
    assert.equal(resolveUrl('anon://bar.anon/', BASE), 'anon://bar.anon/');
});
run('resolveUrl: host-relative /x → anon://foo.anon/x', () => {
    assert.equal(resolveUrl('/sibling', BASE), 'anon://foo.anon/sibling');
});
run('resolveUrl: query ?q against /dir/page → /dir/page?q', () => {
    assert.equal(resolveUrl('?q=1', BASE), 'anon://foo.anon/dir/page?q=1');
});
run('resolveUrl: same-dir relative → anon://foo.anon/dir/next', () => {
    assert.equal(resolveUrl('next', BASE), 'anon://foo.anon/dir/next');
});
run('resolveUrl: https:// stays untouched', () => {
    assert.equal(resolveUrl('https://example.com/', BASE), 'https://example.com/');
});
run('resolveUrl: when base is not anon://, relative stays raw', () => {
    assert.equal(resolveUrl('next', 'https://example.com/x/y'), 'next');
});

// ---------- renderDocument: smoke on each line type ----------

run('renderDocument: heading levels produce h1/h2/h3 with .h1/.h2/.h3 classes', () => {
    const html = renderDocument(parseDocument('# a\n## b\n### c\n'));
    assert.match(html, /<h1 class="h1">a<\/h1>/);
    assert.match(html, /<h2 class="h2">b<\/h2>/);
    assert.match(html, /<h3 class="h3">c<\/h3>/);
});

run('renderDocument: plain text and list items', () => {
    const html = renderDocument(parseDocument('hello world\n* one\n* two\n'));
    assert.match(html, /<p class="plain">hello world<\/p>/);
    assert.ok((html.match(/<div class="list">/g) || []).length === 2);
    assert.match(html, /one/);
    assert.match(html, /two/);
});

run('renderDocument: blockquote', () => {
    const html = renderDocument(parseDocument('> noted\n'));
    assert.match(html, /<div class="bq">noted<\/div>/);
});

run('renderDocument: code fence content renders, fence markers do not', () => {
    const html = renderDocument(parseDocument('```\nbinary\n```\n'));
    assert.match(html, /<div class="code">binary<\/div>/);
    // The literal triple-backticks must not leak through:
    assert.ok(!html.includes('```'));
});

run('renderDocument: anon:// link in-network, https link external, both numbered', () => {
    const doc = '=> anon://x.anon/ alpha\n=> https://example.com/ beta\n';
    const html = renderDocument(parseDocument(doc));
    // Sequential numbering [1], [2↗]
    assert.match(html, /<span class="marker">\[1\]<\/span>/);
    assert.match(html, /<span class="marker">\[2↗\]<\/span>/);
    // The external link gets the .ext class
    assert.match(html, /class="ext"[^>]* data-target="https:\/\/example\.com\/"/);
    // The data-target round-trips
    assert.match(html, /data-target="anon:\/\/x\.anon\/"/);
});

run('renderDocument: link without description falls back to URL as display', () => {
    const html = renderDocument(parseDocument('=> anon://bare.anon/\n'));
    assert.match(html, />anon:\/\/bare\.anon\/<\/a>/);
});

run('renderDocument: XSS-style payloads get escaped, not executed', () => {
    const html = renderDocument(parseDocument(
        '=> anon://evil.anon/ <img src=x onerror=alert(1)>\nplain <script>x</script>\n',
    ));
    assert.ok(!html.includes('<img'), 'raw <img> leaked through');
    assert.ok(!html.includes('<script>'), 'raw <script> leaked through');
    assert.match(html, /&lt;img/);
    assert.match(html, /&lt;script&gt;/);
});

run('renderDocument: blank line → spacer div', () => {
    const html = renderDocument(parseDocument('a\n\nb\n'));
    assert.match(html, /<div class="blank"><\/div>/);
});

run('renderDocument: empty array returns empty string', () => {
    assert.equal(renderDocument([]), '');
});

run('renderDocument: malformed input does not throw', () => {
    // The bridge would never send these, but the renderer should be
    // defensive — a missing field on the line is recoverable, not
    // fatal.
    assert.doesNotThrow(() => renderDocument([{ type: 'unknown' }]));
    assert.doesNotThrow(() => renderDocument([{ type: 'plain' }]));
    assert.doesNotThrow(() => renderDocument([{ type: 'link', url: 'anon://x.anon/' }]));
});

// ---------- Cross-check: link counting is per-document, resets per call ----------

run('renderDocument: link numbering resets across calls', () => {
    const one = renderDocument(parseDocument('=> anon://a.anon/\n'));
    const two = renderDocument(parseDocument('=> anon://b.anon/\n'));
    assert.match(one, /\[1\]/);
    assert.match(two, /\[1\]/);
});

// ---------- Report ----------

process.stdout.write(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
