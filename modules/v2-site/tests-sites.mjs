// v2-site — PRE-AUDIT EXPERIMENTAL CODE
//
// Anon-site protocol codec, see docs/SITES-v0.1.md.

import { expect } from 'chai';

import { encodeOnionAddress } from '../v2/onion_address.mjs';
import {
    MAX_REQUEST_BYTES,
    URL_SCHEME,
    buildRequest,
    parseRequest,
} from './request.mjs';
import {
    MAX_META_BYTES,
    STATUS_INPUT,
    STATUS_SENSITIVE_INPUT,
    STATUS_SUCCESS,
    STATUS_REDIRECT_TEMP,
    STATUS_TEMPORARY_FAILURE,
    STATUS_NOT_FOUND,
    STATUS_BAD_REQUEST,
    isSuccess,
    isRedirect,
    isInput,
    isTempFail,
    isPermFail,
    isReserved,
    isValidStatus,
    buildResponseHead,
    buildResponse,
    parseResponseHead,
    parseSuccessMeta,
} from './response.mjs';
import {
    LINE_PLAIN,
    LINE_HEADING1,
    LINE_HEADING2,
    LINE_HEADING3,
    LINE_LINK,
    LINE_LIST_ITEM,
    LINE_BLOCKQUOTE,
    LINE_CODE,
    LINE_CODE_FENCE,
    LINE_BLANK,
    parseDocument,
} from './text_anon.mjs';

// Generate a sample onion address for tests (deterministic SVC_pk).
const sampleOnion = (fill = 0x33) => encodeOnionAddress(new Uint8Array(32).fill(fill));

// ----- request.mjs -----

describe('v2-site/request', () => {

    it('buildRequest produces <url>\\r\\n for a valid URL', () => {

        const url = `${URL_SCHEME}${sampleOnion()}/`;
        const buf = buildRequest(url);
        expect(buf[buf.length - 2]).to.equal(0x0D);
        expect(buf[buf.length - 1]).to.equal(0x0A);
        expect(new TextDecoder().decode(buf.subarray(0, buf.length - 2))).to.equal(url);

    });

    it('buildRequest rejects non-anon scheme', () => {

        expect(() => buildRequest('https://example.com/')).to.throw(/scheme/);

    });

    it('buildRequest rejects fragments / userinfo / ports', () => {

        const fp = sampleOnion();
        expect(() => buildRequest(`${URL_SCHEME}${fp}/#top`)).to.throw(/fragment/);
        expect(() => buildRequest(`${URL_SCHEME}user@${fp}/`)).to.throw(/userinfo/);
        expect(() => buildRequest(`${URL_SCHEME}${fp}:80/`)).to.throw(/port/);

    });

    it('buildRequest rejects invalid .anon host', () => {

        expect(() => buildRequest(`${URL_SCHEME}not-an-onion.anon/`)).to.throw(/\.anon address/);

    });

    it('buildRequest rejects URLs exceeding 1024 bytes (incl CRLF)', () => {

        const longPath = '/'.padEnd(1100, 'a');
        const url = `${URL_SCHEME}${sampleOnion()}${longPath}`;
        expect(() => buildRequest(url)).to.throw(/bytes/);

    });

    it('parseRequest round-trips a valid URL', () => {

        const onion = sampleOnion();
        const url = `${URL_SCHEME}${onion}/some/path?q=value`;
        const buf = buildRequest(url);
        const parsed = parseRequest(buf);
        expect(parsed.url).to.equal(url);
        expect(parsed.host).to.equal(onion);
        expect(parsed.path).to.equal('/some/path');
        expect(parsed.query).to.equal('q=value');

    });

    it('parseRequest returns null on incomplete input (no CRLF yet)', () => {

        const partial = new TextEncoder().encode(`${URL_SCHEME}${sampleOnion()}/`);
        expect(parseRequest(partial)).to.equal(null);

    });

    it('parseRequest returns {error: "too-long"} on > 1024 bytes without CRLF', () => {

        const tooLong = new Uint8Array(MAX_REQUEST_BYTES + 5).fill(0x61);
        expect(parseRequest(tooLong)).to.deep.equal({ error: 'too-long' });

    });

    it('parseRequest returns {error: "malformed-url"} for non-anon scheme', () => {

        const bytes = new TextEncoder().encode('https://example.com/\r\n');
        expect(parseRequest(bytes)).to.deep.equal({ error: 'malformed-url' });

    });

    it('parseRequest rejects URL with fragment', () => {

        const bytes = new TextEncoder().encode(`${URL_SCHEME}${sampleOnion()}/#top\r\n`);
        expect(parseRequest(bytes)).to.deep.equal({ error: 'malformed-url' });

    });

    it('parseRequest accepts URL with no path (host only)', () => {

        const onion = sampleOnion();
        const url = `${URL_SCHEME}${onion}`;
        const bytes = new TextEncoder().encode(`${url}\r\n`);
        const parsed = parseRequest(bytes);
        expect(parsed.host).to.equal(onion);
        expect(parsed.path).to.equal('/');
        expect(parsed.query).to.equal(null);

    });

});

// ----- response.mjs -----

describe('v2-site/response — status code helpers', () => {

    it('isValidStatus accepts 10..69', () => {

        for (const s of [10, 20, 31, 44, 51, 59, 69]) expect(isValidStatus(s)).to.equal(true);
        for (const s of [9, 70, -1, 0, 100, 1.5]) expect(isValidStatus(s)).to.equal(false);

    });

    it('category predicates correctly classify', () => {

        expect(isInput(STATUS_INPUT)).to.equal(true);
        expect(isInput(STATUS_SENSITIVE_INPUT)).to.equal(true);
        expect(isSuccess(STATUS_SUCCESS)).to.equal(true);
        expect(isRedirect(STATUS_REDIRECT_TEMP)).to.equal(true);
        expect(isTempFail(STATUS_TEMPORARY_FAILURE)).to.equal(true);
        expect(isPermFail(STATUS_NOT_FOUND)).to.equal(true);
        expect(isReserved(65)).to.equal(true);

    });

});

describe('v2-site/response — build/parse head', () => {

    it('buildResponseHead produces <status> <meta>\\r\\n', () => {

        const head = buildResponseHead({ status: STATUS_SUCCESS, meta: 'text/anon; charset=utf-8' });
        expect(new TextDecoder().decode(head)).to.equal('20 text/anon; charset=utf-8\r\n');

    });

    it('buildResponseHead pads single-digit-style statuses to two digits', () => {

        // STATUS_INPUT = 10; first byte is '1'
        const head = buildResponseHead({ status: STATUS_INPUT, meta: 'name?' });
        expect(new TextDecoder().decode(head)).to.equal('10 name?\r\n');

    });

    it('buildResponseHead throws on invalid status', () => {

        expect(() => buildResponseHead({ status: 99, meta: 'x' })).to.throw();

    });

    it('buildResponseHead throws when META contains CR or LF', () => {

        expect(() => buildResponseHead({ status: 20, meta: 'has\rcr' })).to.throw();
        expect(() => buildResponseHead({ status: 20, meta: 'has\nlf' })).to.throw();

    });

    it('buildResponseHead throws on oversized META', () => {

        expect(() => buildResponseHead({ status: 20, meta: 'a'.repeat(MAX_META_BYTES + 1) })).to.throw();

    });

    it('parseResponseHead round-trips', () => {

        const head = buildResponseHead({ status: STATUS_NOT_FOUND, meta: 'no such resource' });
        const parsed = parseResponseHead(head);
        expect(parsed.status).to.equal(STATUS_NOT_FOUND);
        expect(parsed.meta).to.equal('no such resource');
        expect(parsed.headEnd).to.equal(head.length);

    });

    it('parseResponseHead returns null on incomplete head', () => {

        const partial = new TextEncoder().encode('20 text/anon');
        expect(parseResponseHead(partial)).to.equal(null);

    });

    it('parseResponseHead returns {error: "malformed"} on non-digit status', () => {

        expect(parseResponseHead(new TextEncoder().encode('XY meta\r\n'))).to.deep.equal({ error: 'malformed' });

    });

    it('parseResponseHead returns {error: "malformed"} when SP is missing', () => {

        // No space after the digits.
        expect(parseResponseHead(new TextEncoder().encode('20text/anon\r\n'))).to.deep.equal({ error: 'malformed' });

    });

    it('parseResponseHead handles a SUCCESS head with body bytes that follow', () => {

        const head = buildResponseHead({ status: STATUS_SUCCESS, meta: 'text/anon' });
        const body = new TextEncoder().encode('# Hello\n');
        const combined = new Uint8Array(head.length + body.length);
        combined.set(head, 0);
        combined.set(body, head.length);
        const parsed = parseResponseHead(combined);
        expect(parsed.status).to.equal(STATUS_SUCCESS);
        // headEnd points to the first body byte.
        expect(combined[parsed.headEnd]).to.equal(0x23); // '#'

    });

    it('buildResponse for SUCCESS includes the body bytes', () => {

        const body = new TextEncoder().encode('hello world');
        const buf = buildResponse({ status: STATUS_SUCCESS, meta: 'text/plain', body });
        const headEnd = parseResponseHead(buf).headEnd;
        expect(new TextDecoder().decode(buf.subarray(headEnd))).to.equal('hello world');

    });

    it('buildResponse omits the body for non-success even if supplied', () => {

        const buf = buildResponse({
            status: STATUS_NOT_FOUND, meta: 'gone',
            body: new TextEncoder().encode('should not appear'),
        });
        expect(new TextDecoder().decode(buf)).to.equal('51 gone\r\n');

    });

});

describe('v2-site/response — parseSuccessMeta', () => {

    it('parses a simple MIME type', () => {

        expect(parseSuccessMeta('text/anon')).to.deep.equal({
            mimeType: 'text/anon',
            parameters: {},
        });

    });

    it('parses MIME type with parameters', () => {

        const r = parseSuccessMeta('text/anon; charset=utf-8; length=1234');
        expect(r.mimeType).to.equal('text/anon');
        expect(r.parameters.charset).to.equal('utf-8');
        expect(r.parameters.length).to.equal('1234');

    });

    it('returns null on malformed META', () => {

        expect(parseSuccessMeta('')).to.equal(null);
        expect(parseSuccessMeta('not-a-mime')).to.equal(null);
        expect(parseSuccessMeta('text/anon; nokeyvalue')).to.equal(null);

    });

});

// ----- text_anon.mjs -----

describe('v2-site/text_anon — parseDocument', () => {

    it('parses a minimal document with mixed line types', () => {

        const doc = [
            '# Welcome',
            '',
            'This is a paragraph.',
            'It spans two lines.',
            '',
            '## Subsection',
            '',
            '=> anon://abcd...anon/foo  A link',
            '=> anon://abcd...anon/bar',
            '',
            '* item one',
            '* item two',
            '',
            '> quoted line',
            '',
            '```',
            '  code line preserves spacing',
            '```',
        ].join('\n');
        const lines = parseDocument(doc);

        expect(lines[0]).to.deep.equal({ type: LINE_HEADING1, text: 'Welcome' });
        expect(lines[1]).to.deep.equal({ type: LINE_BLANK });
        expect(lines[2]).to.deep.equal({ type: LINE_PLAIN, text: 'This is a paragraph.' });
        expect(lines[3]).to.deep.equal({ type: LINE_PLAIN, text: 'It spans two lines.' });
        expect(lines[4]).to.deep.equal({ type: LINE_BLANK });
        expect(lines[5]).to.deep.equal({ type: LINE_HEADING2, text: 'Subsection' });
        expect(lines[7].type).to.equal(LINE_LINK);
        expect(lines[7].url).to.equal('anon://abcd...anon/foo');
        expect(lines[7].description).to.equal('A link');
        expect(lines[8].description).to.equal(null);
        expect(lines[10]).to.deep.equal({ type: LINE_LIST_ITEM, text: 'item one' });
        expect(lines[13]).to.deep.equal({ type: LINE_BLOCKQUOTE, text: 'quoted line' });

        // Code-fence block.
        const fenceStart = lines.findIndex((l) => l.type === LINE_CODE_FENCE);
        expect(lines[fenceStart + 1].type).to.equal(LINE_CODE);
        expect(lines[fenceStart + 1].text).to.equal('  code line preserves spacing');

    });

    it('parses a single-line h1', () => {

        expect(parseDocument('# Title\n')).to.deep.equal([
            { type: LINE_HEADING1, text: 'Title' },
        ]);

    });

    it('treats a plain `>` as an empty blockquote', () => {

        const lines = parseDocument('>\n');
        expect(lines).to.deep.equal([{ type: LINE_BLOCKQUOTE, text: '' }]);

    });

    it('strips trailing whitespace (§ 6.1 MUST)', () => {

        const lines = parseDocument('hello world   \n');
        expect(lines[0].text).to.equal('hello world');

    });

    it('preserves leading whitespace inside code blocks', () => {

        const doc = '```\n    indented\n```\n';
        const lines = parseDocument(doc);
        const codeLine = lines.find((l) => l.type === LINE_CODE);
        expect(codeLine.text).to.equal('    indented');

    });

    it('treats `# ` and `## ` and `### ` correctly at boundaries', () => {

        const lines = parseDocument([
            '# One',
            '## Two',
            '### Three',
            '#### Four (NOT a deeper heading — rendered as plain)',
        ].join('\n'));
        expect(lines[0].type).to.equal(LINE_HEADING1);
        expect(lines[1].type).to.equal(LINE_HEADING2);
        expect(lines[2].type).to.equal(LINE_HEADING3);
        // No h4 in the spec; falls through to plain.
        expect(lines[3].type).to.equal(LINE_PLAIN);

    });

    it('tolerates CR LF line endings', () => {

        const lines = parseDocument('# Title\r\n\r\nparagraph\r\n');
        expect(lines[0].type).to.equal(LINE_HEADING1);
        expect(lines[0].text).to.equal('Title');
        expect(lines[2].text).to.equal('paragraph');

    });

    it('link with only URL has null description', () => {

        const lines = parseDocument('=> anon://abc.anon\n');
        expect(lines[0]).to.deep.equal({
            type: LINE_LINK, url: 'anon://abc.anon', description: null,
        });

    });

    it('throws on non-string input', () => {

        expect(() => parseDocument(null)).to.throw();
        expect(() => parseDocument(new Uint8Array(0))).to.throw();

    });

});
