// v2-site — PRE-AUDIT EXPERIMENTAL CODE
//
// Anon-site protocol codec, see docs/SITES-v0.1.md.
// The draft has open architectural questions; the code has not been
// audited. Do not rely on this for anonymity or content authenticity
// beyond what the v0.2 transport already provides.

// text/anon document parser for SITES-v0.1 § 6.
//
// The parser converts a UTF-8 document into a sequence of typed
// lines. The client is responsible for rendering each line type
// per its UI conventions. The parser does NOT do any HTML conversion,
// link following, or content fetching — those are application
// concerns.
//
// Line types (§ 6.1):
//   plain       — running text
//   heading1    — `# `
//   heading2    — `## `
//   heading3    — `### `
//   link        — `=> URL [description]`
//   listItem    — `* `
//   blockquote  — `> `
//   code        — inside a ```-fenced block
//   codeFence   — the ``` marker line itself
//   blank       — empty line (paragraph separator)

export const LINE_PLAIN       = 'plain';
export const LINE_HEADING1    = 'heading1';
export const LINE_HEADING2    = 'heading2';
export const LINE_HEADING3    = 'heading3';
export const LINE_LINK        = 'link';
export const LINE_LIST_ITEM   = 'listItem';
export const LINE_BLOCKQUOTE  = 'blockquote';
export const LINE_CODE        = 'code';
export const LINE_CODE_FENCE  = 'codeFence';
export const LINE_BLANK       = 'blank';

const CODE_FENCE = '```';

// Parse one text/anon line. `inCodeBlock` is the parser's caller-
// maintained state (true if we're inside a fenced code block).
// Returns { type, ...payload, newInCodeBlock }.
const parseLine = (line, inCodeBlock) => {

    // Strip trailing whitespace (§ 6.1 MUST).
    const trimmed = line.replace(/[ \t\r]+$/, '');

    if (inCodeBlock) {

        if (trimmed === CODE_FENCE) {

            return { type: LINE_CODE_FENCE, newInCodeBlock: false };

        }
        return { type: LINE_CODE, text: line, newInCodeBlock: true };

    }

    if (trimmed === CODE_FENCE) {

        return { type: LINE_CODE_FENCE, newInCodeBlock: true };

    }

    if (trimmed === '') {

        return { type: LINE_BLANK, newInCodeBlock: false };

    }

    // Headings (check most specific first).
    if (trimmed.startsWith('### ')) {

        return { type: LINE_HEADING3, text: trimmed.slice(4), newInCodeBlock: false };

    }
    if (trimmed.startsWith('## ')) {

        return { type: LINE_HEADING2, text: trimmed.slice(3), newInCodeBlock: false };

    }
    if (trimmed.startsWith('# ')) {

        return { type: LINE_HEADING1, text: trimmed.slice(2), newInCodeBlock: false };

    }

    if (trimmed.startsWith('=> ')) {

        const rest = trimmed.slice(3).trimStart();
        const sp = rest.search(/\s/);
        const url = sp === -1 ? rest : rest.slice(0, sp);
        const description = sp === -1 ? null : rest.slice(sp).trim();
        return {
            type: LINE_LINK,
            url,
            description: description === '' ? null : description,
            newInCodeBlock: false,
        };

    }

    if (trimmed.startsWith('* ')) {

        return { type: LINE_LIST_ITEM, text: trimmed.slice(2), newInCodeBlock: false };

    }

    if (trimmed.startsWith('> ')) {

        return { type: LINE_BLOCKQUOTE, text: trimmed.slice(2), newInCodeBlock: false };

    }
    if (trimmed === '>') {

        // Empty blockquote line.
        return { type: LINE_BLOCKQUOTE, text: '', newInCodeBlock: false };

    }

    return { type: LINE_PLAIN, text: trimmed, newInCodeBlock: false };

};

// Parse a UTF-8 text/anon document into an array of line objects.
// Each line object has `type` and type-specific fields:
//   { type: 'plain', text }
//   { type: 'heading1' | 'heading2' | 'heading3', text }
//   { type: 'link', url, description }
//   { type: 'listItem', text }
//   { type: 'blockquote', text }
//   { type: 'code', text }       — body lines inside a fenced block
//   { type: 'codeFence' }         — the ``` marker itself
//   { type: 'blank' }
export const parseDocument = (text) => {

    if (typeof text !== 'string') throw new Error('text must be a string');
    // Split on LF; tolerate CR LF by stripping trailing CR.
    const lines = text.split('\n').map((l) => l.endsWith('\r') ? l.slice(0, -1) : l);
    // If the last line is empty (text ended with newline), drop it.
    if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();

    let inCodeBlock = false;
    const out = [];
    for (const line of lines) {

        const parsed = parseLine(line, inCodeBlock);
        inCodeBlock = parsed.newInCodeBlock;
        // newInCodeBlock is a parser-internal flag; don't leak into output.
        const { newInCodeBlock, ...rest } = parsed;
        out.push(rest);

    }
    return out;

};
