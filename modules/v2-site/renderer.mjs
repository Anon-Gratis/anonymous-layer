// v2-site — PRE-AUDIT EXPERIMENTAL CODE
//
// Anon-site protocol codec, see docs/SITES-v0.1.md.

// Terminal renderer for text/anon documents.
//
// Takes the output of `parseDocument` (an array of line objects) and
// returns a string ready to print to a terminal. ANSI escape codes
// are used for styling unless `color: false` is passed.

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
} from './text_anon.mjs';

const ESC = '\x1b[';
const RESET = `${ESC}0m`;
const BOLD = `${ESC}1m`;
const DIM = `${ESC}2m`;
const UNDERLINE = `${ESC}4m`;
const CYAN = `${ESC}36m`;
const YELLOW = `${ESC}33m`;
const GREEN = `${ESC}32m`;

const noColor = (s) => s;

export const renderToString = (lines, { color = true } = {}) => {

    const bold      = color ? (s) => `${BOLD}${s}${RESET}`       : noColor;
    const dim       = color ? (s) => `${DIM}${s}${RESET}`        : noColor;
    const underline = color ? (s) => `${UNDERLINE}${s}${RESET}`  : noColor;
    const cyan      = color ? (s) => `${CYAN}${s}${RESET}`       : noColor;
    const yellow    = color ? (s) => `${YELLOW}${s}${RESET}`     : noColor;
    const green     = color ? (s) => `${GREEN}${s}${RESET}`      : noColor;

    const out = [];
    for (const line of lines) {

        switch (line.type) {

            case LINE_HEADING1:
                out.push('');
                out.push(bold(yellow(`▎ ${line.text}`)));
                out.push('');
                break;

            case LINE_HEADING2:
                out.push('');
                out.push(bold(`  ${line.text}`));
                break;

            case LINE_HEADING3:
                out.push(bold(dim(`    ${line.text}`)));
                break;

            case LINE_LINK: {

                const display = line.description !== null ? line.description : line.url;
                const isAnon = line.url.startsWith('anon://');
                const marker = isAnon ? cyan('→') : yellow('↗');
                out.push(`${marker} ${underline(display)} ${dim(`(${line.url})`)}`);
                break;

            }

            case LINE_LIST_ITEM:
                out.push(`  ${green('•')} ${line.text}`);
                break;

            case LINE_BLOCKQUOTE:
                out.push(dim(`  │ ${line.text}`));
                break;

            case LINE_CODE_FENCE:
                // Don't render the fence itself.
                break;

            case LINE_CODE:
                out.push(`    ${dim(line.text)}`);
                break;

            case LINE_BLANK:
                out.push('');
                break;

            case LINE_PLAIN:
            default:
                out.push(line.text);
                break;

        }

    }
    return out.join('\n');

};
