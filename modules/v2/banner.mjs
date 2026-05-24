// Shared startup banner. Any v2 binary that goes near the network
// prints this on launch so the operator gets a visible "yes, I'm
// running anon-layer v2" cue.
//
// The historical PRE-AUDIT EXPERIMENTAL banner was retired once the
// protocol + reference implementation completed external review. The
// `--i-understand-this-is-experimental` CLI flag is retained for
// back-compat with shell scripts that pass it; it no longer gates
// startup behind a scary warning, but `requireAck()` still refuses
// to run without it so a typo in operator tooling fails loud.

const BOLD = '\x1b[1m';
const DIM  = '\x1b[2m';
const RESET = '\x1b[0m';

const BANNER = `${BOLD}
================================================================
                      ANONYMOUS LAYER v0.2
================================================================
${RESET}${DIM}Post-quantum hidden-service network. See docs/ for details.${RESET}

`;

export const printBanner = (out = process.stderr) => {

    out.write(BANNER);

};

export const requireAck = (argv) => {

    if (!argv.includes('--i-understand-this-is-experimental')) {

        printBanner();
        process.stderr.write(
            'Refusing to start without --i-understand-this-is-experimental flag.\n'
            + '(Retained for back-compat with existing launchers; pass it to start.)\n',
        );
        process.exit(2);

    }
    printBanner();

};
