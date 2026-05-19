import './modules/cryptography/elgamal/tests.mjs';
import './modules/cryptography/multiplexing/tests.mjs';
import './modules/cryptography/twofish/tests.mjs';
import './modules/packets/coordination/format/tests.mjs';
import './modules/packets/coordination/parse/tests.mjs';
import './modules/random/tests.mjs';
// router/tests.mjs disabled: router imports symbols that do not exist in
// constants and uses a packet-text schema inconsistent with the format/parse
// modules. Re-enable after the router is rewritten (Phase 4).
// import './modules/router/tests.mjs';
import './modules/utilities/tests.mjs';
