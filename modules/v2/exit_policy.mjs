// v0.2 — PRE-AUDIT EXPERIMENTAL CODE
//
// This file implements part of the v0.2 protocol DRAFT. The draft has
// open architectural questions; the code has not been audited. Do not
// rely on this for anonymity. See modules/v2/WARNING.md for the full
// notice.

// Exit policy codec + evaluator for SPEC-v0.2-draft § 8.
//
// A policy is an ordered list of rules; the first matching rule
// determines the disposition (accept / reject). An implicit final
// REJECT *:* is appended, so an empty policy rejects everything.
//
// The evaluator operates on RESOLVED addresses only. Hostnames in
// RELAY_BEGIN (addr_type 0x03) are resolved at the exit before this
// evaluator runs.

// ----- Constants -----

export const ACTION_ACCEPT = 0x01;
export const ACTION_REJECT = 0x02;

export const ADDR_TYPE_IPV4 = 0x01;
export const ADDR_TYPE_IPV6 = 0x02;
export const ADDR_TYPE_ANY  = 0xFF;

export const NET_LEN_IPV4 = 4;
export const NET_LEN_IPV6 = 16;

const LEN_ACTION = 1;
const LEN_ADDR_TYPE = 1;
const LEN_MASK_LEN = 1;
const LEN_PORT = 2;

// ----- Rule constructors -----

const validatePortRange = (portMin, portMax) => {

    if (!Number.isInteger(portMin) || portMin < 0 || portMin > 0xFFFF) {

        throw new Error('portMin must be a u16');

    }
    if (!Number.isInteger(portMax) || portMax < 0 || portMax > 0xFFFF) {

        throw new Error('portMax must be a u16');

    }
    if (portMax < portMin) {

        throw new Error(`portMax (${portMax}) must be ≥ portMin (${portMin})`);

    }

};

const validateAction = (action) => {

    if (action !== ACTION_ACCEPT && action !== ACTION_REJECT) {

        throw new Error(`action must be ACCEPT or REJECT (got 0x${action.toString(16)})`);

    }

};

export const makeIPv4Rule = ({ action, net, maskLen, portMin, portMax }) => {

    validateAction(action);
    if (!(net instanceof Uint8Array) || net.length !== NET_LEN_IPV4) {

        throw new Error('IPv4 net must be a 4-byte Uint8Array');

    }
    if (!Number.isInteger(maskLen) || maskLen < 0 || maskLen > 32) {

        throw new Error('IPv4 maskLen must be 0..32');

    }
    validatePortRange(portMin, portMax);

    return {
        action,
        addrType: ADDR_TYPE_IPV4,
        net: new Uint8Array(net),
        maskLen,
        portMin,
        portMax,
    };

};

export const makeIPv6Rule = ({ action, net, maskLen, portMin, portMax }) => {

    validateAction(action);
    if (!(net instanceof Uint8Array) || net.length !== NET_LEN_IPV6) {

        throw new Error('IPv6 net must be a 16-byte Uint8Array');

    }
    if (!Number.isInteger(maskLen) || maskLen < 0 || maskLen > 128) {

        throw new Error('IPv6 maskLen must be 0..128');

    }
    validatePortRange(portMin, portMax);

    return {
        action,
        addrType: ADDR_TYPE_IPV6,
        net: new Uint8Array(net),
        maskLen,
        portMin,
        portMax,
    };

};

export const makeAnyRule = ({ action, portMin, portMax }) => {

    validateAction(action);
    validatePortRange(portMin, portMax);

    return {
        action,
        addrType: ADDR_TYPE_ANY,
        net: null,
        maskLen: null,
        portMin,
        portMax,
    };

};

// ----- Wire codec -----

const ruleByteLength = (rule) => {

    let n = LEN_ACTION + LEN_ADDR_TYPE + LEN_PORT * 2;
    if (rule.addrType === ADDR_TYPE_IPV4) n += NET_LEN_IPV4 + LEN_MASK_LEN;
    else if (rule.addrType === ADDR_TYPE_IPV6) n += NET_LEN_IPV6 + LEN_MASK_LEN;
    // ANY contributes zero bytes for the prefix.
    return n;

};

// SPEC § 8.1: serialize a list of rules.
// Layout: rule_count (u16 BE) ‖ rule_count rule records.
export const buildPolicy = (rules) => {

    if (rules.length > 0xFFFF) throw new Error(`policy exceeds rule_count limit`);

    let total = 2;
    for (const r of rules) total += ruleByteLength(r);

    const buf = new Uint8Array(total);
    const view = new DataView(buf.buffer);
    view.setUint16(0, rules.length, false);

    let off = 2;
    for (const r of rules) {

        buf[off]     = r.action;
        buf[off + 1] = r.addrType;
        off += 2;
        if (r.addrType === ADDR_TYPE_IPV4 || r.addrType === ADDR_TYPE_IPV6) {

            buf.set(r.net, off);
            off += r.net.length;
            buf[off] = r.maskLen;
            off += 1;

        }
        view.setUint16(off,     r.portMin, false);
        view.setUint16(off + 2, r.portMax, false);
        off += 4;

    }

    return buf;

};

// SPEC § 8.1: parse a serialised policy. Returns the rule list, or
// null on any structural failure (silent-drop discipline at the wire).
export const parsePolicy = (buf) => {

    if (!buf || buf.length < 2) return null;
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const count = view.getUint16(0, false);

    const rules = [];
    let off = 2;
    for (let i = 0; i < count; i += 1) {

        if (buf.length < off + 2) return null;
        const action = buf[off];
        const addrType = buf[off + 1];
        off += 2;

        if (action !== ACTION_ACCEPT && action !== ACTION_REJECT) return null;

        let net = null;
        let maskLen = null;

        if (addrType === ADDR_TYPE_IPV4) {

            if (buf.length < off + NET_LEN_IPV4 + LEN_MASK_LEN) return null;
            net = new Uint8Array(buf.subarray(off, off + NET_LEN_IPV4));
            off += NET_LEN_IPV4;
            maskLen = buf[off];
            off += 1;
            if (maskLen > 32) return null;

        } else if (addrType === ADDR_TYPE_IPV6) {

            if (buf.length < off + NET_LEN_IPV6 + LEN_MASK_LEN) return null;
            net = new Uint8Array(buf.subarray(off, off + NET_LEN_IPV6));
            off += NET_LEN_IPV6;
            maskLen = buf[off];
            off += 1;
            if (maskLen > 128) return null;

        } else if (addrType === ADDR_TYPE_ANY) {

            // empty addr_prefix

        } else {

            return null;

        }

        if (buf.length < off + 4) return null;
        const portMin = view.getUint16(off,     false);
        const portMax = view.getUint16(off + 2, false);
        off += 4;
        if (portMax < portMin) return null;

        rules.push({ action, addrType, net, maskLen, portMin, portMax });

    }

    if (off !== buf.length) return null; // trailing bytes
    return rules;

};

// ----- Evaluation -----

const prefixMatches = (rule, addrType, addr) => {

    if (rule.addrType === ADDR_TYPE_ANY) return true;
    if (rule.addrType !== addrType) return false;
    if (addr.length !== rule.net.length) return false;

    const fullBytes = (rule.maskLen / 8) | 0;
    const tailBits = rule.maskLen - fullBytes * 8;

    for (let i = 0; i < fullBytes; i += 1) {

        if (rule.net[i] !== addr[i]) return false;

    }
    if (tailBits > 0) {

        const mask = (0xFF << (8 - tailBits)) & 0xFF;
        if ((rule.net[fullBytes] & mask) !== (addr[fullBytes] & mask)) return false;

    }
    return true;

};

// Evaluate a policy against a (addrType, addr, port) triple. Returns
// 'accept' or 'reject'. An empty policy returns 'reject' (implicit
// final REJECT *:*).
export const evaluate = (policy, { addrType, addr, port }) => {

    if (!Number.isInteger(port) || port < 0 || port > 0xFFFF) {

        throw new Error('port must be a u16');

    }
    if (addrType !== ADDR_TYPE_IPV4 && addrType !== ADDR_TYPE_IPV6) {

        throw new Error('evaluate requires a resolved IPv4 or IPv6 address');

    }

    for (const rule of policy) {

        if (!prefixMatches(rule, addrType, addr)) continue;
        if (port < rule.portMin || port > rule.portMax) continue;
        return rule.action === ACTION_ACCEPT ? 'accept' : 'reject';

    }
    return 'reject';

};

// ----- Default policies (SPEC § 8.3) -----

// Non-exit: reject everything. (Empty rule list — implicit final REJECT.)
export const POLICY_REJECT_ALL = Object.freeze([]);

// Reduced exit: web + DNS only.
export const POLICY_REDUCED_EXIT = Object.freeze([
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 80,  portMax: 80  }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 443, portMax: 443 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 53,  portMax: 53  }),
]);

// Standard exit (Tor's ReducedExitPolicy adapted): the common
// protocols, blocking abuse-attractive ports. Operators MAY tighten.
export const POLICY_STANDARD_EXIT = Object.freeze([
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 20,    portMax: 23   }), // FTP, SSH, Telnet (Telnet usually blocked downstream)
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 53,    portMax: 53   }), // DNS
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 80,    portMax: 80   }), // HTTP
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 88,    portMax: 88   }), // Kerberos
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 110,   portMax: 110  }), // POP3
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 143,   portMax: 143  }), // IMAP
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 220,   portMax: 220  }), // IMAP3
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 443,   portMax: 443  }), // HTTPS
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 465,   portMax: 465  }), // SMTPS
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 587,   portMax: 587  }), // SMTP submission
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 706,   portMax: 706  }), // SILC
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 749,   portMax: 749  }), // Kerberos admin
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 873,   portMax: 873  }), // rsync
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 902,   portMax: 904  }), // VMware
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 981,   portMax: 981  }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 989,   portMax: 995  }), // FTPS, IMAPS, POP3S
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 1194,  portMax: 1194 }), // OpenVPN
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 1220,  portMax: 1220 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 1293,  portMax: 1293 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 1500,  portMax: 1500 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 1533,  portMax: 1533 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 1677,  portMax: 1677 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 1723,  portMax: 1723 }), // PPTP
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 1755,  portMax: 1755 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 1863,  portMax: 1863 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 2082,  portMax: 2083 }), // cPanel
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 2086,  portMax: 2087 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 2095,  portMax: 2096 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 2102,  portMax: 2104 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 3690,  portMax: 3690 }), // svn
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 4321,  portMax: 4321 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 4643,  portMax: 4643 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 5050,  portMax: 5050 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 5190,  portMax: 5190 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 5222,  portMax: 5223 }), // XMPP
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 5228,  portMax: 5228 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 5900,  portMax: 5900 }), // VNC
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 6660,  portMax: 6669 }), // IRC
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 6679,  portMax: 6679 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 6697,  portMax: 6697 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 8000,  portMax: 8000 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 8008,  portMax: 8008 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 8074,  portMax: 8074 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 8080,  portMax: 8080 }), // HTTP alt
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 8082,  portMax: 8082 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 8087,  portMax: 8088 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 8232,  portMax: 8233 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 8332,  portMax: 8333 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 8443,  portMax: 8443 }), // HTTPS alt
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 8888,  portMax: 8888 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 9418,  portMax: 9418 }), // git
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 9999,  portMax: 9999 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 10000, portMax: 10000 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 11371, portMax: 11371 }), // GnuPG keyservers
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 19294, portMax: 19294 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 19638, portMax: 19638 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 50002, portMax: 50002 }),
    makeAnyRule({ action: ACTION_ACCEPT, portMin: 64738, portMax: 64738 }),
    // Implicit final REJECT *:* applies to everything else.
]);
