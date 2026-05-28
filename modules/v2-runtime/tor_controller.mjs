// tor_controller — minimal Tor control-protocol client.
//
// Reads the per-launch torrc to discover ControlPort, reads the
// cookie file for auth, opens a TCP socket to 127.0.0.1:<port>,
// AUTHENTICATEs, and issues GETINFO queries. Pure Node — `net` and
// `fs/promises` only, no external deps.
//
// Used by bin/anon-browse-gui.mjs's /api/tor-circuit endpoint to
// surface the 3-hop circuit serving a given hostname (Tor-Browser-
// style circuit display for *.onion pages in the chrome popup).
//
// Tor control-protocol reference:
//   https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/control-spec.txt

import { createConnection } from 'node:net';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

const hex = (buf) => buf.toString('hex');

/**
 * Open + authenticate a control connection.
 *
 * Returns an object {readLine, write, close}. Throws on connect /
 * auth failure. Caller must close().
 *
 * The control connection is line-oriented over CRLF. We buffer
 * incoming bytes and resolve queued read promises per complete line.
 */
async function openControl(runtimeDir) {
  let torrc;
  try {
    torrc = await readFile(join(runtimeDir, 'torrc'), 'utf8');
  } catch (e) {
    throw new Error('tor torrc unreadable at ' + runtimeDir + ': ' + e.message);
  }
  const portM = /^\s*ControlPort\s+(\d+)/m.exec(torrc);
  if (!portM) throw new Error('no ControlPort in torrc');
  const port = parseInt(portM[1], 10);

  let cookie;
  try {
    cookie = await readFile(join(runtimeDir, 'data', 'control_auth_cookie'));
  } catch (e) {
    throw new Error('tor cookie unreadable: ' + e.message);
  }

  return await new Promise((resolve, reject) => {
    const conn = createConnection({ host: '127.0.0.1', port });
    let connectErr = null;
    conn.once('error', (err) => {
      connectErr = err;
      reject(new Error('tor control connect: ' + err.message));
    });
    conn.once('connect', () => {
      let buf = '';
      const lines = [];
      const waiters = [];
      const drainOneTo = (resv) => {
        if (lines.length) resv(lines.shift());
        else waiters.push(resv);
      };
      conn.on('data', (chunk) => {
        buf += chunk.toString('utf8');
        let idx;
        while ((idx = buf.indexOf('\r\n')) >= 0) {
          const line = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          if (waiters.length) waiters.shift()(line);
          else lines.push(line);
        }
      });
      conn.on('end', () => {
        // Wake any pending waiters with EOF so callers don't hang.
        while (waiters.length) waiters.shift()(null);
      });
      const readLine = () => new Promise(drainOneTo);
      const write = (s) => new Promise((res, rej) => {
        conn.write(s + '\r\n', (err) => err ? rej(err) : res());
      });
      const close = () => { try { conn.end(); } catch (_) {} };

      (async () => {
        await write('AUTHENTICATE ' + hex(cookie));
        const r = await readLine();
        if (!r || !r.startsWith('250')) {
          close();
          throw new Error('AUTHENTICATE failed: ' + (r || '<eof>'));
        }
      })()
        .then(() => resolve({ readLine, write, close }))
        .catch((err) => { if (!connectErr) reject(err); });
    });
  });
}

/**
 * Issue GETINFO <key>. Returns array of value lines (the prefix
 * "<key>=" stripped from the first line; subsequent lines are the
 * value continuation when tor uses multi-line "250+key=\n...\n.\n"
 * format). Throws on 5xx error.
 */
async function getInfo(ctl, key) {
  await ctl.write('GETINFO ' + key);
  const out = [];
  while (true) {
    const line = await ctl.readLine();
    if (line === null) throw new Error('control connection closed mid-reply');
    if (line.startsWith('250+')) {
      // Multi-line data: collect until a line that is just "."
      // First emit the part after "250+key=".
      const first = line.slice(4).replace(new RegExp('^' + key + '='), '');
      if (first) out.push(first);
      while (true) {
        const l2 = await ctl.readLine();
        if (l2 === null) throw new Error('control connection closed mid-block');
        if (l2 === '.') break;
        out.push(l2);
      }
    } else if (line.startsWith('250-')) {
      out.push(line.slice(4).replace(new RegExp('^' + key + '='), ''));
    } else if (line.startsWith('250 OK')) {
      break;
    } else if (line.startsWith('250 ')) {
      out.push(line.slice(4).replace(new RegExp('^' + key + '='), ''));
      break;
    } else if (line.startsWith('5')) {
      throw new Error('GETINFO ' + key + ': ' + line);
    } else {
      // Async event line or unknown — ignore.
    }
  }
  // Many GETINFO responses prefix every value line with "key=" — strip if present.
  return out.filter(Boolean);
}

/**
 * Parse one circuit-status entry:
 *   <CircID> SP <CircStatus> [SP <Path>] [SP <BuildFlags=...>]
 *   [SP <Purpose=...>] [SP <HSState=...>] [SP <REND_QUERY=...>] ...
 *
 * Per torspec, path elements use either "=" (named, deprecated) or
 * "~" (unnamed) between fingerprint and nickname. Modern Tor almost
 * always emits "~".
 *
 *   LongName = "$" 40HEXDIG [ ("=" / "~") Nickname ]
 *
 * So a path looks like:
 *   $<fp1>~<nick1>,$<fp2>~<nick2>,...
 * or (older / mixed):
 *   $<fp1>=<nick1>,$<fp2>=<nick2>,...
 * or even bare fingerprints with no nickname.
 */
function parseCircuit(line) {
  const m = /^(\d+)\s+(\w+)(?:\s+(\S+))?(.*)$/.exec(line);
  if (!m) return null;
  const id = m[1];
  const status = m[2];
  const pathStr = m[3] || '';
  const rest = m[4] || '';
  // A genuine path field always begins with "$". This guards against
  // weird statuses where m[3] captures something else.
  const path = pathStr.startsWith('$')
    ? pathStr.split(',').map((tok) => {
        // Split on whichever of "=" / "~" comes first.
        let cut = -1;
        for (let i = 0; i < tok.length; i++) {
          const c = tok[i];
          if (c === '=' || c === '~') { cut = i; break; }
        }
        const fp = (cut < 0 ? tok : tok.slice(0, cut)).replace(/^\$/, '');
        const nick = cut < 0 ? '' : tok.slice(cut + 1);
        return { fp, nick };
      }).filter((h) => h.fp.length >= 8)
    : [];
  const grab = (key) => {
    const re = new RegExp('\\b' + key + '=(\\S+)');
    const mm = re.exec(rest);
    return mm ? mm[1] : null;
  };
  return {
    id,
    status,
    path,
    purpose:   grab('PURPOSE'),
    hsState:   grab('HS_STATE'),
    hsAddress: grab('REND_QUERY') || grab('HS_QUERY'),
    timeCreated: grab('TIME_CREATED'),
  };
}

/**
 * Parse one stream-status entry:
 *   <StreamID> SP <StreamStatus> SP <CircID> SP <Target>
 */
function parseStream(line) {
  const m = /^(\d+)\s+(\w+)\s+(\d+)\s+(\S+)/.exec(line);
  if (!m) return null;
  const target = m[4];
  const colon = target.lastIndexOf(':');
  const host = colon < 0 ? target : target.slice(0, colon);
  const port = colon < 0 ? 0 : parseInt(target.slice(colon + 1), 10);
  return { id: m[1], status: m[2], circId: m[3], host, port };
}

/**
 * Best-effort lookup of relay metadata by fingerprint.
 *
 * Tor's `GETINFO ns/id/$FP` returns a network-status entry:
 *   r <nick> <id-b64> <descr-b64> <pubdate> <pubtime> <ip> <orport> <dirport>
 *   s <flags...>
 *
 * Returns { addr, country? } — country requires `GETINFO ip-to-country/...`
 * which we skip in this v0 (avoids extra round-trips per hop).
 */
async function resolveRelay(ctl, fp) {
  try {
    const lines = await getInfo(ctl, 'ns/id/' + fp);
    const r = lines.find((l) => l.startsWith('r '));
    if (!r) return {};
    const parts = r.split(/\s+/);
    return {
      addr: parts[6] || undefined,
      orPort: parseInt(parts[7] || '0', 10) || undefined,
    };
  } catch (_) {
    return {};
  }
}

/**
 * Locate the BUILT circuit currently serving a given hostname.
 *
 * Strategy:
 *   1. Match a SUCCEEDED stream whose TARGET host == host.
 *   2. Fall back to a BUILT HS_CLIENT_REND circuit whose REND_QUERY
 *      starts with the .onion prefix (for cases where the stream
 *      already closed but the circuit is still around).
 *   3. Fall back to the most recent BUILT circuit if any.
 *      (Useful for showing *any* circuit on clearnet sites — even
 *      though clearnet doesn't actually route through tor in this
 *      build, returning the last-built circuit lets the user see
 *      that tor is alive.)
 *
 * Returns `null` when tor has no built circuits at all.
 *
 * @param {string} host  hostname (e.g. "example.onion")
 * @param {string} runtimeDir  absolute path to AnonLayer/tor/run
 * @param {object} [opts]
 * @param {boolean} [opts.fallbackToLatest=false]
 *   If true and no host-specific match is found, return the newest
 *   BUILT circuit. Default false — caller decides per network type.
 * @returns {Promise<object | null>}
 */
export async function queryTorCircuitForHost(host, runtimeDir, opts = {}) {
  const ctl = await openControl(runtimeDir);
  try {
    const circRaw = await getInfo(ctl, 'circuit-status');
    const streamRaw = await getInfo(ctl, 'stream-status');
    const circs = circRaw.map(parseCircuit).filter(Boolean);
    const streams = streamRaw.map(parseStream).filter(Boolean);
    const hostLc = String(host || '').toLowerCase();

    let circ = null;

    if (hostLc) {
      const matchingStream = streams.find(
        (s) => s.host.toLowerCase() === hostLc &&
          (s.status === 'SUCCEEDED' || s.status === 'SENTRESOLVE' || s.status === 'NEWRESOLVE')
      ) || streams.find((s) => s.host.toLowerCase() === hostLc);
      if (matchingStream) {
        circ = circs.find((c) => c.id === matchingStream.circId);
      }
      if (!circ && hostLc.endsWith('.onion')) {
        const stub = hostLc.replace(/\.onion$/, '');
        circ = circs.find((c) =>
          c.status === 'BUILT' &&
          c.purpose === 'HS_CLIENT_REND' &&
          c.hsAddress && c.hsAddress.toLowerCase().startsWith(stub)
        );
      }
    }

    if (!circ && opts.fallbackToLatest) {
      const built = circs.filter((c) => c.status === 'BUILT');
      if (built.length) {
        // Use the highest CircID as a coarse proxy for "most recent."
        built.sort((a, b) => parseInt(b.id, 10) - parseInt(a.id, 10));
        circ = built[0];
      }
    }

    if (!circ) {
      return circs.length === 0 ? null : { error: 'no matching circuit', built: circs.length };
    }

    // Resolve hops SERIALLY — the control connection is one TCP
    // stream and we can't tell whose response is whose if we issue
    // GETINFO concurrently. Promise.all here used to deadlock (lines
    // for request N would land in waiters for request N+1).
    const hops = [];
    for (const h of circ.path) {
      const meta = await resolveRelay(ctl, h.fp);
      hops.push({ fp: h.fp, nick: h.nick, ...meta });
    }

    return {
      id: circ.id,
      status: circ.status,
      purpose: circ.purpose,
      hsState: circ.hsState,
      hsAddress: circ.hsAddress,
      hops,
    };
  } finally {
    ctl.close();
  }
}
