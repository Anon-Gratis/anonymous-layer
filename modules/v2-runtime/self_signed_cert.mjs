// Self-signed cert generation for link-transport TLS (SPEC § 11.1).
//
// The cert is NOT the relay's identity. The relay's identity is its
// Ed25519 `idPk`, authenticated at LINK_AUTH. This cert exists ONLY
// to enable TLS as a carrier — its only requirements are:
//
//   (1) be valid X.509 the TLS layer will accept,
//   (2) be the same on both sides of any given relay restart
//       (otherwise TLS resumption breaks; merely cosmetic since the
//       handshake is short anyway).
//
// Auditor objections we deliberately accept:
//   - 10-year validity, not 90-day. The cert isn't ever validated
//     against a clock or a CT log; rotating it costs an unrelated
//     handshake roundtrip. A short validity buys nothing.
//   - CN "anon-relay", not the relay's hostname or fingerprint.
//     Including the fingerprint would suggest the CN is meaningful
//     for identity, which it isn't — and a future hostname rotation
//     would force cert rotation for no reason.
//   - openssl shell-out, not a JS X.509 builder. We don't want to
//     vendor an unaudited DER builder for a cert nobody validates.
//     openssl is in every Debian/Alpine/Ubuntu base image we'd use.
//   - Single P-256 keypair, no SAN, no EKU. TLS 1.2/1.3 accepts.
//
// Generated cert is a PEM string; key is a PEM string. Caller stores
// both, passes to createLinkListener({tlsCert, tlsKey}).

import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync, mkdtempSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';

const die = (msg) => { throw new Error(`self_signed_cert: ${msg}`); };

// Generate a fresh self-signed (cert, key) pair via openssl. Synchronous
// because (a) it's only called on startup or test setup, and (b)
// promise plumbing for ~50ms of cpu isn't worth the complexity.
//
// Returns { certPem, keyPem }. Uses a private mkdtemp dir for the
// intermediate files (openssl `req -x509` won't write both key and
// cert to /dev/stdout simultaneously) and removes it before returning.
export const generateSelfSignedCert = () => {

    const tmp = mkdtempSync(join(tmpdir(), 'anon-cert-'));
    const keyPath  = join(tmp, 'key.pem');
    const certPath = join(tmp, 'cert.pem');

    try {

        const res = spawnSync('openssl', [
            'req', '-x509',
            '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
            '-keyout', keyPath,
            '-out',    certPath,
            '-days',   '3650',
            '-nodes',                       // no passphrase
            '-subj',   '/CN=anon-relay',
            '-batch',
        ], { encoding: 'utf8' });

        if (res.error || res.status !== 0) {

            die(`openssl failed: ${res.error?.message || res.stderr || `exit ${res.status}`}`);

        }
        return {
            certPem: readFileSync(certPath, 'utf8'),
            keyPem:  readFileSync(keyPath,  'utf8'),
        };

    } finally {

        // Best-effort cleanup; if it fails the OS reclaims the tmpdir
        // anyway (we're inside $TMPDIR).
        try { rmSync(tmp, { recursive: true, force: true }); } catch {}

    }

};

// Load a (cert, key) pair from `dataDir/link-cert.pem` + `link-key.pem`.
// If either is missing, generate a fresh pair and persist (key mode
// 0600). Persistence is so cert rotation isn't a side-effect of
// every container restart — useful for operators who want their
// session-cache stability across maintenance bounces, harmless if
// they don't.
export const loadOrCreateLinkCert = (dataDir) => {

    const certPath = join(dataDir, 'link-cert.pem');
    const keyPath  = join(dataDir, 'link-key.pem');

    if (existsSync(certPath) && existsSync(keyPath)) {

        return {
            certPem: readFileSync(certPath, 'utf8'),
            keyPem:  readFileSync(keyPath,  'utf8'),
        };

    }

    mkdirSync(dirname(certPath), { recursive: true });
    const { certPem, keyPem } = generateSelfSignedCert();
    writeFileSync(certPath, certPem);
    writeFileSync(keyPath,  keyPem);
    try { chmodSync(keyPath, 0o600); } catch { /* best-effort, not OS-critical */ }
    return { certPem, keyPem };

};
