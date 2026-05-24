#!/usr/bin/env node
// validate.mjs — sanity check for the packaged .xpi.
//
// Not a substitute for web-ext lint or AMO's validator. It catches the
// classes of mistakes a manual review keeps making:
//   - manifest references files that aren't in the zip
//   - manifest declares permissions that don't exist
//   - script paths that drift from disk
//
// Usage:
//   node validate.mjs                       # validate the extension/ tree on disk
//   node validate.mjs dist/anon-layer-X.xpi # validate the contents of a built .xpi

import { readFile, stat } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));

// ---------- Known-good permission and key vocabularies ----------

const VALID_PERMISSIONS = new Set([
    'activeTab', 'alarms', 'bookmarks', 'browserSettings', 'browsingData',
    'clipboardRead', 'clipboardWrite', 'contentSettings', 'contextMenus',
    'cookies', 'declarativeNetRequest', 'declarativeNetRequestFeedback',
    'declarativeNetRequestWithHostAccess', 'devtools', 'downloads',
    'downloads.open', 'find', 'geolocation', 'history', 'identity',
    'idle', 'management', 'menus', 'menus.overrideContext',
    'nativeMessaging', 'notifications', 'pageCapture', 'pkcs11',
    'privacy', 'proxy', 'scripting', 'search', 'sessions', 'storage',
    'tabs', 'tabHide', 'theme', 'topSites', 'unlimitedStorage',
    'webNavigation', 'webRequest', 'webRequestAuthProvider',
    'webRequestBlocking', 'webRequestFilterResponse',
    'webRequestFilterResponse.serviceWorkerScript',
]);

// ---------- Inputs ----------

const args = process.argv.slice(2);
const xpiPath = args[0];

let manifest;
let presentFiles;

if (xpiPath) {

    // Use `unzip -l` to list, `unzip -p` to read contents. Avoids a
    // dependency on a JS zip library.
    const listing = execFileSync('unzip', ['-l', xpiPath], { encoding: 'utf8' });
    presentFiles = new Set(
        listing
            .split('\n')
            .slice(3, -3)
            .map((line) => line.trim().split(/\s+/).slice(3).join(' '))
            .filter(Boolean),
    );
    if (!presentFiles.has('manifest.json')) {
        process.stderr.write('error: zip missing manifest.json\n');
        process.exit(2);
    }
    const manifestRaw = execFileSync('unzip', ['-p', xpiPath, 'manifest.json'], { encoding: 'utf8' });
    manifest = JSON.parse(manifestRaw);

} else {

    const manifestPath = join(ROOT, 'manifest.json');
    manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    presentFiles = null; // checked via fs.stat instead

}

// ---------- Checks ----------

let errors = 0;
let warnings = 0;
const fail = (msg) => { process.stderr.write(`error: ${msg}\n`); errors += 1; };
const warn = (msg) => { process.stderr.write(`warn : ${msg}\n`); warnings += 1; };

const expectFile = async (relPath, context) => {
    if (presentFiles) {
        if (!presentFiles.has(relPath)) fail(`${context}: file not in zip: ${relPath}`);
        return;
    }
    try {
        const s = await stat(resolve(ROOT, relPath));
        if (!s.isFile()) fail(`${context}: not a file: ${relPath}`);
    } catch {
        fail(`${context}: file missing on disk: ${relPath}`);
    }
};

// --- manifest_version ---
if (manifest.manifest_version !== 3) {
    fail(`manifest_version must be 3 (got ${manifest.manifest_version})`);
}

// --- name, version, description ---
if (!manifest.name || typeof manifest.name !== 'string') fail('missing manifest.name');
if (!manifest.version || typeof manifest.version !== 'string') {
    fail('missing manifest.version');
} else if (!/^\d+(\.\d+){0,3}$/.test(manifest.version)) {
    fail(`version must be N[.N[.N[.N]]] (got "${manifest.version}")`);
}

// --- icons ---
for (const [size, file] of Object.entries(manifest.icons || {})) {
    if (!/^\d+$/.test(size)) fail(`bad icon size key: ${size}`);
    await expectFile(file, `icons[${size}]`);
}

// --- gecko id ---
const geckoId = manifest.browser_specific_settings?.gecko?.id;
if (!geckoId) {
    warn('no browser_specific_settings.gecko.id — Firefox will assign a temporary id');
} else if (!/^([^@]+@[^@]+)|(\{[0-9a-f-]+\})$/i.test(geckoId)) {
    fail(`gecko.id must look like name@domain or {uuid}; got "${geckoId}"`);
}

// --- background ---
const bg = manifest.background;
if (bg) {
    if (bg.scripts) for (const s of bg.scripts) await expectFile(s, 'background.scripts');
    if (bg.service_worker) await expectFile(bg.service_worker, 'background.service_worker');
}

// --- action / browser_action ---
if (manifest.action?.default_popup) await expectFile(manifest.action.default_popup, 'action.default_popup');
for (const [size, file] of Object.entries(manifest.action?.default_icon || {})) {
    await expectFile(file, `action.default_icon[${size}]`);
}

// --- options_ui ---
if (manifest.options_ui?.page) await expectFile(manifest.options_ui.page, 'options_ui.page');

// --- content_scripts ---
for (const cs of manifest.content_scripts || []) {
    for (const js of cs.js || [])  await expectFile(js,  'content_scripts[].js');
    for (const css of cs.css || []) await expectFile(css, 'content_scripts[].css');
}

// --- web_accessible_resources ---
for (const wr of manifest.web_accessible_resources || []) {
    for (const r of wr.resources || []) await expectFile(r, 'web_accessible_resources');
}

// --- permissions vocabulary ---
for (const p of manifest.permissions || []) {
    if (!VALID_PERMISSIONS.has(p)) {
        warn(`unknown permission "${p}" (not in our static vocabulary; verify against MDN)`);
    }
}

// --- protocol_handlers ---
for (const ph of manifest.protocol_handlers || []) {
    if (!ph.protocol)   fail('protocol_handlers[]: missing protocol');
    if (!ph.uriTemplate) fail('protocol_handlers[]: missing uriTemplate');
    if (ph.uriTemplate && !ph.uriTemplate.includes('%s')) {
        fail(`protocol_handlers[]: uriTemplate must contain %s: ${ph.uriTemplate}`);
    }
    // Only "web+*" custom protocols and a few whitelisted ones are
    // registerable via Firefox's web protocol-handler UI. If the user
    // tries "anon" directly, it'll be silently ignored.
    if (ph.protocol && !ph.protocol.startsWith('web+')
        && !['bitcoin','geo','im','irc','ircs','magnet','mailto','matrix',
             'mms','news','nntp','openpgp4fpr','sip','sms','smsto','ssh',
             'tel','urn','webcal','wtai','xmpp'].includes(ph.protocol)) {
        warn(`protocol_handlers[]: "${ph.protocol}" is not in Firefox's web-registerable list;`
            + ' only web+-prefixed schemes will work without a browser patch.');
    }
}

// ---------- Report ----------

process.stdout.write(`\nvalidate: ${errors} error(s), ${warnings} warning(s)\n`);
process.exit(errors > 0 ? 1 : 0);
