// background.js — anon-layer entry-point routing.
//
// The extension can't natively register anon:// (only web+ prefixed
// schemes are accepted by navigator.registerProtocolHandler, and the
// manifest protocol_handlers field can't target moz-extension://).
// Instead, we surface four entry points and route them all into
// render.html?u=<anon-url>:
//
//   1. Toolbar action button (popup.html) — landing page.
//   2. Omnibox keyword `anon` — type `anon foo.anon/bar` in the URL bar.
//   3. Context menu — right-click an anon-network link or selection.
//   4. Content script — clicking <a href="anon://..."> on any page.

const RENDER_PAGE = 'render.html';

const DEFAULTS = {
  bridgeUrl:   'http://127.0.0.1:1081',
  bridgeToken: '',
};

// Make raw user text into a canonical anon:// URL. Accepted forms:
//   anon://foo.anon/bar       → as-is
//   web+anon://foo.anon/bar   → anon://foo.anon/bar
//   foo.anon[/bar]            → anon://foo.anon[/bar]
//   anon foo.anon/bar         → anon://foo.anon/bar  (omnibox)
const canonicalAnonUrl = (raw) => {
  let s = String(raw || '').trim();
  if (s === '') return null;
  if (s.startsWith('web+anon://')) return 'anon://' + s.slice('web+anon://'.length);
  if (s.startsWith('anon://')) return s;
  // omnibox path: keyword is stripped by the API, but tolerate the form
  if (s.startsWith('anon ')) s = s.slice(5).trim();
  // bare hostname-like text — treat as anon-network host.
  return 'anon://' + s.replace(/^\/+/, '');
};

// Strict counterpart used by the URL-bar / search-engine interceptor:
// returns a canonical anon:// URL only if the input *looks like* a
// .anon target (host whose final label is "anon", each label a valid
// DNS label). Returns null otherwise so plain text and unrelated URLs
// fall through. Mirrors lib/render-doc.mjs#looksLikeAnonHost — keep in
// sync.
const looksLikeAnonHost = (raw) => {
  let s = String(raw || '').trim();
  if (s === '') return null;
  const lower = s.toLowerCase();
  for (const prefix of ['web+anon://', 'anon://', 'https://', 'http://']) {
    if (lower.startsWith(prefix)) { s = s.slice(prefix.length); break; }
  }
  const sep = s.search(/[\/?#]/);
  const host = sep === -1 ? s : s.slice(0, sep);
  const rest = sep === -1 ? '' : s.slice(sep);
  const portIdx = host.indexOf(':');
  const hostNoPort = portIdx === -1 ? host : host.slice(0, portIdx);
  const labels = hostNoPort.split('.');
  if (labels.length < 2) return null;
  if (labels[labels.length - 1].toLowerCase() !== 'anon') return null;
  for (const label of labels) {
    if (!/^[a-z0-9][a-z0-9-]{0,62}$/i.test(label)) return null;
  }
  return 'anon://' + host + rest;
};

const renderUrlFor = (anonUrl) => {
  const base = browser.runtime.getURL(RENDER_PAGE);
  return base + '?u=' + encodeURIComponent(anonUrl);
};

const openInTab = async (anonUrl, { newTab = false } = {}) => {
  const target = renderUrlFor(anonUrl);
  if (newTab) {
    await browser.tabs.create({ url: target });
    return;
  }
  const [active] = await browser.tabs.query({ active: true, currentWindow: true });
  if (active) await browser.tabs.update(active.id, { url: target });
  else        await browser.tabs.create({ url: target });
};

// ---------- Install / first-run defaults ----------

browser.runtime.onInstalled.addListener(async (details) => {
  const existing = await browser.storage.local.get(Object.keys(DEFAULTS));
  const patch = {};
  for (const k of Object.keys(DEFAULTS)) {
    if (existing[k] === undefined) patch[k] = DEFAULTS[k];
  }
  if (Object.keys(patch).length > 0) await browser.storage.local.set(patch);

  // Open the options page on install (so the user can paste a bridge
  // token before they hit any errors) AND on update if the <all_urls>
  // host permission isn't granted — otherwise the URL-bar interceptor
  // silently doesn't work and the user thinks the extension is broken.
  let hostGranted = true;
  try {
    hostGranted = await browser.permissions.contains({ origins: ['<all_urls>'] });
  } catch { /* permissions API may be missing in very old Firefox */ }

  if (details.reason === 'install' || !hostGranted) {
    try { browser.runtime.openOptionsPage(); } catch { /* ignore */ }
  }
});

// ---------- Action button: open the render page ----------

if (browser.action && browser.action.onClicked) {
  // No popup → click handler fires.
  browser.action.onClicked.addListener(async () => {
    await openInTab('', { newTab: true });
  });
}

// ---------- Omnibox: `anon foo.anon/bar` ----------

if (browser.omnibox) {
  browser.omnibox.setDefaultSuggestion({
    description: 'Open <match>%s</match> as an anon-network URL',
  });
  browser.omnibox.onInputEntered.addListener(async (text, disposition) => {
    const anonUrl = canonicalAnonUrl(text);
    if (!anonUrl) return;
    const newTab = disposition === 'newForegroundTab' || disposition === 'newBackgroundTab';
    await openInTab(anonUrl, { newTab });
  });
}

// ---------- Context menu ----------

const CTX_LINK      = 'anon-open-link';
const CTX_SELECTION = 'anon-open-selection';
const CTX_PAGE      = 'anon-new-tab';

const ensureContextMenus = () => {
  // Manifest V3 contextMenus survive across SW restarts in Chrome, but
  // we recreate defensively. Wrap removeAll in a Promise — Firefox's
  // browser.* API returns one already.
  return browser.contextMenus.removeAll().then(() => {
    browser.contextMenus.create({
      id: CTX_LINK,
      title: 'Open with Anon Layer',
      contexts: ['link'],
      targetUrlPatterns: ['anon://*/*', 'web+anon://*/*'],
    });
    browser.contextMenus.create({
      id: CTX_SELECTION,
      title: 'Open selection as anon:// URL',
      contexts: ['selection'],
    });
    browser.contextMenus.create({
      id: CTX_PAGE,
      title: 'New Anon Layer tab',
      contexts: ['page', 'action'],
    });
  });
};

browser.runtime.onInstalled.addListener(ensureContextMenus);
browser.runtime.onStartup    .addListener(ensureContextMenus);

if (browser.contextMenus && browser.contextMenus.onClicked) {
  browser.contextMenus.onClicked.addListener(async (info) => {
    if (info.menuItemId === CTX_LINK) {
      const anonUrl = canonicalAnonUrl(info.linkUrl);
      if (anonUrl) await openInTab(anonUrl, { newTab: true });
      return;
    }
    if (info.menuItemId === CTX_SELECTION) {
      const anonUrl = canonicalAnonUrl(info.selectionText);
      if (anonUrl) await openInTab(anonUrl, { newTab: true });
      return;
    }
    if (info.menuItemId === CTX_PAGE) {
      await openInTab('', { newTab: true });
    }
  });
}

// ---------- URL-bar / search-engine interception ----------
//
// Browsers don't recognise the .anon TLD natively. When the user
// types "foo.anon" in the URL bar, one of two things happens:
//
//   (a) URL fixup decides it's a URL and tries http://foo.anon/ —
//       which then leaks the hostname to the OS DNS resolver, or
//   (b) The input is handed to the default search engine — leaking
//       the .anon hostname to a third party in the query string.
//
// Both are caught here and rerouted into render.html. We register two
// listeners and let whichever can run, run:
//
//   1. webRequest.onBeforeRequest (blocking) — preferred. Cancels the
//      request before it leaves the browser, so the .anon hostname
//      never reaches any third party. Requires host_permissions for
//      the URL being intercepted, which in MV3 Firefox the user must
//      grant manually via about:addons.
//   2. webNavigation.onBeforeNavigate (fallback) — fires for every
//      navigation and we redirect via tabs.update. Same caveat: in
//      MV3 Firefox, details.url is only populated for URLs the user
//      has granted host access to.
//
// The content script in content/intercept.js handles clicked anon://
// links. The omnibox keyword handler above handles the explicit
// "anon foo.anon/…" form.

const SEARCH_TERM_PARAMS = ['q', 'query', 'p', 'wd', 'text', 'eingabe'];

const anonFromSearchUrl = (urlObj) => {
  for (const name of SEARCH_TERM_PARAMS) {
    const v = urlObj.searchParams.get(name);
    if (!v) continue;
    const a = looksLikeAnonHost(v);
    if (a) return a;
  }
  return null;
};

// Return a canonical anon:// URL if `urlString` represents an anon
// target (direct nav to *.anon, or a search-engine query whose term
// looks like one). Returns null if the URL is irrelevant.
const anonTargetForUrl = (urlString) => {
  let urlObj;
  try { urlObj = new URL(urlString); } catch { return null; }
  if (/\.anon$/i.test(urlObj.hostname)) {
    return 'anon://' + urlObj.host
      + urlObj.pathname + urlObj.search + urlObj.hash;
  }
  return anonFromSearchUrl(urlObj);
};

const EXT_ORIGIN = browser.runtime.getURL('').replace(/\/$/, '');
const isOwnUrl = (u) => typeof u === 'string' && EXT_ORIGIN && u.startsWith(EXT_ORIGIN);

// (1) webRequest blocking — preferred path.
if (browser.webRequest && browser.webRequest.onBeforeRequest) {
  try {
    browser.webRequest.onBeforeRequest.addListener(
      (details) => {
        if (details.type !== 'main_frame') return;
        if (isOwnUrl(details.url)) return;
        const anon = anonTargetForUrl(details.url);
        if (!anon) return;
        console.info('[anon-layer] webRequest intercept:', details.url, '→', anon);
        return { redirectUrl: renderUrlFor(anon) };
      },
      { urls: ['<all_urls>'], types: ['main_frame'] },
      ['blocking'],
    );
    console.info('[anon-layer] webRequest blocking listener registered');
  } catch (e) {
    console.warn('[anon-layer] webRequest registration failed:', e);
  }
}

// (2) webNavigation fallback.
if (browser.webNavigation && browser.webNavigation.onBeforeNavigate) {
  browser.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return;
    if (!details.url || isOwnUrl(details.url)) return;
    const anon = anonTargetForUrl(details.url);
    if (!anon) return;
    console.info('[anon-layer] webNavigation intercept:', details.url, '→', anon);
    try {
      await browser.tabs.update(details.tabId, { url: renderUrlFor(anon) });
    } catch (e) {
      console.warn('[anon-layer] tabs.update failed:', e);
    }
  });
  console.info('[anon-layer] webNavigation listener registered');
}

// Surface permission status at startup so the user can tell from the
// background console whether they need to grant <all_urls> via
// about:addons → Anon Layer → Permissions.
(async () => {
  try {
    const granted = await browser.permissions.contains({ origins: ['<all_urls>'] });
    if (granted) {
      console.info('[anon-layer] <all_urls> host permission: GRANTED');
    } else {
      console.warn(
        '[anon-layer] <all_urls> host permission: NOT GRANTED. '
        + 'URL-bar interception of .anon addresses will not work. '
        + 'Grant via about:addons → Anon Layer → Permissions → '
        + '"Access your data for all websites".',
      );
    }
  } catch (e) {
    console.warn('[anon-layer] permission check failed:', e);
  }
})();

// ---------- Messages from content script + render page ----------

browser.runtime.onMessage.addListener((msg, sender) => {

  if (!msg || typeof msg !== 'object') return;

  // Content script reports a clicked anon:// link.
  if (msg.kind === 'open-anon') {
    const anonUrl = canonicalAnonUrl(msg.url);
    if (!anonUrl) return Promise.resolve({ ok: false, reason: 'invalid' });
    const newTab = !!msg.newTab;
    return openInTab(anonUrl, { newTab }).then(() => ({ ok: true }));
  }

  // Options page asks us to ping the bridge.
  if (msg.kind === 'ping-bridge') {
    return pingBridge(msg.bridgeUrl, msg.bridgeToken)
      .then((r) => ({ ok: true,  ...r }))
      .catch((e) => ({ ok: false, error: e.message }));
  }

  return undefined;

});

const pingBridge = async (bridgeUrl, token) => {

  const u = new URL('/api/health', bridgeUrl);
  if (token) u.searchParams.set('token', token);

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 4000);
  try {
    const resp = await fetch(u.toString(), { credentials: 'omit', signal: ctrl.signal });
    const text = await resp.text();
    let body = null;
    try { body = JSON.parse(text); } catch { /* non-JSON */ }
    return { httpStatus: resp.status, body, raw: text };
  } finally {
    clearTimeout(timer);
  }

};
