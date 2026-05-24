// render.js — extension renderer for the anon-layer network.
//
// Mirrors the inline UI in bin/anon-browse-gui.mjs (HTML_UI). Talks to
// the same /api/fetch endpoint that anon-browse-gui exposes, with a
// session token the user pastes into the options page. The actual
// rendezvous + circuit work happens in the Node bridge process — this
// file is presentation only.

import {
    renderDocument,
    resolveUrl,
    normalizeAnon,
    escapeHtml as escape,
} from './lib/render-doc.mjs';

(() => {

  const $ = (id) => document.getElementById(id);
  const back    = $('back');
  const fwd     = $('fwd');
  const reload  = $('reload');
  const urlBox  = $('url');
  const go      = $('go');
  const opts    = $('opts');
  const content = $('content');
  const status  = $('status');

  // ---------- Storage ----------

  const DEFAULTS = {
    bridgeUrl: 'http://127.0.0.1:1081',
    bridgeToken: '',
  };

  const getConfig = async () => {
    const stored = await browser.storage.local.get(Object.keys(DEFAULTS));
    return { ...DEFAULTS, ...stored };
  };

  // ---------- Status banner ----------

  const setStatus = (text, kind) => {
    status.textContent = text;
    status.className = kind === 'error' ? 'error'
      : kind === 'ok'  ? 'ok'
      : '';
  };

  // ---------- URL handling ----------

  // The page tracks two URL spaces:
  //   * outer: the moz-extension://.../render.html?u=<anon-url> address
  //     bar URL, which the browser shows and back/forward over.
  //   * inner: the anon:// URL currently loaded in the renderer.
  // pushState keeps them in sync.

  const readOuterUrl = () => {
    const p = new URLSearchParams(window.location.search);
    return p.get('u') || '';
  };

  const setOuterUrl = (anonUrl, replace) => {
    const next = `${window.location.pathname}?u=${encodeURIComponent(anonUrl)}`;
    if (replace) window.history.replaceState({ u: anonUrl }, '', next);
    else         window.history.pushState({ u: anonUrl }, '', next);
  };

  // ---------- Bridge fetch ----------

  const fetchViaBridge = async (anonUrl) => {

    const cfg = await getConfig();
    if (!cfg.bridgeUrl) {
      throw new Error(
        'No bridge URL configured. Open the extension Settings (⚙) '
        + 'and point Anon Layer at a running anon-browse-gui instance.'
      );
    }

    const u = new URL('/api/fetch', cfg.bridgeUrl);
    u.searchParams.set('url', anonUrl);
    if (cfg.bridgeToken) u.searchParams.set('token', cfg.bridgeToken);

    let resp;
    try {
      resp = await fetch(u.toString(), { credentials: 'omit', cache: 'no-store' });
    } catch (err) {
      throw new Error(
        `Could not reach the bridge at ${cfg.bridgeUrl}: ${err.message}. `
        + 'Is anon-browse-gui running?'
      );
    }
    if (!resp.ok) {
      throw new Error(`Bridge returned HTTP ${resp.status}.`);
    }
    const data = await resp.json();
    if (data.error) throw new Error('Bridge: ' + data.error);
    return data;

  };

  // ---------- Navigation ----------

  let currentUrl = null;
  let inFlight   = 0;

  const wireLinks = (basis) => {

    for (const a of content.querySelectorAll('a[data-target]')) {
      a.addEventListener('click', (e) => {
        e.preventDefault();
        const t = a.getAttribute('data-target');
        const innet = a.getAttribute('data-innet') === '1';
        const resolved = resolveUrl(t, basis);
        if (innet || resolved.startsWith('anon://')) {
          navigate(resolved, { push: true });
        } else {
          const ok = window.confirm(
            'Off-network link:\n' + resolved + '\n\n'
            + 'This will leave the anon-network and use the normal '
            + 'browser network stack. Continue?'
          );
          if (ok) window.open(resolved, '_blank', 'noopener,noreferrer');
        }
      });
    }

  };

  const renderResult = (data) => {

    if (data.kind === 'document') {
      content.innerHTML = renderDocument(data.lines);
      wireLinks(data.url || currentUrl);
      return;
    }
    if (data.kind === 'plain') {
      content.innerHTML = '<pre class="code">' + escape(data.text) + '</pre>';
      return;
    }
    if (data.kind === 'redirect') {
      content.innerHTML = '<div class="notice-box">Redirect ' + data.status
        + ' →<br><a href="#" data-target="' + escape(data.target) + '"'
        + ' data-innet="' + (data.target && data.target.startsWith('anon://') ? '1' : '0') + '">'
        + escape(data.target) + '</a></div>';
      wireLinks(data.url || currentUrl);
      return;
    }
    if (data.kind === 'binary') {
      content.innerHTML = '<div class="notice-box">Binary content: '
        + escape(data.mimeType) + ', ' + data.byteLength + ' bytes.<br>'
        + 'This renderer does not display non-text content yet.</div>';
      return;
    }
    if (data.kind === 'error') {
      content.innerHTML = '<div class="error-box">Server error ' + data.status
        + ': ' + escape(data.message || '') + '</div>';
      return;
    }
    if (data.kind === 'input') {
      content.innerHTML = '<div class="notice-box">Server requests input: '
        + escape(data.prompt || '')
        + '<br><br>Append <code>?your-answer</code> to the URL and reload.</div>';
      return;
    }
    content.innerHTML = '<div class="error-box">Unexpected response shape.</div>';

  };

  const navigate = async (rawTarget, options = {}) => {

    if (!rawTarget) return;
    const anonUrl = normalizeAnon(rawTarget.trim());
    if (!anonUrl.startsWith('anon://')) {
      content.innerHTML = '<div class="error-box">Not an anon-network URL: '
        + escape(anonUrl) + '</div>';
      return;
    }

    currentUrl = anonUrl;
    urlBox.value = anonUrl;
    if (options.push !== false) setOuterUrl(anonUrl, options.replace);

    const myFetch = ++inFlight;
    setStatus('Loading ' + anonUrl + '…');
    try {
      const data = await fetchViaBridge(anonUrl);
      if (myFetch !== inFlight) return; // stale
      const statusLine = (data.status ? data.status + ' ' : '') + (data.meta || '');
      setStatus(statusLine.trim() || 'loaded', 'ok');
      renderResult(data);
    } catch (err) {
      if (myFetch !== inFlight) return;
      content.innerHTML = '<div class="error-box">' + escape(err.message) + '</div>';
      setStatus(err.message, 'error');
    }

  };

  // ---------- Toolbar wiring ----------

  back   .addEventListener('click', () => window.history.back());
  fwd    .addEventListener('click', () => window.history.forward());
  reload .addEventListener('click', () => {
    if (currentUrl) navigate(currentUrl, { push: false });
  });
  go     .addEventListener('click', () => {
    if (urlBox.value) navigate(urlBox.value, { push: true });
  });
  urlBox .addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && urlBox.value) navigate(urlBox.value, { push: true });
  });
  opts   .addEventListener('click', () => browser.runtime.openOptionsPage());

  window.addEventListener('popstate', (e) => {
    const next = (e.state && e.state.u) || readOuterUrl();
    if (next && next !== currentUrl) navigate(next, { push: false });
  });

  // ---------- Boot ----------

  const initial = readOuterUrl();
  if (initial) {
    navigate(initial, { push: false, replace: true });
  } else {
    setStatus('ready · type an anon:// URL');
  }

})();
