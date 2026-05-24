// options.js — extension settings.

(() => {

  const DEFAULTS = {
    bridgeUrl:   'http://127.0.0.1:1081',
    bridgeToken: '',
  };

  const $ = (id) => document.getElementById(id);
  const bridgeUrl   = $('bridgeUrl');
  const bridgeToken = $('bridgeToken');
  const pasteUrl    = $('pasteUrl');
  const parseUrlBtn = $('parseUrl');
  const saveBtn     = $('save');
  const testBtn     = $('test');
  const resetBtn    = $('reset');
  const statusEl    = $('status');
  const grantBtn    = $('grantHostAccess');
  const grantState  = $('hostAccessState');

  const setStatus = (text, kind) => {
    statusEl.textContent = text;
    statusEl.className = kind === 'error' ? 'error'
      : kind === 'ok'  ? 'ok'
      : '';
  };

  // ---------- Load ----------

  const load = async () => {
    const cfg = { ...DEFAULTS, ...(await browser.storage.local.get(Object.keys(DEFAULTS))) };
    bridgeUrl.value   = cfg.bridgeUrl   || '';
    bridgeToken.value = cfg.bridgeToken || '';
  };

  // ---------- Save ----------

  const validateUrl = (u) => {
    try {
      const p = new URL(u);
      if (p.protocol !== 'http:' && p.protocol !== 'https:') {
        throw new Error('Bridge URL must be http:// or https://');
      }
      // Reject anything but localhost or 127.0.0.0/8 to avoid leaking
      // the user's traffic across the network if they typo their LAN IP.
      const host = p.hostname;
      const isLocal = host === 'localhost'
        || host === '127.0.0.1'
        || /^127\.\d+\.\d+\.\d+$/.test(host)
        || host === '::1';
      if (!isLocal) {
        throw new Error(
          'For safety the bridge must be on localhost (127.0.0.1 / ::1). '
          + 'Got: ' + host
        );
      }
      return p.origin;
    } catch (err) {
      throw new Error(err.message || ('Invalid URL: ' + u));
    }
  };

  const save = async () => {
    let origin;
    try {
      origin = validateUrl(bridgeUrl.value.trim());
    } catch (err) {
      setStatus(err.message, 'error');
      return;
    }
    const token = bridgeToken.value.trim();
    await browser.storage.local.set({ bridgeUrl: origin, bridgeToken: token });
    setStatus('Saved.', 'ok');
  };

  // ---------- Parse pasted URL ----------

  const parse = () => {
    const raw = pasteUrl.value.trim();
    if (!raw) {
      setStatus('Paste the URL the anon-browse-gui binary printed at startup.', 'error');
      return;
    }
    let parsed;
    try {
      parsed = new URL(raw);
    } catch {
      setStatus('Could not parse as a URL: ' + raw, 'error');
      return;
    }
    try {
      validateUrl(parsed.origin);
    } catch (err) {
      setStatus(err.message, 'error');
      return;
    }
    bridgeUrl.value = parsed.origin;
    const tok = parsed.searchParams.get('token');
    if (tok) bridgeToken.value = tok;
    setStatus('Filled. Click Save to persist.', 'ok');
  };

  // ---------- Test ----------

  const test = async () => {
    let origin;
    try {
      origin = validateUrl(bridgeUrl.value.trim());
    } catch (err) {
      setStatus(err.message, 'error');
      return;
    }
    setStatus('Pinging ' + origin + '/api/health…');
    let result;
    try {
      result = await browser.runtime.sendMessage({
        kind:        'ping-bridge',
        bridgeUrl:   origin,
        bridgeToken: bridgeToken.value.trim(),
      });
    } catch (err) {
      setStatus('Background script unreachable: ' + err.message, 'error');
      return;
    }
    if (!result || !result.ok) {
      setStatus('Bridge unreachable: ' + ((result && result.error) || 'no response'), 'error');
      return;
    }
    if (result.httpStatus === 200) {
      const v = (result.body && result.body.version) || 'unknown';
      setStatus(`OK · bridge HTTP 200 · version=${v}`, 'ok');
    } else if (result.httpStatus === 403) {
      setStatus('Reached the bridge, but the session token is missing or wrong (HTTP 403).', 'error');
    } else if (result.httpStatus === 404) {
      setStatus(
        'Reached the host, but no /api/health endpoint (HTTP 404). '
        + 'Is the bridge anon-browse-gui from this repo version 0.0.1+?',
        'error',
      );
    } else {
      setStatus(`Bridge replied with HTTP ${result.httpStatus}.`, 'error');
    }
  };

  // ---------- Reset ----------

  const reset = async () => {
    await browser.storage.local.set(DEFAULTS);
    await load();
    setStatus('Reset to defaults.', 'ok');
  };

  // ---------- URL bar host access ----------
  //
  // In Firefox MV3 host_permissions are user-gated post-install — the
  // manifest's <all_urls> declaration is a *request*, not a grant. The
  // user has to flip the toggle in about:addons OR click this button,
  // which triggers Firefox's native permission prompt via
  // permissions.request(). Without that grant, webRequest/webNavigation
  // events strip details.url and the .anon URL-bar interceptor in
  // background.js silently does nothing.

  const ALL_URLS = { origins: ['<all_urls>'] };

  const refreshHostAccessState = async () => {
    try {
      const granted = await browser.permissions.contains(ALL_URLS);
      if (granted) {
        grantState.textContent = '✓ Granted — typing foo.anon in the URL bar will work.';
        grantState.style.color = 'var(--ok, #4caf50)';
        grantBtn.disabled = true;
        grantBtn.textContent = 'Already granted';
      } else {
        grantState.textContent = '✗ Not granted — typed .anon addresses will still go to search.';
        grantState.style.color = 'var(--err, #f44336)';
        grantBtn.disabled = false;
        grantBtn.textContent = 'Grant URL bar access';
      }
    } catch {
      grantState.textContent = '(permissions API unavailable)';
    }
  };

  const grantHostAccess = async () => {
    try {
      const ok = await browser.permissions.request(ALL_URLS);
      if (ok) setStatus('URL bar access granted. Try typing a .anon address now.', 'ok');
      else    setStatus('URL bar access denied. You can still grant it later via about:addons → Anon Layer → Permissions.', 'error');
    } catch (err) {
      setStatus('Could not request permission: ' + err.message, 'error');
    }
    await refreshHostAccessState();
  };

  // Re-check whenever Firefox tells us permissions changed (the user
  // may also flip the toggle in about:addons while this page is open).
  if (browser.permissions && browser.permissions.onAdded) {
    browser.permissions.onAdded  .addListener(refreshHostAccessState);
  }
  if (browser.permissions && browser.permissions.onRemoved) {
    browser.permissions.onRemoved.addListener(refreshHostAccessState);
  }

  // ---------- Wiring ----------

  saveBtn   .addEventListener('click', save);
  testBtn   .addEventListener('click', test);
  resetBtn  .addEventListener('click', reset);
  parseUrlBtn.addEventListener('click', parse);
  pasteUrl  .addEventListener('keydown', (e) => { if (e.key === 'Enter') parse(); });
  if (grantBtn) grantBtn.addEventListener('click', grantHostAccess);

  load();
  refreshHostAccessState();

})();
