// content/intercept.js — re-route anon:// link clicks to the extension.
//
// Browsers don't know what anon:// is. Clicking such a link normally
// surfaces a "search for…" or "the address wasn't understood" error.
// We catch the click in capture phase and message background.js to
// open the extension renderer instead. Same for web+anon://.
//
// Intentionally minimal: no DOM mutation, no decoration, no fetch.
// Lower attack surface, and avoids any per-page footprint a fingerprint
// script could detect.

(() => {

  const isAnonScheme = (href) =>
    typeof href === 'string'
    && (href.startsWith('anon://') || href.startsWith('web+anon://'));

  document.addEventListener('click', (event) => {

    // Only handle plain left-clicks. Let modifier-clicks (ctrl, shift,
    // middle button) flow through; background.js opens in a new tab
    // on its own.
    if (event.defaultPrevented) return;
    if (event.button !== 0 && event.button !== 1) return;

    // Walk up to find the nearest <a>.
    let el = event.target;
    while (el && el.nodeType === 1 && el.tagName !== 'A') {
      el = el.parentNode;
    }
    if (!el || el.tagName !== 'A') return;

    const href = el.getAttribute('href');
    if (!isAnonScheme(href)) return;

    event.preventDefault();
    event.stopPropagation();

    const newTab =
      event.button === 1
      || event.ctrlKey
      || event.metaKey
      || event.shiftKey
      || el.target === '_blank';

    browser.runtime.sendMessage({
      kind:   'open-anon',
      url:    href,
      newTab,
    }).catch(() => { /* background may be reloading; nothing useful to do */ });

  }, true);

})();
