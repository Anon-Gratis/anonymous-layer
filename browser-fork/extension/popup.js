// popup.js — toolbar action popup.

(() => {

  const $ = (id) => document.getElementById(id);
  const u      = $('u');
  const go     = $('go');
  const newtab = $('newtab');
  const opts   = $('opts');

  const open = async (anonUrl) => {
    await browser.runtime.sendMessage({
      kind:   'open-anon',
      url:    anonUrl,
      newTab: true,
    });
    window.close();
  };

  go.addEventListener('click', () => {
    if (u.value.trim()) open(u.value.trim());
  });
  u.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && u.value.trim()) open(u.value.trim());
  });
  newtab.addEventListener('click', () => open(''));
  opts.addEventListener('click', () => {
    browser.runtime.openOptionsPage();
    window.close();
  });

  u.focus();

})();
