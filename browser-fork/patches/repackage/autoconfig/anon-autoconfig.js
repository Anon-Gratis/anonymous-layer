// Anon Browser — autoconfig pointer.
//
// Installed at Browser/defaults/pref/anon-autoconfig.js. Tells Firefox
// to load mozilla.cfg from the install dir on startup. mozilla.cfg
// then force-injects our userChrome.css / userContent.css via the
// style-sheet service — bypassing the legacy toolkit pref that some
// Tor/Mullvad-derived builds appear to gate or strip.
//
// The "obscure_value" pref is the historical no-op rot13 toggle (we
// set it to 0 = no obfuscation; the .cfg is plain JS).
// sandbox_enabled=false grants the cfg access to full XPCOM.

pref("general.config.filename",        "mozilla.cfg");
pref("general.config.obscure_value",   0);
pref("general.config.sandbox_enabled", false);
