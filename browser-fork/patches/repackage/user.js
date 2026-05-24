// Anon Browser v0.1 (repackage) — default user.js.
//
// Used by browser-fork/scripts/repackage-mullvad.sh; lands at
// Browser/defaults/profile/user.js inside the tarball. Firefox copies
// it into newly-created profiles. Different from
// browser-fork/patches/user.js (which configures SOCKS5 for the
// Mullvad-overlay workflow).
//
// In the bundled Anon Browser:
//   - anon:// is handled by the WebExtension talking to the local
//     bridge over HTTP localhost. No SOCKS proxy needed.
//   - clearnet (https://) loads direct in v0.1. For clearnet
//     anonymity, also run anon-socks and switch this profile to use
//     it (Settings → Network → Manual proxy → SOCKS5 127.0.0.1:1080).

// ----- Disable WebRTC (real-IP leak vector) -----

user_pref("media.peerconnection.enabled", false);
user_pref("media.navigator.enabled", false);
user_pref("media.peerconnection.ice.no_host", true);

// ----- Disable connection-prefetching that could leak destinations -----

user_pref("network.prefetch-next", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.dns.disablePrefetchFromHTTPS", true);
user_pref("network.predictor.enabled", false);
user_pref("browser.send_pings", false);

// ----- Disable safe-browsing lookups -----
//
// Safe Browsing would send URL hashes to Google. Mullvad Browser may
// already disable this; we redundantly set it for clarity.

user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);

// ----- Disable telemetry pings -----

user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.bhrPing.enabled", false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false);
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);

// ----- Disable update channel (we control updates by re-shipping the tarball) -----

user_pref("app.update.enabled", false);
user_pref("app.update.auto", false);

// ----- New-tab page -----
//
// Leave activity-stream's about:newtab enabled so the anon-layer
// extension's chrome_url_overrides.newtab can intercept and show
// the demo site. With enabled=false, Firefox loads about:blank for
// new tabs and the extension's override never fires.
//
// Telemetry/feeds knobs stay off — we want about:newtab as the
// routing target, not its activity-stream content.

user_pref("browser.newtabpage.enabled", true);
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);
user_pref("browser.newtabpage.activity-stream.feeds.snippets", false);
user_pref("browser.newtabpage.activity-stream.showSearch", false);
user_pref("browser.newtabpage.activity-stream.showSponsored", false);
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);

// ----- Anonymous-branded URLs (override upstream Mullvad/Mozilla) -----
//
// The omni.ja inherits a stack of support/feedback/update URLs from
// Mullvad and Mozilla. They get embedded into UI strings — the
// "Anonymous Support" link in Settings, the manual-update prompt,
// the moz-support-link components inside about:preferences, etc.
// Without these overrides the user sees an "Anonymous" label that
// dispatches them to mullvad.net or support.mozilla.org.

// SUMO base — every <moz-support-link support-page="X"> resolves to
// <this URL> + X. Trailing slash matters (URL concat is naive).
user_pref("app.support.baseURL", "https://anonymous.gratis/help/");

// The Tor/Mullvad-specific support-link helper used by some chrome.
user_pref("browser.base-browser-support-url", "https://anonymous.gratis/help/");

// Manual-update fallback and "what's in this update" prompts.
user_pref("app.update.url.manual",  "https://anonymous.gratis/download/");
user_pref("app.update.url.details", "https://anonymous.gratis/download/");

// "Share ideas" / feedback prompts.
user_pref("app.feedback.baseURL", "https://anonymous.gratis/feedback/");

// ----- Tor / .onion routing leak audit -----
//
// PAC routes *.onion -> Tor SOCKS5; rest is direct. These prefs
// close the surfaces that would bypass that policy, particularly
// for DNS / network probes that fire before any URL is loaded.

// DNS-over-HTTPS / TRR: would resolve names via Cloudflare or
// whatever third-party endpoint, bypassing SOCKS remote DNS.
// 5 = off (force OS resolver / SOCKS as appropriate).
user_pref("network.trr.mode", 5);
user_pref("network.trr.uri", "");
user_pref("doh-rollout.disable-heuristics", true);

// Captive-portal detection: pings detectportal.firefox.com on every
// new network. Leaks DNS + reveals Mozilla-shaped traffic pattern.
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);

// Geolocation, network-info, battery — passive fingerprint /
// physical-world deanonymizers. RFP already covers some of these,
// belt-and-suspenders.
user_pref("geo.enabled", false);
user_pref("geo.provider.use_gpsd", false);
user_pref("dom.network.enabled", false);
user_pref("dom.battery.enabled", false);

// Region update probes Mozilla's region service over the network.
user_pref("browser.region.update.enabled", false);
user_pref("browser.region.network.url", "");

// Allow .onion lookups (some Firefox builds block this at the
// resolver; we want them to flow through SOCKS).
user_pref("network.dns.blockDotOnion", false);

// ----- QUIC / HTTP/3 -----
//
// Tor SOCKS5 doesn't route UDP. If HTTP/3 negotiation succeeds, the
// browser will try to send QUIC packets directly over UDP — bypassing
// the SOCKS proxy and revealing the real IP. Disable HTTP/3 at the
// transport layer so the browser always falls back to TCP/HTTPS.
user_pref("network.http.http3.enable", false);
user_pref("network.http.http3.enabled", false);

// ----- Speculative connections -----
//
// Firefox preconnects to URLs the user might visit (link hover, autocomplete,
// search suggestions). Each preconnect is a real TCP+TLS handshake — over
// Tor that's another circuit; off-Tor it leaks intent. Hard-cap to zero.
user_pref("network.http.speculative-parallel-limit", 0);
user_pref("browser.urlbar.speculativeConnect.enabled", false);

// ----- Beacon / Push / Notifications -----
//
// Beacon: lets pages fire-and-forget POST on unload. Hard to audit,
// asynchronous, often used for tracking exfil.
// Push & Notifications: register a persistent endpoint with Mozilla's
// push service, then call out-of-band. No reason to expose these to
// untrusted content for at-risk users.
user_pref("beacon.enabled", false);
user_pref("dom.push.enabled", false);
user_pref("dom.push.connection.enabled", false);
user_pref("dom.webnotifications.enabled", false);
user_pref("dom.webnotifications.serviceworker.enabled", false);

// ----- Referrer policy -----
//
// 2 = send only origin (no path/query) on cross-origin; trim
// query strings off same-origin too. Mullvad ships strict-ish
// defaults; we go one step further.
user_pref("network.http.referer.XOriginPolicy", 2);          // 0 always, 1 same-base-domain, 2 strict same-origin
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);  // 2 = scheme+host+port only
user_pref("network.http.referer.trimmingPolicy", 2);

// ----- IDN punycode display -----
//
// Force the URL bar to render IDN hostnames as their xn-- punycode
// form. Defeats Unicode-homoglyph spoofing (Cyrillic 'а' vs Latin 'a',
// etc.) that would otherwise look identical in the location bar.
user_pref("network.IDN_show_punycode", true);

// ----- WebGPU / SharedArrayBuffer -----
//
// WebGPU: new fingerprintable surface (GPU adapter info, perf timing,
// compute shader artifacts). No legitimate need on an anonymity-first
// browser.
// SharedArrayBuffer outside cross-origin-isolated contexts gives pages
// a high-resolution timer (spectre + fingerprinting).
user_pref("dom.webgpu.enabled", false);
user_pref("javascript.options.shared_memory", false);

// ----- Device API surface (kill all of it) -----
//
// None of these have a legitimate use case for at-risk users. Every
// one of them is a fingerprinting vector and/or a deanonymizer.
user_pref("dom.webusb.enabled", false);
user_pref("dom.serial.enabled", false);
user_pref("dom.webhid.enabled", false);
user_pref("dom.webmidi.enabled", false);
user_pref("dom.webmidi.permission.disabled", true);
user_pref("dom.webxr.enabled", false);
user_pref("dom.vr.enabled", false);
user_pref("dom.gamepad.enabled", false);
user_pref("device.sensors.enabled", false);
user_pref("device.sensors.motion.enabled", false);
user_pref("device.sensors.orientation.enabled", false);
user_pref("device.sensors.proximity.enabled", false);
user_pref("device.sensors.ambientLight.enabled", false);

// ----- Client hints (passive fingerprinting headers) -----
//
// Sec-CH-UA*, Sec-CH-Width, Sec-CH-Platform, Sec-CH-Device-Memory…
// every header is a fingerprint bit volunteered to the server.
user_pref("network.http.network_info.enabled", false);

// ----- Clipboard surface -----
//
// dom.event.clipboardevents.enabled lets pages observe copy/cut/paste
// events on their own content — used by copy-jacking attacks (replace
// clipboard contents on paste). Off.
// dom.events.asyncClipboard.* exposes a JS API to read the clipboard
// programmatically. Off; user can still right-click → paste.
user_pref("dom.event.clipboardevents.enabled", false);
user_pref("dom.events.asyncClipboard.read", false);
user_pref("dom.events.asyncClipboard.clipboardItem", false);

// ----- PDF.js: no scripting -----
//
// PDFs can carry JS. PDF.js runs it inside the browser process.
// Disable; treat PDFs as static documents.
user_pref("pdfjs.enableScripting", false);
user_pref("pdfjs.enableXfa", false);

// ----- Cookie + state lifetime -----
//
// 2 = expire cookies at end of session. Combined with first-party
// isolation (Mullvad default), no cross-session linkability via
// cookies/localStorage/IDB.
user_pref("network.cookie.lifetimePolicy", 2);
user_pref("privacy.clearOnShutdown.cookies", true);
user_pref("privacy.clearOnShutdown.offlineApps", true);
user_pref("privacy.clearOnShutdown.cache", true);
user_pref("privacy.clearOnShutdown.sessions", true);
user_pref("privacy.clearOnShutdown.siteSettings", false);   // keep per-site perms (we want deny defaults)
user_pref("privacy.sanitize.sanitizeOnShutdown", true);

// ----- Tracking protection: strict -----
//
// Strict turns on all the Mozilla-curated blocking lists (trackers,
// social-media trackers, fingerprinters, cryptominers, redirect
// trackers) and full cross-site cookie partitioning.
user_pref("browser.contentblocking.category", "strict");
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("privacy.trackingprotection.fingerprinting.enabled", true);
user_pref("privacy.trackingprotection.cryptomining.enabled", true);
user_pref("privacy.partition.network_state", true);
user_pref("privacy.firstparty.isolate", true);

// ----- ResistFingerprinting (RFP) -----
//
// Spoofs timezone to UTC, rounds timer precision to 100ms, normalizes
// screen size with letterboxing, generic UA, blocks canvas readback
// without prompt, etc. Mullvad ships this on by default — re-affirm.
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.resistFingerprinting.letterboxing", true);
user_pref("privacy.resistFingerprinting.reduceTimerPrecision.microseconds", 100000);

// ----- Mozilla services: off across the board -----
//
// Pocket, Sync, account-related telemetry, studies/Normandy, crash
// reporter, recommendations. Each is a callout to Mozilla or a state
// surface we don't want.
user_pref("extensions.pocket.enabled", false);
user_pref("identity.fxaccounts.enabled", false);
user_pref("services.sync.engine.passwords", false);
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("browser.discovery.enabled", false);
user_pref("browser.crashReports.unsubmittedCheck.enabled", false);
user_pref("breakpad.reportURL", "");
user_pref("browser.tabs.crashReporting.sendReport", false);
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);
user_pref("extensions.getAddons.showPane", false);

// ----- Form autofill / saved logins / search suggestions -----
//
// No autofill (deanonymization via address book / payment card field
// inference). No search suggestions (every keystroke = request to
// search engine). No URL bar suggestions to typed-but-not-visited.
user_pref("signon.rememberSignons", false);
user_pref("signon.autofillForms", false);
user_pref("extensions.formautofill.addresses.enabled", false);
user_pref("extensions.formautofill.creditCards.enabled", false);
user_pref("browser.formfill.enable", false);
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);
user_pref("browser.urlbar.trending.featureGate", false);
user_pref("browser.urlbar.quicksuggest.enabled", false);
user_pref("browser.urlbar.suggest.quicksuggest.sponsored", false);

// ----- Permissions: deny by default -----
//
// Camera, mic, screen-share, geolocation, notifications: prompt at
// most; never auto-grant. (RFP already covers geo for fingerprint.)
user_pref("permissions.default.camera", 2);          // 2 = block
user_pref("permissions.default.microphone", 2);
user_pref("permissions.default.geo", 2);
user_pref("permissions.default.desktop-notification", 2);
user_pref("permissions.default.xr", 2);

// ----- Aesthetic: command-line dark theme -----
//
// Load userChrome.css / userContent.css from <profile>/chrome/ so the
// rest of the look-and-feel files in this directory take effect.
user_pref("toolkit.legacyUserProfileCustomizations.stylesheets", true);

// Force the bundled Firefox dark theme as the active theme. This is
// what paints the chrome before userChrome.css attaches, and prevents
// a flash of light UI on cold launch. The user can switch themes
// from about:addons; this is just the default.
user_pref("extensions.activeThemeID", "firefox-compact-dark@mozilla.org");

// Tell content the system uses a dark color scheme — pages that respect
// prefers-color-scheme get their dark mode automatically, matching the
// rest of the browser. 1 = dark, 0 = light.
user_pref("ui.systemUsesDarkTheme", 1);

// Override the content-side color-scheme to dark regardless of OS.
// 0 = dark, 1 = light, 2 = no-override, 3 = follow OS.
user_pref("layout.css.prefers-color-scheme.content-override", 0);
