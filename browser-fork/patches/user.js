// user.js overrides for Mullvad Browser when running on anon-layer.
//
// Drop this in your Mullvad Browser profile directory:
//   Linux:   ~/.mullvad/firefox/<profile>/user.js
//   macOS:   ~/Library/Application Support/Mullvad Browser/<profile>/user.js
//   Windows: %APPDATA%\Mullvad Browser\Profiles\<profile>\user.js
//
// Most settings here are duplicates of what `policies.json` enforces
// at the distribution level. user.js is for per-profile tweaking.

// ----- Proxy -----

user_pref("network.proxy.type", 1);              // 1 = manual
user_pref("network.proxy.socks", "127.0.0.1");
user_pref("network.proxy.socks_port", 1080);
user_pref("network.proxy.socks_version", 5);
user_pref("network.proxy.socks_remote_dns", false);
//
// `socks_remote_dns = false` means hostname resolution happens
// CLIENT-SIDE (DNS leaks to your OS resolver). This is the v0.2
// reference's current behaviour anyway. To minimise leak risk,
// browse only IP-literal destinations or `.anon` URLs (no DNS
// resolution needed).

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

// ----- Disable safe-browsing lookups (would leak URL hashes to Google) -----

user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
//
// NOTE: Disabling Safe Browsing trades phishing protection for a
// "no Google" property. Mullvad Browser users have to make this
// tradeoff explicitly; we default to "off" because most anon-layer
// users care about no-network-leak-to-Google more than phishing
// protection.

// ----- Disable system-clock / telemetry pings -----

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

// ----- Disable update channel (we want operator-controlled updates) -----

user_pref("app.update.enabled", false);
user_pref("app.update.auto", false);
//
// NOTE: In a properly-maintained fork, replace this with our own
// update URL. As a Mullvad-Browser-overlay user, you take updates
// from Mullvad on their normal schedule.

// ----- New-tab page = blank (no telemetry, no recommended sites) -----

user_pref("browser.newtabpage.enabled", false);
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);
