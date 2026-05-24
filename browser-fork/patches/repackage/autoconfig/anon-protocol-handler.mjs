// anon-protocol-handler.mjs — implements anon:// as a first-class
// URI scheme so the URL bar shows anon://… natively (the way Tor
// Browser shows .onion).
//
// STATUS (2026-05-23): designed + drafted, NOT YET WIRED.
//
// The current shipping path is the cosmetic URL-bar substitution in
// mozilla.cfg sections 6 + 6b (handleCommand override + setURI
// override + location-change listener). That layer works today and
// the URL bar correctly shows anon://… while the load actually fetches
// from the bridge.
//
// This protocol handler is the "do it properly" version. Activating
// it would:
//   1. Inline this file's contents into mozilla.cfg (or load via
//      ChromeUtils.import with a resource:// substitution).
//   2. Call registerAnonProtocol() at startup (after the import).
//   3. Simplify the handleCommand override to just call
//      openLinkIn(anonUrl) — Firefox handles the load natively
//      because anon:// is now a registered scheme.
//   4. Remove the cosmetic setURI override (no longer needed; URI
//      is genuinely anon:// at the channel layer).
//
// What's still uncertain before activating:
//   - Whether Firefox 140 ESR's docloader is fully happy with a JS-
//     implemented nsIChannel that doesn't inherit from BaseChannel.
//   - Whether the bridge HTML's inline `fetch('/api/fetch?…')` calls
//     are correctly mapped back to the bridge by the same-origin
//     resolution under anon://.
//   - Whether the channel needs to expose nsIHttpChannel (Firefox
//     sometimes QI-checks for it; we'd need to add the interface +
//     either implement HTTP methods or return inner channel info).
//
// Decision: ship the cosmetic patch (which works); leave this file
// here as future work. When activated and proven, the cosmetic
// layer in mozilla.cfg sections 6+6b can be deleted.
//
// Architecture:
//
//   Firefox sees a load of `anon://X.anon/path`
//      └── AnonProtocolHandler.newChannel(uri, loadInfo)
//             └── returns AnonChannel
//                    asyncOpen(listener):
//                      └── opens an HTTP channel to the bridge:
//                            - `anon://X.anon/`         → GET http://127.0.0.1:1081/?url=anon://X.anon/
//                            - `anon://X.anon/api/fetch?url=…` (subresource from the bridge HTML)
//                                                       → GET http://127.0.0.1:1081/api/fetch?url=…
//                            - anything else            → mapped 1:1 to the bridge URL with anonSpec preserved
//                      └── pipes bytes back to the listener
//                    Reports channel.URI as the original anon:// URI
//                    so the URL bar + dev-tools + history all show
//                    anon://… cleanly. No cosmetic URL-bar tricks
//                    needed.
//
// Loaded by mozilla.cfg via ChromeUtils.import-style component
// registration. Designed to be wholly chrome-JS — no native code,
// no rebuild of Firefox.

const { Services } = ChromeUtils.importESModule(
  "resource://gre/modules/Services.sys.mjs",
);

const ANON_BRIDGE_BASE = "http://127.0.0.1:1081";
const ANON_BRIDGE_ORIGIN = ANON_BRIDGE_BASE;

const debugLog = (msg) => {
  try { Cu.reportError("[anon-proto] " + msg); } catch {}
  try {
    const f = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
    f.initWithPath("/tmp/anon-debug.log");
    const s = Cc["@mozilla.org/network/file-output-stream;1"].createInstance(Ci.nsIFileOutputStream);
    s.init(f, 0x02 | 0x08 | 0x10, 0o644, 0);
    const line = "[" + new Date().toISOString() + "] [proto] " + msg + "\n";
    s.write(line, line.length);
    s.close();
  } catch {}
};

// Map an anon:// URI to the corresponding bridge URL.
//
// Root: anon://host/  → http://127.0.0.1:1081/?url=anon://host/
// API:  anon://host/api/fetch?url=…  → http://127.0.0.1:1081/api/fetch?url=…
//        (so inline JS in the bridge HTML can call its own API)
// Other: anon://host/path?q=…  → http://127.0.0.1:1081/?url=anon://host/path?q=…
const anonURIToBridgeURL = (anonURI) => {
  const host = anonURI.host || "";
  const pathQuery = anonURI.pathQueryRef || "/";
  // Inline-script subresource on the bridge HTML page: /api/fetch path
  // should round-trip to the bridge's same path so the page's fetch()
  // calls resolve correctly when same-origin against an anon:// page.
  if (pathQuery.startsWith("/api/fetch")) {
    return ANON_BRIDGE_ORIGIN + pathQuery;
  }
  // Top-level navigation: serve the bridge HTML with ?url= param.
  const anonSpec = "anon://" + host + pathQuery;
  return ANON_BRIDGE_ORIGIN + "/?url=" + encodeURIComponent(anonSpec);
};

// ---- AnonChannel: a custom nsIChannel that wraps an inner HTTP channel.
//
// The wrapper reports `URI` as the original anon:// URI so the
// browser's location/URL-bar/history all see anon://. Reads, writes,
// and lifecycle are forwarded to the inner HTTP channel, which
// actually fetches from the bridge.

class AnonChannel {
  constructor(anonURI, loadInfo) {
    this._anonURI = anonURI;
    this._originalAnonURI = anonURI;
    this._loadInfo = loadInfo;
    this._inner = null;
    this._listener = null;
    this._context = null;
    this._loadFlags = 0;
    this._status = Cr.NS_OK;
    this._contentType = "text/html";
    this._contentCharset = "UTF-8";
    this._contentLength = -1;
    this._notificationCallbacks = null;
    this._owner = null;
    this._isPending = false;
    this._securityInfo = null;
    this._contentDisposition = 0;
    this._contentDispositionFilename = "";
    this._contentDispositionHeader = "";
    // Required by Firefox to associate the load with a principal.
    this._loadGroup = null;
  }

  // ---- nsIRequest ----
  get name() { return this._anonURI.spec; }
  isPending() { return this._isPending; }
  get status() { return this._status; }
  cancel(reason) {
    this._status = reason;
    if (this._inner) try { this._inner.cancel(reason); } catch {}
  }
  suspend() { if (this._inner) try { this._inner.suspend(); } catch {} }
  resume()  { if (this._inner) try { this._inner.resume();  } catch {} }
  get loadGroup() { return this._loadGroup; }
  set loadGroup(v) { this._loadGroup = v; }
  get loadFlags() { return this._loadFlags; }
  set loadFlags(v) { this._loadFlags = v; }
  getTRRMode() { return Ci.nsIRequest.TRR_DEFAULT_MODE; }
  setTRRMode() {}

  // ---- nsIChannel ----
  get originalURI() { return this._originalAnonURI; }
  set originalURI(uri) { this._originalAnonURI = uri; }
  get URI() { return this._anonURI; }
  get owner() { return this._owner; }
  set owner(v) { this._owner = v; }
  get notificationCallbacks() { return this._notificationCallbacks; }
  set notificationCallbacks(v) {
    this._notificationCallbacks = v;
    if (this._inner) try { this._inner.notificationCallbacks = v; } catch {}
  }
  get securityInfo() { return this._securityInfo; }
  get contentType() { return this._contentType; }
  set contentType(v) { this._contentType = v; }
  get contentCharset() { return this._contentCharset; }
  set contentCharset(v) { this._contentCharset = v; }
  get contentLength() { return this._contentLength; }
  set contentLength(v) { this._contentLength = v; }
  get contentDisposition() { return this._contentDisposition; }
  get contentDispositionFilename() { return this._contentDispositionFilename; }
  get contentDispositionHeader() { return this._contentDispositionHeader; }
  get loadInfo() { return this._loadInfo; }
  set loadInfo(v) { this._loadInfo = v; }
  get isDocument() {
    return !!(this._loadInfo
      && this._loadInfo.externalContentPolicyType === Ci.nsIContentPolicy.TYPE_DOCUMENT);
  }
  get canceled() { return this._status !== Cr.NS_OK; }

  open() {
    // Synchronous open is rarely used by the modern doc-loader, but
    // implement enough to avoid throws when called.
    if (!this._inner) this._openInner();
    return this._inner.open();
  }

  asyncOpen(listener) {
    if (this._isPending) throw Cr.NS_ERROR_ALREADY_OPENED;
    this._listener = listener;
    this._isPending = true;
    this._openInner();
    // Wrap so onStart/onStop see THIS channel as the request (not the
    // inner HTTP channel); that's what tells Firefox + dev-tools that
    // the load is associated with the anon:// URI.
    const wrapperListener = {
      QueryInterface: ChromeUtils.generateQI(["nsIStreamListener", "nsIRequestObserver"]),
      onStartRequest: (req) => {
        try {
          // Copy useful response metadata onto ourselves.
          if (req instanceof Ci.nsIHttpChannel) {
            try { this._contentType   = req.contentType   || this._contentType; } catch {}
            try { this._contentCharset= req.contentCharset|| this._contentCharset; } catch {}
            try { this._contentLength = req.contentLength; } catch {}
          }
        } catch {}
        try { listener.onStartRequest(this); } catch (e) { debugLog("listener.onStartRequest threw: " + e); }
      },
      onStopRequest: (req, status) => {
        this._isPending = false;
        this._status = status;
        try { listener.onStopRequest(this, status); } catch (e) { debugLog("listener.onStopRequest threw: " + e); }
      },
      onDataAvailable: (req, stream, offset, count) => {
        try { listener.onDataAvailable(this, stream, offset, count); }
        catch (e) { debugLog("listener.onDataAvailable threw: " + e); }
      },
    };
    try {
      this._inner.asyncOpen(wrapperListener);
    } catch (e) {
      this._isPending = false;
      this._status = Cr.NS_ERROR_FAILURE;
      debugLog("inner.asyncOpen threw: " + e);
      throw e;
    }
  }

  _openInner() {
    if (this._inner) return;
    const bridgeURL = anonURIToBridgeURL(this._anonURI);
    debugLog("AnonChannel: " + this._anonURI.spec + " → " + bridgeURL);
    const bridgeURI = Services.io.newURI(bridgeURL);
    this._inner = Services.io.newChannelFromURIWithLoadInfo(bridgeURI, this._loadInfo);
    if (this._notificationCallbacks) {
      try { this._inner.notificationCallbacks = this._notificationCallbacks; } catch {}
    }
  }

  // ---- QI ----
  QueryInterface = ChromeUtils.generateQI([
    "nsIChannel", "nsIRequest",
  ]);
}

// ---- AnonProtocolHandler: nsIProtocolHandler for "anon" scheme ----

class AnonProtocolHandler {
  get scheme() { return "anon"; }
  get defaultPort() { return -1; }
  // URI_NORELATIVE — relative URLs (e.g. "/foo") are NOT resolved
  //   against an anon:// base on the client side; let the bridge HTML
  //   handle relative resolution. But within an anon:// page, the
  //   inline JS fetches /api/fetch which IS resolved relative to the
  //   anon:// origin — we map that back to the bridge in newChannel.
  // URI_LOADABLE_BY_ANYONE — any document can load anon:// URLs.
  // URI_DANGEROUS_TO_LOAD is NOT set; we want bookmarks, history,
  //   etc. to treat anon:// as ordinary content URLs.
  get protocolFlags() {
    return Ci.nsIProtocolHandler.URI_LOADABLE_BY_ANYONE
         | Ci.nsIProtocolHandler.URI_NON_PERSISTABLE;
  }
  allowPort() { return false; }
  newChannel(aURI, aLoadInfo) {
    debugLog("newChannel called for " + aURI.spec);
    return new AnonChannel(aURI, aLoadInfo);
  }
  QueryInterface = ChromeUtils.generateQI(["nsIProtocolHandler"]);
}

// ---- Component registration ----

const ANON_PROTOCOL_CID = Components.ID("{8d4f29b1-7c0e-4a8b-9e21-1a3b5c7d9e02}");
const ANON_PROTOCOL_CONTRACT = "@mozilla.org/network/protocol;1?name=anon";

const factory = {
  createInstance(iid) {
    return new AnonProtocolHandler().QueryInterface(iid);
  },
  QueryInterface: ChromeUtils.generateQI(["nsIFactory"]),
};

let registered = false;

export const registerAnonProtocol = () => {
  if (registered) {
    debugLog("registerAnonProtocol: already registered");
    return;
  }
  try {
    const registrar = Components.manager.QueryInterface(Ci.nsIComponentRegistrar);
    if (registrar.isCIDRegistered(ANON_PROTOCOL_CID)) {
      debugLog("registerAnonProtocol: CID already known");
      return;
    }
    registrar.registerFactory(
      ANON_PROTOCOL_CID,
      "Anon Layer Protocol Handler",
      ANON_PROTOCOL_CONTRACT,
      factory,
    );
    registered = true;
    debugLog("anon:// protocol handler registered (CID=" + ANON_PROTOCOL_CID + ")");
  } catch (e) {
    debugLog("registerAnonProtocol failed: " + (e.stack || e));
  }
};
