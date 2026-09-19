// extdrift instrumentation prelude.
//
// This file is prepended to every JavaScript file of the *analysed copy* of an
// extension (see engine/sandbox/rewrite.py).  Prepending rather than injecting solves
// the isolated-world problem: Chromium runs content scripts in a separate JS world with
// its own prototype wrappers, so a hook installed from the page cannot see them.  Code
// that is part of the extension's own bundle runs in whatever world the extension runs
// in, and patches the wrappers that extension actually uses.
//
// REPORTING CHANNEL
// -----------------
// Events are POSTed to http://extdrift-report.test/e. Chromium dead-maps this host and
// reads the payload off the CDP request event before it connects; the Firefox capture
// proxy serves it and absorbs the payload. A reserved .test host (not .invalid) is used
// because a Firefox content script will send to .test but refuses the .invalid TLD.
// Either way the data never leaves the machine. Using the network as the reporting
// channel is what lets one mechanism cover page scripts, content scripts in the isolated
// world, and the MV3 service worker, which has no DOM to hook at all.
//
// The driver strips every report request out of the trace before scoring, so the
// instrumentation cannot show up as extension behaviour.

(() => {
  "use strict";
  // Use the CURRENT realm's global, not window. In a Firefox content script `window` is the
  // page's Xray-wrapped window, whose fetch/XHR is a different function from the one the
  // content-script code (and any payload) actually calls; hooking it captured nothing and
  // our own reports went out through the page realm (CORS-blocked). globalThis is the
  // content-script sandbox global in a content script, `self` in a worker, and window in a
  // page — always the realm where this code runs.
  const globalScope = (typeof globalThis !== "undefined") ? globalThis
                    : ((typeof self !== "undefined") ? self : window);
  if (globalScope.__extdriftInstalled) return;
  globalScope.__extdriftInstalled = true;

  // Report over a reserved .test host, not .invalid: a Firefox content script will send to
  // a .test host (which the capture proxy serves) but refuses the .invalid TLD, so
  // content-script dom/network events were being lost. The Chromium engine dead-maps this
  // host and reads the payload off the CDP request event, so it still never leaves the box.
  const REPORT_URL = "http://extdrift-report.test/e";
  const t0 = Date.now();
  const now = () => (Date.now() - t0) / 1000;

  const inServiceWorker = (typeof window === "undefined");
  const frame = inServiceWorker ? "service_worker" : "content_script";

  // Grab the native fetch now: if the extension later replaces window.fetch, reporting
  // must not start flowing through the extension's own wrapper.
  const nativeFetch = globalScope.fetch ? globalScope.fetch.bind(globalScope) : null;

  const report = (event) => {
    try {
      event.frame = event.frame || frame;
      const body = JSON.stringify(event);
      // Prefer a plain fetch: it works from the service worker, the MV2 background page and
      // the content script alike. A content script drops a keepalive/no-cors report and a
      // sendBeacon, so those were losing every content-script dom/network event; a plain
      // POST (the same shape the payloads themselves use successfully) lands.
      if (nativeFetch) {
        nativeFetch(REPORT_URL, { method: "POST", body }).catch(() => {});
      } else if (!inServiceWorker && navigator.sendBeacon) {
        navigator.sendBeacon(REPORT_URL, body);
      }
    } catch (_) { /* instrumentation must never break the sample */ }
  };
  globalScope.__extdriftReport = report;

  // ---- Network channel (self-reported) -------------------------------------------
  // On Chromium the driver reads outbound requests off CDP, so the prelude need not
  // report them. Firefox/Selenium exposes no such hook, so here the extension's own
  // fetch / XHR / sendBeacon calls report themselves. The Chromium report absorber
  // ignores channel:"network", so this never double-counts there. We hook the PUBLIC
  // APIs (grabbing the natives first) and always skip the reporting URL to avoid
  // recursion; the underlying call is left untouched so the sample behaves normally.
  const isReportUrl = (u) => typeof u === "string" && u.indexOf("extdrift-report.test") !== -1;
  const bodyLenOf = (b) => {
    try {
      if (!b) return 0;
      if (typeof b === "string") return b.length;
      if (b.byteLength != null) return b.byteLength;   // ArrayBuffer / TypedArray
      if (b.size != null) return b.size;                // Blob / FormData-ish
    } catch (_) {}
    return 0;
  };
  const reportNet = (url, method, bodyLen, kind) => {
    const s = String(url || "");
    if (isReportUrl(s)) return;
    // Only external http(s) egress is behaviour we score; skip the extension's own
    // internal loads (moz-extension:/chrome-extension:, relative paths, data:/blob:).
    if (!/^https?:\/\//i.test(s)) return;
    try {
      report({ channel: "network", ts: now(), url: s,
               method: String(method || "GET").toUpperCase(), body_len: bodyLen | 0,
               resource_type: kind || "xhr", initiator: frame });
    } catch (_) {}
  };

  if (nativeFetch) {
    globalScope.fetch = function (input, init) {
      try {
        const url = (typeof input === "string") ? input : (input && input.url) || "";
        const method = (init && init.method) || (input && input.method) || "GET";
        reportNet(url, method, bodyLenOf(init && init.body), "fetch");
      } catch (_) {}
      return nativeFetch(input, init);
    };
  }
  try {
    const XHR = globalScope.XMLHttpRequest;
    if (XHR && XHR.prototype) {
      const nativeOpen = XHR.prototype.open, nativeSend = XHR.prototype.send;
      XHR.prototype.open = function (method, url) {
        this.__extdriftMethod = method; this.__extdriftUrl = url;
        return nativeOpen.apply(this, arguments);
      };
      XHR.prototype.send = function (bodyArg) {
        reportNet(this.__extdriftUrl, this.__extdriftMethod, bodyLenOf(bodyArg), "xhr");
        return nativeSend.apply(this, arguments);
      };
    }
  } catch (_) {}
  try {
    if (globalScope.navigator && navigator.sendBeacon) {
      const nativeBeacon = navigator.sendBeacon.bind(navigator);
      navigator.sendBeacon = function (url, data) {
        reportNet(url, "POST", bodyLenOf(data), "beacon");
        return nativeBeacon(url, data);
      };
    }
  } catch (_) {}

  const describe = (el) => {
    try {
      if (!el || !el.tagName) return "unknown";
      const tag = el.tagName.toLowerCase();
      if (el.id) return `${tag}#${el.id}`;
      if (el.name) return `${tag}[name=${el.name}]`;
      if (el.type) return `${tag}[type=${el.type}]`;
      if (typeof el.className === "string" && el.className.trim()) {
        return `${tag}.${el.className.trim().split(/\s+/)[0]}`;
      }
      return tag;
    } catch (_) {
      return "unknown";
    }
  };

  // ---- DOM channel (content scripts only; a service worker has no DOM) ------------
  if (!inServiceWorker && typeof Document !== "undefined") {
    const cookieDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");
    if (cookieDescriptor && cookieDescriptor.get) {
      Object.defineProperty(document, "cookie", {
        configurable: true,
        get() {
          const value = cookieDescriptor.get.call(document);
          report({ channel: "dom", ts: now(), event: "read", target: "document.cookie",
                   value_len: value ? value.length : 0, origin: location.origin });
          return value;
        },
        set(value) {
          report({ channel: "dom", ts: now(), event: "write", target: "document.cookie",
                   value_len: value ? String(value).length : 0, origin: location.origin });
          return cookieDescriptor.set.call(document, value);
        },
      });
    }

    for (const ctor of [HTMLInputElement, HTMLTextAreaElement, HTMLSelectElement]) {
      const descriptor = Object.getOwnPropertyDescriptor(ctor.prototype, "value");
      if (!descriptor || !descriptor.get) continue;
      Object.defineProperty(ctor.prototype, "value", {
        configurable: true,
        get() {
          const value = descriptor.get.call(this);
          report({ channel: "dom", ts: now(), event: "read", target: describe(this),
                   value_len: value ? String(value).length : 0, origin: location.origin });
          return value;
        },
        set(value) { return descriptor.set.call(this, value); },
      });
    }

    const nativeAppend = Element.prototype.appendChild;
    Element.prototype.appendChild = function (node) {
      report({ channel: "dom", ts: now(), event: "inject", target: describe(node),
               origin: location.origin });
      return nativeAppend.call(this, node);
    };

    const nativeGetItem = Storage.prototype.getItem;
    Storage.prototype.getItem = function (key) {
      report({ channel: "storage", ts: now(), api: "localStorage.getItem",
               key: String(key) });
      return nativeGetItem.call(this, key);
    };
  }

  // ---- Extension API channel -----------------------------------------------------
  // Wrapping the namespace objects in place works in the isolated world, the service
  // worker and the MV2 background page, because this code is part of the extension's own
  // bundle. Firefox exposes BOTH `browser.*` (promise-based) and `chrome.*` (callback)
  // as distinct wrapper objects, so we wrap each distinct namespace object we find, or a
  // browser.* call slips past a chrome.*-only hook.
  const watched = ["cookies", "tabs", "storage", "scripting", "webRequest",
                   "declarativeNetRequest", "downloads", "history", "identity",
                   "management", "runtime"];
  const skip = new Set(["runtime.getURL", "runtime.id", "runtime.getManifest"]);
  const wrapNamespaces = (root, rootName) => {
    if (!root) return;
    for (const namespace of watched) {
      const target = root[namespace];
      if (!target || typeof target !== "object" || target.__extdriftWrapped) continue;
      try { Object.defineProperty(target, "__extdriftWrapped", { value: true }); } catch (_) {}
      for (const method of Object.keys(target)) {
        const original = target[method];
        if (typeof original !== "function") continue;
        if (skip.has(`${namespace}.${method}`)) continue;
        try {
          target[method] = function (...args) {
            const channel = (namespace === "cookies" || namespace === "storage")
              ? "storage" : "api";
            report({ channel, ts: now(), api: `${rootName}.${namespace}.${method}`,
                     arg_count: args.length });
            return original.apply(this, args);
          };
        } catch (_) { /* some namespaces are read-only; skip them */ }
      }
    }
  };
  // Wrap chrome first; wrap browser only if it is a *different* object (dedupe the alias).
  wrapNamespaces(globalScope.chrome, "chrome");
  if (globalScope.browser && globalScope.browser !== globalScope.chrome) {
    wrapNamespaces(globalScope.browser, "browser");
  }
})();
