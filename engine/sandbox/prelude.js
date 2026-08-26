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
// Events are POSTed to http://extdrift-report.invalid/e.  ".invalid" is reserved by
// RFC 2606 and never resolves, so the request always fails at DNS - but Chromium raises
// the CDP request event *before* it tries to connect, so the driver reads the payload
// off the outgoing request and the data never leaves the machine.  Using the network as
// the reporting channel is what lets one mechanism cover page scripts, content scripts
// in the isolated world, and the MV3 service worker, which has no DOM to hook at all.
//
// The driver strips every report request out of the trace before scoring, so the
// instrumentation cannot show up as extension behaviour.

(() => {
  "use strict";
  const globalScope = (typeof window !== "undefined") ? window : self;
  if (globalScope.__extdriftInstalled) return;
  globalScope.__extdriftInstalled = true;

  const REPORT_URL = "http://extdrift-report.invalid/e";
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
      if (!inServiceWorker && navigator.sendBeacon) {
        navigator.sendBeacon(REPORT_URL, body);
      } else if (nativeFetch) {
        nativeFetch(REPORT_URL, { method: "POST", body, mode: "no-cors", keepalive: true })
          .catch(() => {});
      }
    } catch (_) { /* instrumentation must never break the sample */ }
  };
  globalScope.__extdriftReport = report;

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
  // Wrapping the namespace objects in place works in both the isolated world and the
  // service worker, because this code is part of the extension's own bundle.
  const api = globalScope.chrome || globalScope.browser;
  if (api) {
    const watched = ["cookies", "tabs", "storage", "scripting", "webRequest", "downloads",
                     "history", "identity", "management", "runtime"];
    // Calls whose only effect is our own plumbing; wrapping them adds noise, not signal.
    const skip = new Set(["runtime.getURL", "runtime.id", "runtime.getManifest"]);

    for (const namespace of watched) {
      const target = api[namespace];
      if (!target || typeof target !== "object") continue;
      for (const method of Object.keys(target)) {
        const original = target[method];
        if (typeof original !== "function") continue;
        if (skip.has(`${namespace}.${method}`)) continue;
        try {
          target[method] = function (...args) {
            const channel = namespace === "cookies" || namespace === "storage"
              ? "storage" : "api";
            report({ channel, ts: now(), api: `chrome.${namespace}.${method}`,
                     arg_count: args.length });
            return original.apply(this, args);
          };
        } catch (_) { /* some namespaces are read-only; skip them */ }
      }
    }
  }
})();
