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
  // An https page blocks an http report as mixed content, so the scheme follows the page.
  const REPORT_SCHEME = (typeof location !== "undefined" && location.protocol === "https:")
    ? "https" : "http";
  const REPORT_URL = REPORT_SCHEME + "://extdrift-report.test/e";
  const dateNow = Date.now.bind(Date);
  const t0 = dateNow();
  const now = () => (dateNow() - t0) / 1000;

  const inServiceWorker = (typeof window === "undefined");
  // Which kind of JS context this is. The network path below treats anything that is not the
  // worker or a content script as generic "extension" code.
  const realm = (() => {
    if (inServiceWorker) return "service_worker";
    try {
      const proto = location.protocol;
      if (proto === "chrome-extension:" || proto === "moz-extension:") {
        const ns = globalScope.browser || globalScope.chrome;
        const isBackground = ns && ns.extension && ns.extension.getBackgroundPage
          && ns.extension.getBackgroundPage() === globalScope;
        return isBackground ? "background_page" : "extension_page";
      }
      const ns = globalScope.browser || globalScope.chrome;
      // No extension APIs in a web origin means page-world code (a MAIN-world or injected script).
      return (ns && ns.runtime && ns.runtime.id) ? "content_script" : "page_injected";
    } catch (_) { return "content_script"; }
  })();
  const frame = (realm === "service_worker" || realm === "content_script") ? realm
    : (realm === "page_injected" ? "content_script" : "extension");
  const realmId = realm + "-" + t0.toString(36) + "-" + Math.floor(Math.random() * 1e9).toString(36);
  let reportSeq = 0;

  // Grab natives now: if the extension later replaces them, reporting must not flow through
  // the extension's own wrappers.
  const nativeFetch = globalScope.fetch ? globalScope.fetch.bind(globalScope) : null;
  const nativeStringify = JSON.stringify;

  // Every report is kept so it can be sent again. A service worker starts while the
  // driver is still attaching its request listener, so the first events a worker emits
  // can be posted with nobody listening - which showed up as an MV3 listener
  // registration that appeared in some runs of an extension and not others, i.e. a
  // false difference between two runs of identical code. Re-posting the buffer twice
  // closes that window; the driver discards the duplicates by (realm_id, report_seq).
  const buffered = [];
  const MAX_BUFFERED = 500;

  const post = (body) => {
    // Prefer a plain fetch: it works from the service worker, the MV2 background page and
    // the content script alike. A content script drops a keepalive/no-cors report and a
    // sendBeacon, so those were losing every content-script dom/network event; a plain
    // POST (the same shape the payloads themselves use successfully) lands.
    if (nativeFetch) {
      nativeFetch(REPORT_URL, { method: "POST", body }).catch(() => {});
    } else if (!inServiceWorker && navigator.sendBeacon) {
      navigator.sendBeacon(REPORT_URL, body);
    }
  };

  const report = (event) => {
    try {
      event.frame = event.frame || frame;
      event.realm = realm;
      event.realm_id = realmId;
      event.report_seq = ++reportSeq;
      event.t_wall = dateNow();
      const body = nativeStringify(event);
      if (buffered.length < MAX_BUFFERED) buffered.push(body);
      post(body);
    } catch (_) { /* instrumentation must never break the sample */ }
  };

  const replay = () => { for (let i = 0; i < buffered.length; i++) post(buffered[i]); };
  try { setTimeout(replay, 2000); setTimeout(replay, 6000); } catch (_) {}
  globalScope.__extdriftReport = report;
  // Lets the collector know this realm really ran. A declared script that never says this was
  // not exercised, which is a very different finding from "exercised and did nothing".
  try {
    report({ channel: "meta", event: "realm_start", extended: true,
             page: (typeof location !== "undefined") ? location.origin + location.pathname : "" });
  } catch (_) {}

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

  try {
    const NativeWS = globalScope.WebSocket;
    if (NativeWS) {
      const WrappedWS = function (url, protocols) {
        report({ channel: "network", ts: now(), url: String(url), method: "WEBSOCKET", body_len: 0,
                 resource_type: "websocket", initiator: frame, extended: true });
        return protocols === undefined ? new NativeWS(url) : new NativeWS(url, protocols);
      };
      WrappedWS.prototype = NativeWS.prototype;
      for (const k of ["CONNECTING", "OPEN", "CLOSING", "CLOSED"]) WrappedWS[k] = NativeWS[k];
      globalScope.WebSocket = WrappedWS;
    }
    const NativeRTC = globalScope.RTCPeerConnection;
    if (NativeRTC) {
      const WrappedRTC = function (config) {
        const servers = (config && config.iceServers) || [];
        report({ channel: "network", ts: now(), url: "webrtc://peer", method: "WEBRTC", body_len: 0,
                 resource_type: "webrtc", initiator: frame, extended: true,
                 ice_server_count: servers.length });
        return new NativeRTC(config);
      };
      WrappedRTC.prototype = NativeRTC.prototype;
      globalScope.RTCPeerConnection = WrappedRTC;
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

  // Structural facts about a form field. Never its value.
  const formQuery = (typeof Element !== "undefined") ? Element.prototype.querySelector : null;
  const fieldMeta = (el) => {
    try {
      const form = el.form || (el.closest && el.closest("form")) || null;
      return { tag: (el.tagName || "").toLowerCase(), type: el.type || "", name: el.name || "",
               id: el.id || "", autocomplete: el.autocomplete || "",
               sensitive_mark: (el.dataset && el.dataset.sensitive) || "",
               form_id: form ? (form.id || "") : "",
               form_has_password: !!(form && formQuery && formQuery.call(form, "input[type=password]")) };
    } catch (_) { return {}; }
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
                   value_len: value ? String(value).length : 0, origin: location.origin,
                   field: fieldMeta(this) });
          return value;
        },
        set(value) { return descriptor.set.call(this, value); },
      });
    }

    const nativeAppend = Element.prototype.appendChild;
    Element.prototype.appendChild = function (node) {
      report({ channel: "dom", ts: now(), event: "inject", target: describe(node),
               origin: location.origin, node_tag: (node && node.tagName || "").toLowerCase() });
      return nativeAppend.call(this, node);
    };

    // Held now because the proxies installed below replace these globals.
    let realSessionStorage = null;
    try { realSessionStorage = globalScope.sessionStorage; } catch (_) {}
    const areaOf = (store) => (store === realSessionStorage ? "session_storage" : "local_storage");
    const nativeGetItem = Storage.prototype.getItem;
    Storage.prototype.getItem = function (key) {
      report({ channel: "storage", ts: now(), api: "localStorage.getItem",
               key: String(key), area: areaOf(this), operation: "read" });
      return nativeGetItem.call(this, key);
    };
    // Everything below is newer than the training data and flagged `extended`, so the legacy
    // features (and with them the trained model) keep their original meaning.
    const ext = (channel, fields) => report({ channel, ts: now(), extended: true, ...fields });
    const storageMethod = (method, operation) => {
      const native = Storage.prototype[method];
      Storage.prototype[method] = function (...args) {
        ext("storage", { api: "Storage." + method, area: areaOf(this), operation,
                         key: args.length ? String(args[0]) : "" });
        return native.apply(this, args);
      };
    };
    storageMethod("setItem", "write");
    storageMethod("removeItem", "delete");
    storageMethod("clear", "clear");
    storageMethod("key", "read");
    // localStorage.foo and localStorage["foo"] never reach getItem, so give this realm a proxy.
    for (const [prop, area] of [["localStorage", "local_storage"], ["sessionStorage", "session_storage"]]) {
      try {
        const real = globalScope[prop];
        const proxy = new Proxy(real, {
          get(target, key) {
            const value = Reflect.get(target, key, target);
            if (typeof value === "function") return value.bind(target);
            if (typeof key === "string" && key !== "length" && value !== undefined) {
              ext("storage", { api: "Storage.property", area, operation: "read", key });
            }
            return value;
          },
          set(target, key, value) {
            ext("storage", { api: "Storage.property", area, operation: "write", key: String(key) });
            target[key] = value;
            return true;
          },
          deleteProperty(target, key) {
            ext("storage", { api: "Storage.property", area, operation: "delete", key: String(key) });
            return delete target[key];
          },
        });
        Object.defineProperty(globalScope, prop, { configurable: true, get: () => proxy });
      } catch (_) {}
    }

    const SENSITIVE_SELECTOR = /password|passwd|pwd|login|signin|credit|card|cvv|cvc|otp|ssn|token|secret|csrf|account|hidden|email|username/i;
    const isSensitiveEl = (el) => {
      try {
        if (!el || !el.matches) return false;
        return el.matches("input[type=password],input[type=hidden],input[autocomplete*=cc-]," +
                          "input[autocomplete=one-time-code],input[autocomplete=username],form," +
                          "[data-sensitive]");
      } catch (_) { return false; }
    };
    const isFieldEl = (el) => { try { return !!el && /^(INPUT|TEXTAREA|SELECT|FORM)$/.test(el.tagName); }
                                catch (_) { return false; } };
    // Reads of ordinary nodes are far too frequent to report singly, so count them and send a
    // total periodically. Only reads touching a sensitive element are reported individually.
    let queryCount = 0, textReads = 0;
    setInterval(() => {
      if (queryCount || textReads) {
        ext("dom", { event: "activity_summary", target: "page", queries: queryCount, text_reads: textReads });
        queryCount = 0; textReads = 0;
      }
    }, 2000);
    const firstSensitive = (result) => {
      try {
        if (!result) return null;
        if (result.nodeType) return isSensitiveEl(result) ? result : null;
        const n = Math.min(result.length || 0, 50);
        for (let i = 0; i < n; i++) if (isSensitiveEl(result[i])) return result[i];
      } catch (_) {}
      return null;
    };
    const hookQuery = (proto, method) => {
      const native = proto && proto[method];
      if (!native) return;
      proto[method] = function (selector) {
        const result = native.apply(this, arguments);
        queryCount++;
        const hit = firstSensitive(result);
        if (hit || SENSITIVE_SELECTOR.test(String(selector))) {
          ext("dom", { event: "query", target: String(selector).slice(0, 120), method,
                       field: hit ? fieldMeta(hit) : undefined, origin: location.origin });
        }
        return result;
      };
    };
    for (const m of ["querySelector", "querySelectorAll", "getElementById", "getElementsByName",
                     "getElementsByTagName", "getElementsByClassName"]) {
      hookQuery(Document.prototype, m);
      hookQuery(Element.prototype, m);
    }
    const hookGetter = (proto, prop, onRead) => {
      const d = proto && Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.get) return;
      Object.defineProperty(proto, prop, { configurable: true, enumerable: d.enumerable, set: d.set,
        get() { const value = d.get.call(this); try { onRead(this, value); } catch (_) {} return value; } });
    };
    hookGetter(Document.prototype, "forms", () =>
      ext("dom", { event: "query", target: "document.forms", method: "forms", origin: location.origin }));
    hookGetter(HTMLFormElement.prototype, "elements", (form) =>
      ext("dom", { event: "query", target: describe(form), method: "form.elements",
                   field: fieldMeta(form), origin: location.origin }));
    for (const [proto, prop] of [[Node.prototype, "textContent"], [HTMLElement.prototype, "innerText"],
                                 [Element.prototype, "innerHTML"]]) {
      hookGetter(proto, prop, (el, value) => {
        textReads++;
        const mark = el.closest && el.closest("[data-sensitive]");
        if (mark || (el.tagName === "BODY" || el.tagName === "HTML") || el.tagName === "FORM") {
          ext("dom", { event: "text_read", target: describe(el), prop, origin: location.origin,
                       value_len: value ? String(value).length : 0,
                       field: mark ? fieldMeta(mark) : undefined });
        }
      });
    }
    const nativeGetAttr = Element.prototype.getAttribute;
    Element.prototype.getAttribute = function (name) {
      const value = nativeGetAttr.call(this, name);
      if (String(name).toLowerCase() === "value" && isFieldEl(this)) {
        ext("dom", { event: "attr_read", target: describe(this), origin: location.origin,
                     value_len: value ? String(value).length : 0, field: fieldMeta(this) });
      }
      return value;
    };
    const SENSITIVE_LISTENER = new Set(["keydown", "keypress", "keyup", "input", "change", "submit",
                                        "paste", "copy", "cut", "beforeinput", "formdata", "blur"]);
    const nativeAdd = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function (type, listener, options) {
      try {
        const onField = isFieldEl(this);
        const onRoot = this === document || this === globalScope || this === document.body;
        if (SENSITIVE_LISTENER.has(String(type)) && (onField || onRoot)) {
          ext("dom", { event: "listener", target: onField ? describe(this) : (this === document ? "document" : "window"),
                       listener_type: String(type), capture: !!(options === true || (options && options.capture)),
                       field: onField ? fieldMeta(this) : undefined, origin: location.origin });
        }
      } catch (_) {}
      return nativeAdd.call(this, type, listener, options);
    };
    const nativeCreate = Document.prototype.createElement;
    Document.prototype.createElement = function (tag) {
      const name = String(tag).toLowerCase();
      if (name === "script" || name === "iframe" || name === "embed" || name === "object") {
        ext("dom", { event: "element_created", target: name, origin: location.origin });
      }
      return nativeCreate.apply(this, arguments);
    };
    const modification = (kind, node, extra) => {
      const tag = (node && node.tagName || "").toLowerCase();
      ext("dom", { event: "modify", kind, node_tag: tag, target: node && node.tagName ? describe(node) : kind,
                   origin: location.origin, ...(extra || {}) });
    };
    for (const [proto, method] of [[Element.prototype, "append"], [Element.prototype, "prepend"],
                                   [Element.prototype, "before"], [Element.prototype, "after"],
                                   [Element.prototype, "replaceWith"], [Element.prototype, "insertAdjacentElement"],
                                   [Node.prototype, "insertBefore"], [Node.prototype, "replaceChild"]]) {
      const native = proto[method];
      if (!native) continue;
      proto[method] = function (...args) {
        const node = args.find((a) => a && a.nodeType === 1);
        modification(method, node || this);
        return native.apply(this, args);
      };
    }
    const hookHtmlSetter = (proto, prop) => {
      const d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.set) return;
      Object.defineProperty(proto, prop, { configurable: true, enumerable: d.enumerable, get: d.get,
        set(value) {
          const text = String(value);
          modification("html_set", this, { prop, html_len: text.length,
            contains_script: /<script|<iframe|\son\w+=/i.test(text),
            contains_form: /<form|<input/i.test(text) });
          return d.set.call(this, value);
        } });
    };
    hookHtmlSetter(Element.prototype, "innerHTML");
    hookHtmlSetter(Element.prototype, "outerHTML");
    const nativeAdjacent = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function (position, html) {
      const text = String(html);
      modification("html_set", this, { prop: "insertAdjacentHTML", html_len: text.length,
        contains_script: /<script|<iframe|\son\w+=/i.test(text),
        contains_form: /<form|<input/i.test(text) });
      return nativeAdjacent.call(this, position, html);
    };
    const nativeWrite = Document.prototype.write;
    Document.prototype.write = function (...args) {
      modification("document_write", null, { html_len: args.join("").length });
      return nativeWrite.apply(this, args);
    };
    const WATCHED_ATTRS = new Set(["src", "href", "action", "formaction", "onclick", "onsubmit", "onload", "value"]);
    const nativeSetAttr = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function (name, value) {
      const lowered = String(name).toLowerCase();
      if (WATCHED_ATTRS.has(lowered)) {
        modification(isFieldEl(this) && lowered !== "value" ? "form_attribute" : "attribute", this, { attribute: lowered });
      }
      return nativeSetAttr.call(this, name, value);
    };
    const hookPropSetter = (proto, prop, kind) => {
      const d = proto && Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.set) return;
      Object.defineProperty(proto, prop, { configurable: true, enumerable: d.enumerable, get: d.get,
        set(value) { modification(kind, this, { attribute: prop }); return d.set.call(this, value); } });
    };
    hookPropSetter(HTMLFormElement.prototype, "action", "form_attribute");
    hookPropSetter(HTMLScriptElement.prototype, "src", "attribute");
    hookPropSetter(HTMLIFrameElement.prototype, "src", "attribute");
    const nativeSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function () {
      ext("dom", { event: "form_submit_call", target: describe(this), field: fieldMeta(this), origin: location.origin });
      return nativeSubmit.call(this);
    };
    const NativeFormData = globalScope.FormData;
    if (NativeFormData) {
      globalScope.FormData = class extends NativeFormData {
        constructor(form, submitter) {
          if (form) ext("dom", { event: "form_data_read", target: describe(form), field: fieldMeta(form), origin: location.origin });
          if (form && submitter) super(form, submitter); else if (form) super(form); else super();
        }
      };
    }
    try {
      const clip = navigator.clipboard;
      if (clip) {
        for (const m of ["readText", "read"]) {
          if (!clip[m]) continue;
          const native = clip[m].bind(clip);
          clip[m] = function () { ext("dom", { event: "clipboard_read", target: "navigator.clipboard", origin: location.origin }); return native(); };
        }
      }
    } catch (_) {}
  }

  // These exist in workers as well as pages.
  const extAny = (channel, fields) => report({ channel, ts: now(), extended: true, ...fields });
  try {
    if (globalScope.IDBFactory && IDBFactory.prototype.open) {
      const nativeOpen = IDBFactory.prototype.open;
      IDBFactory.prototype.open = function (name) {
        extAny("storage", { api: "indexedDB.open", area: "indexeddb", operation: "open", key: String(name) });
        return nativeOpen.apply(this, arguments);
      };
    }
    if (globalScope.IDBObjectStore) {
      const ops = { get: "read", getAll: "read", getAllKeys: "read", openCursor: "read",
                    put: "write", add: "write", delete: "delete", clear: "clear" };
      for (const [m, operation] of Object.entries(ops)) {
        const native = IDBObjectStore.prototype[m];
        if (!native) continue;
        IDBObjectStore.prototype[m] = function (...args) {
          extAny("storage", { api: "IDBObjectStore." + m, area: "indexeddb", operation, key: String(this.name) });
          return native.apply(this, args);
        };
      }
    }
    const store = globalScope.cookieStore;
    if (store) {
      for (const [m, operation] of [["get", "read"], ["getAll", "read"], ["set", "write"], ["delete", "delete"]]) {
        const native = store[m] && store[m].bind(store);
        if (!native) continue;
        store[m] = function (...args) {
          const a = args[0];
          extAny("storage", { api: "cookieStore." + m, area: "cookie", operation,
                              key: typeof a === "string" ? a : (a && a.name) || "" });
          return native(...args);
        };
      }
    }
  } catch (_) {}

  // ---- Extension API channel -----------------------------------------------------
  // Wrapping the namespace objects in place works in the isolated world, the service
  // worker and the MV2 background page, because this code is part of the extension's own
  // bundle. Firefox exposes BOTH `browser.*` (promise-based) and `chrome.*` (callback)
  // as distinct wrapper objects, so we wrap each distinct namespace object we find, or a
  // browser.* call slips past a chrome.*-only hook.
  const watched = ["cookies", "tabs", "storage", "scripting", "webRequest",
                   "declarativeNetRequest", "downloads", "history", "identity",
                   "management", "runtime"];
  // Namespaces the training data's instrumentation did not watch; their events are `extended`.
  const watchedExtended = ["action", "alarms", "bookmarks", "browserAction", "browsingData",
                           "contentSettings", "contextMenus", "debugger", "desktopCapture", "dns",
                           "extension", "idle", "notifications", "offscreen", "pageAction",
                           "pageCapture", "permissions", "privacy", "proxy", "sessions", "tabCapture",
                           "tabGroups", "topSites", "userScripts", "webNavigation", "windows"];
  const skip = new Set(["runtime.getURL", "runtime.id", "runtime.getManifest", "extension.getURL",
                        "extension.getBackgroundPage"]);
  // Parameter metadata. Keys and well-known identifying fields only, never stored values.
  const SAFE_FIELDS = new Set(["url", "urls", "domain", "name", "path", "file", "files", "id",
                               "tabId", "world", "origins", "permissions", "active", "currentWindow",
                               "storeId", "periodInMinutes", "delayInMinutes"]);
  const summariseValue = (value) => {
    if (typeof value === "string") return value.slice(0, 160);
    if (typeof value === "number" || typeof value === "boolean") return value;
    if (Array.isArray(value)) return value.slice(0, 8).map((v) => typeof v === "string" ? v.slice(0, 80) : typeof v);
    return typeof value;
  };
  const summariseArgs = (namespace, args) => {
    try {
      return args.slice(0, 3).map((arg) => {
        if (arg === null || arg === undefined) return String(arg);
        if (typeof arg === "function") return "function";
        if (typeof arg === "string") return namespace === "storage" ? "key:" + arg.slice(0, 80) : arg.slice(0, 160);
        if (Array.isArray(arg)) return { array_len: arg.length, strings: arg.slice(0, 8).filter((v) => typeof v === "string").map((v) => v.slice(0, 80)) };
        if (typeof arg !== "object") return typeof arg;
        const out = { keys: Object.keys(arg).slice(0, 16) };
        // A storage value is the extension's data, so only its key names are kept.
        if (namespace !== "storage") {
          for (const k of out.keys) if (SAFE_FIELDS.has(k)) out[k] = summariseValue(arg[k]);
        }
        return out;
      });
    } catch (_) { return []; }
  };
  const channelFor = (namespace) => (namespace === "cookies" || namespace === "storage") ? "storage" : "api";

  const wrapMethod = (target, method, label, namespace, extended) => {
    const original = target[method];
    if (typeof original !== "function") return;
    if (skip.has(`${namespace}.${method}`)) return;
    try {
      target[method] = function (...args) {
        const event = { channel: channelFor(namespace), ts: now(), api: label, arg_count: args.length,
                        args: summariseArgs(namespace, args) };
        if (extended) event.extended = true;
        report(event);
        return original.apply(this, args);
      };
    } catch (_) { /* some namespaces are read-only; skip them */ }
  };
  // chrome.runtime.onMessage and friends: subscribing to an event is behaviour too, and an object
  // whose only members are addListener & co would otherwise be invisible.
  const wrapEvent = (eventObject, label, namespace) => {
    if (!eventObject || typeof eventObject.addListener !== "function") return false;
    const original = eventObject.addListener;
    try {
      eventObject.addListener = function (...args) {
        report({ channel: "api", ts: now(), api: label + ".addListener", arg_count: args.length,
                 args: summariseArgs(namespace, args.slice(1)), extended: true });
        return original.apply(this, args);
      };
    } catch (_) {}
    return true;
  };
  const STORAGE_AREA_METHODS = ["get", "set", "remove", "clear", "getBytesInUse", "getKeys", "setAccessLevel"];
  const wrapNested = (target, rootName, namespace) => {
    for (const key of Object.keys(target)) {
      let value;
      try { value = target[key]; } catch (_) { continue; }
      if (!value || typeof value !== "object") continue;
      const label = `${rootName}.${namespace}.${key}`;
      if (wrapEvent(value, label, namespace)) continue;
      if (namespace === "storage") {
        for (const m of STORAGE_AREA_METHODS) wrapMethod(value, m, `${label}.${m}`, namespace, true);
        wrapEvent(value.onChanged, `${label}.onChanged`, namespace);
      }
    }
  };
  const wrapNamespaces = (root, rootName) => {
    if (!root) return;
    for (const [list, extended] of [[watched, false], [watchedExtended, true]]) {
      for (const namespace of list) {
        let target;
        try { target = root[namespace]; } catch (_) { continue; }
        if (!target || typeof target !== "object" || target.__extdriftWrapped) continue;
        try { Object.defineProperty(target, "__extdriftWrapped", { value: true }); } catch (_) {}
        wrapNested(target, rootName, namespace);
        for (const method of Object.keys(target)) {
          wrapMethod(target, method, `${rootName}.${namespace}.${method}`, namespace, extended);
        }
      }
    }
  };
  // Wrap chrome first; wrap browser only if it is a *different* object (dedupe the alias).
  wrapNamespaces(globalScope.chrome, "chrome");
  if (globalScope.browser && globalScope.browser !== globalScope.chrome) {
    wrapNamespaces(globalScope.browser, "browser");
  }
})();
