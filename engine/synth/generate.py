"""Synthetic corpus generator — the honest "synthetic weaponisation" dataset.

Why this exists
---------------
No public labelled dataset of malicious extension *update pairs* exists (see
docs/research/FEASIBILITY_AND_NOVELTY_PART2.md §7), so we construct our own. This module
generates schema-valid trace *pairs* (a trusted baseline v1 and a candidate v2 of the same
synthetic extension) at scale, without needing a live browser for every row — which lets us
train and cross-validate the ML tier now. Real extensions are also run through the live
pipeline (engine/sandbox), which is the "real-pipeline validation" that grounds the
synthetic distribution.

What makes the task *hard* (so ML is actually justified, not just a threshold)
------------------------------------------------------------------------------
The earlier version was too clean — a single rule separated the classes, so the model had
nothing to learn. This version injects deliberate **overlap and noise**:

* **Count jitter** — every feature varies run-to-run, so no threshold is crisp.
* **Hard-benign updates** — benign versions that add a new third-party host, a new
  permission, or a small analytics POST. They *look* like exfiltration but are benign, so a
  naive rule false-positives on them.
* **Stealth-malicious updates** — attacks that do *not* escalate a permission, exfiltrate a
  *small* payload, or beacon to a host that looks like a CDN. A naive rule misses them.
* **The label lives in the delta, not the counts** — a password-manager persona reads
  passwords in both versions, so that alone is never the signal.

The result: rules score well but with real false positives and misses, and a model that
*combines* features does better — which is the honest case for ML. Everything is SYNTHETIC
and clearly labelled; hosts use the reserved `.test` TLD.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

from engine.features.schema import empty_trace

# --------------------------------------------------------------------------------------
# Personas — a benign extension "shape" that both v1 and v2 share
# --------------------------------------------------------------------------------------

PERSONAS = {
    "reader":    {"own": "readerapi.test",    "perms": ["storage", "activeTab", "scripting"],
                  "reads": ["article.main", "div.content"], "identity": 0, "credential": 0,
                  "injects": 1, "pages": ["demo-news.test", "blog.test"]},
    "shopper":   {"own": "shopassist.test",   "perms": ["storage", "activeTab"],
                  "reads": ["span.price", "div.product"], "identity": 0, "credential": 0,
                  "injects": 1, "pages": ["shop-demo.test", "market.test"]},
    "contacts":  {"own": "contactfinder.test", "perms": ["storage", "activeTab"],
                  "reads": ["span.contact-email", "td.contact-name"], "identity": 2, "credential": 0,
                  "injects": 1, "pages": ["webmail.test", "crm-demo.test"]},
    "passmgr":   {"own": "vaultkeep.test",    "perms": ["storage", "activeTab", "scripting"],
                  "reads": ["article.main"], "identity": 1, "credential": 2,
                  "injects": 1, "pages": ["demo-bank.test", "portal.test"]},
    "weather":   {"own": "weathernow.test",   "perms": ["storage", "geolocation"],
                  "reads": ["div.forecast"], "identity": 0, "credential": 0,
                  "injects": 1, "pages": ["news.test", "portal.test"]},
    "translate": {"own": "quicktranslate.test", "perms": ["storage", "activeTab", "scripting"],
                  "reads": ["p.text", "div.article-body"], "identity": 0, "credential": 0,
                  "injects": 2, "pages": ["blog.test", "wiki-demo.test"]},
    "adblocker": {"own": "blockwell.test",    "perms": ["storage", "declarativeNetRequest", "scripting"],
                  "reads": ["div.ad-slot"], "identity": 0, "credential": 0,
                  "injects": 3, "pages": ["news.test", "blog.test"]},
    "coupon":    {"own": "couponcloud.test",  "perms": ["storage", "activeTab", "tabs"],
                  "reads": ["span.price", "div.cart"], "identity": 0, "credential": 0,
                  "injects": 2, "pages": ["shop-demo.test", "market.test"]},
    "screenshot":{"own": "snapshot.test",     "perms": ["storage", "activeTab", "downloads"],
                  "reads": ["body"], "identity": 0, "credential": 0,
                  "injects": 1, "pages": ["portal.test", "wiki-demo.test"]},
    "notes":     {"own": "quicknotes.test",   "perms": ["storage"],
                  "reads": ["div.content"], "identity": 0, "credential": 0,
                  "injects": 1, "pages": ["blog.test", "wiki-demo.test"]},
    "dictionary":{"own": "worddefine.test",   "perms": ["storage", "activeTab", "scripting"],
                  "reads": ["p.text"], "identity": 0, "credential": 0,
                  "injects": 2, "pages": ["wiki-demo.test", "news.test"]},
    "videohelper":{"own": "vidboost.test",    "perms": ["storage", "activeTab", "webNavigation"],
                  "reads": ["video", "div.player"], "identity": 0, "credential": 0,
                  "injects": 2, "pages": ["media-demo.test", "portal.test"]},
}

PAYLOAD_FAMILIES = (
    "cookie_theft", "credential_theft", "sw_beacon", "ad_affiliate",
    "keylogger", "history_exfil", "form_jacking", "redirect_hijack", "clipboard_steal",
)


# --------------------------------------------------------------------------------------
# Event helpers
# --------------------------------------------------------------------------------------

def _net(ts, url, method="GET", initiator="page", rtype="xhr", body_len=0):
    return {"ts": round(ts, 2), "url": url, "method": method, "initiator": initiator,
            "resource_type": rtype, "body_len": int(body_len)}


def _dom(ts, event, target, value_len=0, origin="https://demo.test"):
    return {"ts": round(ts, 2), "event": event, "target": target,
            "value_len": int(value_len), "origin": origin}


def _sto(ts, api, count=1):
    return {"ts": round(ts, 2), "api": api, "count": int(count)}


def _api(ts, api, frame="service_worker"):
    return {"ts": round(ts, 2), "api": api, "frame": frame}


def _base_trace(persona_key, ext_id, name, version, rng, browser="chromium"):
    """A benign baseline trace for a persona, with per-run jitter so nothing is crisp."""
    p = PERSONAS[persona_key]
    pages = [f"https://{h}/" for h in p["pages"]]
    tr = empty_trace(ext_id, name, version, browser=browser, scenario=f"persona-{persona_key}")
    tr["run"]["pages"] = pages
    tr["run"]["replay_bundle"] = f"synthetic-{persona_key}"
    tr["manifest"] = {
        "manifest_version": 3, "name": name, "version": version,
        "permissions": list(p["perms"]), "host_permissions": ["<all_urls>"],
        "background": {"service_worker": "sw.js"},
    }
    t = 0.4
    origin = f"https://{p['pages'][0]}"
    for h in p["pages"]:
        tr["network"].append(_net(t, f"https://{h}/", initiator="page", rtype="document"))
        t += rng.uniform(0.3, 0.8)
    # own-API config fetch (jittered count of first-party calls)
    for _ in range(rng.randint(1, 2)):
        tr["network"].append(_net(t, f"https://{p['own']}/v1/config", initiator="extension"))
        t += 0.3
    for sel in p["reads"]:
        for _ in range(rng.randint(1, 3)):                       # jitter: how much it reads
            tr["dom"].append(_dom(t, "read", sel, rng.randint(200, 3000), origin))
            t += 0.15
    for _ in range(p["identity"]):
        tr["dom"].append(_dom(t, "read", "span.contact-email", rng.randint(12, 40), origin))
        t += 0.12
    for _ in range(p["credential"]):
        tr["dom"].append(_dom(t, "read", "input#password", rng.randint(8, 20), origin))
        t += 0.12
    for i in range(p["injects"] + rng.randint(0, 1)):            # jitter: injected nodes
        tr["dom"].append(_dom(t, "inject", f"div.ext-ui-{i}", 0, origin))
        t += 0.12
    tr["storage"].append(_sto(0.8, "chrome.storage.local.get", rng.randint(1, 4)))
    tr["storage"].append(_sto(t, "chrome.storage.local.set", rng.randint(1, 2)))
    tr["api"] += [
        _api(0.7, "chrome.runtime.onInstalled"),
        _api(0.8, "chrome.storage.local.get"),
        _api(1.0, "chrome.scripting.executeScript"),
        _api(t, "chrome.storage.local.set"),
    ]
    # Baseline component IPC every extension has (popup/content <-> service worker). Present
    # in BOTH versions so it cancels in the delta; the signal is the *extra* hops an update
    # adds, not the mere presence of messaging.
    for _ in range(rng.randint(1, 2)):
        tr["api"].append(_api(0.9, "chrome.runtime.onMessage", frame="service_worker"))
        tr["api"].append(_api(1.1, "chrome.runtime.sendMessage", frame="content_script"))
    tr["run"]["duration_s"] = round(t + 1.0, 2)
    return tr, t, origin


# --------------------------------------------------------------------------------------
# Benign updates — including HARD cases that look suspicious
# --------------------------------------------------------------------------------------

def _apply_benign_update(tr, t, origin, rng):
    """Add realistic benign changes; some are 'hard' and look like exfiltration."""
    pool = ["cdn", "dom", "perm", "analytics", "partner_beacon", "morecalls", "messaging", "nothing"]
    for c in rng.sample(pool, k=rng.randint(1, 3)):
        if c == "cdn":
            tr["network"].append(_net(t, "https://cdn.jsdelivr-mirror.test/lib.js",
                                      initiator="extension", rtype="script"))
            t += 0.3
        elif c == "dom":
            for _ in range(rng.randint(1, 3)):
                tr["dom"].append(_dom(t, "inject", "span.badge-new", 0, origin)); t += 0.1
        elif c == "perm":
            newp = rng.choice(["alarms", "contextMenus", "notifications", "idle", "tabs", "webNavigation"])
            if newp not in tr["manifest"]["permissions"]:
                tr["manifest"]["permissions"].append(newp)
        elif c == "analytics":  # small telemetry POST to the vendor's own metrics host
            tr["network"].append(_net(t, "https://metrics.vendor-telemetry.test/e?v=1",
                                      method="POST", initiator="extension", body_len=rng.randint(30, 110)))
            t += 0.3
        elif c == "partner_beacon":  # HARD: a NEW third-party host with a small POST (looks like exfil)
            host = rng.choice(["insights.partner-sdk.test", "sync.abtest-cloud.test", "edge.cdnmetrics.test"])
            tr["network"].append(_net(t, f"https://{host}/collect", method="POST",
                                      initiator="extension", body_len=rng.randint(60, 260)))
            t += 0.3
        elif c == "morecalls":
            for _ in range(rng.randint(1, 3)):
                tr["network"].append(_net(t, f"https://{_ownhost(tr)}/v1/sync", initiator="extension")); t += 0.2
        elif c == "messaging":  # a benign feature that adds component IPC (e.g. a new popup panel)
            for _ in range(rng.randint(1, 3)):
                tr["api"].append(_api(t, "chrome.runtime.sendMessage", frame="content_script")); t += 0.1
    return t


def _ownhost(tr):
    for e in tr["network"]:
        if e["initiator"] == "extension" and "/v1/config" in e["url"]:
            return e["url"].split("//")[1].split("/")[0]
    return "api.readermode.test"


# --------------------------------------------------------------------------------------
# Malicious families — with a `stealth` mode that hides the obvious tells
# --------------------------------------------------------------------------------------

def _apply_family(tr, t, origin, family, rng, stealth=False):
    """Inject one malicious payload family's runtime effects into v2."""
    if stealth:  # blend into a plausible-looking host, small payload, and often no perm bump
        collector = rng.choice(["cdn-edge-77.analytics-sync.test", "assets.telemetry-cloud.test",
                                "static.metrics-io.test"])
        body = lambda lo, hi: rng.randint(max(40, lo // 4), hi // 3)
    else:
        collector = rng.choice(["collect-metrics.test", "cdn-analytics-edge.test",
                                "sync-telemetry.test", "data-ingest.test"])
        body = lambda lo, hi: rng.randint(lo, hi)

    # Split-component evasion: a content script harvests, then hands the loot to the service
    # worker over runtime messaging, which does the exfil. Adds cross-component IPC hops on
    # top of the baseline. Probabilistic so msg_passing stays a soft signal, not a giveaway.
    def _relay():
        if rng.random() < 0.7:
            for _ in range(rng.randint(1, 3)):
                tr["api"].append(_api(t + 0.05, "chrome.runtime.sendMessage", frame="content_script"))

    if family == "cookie_theft":
        tr["dom"].append(_dom(t, "read", "document.cookie", rng.randint(30, 120), origin))
        tr["storage"].append(_sto(t + 0.1, "chrome.cookies.getAll", rng.randint(20, 60)))
        tr["api"].append(_api(t + 0.1, "chrome.cookies.getAll"))
        _relay()
        tr["network"].append(_net(t + 0.4, f"https://{collector}/ingest", method="POST",
                                  initiator="service_worker", body_len=body(800, 3000)))
        if not stealth and "cookies" not in tr["manifest"]["permissions"]:
            tr["manifest"]["permissions"].append("cookies")
    elif family == "credential_theft":
        tr["dom"].append(_dom(t, "read", "input#password", rng.randint(8, 20), origin))
        tr["dom"].append(_dom(t + 0.05, "read", "input[name=username]", rng.randint(6, 18), origin))
        tr["network"].append(_net(t + 0.4, f"https://{collector}/c", method="POST",
                                  initiator="extension", body_len=body(200, 900)))
    elif family == "sw_beacon":
        tr["storage"].append(_sto(t, "chrome.storage.local.get", 3))
        tr["api"].append(_api(t + 0.1, "chrome.tabs.query"))
        tr["network"].append(_net(t + 0.5, f"https://{collector}/b", method="POST",
                                  initiator="service_worker", body_len=body(120, 700)))
    elif family == "ad_affiliate":
        for i in range(rng.randint(2, 5)):
            tr["dom"].append(_dom(t + i * 0.1, "inject", f"iframe.ad-slot-{i}", 0, origin))
        tr["network"].append(_net(t + 0.6, f"https://{collector}/aff?u=" + "x" * rng.randint(20, 40),
                                  initiator="extension", rtype="script"))
    elif family == "keylogger":
        for i in range(rng.randint(4, 9)):
            tr["dom"].append(_dom(t + i * 0.05, "read", "input.field", rng.randint(1, 12), origin))
        _relay()
        tr["network"].append(_net(t + 0.8, f"https://{collector}/k", method="POST",
                                  initiator="extension", body_len=body(60, 300)))
    elif family == "history_exfil":
        tr["api"].append(_api(t + 0.1, "chrome.history.search"))
        tr["network"].append(_net(t + 0.5, f"https://{collector}/h", method="POST",
                                  initiator="service_worker", body_len=body(400, 1500)))
        if not stealth and "history" not in tr["manifest"]["permissions"]:
            tr["manifest"]["permissions"].append("history")
    elif family == "form_jacking":
        tr["dom"].append(_dom(t, "inject", "form#overlay-login", 0, origin))
        tr["dom"].append(_dom(t + 0.1, "read", "input#password", rng.randint(8, 20), origin))
        _relay()
        tr["network"].append(_net(t + 0.5, f"https://{collector}/f", method="POST",
                                  initiator="content_script", body_len=body(150, 700)))
    elif family == "redirect_hijack":
        tr["api"].append(_api(t + 0.1, "chrome.declarativeNetRequest.updateDynamicRules"))
        tr["network"].append(_net(t + 0.4, f"https://{collector}/r?to=aff", initiator="extension", rtype="script"))
        if not stealth and "declarativeNetRequest" not in tr["manifest"]["permissions"]:
            tr["manifest"]["permissions"].append("declarativeNetRequest")
    elif family == "clipboard_steal":
        tr["dom"].append(_dom(t, "read", "clipboard.readText", rng.randint(10, 80), origin))
        _relay()
        tr["network"].append(_net(t + 0.4, f"https://{collector}/cl", method="POST",
                                  initiator="content_script", body_len=body(60, 400)))
    else:
        raise ValueError(f"unknown family {family!r}")
    return t + 1.0


# --------------------------------------------------------------------------------------
# Pair builders
# --------------------------------------------------------------------------------------

def make_benign_pair(persona_key, ext_id, name, v1, v2, rng):
    tr1, _, _ = _base_trace(persona_key, ext_id, name, v1, rng)
    tr2, t, origin = _base_trace(persona_key, ext_id, name, v2, rng)
    _apply_benign_update(tr2, t, origin, rng)
    return tr1, tr2


def make_malicious_pair(persona_key, ext_id, name, v1, v2, family, rng,
                        add_benign_noise=True, stealth=False):
    tr1, _, _ = _base_trace(persona_key, ext_id, name, v1, rng)
    tr2, t, origin = _base_trace(persona_key, ext_id, name, v2, rng)
    if add_benign_noise and rng.random() < 0.6:
        t = _apply_benign_update(tr2, t, origin, rng)
    _apply_family(tr2, t, origin, family, rng, stealth=stealth)
    return tr1, tr2


# --------------------------------------------------------------------------------------
# Corpus
# --------------------------------------------------------------------------------------

def generate_corpus(n_extensions=200, updates_per_ext=4, seed=1234, start="2026-01-01",
                    malicious_ratio=0.4, stealth_ratio=0.35):
    """Return a list of pair records spanning many synthetic extensions and dates.

    ~`malicious_ratio` of updates are malicious; of those, ~`stealth_ratio` are stealth
    variants that hide the obvious tells. About a third of benign updates are 'hard'
    (a new third-party POST) via _apply_benign_update, creating real overlap.
    """
    rng = random.Random(seed)
    persona_keys = list(PERSONAS)
    start_dt = datetime.fromisoformat(start)
    records = []
    for e in range(n_extensions):
        persona = persona_keys[e % len(persona_keys)]
        ext_id = f"synthext{e:04d}" + "a" * 22
        name = f"{persona.capitalize()} Tool {e:03d}"
        minor = rng.randint(0, 6)
        for u in range(updates_per_ext):
            v1 = f"1.{minor}.{u}"
            v2 = f"1.{minor}.{u + 1}"
            collected = (start_dt + timedelta(days=rng.randint(0, 330))).date().isoformat()
            if rng.random() < malicious_ratio:
                family = rng.choice(PAYLOAD_FAMILIES)
                stealth = rng.random() < stealth_ratio
                obf = rng.random() < 0.5
                tr1, tr2 = make_malicious_pair(persona, ext_id, name, v1, v2, family, rng, stealth=stealth)
                label, fam = "malicious", family
            else:
                tr1, tr2 = make_benign_pair(persona, ext_id, name, v1, v2, rng)
                label, fam, obf, stealth = "benign", "", False, False
            records.append({
                "pair_id": f"{ext_id}:{v1}->{v2}", "ext_id": ext_id, "name": name,
                "persona": persona, "collected_at": collected, "label": label, "family": fam,
                "obfuscated": obf, "stealth": stealth, "source": "synthetic",
                "trace_v1": tr1, "trace_v2": tr2,
            })
    return records
