"""Synthetic corpus generator — the honest "synthetic weaponisation" dataset.

Why this exists
---------------
No public labelled dataset of malicious extension *update pairs* exists (see
docs/research/FEASIBILITY_AND_NOVELTY_PART2.md §7), so we construct our own. This module
generates schema-valid trace *pairs* (a trusted baseline v1 and a candidate v2 of the same
synthetic extension) at scale, without needing a live browser for every row — which is what
lets us train and cross-validate the ML tier now. A handful of these families are *also*
executed for real by the live pipeline (engine/sandbox + data/corpus/readerlite), which is
the "real-pipeline validation" that proves the synthetic distribution matches reality.

Design principles that make the ML task *meaningful* (not trivially separable)
-----------------------------------------------------------------------------
* Both versions come from the same *persona*, so the label lives in the **delta**, not in
  the absolute counts. A password-manager persona reads password fields in *both* versions,
  so `dom_sensitive_reads` is high in both and its delta is ~0 — the model must not flag it.
* Benign updates add realistic, sometimes *alarming-looking* behaviour: a new CDN host, a
  new analytics beacon, a new permission, extra injected nodes. These create genuine
  **false-positive pressure**, so FPR is a real metric and single features are ambiguous.
* Malicious families overlap benign signals on purpose (ad-injection looks a little like a
  benign CDN + toolbar), forcing the model to combine signals rather than threshold one.
* Every malicious payload's runtime effect is **identical whether or not it is obfuscated** —
  that is the whole thesis, and the `obfuscated` flag drives the static-vs-dynamic head-to-head.

Everything here is SYNTHETIC and clearly labelled; hosts use the reserved `.test` TLD.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

from engine.features.schema import empty_trace

# --------------------------------------------------------------------------------------
# Personas — a benign extension "shape" that both v1 and v2 share
# --------------------------------------------------------------------------------------

#: name -> profile. `own_domain` is the vendor's first party; `pages` are the scenario pages.
PERSONAS = {
    "reader": {
        "own": "readerapi.test", "perms": ["storage", "activeTab", "scripting"],
        "reads": ["article.main", "div.content"], "identity": 0, "credential": 0,
        "injects": 1, "pages": ["demo-news.test", "blog.test"],
    },
    "shopper": {
        "own": "shopassist.test", "perms": ["storage", "activeTab"],
        "reads": ["span.price", "div.product"], "identity": 0, "credential": 0,
        "injects": 1, "pages": ["shop-demo.test", "market.test"],
    },
    "contacts": {  # a scraper — reads identity data as its *advertised* function
        "own": "contactfinder.test", "perms": ["storage", "activeTab"],
        "reads": ["span.contact-email", "td.contact-name"], "identity": 2, "credential": 0,
        "injects": 1, "pages": ["webmail.test", "crm-demo.test"],
    },
    "passmgr": {  # legitimately reads password fields in BOTH versions
        "own": "vaultkeep.test", "perms": ["storage", "activeTab", "scripting"],
        "reads": ["article.main"], "identity": 1, "credential": 2,
        "injects": 1, "pages": ["demo-bank.test", "portal.test"],
    },
    "weather": {
        "own": "weathernow.test", "perms": ["storage", "geolocation"],
        "reads": ["div.forecast"], "identity": 0, "credential": 0,
        "injects": 1, "pages": ["news.test", "portal.test"],
    },
    "translate": {
        "own": "quicktranslate.test", "perms": ["storage", "activeTab", "scripting"],
        "reads": ["p.text", "div.article-body"], "identity": 0, "credential": 0,
        "injects": 2, "pages": ["blog.test", "wiki-demo.test"],
    },
}

#: Malicious payload families. Each is a function name resolved in `_apply_family`.
PAYLOAD_FAMILIES = (
    "cookie_theft",
    "credential_theft",
    "sw_beacon",
    "ad_affiliate",
    "keylogger",
    "history_exfil",
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
    """A benign baseline trace for a persona, with mild per-run variation."""
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
    # page loads
    for h in p["pages"]:
        tr["network"].append(_net(t, f"https://{h}/", initiator="page", rtype="document"))
        t += rng.uniform(0.3, 0.8)
    # own-API config fetch (extension-initiated, first party)
    tr["network"].append(_net(t, f"https://{p['own']}/v1/config", initiator="extension"))
    t += 0.4
    # benign DOM reads (content it is meant to read)
    for sel in p["reads"]:
        tr["dom"].append(_dom(t, "read", sel, rng.randint(200, 3000), origin))
        t += 0.2
    for _ in range(p["identity"]):
        tr["dom"].append(_dom(t, "read", "span.contact-email", rng.randint(12, 40), origin))
        t += 0.15
    for _ in range(p["credential"]):
        tr["dom"].append(_dom(t, "read", "input#password", rng.randint(8, 20), origin))
        t += 0.15
    for i in range(p["injects"]):
        tr["dom"].append(_dom(t, "inject", f"div.ext-ui-{i}", 0, origin))
        t += 0.15
    # storage + api baseline
    tr["storage"].append(_sto(0.8, "chrome.storage.local.get", rng.randint(1, 4)))
    tr["storage"].append(_sto(t, "chrome.storage.local.set", 1))
    tr["api"] += [
        _api(0.7, "chrome.runtime.onInstalled"),
        _api(0.8, "chrome.storage.local.get"),
        _api(1.0, "chrome.scripting.executeScript"),
        _api(t, "chrome.storage.local.set"),
    ]
    tr["run"]["duration_s"] = round(t + 1.0, 2)
    return tr, t, origin


# --------------------------------------------------------------------------------------
# Mutations
# --------------------------------------------------------------------------------------

def _apply_benign_update(tr, t, origin, rng):
    """Add realistic benign changes — some of which look mildly alarming (FP pressure)."""
    choices = rng.sample(["cdn", "dom", "perm", "analytics", "nothing"],
                         k=rng.randint(1, 3))
    for c in choices:
        if c == "cdn":  # new third-party host (font/CDN) — benign but bumps 3p-host count
            tr["network"].append(_net(t, "https://cdn.jsdelivr-mirror.test/lib.js",
                                      initiator="extension", rtype="script"))
            t += 0.3
        elif c == "dom":  # extra benign injection + read
            tr["dom"].append(_dom(t, "inject", "span.badge-new", 0, origin))
            tr["dom"].append(_dom(t + 0.1, "read", "div.content", rng.randint(200, 1500), origin))
            t += 0.3
        elif c == "perm":  # benign new permission
            newp = rng.choice(["alarms", "contextMenus", "notifications", "idle"])
            if newp not in tr["manifest"]["permissions"]:
                tr["manifest"]["permissions"].append(newp)
        elif c == "analytics":  # new analytics beacon — the HARD benign case (looks like exfil)
            tr["network"].append(_net(t, "https://metrics.vendor-telemetry.test/e?v=1&s=42",
                                      method="POST", initiator="extension", body_len=rng.randint(40, 120)))
            t += 0.3
    return t


def _apply_family(tr, t, origin, family, rng):
    """Inject one malicious payload family's *runtime effects* into v2."""
    collector = rng.choice(["collect-metrics.test", "cdn-analytics-edge.test",
                            "sync-telemetry.test", "data-ingest.test"])
    if family == "cookie_theft":
        tr["dom"].append(_dom(t, "read", "document.cookie", rng.randint(30, 120), origin))
        tr["storage"].append(_sto(t + 0.1, "chrome.cookies.getAll", rng.randint(20, 60)))
        tr["api"].append(_api(t + 0.1, "chrome.cookies.getAll"))
        tr["network"].append(_net(t + 0.4, f"https://{collector}/ingest", method="POST",
                                  initiator="service_worker", body_len=rng.randint(800, 3000)))
    elif family == "credential_theft":
        tr["dom"].append(_dom(t, "read", "input#password", rng.randint(8, 20), origin))
        tr["dom"].append(_dom(t + 0.05, "read", "input[name=username]", rng.randint(6, 18), origin))
        tr["network"].append(_net(t + 0.4, f"https://{collector}/c", method="POST",
                                  initiator="extension", body_len=rng.randint(200, 900)))
    elif family == "sw_beacon":
        tr["storage"].append(_sto(t, "chrome.storage.local.get", 3))
        tr["api"].append(_api(t + 0.1, "chrome.tabs.query"))
        tr["network"].append(_net(t + 0.5, f"https://{collector}/b", method="POST",
                                  initiator="service_worker", body_len=rng.randint(120, 700)))
    elif family == "ad_affiliate":  # overlaps benign CDN/inject on purpose
        for i in range(rng.randint(2, 5)):
            tr["dom"].append(_dom(t + i * 0.1, "inject", f"iframe.ad-slot-{i}", 0, origin))
        tr["network"].append(_net(t + 0.6, f"https://{collector}/aff?u=" + "x" * rng.randint(20, 40),
                                  initiator="extension", rtype="script"))
    elif family == "keylogger":
        for i in range(rng.randint(4, 9)):
            tr["dom"].append(_dom(t + i * 0.05, "read", "input.field", rng.randint(1, 12), origin))
        tr["network"].append(_net(t + 0.8, f"https://{collector}/k", method="POST",
                                  initiator="extension", body_len=rng.randint(60, 300)))
    elif family == "history_exfil":
        tr["api"].append(_api(t + 0.1, "chrome.history.search"))
        tr["network"].append(_net(t + 0.5, f"https://{collector}/h", method="POST",
                                  initiator="service_worker", body_len=rng.randint(400, 1500)))
    else:
        raise ValueError(f"unknown family {family!r}")
    # Malicious updates that add a new capability declare the permission (perm-escalation signal)
    if family in ("cookie_theft",) and "cookies" not in tr["manifest"]["permissions"]:
        tr["manifest"]["permissions"].append("cookies")
    if family in ("history_exfil",) and "history" not in tr["manifest"]["permissions"]:
        tr["manifest"]["permissions"].append("history")
    return t + 1.0


# --------------------------------------------------------------------------------------
# Pair builders
# --------------------------------------------------------------------------------------

def make_benign_pair(persona_key, ext_id, name, v1, v2, rng):
    tr1, _, _ = _base_trace(persona_key, ext_id, name, v1, rng)
    tr2, t, origin = _base_trace(persona_key, ext_id, name, v2, rng)
    _apply_benign_update(tr2, t, origin, rng)
    return tr1, tr2


def make_malicious_pair(persona_key, ext_id, name, v1, v2, family, rng, add_benign_noise=True):
    tr1, _, _ = _base_trace(persona_key, ext_id, name, v1, rng)
    tr2, t, origin = _base_trace(persona_key, ext_id, name, v2, rng)
    if add_benign_noise and rng.random() < 0.6:
        t = _apply_benign_update(tr2, t, origin, rng)
    _apply_family(tr2, t, origin, family, rng)
    return tr1, tr2


# --------------------------------------------------------------------------------------
# Corpus
# --------------------------------------------------------------------------------------

def generate_corpus(n_extensions=40, updates_per_ext=3, seed=1234, start="2026-01-01"):
    """Return a list of pair records spanning several synthetic extensions and dates.

    Each record: {pair_id, ext_id, name, persona, collected_at, label, family,
    obfuscated, trace_v1, trace_v2}. ~40% of update pairs are malicious.
    """
    rng = random.Random(seed)
    persona_keys = list(PERSONAS)
    start_dt = datetime.fromisoformat(start)
    records = []
    for e in range(n_extensions):
        persona = persona_keys[e % len(persona_keys)]
        ext_id = f"synthext{e:04d}" + "a" * 22
        name = f"{persona.capitalize()} Tool {e:03d}"
        major = 1
        minor = rng.randint(0, 4)
        for u in range(updates_per_ext):
            v1 = f"{major}.{minor}.{u}"
            v2 = f"{major}.{minor}.{u + 1}"
            collected = (start_dt + timedelta(days=rng.randint(0, 300))).date().isoformat()
            is_mal = rng.random() < 0.4
            if is_mal:
                family = rng.choice(PAYLOAD_FAMILIES)
                obf = rng.random() < 0.5
                tr1, tr2 = make_malicious_pair(persona, ext_id, name, v1, v2, family, rng)
                label, fam = "malicious", family
            else:
                tr1, tr2 = make_benign_pair(persona, ext_id, name, v1, v2, rng)
                label, fam, obf = "benign", "", False
            records.append({
                "pair_id": f"{ext_id}:{v1}->{v2}",
                "ext_id": ext_id, "name": name, "persona": persona,
                "collected_at": collected, "label": label, "family": fam,
                "obfuscated": obf, "source": "synthetic",
                "trace_v1": tr1, "trace_v2": tr2,
            })
    return records
