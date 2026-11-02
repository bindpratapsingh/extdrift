"""Normalised events -> behaviours and the extended feature vector.

Two products of one pass:

* **Behaviours** are events grouped by what they mean: "read a password field", "POST to
  host X". The differ compares them across versions, and the scorer reasons over them.
* **Features** are numeric counts stored next to each trace, for measurement and comparison.

The legacy 26 features in :mod:`engine.features.extract` still exist, unchanged, because the trained
model depends on them. These are additional. Everything here is a pure function of the events and
the manifest, so the same trace always yields the same vector.
"""

from __future__ import annotations

import hashlib
import json
import re
import statistics
from collections import defaultdict
from urllib.parse import urlsplit

from engine.features.extract import domain_low_reputation, registrable_domain

EXTENSION_CONTEXTS = {"service_worker", "background_page", "extension_page", "content_script",
                      "page_injected_script", "extension", "extension_induced", "unattributed"}
#: Sensitive reads before an upload within this many seconds form a temporal candidate.
EXFIL_WINDOW_S = 10.0
SMALL_UPLOAD_BYTES = 256
BEACON_MIN_REPEATS = 3
BEACON_MAX_CV = 0.35
#: Faster than this is a burst from one action, not something checking in on a schedule.
BEACON_MIN_INTERVAL_S = 1.0
KEY_LISTENERS = {"keydown", "keypress", "keyup", "input", "beforeinput"}
PRIVILEGED_NAMESPACES = {
    "cookies", "webRequest", "debugger", "proxy", "scripting", "history", "downloads", "management",
    "browsingData", "privacy", "contentSettings", "identity", "pageCapture", "tabCapture",
    "desktopCapture", "userScripts", "declarativeNetRequest", "nativeMessaging",
}
PRIVILEGED_METHODS = {"tabs.executeScript", "tabs.captureVisibleTab", "tabs.insertCSS",
                      "runtime.sendNativeMessage", "runtime.connectNative"}
_INSPECTION_METHOD = re.compile(r"\.(getDynamicRules|getSessionRules|getEnabledRulesets|getMatchedRules"
                                r"|getAvailableStaticRuleCount|isRegexSupported|getAll)$")
READ_FIELD_CLASSES = ("password", "payment", "otp", "auth_token", "hidden", "account", "personal")

FEATURE_DOCS: dict[str, str] = {
    "net_outbound_requests": "Requests attributed to the extension",
    "net_unique_domains": "Distinct registrable domains the extension contacted",
    "net_uploads": "Extension requests carrying data outwards",
    "net_upload_bytes": "Bytes in extension request bodies",
    "net_undeclared_domains": "Contacted domains absent from the manifest and the fixed web",
    "net_suspicious_destinations": "Upload destinations with a low-reputation shape or an IP literal",
    "net_marker_requests": "Requests containing a synthetic secret value",
    "net_websockets": "WebSocket connections opened by the extension",
    "net_attempts_not_on_wire": "Requests reported by code that the gateway never saw",
    "net_beacon_groups": "Destinations receiving regular repeated requests",
    "net_beacon_max_repeats": "Largest repeat count among those destinations",
    "dom_password_field_reads": "Value reads of password fields",
    "dom_password_field_lookups": "Lookups of password fields without a value read",
    "dom_login_form_interactions": "DOM operations touching a form that has a password field",
    "dom_sensitive_reads": "Value or text reads of any sensitive field class",
    "dom_scripts_injected": "Scripts or iframes added to pages",
    "dom_modifications": "Other changes to page structure",
    "dom_form_tampering": "Changes to form attributes such as the action URL",
    "dom_key_listeners": "Key or input listeners on the document or on fields",
    "dom_form_captures": "FormData built from a form",
    "cookie_reads": "Cookie reads through document.cookie or the cookies API",
    "cookie_bulk_reads": "Whole-jar reads through cookies.getAll",
    "storage_reads": "Web and extension storage reads",
    "storage_writes": "Web and extension storage writes",
    "storage_deletes": "Web and extension storage deletes and clears",
    "storage_sensitive_accesses": "Storage operations on keys that look like credentials",
    "api_calls": "Extension API calls and listener registrations",
    "api_distinct": "Distinct extension APIs used",
    "api_privileged_calls": "Calls into privileged extension APIs",
    "exfil_events": "Requests where a synthetic secret left for a non-owning destination",
    "exfil_credential_events": "Of those, passwords and one-time codes",
    "exfil_session_events": "Of those, session cookies and tokens",
    "exfil_temporal_candidates": "Uploads shortly after a sensitive read, without a marker match",
    "worker_uploads": "Uploads from a service worker or background page",
    "sensitive_scenarios": "Scenarios in which sensitive data was read",
    "perm_high_risk": "Declared high-risk API permissions",
    "perm_broad_host": "1 when host access covers every site",
}
FEATURE_ORDER = tuple(FEATURE_DOCS)

HIGH_RISK_PERMISSIONS = {
    "cookies", "webRequest", "webRequestBlocking", "declarativeNetRequest",
    "declarativeNetRequestWithHostAccess", "scripting", "tabs", "debugger", "proxy", "history",
    "downloads", "management", "nativeMessaging", "clipboardRead", "privacy", "contentSettings",
    "identity", "webNavigation", "browsingData",
}


def _is_privileged(api: str) -> bool:
    namespace = api.split(".")[0]
    if api in PRIVILEGED_METHODS:
        return True
    if namespace in PRIVILEGED_NAMESPACES:
        return not _INSPECTION_METHOD.search(api) or namespace == "cookies"
    return False


def _normal_path(url: str) -> str:
    """URL path with volatile parts folded, so /u/1 and /u/2 are one behaviour."""
    path = urlsplit(url).path or "/"
    path = re.sub(r"\[MARKER:[^\]]+\]", "M", path)
    return re.sub(r"/[0-9a-fA-F-]{8,}|/\d+", "/N", path)[:80]


def _body_bucket(size: int) -> str:
    if size <= 0:
        return "none"
    if size <= SMALL_UPLOAD_BYTES:
        return "small"
    if size <= 4096:
        return "medium"
    return "large"


def annotate_uploads(events: list[dict]) -> None:
    """Mark uploads that follow a sensitive read in the same scenario with no marker match."""
    sensitive_times: dict[str, list[float]] = defaultdict(list)
    for event in events:
        if _is_sensitive_read(event):
            sensitive_times[event["scenario"]].append(event["ts"])
    for event in events:
        if event["category"] != "network" or "upload" not in event["risk_indicators"]:
            continue
        reads = sensitive_times.get(event["scenario"], [])
        if any(0 <= event["ts"] - t <= EXFIL_WINDOW_S for t in reads):
            event["risk_indicators"].append("after_sensitive_read")


def _is_sensitive_read(event: dict) -> bool:
    if event["category"] == "storage":
        return "cookie_access" in event["risk_indicators"] or "sensitive_storage_key" in event["risk_indicators"]
    if event["category"] != "dom":
        return False
    if event["event_type"] == "cookie_read":
        return True
    if event["event_type"] in ("field_read", "text_read", "form_data_read", "clipboard_read"):
        if event["event_type"] in ("form_data_read", "clipboard_read"):
            return True
        return event["metadata"].get("field_class") in READ_FIELD_CLASSES
    return False


def detect_beacons(events: list[dict]) -> dict[str, dict]:
    """Regular repeated requests to one destination, by inter-arrival regularity."""
    groups: dict[str, list[float]] = defaultdict(list)
    for event in events:
        if event["category"] == "network" and event["event_type"] == "http_request" \
                and event["source_context"] in EXTENSION_CONTEXTS:
            key = f"{event['operation']} {event['destination']}{_normal_path(event['metadata'].get('url', ''))}"
            groups[key].append(event["ts"])
    beacons = {}
    for key, times in groups.items():
        if len(times) < BEACON_MIN_REPEATS:
            continue
        gaps = [b - a for a, b in zip(times, times[1:]) if b > a]
        if len(gaps) < BEACON_MIN_REPEATS - 1:
            continue
        mean = statistics.fmean(gaps)
        cv = statistics.pstdev(gaps) / mean if mean else 1.0
        if cv <= BEACON_MAX_CV and mean >= BEACON_MIN_INTERVAL_S:
            beacons[key] = {"repeats": len(times), "mean_interval_s": round(mean, 2), "cv": round(cv, 3)}
    return beacons


class _Group:
    def __init__(self, signature: str, category: str, label: str):
        self.signature, self.category, self.label = signature, category, label
        self.count = 0
        self.scenarios: set[str] = set()
        self.contexts: set[str] = set()
        self.targets: set[str] = set()
        self.params: set[str] = set()
        self.tags: set[str] = set()
        self.confidence = "inferred"
        self.event_ids: list[str] = []
        self.first_ts: float | None = None
        self.first_timestamp: str | None = None
        self.details: dict = {}

    def add(self, event: dict) -> None:
        self.count += 1
        self.scenarios.add(event["scenario"])
        self.contexts.add(event["source_context"])
        self.tags.update(event["risk_indicators"])
        if event["attribution_confidence"] == "confirmed":
            self.confidence = "confirmed"
        if len(self.event_ids) < 5:
            self.event_ids.append(event["event_id"])
        if self.first_ts is None:
            self.first_ts, self.first_timestamp = event["ts"], event["timestamp"]

    def as_dict(self) -> dict:
        return {
            "signature": self.signature, "category": self.category, "label": self.label,
            "count": self.count, "scenarios": sorted(self.scenarios),
            "contexts": sorted(self.contexts), "targets": sorted(self.targets)[:12],
            "parameters": sorted(self.params)[:24], "tags": sorted(self.tags),
            "attribution_confidence": self.confidence, "event_ids": self.event_ids,
            "first_ts": self.first_ts, "first_timestamp": self.first_timestamp,
            "details": self.details,
        }


def _behaviour_key(event: dict) -> tuple[str, str] | None:
    """(signature, readable label) for an event, or None when it is not extension behaviour."""
    category, kind = event["category"], event["event_type"]
    meta = event["metadata"]
    if category == "network":
        if event["source_context"] not in EXTENSION_CONTEXTS:
            return None
        if kind in ("tls_failure", "connection_failure"):
            return None
        host = event.get("destination") or "?"
        if kind == "websocket_message":
            return f"net:ws_send:{host}", f"WebSocket message to {host}"
        if kind == "websocket_open":
            return f"net:ws:{host}", f"WebSocket opened to {host}"
        if kind == "attempt_not_on_wire":
            return f"net:unobserved:{event['operation']}:{host}", f"{event['operation']} attempt to {host}, not seen on the wire"
        if kind in ("raw_tcp", "raw_tcp_data"):
            return f"net:tcp:{host}", f"Raw TCP traffic to {host}"
        path = _normal_path(meta.get("url", ""))
        return (f"net:{event['operation']}:{host}{path}",
                f"{event['operation']} to {host}{path}")
    if category == "dom":
        cls = meta.get("field_class") or "other"
        if kind == "activity_summary":
            return None
        if kind == "field_read":
            return f"dom:field_read:{cls}", f"Read the value of a {cls} field"
        if kind == "cookie_read":
            return "dom:cookie_read", "Read document.cookie"
        if kind == "cookie_write":
            return "dom:cookie_write", "Wrote document.cookie"
        if kind == "text_read":
            return f"dom:text_read:{cls}", f"Read page text ({cls})"
        if kind == "query":
            return f"dom:query:{cls}", f"Looked up {cls} elements"
        if kind == "listener":
            listener = meta.get("listener_type", "")
            where = meta.get("field_class") or ("root" if meta.get("target") in ("document", "window") else "other")
            return f"dom:listener:{listener}:{where}", f"Listens for {listener} on {where}"
        if kind == "script_injected":
            return f"dom:script_injected:{meta.get('node_tag')}", f"Injected a {meta.get('node_tag')} element"
        if kind == "html_injected":
            shape = "form" if meta.get("contains_form") else ("script" if meta.get("contains_script") else "plain")
            return f"dom:html_injected:{shape}", f"Injected HTML ({shape})"
        if kind == "form_modified":
            return f"dom:form_modified:{meta.get('attribute')}", f"Changed a form's {meta.get('attribute')}"
        if kind == "node_injected":
            return f"dom:node_injected:{meta.get('node_tag')}", f"Added a {meta.get('node_tag')} element"
        if kind == "element_modified":
            return f"dom:element_modified:{meta.get('kind')}", f"Modified the page ({meta.get('kind')})"
        if kind == "element_created":
            return f"dom:element_created:{meta.get('node_tag')}", f"Created a {meta.get('node_tag')} element"
        if kind == "form_data_read":
            return "dom:form_data_read", "Captured a whole form with FormData"
        if kind == "form_submit_call":
            return "dom:form_submit_call", "Called form.submit()"
        if kind == "clipboard_read":
            return "dom:clipboard_read", "Read the clipboard"
        return f"dom:{kind}", f"DOM operation {kind}"
    if category == "storage":
        area = meta.get("area")
        key_part = "sensitive_key" if meta.get("sensitive_key") else "key"
        if area == "cookie":
            return f"cookie:{kind}:{event['operation']}", f"Cookie {kind} through {event['operation']}"
        return f"storage:{kind}:{area}:{key_part}", f"Storage {kind} in {area}" + (
            " on a credential-like key" if meta.get("sensitive_key") else "")
    if category == "api":
        return f"api:{kind}:{event['operation']}", f"Extension API {event['operation']}"
    return None


def extract_behaviours(events: list[dict], manifest: dict, bundle_hosts: set[str],
                       declared: set[str]) -> dict[str, dict]:
    """Group events into behaviours and tag each with its context."""
    annotate_uploads(events)
    beacons = detect_beacons(events)
    groups: dict[str, _Group] = {}
    for event in events:
        key = _behaviour_key(event)
        if key is None:
            continue
        signature, label = key
        group = groups.get(signature)
        if group is None:
            group = groups[signature] = _Group(signature, event["category"], label)
        group.add(event)
        _collect_params(group, event, declared, bundle_hosts)
    for key, info in beacons.items():
        method, rest = key.split(" ", 1)
        signature = f"net:{method}:{rest}"
        if signature in groups:
            groups[signature].tags.add("beacon")
            groups[signature].details["beacon"] = info
    return {signature: group.as_dict() for signature, group in sorted(groups.items())}


def _collect_params(group: _Group, event: dict, declared: set[str], bundle_hosts: set[str]) -> None:
    meta = event["metadata"]
    if event["category"] == "network":
        host = event.get("destination") or ""
        domain = registrable_domain(host)
        group.targets.add(host)
        group.params.add(f"context={event['source_context']}")
        group.params.add(f"body={_body_bucket(int(meta.get('body_len') or 0))}")
        for hit in meta.get("marker_hits") or []:
            if hit.get("location") == "header:cookie":
                continue
            group.params.add(f"marker={hit['kind']}")
            group.tags.add(f"exfil:{hit['sensitivity']}")
            group.details.setdefault("markers", [])
            entry = {"kind": hit["kind"], "sensitivity": hit["sensitivity"],
                     "encoding": hit["encoding"], "location": hit["location"]}
            if entry not in group.details["markers"]:
                group.details["markers"].append(entry)
        if host in bundle_hosts:
            group.tags.add("in_fixed_web")
        elif domain in declared:
            group.tags.add("declared_host")
        else:
            group.tags.add("undeclared_host")
        if "upload" in event["risk_indicators"] and domain_low_reputation(host):
            group.tags.add("low_reputation")
        size = int(meta.get("body_len") or 0)
        group.details["max_body_len"] = max(group.details.get("max_body_len", 0), size)
        if size > SMALL_UPLOAD_BYTES:
            group.tags.add("large_upload")
        if event["event_type"] in ("websocket_open", "websocket_message"):
            group.tags.add("websocket")
        if event["source_context"] in ("service_worker", "background_page"):
            group.tags.add("background_context")
    elif event["category"] == "dom":
        target = str(meta.get("target", ""))[:80]
        if target:
            group.targets.add(target)
        if meta.get("field_class") and meta["field_class"] != "other":
            group.tags.add(f"field:{meta['field_class']}")
        if event["event_type"] == "listener" and meta.get("listener_type") in KEY_LISTENERS:
            group.tags.add("key_listener")
        if meta.get("capture"):
            group.tags.add("capture_phase")
    elif event["category"] == "storage":
        if meta.get("key"):
            group.targets.add(str(meta["key"])[:80])
        group.params.add(f"area={meta.get('area')}")
        group.tags.add(f"operation:{event['event_type']}")
    elif event["category"] == "api":
        group.targets.add(event["operation"])
        group.details["permission"] = meta.get("permission")
        if _is_privileged(event["operation"]):
            group.tags.add("privileged_api")
        args = meta.get("args")
        if args:
            group.params.add("args=" + json.dumps(args, sort_keys=True, default=str)[:120])


def extract_features(events: list[dict], behaviours: dict[str, dict], manifest: dict,
                     bundle_hosts: set[str], declared: set[str]) -> dict[str, float]:
    """The extended feature vector, in FEATURE_ORDER."""
    from engine.features.extract import split_permissions

    net = [e for e in events if e["category"] == "network" and e["source_context"] in EXTENSION_CONTEXTS
           and e["event_type"] in ("http_request", "websocket_open", "websocket_message", "raw_tcp_data")]
    http = [e for e in net if e["event_type"] == "http_request"]
    domains = {registrable_domain(e["destination"]) for e in net if e.get("destination")}
    uploads = [e for e in http if "upload" in e["risk_indicators"]]
    undeclared = {d for d in domains if d not in declared
                  and not any(registrable_domain(h) == d for h in bundle_hosts)}
    suspicious = {e["destination"] for e in uploads
                  if domain_low_reputation(e["destination"] or "")
                  or "ip_literal_destination" in e["risk_indicators"]}
    marker_events = [e for e in net if any(i.startswith("marker:") for i in e["risk_indicators"])]

    dom = [e for e in events if e["category"] == "dom"]
    reads = [e for e in dom if e["event_type"] in ("field_read", "text_read")]
    sensitive_reads = [e for e in reads if e["metadata"].get("field_class") in READ_FIELD_CLASSES]
    storage = [e for e in events if e["category"] == "storage"]
    api = [e for e in events if e["category"] == "api"]
    storage_web = [e for e in storage if e["metadata"].get("area") != "cookie"]
    cookie_store = [e for e in storage if e["metadata"].get("area") == "cookie"]
    beacons = [b for b in behaviours.values() if "beacon" in b["tags"]]

    permissions, hosts = split_permissions(manifest or {})
    sensitive_scenarios = {e["scenario"] for e in events if _is_sensitive_read(e)}

    def indicator(event: dict, prefix: str) -> bool:
        return any(i.startswith(prefix) for i in event["risk_indicators"])

    features = {
        "net_outbound_requests": len(http),
        "net_unique_domains": len(domains),
        "net_uploads": len(uploads),
        "net_upload_bytes": sum(int(e["metadata"].get("body_len") or 0) for e in uploads),
        "net_undeclared_domains": len(undeclared),
        "net_suspicious_destinations": len(suspicious),
        "net_marker_requests": len(marker_events),
        "net_websockets": sum(1 for e in net if e["event_type"] == "websocket_open"),
        "net_attempts_not_on_wire": sum(1 for e in events if e["event_type"] == "attempt_not_on_wire"),
        "net_beacon_groups": len(beacons),
        "net_beacon_max_repeats": max((b["details"]["beacon"]["repeats"] for b in beacons), default=0),
        "dom_password_field_reads": sum(1 for e in reads if e["metadata"].get("field_class") == "password"),
        "dom_password_field_lookups": sum(1 for e in dom if e["event_type"] == "query"
                                          and e["metadata"].get("field_class") == "password"),
        "dom_login_form_interactions": sum(1 for e in dom if "login_form" in e["risk_indicators"]),
        "dom_sensitive_reads": len(sensitive_reads),
        "dom_scripts_injected": sum(1 for e in dom if e["event_type"] == "script_injected"),
        "dom_modifications": sum(1 for e in dom if e["event_type"] in
                                 ("node_injected", "element_modified", "html_injected")),
        "dom_form_tampering": sum(1 for e in dom if e["event_type"] == "form_modified"),
        "dom_key_listeners": sum(1 for e in dom if e["event_type"] == "listener"
                                 and e["metadata"].get("listener_type") in KEY_LISTENERS),
        "dom_form_captures": sum(1 for e in dom if e["event_type"] == "form_data_read"),
        "cookie_reads": sum(1 for e in dom if e["event_type"] == "cookie_read")
                        + sum(1 for e in cookie_store if str(e["event_type"]).startswith("read")),
        "cookie_bulk_reads": sum(1 for e in cookie_store if e["event_type"] == "read_all"),
        "storage_reads": sum(1 for e in storage_web if str(e["event_type"]).startswith("read")),
        "storage_writes": sum(1 for e in storage_web if e["event_type"] == "write"),
        "storage_deletes": sum(1 for e in storage_web if e["event_type"] in ("delete", "clear")),
        "storage_sensitive_accesses": sum(1 for e in storage_web if e["metadata"].get("sensitive_key")),
        "api_calls": len(api),
        "api_distinct": len({e["operation"] for e in api}),
        "api_privileged_calls": sum(1 for e in api if _is_privileged(e["operation"]))
                                + len(cookie_store),
        "exfil_events": len(marker_events),
        "exfil_credential_events": sum(1 for e in marker_events if indicator(e, "marker:credential")),
        "exfil_session_events": sum(1 for e in marker_events if indicator(e, "marker:session")),
        "exfil_temporal_candidates": sum(
            1 for e in uploads if "after_sensitive_read" in e["risk_indicators"]
            and not indicator(e, "marker:")),
        "worker_uploads": sum(1 for e in uploads if e["source_context"] in ("service_worker", "background_page")),
        "sensitive_scenarios": len(sensitive_scenarios),
        "perm_high_risk": len(set(permissions) & HIGH_RISK_PERMISSIONS),
        "perm_broad_host": 1 if hosts & {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"} else 0,
    }
    assert set(features) == set(FEATURE_ORDER), "feature catalogue drifted from FEATURE_DOCS"
    return {name: float(features[name]) for name in FEATURE_ORDER}


def feature_digest(features: dict[str, float]) -> str:
    """Hash of a vector, so a reader can verify two runs produced the same features."""
    canonical = json.dumps([features[name] for name in FEATURE_ORDER])
    return hashlib.sha256(canonical.encode()).hexdigest()
