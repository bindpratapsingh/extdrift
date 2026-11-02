"""Raw run evidence -> the central event schema, plus a legacy trace for the existing features.

Each event has the fields of :data:`NORMALISED_FIELDS`, whatever browser produced it. The raw
files stay untouched next to the normalised output, so any normalised event can be checked against
what was really recorded. Reports are hints that an extension could forge or suppress, so the
gateway's wire record is the source of truth for network events, with reports only annotating them.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from engine.features.extract import host_of, looks_encoded, registrable_domain
from engine.features.schema import SCHEMA_VERSION
from engine.sandbox.attribution import (
    CONFIRMED,
    INFERRED,
    LEGACY_INITIATOR,
    DriverIndex,
    ReportIndex,
    attribute_flow,
)
from engine.unpack.manifest import normalise_manifest

NORMALISED_SCHEMA_VERSION = "1.0"
NORMALISED_FIELDS = (
    "event_id", "analysis_id", "extension_id", "extension_version", "browser", "timestamp", "ts",
    "scenario", "category", "event_type", "source_context", "destination", "operation",
    "metadata", "risk_indicators", "attribution_confidence", "attribution_basis",
)
#: Sensitive form-field classes, strongest first. Structure (type, autocomplete) outranks names.
_NAME_CLASSES = (
    ("otp", re.compile(r"\botp\b|one.?time|2fa|totp|mfa", re.I)),
    ("payment", re.compile(r"card|\bcc\b|cc[-_]|cvv|cvc|csc|iban|expiry", re.I)),
    ("password", re.compile(r"pass(word|wd|phrase)?|\bpwd\b|\bpin\b", re.I)),
    ("auth_token", re.compile(r"token|csrf|xsrf|api.?key|secret|session|bearer|auth", re.I)),
    ("account", re.compile(r"account|routing|ssn|national.?id", re.I)),
    ("username", re.compile(r"user(name)?|login|e.?mail|\bcustomer\b", re.I)),
)
_SENSITIVE_STORAGE_KEY = re.compile(
    r"token|auth|session|sess|jwt|secret|pass(word|wd)?|credential|api.?key|cookie|bearer|csrf", re.I)
_SELECTOR_PASSWORD = re.compile(r"type=[\"']?password|password|passwd|\bpwd\b", re.I)
_SELECTOR_LOGIN = re.compile(r"login|signin|sign-in|auth", re.I)
_SELECTOR_SENSITIVE = re.compile(r"cvv|cvc|card|cc-|otp|ssn|token|secret|csrf|hidden", re.I)
HIGH_ENTROPY = 5.0


def classify_field(meta: dict | None, target: str = "") -> str | None:
    """Classify a form field from its structure, falling back to its name."""
    meta = meta or {}
    kind = str(meta.get("type", "")).lower()
    autocomplete = str(meta.get("autocomplete", "")).lower()
    mark = str(meta.get("sensitive_mark", "")).lower()
    if mark:
        return "account" if mark in ("account", "balance") else "personal"
    if autocomplete.startswith("cc-"):
        return "payment"
    if autocomplete == "one-time-code":
        return "otp"
    if kind == "password" or "password" in autocomplete:
        return "password"
    names = " ".join(str(meta.get(k, "")) for k in ("name", "id")) + " " + target
    for label, pattern in _NAME_CLASSES:
        if pattern.search(names):
            return label
    if kind == "hidden":
        return "hidden"
    if kind == "email" or autocomplete in ("username", "email"):
        return "username"
    return None


def classify_selector(selector: str) -> str | None:
    if _SELECTOR_PASSWORD.search(selector):
        return "password"
    if _SELECTOR_LOGIN.search(selector):
        return "login_form"
    if _SELECTOR_SENSITIVE.search(selector):
        return "sensitive"
    return None


def _read_jsonl(path: Path) -> tuple[list[dict], int]:
    """Read one evidence file, returning its records and how many lines were unreadable."""
    records, bad = [], 0
    if not path.exists():
        return records, 0
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                bad += 1
                continue
            if isinstance(record, dict):
                records.append(record)
            else:
                bad += 1
    return records, bad


def _read_json(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


@dataclass
class RunContext:
    """Facts the normaliser needs that are not in the raw evidence."""

    analysis_id: str
    extension_id: str
    extension_version: str
    browser: str
    manifest: dict
    noise_domains: list[str] = field(default_factory=list)
    report_window: float = 8.0


@dataclass
class NormalisedRun:
    events: list[dict]
    coverage: dict
    legacy_trace: dict
    run_info: dict
    preflight: dict
    gateway_preflight: dict
    bundle: dict
    parse_problems: dict
    #: Page-attributed requests, kept apart. Identical across versions when the web was fixed.
    page_traffic: list[str]


class _ScenarioClock:
    def __init__(self, control: list[dict]):
        self.starts = sorted((float(c["t"]), c["scenario"]) for c in control
                             if c.get("command") == "start" and "t" in c and "scenario" in c)

    def scenario_at(self, t: float) -> str:
        current = "startup"
        for start, name in self.starts:
            if t >= start:
                current = name
            else:
                break
        return current


def _event_id(analysis_id: str, *parts: object) -> str:
    return hashlib.sha1("|".join(str(p) for p in (analysis_id, *parts)).encode()).hexdigest()[:16]


def _report_time(entry: dict) -> float:
    """Trust the report's own clock only if it agrees with arrival, as an extension can forge it."""
    arrival = float(entry.get("arrival") or 0.0)
    wall = (entry.get("event") or {}).get("t_wall")
    if isinstance(wall, (int, float)) and abs(wall / 1000.0 - arrival) < 30.0:
        return wall / 1000.0
    return arrival


def _api_generic(name: str) -> str:
    return re.sub(r"^(chrome|browser)\.", "", name)


def normalise_run(raw_dir: str | Path, ctx: RunContext) -> NormalisedRun:
    raw_dir = Path(raw_dir)
    flows, bad_flows = _read_jsonl(raw_dir / "gateway" / "flows.jsonl")
    reports, bad_reports = _read_jsonl(raw_dir / "gateway" / "reports.jsonl")
    control, _ = _read_jsonl(raw_dir / "gateway" / "control.jsonl")
    driver, bad_driver = _read_jsonl(raw_dir / "browser" / "driver.jsonl")
    run_info = _read_json(raw_dir / "browser" / "run.json")
    bundle = _read_json(raw_dir / "gateway" / "bundle.json")
    summary = _read_json(raw_dir / "gateway" / "gateway_summary.json")

    clock = _ScenarioClock(control)
    # All times are seconds from the first scenario, or from the first evidence if none started.
    candidates = [float(f["t"]) for f in flows if "t" in f] + [_report_time(r) for r in reports]
    t0 = min(candidates, default=0.0) if candidates else 0.0

    def base(category: str, event_type: str, t: float, *, context: str, destination: str | None,
             operation: str, metadata: dict, confidence: str, attribution_basis: str,
             indicators: list[str] | None = None, unique: object = "") -> dict:
        return {
            "event_id": _event_id(ctx.analysis_id, ctx.extension_version, category, event_type, t, unique),
            "analysis_id": ctx.analysis_id,
            "extension_id": ctx.extension_id,
            "extension_version": ctx.extension_version,
            "browser": ctx.browser,
            "timestamp": datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="milliseconds"),
            "ts": round(t - t0, 3),
            "scenario": clock.scenario_at(t),
            "category": category,
            "event_type": event_type,
            "source_context": context,
            "destination": destination,
            "operation": operation,
            "metadata": metadata,
            "risk_indicators": indicators or [],
            "attribution_confidence": confidence,
            "attribution_basis": attribution_basis,
        }

    events: list[dict] = []
    realms: dict[str, int] = {}
    realm_pages: dict[str, set[str]] = {}
    seen_reports: set[tuple] = set()
    duplicates = 0
    max_seq: dict[str, int] = {}
    seq_count: dict[str, int] = {}
    network_reports: list[dict] = []
    legacy_channels: dict[str, list[dict]] = {"dom": [], "storage": [], "api": []}

    for entry in reports:
        raw_event = entry.get("event")
        if not isinstance(raw_event, dict):
            continue
        channel = raw_event.get("channel")
        realm_id = str(raw_event.get("realm_id", ""))
        seq = raw_event.get("report_seq")
        key = (realm_id, seq)
        if realm_id and seq is not None:
            if key in seen_reports:
                duplicates += 1
                continue
            seen_reports.add(key)
            max_seq[realm_id] = max(max_seq.get(realm_id, 0), int(seq))
            seq_count[realm_id] = seq_count.get(realm_id, 0) + 1
        t = _report_time(entry)
        realm = str(raw_event.get("realm", "unknown"))
        realms[realm] = realms.get(realm, 0) + 1
        context = {"service_worker": "service_worker", "background_page": "background_page",
                   "extension_page": "extension_page", "content_script": "content_script",
                   "page_injected": "page_injected_script"}.get(realm, "unknown")
        if channel == "meta":
            realm_pages.setdefault(realm, set()).add(str(raw_event.get("page", "")))
            continue
        if channel == "network":
            network_reports.append({**raw_event, "_t": t})
            continue
        converted = _convert_report(channel, raw_event, t, context, base)
        if converted is not None:
            events.append(converted)
        if channel in legacy_channels:
            legacy = {k: v for k, v in raw_event.items()
                      if k not in ("channel", "t_wall", "report_seq", "realm_id")}
            legacy["ts"] = round(t - t0, 3)
            legacy_channels[channel].append(legacy)

    report_index = ReportIndex(network_reports, ctx.report_window)
    driver_index = DriverIndex([d for d in driver if d.get("kind") == "request"])
    bundle_hosts = set(bundle.get("hosts") or [])
    legacy_network: list[dict] = []
    page_traffic: list[str] = []
    wire_counts = {"http": 0, "extension_attributed": 0, "browser_internal": 0, "page": 0}
    ws_open: dict[int, dict] = {}

    for flow in sorted(flows, key=lambda f: float(f.get("t", 0.0))):
        kind = flow.get("kind")
        t = float(flow.get("t") or t0)
        if kind == "http":
            wire_counts["http"] += 1
            method = str(flow.get("method", "GET")).upper()
            url = str(flow.get("url", ""))
            is_ws = (flow.get("response") or {}).get("source") == "websocket"
            report = report_index.take(url, "WEBSOCKET" if is_ws else method, t)
            attribution = attribute_flow(
                flow, report=report, driver=driver_index.take(url, method),
                bundle_hosts=bundle_hosts, noise_domains=ctx.noise_domains)
            if attribution.context == "page":
                wire_counts["page"] += 1
                page_traffic.append(f"{method} {url}")
            elif attribution.context == "browser_internal":
                wire_counts["browser_internal"] += 1
            else:
                wire_counts["extension_attributed"] += 1
            event = _flow_event(flow, url, method, is_ws, attribution, t, base, bundle_hosts)
            if is_ws:
                ws_open[flow.get("seq")] = event
            events.append(event)
            if attribution.context != "browser_internal":
                legacy_network.append({
                    "ts": round(t - t0, 3), "url": url, "method": method,
                    "initiator": LEGACY_INITIATOR.get(attribution.context, "extension"),
                    "resource_type": (flow.get("headers") or {}).get("sec-fetch-dest", "xhr"),
                    "body_len": int(flow.get("body_len") or 0),
                    **({"extended": True} if is_ws else {}),
                })
        elif kind == "websocket_message":
            opened = ws_open.get(flow.get("open_seq"))
            events.append(base(
                "network", "websocket_message", t,
                context=(opened or {}).get("source_context", "unattributed"),
                destination=flow.get("host"), operation="send",
                metadata={"body_len": flow.get("body_len"), "body_entropy": flow.get("body_entropy"),
                          "marker_hits": flow.get("marker_hits", [])},
                confidence=(opened or {}).get("attribution_confidence", INFERRED),
                attribution_basis=(opened or {}).get("attribution_basis", "websocket_frame"),
                indicators=_marker_indicators(flow.get("marker_hits", []), allowed_host=False),
                unique=flow.get("seq")))
        elif kind in ("connection_failure", "tls_failure", "raw_tcp", "raw_tcp_data"):
            events.append(base(
                "network", kind, t, context="unattributed", destination=flow.get("host"),
                operation="connect",
                metadata={k: flow.get(k) for k in ("error", "port", "body_len", "marker_hits", "url")
                          if flow.get(k) not in (None, "", [])},
                confidence=INFERRED, attribution_basis="wire_only",
                indicators=_marker_indicators(flow.get("marker_hits", []), allowed_host=False),
                unique=flow.get("seq")))

    for report in report_index.unmatched():
        # Code asked for this but the wire never saw it: blocked, cached, or a forged report.
        method = str(report.get("method", "GET")).upper()
        attempted_upload = method in ("POST", "PUT", "PATCH") or int(report.get("body_len") or 0) > 0
        events.append(base(
            "network", "attempt_not_on_wire", report["_t"],
            context={"service_worker": "service_worker", "content_script": "content_script",
                     "background_page": "background_page", "extension_page": "extension_page",
                     }.get(report.get("realm"), "unknown"),
            destination=host_of(str(report.get("url", ""))) or None,
            operation=str(report.get("method", "GET")).upper(),
            metadata={"url": report.get("url"), "resource_type": report.get("resource_type"),
                      "body_len": report.get("body_len"), "ice_server_count": report.get("ice_server_count")},
            confidence=CONFIRMED, attribution_basis="prelude_self_report",
            indicators=["upload", "blocked_before_wire"] if attempted_upload else ["blocked_before_wire"],
            unique=(report.get("realm_id"), report.get("report_seq"))))

    events.sort(key=lambda e: (e["ts"], e["event_id"]))

    coverage = _coverage(run_info, realms, realm_pages, max_seq, seq_count, wire_counts, ctx,
                         summary, duplicates)
    legacy = _legacy_trace(ctx, run_info, bundle, legacy_network, legacy_channels)
    return NormalisedRun(
        events=events, coverage=coverage, legacy_trace=legacy, run_info=run_info,
        preflight=_read_json(raw_dir / "browser" / "preflight.json"),
        gateway_preflight=_read_json(raw_dir / "gateway" / "preflight.json"),
        bundle=bundle,
        parse_problems={"flows": bad_flows, "reports": bad_reports, "driver": bad_driver},
        page_traffic=page_traffic,
    )


def _marker_indicators(hits: list[dict], *, allowed_host: bool) -> list[str]:
    if allowed_host:
        return []
    return sorted({f"marker:{h['sensitivity']}" for h in hits if h.get("location") != "header:cookie"})


def _flow_event(flow: dict, url: str, method: str, is_ws: bool, attribution, t: float, base,
                bundle_hosts: set[str]) -> dict:
    host = flow.get("host", "")
    headers = flow.get("headers") or {}
    is_page = attribution.context == "page"
    # A page's own form posting to its own site is the legitimate route for these values.
    hits = flow.get("marker_hits") or []
    indicators = _marker_indicators(hits, allowed_host=is_page and host in bundle_hosts)
    body_len = int(flow.get("body_len") or 0)
    encoded = sum(1 for _, value in parse_qsl(urlsplit(url).query) if looks_encoded(value))
    is_upload = method in ("POST", "PUT", "PATCH") or body_len > 0 or encoded > 0
    if is_upload and not is_page and attribution.context != "browser_internal":
        indicators.append("upload")
    if encoded:
        indicators.append("encoded_query_parameter")
    if float(flow.get("body_entropy") or 0.0) >= HIGH_ENTROPY:
        indicators.append("high_entropy_body")
    if flow.get("destination_ip"):
        indicators.append("ip_literal_destination")
    return base(
        "network", "websocket_open" if is_ws else "http_request", t,
        context=attribution.context, destination=host, operation=method,
        metadata={
            "url": url, "scheme": flow.get("scheme"), "port": flow.get("port"),
            "destination_ip": flow.get("destination_ip"),
            "request_type": headers.get("sec-fetch-dest"), "request_headers": headers,
            "header_names": flow.get("header_names"), "cookie_names": flow.get("cookie_names"),
            "has_authorization": flow.get("has_authorization"),
            "body_len": body_len, "body_sha256": flow.get("body_sha256"),
            "body_entropy": flow.get("body_entropy"), "body_keys": flow.get("body_keys"),
            "encoded_query_parameters": encoded, "marker_hits": hits,
            "response": flow.get("response"),
        },
        confidence=attribution.confidence, attribution_basis=attribution.basis,
        indicators=indicators, unique=flow.get("seq"))


def _convert_report(channel: str | None, raw: dict, t: float, context: str, base) -> dict | None:
    """One prelude report -> one normalised event, or None for a malformed report."""
    common = dict(context=context, confidence=CONFIRMED, attribution_basis="prelude_self_report",
                  unique=(raw.get("realm_id"), raw.get("report_seq")))
    origin = host_of(str(raw.get("origin", ""))) or None
    if channel == "dom":
        return _dom_event(raw, t, origin, base, common)
    if channel == "storage":
        return _storage_event(raw, t, base, common)
    if channel == "api":
        api = str(raw.get("api", ""))
        generic = _api_generic(api)
        event_type = "event_listener" if api.endswith(".addListener") else "api_call"
        namespace = generic.split(".")[0] if generic else ""
        return base("api", event_type, t, destination=None, operation=generic,
                    metadata={"api": api, "namespace": namespace, "permission": namespace,
                              "arg_count": raw.get("arg_count"), "args": raw.get("args")},
                    **common)
    return None


def _dom_event(raw: dict, t: float, origin: str | None, base, common: dict) -> dict | None:
    kind = str(raw.get("event", ""))
    target = str(raw.get("target", ""))
    meta = raw.get("field") if isinstance(raw.get("field"), dict) else {}
    indicators: list[str] = []
    event_type, operation = kind, kind
    field_class = classify_field(meta, target if kind in ("read", "attr_read") else "")
    metadata = {"target": target, "field_class": field_class, "field": meta,
                "value_len": raw.get("value_len")}

    if kind == "read":
        if target == "document.cookie":
            event_type, field_class = "cookie_read", "cookie"
            metadata["field_class"] = "cookie"
            indicators.append("cookie_access")
        else:
            event_type = "field_read"
    elif kind == "write":
        event_type = "cookie_write"
    elif kind == "attr_read":
        event_type = "field_read"
    elif kind == "query":
        selector_class = classify_selector(target)
        field_class = field_class or selector_class
        metadata["field_class"] = field_class
        metadata["method"] = raw.get("method")
    elif kind == "text_read":
        metadata["prop"] = raw.get("prop")
    elif kind == "listener":
        metadata.update(listener_type=raw.get("listener_type"), capture=raw.get("capture"))
    elif kind == "inject":
        tag = str(raw.get("node_tag", ""))
        event_type = "script_injected" if tag in ("script", "iframe") else "node_injected"
        metadata["node_tag"] = tag
    elif kind == "modify":
        modification = str(raw.get("kind", ""))
        tag = str(raw.get("node_tag", ""))
        metadata.update(kind=modification, node_tag=tag, attribute=raw.get("attribute"),
                        html_len=raw.get("html_len"), contains_script=raw.get("contains_script"),
                        contains_form=raw.get("contains_form"))
        if modification == "form_attribute":
            event_type = "form_modified"
        elif modification == "html_set":
            event_type = "html_injected"
        elif tag in ("script", "iframe") and modification not in ("attribute",):
            event_type = "script_injected"
        else:
            event_type = "element_modified"
    elif kind == "element_created":
        metadata["node_tag"] = target
    elif kind == "activity_summary":
        metadata.update(queries=raw.get("queries"), text_reads=raw.get("text_reads"))
    elif kind in ("form_data_read", "form_submit_call", "clipboard_read"):
        pass
    else:
        return None

    if meta.get("form_has_password") or field_class == "login_form":
        indicators.append("login_form")
    if field_class in ("password", "payment", "otp", "auth_token", "hidden", "account", "personal",
                       "username"):
        indicators.append(f"sensitive_field:{field_class}")
    return base("dom", event_type, t, destination=origin, operation=operation, metadata=metadata,
                indicators=indicators, **common)


def _storage_event(raw: dict, t: float, base, common: dict) -> dict | None:
    api = str(raw.get("api", ""))
    generic = _api_generic(api)
    if not api:
        return None
    key = str(raw.get("key") or "")
    args = raw.get("args") if isinstance(raw.get("args"), list) else []
    indicators: list[str] = []
    area = raw.get("area")
    operation = raw.get("operation")
    if generic.startswith("cookies."):
        method = generic.split(".", 1)[1]
        area = "cookie"
        operation = {"getAll": "read_all", "get": "read", "getAllCookieStores": "read_stores",
                     "set": "write", "remove": "delete"}.get(method, method)
        if method.startswith("get") and args and isinstance(args[0], dict):
            key = str(args[0].get("name") or "")
        indicators.append("cookie_access")
    elif generic.startswith("cookieStore."):
        area = "cookie"
        indicators.append("cookie_access")
    elif generic.startswith("storage."):
        parts = generic.split(".")
        area = f"extension_{parts[1]}" if len(parts) > 2 else "extension_storage"
        method = parts[-1]
        operation = {"get": "read", "getKeys": "read", "getBytesInUse": "read", "set": "write",
                     "remove": "delete", "clear": "clear", "addListener": "listen"}.get(method, method)
        names = []
        if args:
            first = args[0]
            if isinstance(first, dict):
                names = [str(k) for k in first.get("keys", [])] or [str(s) for s in first.get("strings", [])]
            elif isinstance(first, str):
                names = [first.replace("key:", "", 1)]
        key = ",".join(names)[:160]
    area = area or "unknown"
    sensitive = bool(key and _SENSITIVE_STORAGE_KEY.search(key))
    if sensitive:
        indicators.append("sensitive_storage_key")
    return base("storage", str(operation or "access"), t, destination=None, operation=generic,
                metadata={"area": area, "key": key, "api": api, "sensitive_key": sensitive},
                indicators=indicators, **common)


def _match_pattern(pattern: str, url: str) -> bool:
    """Chrome match-pattern test, used only to decide what the scenarios exercised."""
    if pattern == "<all_urls>":
        return True
    match = re.match(r"^(\*|https?|file|ftp)://([^/]*)(/.*)$", pattern)
    if not match:
        return False
    scheme, host, path = match.groups()
    parts = urlsplit(url)
    if scheme != "*" and scheme != parts.scheme:
        return False
    if scheme == "*" and parts.scheme not in ("http", "https"):
        return False
    hostname = parts.hostname or ""
    if host == "*":
        pass
    elif host.startswith("*."):
        if not (hostname == host[2:] or hostname.endswith(host[1:])):
            return False
    elif hostname != host:
        return False
    regex = "^" + re.escape(path).replace(r"\*", ".*") + "$"
    return re.match(regex, parts.path or "/") is not None


def _coverage(run_info: dict, realms: dict, realm_pages: dict, max_seq: dict, seq_count: dict,
              wire: dict, ctx: RunContext, summary: dict, duplicates: int) -> dict:
    """Record what could actually be observed, so silence is never mistaken for good behaviour."""
    manifest = ctx.manifest or {}
    background = manifest.get("background") or {}
    has_background = bool(background.get("service_worker") or background.get("scripts")
                          or background.get("page"))
    content = manifest.get("content_scripts") or []
    has_js_content = any(entry.get("js") for entry in content)
    visited = [page for s in run_info.get("scenarios", []) for page in s.get("pages", [])]
    content_applicable = any(
        _match_pattern(pattern, url)
        for entry in content if entry.get("js")
        for pattern in entry.get("matches") or []
        for url in visited)

    background_seen = any(realms.get(r) for r in ("service_worker", "background_page"))
    content_seen = bool(realms.get("content_script") or realms.get("page_injected"))
    scenarios = run_info.get("scenarios", [])
    completed = [s for s in scenarios if s.get("status") == "completed"]
    lost = sum(max(0, max_seq[r] - seq_count.get(r, 0)) for r in max_seq)

    problems: list[str] = []
    notes: list[str] = []
    if run_info.get("status") != "completed":
        problems.append(f"browser run did not complete: {run_info.get('error', 'no result recorded')}")
    if not run_info.get("extension_loaded"):
        problems.append("the extension was not confirmed loaded in the browser")
    if scenarios and not completed:
        problems.append("no browsing scenario completed")
    if wire["http"] == 0:
        problems.append("the gateway saw no network traffic, so the network monitor did not work")
    elif wire["page"] == 0:
        problems.append("the gateway saw no page traffic, so the scripted browsing did not reach it")
    if has_background and not background_seen:
        problems.append("the declared background code never reported that it started, so its "
                        "instrumentation failed or the code never ran")
    if has_js_content and content_applicable and not content_seen:
        problems.append("content scripts match the visited pages but never reported that they "
                        "started, so their instrumentation failed or the browser did not inject them")
    if has_js_content and not content_applicable:
        notes.append("content scripts do not match any page visited here, so their behaviour was "
                     "not exercised")
    if not has_background and not has_js_content:
        notes.append("the manifest declares no background or content script, so little behaviour "
                     "can be observed")
    if lost:
        notes.append(f"{lost} instrumentation reports were lost or dropped")
    if summary.get("flows_truncated") or summary.get("reports_truncated"):
        problems.append("evidence hit its size ceiling and was truncated")
    failed = [s["name"] for s in scenarios if s.get("status") != "completed"]
    if failed:
        notes.append(f"scenarios that failed: {', '.join(failed)}")

    def channel(has_reports: bool) -> str:
        if problems and not has_reports:
            return "failed"
        return "ok" if has_reports else "no_events"

    dom_or_storage_seen = bool(realms)
    return {
        "complete": not problems,
        "problems": problems,
        "notes": notes,
        "realms_seen": realms,
        "pages_with_content_script": sorted(realm_pages.get("content_script", set())),
        "expected": {"background": has_background, "content_scripts": has_js_content,
                     "content_scripts_match_visited_pages": content_applicable},
        "dimensions": {
            "network": "ok" if wire["http"] and wire["page"] else "failed",
            "dom": channel(bool(realms.get("content_script") or realms.get("page_injected")
                                or realms.get("extension_page"))),
            "storage": channel(dom_or_storage_seen),
            "api": channel(dom_or_storage_seen),
        },
        "wire_counts": wire,
        "scenarios_completed": len(completed),
        "scenarios_total": len(scenarios),
        "reports_lost": lost,
        "duplicate_reports_dropped": duplicates,
    }


def _legacy_trace(ctx: RunContext, run_info: dict, bundle: dict, network: list[dict],
                  channels: dict) -> dict:
    """The same run in the v0.1 trace shape, so existing features and the model can read it."""
    trace = {
        "schema_version": SCHEMA_VERSION,
        "extension": {"id": ctx.extension_id, "name": ctx.manifest.get("name", "unknown"),
                      "version": ctx.extension_version},
        "run": {
            "browser": ctx.browser,
            "scenario": "+".join(s.get("name", "") for s in run_info.get("scenarios", [])) or "none",
            "replay_bundle": bundle.get("digest"),
            "started_at": None,
            "duration_s": run_info.get("seconds"),
            "pages": [p for s in run_info.get("scenarios", []) for p in s.get("pages", [])],
        },
        "manifest": ctx.manifest,
        "network": network,
        "dom": channels["dom"],
        "storage": channels["storage"],
        "api": channels["api"],
    }
    return trace


def slice_legacy_trace(trace: dict, events: list[dict], scenario: str, pages: list[str]) -> dict:
    """A legacy trace restricted to one scenario's time range.

    The trained model saw deltas from single-scenario runs, so it gets the same kind of input here.
    """
    in_scenario = [e["ts"] for e in events if e["scenario"] == scenario]
    if not in_scenario:
        lo, hi = 0.0, -1.0
    else:
        lo, hi = min(in_scenario), max(in_scenario)
    view = dict(trace)
    view["run"] = {**trace["run"], "scenario": scenario, "pages": list(pages)}
    for channel in ("network", "dom", "storage", "api"):
        view[channel] = [e for e in trace[channel] if lo <= float(e.get("ts", 0.0)) <= hi]
    return view


def declared_hosts(manifest: dict) -> set[str]:
    """Hostnames the manifest names explicitly, for telling expected traffic from unexpected."""
    normal = normalise_manifest(manifest or {})
    hosts: set[str] = set()
    for pattern in list(normal["host_permissions"]) + list(normal["content_script_matches"]):
        match = re.match(r"^[^:]+://(\*\.)?([^/*]+)", pattern)
        if match:
            hosts.add(registrable_domain(match.group(2).lower()))
    homepage = (manifest or {}).get("homepage_url")
    if isinstance(homepage, str):
        host = host_of(homepage)
        if host:
            hosts.add(registrable_domain(host))
    return hosts


def targeted_hosts_from_manifests(manifests: list[dict], bundle_hosts: set[str], limit: int,
                                  extra: list[str] | None = None) -> list[str]:
    """Literal hostnames named by any version's manifest, for gated-payload elicitation.

    The union over both versions, sorted, keeps the scenario identical for each run.
    """
    hosts: set[str] = set(extra or [])
    for manifest in manifests:
        normal = normalise_manifest(manifest or {})
        for pattern in list(normal["host_permissions"]) + list(normal["content_script_matches"]):
            match = re.match(r"^[^:]+://(\*\.)?([^/*:]+)", pattern)
            if not match:
                continue
            host = match.group(2).lower()
            hosts.add(("www." + host) if match.group(1) else host)
    hosts = {h for h in hosts if h not in bundle_hosts and not h.endswith(".test")}
    return sorted(hosts)[:limit]


def events_from_legacy_trace(trace: dict, analysis_id: str = "legacy") -> list[dict]:
    """Normalised events from a v0.1 trace, so existing labelled data can evaluate the scorer.

    Legacy traces hold no wire record, attribution evidence or marker hits, so scores from this
    path can only under-represent what a Docker run would observe. It exists for evaluation.
    """
    extension = trace.get("extension", {})
    t0 = 0.0

    def base(category, event_type, t, *, context, destination, operation, metadata, confidence,
             attribution_basis, indicators=None, unique=""):
        return {
            "event_id": _event_id(analysis_id, extension.get("version"), category, event_type, t, unique),
            "analysis_id": analysis_id, "extension_id": extension.get("id"),
            "extension_version": extension.get("version"), "browser": trace.get("run", {}).get("browser"),
            "timestamp": None, "ts": round(float(t) - t0, 3),
            "scenario": trace.get("run", {}).get("scenario", "scenario"),
            "category": category, "event_type": event_type, "source_context": context,
            "destination": destination, "operation": operation, "metadata": metadata,
            "risk_indicators": indicators or [], "attribution_confidence": confidence,
            "attribution_basis": attribution_basis,
        }

    events: list[dict] = []
    for i, e in enumerate(trace.get("network", [])):
        initiator = e.get("initiator", "page")
        url = str(e.get("url", ""))
        method = str(e.get("method", "GET")).upper()
        body_len = int(e.get("body_len") or 0)
        encoded = sum(1 for _, v in parse_qsl(urlsplit(url).query) if looks_encoded(v))
        is_ext = initiator != "page"
        indicators = []
        if is_ext and (method in ("POST", "PUT", "PATCH") or body_len or encoded):
            indicators.append("upload")
        events.append(base(
            "network", "http_request", float(e.get("ts", 0.0)),
            context=initiator if initiator in ("page", "content_script", "service_worker") else "extension",
            destination=host_of(url) or None, operation=method,
            metadata={"url": url, "body_len": body_len, "marker_hits": []},
            confidence=CONFIRMED, attribution_basis="legacy_trace", indicators=indicators, unique=i))
    for i, e in enumerate(trace.get("dom", [])):
        raw = {**e, "realm_id": "legacy", "report_seq": i}
        tag = str(e.get("target", "")).split(".")[0].split("#")[0].lower()
        if e.get("event") == "inject":
            raw["node_tag"] = tag
        common = dict(context="content_script", confidence=CONFIRMED,
                      attribution_basis="legacy_trace", unique=("dom", i))
        event = _dom_event(raw, float(e.get("ts", 0.0)), None, base, common)
        if event:
            events.append(event)
    for i, e in enumerate(trace.get("storage", [])):
        common = dict(context="service_worker", confidence=CONFIRMED,
                      attribution_basis="legacy_trace", unique=("storage", i))
        event = _storage_event(dict(e), float(e.get("ts", 0.0)), base, common)
        if event:
            events.append(event)
    for i, e in enumerate(trace.get("api", [])):
        common = dict(context=str(e.get("frame") or "service_worker"), confidence=CONFIRMED,
                      attribution_basis="legacy_trace", unique=("api", i))
        generic = _api_generic(str(e.get("api", "")))
        events.append(base("api", "api_call", float(e.get("ts", 0.0)), destination=None, operation=generic,
                           metadata={"api": e.get("api"), "namespace": generic.split(".")[0],
                                     "permission": generic.split(".")[0], "args": None}, **common))
    events.sort(key=lambda ev: (ev["ts"], ev["event_id"]))
    return events
