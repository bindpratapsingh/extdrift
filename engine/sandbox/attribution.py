"""Who caused a request? Every answer carries how it is known.

A wire record alone cannot say which code issued a request, and treating every browser request as
the extension's would be wrong in both directions. Each request is attributed from the strongest
evidence available:

    confirmed   prelude self-report, an extension ``Origin`` header, or the browser's own report
                that the request came from a service worker, or a scripted navigation
    inferred    reasoning from context: the fixed web cannot have asked for this host, or the
                host is a known browser background service

Extension code that avoids the hooked APIs can reach only the inferred tiers. An attacker can
also deliberately use a host on the browser-noise list. That combination is suppressed only when
no synthetic marker is present, and the residual blind spot is documented in docs/SANDBOX.md.
"""

from __future__ import annotations

from dataclasses import dataclass

CONFIRMED = "confirmed"
INFERRED = "inferred"

EXTENSION_SCHEMES = ("chrome-extension://", "moz-extension://")

#: Report realm -> source context for an attributed request.
REALM_CONTEXT = {
    "service_worker": "service_worker", "background_page": "background_page",
    "extension_page": "extension_page", "content_script": "content_script",
    "page_injected": "page_injected_script",
}
#: Source context -> the initiator vocabulary of the legacy trace schema.
LEGACY_INITIATOR = {
    "page": "page", "service_worker": "service_worker", "content_script": "content_script",
    "background_page": "extension", "extension_page": "extension", "extension": "extension",
    "page_injected_script": "content_script", "extension_induced": "content_script",
    "unattributed": "extension",
}


@dataclass(frozen=True)
class Attribution:
    context: str
    confidence: str
    basis: str


def domain_matches(host: str, domains: list[str] | set[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _without_scheme(url: str) -> str:
    return url.split("://", 1)[-1]


class ReportIndex:
    """Prelude network self-reports, consumed as they are matched to wire requests.

    Schemes are ignored because the browser may upgrade http to https, and because a WebSocket's
    ws(s) URL reaches the proxy as an http(s) upgrade request. Either way it is the same request.
    """

    def __init__(self, reports: list[dict], window: float):
        self.window = window
        self.items = [dict(r) for r in reports]

    def take(self, url: str, method: str, t: float) -> dict | None:
        best, best_gap = None, None
        target = _without_scheme(url)
        for item in self.items:
            if item.get("_used") or _without_scheme(str(item.get("url", ""))) != target:
                continue
            if str(item.get("method", "GET")).upper() != method:
                continue
            gap = abs(item["_t"] - t)
            if gap <= self.window and (best_gap is None or gap < best_gap):
                best, best_gap = item, gap
        if best is not None:
            best["_used"] = True
        return best

    def unmatched(self) -> list[dict]:
        return [item for item in self.items if not item.get("_used")]


class DriverIndex:
    """The browser driver's view of requests. Low trust, so it only adds detail."""

    def __init__(self, records: list[dict]):
        self.by_key: dict[tuple[str, str], list[dict]] = {}
        for record in records:
            self.by_key.setdefault((record.get("url", ""), record.get("method", "")), []).append(record)

    def take(self, url: str, method: str) -> dict | None:
        bucket = self.by_key.get((url, method))
        return bucket.pop(0) if bucket else None


def attribute_flow(flow: dict, *, report: dict | None, driver: dict | None, bundle_hosts: set[str],
                   noise_domains: list[str]) -> Attribution:
    """Attribute one HTTP flow using the strongest available evidence."""
    host = flow.get("host", "")
    headers = flow.get("headers") or {}
    origin = headers.get("origin", "")
    referer = headers.get("referer", "")
    has_markers = any(h.get("location") != "header:cookie" for h in flow.get("marker_hits", []))

    if report is not None:
        context = REALM_CONTEXT.get(report.get("realm"), "extension")
        return Attribution(context, CONFIRMED, "prelude_self_report")
    if driver is not None and driver.get("from_service_worker"):
        return Attribution("service_worker", CONFIRMED, "browser_worker_flag")
    if origin.startswith(EXTENSION_SCHEMES) or referer.startswith(EXTENSION_SCHEMES):
        return Attribution("extension", CONFIRMED, "extension_origin_header")
    is_navigation = headers.get("sec-fetch-mode") == "navigate"
    if host in bundle_hosts:
        if is_navigation:
            return Attribution("page", CONFIRMED, "navigation_within_fixed_web")
        return Attribution("page", INFERRED, "host_in_fixed_web")
    if not has_markers and domain_matches(host, noise_domains):
        return Attribution("browser_internal", INFERRED, "known_browser_service")
    if referer or (driver is not None and driver.get("frame_url")):
        # The fixed web never asks for this host, so something added this request to the page.
        return Attribution("extension_induced", INFERRED, "outside_fixed_web")
    return Attribution("unattributed", INFERRED, "outside_fixed_web_no_page_context")
