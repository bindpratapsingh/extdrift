"""Trace -> feature vector.  This is ``f(.)`` in ``delta = f(T2) - f(T1)``.

Every feature here is (a) cheap to compute, (b) explainable in one sentence to an
examiner, and (c) traceable to a behaviour described in the literature.  The
``FEATURE_DOCS`` table below is the single source of truth for that mapping and is
rendered straight into the report, so a verdict can always be read back to the paper
that motivated the feature.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlsplit, parse_qsl

# --------------------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------------------

#: Input names / selectors whose contents are credentials or other secrets.
#: 'mnemonic'/'seed' cover crypto-wallet theft, the dominant 2024-25 extension payload.
SENSITIVE_TARGET_RE = re.compile(
    r"password|passwd|\bpwd\b|credit|cardnum|card-num|cc-num|\bcvv\b|\bssn\b|"
    r"\botp\b|2fa|mnemonic|seed[-_ ]?phrase|private[-_ ]?key|api[-_ ]?key|"
    r"session|auth|token|document\.cookie",
    re.IGNORECASE,
)

#: A weaker signal than the above: identity, not secrets.  Tracked separately so we do
#: not conflate "this extension reads your email address" with "it reads your password".
IDENTITY_TARGET_RE = re.compile(r"email|e-mail|username|\buser\b|phone|mobile", re.IGNORECASE)

#: chrome.* / browser.* namespaces that grant access to data worth stealing, or to
#: traffic worth tampering with.  Sourced from the MV3 permission docs and from the
#: capability set abused in the Cyberhaven (Dec 2024) campaign.
HIGH_RISK_API_RE = re.compile(
    r"^(chrome|browser)\.("
    r"cookies|webRequest|declarativeNetRequest|scripting|debugger|proxy|history|"
    r"downloads|management|nativeMessaging|clipboard|privacy|contentSettings|"
    r"identity|tabs\.(query|captureVisibleTab|executeScript)"
    r")",
    re.IGNORECASE,
)

#: Permissions that materially widen what an update is able to do.
HIGH_RISK_PERMISSIONS = frozenset({
    "cookies", "webRequest", "webRequestBlocking", "declarativeNetRequest",
    "declarativeNetRequestWithHostAccess", "scripting", "tabs", "debugger", "proxy",
    "history", "downloads", "management", "nativeMessaging", "clipboardRead",
    "privacy", "contentSettings", "identity", "webNavigation", "browsingData",
})

#: Host patterns that mean "this extension may act on every site you visit".
BROAD_HOST_PATTERNS = frozenset({"<all_urls>", "*://*/*", "http://*/*", "https://*/*"})

#: A sensitive read followed by an outbound request within this many seconds counts as
#: one candidate exfiltration flow.  10 s is generous on purpose: we want recall here,
#: and the rule layer decides what to do with the count.
EXFIL_WINDOW_S = 10.0

#: Query-string values at least this long and this random-looking are treated as an
#: encoded payload rather than an ordinary identifier.
ENCODED_MIN_LEN = 24
ENCODED_MIN_ENTROPY = 3.5

_BASE64ISH_RE = re.compile(r"^[A-Za-z0-9+/=_-]{" + str(ENCODED_MIN_LEN) + r",}$")


def shannon_entropy(s: str) -> float:
    """Bits of entropy per character.  Random-looking blobs score ~4-6; words score ~3."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_encoded(value: str) -> bool:
    """True if *value* looks like base64/hex-encoded data rather than a plain identifier."""
    return bool(_BASE64ISH_RE.match(value)) and shannon_entropy(value) >= ENCODED_MIN_ENTROPY


def host_of(url: str) -> str:
    """Lower-cased hostname of *url*, or '' when it has none (e.g. a data: URL)."""
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def registrable_domain(hostname: str) -> str:
    """Best-effort eTLD+1 without a public-suffix dependency.

    Handles the common two-label public suffixes we actually meet in the corpus
    (``co.uk``, ``com.au``, ...).  A full Public Suffix List lookup is a drop-in
    upgrade; it is not worth a dependency while the scenario set is fixed and known.
    """
    parts = [p for p in hostname.split(".") if p]
    if len(parts) <= 2:
        return hostname
    two_label_suffixes = {"co", "com", "net", "org", "gov", "ac", "edu"}
    if parts[-2] in two_label_suffixes and len(parts[-1]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# --------------------------------------------------------------------------------------
# Feature catalogue
# --------------------------------------------------------------------------------------

#: name -> (one-line meaning, provenance).  Provenance names the paper or incident that
#: makes the feature worth measuring; the report prints it next to any fired rule.
FEATURE_DOCS: dict[str, tuple[str, str]] = {
    "net_requests":            ("Total network requests observed", "ExtPrivA S&P'23"),
    "net_hosts":               ("Distinct hostnames contacted", "ExtPrivA S&P'23"),
    "net_third_party_hosts":   ("Hosts outside the visited pages' own domains", "ExtPrivA S&P'23"),
    "net_ext_initiated":       ("Requests initiated by extension code, not the page", "ExtPrivA S&P'23"),
    "net_posts":               ("POST/PUT/PATCH requests", "Hulk USENIX'14"),
    "net_upload_bytes":        ("Total bytes uploaded in request bodies", "Hulk USENIX'14"),
    "net_max_upload_bytes":    ("Largest single upload", "Hulk USENIX'14"),
    "net_encoded_params":      ("Query parameters carrying encoded/high-entropy blobs", "WRIT TDSC'24"),
    "net_worker_initiated":    ("Requests from an MV3 service worker (no page needed)", "Karami NDSS'21"),
    "dom_reads":               ("DOM read events", "VEX NDSS'10"),
    "dom_sensitive_reads":     ("Reads of credential/secret-bearing fields", "ExtPrivA S&P'23"),
    "dom_identity_reads":      ("Reads of identity fields (email, username)", "ExtPrivA S&P'23"),
    "dom_injections":          ("Nodes injected into the page", "VEX NDSS'10"),
    "storage_calls":           ("Cookie / storage API calls", "Cyberhaven Dec'24"),
    "cookie_reads":            ("Cookie read operations", "Cyberhaven Dec'24"),
    "cookie_bulk_reads":       ("Whole-jar cookie reads (getAll)", "Cyberhaven Dec'24"),
    "api_calls":               ("Extension-API calls", "Hulk USENIX'14"),
    "api_distinct":            ("Distinct extension APIs used", "Hulk USENIX'14"),
    "api_high_risk":           ("Calls into high-risk API namespaces", "MV3 permission model"),
    "perm_count":              ("Declared permissions", "VEX NDSS'10"),
    "perm_high_risk":          ("Declared permissions from the high-risk set", "VEX NDSS'10"),
    "host_perm_breadth":       ("1.0 when the extension may act on every site", "VEX NDSS'10"),
    "exfil_flows":             ("Sensitive read followed by an outbound request", "ExtPrivA S&P'23"),
    "exfil_flows_third_party": ("...where the destination is a third-party host", "Cyberhaven Dec'24"),
}

#: Stable column order.  The ML tier consumes vectors in exactly this order, so it must
#: never be reordered - only appended to (with a schema_version bump).
FEATURE_ORDER = tuple(FEATURE_DOCS)


def _first_party_domains(trace: dict) -> set[str]:
    """Domains that legitimately belong to the scenario being replayed.

    Taken from the scripted page list when the sandbox recorded one (it always does for
    our own scenarios), else inferred from top-level document requests.
    """
    pages = trace.get("run", {}).get("pages") or []
    domains = {registrable_domain(host_of(u)) for u in pages}
    if not domains:
        domains = {
            registrable_domain(host_of(e["url"]))
            for e in trace.get("network", [])
            if e.get("resource_type") == "document"
        }
    domains.discard("")
    return domains


def _sensitive_read_times(trace: dict) -> list[float]:
    """Timestamps at which the extension got hold of something worth stealing."""
    times = []
    for e in trace.get("dom", []):
        if e.get("event") == "read" and SENSITIVE_TARGET_RE.search(str(e.get("target", ""))):
            times.append(float(e.get("ts", 0.0)))
    for e in trace.get("storage", []):
        if "cookie" in str(e.get("api", "")).lower():
            times.append(float(e.get("ts", 0.0)))
    return sorted(times)


def _is_upload(event: dict) -> bool:
    """True if this request carries data outwards rather than merely fetching."""
    if str(event.get("method", "GET")).upper() in ("POST", "PUT", "PATCH"):
        return True
    if int(event.get("body_len", 0) or 0) > 0:
        return True
    query = urlsplit(str(event.get("url", ""))).query
    return any(looks_encoded(value) for _, value in parse_qsl(query))


def _count_exfil_flows(trace: dict, first_party: set[str]) -> tuple[int, int]:
    """Pair each sensitive read with extension uploads that follow it closely.

    This is deliberately a *lite* taint approximation: temporal adjacency, not real
    data-flow tracking.  It is the tabular stand-in for the data-flow graph a Tier-2
    graph model would learn properly (docs/design/MODEL_PLAN.md), and it is reported as
    a candidate flow, never as proof.
    """
    reads = _sensitive_read_times(trace)
    if not reads:
        return 0, 0

    uploads = [
        e for e in trace.get("network", [])
        if e.get("initiator") in ("extension", "content_script", "service_worker")
        and _is_upload(e)
    ]

    flows = third_party_flows = 0
    for event in uploads:
        ts = float(event.get("ts", 0.0))
        if any(0 <= ts - r <= EXFIL_WINDOW_S for r in reads):
            flows += 1
            if registrable_domain(host_of(event["url"])) not in first_party:
                third_party_flows += 1
    return flows, third_party_flows


def split_permissions(manifest: dict) -> tuple[set[str], set[str]]:
    """Return (api_permissions, host_permissions) for either MV2 or MV3.

    MV2 kept host match patterns inside ``permissions``; MV3 moved them to
    ``host_permissions``.  Folding them apart makes MV2 and MV3 extensions produce
    comparable vectors, which matters because real update pairs straddle the migration.
    """
    permissions = set(manifest.get("permissions", []) or [])
    host_permissions = set(manifest.get("host_permissions", []) or [])
    host_permissions |= {p for p in permissions if "://" in p or p == "<all_urls>"}
    return permissions - host_permissions, host_permissions


def extract_features(trace: dict) -> dict[str, float]:
    """Reduce one validated trace to the flat feature vector defined by FEATURE_ORDER."""
    network = trace.get("network", [])
    dom = trace.get("dom", [])
    storage = trace.get("storage", [])
    api = trace.get("api", [])

    first_party = _first_party_domains(trace)
    hosts = {host_of(e["url"]) for e in network} - {""}
    third_party = {h for h in hosts if registrable_domain(h) not in first_party}

    ext_initiated = [e for e in network
                     if e.get("initiator") in ("extension", "content_script", "service_worker")]
    uploads = [int(e.get("body_len", 0) or 0) for e in network]

    encoded_params = sum(
        1
        for e in network
        for _, value in parse_qsl(urlsplit(str(e.get("url", ""))).query)
        if looks_encoded(value)
    )

    permissions, host_permissions = split_permissions(trace.get("manifest", {}))
    flows, third_party_flows = _count_exfil_flows(trace, first_party)

    features = {
        "net_requests": float(len(network)),
        "net_hosts": float(len(hosts)),
        "net_third_party_hosts": float(len(third_party)),
        "net_ext_initiated": float(len(ext_initiated)),
        "net_posts": float(sum(1 for e in network
                               if str(e.get("method", "GET")).upper() in ("POST", "PUT", "PATCH"))),
        "net_upload_bytes": float(sum(uploads)),
        "net_max_upload_bytes": float(max(uploads, default=0)),
        "net_encoded_params": float(encoded_params),
        "net_worker_initiated": float(sum(1 for e in network
                                          if e.get("initiator") == "service_worker")),
        "dom_reads": float(sum(1 for e in dom if e.get("event") == "read")),
        "dom_sensitive_reads": float(sum(
            1 for e in dom
            if e.get("event") == "read" and SENSITIVE_TARGET_RE.search(str(e.get("target", ""))))),
        "dom_identity_reads": float(sum(
            1 for e in dom
            if e.get("event") == "read" and IDENTITY_TARGET_RE.search(str(e.get("target", ""))))),
        "dom_injections": float(sum(1 for e in dom if e.get("event") == "inject")),
        "storage_calls": float(len(storage)),
        "cookie_reads": float(sum(1 for e in storage
                                  if "cookie" in str(e.get("api", "")).lower())),
        "cookie_bulk_reads": float(sum(
            1 for e in storage
            if "getall" in str(e.get("api", "")).lower().replace("_", ""))),
        "api_calls": float(len(api)),
        "api_distinct": float(len({e.get("api") for e in api})),
        "api_high_risk": float(sum(1 for e in api
                                   if HIGH_RISK_API_RE.match(str(e.get("api", ""))))),
        "perm_count": float(len(permissions)),
        "perm_high_risk": float(len(permissions & HIGH_RISK_PERMISSIONS)),
        "host_perm_breadth": (1.0 if (host_permissions & BROAD_HOST_PATTERNS)
                              else min(1.0, len(host_permissions) / 10.0)),
        "exfil_flows": float(flows),
        "exfil_flows_third_party": float(third_party_flows),
    }
    assert set(features) == set(FEATURE_ORDER), "feature catalogue drifted from FEATURE_DOCS"
    return features


def feature_vector(trace: dict) -> list[float]:
    """The same features as a plain ordered list, for the ML tier."""
    values = extract_features(trace)
    return [values[name] for name in FEATURE_ORDER]
