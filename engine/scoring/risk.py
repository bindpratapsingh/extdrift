"""The explainable 0-100 behavioural risk score.

This sits beside the 12-rule scorer in :mod:`engine.scoring.rules` rather than replacing it: that
scorer works on the legacy delta, is pinned by the tests and supplies the dataset's ``rule_score``.
This one works on behaviours, so it can also score a single version (Mode A), use marker evidence
and attribution confidence, and report 0-100.

The score represents **observed behavioural risk**. It is not the probability that an extension
is malicious, and a low score does not show that an extension is safe.

Combination rule: within a cluster, only the strongest indicator counts, so one underlying
behaviour cannot be counted twice through related indicators. A host already counted as an
exfiltration destination is also not counted again as a merely unexpected destination. Clusters
then combine as a noisy-OR, the same rule the existing scorer uses:
``score = 100 * (1 - product(1 - weight * confidence * change))``.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    """One fired indicator and the behaviours that fired it."""

    indicator: str
    weight: float
    effective_weight: float
    cluster: str
    why: str
    direct_evidence: bool
    behaviours: list[dict] = field(default_factory=list)
    summary: str = ""
    confidence: str = "confirmed"
    change: str | None = None
    counted: bool = True
    contribution: float = 0.0

    def as_dict(self) -> dict:
        return {
            "indicator": self.indicator, "summary": self.summary, "why": self.why,
            "weight": self.weight, "effective_weight": round(self.effective_weight, 4),
            "cluster": self.cluster, "direct_evidence": self.direct_evidence,
            "attribution_confidence": self.confidence, "change": self.change,
            "counted_in_score": self.counted, "risk_contribution": round(self.contribution, 1),
            "behaviours": [_evidence(b) for b in self.behaviours[:6]],
        }


def _evidence(behaviour: dict) -> dict:
    return {key: behaviour.get(key) for key in (
        "signature", "label", "category", "count", "scenarios", "contexts", "targets", "first_timestamp",
        "attribution_confidence", "event_ids", "details", "change", "baseline_count", "candidate_count")
        if behaviour.get(key) not in (None, [], {})}


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _has(behaviour: dict, *tags: str) -> bool:
    return any(tag in behaviour["tags"] for tag in tags)


def _field_read(b: dict, *classes: str) -> bool:
    return b["signature"].startswith("dom:field_read:") and any(f"field:{c}" in b["tags"] for c in classes)


def _scenario_phrase(behaviours: list[dict]) -> str:
    scenarios = {s for b in behaviours for s in b["scenarios"]} - {"startup"}
    return f" in {_plural(len(scenarios), 'test scenario')}" if scenarios else ""


def _targets(behaviours: list[dict], limit: int = 4) -> str:
    targets = sorted({t for b in behaviours for t in b["targets"]})
    if not targets:
        return ""
    shown = ", ".join(targets[:limit])
    return f" ({shown}{', ...' if len(targets) > limit else ''})"


def _marker_kinds(behaviours: list[dict], sensitivity: str) -> str:
    kinds = sorted({m["kind"] for b in behaviours for m in b["details"].get("markers", [])
                    if m.get("sensitivity") == sensitivity})
    return ", ".join(kinds)


#: indicator -> behaviour predicate. Order only affects how findings list.
PREDICATES = {
    "credential_exfiltration": lambda b: _has(b, "exfil:credential"),
    "session_exfiltration": lambda b: _has(b, "exfil:session"),
    "financial_exfiltration": lambda b: _has(b, "exfil:financial"),
    "pii_exfiltration": lambda b: _has(b, "exfil:pii"),
    "temporal_exfiltration_candidate": lambda b: (
        b["category"] == "network" and _has(b, "after_sensitive_read") and _has(b, "upload")
        and not any(t.startswith("exfil:") for t in b["tags"]) and not _has(b, "in_fixed_web")),
    "credential_field_read": lambda b: _field_read(b, "password", "payment", "otp"),
    "key_capture": lambda b: (
        _has(b, "key_listener") and (b["signature"].endswith(":root") or
                                     any(f"field:{c}" in b["tags"] for c in ("password", "payment", "otp")))),
    "form_capture": lambda b: b["signature"] == "dom:form_data_read",
    "credential_field_lookup": lambda b: (
        b["signature"].startswith("dom:query:")
        and b["signature"].split(":")[2] in ("password", "login_form", "payment", "otp")),
    "cookie_bulk_read": lambda b: b["signature"].startswith("cookie:read_all"),
    "cookie_read": lambda b: (b["signature"] == "dom:cookie_read"
                              or b["signature"].startswith(("cookie:read:", "cookie:read_stores"))),
    "sensitive_storage_read": lambda b: (
        b["category"] == "storage" and _has(b, "sensitive_storage_key")
        and _has(b, "operation:read")),
    "sensitive_page_data_read": lambda b: (
        (b["signature"].startswith("dom:text_read:") and any(
            f"field:{c}" in b["tags"] for c in ("account", "personal", "auth_token", "hidden")))
        or _field_read(b, "auth_token", "hidden", "account", "personal")),
    "routine_storage": lambda b: (
        b["category"] == "storage" and not b["signature"].startswith("cookie:")
        and not _has(b, "sensitive_storage_key")),
    "beaconing": lambda b: _has(b, "beacon"),
    "suspicious_upload_destination": lambda b: (
        b["category"] == "network" and _has(b, "upload") and _has(b, "low_reputation")
        and not _has(b, "in_fixed_web")),
    "unexpected_upload": lambda b: (
        b["category"] == "network" and _has(b, "upload") and _has(b, "undeclared_host")
        and _has(b, "large_upload")),
    "small_telemetry": lambda b: (
        b["category"] == "network" and _has(b, "upload") and not _has(b, "large_upload")
        and _has(b, "undeclared_host")),
    "new_external_contact": lambda b: (
        b["category"] == "network" and not _has(b, "upload") and _has(b, "undeclared_host")),
    "websocket_channel": lambda b: _has(b, "websocket") and b["signature"].startswith("net:ws:"),
    "form_tampering": lambda b: b["signature"].startswith("dom:form_modified:"),
    "overlay_form_injection": lambda b: b["signature"] == "dom:html_injected:form",
    "script_injection": lambda b: b["signature"].startswith("dom:script_injected:"),
    "routine_dom_change": lambda b: b["signature"].startswith(
        ("dom:node_injected", "dom:element_modified", "dom:html_injected:plain")),
    "privileged_api_use": lambda b: _has(b, "privileged_api"),
}

_DESTINATION_INDICATORS = {"suspicious_upload_destination", "unexpected_upload", "small_telemetry",
                           "new_external_contact", "websocket_channel", "beaconing"}
_EXFIL_INDICATORS = {"credential_exfiltration", "session_exfiltration", "financial_exfiltration",
                     "pii_exfiltration"}

_SUMMARIES = {
    "credential_exfiltration": lambda b: f"Synthetic credential values ({_marker_kinds(b, 'credential')}) were sent to {_hosts(b)}",
    "session_exfiltration": lambda b: f"Synthetic session values ({_marker_kinds(b, 'session')}) were sent to {_hosts(b)}",
    "financial_exfiltration": lambda b: f"Synthetic financial values ({_marker_kinds(b, 'financial')}) were sent to {_hosts(b)}",
    "pii_exfiltration": lambda b: f"Synthetic personal data ({_marker_kinds(b, 'pii')}) was sent to {_hosts(b)}",
    "temporal_exfiltration_candidate": lambda b: f"{_plural(_count(b), 'upload')} to {_hosts(b)} shortly after sensitive data was read",
    "credential_field_read": lambda b: f"Read credential or payment field values {_plural(_count(b), 'time')}{_scenario_phrase(b)}{_targets(b)}",
    "key_capture": lambda b: f"Registered {_plural(_count(b), 'keystroke or input listener')}{_targets(b)}",
    "form_capture": lambda b: f"Captured {_plural(_count(b), 'whole form')}{_scenario_phrase(b)}",
    "credential_field_lookup": lambda b: f"Looked up password or login elements {_plural(_count(b), 'time')}{_scenario_phrase(b)}",
    "cookie_bulk_read": lambda b: f"Read the entire cookie jar {_plural(_count(b), 'time')}{_scenario_phrase(b)}",
    "cookie_read": lambda b: f"Read cookies {_plural(_count(b), 'time')}{_scenario_phrase(b)}",
    "sensitive_storage_read": lambda b: f"Read credential-like storage keys{_targets(b)}",
    "sensitive_page_data_read": lambda b: f"Read hidden tokens or sensitive page text {_plural(_count(b), 'time')}{_scenario_phrase(b)}",
    "routine_storage": lambda b: f"{_plural(_count(b), 'routine storage operation')}",
    "beaconing": lambda b: f"Regular repeated requests to {_hosts(b)}",
    "suspicious_upload_destination": lambda b: f"Uploaded data to a generated-looking host: {_hosts(b)}",
    "unexpected_upload": lambda b: f"Uploaded a substantial payload to {_hosts(b)}, which the manifest does not name",
    "small_telemetry": lambda b: f"Small upload to {_hosts(b)}, with no recognised sensitive data",
    "new_external_contact": lambda b: f"Fetched from {_hosts(b)}, which the manifest does not name",
    "websocket_channel": lambda b: f"Opened a WebSocket to {_hosts(b)}",
    "form_tampering": lambda b: f"Changed form attributes {_plural(_count(b), 'time')}{_scenario_phrase(b)}",
    "overlay_form_injection": lambda b: f"Injected HTML containing a form {_plural(_count(b), 'time')}",
    "script_injection": lambda b: f"Injected scripts or iframes {_plural(_count(b), 'time')}{_scenario_phrase(b)}",
    "routine_dom_change": lambda b: f"{_plural(_count(b), 'routine page change')}",
    "privileged_api_use": lambda b: f"Called privileged APIs{_targets(b)}",
}


def _count(behaviours: list[dict]) -> int:
    return sum(b["count"] for b in behaviours)


def _hosts(behaviours: list[dict]) -> str:
    return ", ".join(sorted({t for b in behaviours for t in b["targets"]})[:5]) or "an unknown host"


def _factor(behaviours: list[dict], factors: dict) -> tuple[float, str, str | None]:
    """The strongest (confidence, change) pairing among the behaviours that fired an indicator."""
    best, confidence, change = 0.0, "inferred", None
    for b in behaviours:
        c = factors["confirmed"] if b["attribution_confidence"] == "confirmed" else factors["inferred"]
        name = b.get("change")
        v = c * (factors.get(name, 1.0) if name else 1.0)
        if v > best:
            best, confidence, change = v, b["attribution_confidence"], name
    return best, confidence, change


def _manifest_findings(config: dict, manifest: dict | None, manifest_diff: dict | None,
                       manifest_features: dict | None) -> list[Finding]:
    indicators = config["indicators"]

    def finding(name: str, summary: str) -> Finding:
        spec = indicators[name]
        return Finding(name, spec["weight"], spec["weight"], spec["cluster"], spec["why"],
                       spec.get("direct_evidence", False), summary=summary,
                       confidence="confirmed", change="new" if manifest_diff else None)

    found = []
    if manifest_diff is not None:
        added = sorted(set(manifest_diff.get("high_risk_added", [])))
        if added:
            found.append(finding("permission_escalation", f"New high-risk permissions: {', '.join(added)}"))
        if manifest_diff.get("escalated_to_broad_host_access"):
            found.append(finding("host_access_broadened", "Host access widened to every site"))
    elif manifest_features is not None:
        count, broad = int(manifest_features.get("perm_high_risk", 0)), manifest_features.get("perm_broad_host", 0)
        if count or broad:
            text = []
            if count:
                text.append(_plural(count, "high-risk permission"))
            if broad:
                text.append("access to every site")
            found.append(finding("broad_declared_capability", "Declares " + " and ".join(text)))
    return found


def score_behaviours(behaviours: list[dict], config: dict, *, manifest: dict | None = None,
                     manifest_diff: dict | None = None,
                     manifest_features: dict | None = None) -> dict:
    """Score a set of behaviours.

    In Mode A *behaviours* is everything observed. In Mode B it is only what the update
    introduced or increased (see :func:`behaviours_to_score`), which makes a password manager that
    has always read passwords score nothing for that.
    """
    indicators = config["indicators"]
    factors = config["factors"]
    findings: list[Finding] = []
    exfil_hosts: set[str] = set()
    for name in _EXFIL_INDICATORS:
        exfil_hosts.update(t for b in behaviours if PREDICATES[name](b) for t in b["targets"])
    # Traffic already explained by a stronger reading of the same requests is not counted again.
    claimed = exfil_hosts | {
        t for b in behaviours
        if PREDICATES["temporal_exfiltration_candidate"](b) or PREDICATES["beaconing"](b)
        for t in b["targets"]}

    for name, predicate in PREDICATES.items():
        matched = [b for b in behaviours if predicate(b)]
        if name in ("beaconing", "temporal_exfiltration_candidate"):
            matched = [b for b in matched if not set(b["targets"]) <= exfil_hosts]
        elif name in _DESTINATION_INDICATORS:
            matched = [b for b in matched if not set(b["targets"]) <= claimed]
        if not matched:
            continue
        spec = indicators[name]
        multiplier, confidence, change = _factor(matched, factors)
        findings.append(Finding(
            name, spec["weight"], spec["weight"] * multiplier, spec["cluster"], spec["why"],
            spec.get("direct_evidence", False), matched, _SUMMARIES[name](matched), confidence, change))

    findings += _manifest_findings(config, manifest, manifest_diff, manifest_features)

    strongest: dict[str, Finding] = {}
    for f in findings:
        current = strongest.get(f.cluster)
        if current is None or f.effective_weight > current.effective_weight:
            strongest[f.cluster] = f
    for f in findings:
        f.counted = strongest[f.cluster] is f

    def combine(items: list[Finding]) -> float:
        product = 1.0
        for item in items:
            product *= 1.0 - item.effective_weight
        return 1.0 - product

    counted = [f for f in findings if f.counted]
    total = combine(counted)
    for f in counted:
        without = combine([g for g in counted if g is not f])
        f.contribution = (total - without) * 100.0

    score = int(round(total * 100))
    findings.sort(key=lambda f: (-int(f.counted), -f.effective_weight, f.indicator))
    risky = [f for f in findings if f.cluster != "routine" and f.counted]
    return {
        "score": score,
        "classification": classify(score, config),
        "findings": [f.as_dict() for f in findings],
        "direct_evidence": any(f.direct_evidence for f in findings),
        "indicators_fired": len(findings),
        "risk_indicators_fired": len(risky),
        "explanation": explain(score, findings, config),
    }


def classify(score: float, config: dict) -> str:
    bands = config["bands"]
    if score >= bands["critical"]:
        return "Critical observed risk"
    if score >= bands["high"]:
        return "High observed risk"
    if score >= bands["moderate"]:
        return "Moderate observed risk"
    if score >= bands["mild"]:
        return "Mild observed risk"
    return "Low observed risk"


def explain(score: int, findings: list[Finding], config: dict) -> list[str]:
    lines = [f"Risk score: {score}/100 ({classify(score, config)})."]
    for f in findings:
        if f.counted and f.cluster != "routine":
            lines.append(f"{f.summary}. [{f.indicator}, weight {f.effective_weight:.2f}]")
    if len(lines) == 1:
        lines.append("No risk indicator fired during this analysis.")
    return lines


def behaviours_to_score(comparison: dict) -> list[dict]:
    """The Mode B input: what the update introduced, and what it clearly increased or changed."""
    classes = comparison["classes"]
    return classes["new"] + classes["changed_parameters"] + classes["increased"]


def verdict_for(score: float, findings_fired: int, *, config: dict, complete: bool) -> str:
    """The qualified verdict. Absence of observed misbehaviour is never called safe."""
    bands = config["bands"]
    if score >= bands["critical"]:
        return "Critical behaviour detected"
    if score >= bands["high"]:
        return "High-risk behaviour detected"
    if score >= bands["moderate"]:
        return "Suspicious behaviour detected"
    if not complete:
        return "Inconclusive analysis"
    if score >= bands["mild"] or findings_fired:
        return "Low observed risk"
    return "No significant suspicious behaviour observed"
