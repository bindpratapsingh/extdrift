"""The security report, in JSON for machines and in Markdown and HTML for people.

The JSON document is built once. Both human formats are rendered from it, so they cannot disagree.
A report states what was observed and how confident the analysis is. It never calls an extension
safe, because a dynamic analysis can only speak for the behaviour it managed to trigger.
"""

from __future__ import annotations

import html
import json

from engine.features.behaviour import FEATURE_DOCS
from engine.sandbox.markers import assert_no_marker_values, redact
from engine.unpack.manifest import summarise_manifest_diff

LIMITATIONS = [
    "This is dynamic analysis. It can only report behaviour that happened during this run, so "
    "malicious code that stayed dormant, was tied to a date, a specific website, a specific user, "
    "or a server response that the sealed sandbox could not provide, would not appear here.",
    "No suspicious behaviour being captured does not show that an extension is safe.",
    "The score reflects observed behavioural risk. It is not the probability that the extension is "
    "malicious, and its bands are configurable starting points rather than established boundaries.",
    "An extension could detect the analysis environment and behave differently. Instrumentation is "
    "inside the extension's own JavaScript, so sufficiently careful code could evade or tamper with "
    "it. The network record, kept in a separate container, is harder to evade than the other channels.",
    "Browser scheduling, service-worker lifetimes and asynchronous code mean two runs are not "
    "perfectly identical, even though both versions receive the same pages and scripted actions.",
]

PLAIN_VERDICT = {
    "Critical behaviour detected": "The extension did something that very commonly indicates theft "
                                   "of sensitive data. It should not be trusted until reviewed.",
    "High-risk behaviour detected": "The extension showed behaviour that is often associated with "
                                    "misuse of sensitive data. It should be reviewed before use.",
    "Suspicious behaviour detected": "The extension did things that deserve a closer look, though "
                                     "they might have legitimate explanations.",
    "Low observed risk": "Only minor signals were seen. This is not proof that the extension is safe.",
    "No significant suspicious behaviour observed":
        "Nothing concerning happened during this test. This is not proof that the extension is "
        "safe, because some behaviour only appears under conditions this test did not create.",
    "Inconclusive analysis": "The analysis could not produce a trustworthy result, so this report "
                             "says nothing either way about whether the extension is safe.",
}


def runtime_summary(events: list[dict], behaviours: dict[str, dict], findings: list[dict]) -> dict:
    extension_net = [e for e in events if e["category"] == "network"
                     and e["source_context"] not in ("page", "browser_internal")
                     and e["event_type"] in ("http_request", "websocket_open")]
    wire = [e for e in events if e["category"] == "network" and e["event_type"] == "http_request"]
    storage = [e for e in events if e["category"] == "storage"]
    dom = [e for e in events if e["category"] == "dom" and e["event_type"] != "activity_summary"]
    return {
        "network_requests_total": len(wire),
        "network_requests_extension": len(extension_net),
        "network_requests_page": sum(1 for e in wire if e["source_context"] == "page"),
        "network_requests_browser_internal": sum(1 for e in wire if e["source_context"] == "browser_internal"),
        "unique_destinations_extension": len({e["destination"] for e in extension_net if e.get("destination")}),
        "dom_access_events": len(dom),
        "storage_operations": sum(1 for e in storage if e["metadata"].get("area") != "cookie"),
        "cookie_operations": sum(1 for e in storage if e["metadata"].get("area") == "cookie")
                             + sum(1 for e in dom if e["event_type"] in ("cookie_read", "cookie_write")),
        "extension_api_calls": sum(1 for e in events if e["category"] == "api"),
        "script_injections": sum(1 for e in dom if e["event_type"] == "script_injected"),
        "suspicious_events": sum(1 for f in findings if f["cluster"] != "routine"),
    }


def _suspicious_items(findings: list[dict]) -> list[dict]:
    items = []
    for finding in findings:
        if finding["cluster"] == "routine":
            continue
        behaviours = finding["behaviours"]
        first = behaviours[0] if behaviours else {}
        items.append({
            "description": finding["summary"],
            "indicator": finding["indicator"],
            "category": first.get("category", "permissions"),
            "timestamp": first.get("first_timestamp"),
            "evidence": behaviours,
            "why_suspicious": finding["why"],
            "risk_contribution": finding["risk_contribution"],
            "weight": finding["effective_weight"],
            "counted_in_score": finding["counted_in_score"],
            "attribution_confidence": finding["attribution_confidence"],
            "change": finding.get("change"),
        })
    return items


def _manifest_section(meta: dict) -> dict:
    return {key: meta.get(key) for key in (
        "manifest_version", "permissions", "optional_permissions", "host_permissions", "background_kind",
        "service_worker", "background_scripts", "content_scripts", "web_accessible_resources",
        "externally_connectable")}


def build_report(analysis: dict) -> dict:
    """Assemble the machine-readable report from a finished analysis."""
    mode = analysis["mode"]
    candidate = analysis.get("candidate") or {}
    baseline = analysis.get("baseline") or {}
    meta = analysis.get("candidate_meta") or {}
    risk = analysis.get("risk") or {}
    findings = risk.get("findings", [])
    failure = analysis.get("failure")
    combined = analysis.get("combined") or {}

    report = {
        "tool": "extdrift", "report_version": "1.0", "mode": mode,
        "status": analysis["status"],
        "A_summary": {
            "extension_name": meta.get("name"), "extension_id": meta.get("extension_id"),
            "extension_id_source": meta.get("extension_id_source"),
            "extension_version": meta.get("version"),
            "baseline_version": (analysis.get("baseline_meta") or {}).get("version"),
            "browser": analysis["browser"], "browser_version": candidate.get("browser_version"),
            "analysis_id": analysis["analysis_id"], "analysis_date": analysis["started_at"],
            "sandbox_execution_status": analysis["status"],
            "scenarios_requested": analysis.get("scenarios", []),
            "scenarios_completed": (candidate.get("coverage") or {}).get("scenarios_completed", 0),
            "number_of_browsing_scenarios": (candidate.get("coverage") or {}).get("scenarios_total", 0),
            "total_execution_seconds": analysis.get("duration_s"),
        },
        "B_manifest": {
            "candidate": _manifest_section(meta),
            "baseline": _manifest_section(analysis["baseline_meta"]) if analysis.get("baseline_meta") else None,
            "permission_changes": analysis.get("manifest_diff"),
            "permission_change_summary": (summarise_manifest_diff(analysis["manifest_diff"])
                                          if analysis.get("manifest_diff") else []),
            "validation_warnings": analysis.get("validation_warnings", []),
        },
        "C_runtime_summary": {
            "candidate": candidate.get("summary"), "baseline": baseline.get("summary"),
        },
        "D_suspicious_activity": _suspicious_items(findings),
        "E_version_comparison": _comparison_section(analysis) if mode == "compare" else None,
        "F_risk_assessment": {
            "overall_risk_score": combined.get("combined_score", risk.get("score")),
            "risk_classification": combined.get("classification", risk.get("classification")),
            "weighted_baseline_score": risk.get("score"),
            "ml_classification": (analysis.get("ml") or {}).get("classification"),
            "ml_probability": (analysis.get("ml") or {}).get("probability"),
            "ml_confidence_is_calibrated": (analysis.get("ml") or {}).get("confidence_is_calibrated"),
            "ml": analysis.get("ml"),
            "combination": combined,
            "primary_risk_indicators": [f["indicator"] for f in findings
                                        if f["counted_in_score"] and f["cluster"] != "routine"][:8],
            "score_explanation": risk.get("explanation", []),
            "lower_risk_observations": [f["summary"] for f in findings if f["cluster"] == "routine"],
            "scored_input": risk.get("scored_input"),
            "baseline_version_own_risk": analysis.get("baseline_risk"),
            "existing_rule_scorer_for_reference": analysis.get("legacy_rules"),
            "feature_vector_candidate": candidate.get("features"),
            "feature_vector_baseline": baseline.get("features"),
        },
        "G_verdict": {
            "verdict": analysis["verdict"],
            "plain_language": PLAIN_VERDICT[analysis["verdict"]],
            "failure": failure,
            "limitations": LIMITATIONS + analysis.get("extra_limitations", []),
        },
        "isolation": analysis.get("isolation"),
        "monitoring_coverage": {"candidate": candidate.get("coverage"), "baseline": baseline.get("coverage")},
        "reproducibility": analysis.get("reproducibility"),
        "artefacts": analysis.get("artefacts"),
    }
    return report


def _comparison_section(analysis: dict) -> dict | None:
    comparison = analysis.get("comparison")
    if not comparison:
        return None
    classes = comparison["classes"]

    def brief(items: list[dict]) -> list[dict]:
        return [{"behaviour": i["label"], "signature": i["signature"], "category": i["category"],
                 "baseline_count": i["baseline_count"], "candidate_count": i["candidate_count"],
                 "scenarios": i["scenarios"], "targets": i["targets"],
                 "attribution_confidence": i["attribution_confidence"],
                 "detail": i.get("change_detail")} for i in items]

    scored = {f_b.get("signature") for f in (analysis.get("risk") or {}).get("findings", [])
              if f["cluster"] != "routine" for f_b in f["behaviours"]}
    return {
        "newly_introduced_behaviours": brief(classes["new"]),
        "newly_introduced_and_suspicious": brief([i for i in classes["new"] if i["signature"] in scored]),
        "increased_behaviours": brief(classes["increased"]),
        "changed_parameter_behaviours": brief(classes["changed_parameters"]),
        "removed_behaviours": brief(classes["removed"]),
        "decreased_behaviours": brief(classes["decreased"]),
        "unstable_behaviours_excluded": brief(classes["unstable"]),
        "unchanged_behaviour_count": len(classes["unchanged"]),
        "permission_differences": comparison["permissions"],
        "network_destination_differences": comparison["network_destinations"],
        "network_differences": comparison["network"],
        "dom_differences": comparison["dom"],
        "storage_differences": comparison["storage"],
        "extension_api_differences": comparison["api"],
        "sensitive_data_access_differences": comparison["sensitive_data_access"],
        "feature_difference_vector": {k: v for k, v in comparison["feature_delta"].items() if v},
        "legacy_feature_delta": analysis.get("legacy_delta"),
        "comparability": analysis.get("comparability"),
        "noise_floor_applied": comparison["noise_floor_applied"],
    }


def render_json(report: dict) -> str:
    text = redact(json.dumps(report, indent=2, default=str))
    assert_no_marker_values(text)
    return text


# ------------------------------------------------------------------------------------------
# Markdown
# ------------------------------------------------------------------------------------------

def _md_escape(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _md_table(rows: list[tuple[str, object]]) -> list[str]:
    lines = ["| Item | Value |", "|---|---|"]
    lines += [f"| {_md_escape(k)} | {_md_escape(v if v not in (None, '') else 'n/a')} |" for k, v in rows]
    return lines + [""]


def _join(value) -> str:
    if not value:
        return "none"
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(v) for v in value)
    return str(value)


def render_markdown(report: dict) -> str:
    a, b, c, d, e, f, g = (report["A_summary"], report["B_manifest"], report["C_runtime_summary"],
                           report["D_suspicious_activity"], report["E_version_comparison"],
                           report["F_risk_assessment"], report["G_verdict"])
    title = a.get("extension_name") or "Unknown extension"
    lines = [f"# Security report: {title}", ""]
    lines += [f"**Verdict: {g['verdict']}**", "", g["plain_language"], ""]
    score = f.get("overall_risk_score")
    if score is not None:
        lines += [f"**Risk score: {score}/100** ({f.get('risk_classification')}). This reflects observed "
                  "behaviour and is not a probability that the extension is malicious.", ""]
    if g.get("failure"):
        lines += ["## The analysis failed", "",
                  f"Failed during: **{g['failure'].get('stage')}**", "", str(g['failure'].get('reason')), ""]
        for problem in g["failure"].get("details", {}).get("problems", []):
            lines.append(f"- {problem}")
        lines.append("")

    lines += ["## A. Analysis summary", ""]
    version = a.get("extension_version")
    if a.get("baseline_version"):
        version = f"{a['baseline_version']} (baseline) to {a.get('extension_version')} (candidate)"
    lines += _md_table([
        ("Extension", a.get("extension_name")), ("Extension ID", a.get("extension_id")),
        ("Version", version), ("Browser", f"{a.get('browser')} {a.get('browser_version') or ''}"),
        ("Analysis ID", a.get("analysis_id")), ("Date", a.get("analysis_date")),
        ("Sandbox status", a.get("sandbox_execution_status")),
        ("Scenarios completed", f"{a.get('scenarios_completed')} of {a.get('number_of_browsing_scenarios')}"),
        ("Total time", f"{a.get('total_execution_seconds')} s"),
    ])

    lines += ["## B. Manifest and permissions", ""]
    candidate = b.get("candidate") or {}
    lines += _md_table([
        ("Manifest version", candidate.get("manifest_version")),
        ("Permissions", _join(candidate.get("permissions"))),
        ("Host permissions", _join(candidate.get("host_permissions"))),
        ("Background", candidate.get("background_kind")),
        ("Service worker", candidate.get("service_worker")),
        ("Content scripts", len(candidate.get("content_scripts") or [])),
        ("Web-accessible resources", len(candidate.get("web_accessible_resources") or [])),
    ])
    if b.get("permission_change_summary"):
        lines += ["**Permission changes in the update**", ""]
        lines += [f"- {line}" for line in b["permission_change_summary"]] + [""]
    if b.get("validation_warnings"):
        lines += [f"- Warning: {w}" for w in b["validation_warnings"]] + [""]

    lines += ["## C. Runtime behaviour", ""]
    labels = [("network_requests_total", "Network requests, all"),
              ("network_requests_extension", "Attributed to the extension"),
              ("network_requests_page", "Attributed to the page"),
              ("network_requests_browser_internal", "Browser background traffic"),
              ("unique_destinations_extension", "Unique extension destinations"),
              ("dom_access_events", "DOM access events"), ("storage_operations", "Storage operations"),
              ("cookie_operations", "Cookie operations"), ("extension_api_calls", "Extension API calls"),
              ("script_injections", "Script injections"), ("suspicious_events", "Suspicious findings")]
    cand_summary, base_summary = c.get("candidate") or {}, c.get("baseline")
    if base_summary:
        lines += ["| Measure | Baseline | Candidate |", "|---|---|---|"]
        lines += [f"| {label} | {base_summary.get(key, 'n/a')} | {cand_summary.get(key, 'n/a')} |"
                  for key, label in labels]
    else:
        lines += ["| Measure | Count |", "|---|---|"]
        lines += [f"| {label} | {cand_summary.get(key, 'n/a')} |" for key, label in labels]
    lines.append("")

    lines += ["## D. Suspicious activity", ""]
    if not d:
        lines += ["No risk indicator fired. This describes this run and is not a statement of safety.", ""]
    for item in d:
        status = "" if item["counted_in_score"] else " (not added to the score: same behaviour group as a stronger finding)"
        lines += [f"### {item['description']}", "",
                  f"- **Category:** {item['category']}",
                  f"- **First seen:** {item.get('timestamp') or 'declared in the manifest'}",
                  f"- **Why it matters:** {item['why_suspicious']}",
                  f"- **Risk contribution:** weight {item['weight']:.2f}, adding {item['risk_contribution']:.1f} points "
                  f"on top of the other findings{status}",
                  f"- **Attribution:** {item['attribution_confidence']}"]
        if item.get("change"):
            lines.append(f"- **Change from baseline:** {item['change']}")
        for evidence in item["evidence"][:4]:
            detail = [f"{evidence.get('label')} x{evidence.get('count')}"]
            if evidence.get("scenarios"):
                detail.append("scenarios: " + ", ".join(evidence["scenarios"]))
            if evidence.get("contexts"):
                detail.append("from: " + ", ".join(evidence["contexts"]))
            markers = (evidence.get("details") or {}).get("markers")
            if markers:
                detail.append("markers: " + ", ".join(f"{m['kind']} ({m['encoding']}, {m['location']})" for m in markers))
            lines.append("- **Evidence:** " + "; ".join(detail))
        lines.append("")

    if e:
        lines += ["## E. Version comparison", ""]
        for key, label in (("newly_introduced_and_suspicious", "Newly introduced and suspicious"),
                           ("newly_introduced_behaviours", "All newly introduced behaviours"),
                           ("increased_behaviours", "More frequent"),
                           ("changed_parameter_behaviours", "Changed parameters"),
                           ("removed_behaviours", "Removed"),
                           ("decreased_behaviours", "Less frequent"),
                           ("unstable_behaviours_excluded", "Unstable across baseline runs, so excluded")):
            items = e.get(key) or []
            lines += [f"**{label}: {len(items)}**", ""]
            lines += [f"- {i['behaviour']} (baseline {i['baseline_count']}, candidate {i['candidate_count']})"
                      for i in items[:25]]
            lines.append("")
        lines += [f"Unchanged behaviours: {e.get('unchanged_behaviour_count')}", ""]
        destinations = e.get("network_destination_differences") or {}
        lines += [f"- New destinations: {_join(destinations.get('new'))}",
                  f"- Destinations no longer contacted: {_join(destinations.get('removed'))}", ""]
        if e.get("feature_difference_vector"):
            lines += ["**Feature differences (candidate minus baseline)**", "",
                      "| Feature | Change | Meaning |", "|---|---|---|"]
            lines += [f"| {k} | {v:+g} | {FEATURE_DOCS.get(k, '')} |"
                      for k, v in e["feature_difference_vector"].items()]
            lines.append("")
        comparability = e.get("comparability") or {}
        if comparability.get("problems"):
            lines += ["**Comparability problems**", ""]
            lines += [f"- {p}" for p in comparability["problems"]] + [""]

    lines += ["## F. Risk assessment", ""]
    ml = f.get("ml") or {}
    if ml.get("status") == "available":
        ml_text = f"{ml['classification']} (probability {ml['probability']:.2f}, highest in {ml['scenario']})"
    else:
        ml_text = f"not used: {ml.get('reason', 'unavailable')}"
    combination = f.get("combination") or {}
    lines += _md_table([
        ("Overall risk score", f"{score}/100" if score is not None else "not scored"),
        ("Classification", f.get("risk_classification")),
        ("Weighted baseline score", f.get("weighted_baseline_score")),
        ("Machine learning", ml_text),
        ("ML confidence", "uncalibrated: useful for ranking only" if ml.get("status") == "available" else "n/a"),
        ("How they combined", combination.get("rule_applied")),
    ])
    if combination.get("explanation"):
        lines += [combination["explanation"], ""]
    if f.get("score_explanation"):
        lines += ["**Why this score**", ""]
        lines += [f"- {line}" for line in f["score_explanation"][1:]] + [""]
    if f.get("lower_risk_observations"):
        lines += ["**Lower-risk observations**", ""]
        lines += [f"- {line}" for line in f["lower_risk_observations"]] + [""]

    coverage = report.get("monitoring_coverage", {}).get("candidate") or {}
    if coverage:
        lines += ["## Monitoring coverage", "", "| Dimension | Status |", "|---|---|"]
        lines += [f"| {k} | {v} |" for k, v in (coverage.get("dimensions") or {}).items()]
        lines.append("")
        lines += [f"- Problem: {p}" for p in coverage.get("problems", [])]
        lines += [f"- Note: {n}" for n in coverage.get("notes", [])] + [""]
    isolation = report.get("isolation") or {}
    for role, check in (isolation.get("checks") or {}).items():
        lines += [f"Isolation checks ({role}): {'passed' if check.get('passed') else 'FAILED'}, "
                  f"{sum(1 for c in check.get('checks', []) if c['passed'])} of {len(check.get('checks', []))}."]
    if isolation.get("checks"):
        lines.append("")

    lines += ["## G. Final verdict", "", f"**{g['verdict']}**", "", g["plain_language"], "",
              "### Limitations", ""]
    lines += [f"- {text}" for text in g["limitations"]]
    text = redact("\n".join(lines) + "\n")
    assert_no_marker_values(text)
    return text


# ------------------------------------------------------------------------------------------
# HTML
# ------------------------------------------------------------------------------------------

_VERDICT_COLOUR = {
    "Critical behaviour detected": "#a4161a", "High-risk behaviour detected": "#c44900",
    "Suspicious behaviour detected": "#b7791f", "Low observed risk": "#2b6777",
    "No significant suspicious behaviour observed": "#2f6f4e", "Inconclusive analysis": "#555b6e",
}

_CSS = """
body{font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f7f7f8;color:#1c1e21}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:26px;margin:0 0 8px}h2{font-size:19px;margin:32px 0 10px;border-bottom:1px solid #d9dbe0;padding-bottom:6px}
h3{font-size:15px;margin:18px 0 6px}
.verdict{color:#fff;padding:18px 20px;border-radius:8px;margin:12px 0 20px}
.verdict strong{display:block;font-size:20px}.score{font-size:15px;opacity:.95;margin-top:6px}
table{border-collapse:collapse;width:100%;margin:8px 0 16px;background:#fff}
th,td{border:1px solid #e2e4e9;padding:6px 10px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#f0f1f4;font-weight:600}.wrap{overflow-x:auto}
.finding{background:#fff;border:1px solid #e2e4e9;border-radius:6px;padding:10px 14px;margin:10px 0}
.small{color:#555;font-size:13px}li{margin:3px 0}code{background:#eef0f3;padding:1px 4px;border-radius:3px;overflow-wrap:anywhere}
"""


def render_html(report: dict) -> str:
    """A self-contained page. Every value is escaped, as it may originate from the sample."""
    def esc(value: object) -> str:
        return html.escape(str(value), quote=True)

    def table(headers: list[str], rows: list[list[object]]) -> str:
        head = "".join(f"<th>{esc(h)}</th>" for h in headers)
        body = "".join("<tr>" + "".join(f"<td>{esc(c if c not in (None, '') else 'n/a')}</td>" for c in row)
                       + "</tr>" for row in rows)
        return f'<div class="wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'

    a, b, c, d, e, f, g = (report["A_summary"], report["B_manifest"], report["C_runtime_summary"],
                           report["D_suspicious_activity"], report["E_version_comparison"],
                           report["F_risk_assessment"], report["G_verdict"])
    score = f.get("overall_risk_score")
    colour = _VERDICT_COLOUR[g["verdict"]]
    parts = [f"<title>{esc(a.get('extension_name') or 'Extension')} security report</title>",
             f"<style>{_CSS}</style><main>",
             f"<h1>Security report: {esc(a.get('extension_name') or 'Unknown extension')}</h1>",
             f'<div class="verdict" style="background:{colour}"><strong>{esc(g["verdict"])}</strong>',
             f"<div>{esc(g['plain_language'])}</div>"]
    if score is not None:
        parts.append(f'<div class="score">Risk score {esc(score)}/100, {esc(f.get("risk_classification"))}. '
                     "Observed behaviour, not a probability of malice.</div>")
    parts.append("</div>")

    if g.get("failure"):
        parts.append(f"<h2>The analysis failed</h2><p>Failed during <strong>{esc(g['failure'].get('stage'))}</strong>: "
                     f"{esc(g['failure'].get('reason'))}</p><ul>")
        parts += [f"<li>{esc(p)}</li>" for p in g["failure"].get("details", {}).get("problems", [])]
        parts.append("</ul>")

    version = a.get("extension_version")
    if a.get("baseline_version"):
        version = f"{a['baseline_version']} (baseline) to {a.get('extension_version')} (candidate)"
    parts.append("<h2>A. Analysis summary</h2>")
    parts.append(table(["Item", "Value"], [
        ["Extension ID", a.get("extension_id")], ["Version", version],
        ["Browser", f"{a.get('browser')} {a.get('browser_version') or ''}"],
        ["Analysis ID", a.get("analysis_id")], ["Date", a.get("analysis_date")],
        ["Sandbox status", a.get("sandbox_execution_status")],
        ["Scenarios completed", f"{a.get('scenarios_completed')} of {a.get('number_of_browsing_scenarios')}"],
        ["Total time", f"{a.get('total_execution_seconds')} s"]]))

    candidate = b.get("candidate") or {}
    parts.append("<h2>B. Manifest and permissions</h2>")
    parts.append(table(["Item", "Value"], [
        ["Manifest version", candidate.get("manifest_version")],
        ["Permissions", _join(candidate.get("permissions"))],
        ["Host permissions", _join(candidate.get("host_permissions"))],
        ["Background", candidate.get("background_kind")], ["Service worker", candidate.get("service_worker")],
        ["Content scripts", len(candidate.get("content_scripts") or [])],
        ["Web-accessible resources", len(candidate.get("web_accessible_resources") or [])]]))
    if b.get("permission_change_summary"):
        parts.append("<ul>" + "".join(f"<li>{esc(x)}</li>" for x in b["permission_change_summary"]) + "</ul>")
    if b.get("validation_warnings"):
        parts.append("<ul>" + "".join(f"<li>Warning: {esc(x)}</li>" for x in b["validation_warnings"]) + "</ul>")

    parts.append("<h2>C. Runtime behaviour</h2>")
    cand_summary, base_summary = c.get("candidate") or {}, c.get("baseline")
    if base_summary:
        parts.append(table(["Measure", "Baseline", "Candidate"],
                           [[k.replace("_", " "), base_summary.get(k), cand_summary.get(k)] for k in cand_summary]))
    else:
        parts.append(table(["Measure", "Count"], [[k.replace("_", " "), v] for k, v in cand_summary.items()]))

    parts.append("<h2>D. Suspicious activity</h2>")
    if not d:
        parts.append("<p>No risk indicator fired. This describes this run and is not a statement of safety.</p>")
    for item in d:
        evidence = []
        for ev in item["evidence"][:4]:
            markers = (ev.get("details") or {}).get("markers") or []
            extra = (" markers: " + ", ".join(f"{m['kind']} ({m['encoding']})" for m in markers)) if markers else ""
            evidence.append(f"<li>{esc(ev.get('label'))} &times;{esc(ev.get('count'))}, "
                            f"scenarios: {esc(', '.join(ev.get('scenarios') or []))}{esc(extra)}</li>")
        counted = "" if item["counted_in_score"] else " (same behaviour group as a stronger finding, not added)"
        parts.append(
            f'<div class="finding"><h3>{esc(item["description"])}</h3><p>{esc(item["why_suspicious"])}</p>'
            f'<p class="small">Category: {esc(item["category"])}. First seen: {esc(item.get("timestamp") or "manifest")}. '
            f'Weight {item["weight"]:.2f}, adding {item["risk_contribution"]:.1f} points on top of the other findings{esc(counted)}. Attribution: {esc(item["attribution_confidence"])}. '
            + (f'Change: {esc(item.get("change"))}.' if item.get("change") else "")
            + f"</p><ul>{''.join(evidence)}</ul></div>")

    if e:
        parts.append("<h2>E. Version comparison</h2>")
        for key, label in (("newly_introduced_and_suspicious", "Newly introduced and suspicious"),
                           ("newly_introduced_behaviours", "All newly introduced behaviours"),
                           ("increased_behaviours", "More frequent"),
                           ("changed_parameter_behaviours", "Changed parameters"),
                           ("removed_behaviours", "Removed"), ("decreased_behaviours", "Less frequent"),
                           ("unstable_behaviours_excluded", "Unstable across baseline runs, so excluded")):
            items = e.get(key) or []
            parts.append(f"<h3>{esc(label)}: {len(items)}</h3>")
            if items:
                parts.append(table(["Behaviour", "Baseline", "Candidate"],
                                   [[i["behaviour"], i["baseline_count"], i["candidate_count"]] for i in items[:25]]))
        destinations = e.get("network_destination_differences") or {}
        parts.append(f"<p>New destinations: {esc(_join(destinations.get('new')))}. "
                     f"No longer contacted: {esc(_join(destinations.get('removed')))}. "
                     f"Unchanged behaviours: {esc(e.get('unchanged_behaviour_count'))}.</p>")
        if e.get("feature_difference_vector"):
            parts.append("<h3>Feature differences</h3>")
            parts.append(table(["Feature", "Change", "Meaning"],
                               [[k, f"{v:+g}", FEATURE_DOCS.get(k, "")] for k, v in e["feature_difference_vector"].items()]))

    parts.append("<h2>F. Risk assessment</h2>")
    ml = f.get("ml") or {}
    ml_text = (f"{ml['classification']}, probability {ml['probability']:.2f}, highest in {ml['scenario']}"
               if ml.get("status") == "available" else f"not used: {ml.get('reason', 'unavailable')}")
    combination = f.get("combination") or {}
    parts.append(table(["Item", "Value"], [
        ["Overall score", f"{score}/100" if score is not None else "not scored"],
        ["Classification", f.get("risk_classification")],
        ["Weighted baseline score", f.get("weighted_baseline_score")],
        ["Machine learning", ml_text],
        ["ML confidence", "uncalibrated: useful for ranking only" if ml.get("status") == "available" else "n/a"],
        ["How they combined", combination.get("rule_applied")]]))
    if combination.get("explanation"):
        parts.append(f"<p>{esc(combination['explanation'])}</p>")
    if f.get("score_explanation"):
        parts.append("<ul>" + "".join(f"<li>{esc(x)}</li>" for x in f["score_explanation"][1:]) + "</ul>")
    if f.get("lower_risk_observations"):
        parts.append("<h3>Lower-risk observations</h3><ul>"
                     + "".join(f"<li>{esc(x)}</li>" for x in f["lower_risk_observations"]) + "</ul>")

    coverage = report.get("monitoring_coverage", {}).get("candidate") or {}
    if coverage:
        parts.append("<h2>Monitoring coverage</h2>")
        parts.append(table(["Dimension", "Status"], [[k, v] for k, v in (coverage.get("dimensions") or {}).items()]))
        items = [f"Problem: {p}" for p in coverage.get("problems", [])] + [f"Note: {n}" for n in coverage.get("notes", [])]
        if items:
            parts.append("<ul>" + "".join(f"<li>{esc(x)}</li>" for x in items) + "</ul>")
    isolation = report.get("isolation") or {}
    if isolation.get("checks"):
        parts.append("<h2>Isolation evidence</h2>")
        rows = []
        for role, check in isolation["checks"].items():
            rows += [[role, x["name"], "pass" if x["passed"] else "FAIL"] for x in check.get("checks", [])]
        parts.append(table(["Container", "Check", "Result"], rows))

    parts.append(f"<h2>G. Final verdict</h2><p><strong>{esc(g['verdict'])}</strong>. {esc(g['plain_language'])}</p>"
                 "<h3>Limitations</h3><ul>" + "".join(f"<li>{esc(x)}</li>" for x in g["limitations"]) + "</ul></main>")
    text = redact("".join(parts))
    assert_no_marker_values(text)
    return text
