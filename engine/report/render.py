"""Verdict rendering: one human-readable report, one machine-readable record.

The text form is what gets read out in a demo; the JSON form is what the evaluation
harness aggregates over the whole corpus.  Both are produced from the same record, so
they can never disagree.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from engine.features.extract import FEATURE_DOCS

BAR_WIDTH = 32


def _bar(score: float) -> str:
    filled = int(round(score * BAR_WIDTH))
    return "[" + "#" * filled + "-" * (BAR_WIDTH - filled) + "]"


def build_record(delta: dict, scored: dict) -> dict:
    """Assemble the full analysis record from the delta and the scorer output."""
    return {
        "tool": "extdrift",
        "record_version": "0.1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "extension": delta["extension"],
        "run": delta["run"],
        "verdict": scored["verdict"],
        "scores": {scored["scorer"]: scored["score"]},
        "fired_rules": scored["fired_rules"],
        "evidence": delta["evidence"],
        "delta": delta["numeric"],
        "features_v1": delta["features_v1"],
        "features_v2": delta["features_v2"],
        "caveats": _caveats(scored),
    }


def _caveats(scored: dict) -> list[str]:
    """State the limits of this verdict in the verdict itself.

    An analyst who is not told the weights are uncalibrated will read the score as more
    precise than it is, so the report always says so.
    """
    notes = []
    if not scored.get("weights_calibrated", False):
        notes.append(
            "Rule weights are expert-assigned priors from the literature, not yet "
            "calibrated on labelled data; treat the score as a ranking, not a probability."
        )
    notes.append(
        "Exfiltration flows are inferred from temporal adjacency (read then upload), "
        "not from true data-flow tracking; they are candidates for review."
    )
    return notes


def render_json(delta: dict, scored: dict, *, indent: int = 2) -> str:
    """The full record as JSON text."""
    return json.dumps(build_record(delta, scored), indent=indent, sort_keys=False)


def render_text(delta: dict, scored: dict) -> str:
    """The analyst-facing report."""
    ext = delta["extension"]
    run = delta["run"]
    lines = []

    lines.append("=" * 78)
    lines.append("  extdrift - behavioural diff report")
    lines.append("=" * 78)
    lines.append(f"  Extension : {ext.get('name')}  ({ext.get('id')})")
    lines.append(f"  Update    : {ext.get('version_from')}  ->  {ext.get('version_to')}")
    lines.append(f"  Run       : {run.get('browser')} / scenario '{run.get('scenario')}'"
                 f" / replay bundle {run.get('replay_bundle')}")
    lines.append("")
    lines.append(f"  VERDICT   : {scored['verdict']}")
    lines.append(f"  Score     : {scored['score']:.2f}  {_bar(scored['score'])}"
                 f"   (weighted rules, {len(scored['fired_rules'])}"
                 f"/{scored['rules_evaluated']} fired)")
    lines.append("")

    if scored["fired_rules"]:
        lines.append("-" * 78)
        lines.append("  WHY - rules that fired on the change")
        lines.append("-" * 78)
        for hit in scored["fired_rules"]:
            lines.append(f"  [{hit['id']}] {hit['name']}  (weight {hit['weight']:.2f})")
            lines.append(f"        {hit['evidence']}")
            lines.append(f"        source: {hit['provenance']}")
    else:
        lines.append("  No heuristic fired: the update introduced no behaviour from the")
        lines.append("  known-malicious catalogue under this scenario.")
    lines.append("")

    evidence = delta["evidence"]
    interesting = [
        ("New hosts contacted", evidence["new_hosts"]),
        ("New third-party hosts", evidence["new_third_party_hosts"]),
        ("New upload destinations", evidence["new_upload_hosts"]),
        ("New extension APIs used", evidence["new_apis"]),
        ("New permissions declared", evidence["new_permissions"]),
        ("New host permissions", evidence["new_host_permissions"]),
        ("New DOM read targets", evidence["new_dom_targets"]),
        ("Hosts no longer contacted", evidence["dropped_hosts"]),
    ]
    shown = [(label, items) for label, items in interesting if items]
    if shown:
        lines.append("-" * 78)
        lines.append("  WHAT CHANGED - set-level differences")
        lines.append("-" * 78)
        for label, items in shown:
            lines.append(f"  {label}:")
            for item in items:
                lines.append(f"      + {item}")
    lines.append("")

    moved = {k: v for k, v in delta["numeric"].items() if abs(v) > 1e-9}
    if moved:
        lines.append("-" * 78)
        lines.append("  FEATURE DELTA  (v2 - v1; only features that moved)")
        lines.append("-" * 78)
        width = max(len(k) for k in moved)
        for name, value in sorted(moved.items(), key=lambda kv: -abs(kv[1])):
            meaning = FEATURE_DOCS.get(name, ("", ""))[0]
            lines.append(f"  {name.ljust(width)}  {value:+10.2f}   {meaning}")
    lines.append("")

    lines.append("-" * 78)
    lines.append("  CAVEATS")
    lines.append("-" * 78)
    for note in _caveats(scored):
        lines.append(f"  * {note}")
    lines.append("=" * 78)
    return "\n".join(lines)
