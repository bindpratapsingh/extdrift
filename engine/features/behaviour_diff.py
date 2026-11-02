"""Behaviour-level comparison of two versions of an extension.

Every behaviour in either version falls into exactly one class:

    new                 absent from the baseline
    increased           present in both, clearly more frequent in the candidate
    changed_parameters  similar frequency, but it now touches something different
    removed             absent from the candidate
    decreased           present in both, clearly less frequent
    unchanged           no meaningful difference

This classifies *what changed* and makes no judgement about it. Whether a change is dangerous is
decided by :mod:`engine.scoring.risk`.
"""

from __future__ import annotations

#: A behaviour counts as more or less frequent only past both a ratio and an absolute gap, because
#: browser scheduling alone can move small counts by one or two.
FREQUENCY_RATIO = 1.5
FREQUENCY_MIN_GAP = 2
#: Parameter classes whose change matters. Anything else varying is treated as the same behaviour.
_MATERIAL_PREFIXES = ("marker=", "context=", "body=", "area=")


def _material(params: list[str]) -> set[str]:
    return {p for p in params if p.startswith(_MATERIAL_PREFIXES)}


def noise_floor(run_a: dict[str, dict], run_b: dict[str, dict]) -> dict:
    """Variation between two runs of the same version: what happens with nothing changed."""
    signatures = set(run_a) | set(run_b)
    tolerance, unstable = {}, []
    for signature in signatures:
        a = run_a.get(signature, {}).get("count", 0)
        b = run_b.get(signature, {}).get("count", 0)
        if abs(a - b):
            tolerance[signature] = abs(a - b)
        if signature in run_a and signature in run_b:
            continue
        unstable.append(signature)
    return {"tolerance": tolerance, "unstable": sorted(unstable)}


def classify_behaviour(baseline: dict | None, candidate: dict | None, *,
                       tolerance: int = 0) -> tuple[str, dict]:
    if baseline is None:
        return "new", {}
    if candidate is None:
        return "removed", {}
    before, after = baseline["count"], candidate["count"]
    gap = after - before
    effective_gap = max(abs(gap) - tolerance, 0)
    added_params = sorted(_material(candidate["parameters"]) - _material(baseline["parameters"]))
    removed_params = sorted(_material(baseline["parameters"]) - _material(candidate["parameters"]))
    if added_params:
        return "changed_parameters", {"added_parameters": added_params,
                                      "removed_parameters": removed_params}
    if effective_gap >= FREQUENCY_MIN_GAP:
        if gap > 0 and after >= before * FREQUENCY_RATIO:
            return "increased", {"from": before, "to": after}
        if gap < 0 and before >= after * FREQUENCY_RATIO:
            return "decreased", {"from": before, "to": after}
    return "unchanged", {}


def diff_behaviours(baseline: dict[str, dict], candidate: dict[str, dict],
                    noise: dict | None = None) -> dict:
    """Classify every behaviour across versions. *noise* comes from :func:`noise_floor`."""
    noise = noise or {"tolerance": {}, "unstable": []}
    unstable = set(noise.get("unstable", []))
    classes: dict[str, list[dict]] = {key: [] for key in (
        "new", "increased", "changed_parameters", "removed", "decreased", "unchanged", "unstable")}
    for signature in sorted(set(baseline) | set(candidate)):
        before, after = baseline.get(signature), candidate.get(signature)
        if signature in unstable:
            classes["unstable"].append({**(after or before), "change": "unstable",
                                        "baseline_count": (before or {}).get("count", 0),
                                        "candidate_count": (after or {}).get("count", 0)})
            continue
        change, detail = classify_behaviour(
            before, after, tolerance=noise.get("tolerance", {}).get(signature, 0))
        classes[change].append({**(after or before), "change": change, "change_detail": detail,
                                "baseline_count": (before or {}).get("count", 0),
                                "candidate_count": (after or {}).get("count", 0)})
    return classes


def _section(classes: dict, category_prefixes: tuple[str, ...]) -> dict:
    out = {}
    for change, items in classes.items():
        if change == "unchanged":
            continue
        selected = [i["label"] for i in items if i["signature"].startswith(category_prefixes)]
        if selected:
            out[change] = selected
    return out


def network_destinations(behaviours: dict[str, dict]) -> set[str]:
    hosts: set[str] = set()
    for behaviour in behaviours.values():
        if behaviour["category"] == "network":
            hosts.update(behaviour["targets"])
    return hosts


def compare_versions(baseline_behaviours: dict[str, dict], candidate_behaviours: dict[str, dict],
                     baseline_features: dict[str, float], candidate_features: dict[str, float],
                     manifest_diff: dict, noise: dict | None = None) -> dict:
    """The full comparison: behaviour classes, per-dimension summaries and the Δ vector."""
    classes = diff_behaviours(baseline_behaviours, candidate_behaviours, noise)
    before_hosts = network_destinations(baseline_behaviours)
    after_hosts = network_destinations(candidate_behaviours)
    feature_delta = {name: candidate_features[name] - baseline_features[name]
                     for name in candidate_features}
    return {
        "classes": classes,
        "counts": {change: len(items) for change, items in classes.items()},
        "network_destinations": {"new": sorted(after_hosts - before_hosts),
                                 "removed": sorted(before_hosts - after_hosts),
                                 "common": sorted(before_hosts & after_hosts)},
        "network": _section(classes, ("net:",)),
        "dom": _section(classes, ("dom:",)),
        "storage": _section(classes, ("storage:", "cookie:")),
        "api": _section(classes, ("api:",)),
        "sensitive_data_access": {
            change: [i["label"] for i in items if _touches_sensitive(i)]
            for change, items in classes.items() if change != "unchanged"
            and any(_touches_sensitive(i) for i in items)
        },
        "permissions": manifest_diff,
        "feature_delta": feature_delta,
        "noise_floor_applied": bool(noise),
    }


def _touches_sensitive(behaviour: dict) -> bool:
    tags = behaviour.get("tags", [])
    return any(t.startswith(("field:password", "field:payment", "field:otp", "field:auth_token",
                             "field:hidden", "field:account", "field:personal", "exfil:"))
               or t in ("cookie_access", "sensitive_storage_key") for t in tags)
