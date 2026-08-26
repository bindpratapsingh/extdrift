"""The behavioural delta: ``delta = f(T2) - f(T1)``.

Scoring the *change* rather than the extension is the whole point of the project, so
this module produces two things side by side:

* ``numeric`` - the per-feature difference, which is what a classifier consumes;
* ``evidence`` - the set-level "what is actually new in v2" (new hosts, new APIs, new
  permissions), which is what a human reads in the report.

Without the evidence half a verdict is unexplainable, and an unexplainable verdict is
useless to the analyst this tool is built for.
"""

from __future__ import annotations

from engine.features.extract import (
    FEATURE_ORDER,
    SENSITIVE_TARGET_RE,
    _is_upload,
    extract_features,
    host_of,
    registrable_domain,
    split_permissions,
)


def _hosts(trace: dict) -> set[str]:
    return {host_of(e["url"]) for e in trace.get("network", [])} - {""}


def _upload_hosts(trace: dict) -> set[str]:
    """Hosts that received data from extension code, as opposed to merely serving it."""
    return {
        host_of(e["url"]) for e in trace.get("network", [])
        if e.get("initiator") in ("extension", "content_script", "service_worker")
        and _is_upload(e)
    } - {""}


def _apis(trace: dict) -> set[str]:
    return ({str(e.get("api")) for e in trace.get("api", [])}
            | {str(e.get("api")) for e in trace.get("storage", [])}) - {"None"}


def _dom_targets(trace: dict) -> set[str]:
    return {str(e.get("target")) for e in trace.get("dom", []) if e.get("event") == "read"}


def behavioral_delta(trace_v1: dict, trace_v2: dict) -> dict:
    """Compare two traces of the same extension and return the delta record.

    The two traces must come from the same scenario and the same replay bundle; the
    caller (engine.cli) enforces that, because comparing runs against different page
    content is precisely the false-positive trap record/replay exists to close.
    """
    f1 = extract_features(trace_v1)
    f2 = extract_features(trace_v2)

    hosts_v1, hosts_v2 = _hosts(trace_v1), _hosts(trace_v2)
    apis_v1, apis_v2 = _apis(trace_v1), _apis(trace_v2)
    perms_v1, host_perms_v1 = split_permissions(trace_v1.get("manifest", {}))
    perms_v2, host_perms_v2 = split_permissions(trace_v2.get("manifest", {}))

    new_hosts = sorted(hosts_v2 - hosts_v1)
    # "Known parties" = every registrable domain the trusted baseline already talked to.
    # A newly contacted host under one of those domains is the vendor's own new subdomain,
    # not a new party, so it does not count as a third-party appearance.
    known_parties = {registrable_domain(h) for h in hosts_v1}
    new_dom_targets = sorted(_dom_targets(trace_v2) - _dom_targets(trace_v1))

    return {
        "extension": {
            "id": trace_v2.get("extension", {}).get("id"),
            "name": trace_v2.get("extension", {}).get("name"),
            "version_from": trace_v1.get("extension", {}).get("version"),
            "version_to": trace_v2.get("extension", {}).get("version"),
        },
        "run": {
            "browser": trace_v2.get("run", {}).get("browser"),
            "scenario": trace_v2.get("run", {}).get("scenario"),
            "replay_bundle": trace_v2.get("run", {}).get("replay_bundle"),
        },
        "features_v1": f1,
        "features_v2": f2,
        "numeric": {name: f2[name] - f1[name] for name in FEATURE_ORDER},
        "evidence": {
            "new_hosts": new_hosts,
            "new_third_party_hosts": [
                h for h in new_hosts if registrable_domain(h) not in known_parties
            ],
            "new_upload_hosts": sorted(
                h for h in (_upload_hosts(trace_v2) - _upload_hosts(trace_v1))
                if registrable_domain(h) not in known_parties
            ),
            "dropped_hosts": sorted(hosts_v1 - hosts_v2),
            "new_apis": sorted(apis_v2 - apis_v1),
            "new_permissions": sorted(perms_v2 - perms_v1),
            "new_host_permissions": sorted(host_perms_v2 - host_perms_v1),
            "dropped_permissions": sorted(perms_v1 - perms_v2),
            "new_dom_targets": new_dom_targets,
            "new_sensitive_dom_targets": [
                t for t in new_dom_targets if SENSITIVE_TARGET_RE.search(t)
            ],
        },
    }


def delta_vector(delta: dict) -> list[float]:
    """Flatten a delta record into the ordered numeric vector the ML tier trains on."""
    return [delta["numeric"][name] for name in FEATURE_ORDER]
