"""The extdrift trace schema — the contract between the sandbox and everything downstream.

A *trace* is the complete record of what ONE extension version did during ONE scripted
run against ONE replayed page bundle.  The sandbox writes it; feature extraction reads
it.  Keeping the schema in a single file (and versioned) means the capture side and the
analysis side can be built in parallel, which is exactly how we are working: the
analysis half already runs on fixture traces while the capture half is being wired up.

Four observation channels, per the proposal:

    network   every request that left the browser, with its initiator
    dom       page-content access: reads of form fields, injected nodes
    storage   cookie / localStorage / chrome.storage access
    api       chrome.* / browser.* extension-API calls

Design notes
------------
* Every event carries ``ts`` (seconds since run start) so the trace can later be
  re-read as an ordered *sequence* — that is the Tier-2 representation change
  (Transformer/GNN) described in docs/design/MODEL_PLAN.md.  Capturing order now
  costs nothing and keeps the stretch goal open.
* We never store captured secret values, only ``value_len`` and a salted digest.
  The sandbox only ever sees dummy credentials, but not storing them keeps the
  artefacts safe to commit and to hand to an examiner.
"""

from __future__ import annotations

SCHEMA_VERSION = "0.1"

#: Channels a trace must contain (may be empty lists, but must be present).
CHANNELS = ("network", "dom", "storage", "api")

#: Fields required on the trace envelope.
REQUIRED_TOP_LEVEL = ("schema_version", "extension", "run", "manifest") + CHANNELS

REQUIRED_EVENT_FIELDS = {
    "network": ("ts", "url", "method", "initiator"),
    "dom": ("ts", "event", "target"),
    "storage": ("ts", "api"),
    "api": ("ts", "api"),
}


class TraceError(ValueError):
    """Raised when a trace does not satisfy the schema."""


def validate_trace(trace: dict, *, source: str = "<trace>") -> dict:
    """Check *trace* against the schema and return it unchanged.

    Raises :class:`TraceError` with a precise message on the first problem found.
    Validation is intentionally strict: a silently malformed trace would show up
    downstream as a phantom behavioural change, i.e. a false positive.
    """
    if not isinstance(trace, dict):
        raise TraceError(f"{source}: trace must be a JSON object, got {type(trace).__name__}")

    for key in REQUIRED_TOP_LEVEL:
        if key not in trace:
            raise TraceError(f"{source}: missing required top-level key {key!r}")

    version = str(trace["schema_version"])
    if version.split(".")[0] != SCHEMA_VERSION.split(".")[0]:
        raise TraceError(
            f"{source}: incompatible schema_version {version!r} "
            f"(this build understands {SCHEMA_VERSION!r})"
        )

    for field in ("id", "name", "version"):
        if field not in trace["extension"]:
            raise TraceError(f"{source}: extension.{field} is required")

    for field in ("browser", "scenario"):
        if field not in trace["run"]:
            raise TraceError(f"{source}: run.{field} is required")

    for channel in CHANNELS:
        events = trace[channel]
        if not isinstance(events, list):
            raise TraceError(f"{source}: channel {channel!r} must be a list")
        for i, event in enumerate(events):
            if not isinstance(event, dict):
                raise TraceError(f"{source}: {channel}[{i}] must be an object")
            for field in REQUIRED_EVENT_FIELDS[channel]:
                if field not in event:
                    raise TraceError(f"{source}: {channel}[{i}] missing field {field!r}")
    return trace


def empty_trace(ext_id: str, name: str, version: str, *, browser: str, scenario: str) -> dict:
    """Return a well-formed, empty trace envelope for the sandbox to fill in."""
    return {
        "schema_version": SCHEMA_VERSION,
        "extension": {"id": ext_id, "name": name, "version": version},
        "run": {
            "browser": browser,
            "scenario": scenario,
            "replay_bundle": None,
            "started_at": None,
            "duration_s": None,
        },
        "manifest": {},
        "network": [],
        "dom": [],
        "storage": [],
        "api": [],
    }
