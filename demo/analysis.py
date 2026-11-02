"""The demo's view of the pipeline: run a pair, and narrate every step as it happens.

``analyse_pair`` is a thin shell around the real engine - :func:`engine.sandbox.capture`,
:func:`engine.features.delta.behavioral_delta`, :func:`engine.scoring.rules.score_delta`
and the trained model. It adds nothing to the analysis. What it adds is *narration*: it
reports each pipeline stage as it starts and finishes, turns each version's trace into a
flat table of observed behaviour, and marks the rows that exist in the candidate and not
in the baseline. That is what makes the process visible on screen instead of being a
single verdict printed after a silent wait.

The one judgement made here and nowhere else is the NO CHANGE verdict: the engine scores
a zero delta as a very low BENIGN, which is correct but tells a viewer nothing. When two
versions behave identically the demo says so explicitly, because "this update changed
nothing observable" is a different statement from "this update is safe".
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from engine.features.delta import behavioral_delta
from engine.report.render import build_record
from engine.scoring.rules import score_delta
from engine.unpack.crx import unpack_extension
from engine.unpack.manifest import diff_manifests, summarise_manifest_diff

Emit = Callable[..., None]

SCENARIO = "bank-login-then-webmail"

# The stages a viewer sees, in order. Kept here so the UI and the runner cannot drift.
STAGES = [
    ("validate", "Validate and unpack both packages"),
    ("seal", "Seal the sandbox"),
    ("run_v1", "Execute version N"),
    ("run_v2", "Execute version N+1"),
    ("diff", "Difference the two behaviours"),
    ("score", "Score the change"),
]

# Reads that are sensitive wherever they happen. Used only to mark rows in the table;
# the scoring rules reach their own conclusion independently of this list.
SENSITIVE_TARGETS = ("document.cookie", "password", "input[name=username]", "creditcard")


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def behaviour_rows(trace: dict) -> list[dict]:
    """Flatten a trace into one table of observed behaviour, in time order.

    ``key`` is what makes two runs comparable: it deliberately excludes timestamps and
    the per-run random realm id, so the same action in two runs produces the same key and
    the diff shows real behavioural change rather than run-to-run jitter.
    """
    rows: list[dict] = []

    for event in trace.get("network", []):
        url = event.get("url", "")
        rows.append({
            "t": event.get("ts", 0.0),
            "channel": "network",
            "actor": event.get("initiator", "?"),
            "action": f"{event.get('method', 'GET')} {event.get('resource_type', '')}".strip(),
            "detail": url,
            "note": f"{event['body_len']} bytes uploaded" if event.get("body_len") else "",
            "key": "network|%s|%s|%s" % (event.get("method"), _host(url), urlsplit(url).path),
        })

    for event in trace.get("dom", []):
        target = event.get("target", "")
        rows.append({
            "t": event.get("ts", 0.0),
            "channel": "dom",
            "actor": event.get("realm") or event.get("frame", "?"),
            "action": event.get("event", "?"),
            "detail": target,
            "note": event.get("origin", ""),
            "key": "dom|%s|%s|%s" % (event.get("event"), target, event.get("listener_type", "")),
            "sensitive": any(s in target.lower() for s in SENSITIVE_TARGETS),
        })

    for event in trace.get("storage", []):
        rows.append({
            "t": event.get("ts", 0.0),
            "channel": "storage",
            "actor": event.get("frame", "?"),
            "action": event.get("api", "?"),
            "detail": "%d argument(s)" % event.get("arg_count", 0),
            "note": "",
            "key": "storage|%s" % event.get("api"),
        })

    for event in trace.get("api", []):
        shapes = [".".join(sorted(a.get("keys", [])))
                  for a in event.get("args", []) if isinstance(a, dict)]
        rows.append({
            "t": event.get("ts", 0.0),
            "channel": "api",
            "actor": event.get("realm") or event.get("frame", "?"),
            "action": event.get("api", "?"),
            "detail": ", ".join(s for s in shapes if s) or "%d argument(s)" % event.get("arg_count", 0),
            "note": "",
            "key": "api|%s" % event.get("api"),
        })

    rows.sort(key=lambda r: (r["t"], r["channel"]))
    return rows


def package_summary(unpacked: dict, path: Path) -> dict:
    """The facts about a package worth showing before it is ever executed."""
    manifest = unpacked["manifest"]
    background = manifest.get("background") or {}
    if "service_worker" in background:
        background_kind = "service worker"
    elif background:
        background_kind = "background page"
    else:
        background_kind = "none"
    return {
        "file": path.name,
        "format": unpacked.get("format", "directory"),
        "name": manifest.get("name", "unknown"),
        "version": manifest.get("version", "0"),
        "manifest_version": manifest.get("manifest_version", 2),
        "permissions": manifest.get("permissions", []),
        "host_permissions": manifest.get("host_permissions", []),
        "background": background_kind,
        "files": unpacked.get("file_count", 0),
    }


def classify(numeric: dict, scored: dict, new_keys: list, dropped_keys: list) -> dict:
    """Decide what goes on the verdict band, and say why in one sentence.

    *numeric* is the per-feature delta, i.e. ``behavioral_delta(...)["numeric"]``.
    """
    moved = [name for name, value in numeric.items() if abs(value) > 1e-9]
    if not moved and not new_keys and not dropped_keys:
        return {
            "label": "NO CHANGE",
            "class": "nochange",
            "headline": "The update changed nothing we can observe.",
            "detail": "Both versions produced an identical set of behaviours under an "
                      "identical scripted run, and every one of the 26 behavioural "
                      "features is unchanged. There is nothing to score.",
        }
    headlines = {
        "MALICIOUS": "The update introduced behaviour consistent with an attack.",
        "SUSPICIOUS": "The update introduced behaviour a human needs to look at.",
        "BENIGN": "The update changed behaviour, and the change is not dangerous.",
    }
    verdict = scored["verdict"]
    return {
        "label": verdict,
        "class": verdict.lower(),
        "headline": headlines.get(verdict, verdict),
        "detail": "%d behaviour(s) appear in version N+1 that version N never produced; "
                  "%d of the 26 behavioural features moved." % (len(new_keys), len(moved)),
    }


def analyse_pair(
    package_v1: Path,
    package_v2: Path,
    work_dir: Path,
    emit: Emit,
    *,
    scenario: str = SCENARIO,
    headless: bool = True,
) -> dict:
    """Run the full pipeline on two packages, narrating it through *emit*."""
    from engine.sandbox.capture import capture  # lazy: needs Playwright

    work_dir.mkdir(parents=True, exist_ok=True)

    # --- 1. validate and unpack -------------------------------------------------------
    emit("stage", id="validate", state="active")
    unpacked_v1 = unpack_extension(package_v1, work_dir / "unpacked-v1")
    unpacked_v2 = unpack_extension(package_v2, work_dir / "unpacked-v2")
    summary_v1 = package_summary(unpacked_v1, Path(package_v1))
    summary_v2 = package_summary(unpacked_v2, Path(package_v2))
    emit("package", slot="v1", **summary_v1)
    emit("package", slot="v2", **summary_v2)
    emit("log", text="version N   : %s %s (MV%s, %d files)" % (
        summary_v1["name"], summary_v1["version"],
        summary_v1["manifest_version"], summary_v1["files"]))
    emit("log", text="version N+1 : %s %s (MV%s, %d files)" % (
        summary_v2["name"], summary_v2["version"],
        summary_v2["manifest_version"], summary_v2["files"]))

    manifest_diff = diff_manifests(unpacked_v1["manifest"], unpacked_v2["manifest"])
    declared = summarise_manifest_diff(manifest_diff)
    emit("manifest_diff",
         lines=declared or ["The update declares no new capability."],
         added_permissions=[p["permission"] for p in manifest_diff["added_permissions"]])
    for line in declared:
        emit("log", text="declared change: " + line)
    if not declared:
        emit("log", text="declared change: none - the manifest asks for nothing new")
    emit("stage", id="validate", state="done")

    # --- 2. the sandbox ---------------------------------------------------------------
    emit("stage", id="seal", state="active")
    emit("log", text="sandbox: Chromium, fresh profile, no state carried in or out")
    emit("log", text="sandbox: every .test name resolves to the in-process test site, "
                     "so no DNS query is made and no packet leaves this machine")
    emit("log", text="sandbox: the fake collector is armed - whatever the extension "
                     "uploads is captured here, as ground truth")
    emit("log", text="sandbox: both versions run the identical scenario '%s' against "
                     "byte-identical pages" % scenario)
    emit("stage", id="seal", state="done")

    # --- 3 and 4. the two runs --------------------------------------------------------
    traces = {}
    for slot, source, stage in (("v1", unpacked_v1, "run_v1"), ("v2", unpacked_v2, "run_v2")):
        emit("stage", id=stage, state="active")
        emit("log", text="%s: instrumenting the extension's own bundle (prelude injection "
                         "into the content script and the background context)" % slot)
        started = time.monotonic()
        trace = capture(
            Path(source["unpacked_to"]), scenario,
            out_path=work_dir / ("%s.trace.json" % slot),
            work_dir=work_dir / ("work-%s" % slot),
            headless=headless,
        )
        traces[slot] = trace
        rows = behaviour_rows(trace)
        emit("log", text="%s: run finished in %.1fs - %d behaviours observed across "
                         "%d pages" % (slot, time.monotonic() - started, len(rows),
                                       len(trace["run"]["pages"])))
        emit("observed", slot=slot, rows=rows,
             duration=trace["run"]["duration_s"],
             pages=trace["run"]["pages"],
             collector=trace["run"].get("collector_received", []))
        emit("stage", id=stage, state="done")

    # --- 5. the diff ------------------------------------------------------------------
    emit("stage", id="diff", state="active")
    rows_v1, rows_v2 = behaviour_rows(traces["v1"]), behaviour_rows(traces["v2"])
    keys_v1 = {r["key"] for r in rows_v1}
    keys_v2 = {r["key"] for r in rows_v2}
    new_keys = sorted(keys_v2 - keys_v1)
    dropped_keys = sorted(keys_v1 - keys_v2)
    delta = behavioral_delta(traces["v1"], traces["v2"])
    emit("diff", new_keys=new_keys, dropped_keys=dropped_keys, delta=delta["numeric"])
    emit("log", text="diff: %d new behaviour(s), %d behaviour(s) no longer present" % (
        len(new_keys), len(dropped_keys)))
    emit("stage", id="diff", state="done")

    # --- 6. score ---------------------------------------------------------------------
    emit("stage", id="score", state="active")
    scored = score_delta(delta)
    emit("log", text="rules: %d of 12 heuristics fired, combined %.3f" % (
        len(scored["fired_rules"]), scored["score"]))
    try:
        from engine.ml.predict import predict_pair
        ml = predict_pair(traces["v1"], traces["v2"])
    except Exception:
        ml = None
    if ml:
        emit("log", text="model: %s probability %.3f" % (ml["scorer"], ml["probability"]))
    else:
        emit("log", text="model: no trained model on disk - rules only "
                         "(train with: python -m engine.ml.bakeoff data/dataset/deltas.csv)")

    record = build_record(delta, scored, ml)
    leaked = traces["v2"]["run"].get("collector_received", [])
    record["ground_truth"] = {
        "collector_received_data": bool(leaked),
        "collector_log": leaked,
    }
    if leaked:
        emit("log", text="ground truth: the collector received %d upload(s) - the leak is "
                         "proven, not inferred" % len(leaked))

    outcome = classify(delta["numeric"], scored, new_keys, dropped_keys)
    emit("stage", id="score", state="done")
    emit("verdict", outcome=outcome, record=record,
         new_keys=new_keys, dropped_keys=dropped_keys)
    return record
