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
from engine.sandbox.testsite import COLLECTOR_HOSTS
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
        "extension_id": unpacked.get("extension_id"),
        "name": manifest.get("name", "unknown"),
        "version": manifest.get("version", "0"),
        "manifest_version": manifest.get("manifest_version", 2),
        "permissions": manifest.get("permissions", []),
        "host_permissions": manifest.get("host_permissions", []),
        "background": background_kind,
        "files": unpacked.get("file_count", 0),
    }


#: The features worth charting: small integer counts that share one axis, so a reader can
#: compare version N and version N+1 at a glance. Byte-scale features are left off the
#: chart (they would flatten everything else) and reported as plain numbers instead.
CHART_FEATURES = [
    ("net_hosts", "Hosts contacted"),
    ("net_ext_initiated", "Requests from the extension"),
    ("net_posts", "Uploads (POST/PUT)"),
    ("cookie_reads", "Cookie reads"),
    ("cookie_bulk_reads", "Whole-jar cookie reads"),
    ("dom_sensitive_reads", "Credential-field reads"),
    ("api_high_risk", "High-risk API calls"),
    ("exfil_flows", "Read-then-send flows"),
    ("perm_high_risk", "High-risk permissions"),
]


def chart_series(features_v1: dict, features_v2: dict) -> list[dict]:
    """The bars for the version-vs-version chart: only features that are non-zero in at
    least one version, so the chart shows signal rather than a row of empty axes."""
    series = []
    for name, label in CHART_FEATURES:
        v1 = float(features_v1.get(name, 0.0))
        v2 = float(features_v2.get(name, 0.0))
        if v1 or v2:
            series.append({"label": label, "v1": v1, "v2": v2})
    return series


def build_briefing(record: dict, outcome: dict, *, new_keys: list, dropped_keys: list,
                   declared: list, leaked: list,
                   summary_v1: dict, summary_v2: dict) -> dict:
    """A short, plain-English brief: the verdict, what the update is doing, and the
    indicators behind the call. This is the thing a reviewer reads instead of the trace.
    """
    evidence = record.get("evidence", {})

    doing: list[str] = []
    if leaked:
        doing.append("Exfiltration confirmed: the sandbox collector received %d upload(s) "
                     "from version N+1. This is observed, not inferred." % len(leaked))
    for host in evidence.get("new_upload_hosts", []):
        doing.append("Uploads to a host the old version never contacted: %s." % host)
    for target in evidence.get("new_sensitive_dom_targets", []):
        doing.append("Reads a credential/secret-bearing field it did not read before: %s." % target)
    for api in evidence.get("new_apis", []):
        doing.append("Calls a new extension API: %s." % api)
    for host in evidence.get("new_third_party_hosts", []):
        if host not in evidence.get("new_upload_hosts", []):
            doing.append("Contacts a new third-party host: %s." % host)
    if not doing and new_keys:
        doing.append("Adds %d new behaviour(s), none of which match a known-dangerous "
                     "pattern." % len(new_keys))
    if not doing and not new_keys:
        doing.append("Produces the same behaviour as the old version under this scenario.")

    indicators = [
        {"name": r.get("name", r.get("id", "")),
         "weight": r.get("weight"),
         "provenance": r.get("provenance", ""),
         "evidence": r.get("evidence", "")}
        for r in record.get("fired_rules", [])
    ]

    capability = list(declared) if declared else ["The update declares no new capability."]

    scores = record.get("scores", {})
    ml = record.get("ml")
    confidence = []
    if ml:
        confidence.append("Two independent scorers were run: heuristic rules and a trained "
                          "model. They %s." % ("agree on this verdict"
                          if record.get("scorer_agreement") else "do NOT agree - treat with care"))
    confidence.extend(record.get("caveats", []))

    return {
        "verdict": outcome["label"],
        "class": outcome["class"],
        "headline": outcome["headline"],
        "summary": outcome["detail"],
        "extension": {"name": summary_v2.get("name"),
                      "v1": summary_v1.get("version"), "v2": summary_v2.get("version"),
                      "manifest_version": summary_v2.get("manifest_version"),
                      "extension_id": summary_v2.get("extension_id")},
        "doing": doing,
        "indicators": indicators,
        "capability_change": capability,
        "scores": scores,
        "confidence": confidence,
        "collector_proven": bool(leaked),
        "counts": {"new_behaviours": len(new_keys), "dropped_behaviours": len(dropped_keys)},
        "chart": chart_series(record.get("features_v1", {}), record.get("features_v2", {})),
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
        "detail": "%d distinct behaviour(s) appear in version N+1 that version N never "
                  "produced; %d of the 26 behavioural features moved." % (
                      len(new_keys), len(moved)),
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
    for slot, summary in (("N  ", summary_v1), ("N+1", summary_v2)):
        emit("log", text="version %s : %s %s, MV%s, %d files, read from %s" % (
            slot, summary["name"], summary["version"], summary["manifest_version"],
            summary["files"], summary["format"]))

    # Two packages are versions of one extension only if they carry the same id. Chrome
    # decides that from the signing key in the CRX header; if we are given bare archives
    # there is no id to check and the comparison rests on the operator's say-so.
    id_v1, id_v2 = summary_v1["extension_id"], summary_v2["extension_id"]
    if id_v1 and id_v2:
        emit("log", text="identity    : both packages are signed as %s - %s" % (
            id_v1, "the same extension, so this really is an update" if id_v1 == id_v2
            else "DIFFERENT IDS, these are not two versions of one extension"))
    else:
        emit("log", text="identity    : unsigned archive, so there is no extension id to "
                         "check; taking it on trust that these are two versions of one "
                         "extension")

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
    # These lines say how the run is configured. They are settings, not findings, and are
    # marked as such: the measurements come after each run, read back off the trace.
    emit("stage", id="seal", state="active")
    emit("log", text="config  : Chromium, fresh profile, no state carried in or out")
    emit("log", text="config  : every .test name is resolved to the in-process test site, "
                     "so no DNS query is made and no packet leaves this machine")
    emit("log", text="config  : collector hosts %s answer locally and record what they "
                     "are sent" % ", ".join(sorted(COLLECTOR_HOSTS)))
    emit("log", text="config  : both versions run scenario '%s' against the same local "
                     "pages" % scenario)
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
        run = trace["run"]
        instrumentation = run.get("instrumentation", {})

        # Everything from here is read back off the trace this run produced.
        emit("log", text="%s run   : finished in %.1fs, %d behaviours across %d pages" % (
            slot, time.monotonic() - started, len(rows), len(run["pages"])))
        emit("log", text="%s run   : instrumented %s; test site served on port %s" % (
            slot, ", ".join(instrumentation.get("instrumented_scripts", [])) or "nothing",
            instrumentation.get("testsite_port", "?")))
        hosts = sorted({_host(e.get("url", "")) for e in trace.get("network", [])} - {""})
        offsite = [h for h in hosts if not h.endswith(".test")]
        emit("log", text="%s egress: %d request(s) to %d host(s): %s" % (
            slot, len(trace.get("network", [])), len(hosts), ", ".join(hosts) or "none"))
        emit("log", text="%s egress: %s" % (
            slot, "every host is a .test name answered inside the sandbox; nothing "
                  "reached the internet" if not offsite
                  else "OFF-SANDBOX HOSTS CONTACTED: %s" % ", ".join(offsite)))
        counts = ", ".join("%s %d" % (channel, len(trace.get(channel, [])))
                           for channel in ("network", "dom", "storage", "api"))
        emit("log", text="%s record: %s" % (slot, counts))
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
    briefing = build_briefing(record, outcome, new_keys=new_keys, dropped_keys=dropped_keys,
                              declared=declared, leaked=leaked,
                              summary_v1=summary_v1, summary_v2=summary_v2)
    record["briefing"] = briefing
    emit("stage", id="score", state="done")
    emit("verdict", outcome=outcome, record=record, briefing=briefing,
         new_keys=new_keys, dropped_keys=dropped_keys)
    return record
