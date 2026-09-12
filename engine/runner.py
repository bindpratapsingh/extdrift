"""End-to-end orchestration: two unpacked versions in, one scored report out.

    from engine.runner import run_pair
    report = run_pair("data/corpus/readerlite/1.0.0",
                      "data/corpus/readerlite/1.1.0",
                      scenario="bank-login-then-webmail")

This is the whole pipeline in one call - capture v1, capture v2 under an identical
scripted run against identical pages, diff, score, render - and it is what the
``run-pair`` CLI command and the demo script both drive.  Capture is imported inside the
function so importing this module does not require Playwright.
"""

from __future__ import annotations

import json
from pathlib import Path

from engine.features.delta import behavioral_delta
from engine.report.render import build_record, render_text
from engine.scoring.rules import score_delta


def run_pair(
    baseline_dir: str | Path,
    candidate_dir: str | Path,
    *,
    scenario: str = "bank-login-then-webmail",
    out_dir: str | Path = "out",
    headless: bool = True,
) -> dict:
    """Capture both versions, diff and score them, and write all artefacts to *out_dir*.

    Returns the full analysis record.  Writes v1.trace.json, v2.trace.json,
    report.json and report.txt so a run is fully reproducible from disk afterwards.
    """
    from engine.sandbox.capture import capture  # lazy: needs Playwright

    baseline_dir, candidate_dir = Path(baseline_dir), Path(candidate_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    trace_v1 = capture(baseline_dir, scenario,
                       out_path=out_dir / "v1.trace.json",
                       work_dir=out_dir / "work-v1", headless=headless)
    trace_v2 = capture(candidate_dir, scenario,
                       out_path=out_dir / "v2.trace.json",
                       work_dir=out_dir / "work-v2", headless=headless)

    delta = behavioral_delta(trace_v1, trace_v2)
    scored = score_delta(delta)
    # Add the ML probability when a trained model is present; None otherwise (the pipeline
    # never hard-depends on the ML stack).
    try:
        from engine.ml.predict import predict_pair
        ml = predict_pair(trace_v1, trace_v2)
    except Exception:
        ml = None
    record = build_record(delta, scored, ml)

    # Cross-check the verdict against the fake collector's own log: if data actually
    # reached the collector, a MALICIOUS/SUSPICIOUS verdict is corroborated by ground
    # truth, and a BENIGN one is a miss worth surfacing rather than hiding.
    leaked = bool(trace_v2["run"].get("collector_received"))
    record["ground_truth"] = {
        "collector_received_data": leaked,
        "collector_log": trace_v2["run"].get("collector_received", []),
    }

    (out_dir / "report.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    (out_dir / "report.txt").write_text(render_text(delta, scored, ml), encoding="utf-8")
    return record
