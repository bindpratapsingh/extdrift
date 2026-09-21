"""Performance characterization — how fast is each stage, and how does it scale?

A complete system should quantify its throughput. The pipeline has three stages with very
different costs, and this measures each on the current machine:

  * CAPTURE   — browser-bound; one extension version takes seconds-to-minutes. Reported from the
    committed capture logs / a note, since it needs a browser (not re-measured here).
  * ANALYSIS  — trace -> delta -> score. This is the stage that must scale to a whole store, and
    it is pure Python: we time it over the real captured pairs and project a per-hour rate.
  * ML        — rebuilding the dataset table and re-training the six-model bake-off.

Run:  python -m experiments.performance
"""

from __future__ import annotations

import json
import time
from pathlib import Path

CAPTURED = Path("data/dataset/captured")


def _time(fn, *a, **k):
    t0 = time.perf_counter(); out = fn(*a, **k); return out, time.perf_counter() - t0


def run():
    from engine.features.delta import behavioral_delta
    from engine.scoring.rules import score_delta

    pairs = []
    for d in sorted(CAPTURED.glob("*")):
        v1, v2 = d / "v1.trace.json", d / "v2.trace.json"
        if v1.exists() and v2.exists():
            pairs.append((json.loads(v1.read_text()), json.loads(v2.read_text())))

    print("\nPerformance characterization (this machine)\n")

    # --- ANALYSIS stage (the one that must scale to store size) ---
    if pairs:
        # warm up, then time delta+score over all captured pairs a few times
        for t1, t2 in pairs[:3]:
            score_delta(behavioral_delta(t1, t2))
        reps = 5
        t0 = time.perf_counter()
        for _ in range(reps):
            for t1, t2 in pairs:
                score_delta(behavioral_delta(t1, t2))
        dt = (time.perf_counter() - t0) / (reps * len(pairs))
        per_ms = dt * 1000
        per_hr = int(3600 / dt) if dt else 0
        print(f"   ANALYSIS (delta + rule score), per update pair: {per_ms:.2f} ms")
        print(f"     -> ~{per_hr:,} pairs/hour on one core (this is the store-scan-relevant rate)")
        print(f"     measured over {len(pairs)} real captured pairs")
    else:
        print("   ANALYSIS: no captured pairs on disk to time.")

    # --- ML stage ---
    try:
        from engine.batch import build
        from engine.ml.bakeoff import run_bakeoff
        _, t_build = _time(build, n_extensions=250, updates_per_ext=4,
                           captured_dir="data/dataset/captured", out="out/perf_deltas.csv")
        _, t_bake = _time(run_bakeoff, "out/perf_deltas.csv", save=False)
        print(f"\n   ML: rebuild dataset (1000+ pairs): {t_build:.1f} s")
        print(f"   ML: six-model bake-off (train + leakage-free CV): {t_bake:.1f} s")
    except Exception as exc:  # noqa: BLE001
        print(f"\n   ML timing skipped: {type(exc).__name__}: {exc}")

    print("\n   CAPTURE (browser-bound, not re-timed here): ~1-3 min per extension version on this")
    print("   machine (large ad-blockers slower); this is the only stage that needs a browser and")
    print("   the reason large-scale real capture is offloaded (see docs/MAC_RUNBOOK.md).")
    print("\n   Reading: analysis is milliseconds per pair, so once traces exist the detector scans")
    print("   at scale on one core; capture is the bottleneck, and it parallelises across machines.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
