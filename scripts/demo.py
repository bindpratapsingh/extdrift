"""One-command demo for the progress meeting.

    python scripts/demo.py

Runs the full live pipeline on both update pairs in the corpus - a genuinely benign
feature update and a synthetically weaponised one - and prints a side-by-side summary of
the verdicts against the ground truth from the fake collector.

Needs Playwright + Chromium (see requirements.txt).  If they are missing it says so and
points at ``scripts/demo_offline.py``, which shows the same verdicts from the committed
fixture traces with no browser required.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

CASES = [
    ("Benign feature update", "readerlite/1.0.0", "readerlite/1.0.1", "BENIGN"),
    ("Weaponised update", "readerlite/1.0.0", "readerlite/1.1.0", "MALICIOUS"),
]


def main() -> int:
    from engine.runner import run_pair
    from engine.sandbox.capture import CaptureError

    corpus = ROOT / "data" / "corpus"
    rows = []
    for title, v1, v2, expected in CASES:
        print(f"\n### {title}: {v1}  ->  {v2}")
        try:
            record = run_pair(corpus / v1, corpus / v2,
                              out_dir=ROOT / "out" / f"demo-{Path(v2).parent.name}-{Path(v2).name}")
        except CaptureError as exc:
            print(f"\n[capture unavailable] {exc}")
            print("Run scripts/demo_offline.py for the same verdicts without a browser.")
            return 1
        verdict = record["verdict"]
        score = list(record["scores"].values())[0]
        leaked = record["ground_truth"]["collector_received_data"]
        ok = "OK" if verdict == expected else "!! UNEXPECTED"
        print(f"    verdict={verdict}  score={score:.2f}  "
              f"collector_got_data={leaked}  (expected {expected})  {ok}")
        rows.append((title, verdict, score, leaked, expected, verdict == expected))

    print("\n" + "=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    for title, verdict, score, leaked, expected, passed in rows:
        print(f"  {title:24s}  {verdict:10s}  score={score:.2f}  "
              f"leak={str(leaked):5s}  {'PASS' if passed else 'FAIL'}")
    print("=" * 70)
    return 0 if all(row[5] for row in rows) else 2


if __name__ == "__main__":
    raise SystemExit(main())
