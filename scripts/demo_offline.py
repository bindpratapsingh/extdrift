"""Browser-free demo: scores the three committed fixture pairs.

    python scripts/demo_offline.py

Runs the analysis half of the pipeline (diff + rules + report) over the hand-authored
fixture traces in data/fixtures/.  Needs nothing but the standard library, so it works on
any machine and is the fallback when Playwright/Chromium are not installed.  The verdicts
here match what the live pipeline (scripts/demo.py) produces from real browser runs.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.features.delta import behavioral_delta  # noqa: E402
from engine.scoring.rules import score_delta  # noqa: E402

PAIRS = [
    ("Benign feature update", "benign_pair", "BENIGN"),
    ("Gray-zone data-enrichment update", "grayzone_pair", "SUSPICIOUS"),
    ("Weaponised (Cyberhaven-style) update", "weaponised_pair", "MALICIOUS"),
]


def load(pair: str, version: str) -> dict:
    return json.loads((ROOT / "data" / "fixtures" / pair / f"{version}.trace.json")
                      .read_text(encoding="utf-8"))


def main() -> int:
    rows = []
    for title, pair, expected in PAIRS:
        delta = behavioral_delta(load(pair, "v1"), load(pair, "v2"))
        scored = score_delta(delta)
        fired = ", ".join(hit["id"] for hit in scored["fired_rules"]) or "-"
        rows.append((title, scored["verdict"], scored["score"], fired, expected,
                     scored["verdict"] == expected))

    print("=" * 78)
    print("  extdrift - offline fixture demo (no browser required)")
    print("=" * 78)
    for title, verdict, score, fired, expected, passed in rows:
        print(f"\n  {title}")
        print(f"    verdict = {verdict:10s}  score = {score:.2f}  "
              f"(expected {expected})  {'PASS' if passed else 'FAIL'}")
        print(f"    rules fired: {fired}")
    print("\n" + "=" * 78)
    return 0 if all(row[5] for row in rows) else 2


if __name__ == "__main__":
    raise SystemExit(main())
