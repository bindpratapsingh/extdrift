"""Head-to-head: static code-delta vs. our dynamic behavioural diff, on obfuscation.

This is the experiment that demonstrates added value over the closest prior work.

For a benign base extension we build two malicious updates with an IDENTICAL payload:
one in clear code, one obfuscated. Then:
  * the STATIC baseline (engine.baseline, "You've Changed" style) scores each by source
    tokens — it catches the clean one and is blind to the obfuscated one;
  * OUR dynamic pipeline captures each in a real browser and scores the behavioural diff
    — it catches BOTH, because the runtime effect is the same however the code is written.

Run:  python -m experiments.headtohead
Needs Playwright + Chromium (it captures live). Writes results to out/headtohead/.
"""

from __future__ import annotations

import json
from pathlib import Path

from engine.baseline import static_score
from engine.features.delta import behavioral_delta
from engine.scoring.rules import score_delta
from engine.weaponiser import weaponise

BASE = "data/corpus/readerlite/1.0.0"
SCENARIO = "bank-login-then-webmail"
OUT = Path("out/headtohead")


def _dynamic(base_dir, cand_dir, tag) -> dict:
    """Capture base and candidate live, return our rules verdict + collector ground truth."""
    from engine.sandbox.capture import capture
    work = OUT / f"work-{tag}"
    t1 = capture(base_dir, SCENARIO, out_path=OUT / f"{tag}.v1.trace.json",
                 work_dir=work / "v1")
    t2 = capture(cand_dir, SCENARIO, out_path=OUT / f"{tag}.v2.trace.json",
                 work_dir=work / "v2")
    delta = behavioral_delta(t1, t2)
    scored = score_delta(delta)
    leaked = bool(t2["run"].get("collector_received"))
    return {"verdict": scored["verdict"], "score": scored["score"],
            "fired": [h["id"] for h in scored["fired_rules"]], "leaked": leaked}


def run(family="cookie_theft") -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    variants = {
        "clean": weaponise(BASE, OUT / "ext-clean", family=family, obfuscated=False),
        "obfuscated": weaponise(BASE, OUT / "ext-obf", family=family, obfuscated=True),
    }
    rows = []
    for name, w in variants.items():
        stat = static_score(BASE, w["out_dir"])
        dyn = _dynamic(BASE, w["out_dir"], name)
        rows.append({"variant": name, "static": stat, "dynamic": dyn})
    result = {"family": family, "base": BASE, "rows": rows}
    (OUT / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _print(result):
    print("\n" + "=" * 74)
    print(f"  HEAD-TO-HEAD  ·  payload family = {result['family']}  ·  identical behaviour, two code forms")
    print("=" * 74)
    print(f"\n  {'variant':12s} {'STATIC baseline':>22s}   {'OUR dynamic diff':>22s}   ground truth")
    print("  " + "-" * 72)
    for r in result["rows"]:
        s = r["static"]; d = r["dynamic"]
        st = f"{s['verdict']} ({s['score']:.2f})"
        dy = f"{d['verdict']} ({d['score']:.2f})"
        leak = "leak CONFIRMED" if d["leaked"] else "no leak"
        print(f"  {r['variant']:12s} {st:>22s}   {dy:>22s}   {leak}")
    print("\n  Reading: the static baseline flags the clean payload but is BLIND to the")
    print("  obfuscated one; our dynamic diff flags BOTH, because the runtime effect")
    print("  (cookie read -> POST to a new host from the service worker) is identical.")
    print("=" * 74)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="extdrift-headtohead")
    ap.add_argument("--family", default="cookie_theft")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    result = run(args.family)
    print(json.dumps(result, indent=2)) if args.json else _print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
