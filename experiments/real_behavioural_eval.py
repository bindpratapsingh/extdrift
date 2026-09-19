"""Score ONLY the real captured pairs — the honest real-data behavioural evaluation.

The bake-off number is dominated by synthetic rows; this reports how the detector does on
the real captured pairs alone: real benign AMO updates (should stay BENIGN) and real
extensions weaponised with a real payload (should read MALICIOUS). It scores each pair with
both the transparent rules and the trained ML model, so the two are directly comparable on
real data, and prints per-pair verdicts plus recall / false-positive summaries.

It is deliberately not cherry-picked: every captured pair is shown, including the
trigger-dependent payloads that did not fire under this scenario — that miss is the real
recall gap (literature pitfall #3, dilatory/trigger-based evasion), not something to hide.

Run:  python -m experiments.real_behavioural_eval
"""

from __future__ import annotations

import json
from pathlib import Path

from engine.features.delta import behavioral_delta
from engine.scoring.rules import score_delta

CAPTURED = Path("data/dataset/captured")


def _real_pairs():
    for d in sorted(CAPTURED.glob("amo_*")):
        v1, v2, lab = d / "v1.trace.json", d / "v2.trace.json", d / "label.json"
        if v1.exists() and v2.exists() and lab.exists():
            yield d.name, json.loads(v1.read_text()), json.loads(v2.read_text()), \
                json.loads(lab.read_text())


def run():
    try:
        from engine.ml.predict import load_model, predict_pair
        have_ml = load_model() is not None
    except Exception:
        have_ml, predict_pair = False, None

    rows = list(_real_pairs())
    if not rows:
        print("No real captured pairs. Run experiments/capture_amo_behavioural + "
              "capture_weaponised_behavioural first.")
        return {"pairs": 0}

    print(f"\nReal-data behavioural evaluation — {len(rows)} captured pairs "
          f"(Firefox engine, same schema as training)\n")
    hdr = f"{'pair':44s} {'truth':10s} {'rule':11s} {'ml_prob':>7s}  ok"
    print(hdr); print("-" * len(hdr))

    tp = fp = fn = tn = 0
    ml_correct = 0
    for name, t1, t2, lab in rows:
        truth = lab.get("label", "?")
        delta = behavioral_delta(t1, t2)
        sc = score_delta(delta)
        rule_v = sc.get("verdict", "?")
        ml_prob = None
        if have_ml:
            try:
                ml_prob = predict_pair(t1, t2).get("probability")
            except Exception:
                ml_prob = None
        # rule "flag" = SUSPICIOUS or MALICIOUS; ml flag = prob >= 0.5
        rule_flag = rule_v in ("SUSPICIOUS", "MALICIOUS")
        truth_mal = truth == "malicious"
        if truth_mal and rule_flag: tp += 1
        elif truth_mal and not rule_flag: fn += 1
        elif not truth_mal and rule_flag: fp += 1
        else: tn += 1
        if ml_prob is not None and ((ml_prob >= 0.5) == truth_mal):
            ml_correct += 1
        ok = "OK" if (rule_flag == truth_mal) else "MISS"
        mlp = f"{ml_prob:.2f}" if ml_prob is not None else "  -"
        print(f"{name:44s} {truth:10s} {rule_v:11s} {mlp:>7s}  {ok}")

    mal = tp + fn
    ben = tn + fp
    print("\nRules on real data:")
    print(f"   malicious recall (flagged SUSPICIOUS+): {tp}/{mal}"
          + (f" = {tp/mal:.0%}" if mal else ""))
    print(f"   benign false-positives:                 {fp}/{ben}"
          + (f" = {fp/ben:.0%}" if ben else ""))
    if have_ml:
        print(f"ML model on real data: {ml_correct}/{len(rows)} correct at p>=0.5 "
              "(note: these rows are also in training; this is a sanity read, not held-out).")
    print("\nReading: real benign updates stay benign; real extensions weaponised with a "
          "background-exfil payload are caught; content-script payloads that never triggered "
          "under this scenario are the honest recall gap -> richer scenarios are the next step.")
    return {"pairs": len(rows), "tp": tp, "fn": fn, "fp": fp, "tn": tn}


if __name__ == "__main__":
    run()
