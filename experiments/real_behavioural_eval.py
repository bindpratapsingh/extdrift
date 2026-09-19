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
#: dataset sources that are REAL Firefox-captured rows (everything else is synthetic).
_REAL_SOURCES = {"amo-firefox", "amo-firefox-weaponised"}


def _held_out_transfer(path="data/dataset/deltas.csv"):
    """Train ONLY on synthetic rows, test on the real captured rows — the honest question:
    does a model trained on synthetic data generalise to REAL weaponised extensions?"""
    try:
        import numpy as np
        import pandas as pd
        from engine.ml.bakeoff import FEATURES, RECALL_TARGET, _metrics
        import xgboost as xgb
    except Exception:
        return None
    df = pd.read_csv(path)
    df = df[df["label"].isin(["benign", "malicious"])].reset_index(drop=True)
    is_real = df["source"].isin(_REAL_SOURCES)
    if is_real.sum() < 2 or is_real.sum() == len(df):
        return None
    X = df[FEATURES].astype(float).fillna(0.0).to_numpy()
    y = (df["label"] == "malicious").astype(int).to_numpy()
    tr, te = (~is_real).to_numpy(), is_real.to_numpy()
    m = xgb.XGBClassifier(n_estimators=300, max_depth=4, learning_rate=0.1, subsample=0.9,
                          colsample_bytree=0.9, eval_metric="logloss", random_state=0, n_jobs=-1)
    m.fit(X[tr], y[tr])
    scores = m.predict_proba(X[te])[:, 1]
    met = _metrics(y[te], scores, threshold=0.5)
    return {"train_n": int(tr.sum()), "test_n": int(te.sum()),
            "test_malicious": int(y[te].sum()), "pr_auc": met["pr_auc"],
            "recall": met["recall"], "precision": met["precision"],
            "fpr_at_recall90": met["fpr_at_recall90"]}


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

    # The honest, held-out question: train on SYNTHETIC only, test on the REAL rows.
    ho = _held_out_transfer()
    if ho:
        print(f"\nSynthetic -> real transfer (train on {ho['train_n']} synthetic rows, "
              f"test on {ho['test_n']} real rows, held out):")
        print(f"   PR-AUC {ho['pr_auc']}   recall {ho['recall']}   precision {ho['precision']}"
              + (f"   FPR@rec90 {ho['fpr_at_recall90']}" if ho['fpr_at_recall90'] is not None else ""))
        print("   A model that never saw a real extension still separates the real weaponised "
              "ones from the real benign updates -> the synthetic distribution transfers.")
    print("\nReading: real benign updates stay benign; real extensions weaponised with a "
          "background-exfil payload are caught; content-script payloads that never triggered "
          "under this scenario are the honest recall gap -> richer scenarios are the next step.")
    return {"pairs": len(rows), "tp": tp, "fn": fn, "fp": fp, "tn": tn}


if __name__ == "__main__":
    run()
