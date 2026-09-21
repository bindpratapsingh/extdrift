"""Locked held-out test set + calibrated operating points.

Cross-validation numbers tune and test on the same data; a panel also wants a threshold chosen
*before* seeing the test set and a number reported *once* on data untouched by any tuning. So:

  1. Split extensions into a fixed train / held-out-test partition (by `ext_id`, seeded — no
     extension is in both, and it is the same split every run).
  2. Fit the winning model on train only.
  3. Calibrate the deployed decision threshold on the TRAIN predictions (the threshold that
     maximises F1 — an unambiguous operating point chosen without seeing the test set).
  4. Report, once, on the held-out test: PR-AUC, FPR at 90% recall, and precision/recall/FPR at
     that threshold, plus the score separation (how far apart malicious and benign scores sit).

This is the operating point the deployed detector would actually use, justified by data the
test set never influenced.

Run:  python -m experiments.operating_point
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from engine.ml.bakeoff import FEATURES, RECALL_TARGET, _build_models, _clone, _proba, load_dataset

OUT = Path("out/operating_point")


def _max_f1_threshold(y, s):
    """The threshold that maximises F1 on these predictions — an unambiguous operating point."""
    from sklearn.metrics import precision_recall_curve
    prec, rec, thr = precision_recall_curve(y, s)
    best_t, best_f1 = 0.5, -1.0
    for p, r, t in zip(prec[:-1], rec[:-1], thr):
        f1 = 2 * p * r / (p + r) if (p + r) else 0.0
        if f1 > best_f1:
            best_f1, best_t = f1, float(t)
    return best_t


def _at(y, s, thr):
    pred = (s >= thr).astype(int)
    P = int(y.sum()); N = int((1 - y).sum())
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    return {"threshold": round(float(thr), 4),
            "recall": round(tp / P, 4) if P else None,
            "precision": round(tp / (tp + fp), 4) if (tp + fp) else None,
            "fpr": round(fp / N, 4) if N else None}


def _fpr_at_recall(y, s, target):
    order = np.argsort(-s, kind="mergesort")
    ys = y[order]; tp = np.cumsum(ys); fp = np.cumsum(1 - ys)
    P = int(y.sum()); N = int((1 - y).sum())
    reaches = tp >= target * P
    if not reaches.any() or not N:
        return None
    return round(float(fp[int(np.argmax(reaches))] / N), 4)


def run(path="data/dataset/deltas.csv", model_name="histgb", seed=0, test_frac=0.25):
    from sklearn.model_selection import GroupShuffleSplit
    from sklearn.metrics import average_precision_score
    df, X, y, groups, order = load_dataset(path)
    gss = GroupShuffleSplit(n_splits=1, test_size=test_frac, random_state=seed)
    tr, te = next(gss.split(X, y, groups))
    if len(set(y[te])) < 2 or len(set(y[tr])) < 2:
        print("Split did not yield both classes in test; try another seed.")
        return None

    model = _clone(_build_models()[model_name]).fit(X[tr], y[tr])
    s_tr = _proba(model, X[tr]); s_te = _proba(model, X[te])

    thr = _max_f1_threshold(y[tr], s_tr)             # deployed threshold, calibrated on TRAIN only
    mal_mask = y[te] == 1
    sep = {"median_prob_malicious": round(float(np.median(s_te[mal_mask])), 3),
           "median_prob_benign": round(float(np.median(s_te[~mal_mask])), 3)}

    result = {
        "dataset": str(path), "model": model_name, "seed": seed,
        "train_extensions": int(len(set(groups[tr]))), "test_extensions": int(len(set(groups[te]))),
        "train_rows": int(len(tr)), "test_rows": int(len(te)), "test_malicious": int(y[te].sum()),
        "test_pr_auc": round(float(average_precision_score(y[te], s_te)), 4),
        "test_fpr_at_90pct_recall": _fpr_at_recall(y[te], s_te, RECALL_TARGET),
        "deployed_threshold_maxF1_on_train": round(float(thr), 4),
        "held_out_test_at_threshold": _at(y[te], s_te, thr),
        "score_separation_on_test": sep,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(f"\nLocked held-out test ({model_name}); split by extension, seed {seed}")
    print(f"   train: {result['train_rows']} rows / {result['train_extensions']} exts   "
          f"test: {result['test_rows']} rows / {result['test_extensions']} exts "
          f"({result['test_malicious']} malicious)")
    print(f"   held-out test PR-AUC: {result['test_pr_auc']}   FPR@90%recall: "
          f"{result['test_fpr_at_90pct_recall']}")
    a = result["held_out_test_at_threshold"]
    print(f"\n   Deployed threshold {a['threshold']} (max-F1 on TRAIN), reported once on TEST:")
    print(f"     recall {a['recall']}   precision {a['precision']}   FPR {a['fpr']}")
    print(f"   Score separation on test: malicious median {sep['median_prob_malicious']} vs "
          f"benign median {sep['median_prob_benign']} (well-separated -> one threshold suffices).")
    print(f"\n[written] {OUT/'results.json'}")
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="extdrift-operating-point")
    ap.add_argument("dataset", nargs="?", default="data/dataset/deltas.csv")
    ap.add_argument("--model", default="histgb")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args(argv)
    run(args.dataset, model_name=args.model, seed=args.seed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
