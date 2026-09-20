"""Statistical rigor: confidence intervals on the headline metrics + is ML really beating rules?

A point estimate ("PR-AUC 0.98") does not tell a panel whether the number is stable or whether
the ML tier's edge over the rules baseline is real or noise. This bootstraps the leakage-free
out-of-fold predictions to put **95% confidence intervals** on PR-AUC and on the false-positive
rate at 90% recall, for the rules control and the tree models, and it puts a CI on the
*difference* (best model minus rules): if that CI excludes 0, the improvement is significant.

Bootstrapping the out-of-fold scores (rather than re-running cross-validation thousands of times)
is the standard, cheap way to get CIs on classifier metrics from a single evaluation.

Run:  python -m experiments.statistical_rigor
      python -m experiments.statistical_rigor --boot 5000 --models rules,rf,xgboost,histgb
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from engine.ml.bakeoff import RECALL_TARGET, _build_models, _cv_scores, load_dataset

OUT = Path("out/statistical_rigor")


def _pr_auc(y, s):
    from sklearn.metrics import average_precision_score
    return float(average_precision_score(y, s)) if y.sum() and (1 - y).sum() else float("nan")


def _fpr_at_recall(y, s, target=RECALL_TARGET):
    """Minimum FPR at the strictest threshold that still reaches `target` recall.

    Vectorised (sort once, cumulative TP/FP) so it is cheap enough to bootstrap thousands of
    times; equivalent to the sweep in bakeoff._metrics.
    """
    y = np.asarray(y); s = np.asarray(s, dtype=float)
    P = int(y.sum()); N = int((1 - y).sum())
    if not P or not N:
        return float("nan")
    order = np.argsort(-s, kind="mergesort")     # highest score first = strictest threshold first
    ys = y[order]
    tp = np.cumsum(ys)
    fp = np.cumsum(1 - ys)
    reaches = tp >= target * P
    if not reaches.any():
        return float("nan")
    k = int(np.argmax(reaches))                  # first (smallest) prefix that hits target recall
    return float(fp[k] / N)


def _ci(values, lo=2.5, hi=97.5):
    arr = np.array([v for v in values if not np.isnan(v)], dtype=float)
    if arr.size == 0:
        return (float("nan"), float("nan"))
    return (float(np.percentile(arr, lo)), float(np.percentile(arr, hi)))


def _oof(name, models, X, y, groups, df):
    return _cv_scores(name, models.get(name), X, y, groups, df)


def run(path="data/dataset/deltas.csv", boot=2000, model_names=("rules", "rf", "xgboost", "histgb"),
        seed=0):
    df, X, y, groups, order = load_dataset(path)
    models = _build_models()
    rng = np.random.RandomState(seed)
    n = len(y)

    # Out-of-fold scores per model (leakage-free), computed once.
    oof = {name: _oof(name, models, X, y, groups, df) for name in model_names}

    # Bootstrap resamples of row indices, shared across models so the ML-minus-rules
    # difference is paired on the same resample.
    idxs = [rng.randint(0, n, n) for _ in range(boot)]

    report = {"dataset": str(path), "rows": n, "bootstrap": boot, "models": {}}
    point, dist = {}, {}
    for name in model_names:
        s = oof[name]
        pr_pt = _pr_auc(y, s); fpr_pt = _fpr_at_recall(y, s)
        pr_bs = [_pr_auc(y[i], s[i]) for i in idxs]
        fpr_bs = [_fpr_at_recall(y[i], s[i]) for i in idxs]
        point[name] = pr_pt; dist[name] = pr_bs
        report["models"][name] = {
            "pr_auc": round(pr_pt, 4), "pr_auc_ci95": [round(v, 4) for v in _ci(pr_bs)],
            "fpr_at_recall90": round(fpr_pt, 4), "fpr_ci95": [round(v, 4) for v in _ci(fpr_bs)]}

    # Significance: best ML model vs rules, paired on each resample.
    ml = [m for m in model_names if m != "rules"]
    best = max(ml, key=lambda m: point.get(m, 0.0)) if ml else None
    sig = None
    if best and "rules" in oof:
        diffs = [dist[best][b] - dist["rules"][b] for b in range(boot)]
        lo, hi = _ci(diffs)
        sig = {"best_model": best,
               "pr_auc_gain": round(point[best] - point["rules"], 4),
               "gain_ci95": [round(lo, 4), round(hi, 4)],
               "significant": bool(lo > 0)}
    report["significance"] = sig

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"\nStatistical rigor on {n} pairs ({boot} bootstrap resamples of the "
          f"leakage-free out-of-fold predictions)\n")
    print(f"   {'model':10s} {'PR-AUC (95% CI)':26s} {'FPR@90%rec (95% CI)':24s}")
    print("   " + "-" * 60)
    for name in model_names:
        m = report["models"][name]
        pr = f"{m['pr_auc']:.3f} [{m['pr_auc_ci95'][0]:.3f}, {m['pr_auc_ci95'][1]:.3f}]"
        fp = f"{m['fpr_at_recall90']:.3f} [{m['fpr_ci95'][0]:.3f}, {m['fpr_ci95'][1]:.3f}]"
        print(f"   {name:10s} {pr:26s} {fp:24s}")
    if sig:
        verdict = ("SIGNIFICANT (CI excludes 0)" if sig["significant"]
                   else "not significant (CI includes 0)")
        print(f"\n   {sig['best_model']} vs rules: +{sig['pr_auc_gain']:.3f} PR-AUC "
              f"(95% CI [{sig['gain_ci95'][0]:.3f}, {sig['gain_ci95'][1]:.3f}]) -> {verdict}")
    print(f"\n[written] {OUT/'results.json'}")
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="extdrift-stat-rigor")
    ap.add_argument("dataset", nargs="?", default="data/dataset/deltas.csv")
    ap.add_argument("--boot", type=int, default=2000)
    ap.add_argument("--models", default="rules,rf,xgboost,histgb")
    args = ap.parse_args(argv)
    run(args.dataset, boot=args.boot, model_names=tuple(args.models.split(",")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
