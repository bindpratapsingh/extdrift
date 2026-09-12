"""The model bake-off — evidence-based model selection, not "XGBoost because everyone uses it".

Compares, on the identical delta features:
  * rules   — the transparent heuristic score (the control: ML must beat this)
  * logreg  — Logistic Regression (the floor baseline)
  * rf      — Random Forest
  * xgboost — gradient-boosted trees (the usual tabular state-of-the-art)
  * svm     — RBF Support Vector Machine

Evaluation is leakage-free:
  * StratifiedGroupKFold by `ext_id` — all versions of one extension stay in one fold, so
    the model cannot memorise an extension and inflate the score.
  * a separate time-based split (train older, test newer) exposes concept drift.

Metrics: accuracy, precision, recall, F1, ROC-AUC, PR-AUC, and FPR at recall >= 0.90.
Selection rule: highest mean PR-AUC, tie-broken by lower FPR. Winner + its metrics card and
feature importances (a light SHAP substitute) are saved under engine/ml/models/.

Run:  python -m engine.ml.bakeoff data/dataset/deltas.csv
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from engine.features.extract import FEATURE_ORDER

STATIC_FEATURES = ["stat_added_highrisk_perms", "stat_escalated_broad_host", "stat_added_hosts"]
FEATURES = list(FEATURE_ORDER) + STATIC_FEATURES
MODELS_DIR = Path(__file__).with_name("models")
RECALL_TARGET = 0.90


def load_dataset(path: str | Path):
    """Return (df, X, y, groups, order) from the delta CSV."""
    df = pd.read_csv(path)
    df = df[df["label"].isin(["benign", "malicious"])].reset_index(drop=True)
    X = df[FEATURES].astype(float).fillna(0.0).to_numpy()
    y = (df["label"] == "malicious").astype(int).to_numpy()
    groups = df["ext_id"].to_numpy()
    order = np.argsort(df["collected_at"].fillna("").to_numpy(), kind="stable")
    return df, X, y, groups, order


def _build_models():
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.svm import SVC
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    import xgboost as xgb

    return {
        "logreg": make_pipeline(StandardScaler(),
                                LogisticRegression(max_iter=2000, class_weight="balanced")),
        "rf": RandomForestClassifier(n_estimators=300, class_weight="balanced_subsample",
                                     random_state=0, n_jobs=-1),
        "xgboost": xgb.XGBClassifier(n_estimators=300, max_depth=4, learning_rate=0.1,
                                     subsample=0.9, colsample_bytree=0.9, eval_metric="logloss",
                                     random_state=0, n_jobs=-1),
        # No probability=True (deprecated in sklearn 1.9); ranking metrics use the
        # decision_function score, which _proba() min-max normalises.
        "svm": make_pipeline(StandardScaler(),
                             SVC(kernel="rbf", class_weight="balanced", random_state=0)),
    }


def _metrics(y_true, scores, threshold=0.5):
    from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                                 roc_auc_score, average_precision_score, confusion_matrix,
                                 precision_recall_curve)
    y_true = np.asarray(y_true); scores = np.asarray(scores, dtype=float)
    pred = (scores >= threshold).astype(int)
    # FPR at the lowest decision threshold that still reaches RECALL_TARGET
    prec, rec, thr = precision_recall_curve(y_true, scores)
    fpr_at_recall = None
    P = int(y_true.sum()); N = int((1 - y_true).sum())
    if N:
        best = None
        for t in np.r_[thr, 1.0]:
            p = (scores >= t).astype(int)
            tp = int(((p == 1) & (y_true == 1)).sum()); fp = int(((p == 1) & (y_true == 0)).sum())
            r = tp / P if P else 0.0
            if r >= RECALL_TARGET:
                best = fp / N
        fpr_at_recall = best
    return {
        "accuracy": round(accuracy_score(y_true, pred), 4),
        "precision": round(precision_score(y_true, pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y_true, scores), 4) if len(set(y_true)) > 1 else None,
        "pr_auc": round(average_precision_score(y_true, scores), 4) if P else None,
        "fpr_at_recall90": round(fpr_at_recall, 4) if fpr_at_recall is not None else None,
        "confusion": confusion_matrix(y_true, pred).tolist(),
    }


def _cv_scores(name, model, X, y, groups, df):
    """Out-of-fold scores for one model under StratifiedGroupKFold(ext_id)."""
    from sklearn.model_selection import StratifiedGroupKFold
    n_splits = min(5, len(np.unique(groups)), int(y.sum()), int((1 - y).sum()))
    n_splits = max(2, n_splits)
    skf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=0)
    oof = np.zeros(len(y), dtype=float)
    for tr, te in skf.split(X, y, groups):
        if name == "rules":
            oof[te] = df["rule_score"].to_numpy()[te]
            continue
        m = _clone(model)
        m.fit(X[tr], y[tr])
        oof[te] = _proba(m, X[te])
    return oof


def _clone(model):
    from sklearn.base import clone
    return clone(model)


def _proba(model, X):
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X)[:, 1]
    d = model.decision_function(X)
    return (d - d.min()) / (d.max() - d.min() + 1e-9)


def _time_split_eval(name, model, X, y, order, df):
    """Train on the older 70% of pairs, test on the newer 30% (concept-drift probe)."""
    cut = int(len(order) * 0.7)
    tr, te = order[:cut], order[cut:]
    if len(set(y[te])) < 2:
        return None
    if name == "rules":
        scores = df["rule_score"].to_numpy()[te]
    else:
        m = _clone(model); m.fit(X[tr], y[tr]); scores = _proba(m, X[te])
    return _metrics(y[te], scores, threshold=(0.5 if name != "rules" else 0.5))


def run_bakeoff(path="data/dataset/deltas.csv", save=True):
    df, X, y, groups, order = load_dataset(path)
    models = _build_models()
    results = {}

    # Rules control first (no fitting)
    for name in ["rules"] + list(models):
        model = models.get(name)
        oof = _cv_scores(name, model, X, y, groups, df)
        thr = 0.5
        cv = _metrics(y, oof, threshold=thr)
        ts = _time_split_eval(name, model, X, y, order, df)
        results[name] = {"cv": cv, "time_split": ts}

    # Winner: highest CV PR-AUC, tie-break lower FPR@recall90
    def key(n):
        m = results[n]["cv"]
        return (m["pr_auc"] or 0.0, -(m["fpr_at_recall90"] if m["fpr_at_recall90"] is not None else 1.0))
    winner = max(results, key=key)

    importances = None
    if winner not in ("rules",):
        importances = _feature_importance(winner, models[winner], X, y)
        if save:
            _save_winner(winner, models[winner], X, y, results, importances)

    summary = {"dataset": str(path), "rows": len(y), "positives": int(y.sum()),
               "extensions": int(len(np.unique(groups))), "winner": winner,
               "results": results, "winner_importances": importances}
    return summary


def _feature_importance(name, model, X, y, top=12):
    from sklearn.inspection import permutation_importance
    m = _clone(model); m.fit(X, y)
    if hasattr(m, "feature_importances_"):
        imp = m.feature_importances_
    else:
        imp = permutation_importance(m, X, y, n_repeats=8, random_state=0).importances_mean
    idx = np.argsort(imp)[::-1][:top]
    return [{"feature": FEATURES[i], "importance": round(float(imp[i]), 4)} for i in idx]


def _save_winner(name, model, X, y, results, importances):
    import joblib
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    m = _clone(model); m.fit(X, y)
    joblib.dump({"name": name, "features": FEATURES, "model": m}, MODELS_DIR / "winner.joblib")
    (MODELS_DIR / "metrics.json").write_text(
        json.dumps({"winner": name, "results": results, "importances": importances}, indent=2),
        encoding="utf-8")


def _print(summary):
    r = summary["results"]
    print(f"\nDataset: {summary['rows']} pairs · {summary['positives']} malicious · "
          f"{summary['extensions']} extensions")
    print("Cross-validation (StratifiedGroupKFold by extension) — the leakage-free numbers\n")
    hdr = f"{'model':10s} {'PR-AUC':>7s} {'ROC-AUC':>8s} {'prec':>6s} {'recall':>7s} " \
          f"{'F1':>6s} {'FPR@rec90':>10s}"
    print(hdr); print("-" * len(hdr))
    ordered = sorted(r, key=lambda n: -(r[n]['cv']['pr_auc'] or 0))
    for n in ordered:
        c = r[n]["cv"]
        star = "  <= winner" if n == summary["winner"] else ""
        fpr = f"{c['fpr_at_recall90']:.3f}" if c['fpr_at_recall90'] is not None else "   -"
        print(f"{n:10s} {c['pr_auc'] or 0:7.3f} {c['roc_auc'] or 0:8.3f} {c['precision']:6.3f} "
              f"{c['recall']:7.3f} {c['f1']:6.3f} {fpr:>10s}{star}")
    print(f"\nWinner: {summary['winner'].upper()} "
          f"(selected by PR-AUC, tie-broken by FPR at 90% recall)")
    if summary["winner_importances"]:
        print("\nTop features driving the winner (SHAP-style importance):")
        for f in summary["winner_importances"][:8]:
            print(f"   {f['feature']:26s} {f['importance']:.3f}")
    # Does ML beat the rules?
    ml = [n for n in ordered if n != "rules"]
    if ml:
        best_ml = ml[0]
        beat = (r[best_ml]["cv"]["pr_auc"] or 0) > (r["rules"]["cv"]["pr_auc"] or 0)
        verdict = "YES — the learned model beats the rules" if beat else \
                  "NO — the rules hold their own at this data scale (an honest finding)"
        print(f"\nDoes ML earn its place? {verdict}.")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="extdrift-bakeoff")
    ap.add_argument("dataset", nargs="?", default="data/dataset/deltas.csv")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-save", action="store_true")
    args = ap.parse_args(argv)
    summary = run_bakeoff(args.dataset, save=not args.no_save)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        _print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
