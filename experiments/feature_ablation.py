"""Feature-group ablation — the study top-tier papers require to justify a feature set.

Presenting a final score for a multi-part feature vector without proving each part earns
its place is one of the "student pitfalls" the literature calls out. So we do the standard
ablation: train the winning model (XGBoost) with the full feature set, then (a) with each
feature GROUP removed and (b) with each group used ALONE, and report the change in PR-AUC and
false-positive rate under the same leakage-free extension-level cross-validation.

  * "leave-one-group-out": how much the model degrades without a group → the group's
    *marginal* contribution.
  * "group alone": how predictive a group is on its own → the group's *standalone* signal.

Run:  python -m experiments.feature_ablation
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from engine.ml.bakeoff import FEATURES, RECALL_TARGET, _metrics, load_dataset

# Feature groups map to the four observation channels + static manifest + the derived flow.
GROUPS = {
    "network":  [f for f in FEATURES if f.startswith("net_")],
    "dom":      [f for f in FEATURES if f.startswith("dom_")],
    "storage":  ["storage_calls", "cookie_reads", "cookie_bulk_reads"],
    "api":      ["api_calls", "api_distinct", "api_high_risk"],
    "static":   ["perm_count", "perm_high_risk", "host_perm_breadth",
                 "stat_added_highrisk_perms", "stat_escalated_broad_host", "stat_added_hosts"],
    "exfil":    ["exfil_flows", "exfil_flows_third_party"],
}
OUT = Path("out/ablation_features")


def _cv_pr_auc(df, X_cols, y, groups):
    """Out-of-fold PR-AUC and FPR@recall for XGBoost on the given feature columns."""
    from sklearn.model_selection import StratifiedGroupKFold
    import xgboost as xgb
    idx = [FEATURES.index(c) for c in X_cols]
    X = df[X_cols].astype(float).fillna(0.0).to_numpy()
    n_splits = max(2, min(5, len(np.unique(groups)), int(y.sum()), int((1 - y).sum())))
    skf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=0)
    oof = np.zeros(len(y), dtype=float)
    for tr, te in skf.split(X, y, groups):
        m = xgb.XGBClassifier(n_estimators=250, max_depth=4, learning_rate=0.1,
                              subsample=0.9, colsample_bytree=0.9, eval_metric="logloss",
                              random_state=0, n_jobs=-1)
        m.fit(X[tr], y[tr])
        oof[te] = m.predict_proba(X[te])[:, 1]
    m = _metrics(y, oof)
    return m["pr_auc"], m["fpr_at_recall90"]


def run(path="data/dataset/deltas.csv"):
    df, X, y, groups, order = load_dataset(path)
    OUT.mkdir(parents=True, exist_ok=True)
    full_pr, full_fpr = _cv_pr_auc(df, FEATURES, y, groups)
    rows = []
    for name, cols in GROUPS.items():
        remaining = [f for f in FEATURES if f not in cols]
        drop_pr, drop_fpr = _cv_pr_auc(df, remaining, y, groups)     # leave-one-group-out
        alone_pr, alone_fpr = _cv_pr_auc(df, cols, y, groups)        # group alone
        rows.append({"group": name, "n_features": len(cols),
                     "pr_auc_without": drop_pr, "pr_auc_drop": round(full_pr - drop_pr, 4),
                     "fpr_without": drop_fpr,
                     "pr_auc_alone": alone_pr, "fpr_alone": alone_fpr})
    rows.sort(key=lambda r: -r["pr_auc_drop"])
    result = {"dataset": str(path), "full_pr_auc": full_pr, "full_fpr90": full_fpr, "groups": rows}
    (OUT / "results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _print(r):
    print("\nFeature-group ablation (XGBoost, extension-level CV)")
    print(f"Full model: PR-AUC {r['full_pr_auc']:.3f} | FPR@90% {r['full_fpr90']}\n")
    hdr = f"{'group':9s} {'#feat':>5s} {'PR-AUC drop if removed':>23s} {'PR-AUC group alone':>19s}"
    print(hdr); print("-" * len(hdr))
    for g in r["groups"]:
        print(f"{g['group']:9s} {g['n_features']:5d} {g['pr_auc_drop']:>23.3f} {g['pr_auc_alone']:>19.3f}")
    top = r["groups"][0]
    print(f"\nMost important group (largest drop when removed): {top['group'].upper()} "
          f"(-{top['pr_auc_drop']:.3f} PR-AUC).")
    print("Reading: a large 'drop if removed' means the group carries signal the others don't;")
    print("a high 'group alone' means it is predictive by itself. Together they justify the set.")


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="extdrift-feature-ablation")
    ap.add_argument("dataset", nargs="?", default="data/dataset/deltas.csv")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    r = run(args.dataset)
    print(json.dumps(r, indent=2)) if args.json else _print(r)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
