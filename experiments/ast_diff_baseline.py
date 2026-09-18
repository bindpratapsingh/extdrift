"""AST/token-diff baseline vs semantic static-code features, on REAL extension code.

Answers a question the panel will ask of the static track: is the richer, security-aware
feature set (engine.features.static_code) actually better than just measuring *how much* the
code changed? So on the identical real pairs -- real AMO benign updates plus the same real
extensions weaponised -- we build three feature sets and score each under the same
leave-one-extension-out Random Forest:

  * baseline  -- AST/token-diff churn only (engine.features.ast_diff), the You've Changed
                 structural-similarity idea, no security semantics;
  * semantic  -- the static-code capability deltas (permissions, API/sink tokens, obfuscation);
  * combined  -- both together.

If semantic clearly beats baseline, the security-aware features earn their place; if combined
beats both, the structural churn adds complementary signal. Either way it is an ablation, not
an assertion.

Run:  python -m experiments.ast_diff_baseline   (needs the AMO pairs on disk; see data/real/amo)
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from engine.features.ast_diff import AST_DIFF_FEATURES, ast_diff_features
from engine.features.static_code import STATIC_CODE_FEATURES, static_code_delta
from engine.weaponiser import weaponise
from experiments.real_static_dataset import FAMILIES, _pairs


def _row(v1, v2):
    """Both feature sets for one (v1 -> v2) code delta."""
    sc = static_code_delta(v1, v2)["numeric"]
    ad = ast_diff_features(v1, v2)
    return ({k: sc[k] for k in STATIC_CODE_FEATURES}, {k: ad[k] for k in AST_DIFF_FEATURES})


def build_rows():
    rows = []
    for p in _pairs():
        v1, v2 = Path(p["v1_dir"]), Path(p["v2_dir"])
        if not (v1 / "manifest.json").exists() or not (v2 / "manifest.json").exists():
            continue
        sc, ad = _row(v1, v2)
        rows.append({"ext": p["slug"], "y": 0, "sc": sc, "ad": ad})       # real benign update
        for fam in FAMILIES:
            with tempfile.TemporaryDirectory() as tmp:
                try:
                    w = weaponise(v2, Path(tmp) / "mal", family=fam, obfuscated=False)
                    sc, ad = _row(v2, w["out_dir"])
                except Exception:
                    continue
                rows.append({"ext": p["slug"], "y": 1, "sc": sc, "ad": ad})  # weaponised
    return rows


def _loo_pr_auc(rows, feature_keys, which):
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import LeaveOneGroupOut
    from sklearn.metrics import average_precision_score, roc_auc_score
    X = np.array([[float(r[which][k]) for k in feature_keys] for r in rows])
    y = np.array([r["y"] for r in rows])
    groups = np.array([r["ext"] for r in rows])
    if len(set(y)) < 2 or len(set(groups)) < 2:
        return None
    oof = np.zeros(len(y), dtype=float)
    for tr, te in LeaveOneGroupOut().split(X, y, groups):
        if len(set(y[tr])) < 2:
            oof[te] = y[tr].mean(); continue
        m = RandomForestClassifier(n_estimators=300, class_weight="balanced_subsample",
                                   random_state=0, n_jobs=-1).fit(X[tr], y[tr])
        oof[te] = m.predict_proba(X[te])[:, 1]
    return {"pr_auc": round(float(average_precision_score(y, oof)), 3),
            "roc_auc": round(float(roc_auc_score(y, oof)), 3)}


def _combined(rows):
    for r in rows:
        r["all"] = {**r["sc"], **r["ad"]}
    return list(STATIC_CODE_FEATURES) + list(AST_DIFF_FEATURES)


def run():
    rows = build_rows()
    if not rows:
        print("No AMO pairs on disk. Run the AMO collector first (see data/real/amo).")
        return {"rows": 0}
    all_keys = _combined(rows)
    res = {
        "baseline (AST/token churn)": _loo_pr_auc(rows, AST_DIFF_FEATURES, "ad"),
        "semantic (static-code)":     _loo_pr_auc(rows, STATIC_CODE_FEATURES, "sc"),
        "combined":                   _loo_pr_auc(rows, all_keys, "all"),
    }
    n_ext = len({r["ext"] for r in rows})
    print(f"\nAST-diff baseline vs semantic static features on REAL code: {len(rows)} rows "
          f"({sum(r['y'] == 0 for r in rows)} benign + {sum(r['y'] == 1 for r in rows)} weaponised) "
          f"across {n_ext} real extensions.")
    print("Leave-one-extension-out Random Forest:\n")
    print(f"   {'feature set':30s} {'PR-AUC':>7s} {'ROC-AUC':>8s} {'#feat':>6s}")
    print("   " + "-" * 54)
    sizes = {"baseline (AST/token churn)": len(AST_DIFF_FEATURES),
             "semantic (static-code)": len(STATIC_CODE_FEATURES), "combined": len(all_keys)}
    for name, m in res.items():
        if m:
            print(f"   {name:30s} {m['pr_auc']:7.3f} {m['roc_auc']:8.3f} {sizes[name]:6d}")
    b, s = res["baseline (AST/token churn)"], res["semantic (static-code)"]
    if b and s:
        gain = round(s["pr_auc"] - b["pr_auc"], 3)
        verdict = (f"semantic features add +{gain} PR-AUC over raw churn"
                   if gain > 0 else "raw churn already suffices on this sample")
        print(f"\n   Reading: {verdict}.")
    return {"rows": len(rows), "extensions": n_ext, "results": res}


if __name__ == "__main__":
    run()
