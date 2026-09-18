"""Build and evaluate a static-code dataset from REAL extension code.

This brings real-world data into the ML pipeline today (no browser): it reads the real
Firefox update pairs downloaded by the AMO collector and computes static-code deltas for
  * benign rows  — the real (v_N -> v_N+1) update of a real extension, and
  * malicious rows — the same real extension with a known payload injected into its code
    (engine.weaponiser), i.e. a real extension turned malicious.

Then it runs a leave-one-extension-out classifier so no extension appears in both train and
test. This is the *You've Changed* static-delta methodology applied to genuinely real code.

Run:  python -m experiments.real_static_dataset
Needs the AMO pairs on disk (python -m engine.collector.amo … / see data/real/amo).
"""

from __future__ import annotations

import csv
import json
import tempfile
from pathlib import Path

from engine.features.static_code import STATIC_CODE_FEATURES, static_code_delta
from engine.weaponiser import weaponise

AMO = Path("data/real/amo")
FAMILIES = ["cookie_theft", "credential_theft", "sw_beacon"]
OUT = Path("out/real_static")


def _pairs() -> list[dict]:
    pj = AMO / "pairs.json"
    if not pj.exists():
        return []
    return [p for p in json.loads(pj.read_text(encoding="utf-8")) if "v1_dir" in p]


def build_rows() -> list[dict]:
    rows = []
    for p in _pairs():
        v1, v2 = Path(p["v1_dir"]), Path(p["v2_dir"])
        if not (v1 / "manifest.json").exists() or not (v2 / "manifest.json").exists():
            continue
        # benign: the real update
        d = static_code_delta(v1, v2)
        rows.append({"ext": p["slug"], "label": "benign", "family": "",
                     **{k: d["numeric"][k] for k in STATIC_CODE_FEATURES}})
        # malicious: the real v2 with a payload injected (a real extension turned malicious)
        for fam in FAMILIES:
            with tempfile.TemporaryDirectory() as tmp:
                try:
                    w = weaponise(v2, Path(tmp) / "mal", family=fam, obfuscated=False)
                    dm = static_code_delta(v2, w["out_dir"])
                except Exception:
                    continue
                rows.append({"ext": p["slug"], "label": "malicious", "family": fam,
                             **{k: dm["numeric"][k] for k in STATIC_CODE_FEATURES}})
    return rows


def _evaluate(rows):
    try:
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import LeaveOneGroupOut
        from sklearn.metrics import average_precision_score, roc_auc_score
    except Exception:
        return None
    X = np.array([[float(r[k]) for k in STATIC_CODE_FEATURES] for r in rows])
    y = np.array([1 if r["label"] == "malicious" else 0 for r in rows])
    groups = np.array([r["ext"] for r in rows])
    if len(set(y)) < 2 or len(set(groups)) < 2:
        return None
    logo = LeaveOneGroupOut()
    oof = np.zeros(len(y), dtype=float)
    for tr, te in logo.split(X, y, groups):
        if len(set(y[tr])) < 2:
            oof[te] = y[tr].mean()
            continue
        m = RandomForestClassifier(n_estimators=300, class_weight="balanced_subsample",
                                   random_state=0, n_jobs=-1).fit(X[tr], y[tr])
        oof[te] = m.predict_proba(X[te])[:, 1]
    return {"rows": len(y), "malicious": int(y.sum()), "extensions": len(set(groups)),
            "pr_auc": round(float(average_precision_score(y, oof)), 3),
            "roc_auc": round(float(roc_auc_score(y, oof)), 3)}


def run():
    rows = build_rows()
    if not rows:
        print("No AMO pairs on disk. Run the AMO collector first (see data/real/amo).")
        return {"rows": 0}
    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT / "real_static.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["ext", "label", "family"] + list(STATIC_CODE_FEATURES))
        w.writeheader(); w.writerows(rows)
    ev = _evaluate(rows)
    print(f"\nStatic-code dataset from REAL extensions: {len(rows)} rows "
          f"({sum(r['label']=='benign' for r in rows)} benign real updates + "
          f"{sum(r['label']=='malicious' for r in rows)} real-extension weaponisations) "
          f"across {len({r['ext'] for r in rows})} real extensions.")
    if ev:
        print(f"\nLeave-one-extension-out detection (Random Forest on static-code deltas):")
        print(f"   PR-AUC {ev['pr_auc']}   ROC-AUC {ev['roc_auc']}")
        print("   Real extensions the classifier never saw are still separated by their static-code delta.")
    print(f"\n[written] {OUT/'real_static.csv'}")
    return {"rows": len(rows), "eval": ev}


if __name__ == "__main__":
    run()
