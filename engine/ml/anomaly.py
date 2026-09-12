"""Anomaly / novelty layer — flagging *unseen* malicious updates.

The supervised bake-off (bakeoff.py) classifies *known* malicious behaviour patterns. This
layer answers the faculty's "unknown threats" question honestly: train only on **benign
update deltas** (the "normal" of an extension changing benignly), then flag any update whose
delta is anomalous — even a payload family never seen in training.

It does NOT discover zero-day *vulnerabilities*; it detects behavioural *novelty* in an
update. Because our baseline is the extension's own prior version, "normal" is unusually
well-defined, which is what makes this workable.

Evaluation protocol (leave-one-family-out): hold out an entire malicious family from any
influence on the threshold, fit on benign only, and measure how many held-out-family
malicious updates are flagged as anomalous — i.e. generalisation to the genuinely unseen.
"""

from __future__ import annotations

import argparse
import json

import numpy as np
import pandas as pd

from engine.ml.bakeoff import FEATURES, load_dataset


def _fit_detectors(X_benign):
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler().fit(X_benign)
    Xb = scaler.transform(X_benign)
    iso = IsolationForest(n_estimators=300, contamination=0.05, random_state=0).fit(Xb)
    ocsvm = OneClassSVM(kernel="rbf", nu=0.05, gamma="scale").fit(Xb)
    return scaler, iso, ocsvm


def _anomaly_scores(scaler, iso, ocsvm, X):
    Xs = scaler.transform(X)
    # Higher = more anomalous. Both give higher-is-more-normal, so negate.
    return -0.5 * iso.score_samples(Xs) - 0.5 * ocsvm.score_samples(Xs)


def run_anomaly(path="data/dataset/deltas.csv"):
    """Leave-one-family-out novelty evaluation using benign-only training."""
    from sklearn.metrics import roc_auc_score
    df, X, y, groups, order = load_dataset(path)
    families = sorted(f for f in df.loc[df.label == "malicious", "family"].dropna().unique() if f)

    benign_mask = (y == 0)
    per_family = {}
    for fam in families:
        # Train the detector on benign only (the family is never seen in fit).
        scaler, iso, ocsvm = _fit_detectors(X[benign_mask])
        held = df["family"].to_numpy() == fam
        eval_mask = benign_mask | held
        scores = _anomaly_scores(scaler, iso, ocsvm, X[eval_mask])
        labels = held[eval_mask].astype(int)
        # Flag at the 95th percentile of benign anomaly scores.
        thr = np.percentile(scores[labels == 0], 95)
        flagged = scores >= thr
        tp = int(((flagged == 1) & (labels == 1)).sum()); P = int(labels.sum())
        fp = int(((flagged == 1) & (labels == 0)).sum()); N = int((labels == 0).sum())
        per_family[fam] = {
            "held_out_detected": tp, "held_out_total": P,
            "detection_rate": round(tp / P, 3) if P else None,
            "benign_false_positives": fp, "benign_total": N,
            "fpr": round(fp / N, 3) if N else None,
            "roc_auc": round(roc_auc_score(labels, scores), 3) if P and N else None,
        }
    return {"dataset": str(path), "families": families, "per_family": per_family}


def _print(summary):
    print("\nAnomaly / novelty layer — leave-one-family-out (train on benign deltas only)")
    print("Each row: a malicious family the detector NEVER saw in training.\n")
    hdr = f"{'held-out family':18s} {'detected':>14s} {'detect-rate':>12s} {'benign-FPR':>11s} {'ROC-AUC':>8s}"
    print(hdr); print("-" * len(hdr))
    for fam, m in summary["per_family"].items():
        dr = f"{m['detection_rate']:.2f}" if m['detection_rate'] is not None else "-"
        fpr = f"{m['fpr']:.2f}" if m['fpr'] is not None else "-"
        auc = f"{m['roc_auc']:.2f}" if m['roc_auc'] is not None else "-"
        print(f"{fam:18s} {str(m['held_out_detected'])+'/'+str(m['held_out_total']):>14s} "
              f"{dr:>12s} {fpr:>11s} {auc:>8s}")
    print("\nReading: a high detection-rate on a family the model was never trained on means the")
    print("anomaly layer catches genuinely unseen malicious behaviour change — not zero-day")
    print("vulnerabilities, but novel malicious *behaviour*, which is what we can honestly claim.")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="extdrift-anomaly")
    ap.add_argument("dataset", nargs="?", default="data/dataset/deltas.csv")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    summary = run_anomaly(args.dataset)
    print(json.dumps(summary, indent=2)) if args.json else _print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
