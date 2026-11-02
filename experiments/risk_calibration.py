"""Evaluate the 0-100 risk score and the combined assessment on the labelled dataset.

The score's weights are expert priors and its bands are starting points, so they must be checked
against whatever labelled data exists. This runs the Mode B scorer over every labelled pair:

  * the synthetic pairs (same generator and seed as data/dataset/deltas.csv);
  * the committed real captures: real benign AMO updates, and real extensions with a synthetic
    payload injected.

The classifier's input is out-of-fold, by extension, so no pair is scored by a model that saw it.

Validity limits, which the output repeats:
  * Legacy traces contain no wire record or marker hits, so the marker indicators cannot fire here.
    The strongest evidence of the Docker pipeline is unused, and exfiltration is seen only through
    the weaker timing-based candidate.
  * "Malicious" means synthetic weaponisation. No real-world malicious update pair is included.

Run:  python -m experiments.risk_calibration [--out out/risk_calibration]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from engine.features.behaviour import extract_behaviours, extract_features
from engine.features.behaviour_diff import compare_versions
from engine.features.extract import host_of
from engine.ml.bakeoff import _build_models, _cv_scores, load_dataset
from engine.pipeline.config import load_risk_config
from engine.sandbox.normalise import declared_hosts, events_from_legacy_trace
from engine.scoring.combined import combine
from engine.scoring.risk import behaviours_to_score, score_behaviours
from engine.unpack.manifest import diff_manifests

CAPTURED = Path("data/dataset/captured")


def _version_view(trace: dict) -> tuple[dict, dict]:
    events = events_from_legacy_trace(trace)
    manifest = trace.get("manifest", {})
    bundle = {host_of(p) for p in trace.get("run", {}).get("pages", [])} - {""}
    declared = declared_hosts(manifest)
    behaviours = extract_behaviours(events, manifest, bundle, declared)
    return behaviours, extract_features(events, behaviours, manifest, bundle, declared)


def score_pair(trace_v1: dict, trace_v2: dict, config: dict) -> dict:
    base_b, base_f = _version_view(trace_v1)
    cand_b, cand_f = _version_view(trace_v2)
    manifest_diff = diff_manifests(trace_v1.get("manifest", {}), trace_v2.get("manifest", {}))
    comparison = compare_versions(base_b, cand_b, base_f, cand_f, manifest_diff)
    return score_behaviours(behaviours_to_score(comparison), config,
                            manifest=trace_v2.get("manifest", {}), manifest_diff=manifest_diff)


def labelled_pairs():
    """Yield (pair_id, trace_v1, trace_v2) for every labelled row source."""
    from engine.synth.generate import generate_corpus
    for record in generate_corpus(n_extensions=250, updates_per_ext=4, seed=1234):
        yield record["pair_id"], record["trace_v1"], record["trace_v2"]
    for sub in sorted(p for p in CAPTURED.iterdir() if p.is_dir()):
        v1, v2 = sub / "v1.trace.json", sub / "v2.trace.json"
        if v1.exists() and v2.exists():
            yield sub.name, json.loads(v1.read_text(encoding="utf-8")), json.loads(v2.read_text(encoding="utf-8"))


def operating_points(y: np.ndarray, s: np.ndarray, thresholds: list[float]) -> list[dict]:
    positives, negatives = int(y.sum()), int((1 - y).sum())
    out = []
    for threshold in thresholds:
        flagged = s >= threshold
        tp = int((flagged & (y == 1)).sum())
        fp = int((flagged & (y == 0)).sum())
        out.append({"threshold": threshold, "recall": round(tp / positives, 4) if positives else None,
                    "false_positive_rate": round(fp / negatives, 4) if negatives else None,
                    "precision": round(tp / (tp + fp), 4) if tp + fp else None,
                    "flagged": int(flagged.sum())})
    return out


def band_table(y: np.ndarray, s: np.ndarray, config: dict) -> list[dict]:
    bands = config["bands"]
    edges = [("0-19 Low", 0, bands["mild"]), ("20-39 Mild", bands["mild"], bands["moderate"]),
             ("40-59 Moderate", bands["moderate"], bands["high"]),
             ("60-79 High", bands["high"], bands["critical"]), ("80-100 Critical", bands["critical"], 101)]
    rows = []
    for label, lo, hi in edges:
        mask = (s >= lo) & (s < hi)
        benign, malicious = int((mask & (y == 0)).sum()), int((mask & (y == 1)).sum())
        rows.append({"band": label, "benign": benign, "malicious": malicious,
                     "share_malicious": round(malicious / (benign + malicious), 3) if benign + malicious else None})
    return rows


def evaluate(scores: dict[str, dict], dataset="data/dataset/deltas.csv") -> dict:
    from sklearn.metrics import average_precision_score, roc_auc_score
    config = load_risk_config()
    df, X, y, groups, _ = load_dataset(dataset)
    available = df["pair_id"].isin(scores).to_numpy()
    model = _build_models()["rf"]
    oof = _cv_scores("rf", model, X, y, groups, df)

    rule = np.array([scores[p]["score"] if p in scores else np.nan for p in df["pair_id"]], dtype=float)
    combined = np.array(rule)
    for i, pair in enumerate(df["pair_id"]):
        if pair in scores:
            result = combine(scores[pair]["score"], scores[pair]["direct_evidence"],
                             {"status": "available", "probability": float(oof[i])}, config)
            combined[i] = result["combined_score"]

    def metrics(s: np.ndarray, mask: np.ndarray) -> dict:
        yy, ss = y[mask], s[mask]
        positive_and_negative = len(set(yy.tolist())) > 1
        return {
            "rows": int(mask.sum()), "malicious": int(yy.sum()), "benign": int((1 - yy).sum()),
            "roc_auc": round(float(roc_auc_score(yy, ss)), 4) if positive_and_negative else None,
            "pr_auc": round(float(average_precision_score(yy, ss)), 4) if positive_and_negative else None,
            "at": operating_points(yy, ss, [20, 40, 60, 80]),
            "bands": band_table(yy, ss, config),
        }

    source = df["source"].astype(str).to_numpy()
    real = np.char.startswith(source.astype(str), "amo-firefox")
    synthetic = source == "synthetic"
    results = {
        "dataset": dataset, "rows_scored": int(available.sum()),
        "rule_score_all": metrics(rule, available),
        "rule_score_synthetic": metrics(rule, available & synthetic),
        "rule_score_real_captures": metrics(rule, available & real),
        "combined_all": metrics(combined, available),
        "combined_real_captures": metrics(combined, available & real),
        "classifier_oof_all": {
            "roc_auc": round(float(roc_auc_score(y[available], oof[available])), 4),
            "pr_auc": round(float(average_precision_score(y[available], oof[available])), 4),
        },
    }
    family = df["family"].fillna("").astype(str).to_numpy()
    results["recall_at_40_by_family"] = {}
    for name in sorted(set(family.tolist()) - {""}):
        mask = available & (family == name) & (y == 1)
        if mask.any():
            results["recall_at_40_by_family"][name] = {
                "rule": round(float((rule[mask] >= 40).mean()), 3),
                "combined": round(float((combined[mask] >= 40).mean()), 3), "n": int(mask.sum())}
    return results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="extdrift-risk-calibration")
    parser.add_argument("--out", default="out/risk_calibration")
    args = parser.parse_args(argv)
    config = load_risk_config()
    scores = {pair: score_pair(t1, t2, config) for pair, t1, t2 in labelled_pairs()}
    results = evaluate(scores)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps({k: results[k] for k in ("rows_scored", "classifier_oof_all", "recall_at_40_by_family")}, indent=1))
    for name in ("rule_score_all", "rule_score_synthetic", "rule_score_real_captures", "combined_all", "combined_real_captures"):
        m = results[name]
        print(f"\n{name}: rows {m['rows']} (malicious {m['malicious']}, benign {m['benign']}) "
              f"ROC-AUC {m['roc_auc']} PR-AUC {m['pr_auc']}")
        for row in m["at"]:
            print(f"   score >= {row['threshold']:3d}: recall {row['recall']}  FPR {row['false_positive_rate']}  precision {row['precision']}")
        for row in m["bands"]:
            print(f"   {row['band']:16s} benign {row['benign']:4d}  malicious {row['malicious']:4d}  share {row['share_malicious']}")
    print("\nLimits: marker evidence cannot fire on legacy traces, and malicious labels are synthetic.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
