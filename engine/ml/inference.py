"""Random Forest inference for the Docker pipeline, stating why when it cannot run.

:mod:`engine.ml.predict` returns ``None`` for every failure, which is right for the legacy report
but too quiet here: a report has to say whether the model ran. This module reuses that module's
model loading and feature layout. No new model is trained here and the saved model is not altered.

The model takes a *delta*, so it applies only to version comparison (Mode B). A single version has
no delta, and feeding it one against an empty baseline would be outside what it was trained on.
"""

from __future__ import annotations

import json

from engine.ml import predict as legacy_predict


def _not_available(reason: str, **extra) -> dict:
    return {"status": "unavailable", "reason": reason, **extra}


def model_card() -> dict:
    """What is known about the saved model, from its own evaluation record."""
    path = legacy_predict.MODEL_PATH.with_name("metrics.json")
    try:
        metrics = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    winner = metrics.get("winner")
    evaluation = ((metrics.get("results") or {}).get(winner) or {}).get("cv") or {}
    return {
        "winner": winner,
        "cv_pr_auc": evaluation.get("pr_auc"),
        "cv_fpr_at_recall90": evaluation.get("fpr_at_recall90"),
        "importances": metrics.get("importances") or [],
        "training_data": "Synthetic update pairs, plus real benign AMO updates and real extensions "
                         "with injected synthetic payloads. Not validated on real-world malicious updates.",
    }


def predict_slices(baseline_trace: dict, candidate_trace: dict, slices: list[dict]) -> dict:
    """Score each scenario's delta and report the highest, naming the scenario it came from.

    The model was trained on single-scenario deltas, so a multi-scenario total would have counts
    outside its training range. The maximum is used because a payload may fire in only one
    scenario, at the cost of more chances for a false alarm.
    """
    try:
        bundle = legacy_predict.load_model()
    except Exception as exc:  # noqa: BLE001 - the report states the reason instead
        return _not_available(f"could not load the model: {type(exc).__name__}: {exc}")
    if bundle is None:
        reason = ("no saved model at engine/ml/models/winner.joblib, or its dependencies are missing. "
                  "Train one with: python -m engine.ml.bakeoff data/dataset/deltas.csv")
        return _not_available(reason)

    per_scenario = []
    try:
        for item in slices:
            row = legacy_predict._feature_row(item["baseline"], item["candidate"], bundle["features"])
            probability = float(bundle["model"].predict_proba([row])[0][1])
            per_scenario.append({"scenario": item["scenario"], "probability": round(probability, 4)})
    except Exception as exc:  # noqa: BLE001 - e.g. a model pickled by an incompatible library
        return _not_available(f"inference failed: {type(exc).__name__}: {exc}")
    if not per_scenario:
        return _not_available("no scenario was available to score")

    top = max(per_scenario, key=lambda r: r["probability"])
    card = model_card()
    moved = _moved_features(baseline_trace, candidate_trace, bundle["features"], card)
    return {
        "status": "available",
        "model": f"ml-{bundle['name']}",
        "model_type": type(bundle["model"]).__name__,
        "probability": top["probability"],
        "scenario": top["scenario"],
        "per_scenario": per_scenario,
        "classification": "MALICIOUS" if top["probability"] >= 0.5 else "BENIGN",
        "confidence_is_calibrated": False,
        "confidence_note": "The probability is the fraction of trees voting malicious. It is "
                           "uncalibrated: use it to rank updates, not as a real-world likelihood.",
        "important_features_that_moved": moved,
        "model_card": {k: v for k, v in card.items() if k != "importances"},
        "domain_note": "Trained mostly on synthetic data and Firefox captures, with features "
                       "from a narrower instrumentation. Chromium-in-Docker input may differ.",
    }


def _moved_features(baseline: dict, candidate: dict, features: list[str], card: dict) -> list[dict]:
    from engine.features.delta import behavioral_delta

    numeric = behavioral_delta(baseline, candidate)["numeric"]
    importance = {i["feature"]: i["importance"] for i in card.get("importances", [])}
    return [{"feature": name, "delta": numeric[name], "global_importance": importance[name]}
            for name in features if name in numeric and numeric[name] and name in importance][:8]
