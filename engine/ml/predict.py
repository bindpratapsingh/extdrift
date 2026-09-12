"""Apply a trained model to a single update at analysis time.

This is the bridge from the ML tier back into the live pipeline: if a model has been
trained and saved (engine/ml/models/winner.joblib), `predict_pair` returns its probability
for a new (v1, v2) pair so the report can show rules + ML side by side. If no model is
present, it returns None and the pipeline simply falls back to the rule score — so the
capture/report path never hard-depends on the ML stack.
"""

from __future__ import annotations

from pathlib import Path

MODEL_PATH = Path(__file__).with_name("models") / "winner.joblib"


def load_model():
    """Load the saved winner, or return None if it/its dependencies are unavailable."""
    try:
        import joblib
    except ImportError:
        return None
    if not MODEL_PATH.exists():
        return None
    try:
        return joblib.load(MODEL_PATH)
    except Exception:
        return None


def _feature_row(trace_v1: dict, trace_v2: dict, feature_names) -> list[float]:
    """Build the model's feature vector for a pair, matching engine.batch column order."""
    from engine.features.delta import behavioral_delta
    from engine.batch import _static_features
    delta = behavioral_delta(trace_v1, trace_v2)
    row = dict(delta["numeric"])
    row.update(_static_features(trace_v1, trace_v2))
    return [float(row.get(name, 0.0)) for name in feature_names]


def predict_pair(trace_v1: dict, trace_v2: dict) -> dict | None:
    """Return {scorer, probability, verdict} for the pair, or None if no model is available."""
    bundle = load_model()
    if bundle is None:
        return None
    try:
        x = [_feature_row(trace_v1, trace_v2, bundle["features"])]
        proba = float(bundle["model"].predict_proba(x)[0][1])
    except Exception:
        return None
    return {
        "scorer": f"ml-{bundle['name']}",
        "probability": round(proba, 4),
        "verdict": "MALICIOUS" if proba >= 0.5 else "BENIGN",
    }
