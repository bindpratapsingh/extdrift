"""Machine-learning tier: the model bake-off and the anomaly (novelty) layer.

The task is fixed and precise (see docs/design/IMPLEMENTATION_PLAN.md):
    predict  P(this update introduced malicious behavioural change)  from the delta vector.

`bakeoff` compares the transparent rule scorer (the control), Logistic Regression (floor),
Random Forest, XGBoost and an SVM on the SAME features, under extension-level and time-based
cross-validation, and selects the winner by PR-AUC and false-positive rate.

Submodules are imported lazily (``from engine.ml.bakeoff import run_bakeoff``) so that
``python -m engine.ml.bakeoff`` does not double-import the module.
"""

__all__ = ["bakeoff", "anomaly"]
