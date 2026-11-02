"""Combining the explainable score with the classifier, without averaging them.

A rule score and a classifier probability are not on the same scale: the first is a noisy-OR of
expert weights and the second is a Random Forest vote fraction. Averaging them would produce a
number with no meaning, so the methodology is an explicit decision table:

1. Direct evidence wins. If a synthetic secret was seen leaving the browser, the classifier cannot
   reduce the score, because the evidence does not depend on any model.
2. ML can raise but not decide alone. If the rules see little and the classifier flags the update,
   the result rises to a *floor* and stays capped below "high", since nothing explainable supports
   a stronger claim. The analyst is told this is a model-only flag.
3. ML can temper indirect rule evidence. If the rules see moderate, inferred signals and the model
   is confident the update is benign, the score falls by a fixed amount, down to a floor. This is
   the case the evaluation found rules weakest on: benign updates tripping heuristics.
4. Otherwise the result is the rule score.

The rule score is always reported unchanged, so this adjustment can always be seen and undone.
Without a classifier, step 4 applies throughout. See docs/design/RISK_CALIBRATION.md.
"""

from __future__ import annotations

from engine.scoring.risk import classify


def combine(rule_score: int, direct_evidence: bool, ml: dict | None, config: dict) -> dict:
    """Return the combined score, the path taken and how the two scorers relate."""
    settings = config["combination"]
    bands = config["bands"]
    result = {"rule_score": rule_score, "combined_score": rule_score, "rule_applied": "rules_only",
              "agreement": "not_applicable", "explanation": ""}

    probability = ml.get("probability") if ml and ml.get("status") == "available" else None
    if probability is None:
        reason = (ml or {}).get("reason", "no classifier result")
        result["explanation"] = f"The classifier gave no result ({reason}), so the rule score stands alone."
        result["classification"] = classify(rule_score, config)
        return result

    flagged = probability >= settings["ml_flag_probability"]
    cleared = probability <= settings["ml_clear_probability"]
    suspicious = rule_score >= bands["moderate"]
    result["agreement"] = "agree" if (flagged == suspicious) else ("disagree" if (flagged or (cleared and suspicious))
                                                                  else "agree")

    if direct_evidence:
        result["rule_applied"] = "direct_evidence_overrides_ml"
        tail = ("The classifier agrees." if flagged else
                f"The classifier gave only {probability:.2f}, but it cannot override direct evidence.")
        result["explanation"] = "A synthetic secret was observed leaving the browser. " + tail
    elif flagged and not suspicious:
        raised = min(max(rule_score, settings["ml_only_floor"]), settings["ml_only_ceiling"])
        result.update(combined_score=raised, rule_applied="ml_only_flag")
        result["explanation"] = (
            f"The rules found little (score {rule_score}) but the classifier flagged this update "
            f"(probability {probability:.2f}). The score rose to {raised}, and it is capped because "
            "no explainable evidence supports a stronger claim. Treat this as a prompt for review.")
    elif cleared and suspicious and rule_score < bands["critical"]:
        lowered = max(rule_score - settings["ml_clear_reduction"], settings["ml_clear_floor"])
        result.update(combined_score=lowered, rule_applied="ml_tempered_indirect_rules")
        result["explanation"] = (
            f"The rules fired on indirect signals only (score {rule_score}) and the classifier "
            f"considered this update benign (probability {probability:.2f}), so the score fell to {lowered}.")
    elif flagged:
        result["rule_applied"] = "both_flagged"
        result["explanation"] = f"The rules and the classifier (probability {probability:.2f}) both flag this update."
    elif suspicious:
        result["rule_applied"] = "rules_flagged_ml_unsure"
        result["explanation"] = (
            f"The rules flag this update and the classifier does not (probability {probability:.2f}), "
            "without being confident enough to lower the score.")
    else:
        result["rule_applied"] = "both_quiet"
        result["explanation"] = f"Neither the rules nor the classifier (probability {probability:.2f}) flag this update."

    result["classification"] = classify(result["combined_score"], config)
    return result
