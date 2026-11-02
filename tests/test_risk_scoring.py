"""The risk score and the combined assessment. Runs without a browser or Docker."""

from __future__ import annotations

import unittest

from engine.pipeline.config import load_risk_config
from engine.scoring.combined import combine
from engine.scoring.risk import (
    PREDICATES,
    behaviours_to_score,
    classify,
    score_behaviours,
    verdict_for,
)

CONFIG = load_risk_config()


def behaviour(signature, category, *tags, targets=(), confidence="confirmed", change=None, count=1, details=None):
    item = {"signature": signature, "category": category, "label": signature, "count": count,
            "scenarios": ["s1"], "contexts": ["content_script"], "targets": list(targets),
            "parameters": [], "tags": list(tags), "attribution_confidence": confidence,
            "event_ids": [], "first_ts": 1.0, "first_timestamp": "t", "details": details or {}}
    if change:
        item["change"] = change
    return item


PASSWORD_READ = behaviour("dom:field_read:password", "dom", "field:password", "login_form", targets=["input#password"])
COOKIE_DUMP = behaviour("cookie:read_all:cookies.getAll", "storage", "cookie_access")
EXFIL = behaviour("net:POST:evil.test/up", "network", "upload", "exfil:credential", "undeclared_host",
                  targets=["evil.test"], details={"markers": [{"kind": "password", "sensitivity": "credential",
                                                                "encoding": "base64", "location": "body"}]})
GET_CDN = behaviour("net:GET:cdn.test/lib.js", "network", "undeclared_host", targets=["cdn.test"])
SMALL_POST = behaviour("net:POST:metrics.test/e", "network", "upload", "undeclared_host", targets=["metrics.test"])
STORAGE = behaviour("storage:read:extension_local:key", "storage", "operation:read")


def score(*behaviours, **kw):
    return score_behaviours(list(behaviours), CONFIG, **kw)


class TestContextualScoring(unittest.TestCase):
    def test_nothing_observed_scores_zero_with_an_explanation(self):
        result = score()
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["classification"], "Low observed risk")
        self.assertIn("No risk indicator fired", result["explanation"][1])

    def test_password_read_followed_by_exfiltration_far_exceeds_either_alone(self):
        alone = score(PASSWORD_READ)["score"]
        exfil_only = score(EXFIL)["score"]
        both = score(PASSWORD_READ, EXFIL)["score"]
        self.assertGreater(both, 90)
        self.assertLess(alone, 40)
        self.assertGreater(both, alone * 2)
        self.assertGreaterEqual(both, exfil_only)

    def test_a_new_destination_alone_is_not_treated_as_malicious(self):
        self.assertLess(score(GET_CDN)["score"], 20)
        self.assertLess(score(SMALL_POST)["score"], 20)

    def test_routine_activity_barely_moves_the_score(self):
        result = score(STORAGE, behaviour("dom:node_injected:div", "dom"))
        self.assertLess(result["score"], 5)
        self.assertEqual(result["risk_indicators_fired"], 0)

    def test_cookie_read_scores_but_is_not_critical(self):
        self.assertTrue(40 <= score(COOKIE_DUMP)["score"] < 60)

    def test_inferred_attribution_counts_for_less(self):
        confirmed = score(behaviour("dom:field_read:password", "dom", "field:password"))["score"]
        inferred = score(behaviour("dom:field_read:password", "dom", "field:password", confidence="inferred"))["score"]
        self.assertLess(inferred, confirmed)


class TestNoDoubleCounting(unittest.TestCase):
    def test_one_cluster_counts_once(self):
        lookup = behaviour("dom:query:password", "dom", "field:password")
        keys = behaviour("dom:listener:keydown:root", "dom", "key_listener")
        combined = score(PASSWORD_READ, lookup, keys)
        self.assertEqual(combined["score"], score(PASSWORD_READ)["score"])
        counted = [f for f in combined["findings"] if f["counted_in_score"]]
        self.assertEqual(len(counted), 1)

    def test_exfil_destination_is_not_also_scored_as_a_new_destination(self):
        findings = score(EXFIL)["findings"]
        names = {f["indicator"] for f in findings}
        self.assertIn("credential_exfiltration", names)
        self.assertFalse(names & {"unexpected_upload", "small_telemetry", "new_external_contact"})

    def test_beacon_requests_are_not_also_scored_as_telemetry(self):
        beacon = behaviour("net:POST:x.test/b", "network", "upload", "undeclared_host", "beacon", targets=["x.test"])
        names = {f["indicator"] for f in score(beacon)["findings"]}
        self.assertEqual(names, {"beaconing"})

    def test_timing_candidate_is_not_also_scored_as_an_unexpected_upload(self):
        upload = behaviour("net:POST:x.test/up", "network", "upload", "undeclared_host", "large_upload",
                           "after_sensitive_read", targets=["x.test"])
        names = {f["indicator"] for f in score(upload)["findings"]}
        self.assertEqual(names, {"temporal_exfiltration_candidate"})

    def test_contributions_explain_the_score(self):
        result = score(PASSWORD_READ, COOKIE_DUMP)
        self.assertTrue(all(f["risk_contribution"] > 0 for f in result["findings"] if f["counted_in_score"]))


class TestModeB(unittest.TestCase):
    def comparison(self, new=(), increased=(), changed=(), unchanged=()):
        return {"classes": {"new": list(new), "increased": list(increased),
                            "changed_parameters": list(changed), "unchanged": list(unchanged)}}

    def test_only_introduced_behaviour_is_scored(self):
        items = behaviours_to_score(self.comparison(new=[PASSWORD_READ], unchanged=[COOKIE_DUMP]))
        self.assertEqual(items, [PASSWORD_READ])

    def test_behaviour_the_baseline_already_had_does_not_score(self):
        result = score(*behaviours_to_score(self.comparison(unchanged=[PASSWORD_READ, COOKIE_DUMP])))
        self.assertEqual(result["score"], 0)

    def test_an_increase_counts_for_less_than_something_new(self):
        new = behaviour("dom:field_read:password", "dom", "field:password", change="new")
        more = behaviour("dom:field_read:password", "dom", "field:password", change="increased")
        self.assertLess(score(more)["score"], score(new)["score"])

    def test_permission_escalation_is_scored_from_the_manifest_diff(self):
        result = score(manifest_diff={"high_risk_added": ["cookies"], "escalated_to_broad_host_access": True})
        names = {f["indicator"] for f in result["findings"]}
        self.assertEqual(names, {"permission_escalation", "host_access_broadened"})
        self.assertEqual(result["score"], 30)


class TestConfigurable(unittest.TestCase):
    def test_every_indicator_has_config_and_a_reason(self):
        for name in PREDICATES:
            self.assertIn(name, CONFIG["indicators"])
        for name, spec in CONFIG["indicators"].items():
            self.assertTrue(0 < spec["weight"] <= 1, name)
            self.assertTrue(spec["why"], name)

    def test_weights_come_from_configuration(self):
        changed = {**CONFIG, "indicators": {**CONFIG["indicators"],
                   "credential_field_read": {**CONFIG["indicators"]["credential_field_read"], "weight": 0.9}}}
        self.assertEqual(score_behaviours([PASSWORD_READ], changed)["score"], 90)


class TestVerdicts(unittest.TestCase):
    def test_bands(self):
        for value, expected in ((0, "Low"), (19, "Low"), (20, "Mild"), (40, "Moderate"), (60, "High"), (80, "Critical"), (100, "Critical")):
            self.assertIn(expected, classify(value, CONFIG))

    def test_verdict_text(self):
        v = lambda s, n=1, complete=True: verdict_for(s, n, config=CONFIG, complete=complete)
        self.assertEqual(v(90), "Critical behaviour detected")
        self.assertEqual(v(70), "High-risk behaviour detected")
        self.assertEqual(v(50), "Suspicious behaviour detected")
        self.assertEqual(v(25), "Low observed risk")
        self.assertEqual(v(0, 0), "No significant suspicious behaviour observed")

    def test_incomplete_monitoring_cannot_produce_a_reassuring_verdict(self):
        self.assertEqual(verdict_for(0, 0, config=CONFIG, complete=False), "Inconclusive analysis")
        self.assertEqual(verdict_for(25, 1, config=CONFIG, complete=False), "Inconclusive analysis")

    def test_positive_evidence_survives_incomplete_monitoring(self):
        self.assertEqual(verdict_for(90, 3, config=CONFIG, complete=False), "Critical behaviour detected")

    def test_no_verdict_claims_safety(self):
        from engine.report.security_report import PLAIN_VERDICT
        for verdict, text in PLAIN_VERDICT.items():
            if "safe" in text:
                self.assertTrue("not proof" in text or "says nothing" in text, verdict)


def ml(probability):
    return {"status": "available", "probability": probability}


class TestCombination(unittest.TestCase):
    def test_without_a_model_the_rule_score_stands(self):
        result = combine(47, False, {"status": "unavailable", "reason": "no saved model"}, CONFIG)
        self.assertEqual(result["combined_score"], 47)
        self.assertEqual(result["rule_applied"], "rules_only")
        self.assertIn("no saved model", result["explanation"])

    def test_direct_evidence_cannot_be_reduced_by_the_model(self):
        result = combine(97, True, ml(0.01), CONFIG)
        self.assertEqual(result["combined_score"], 97)
        self.assertEqual(result["rule_applied"], "direct_evidence_overrides_ml")

    def test_model_alone_raises_only_to_a_capped_review_level(self):
        result = combine(5, False, ml(0.99), CONFIG)
        self.assertEqual(result["combined_score"], CONFIG["combination"]["ml_only_floor"])
        self.assertEqual(result["rule_applied"], "ml_only_flag")
        self.assertLess(result["combined_score"], CONFIG["bands"]["high"])
        self.assertEqual(result["agreement"], "disagree")

    def test_confident_model_tempers_indirect_rule_signals(self):
        result = combine(47, False, ml(0.02), CONFIG)
        self.assertEqual(result["combined_score"], 32)
        self.assertEqual(result["rule_applied"], "ml_tempered_indirect_rules")

    def test_critical_rule_score_is_not_tempered(self):
        self.assertEqual(combine(85, False, ml(0.02), CONFIG)["combined_score"], 85)

    def test_the_rule_score_is_always_preserved(self):
        self.assertEqual(combine(47, False, ml(0.02), CONFIG)["rule_score"], 47)

    def test_agreement_is_reported(self):
        self.assertEqual(combine(70, False, ml(0.9), CONFIG)["agreement"], "agree")
        self.assertEqual(combine(5, False, ml(0.02), CONFIG)["agreement"], "agree")


if __name__ == "__main__":
    unittest.main()
