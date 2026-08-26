"""Regression tests for the analysis half of the pipeline.

Standard-library ``unittest`` on purpose: these must run on the 4 GB laptop with nothing
installed.  Run them with::

    python -m unittest discover -s tests -v

The three fixture pairs are the acceptance criteria for Tier 1.  If a change to the
features or the rule weights flips one of those verdicts, that is a finding to discuss,
not a test to quietly update.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from engine.cli import _check_comparable
from engine.features.delta import behavioral_delta
from engine.features.extract import (
    FEATURE_ORDER,
    extract_features,
    looks_encoded,
    registrable_domain,
    shannon_entropy,
    split_permissions,
)
from engine.features.schema import TraceError, validate_trace
from engine.report.render import build_record, render_text
from engine.scoring.rules import RULES, score_delta, verdict_for

FIXTURES = Path(__file__).resolve().parent.parent / "data" / "fixtures"


def load(pair: str, version: str) -> dict:
    return json.loads((FIXTURES / pair / f"{version}.trace.json").read_text(encoding="utf-8"))


def scored_pair(pair: str) -> tuple[dict, dict]:
    delta = behavioral_delta(load(pair, "v1"), load(pair, "v2"))
    return delta, score_delta(delta)


class TestSchema(unittest.TestCase):
    def test_fixtures_all_validate(self):
        for path in sorted(FIXTURES.glob("*/*.trace.json")):
            with self.subTest(trace=path.name, pair=path.parent.name):
                validate_trace(json.loads(path.read_text(encoding="utf-8")), source=str(path))

    def test_missing_channel_is_rejected(self):
        trace = load("benign_pair", "v1")
        del trace["storage"]
        with self.assertRaises(TraceError):
            validate_trace(trace)

    def test_incompatible_schema_version_is_rejected(self):
        trace = load("benign_pair", "v1")
        trace["schema_version"] = "9.0"
        with self.assertRaises(TraceError):
            validate_trace(trace)

    def test_event_missing_required_field_is_rejected(self):
        trace = load("benign_pair", "v1")
        del trace["network"][0]["initiator"]
        with self.assertRaisesRegex(TraceError, "initiator"):
            validate_trace(trace)


class TestHelpers(unittest.TestCase):
    def test_registrable_domain(self):
        cases = {
            "webmail.test": "webmail.test",
            "api.readermode.test": "readermode.test",
            "a.b.example.co.uk": "example.co.uk",
            "example.com": "example.com",
        }
        for hostname, expected in cases.items():
            with self.subTest(hostname=hostname):
                self.assertEqual(registrable_domain(hostname), expected)

    def test_looks_encoded_separates_blobs_from_identifiers(self):
        self.assertTrue(looks_encoded("aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQgZGF0YQ"))
        self.assertFalse(looks_encoded("en-GB"))
        self.assertFalse(looks_encoded("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))  # long but no entropy

    def test_entropy_is_zero_for_empty_string(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_mv2_host_patterns_are_folded_out_of_permissions(self):
        api, hosts = split_permissions({"permissions": ["cookies", "https://*/*", "<all_urls>"]})
        self.assertEqual(api, {"cookies"})
        self.assertEqual(hosts, {"https://*/*", "<all_urls>"})


class TestFeatures(unittest.TestCase):
    def test_vector_is_complete_and_ordered(self):
        features = extract_features(load("benign_pair", "v1"))
        self.assertEqual(tuple(features), FEATURE_ORDER)

    def test_baseline_has_no_exfiltration_flow(self):
        features = extract_features(load("weaponised_pair", "v1"))
        self.assertEqual(features["exfil_flows"], 0.0)

    def test_weaponised_version_shows_a_third_party_flow(self):
        features = extract_features(load("weaponised_pair", "v2"))
        self.assertGreaterEqual(features["exfil_flows_third_party"], 1.0)

    def test_first_party_hosts_are_not_counted_as_third_party(self):
        features = extract_features(load("benign_pair", "v1"))
        # demo-bank.test and webmail.test are the scenario's own pages.
        self.assertEqual(features["net_hosts"] - features["net_third_party_hosts"], 2.0)

    def test_identity_reads_are_not_counted_as_credential_reads(self):
        features = extract_features(load("grayzone_pair", "v2"))
        self.assertGreater(features["dom_identity_reads"], 0.0)
        self.assertEqual(features["dom_sensitive_reads"], 0.0)


class TestDelta(unittest.TestCase):
    def test_delta_is_v2_minus_v1(self):
        delta = behavioral_delta(load("benign_pair", "v1"), load("benign_pair", "v2"))
        for name in FEATURE_ORDER:
            self.assertAlmostEqual(
                delta["numeric"][name],
                delta["features_v2"][name] - delta["features_v1"][name],
                msg=f"delta mismatch on {name}",
            )

    def test_identical_traces_produce_a_zero_delta(self):
        trace = load("benign_pair", "v1")
        delta = behavioral_delta(trace, trace)
        self.assertEqual(set(delta["numeric"].values()), {0.0})
        self.assertEqual(score_delta(delta)["score"], 0.0)

    def test_new_subdomain_of_a_known_party_is_not_a_new_third_party(self):
        # v1 already talks to api.contactfinder.test; a sibling subdomain is the same party.
        v1 = load("grayzone_pair", "v1")
        v2 = load("grayzone_pair", "v2")
        v2["network"].append({
            "ts": 4.0, "url": "https://cdn2.contactfinder.test/x.json",
            "method": "GET", "initiator": "extension", "resource_type": "xhr", "body_len": 0,
        })
        evidence = behavioral_delta(v1, v2)["evidence"]
        self.assertIn("cdn2.contactfinder.test", evidence["new_hosts"])
        self.assertNotIn("cdn2.contactfinder.test", evidence["new_third_party_hosts"])

    def test_evidence_lists_the_new_credential_target(self):
        delta = behavioral_delta(load("weaponised_pair", "v1"), load("weaponised_pair", "v2"))
        self.assertEqual(delta["evidence"]["new_sensitive_dom_targets"], ["input#password"])
        self.assertEqual(delta["evidence"]["new_upload_hosts"], ["collect-analytics.test"])


class TestScoring(unittest.TestCase):
    def test_rule_ids_are_unique(self):
        ids = [rule.id for rule in RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_weights_are_probabilities(self):
        for rule in RULES:
            with self.subTest(rule=rule.id):
                self.assertTrue(0.0 < rule.weight <= 1.0)

    def test_noisy_or_stays_within_bounds(self):
        for pair in ("benign_pair", "grayzone_pair", "weaponised_pair"):
            with self.subTest(pair=pair):
                score = scored_pair(pair)[1]["score"]
                self.assertGreaterEqual(score, 0.0)
                self.assertLessEqual(score, 1.0)

    def test_verdict_boundaries(self):
        self.assertEqual(verdict_for(0.0), "BENIGN")
        self.assertEqual(verdict_for(0.34), "BENIGN")
        self.assertEqual(verdict_for(0.35), "SUSPICIOUS")
        self.assertEqual(verdict_for(0.69), "SUSPICIOUS")
        self.assertEqual(verdict_for(0.70), "MALICIOUS")
        self.assertEqual(verdict_for(1.0), "MALICIOUS")

    def test_benign_update_is_not_flagged(self):
        _, scored = scored_pair("benign_pair")
        self.assertEqual(scored["verdict"], "BENIGN")

    def test_weaponised_update_is_flagged(self):
        _, scored = scored_pair("weaponised_pair")
        self.assertEqual(scored["verdict"], "MALICIOUS")
        self.assertIn("R01", [hit["id"] for hit in scored["fired_rules"]])

    def test_grayzone_update_lands_between_the_two(self):
        _, scored = scored_pair("grayzone_pair")
        self.assertEqual(scored["verdict"], "SUSPICIOUS")

    def test_scores_are_ordered_benign_gray_malicious(self):
        benign = scored_pair("benign_pair")[1]["score"]
        gray = scored_pair("grayzone_pair")[1]["score"]
        malicious = scored_pair("weaponised_pair")[1]["score"]
        self.assertLess(benign, gray)
        self.assertLess(gray, malicious)

    def test_unchanged_broad_permission_does_not_fire(self):
        # Both versions declare <all_urls>; only a *widening* should fire R07.
        _, scored = scored_pair("weaponised_pair")
        self.assertNotIn("R07", [hit["id"] for hit in scored["fired_rules"]])


class TestReport(unittest.TestCase):
    def test_record_is_json_serialisable_and_complete(self):
        delta, scored = scored_pair("weaponised_pair")
        record = build_record(delta, scored)
        json.dumps(record)
        for key in ("verdict", "scores", "fired_rules", "evidence", "delta", "caveats"):
            self.assertIn(key, record)

    def test_report_states_that_weights_are_uncalibrated(self):
        delta, scored = scored_pair("weaponised_pair")
        self.assertIn("calibrated", render_text(delta, scored))

    def test_report_names_the_collector(self):
        delta, scored = scored_pair("weaponised_pair")
        self.assertIn("collect-analytics.test", render_text(delta, scored))


class TestComparabilityGuard(unittest.TestCase):
    def test_matching_runs_produce_no_warning(self):
        self.assertEqual(_check_comparable(load("benign_pair", "v1"),
                                           load("benign_pair", "v2")), [])

    def test_different_replay_bundle_is_warned_about(self):
        v1, v2 = load("benign_pair", "v1"), load("benign_pair", "v2")
        v2["run"]["replay_bundle"] = "rb-different"
        self.assertTrue(any("replayed different page bundles" in w
                            for w in _check_comparable(v1, v2)))

    def test_live_run_without_replay_is_warned_about(self):
        v1, v2 = load("benign_pair", "v1"), load("benign_pair", "v2")
        v1["run"]["replay_bundle"] = v2["run"]["replay_bundle"] = None
        self.assertTrue(any("no replay bundle" in w for w in _check_comparable(v1, v2)))

    def test_mismatched_scenario_is_warned_about(self):
        v1, v2 = load("benign_pair", "v1"), load("grayzone_pair", "v2")
        warnings = _check_comparable(v1, v2)
        self.assertTrue(any("different interaction scenarios" in w for w in warnings))
        self.assertTrue(any("different extension IDs" in w for w in warnings))


if __name__ == "__main__":
    unittest.main()
