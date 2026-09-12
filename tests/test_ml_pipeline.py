"""Tests for the dataset + ML tier (synth → batch → bake-off → anomaly).

These need numpy/pandas/scikit-learn; they skip cleanly if the ML stack is absent, so the
pure-stdlib analysis suite still runs on any machine. They use a small synthetic corpus so
they stay fast.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path


def _ml_available() -> bool:
    try:
        import numpy, pandas, sklearn, xgboost  # noqa: F401
        return True
    except Exception:
        return False


from engine.synth.generate import PAYLOAD_FAMILIES, generate_corpus  # noqa: E402
from engine.features.schema import validate_trace  # noqa: E402
from engine.features.delta import behavioral_delta  # noqa: E402


class TestSynthGenerator(unittest.TestCase):
    def test_corpus_traces_are_schema_valid(self):
        for r in generate_corpus(n_extensions=8, updates_per_ext=3, seed=1):
            validate_trace(r["trace_v1"]); validate_trace(r["trace_v2"])

    def test_corpus_has_both_classes_and_multiple_extensions(self):
        recs = generate_corpus(n_extensions=12, updates_per_ext=3, seed=2)
        labels = {r["label"] for r in recs}
        self.assertEqual(labels, {"benign", "malicious"})
        self.assertGreaterEqual(len({r["ext_id"] for r in recs}), 6)

    def test_malicious_families_are_all_known(self):
        recs = generate_corpus(n_extensions=20, updates_per_ext=3, seed=3)
        fams = {r["family"] for r in recs if r["label"] == "malicious"}
        self.assertTrue(fams.issubset(set(PAYLOAD_FAMILIES)))

    def test_password_manager_persona_reads_credentials_in_both_versions(self):
        # The label must live in the DELTA, not the absolute count: a passmgr reads password
        # fields in v1 and v2, so a benign passmgr update must not spike dom_sensitive_reads.
        recs = [r for r in generate_corpus(n_extensions=6, updates_per_ext=4, seed=5)
                if r["persona"] == "passmgr" and r["label"] == "benign"]
        self.assertTrue(recs)
        for r in recs:
            d = behavioral_delta(r["trace_v1"], r["trace_v2"])
            self.assertLessEqual(d["numeric"]["dom_sensitive_reads"], 0.0)


class TestBatchDataset(unittest.TestCase):
    def test_build_writes_expected_columns_and_rows(self):
        from engine.batch import build, ALL_COLUMNS
        import csv
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "deltas.csv"
            summary = build(n_extensions=10, updates_per_ext=3, seed=9,
                            captured_dir=None, out=out)
            self.assertEqual(summary["rows"], 30)
            with out.open(encoding="utf-8") as fh:
                header = next(csv.reader(fh))
            self.assertEqual(header, ALL_COLUMNS)
            self.assertIn("rule_score", header)
            self.assertIn("exfil_flows_third_party", header)


@unittest.skipUnless(_ml_available(), "ML stack (sklearn/xgboost/pandas) not installed")
class TestBakeoff(unittest.TestCase):
    def _dataset(self, tmp):
        from engine.batch import build
        out = Path(tmp) / "deltas.csv"
        build(n_extensions=30, updates_per_ext=3, seed=11, captured_dir=None, out=out)
        return out

    def test_bakeoff_runs_and_ranks_models(self):
        from engine.ml.bakeoff import run_bakeoff
        with tempfile.TemporaryDirectory() as tmp:
            out = self._dataset(tmp)
            summary = run_bakeoff(out, save=False)
            self.assertIn(summary["winner"], {"rules", "logreg", "rf", "xgboost", "svm"})
            for name in ("rules", "rf", "xgboost", "logreg", "svm"):
                self.assertIn(name, summary["results"])
                self.assertIsNotNone(summary["results"][name]["cv"]["pr_auc"])

    def test_a_learned_model_is_competitive_with_or_beats_rules(self):
        from engine.ml.bakeoff import run_bakeoff
        with tempfile.TemporaryDirectory() as tmp:
            out = self._dataset(tmp)
            r = run_bakeoff(out, save=False)["results"]
            best_ml = max((n for n in r if n != "rules"),
                          key=lambda n: r[n]["cv"]["pr_auc"] or 0)
            self.assertGreaterEqual(r[best_ml]["cv"]["pr_auc"], r["rules"]["cv"]["pr_auc"] - 0.05)

    def test_anomaly_layer_detects_held_out_families(self):
        from engine.ml.anomaly import run_anomaly
        with tempfile.TemporaryDirectory() as tmp:
            out = self._dataset(tmp)
            summary = run_anomaly(out)
            self.assertTrue(summary["families"])
            # At least one held-out family is detected above chance.
            rates = [m["detection_rate"] for m in summary["per_family"].values()
                     if m["detection_rate"] is not None]
            self.assertTrue(any(rate >= 0.5 for rate in rates))


if __name__ == "__main__":
    unittest.main()
