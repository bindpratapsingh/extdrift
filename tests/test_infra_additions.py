"""Tests for the new infrastructure: weaponiser, static baseline, ML predict bridge,
collector (offline parts), and the noisy-web test-site option.

All standard-library where possible; the ML predict test skips cleanly without sklearn.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from engine.baseline import static_score
from engine.collector.corpus import append_pair, load_manifest
from engine.collector.snapshot import list_installed, snapshot_installed
from engine.weaponiser import obfuscate_js, weaponise
from engine.weaponiser.payloads import COLLECTOR, PAYLOAD_MARKER, PAYLOADS, render

BENIGN = "data/corpus/readerlite/1.0.0"


def _ml_available() -> bool:
    try:
        import sklearn, joblib  # noqa: F401
        return True
    except Exception:
        return False


class TestWeaponiser(unittest.TestCase):
    def test_clean_injection_adds_real_payload_and_permission(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = weaponise(BENIGN, Path(tmp) / "mal", family="cookie_theft", obfuscated=False)
            self.assertEqual(r["added_permission"], "cookies")
            sw = (Path(r["out_dir"]) / "sw.js").read_text(encoding="utf-8")
            self.assertIn("chrome.cookies", sw)      # clean: literal tokens present
            self.assertIn(PAYLOAD_MARKER, sw)
            manifest = json.loads((Path(r["out_dir"]) / "manifest.json").read_text())
            self.assertIn("cookies", manifest["permissions"])
            self.assertEqual(manifest["_extdrift_synthetic"]["family"], "cookie_theft")

    def test_obfuscation_hides_tokens_but_keeps_the_collector_reachable(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = weaponise(BENIGN, Path(tmp) / "obf", family="cookie_theft", obfuscated=True)
            sw = (Path(r["out_dir"]) / "sw.js").read_text(encoding="utf-8")
            # The literal high-risk tokens must be gone...
            self.assertNotIn("chrome.cookies", sw)
            self.assertNotIn(".getAll(", sw)
            # ...but the behaviour is intact (computed access + atob-encoded collector).
            self.assertIn("atob(", sw)

    def test_original_extension_is_untouched(self):
        before = (Path(BENIGN) / "sw.js").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            weaponise(BENIGN, Path(tmp) / "mal", family="cookie_theft")
        after = (Path(BENIGN) / "sw.js").read_text(encoding="utf-8")
        self.assertEqual(before, after)

    def test_unknown_family_is_rejected(self):
        from engine.weaponiser import WeaponiseError
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(WeaponiseError):
                weaponise(BENIGN, Path(tmp) / "x", family="nope")

    def test_obfuscate_preserves_collector_semantics(self):
        obf = obfuscate_js(render(PAYLOADS["cookie_theft"]["service_worker"]))
        self.assertNotIn(f'"{COLLECTOR}"', obf)   # url no longer a literal
        self.assertIn("atob(", obf)


class TestStaticBaseline(unittest.TestCase):
    def test_static_catches_clean_but_misses_obfuscated(self):
        with tempfile.TemporaryDirectory() as tmp:
            clean = weaponise(BENIGN, Path(tmp) / "c", family="cookie_theft", obfuscated=False)
            obf = weaponise(BENIGN, Path(tmp) / "o", family="cookie_theft", obfuscated=True)
            s_clean = static_score(BENIGN, clean["out_dir"])
            s_obf = static_score(BENIGN, obf["out_dir"])
            self.assertEqual(s_clean["verdict"], "MALICIOUS")
            self.assertEqual(s_obf["verdict"], "BENIGN")   # the whole point of the head-to-head
            self.assertGreater(s_clean["score"], s_obf["score"])

    def test_identical_versions_score_zero(self):
        s = static_score(BENIGN, BENIGN)
        self.assertEqual(s["score"], 0.0)


class TestCollectorSnapshot(unittest.TestCase):
    def _fake_profile(self, tmp: str) -> Path:
        root = Path(tmp) / "Extensions"
        (root / "extidaaaa" / "1.0.0_0").mkdir(parents=True)
        (root / "extidaaaa" / "1.0.0_0" / "manifest.json").write_text(
            json.dumps({"manifest_version": 3, "name": "X", "version": "1.0.0"}))
        return root

    def test_list_and_snapshot_installed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fake_profile(tmp)
            listed = list_installed(root)
            self.assertEqual(listed[0]["ext_id"], "extidaaaa")
            saved = snapshot_installed(Path(tmp) / "snap", extensions_root=root)
            self.assertEqual(len(saved), 1)
            self.assertTrue((Path(tmp) / "snap" / "extidaaaa" / "1.0.0_0" / "manifest.json").exists())

    def test_snapshot_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fake_profile(tmp)
            dest = Path(tmp) / "snap"
            snapshot_installed(dest, extensions_root=root)
            second = snapshot_installed(dest, extensions_root=root)
            self.assertEqual(second, [])  # already present -> nothing new copied


class TestCollectorCorpus(unittest.TestCase):
    def test_append_and_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            mpath = Path(tmp) / "manifest.jsonl"
            append_pair(mpath, pair_id="p1", ext_id="e1", v1_dir="a", v2_dir="b",
                        label="benign", source="github")
            append_pair(mpath, pair_id="p2", ext_id="e2", v1_dir="c", v2_dir="d",
                        label="unknown", source="snapshot")
            rows = load_manifest(mpath)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["label"], "benign")

    def test_invalid_label_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                append_pair(Path(tmp) / "m.jsonl", pair_id="p", ext_id="e",
                            v1_dir="a", v2_dir="b", label="evil")


@unittest.skipUnless(_ml_available(), "sklearn/joblib not installed")
class TestPredictBridge(unittest.TestCase):
    def test_predict_returns_none_without_a_model(self):
        # Point the model path at a non-existent file by checking the graceful path:
        from engine.ml import predict
        real = predict.MODEL_PATH
        try:
            predict.MODEL_PATH = Path("does-not-exist.joblib")
            self.assertIsNone(predict.load_model())
        finally:
            predict.MODEL_PATH = real

    def test_predict_on_a_pair_when_model_exists(self):
        from engine.ml.predict import predict_pair, load_model
        if load_model() is None:
            self.skipTest("no trained model on disk (run engine.ml.bakeoff first)")
        v1 = json.loads((Path(BENIGN).parent / "1.0.0" / "manifest.json").read_text())  # noqa
        # Use the committed fixture traces as a stand-in pair.
        t1 = json.loads(Path("data/fixtures/weaponised_pair/v1.trace.json").read_text())
        t2 = json.loads(Path("data/fixtures/weaponised_pair/v2.trace.json").read_text())
        result = predict_pair(t1, t2)
        self.assertIn(result["verdict"], {"BENIGN", "MALICIOUS"})
        self.assertGreaterEqual(result["probability"], 0.0)
        self.assertLessEqual(result["probability"], 1.0)


if __name__ == "__main__":
    unittest.main()
