"""Live end-to-end capture test.

This actually launches Chromium, loads the instrumented extension, runs the scenario and
scores the diff.  It is the real integration test for the capture half, so it is slow and
needs Playwright + a Chromium build.  It skips cleanly when either is missing, so the
fast standard-library suite still runs everywhere.

Run just this one with::

    python -m unittest tests.test_live_capture -v
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "data" / "corpus" / "readerlite"


def _capture_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


@unittest.skipUnless(_capture_available(), "Playwright + Chromium not available")
class TestLiveCapture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="extdrift-live-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_weaponised_update_is_caught_and_actually_leaks(self):
        from engine.runner import run_pair
        record = run_pair(CORPUS / "1.0.0", CORPUS / "1.1.0",
                          scenario="bank-login-then-webmail", out_dir=self.tmp)
        self.assertEqual(record["verdict"], "MALICIOUS")
        # Ground truth: the fake collector must have actually received the stolen data.
        self.assertTrue(record["ground_truth"]["collector_received_data"])
        fired = [hit["id"] for hit in record["fired_rules"]]
        self.assertIn("R01", fired)  # exfiltration flow
        self.assertIn("R02", fired)  # bulk cookie read

    def test_benign_update_is_not_flagged_and_does_not_leak(self):
        from engine.runner import run_pair
        record = run_pair(CORPUS / "1.0.0", CORPUS / "1.0.1",
                          scenario="bank-login-then-webmail", out_dir=self.tmp)
        self.assertEqual(record["verdict"], "BENIGN")
        self.assertFalse(record["ground_truth"]["collector_received_data"])


if __name__ == "__main__":
    unittest.main()
