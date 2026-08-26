"""Tests for the capture stage that do not need a browser.

The point of these is the split itself: the capture module must be importable, and the
scenarios and manifest rewriting must be testable, on a machine with no Playwright and
no Chromium.  If that ever stops being true, the analysis half stops being workable on
the laptop and the whole division of labour breaks.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from engine.features.schema import validate_trace
from engine.sandbox import scenarios
from engine.sandbox.capture import CaptureError, _initiator_for, _require_playwright
from engine.sandbox.rewrite import PRELUDE_JS, RewriteError, instrument_extension, scripts_declared_by


class TestScenarios(unittest.TestCase):
    def test_every_scenario_declares_its_pages(self):
        for name, scenario in scenarios.SCENARIOS.items():
            with self.subTest(scenario=name):
                self.assertTrue(scenario.pages)
                self.assertTrue(scenario.description)

    def test_lookup_error_lists_valid_names(self):
        with self.assertRaises(KeyError) as ctx:
            scenarios.get("no-such-scenario")
        self.assertIn("bank-login-then-webmail", str(ctx.exception))

    def test_steps_only_use_known_actions(self):
        known = {"goto", "fill", "click", "wait", "scroll"}
        for name, scenario in scenarios.SCENARIOS.items():
            for step in scenario.steps:
                with self.subTest(scenario=name, action=step.action):
                    self.assertIn(step.action, known)

    def test_fill_and_click_steps_have_selectors(self):
        for scenario in scenarios.SCENARIOS.values():
            for step in scenario.steps:
                if step.action in ("fill", "click"):
                    self.assertIsNotNone(step.selector)

    def test_credentials_are_obviously_fake(self):
        self.assertIn("example.test", scenarios.DUMMY_USERNAME)

    def test_scenario_names_match_the_fixture_traces(self):
        """The fixtures claim scenarios that must actually exist."""
        fixtures = Path(__file__).resolve().parent.parent / "data" / "fixtures"
        for path in fixtures.glob("*/*.trace.json"):
            trace = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(trace=path.name, pair=path.parent.name):
                self.assertIn(trace["run"]["scenario"], scenarios.SCENARIOS)


class TestInstrumentation(unittest.TestCase):
    def test_prelude_exists_and_is_guarded(self):
        source = PRELUDE_JS.read_text(encoding="utf-8")
        self.assertIn("__extdriftInstalled", source)   # must be idempotent per world
        self.assertIn("extdrift-report.invalid", source)  # dead reporting host

    def test_prelude_never_stores_captured_values(self):
        """Only lengths leave the page. Traces must be safe to commit and to hand over."""
        source = PRELUDE_JS.read_text(encoding="utf-8")
        self.assertIn("value_len", source)
        self.assertNotIn("value: value", source)


class TestScriptDiscovery(unittest.TestCase):
    def test_service_worker_and_content_scripts_are_found_in_load_order(self):
        manifest = {
            "manifest_version": 3,
            "background": {"service_worker": "sw.js"},
            "content_scripts": [{"matches": ["<all_urls>"], "js": ["a.js", "b.js"]}],
        }
        self.assertEqual(scripts_declared_by(manifest), ["sw.js", "a.js", "b.js"])

    def test_duplicate_scripts_are_listed_once(self):
        manifest = {
            "manifest_version": 3,
            "content_scripts": [
                {"matches": ["<all_urls>"], "js": ["shared.js"]},
                {"matches": ["https://x.test/*"], "js": ["shared.js", "extra.js"]},
            ],
        }
        self.assertEqual(scripts_declared_by(manifest), ["shared.js", "extra.js"])


class TestInstrumentExtension(unittest.TestCase):
    def _extension(self, tmp: str, manifest: dict) -> Path:
        source = Path(tmp) / "ext-src"
        source.mkdir()
        (source / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        (source / "content.js").write_text("console.log('hi');", encoding="utf-8")
        (source / "sw.js").write_text("console.log('sw');", encoding="utf-8")
        return source

    def test_prelude_is_prepended_to_declared_scripts(self):
        manifest = {
            "manifest_version": 3, "name": "x", "version": "1.0",
            "background": {"service_worker": "sw.js"},
            "content_scripts": [{"matches": ["<all_urls>"], "js": ["content.js"]}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            source = self._extension(tmp, manifest)
            result = instrument_extension(source, Path(tmp) / "work")
            self.assertEqual(sorted(result["instrumented_scripts"]), ["content.js", "sw.js"])
            rewritten = (result["path"] / "content.js").read_text(encoding="utf-8")
            self.assertIn("__extdriftInstalled", rewritten)
            self.assertIn("console.log('hi');", rewritten)  # original code preserved

    def test_the_original_extension_is_never_modified(self):
        manifest = {
            "manifest_version": 3, "name": "x", "version": "1.0",
            "content_scripts": [{"matches": ["<all_urls>"], "js": ["content.js"]}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            source = self._extension(tmp, manifest)
            instrument_extension(source, Path(tmp) / "work")
            untouched = (source / "content.js").read_text(encoding="utf-8")
            self.assertNotIn("__extdriftInstalled", untouched)

    def test_injection_is_idempotent(self):
        manifest = {
            "manifest_version": 3, "name": "x", "version": "1.0",
            "content_scripts": [{"matches": ["<all_urls>"], "js": ["content.js"]}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            source = self._extension(tmp, manifest)
            work = Path(tmp) / "work"
            instrument_extension(source, work)
            once = (work / "content.js").read_text(encoding="utf-8")
            # Re-running against the already-instrumented copy must not double-inject.
            second = instrument_extension(work, Path(tmp) / "work2")
            twice = (second["path"] / "content.js").read_text(encoding="utf-8")
            self.assertEqual(once.count("__extdriftInstalled"), twice.count("__extdriftInstalled"))

    def test_missing_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty"
            empty.mkdir()
            with self.assertRaises(RewriteError):
                instrument_extension(empty, Path(tmp) / "work")

    def test_declared_but_absent_script_is_reported_not_fatal(self):
        manifest = {
            "manifest_version": 3, "name": "x", "version": "1.0",
            "content_scripts": [{"matches": ["<all_urls>"], "js": ["ghost.js"]}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            source = self._extension(tmp, manifest)
            result = instrument_extension(source, Path(tmp) / "work")
            self.assertIn("ghost.js", result["declared_but_missing"])


class TestInitiatorAttribution(unittest.TestCase):
    EXT = "chrome-extension://abcdefghabcdefghabcdefghabcdefgh/"

    def test_extension_url_is_attributed_to_the_extension(self):
        self.assertEqual(_initiator_for(self.EXT + "sw.js", "", self.EXT), "extension")

    def test_request_from_extension_frame_is_a_content_script(self):
        self.assertEqual(
            _initiator_for("http://collect.test/x", self.EXT + "cs.js", self.EXT),
            "content_script")

    def test_page_request_is_attributed_to_the_page(self):
        self.assertEqual(
            _initiator_for("http://demo-bank.test/x", "http://demo-bank.test/login", self.EXT),
            "page")

    def test_frameless_request_is_attributed_to_the_service_worker(self):
        self.assertEqual(_initiator_for("http://collect.test/x", "", self.EXT),
                         "service_worker")


class TestEnvironmentGuard(unittest.TestCase):
    def test_missing_playwright_gives_an_actionable_message(self):
        try:
            _require_playwright()
        except CaptureError as exc:
            self.assertIn("pip install playwright", str(exc))
        else:
            self.skipTest("Playwright is installed in this environment")


class TestEmptyTrace(unittest.TestCase):
    def test_the_envelope_the_sandbox_starts_from_is_already_valid(self):
        from engine.features.schema import empty_trace
        trace = empty_trace("id", "name", "1.0", browser="chromium", scenario="idle-background")
        validate_trace(trace)


if __name__ == "__main__":
    unittest.main()
