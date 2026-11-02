"""End-to-end tests of the Docker pipeline, on real browser runs in real containers.

These are the acceptance tests. Nothing is mocked: each extension runs in the hardened sandbox and
the assertions read what was captured. They take several minutes, so they run only on request:

    EXTDRIFT_DOCKER_TESTS=1 python -m pytest tests/test_docker_e2e.py -v

Set EXTDRIFT_E2E_BROWSERS=chromium,firefox to choose browsers (default: both).
"""

from __future__ import annotations

import io
import json
import os
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTROLLED = ROOT / "data" / "corpus" / "controlled"
SCENARIOS = ["general-browsing", "financial-portal-login", "idle-background"]
BROWSERS = os.environ.get("EXTDRIFT_E2E_BROWSERS", "chromium,firefox").split(",")


def _docker_ready() -> bool:
    if os.environ.get("EXTDRIFT_DOCKER_TESTS") != "1":
        return False
    from engine.pipeline.config import load_sandbox_config
    from engine.sandbox import docker_manager
    try:
        docker_manager.check_daemon()
        config = load_sandbox_config()
        docker_manager.image_id(config["images"]["sandbox"])
        docker_manager.image_id(config["images"]["gateway"])
    except docker_manager.DockerError:
        return False
    return True


def run_single(extension: str, browser: str, tmp: str, scenarios=SCENARIOS) -> tuple[dict, Path]:
    from engine.pipeline.orchestrator import AnalysisPipeline
    pipeline = AnalysisPipeline(browser=browser, scenarios=scenarios, out_root=tmp)
    return pipeline.analyse(CONTROLLED / extension), pipeline.out_dir


def run_pair(base: str, candidate: str, browser: str, tmp: str, *, aa_check=False, scenarios=SCENARIOS):
    from engine.pipeline.orchestrator import AnalysisPipeline
    pipeline = AnalysisPipeline(browser=browser, scenarios=scenarios, out_root=tmp, aa_check=aa_check)
    return pipeline.compare(CONTROLLED / base, CONTROLLED / candidate), pipeline.out_dir


def events_of(directory: Path, role: str = "candidate") -> list[dict]:
    path = directory / role / "trace.normalised.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def score(report: dict) -> int:
    return report["F_risk_assessment"]["overall_risk_score"]


def indicators(report: dict) -> set[str]:
    return {item["indicator"] for item in report["D_suspicious_activity"]}


@unittest.skipUnless(_docker_ready(), "set EXTDRIFT_DOCKER_TESTS=1, with Docker running and images built")
class DockerE2E(unittest.TestCase):
    browser = "chromium"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="extdrift-e2e-")
        self.addCleanup(self.tmp.cleanup)

    def assertCompleted(self, report):
        self.assertEqual(report["status"], "COMPLETED", report["G_verdict"].get("failure"))
        coverage = report["monitoring_coverage"]["candidate"]
        self.assertTrue(coverage["complete"], coverage["problems"])

    def assertNothingLeftBehind(self):
        from engine.sandbox.docker_manager import wait_until_removed
        self.assertEqual(wait_until_removed(), {"containers": [], "networks": [], "volumes": []})

    # -- required tests ---------------------------------------------------------------------

    def test_1_benign_extension_has_low_observed_risk(self):
        report, _ = run_single("benign", self.browser, self.tmp.name)
        self.assertCompleted(report)
        self.assertLess(score(report), 20)
        self.assertIn(report["G_verdict"]["verdict"],
                      ("No significant suspicious behaviour observed", "Low observed risk"))
        self.assertNotIn("is safe", report["G_verdict"]["plain_language"].replace("extension is safe", ""))

    def test_2_credential_access_is_recorded_and_raises_risk(self):
        report, directory = run_single("credential_access", self.browser, self.tmp.name)
        self.assertCompleted(report)
        reads = [e for e in events_of(directory) if e["event_type"] == "field_read"
                 and e["metadata"].get("field_class") == "password"]
        self.assertTrue(reads, "the password field read was not captured")
        self.assertEqual(reads[0]["category"], "dom")
        self.assertEqual(reads[0]["source_context"], "content_script")
        self.assertIn("sensitive_field:password", reads[0]["risk_indicators"])
        self.assertIn("credential_field_read", indicators(report))
        self.assertTrue(20 <= score(report) < 60, score(report))

    def test_3_cookie_access_is_captured(self):
        report, directory = run_single("cookie_access", self.browser, self.tmp.name)
        self.assertCompleted(report)
        events = events_of(directory)
        self.assertTrue([e for e in events if e["event_type"] == "cookie_read"], "document.cookie read not captured")
        self.assertTrue([e for e in events if e["category"] == "storage" and e["event_type"] == "read_all"],
                        "cookies.getAll not captured")
        self.assertIn("cookie_bulk_read", indicators(report))
        self.assertGreaterEqual(score(report), 40)

    def test_4_marker_in_network_traffic_is_captured_and_related_to_the_data(self):
        report, directory = run_single("network_marker", self.browser, self.tmp.name)
        self.assertCompleted(report)
        posts = [e for e in events_of(directory) if e["event_type"] == "http_request"
                 and e["destination"] == "collect-metrics.test"]
        self.assertTrue(posts, "the request was not captured")
        hits = posts[0]["metadata"]["marker_hits"]
        self.assertEqual(hits[0]["marker"], "auth_token")
        self.assertIn("marker:session", posts[0]["risk_indicators"])
        self.assertEqual(posts[0]["attribution_confidence"], "confirmed")
        self.assertIn("session_exfiltration", indicators(report))

    def test_5_combined_behaviour_far_exceeds_either_isolated_event(self):
        access, _ = run_single("credential_access", self.browser, self.tmp.name)
        combined, directory = run_single("combined", self.browser, self.tmp.name)
        self.assertCompleted(combined)
        self.assertIn("credential_exfiltration", indicators(combined))
        self.assertGreaterEqual(score(combined), 80)
        self.assertGreater(score(combined), score(access) + 40)
        hits = [h for e in events_of(directory) for h in e["metadata"].get("marker_hits", [])
                if e["category"] == "network" and h["kind"] == "password"]
        self.assertTrue(hits)
        self.assertIn("base64", hits[0]["encoding"])

    def test_6_version_comparison_identifies_what_the_update_introduced(self):
        report, directory = run_pair("pair_v1", "pair_v2", self.browser, self.tmp.name)
        self.assertCompleted(report)
        comparison = report["E_version_comparison"]
        new = {item["signature"] for item in comparison["newly_introduced_behaviours"]}
        self.assertIn("dom:field_read:password", new)
        self.assertIn("dom:cookie_read", new)
        self.assertIn("telemetry-sync9.test", comparison["network_destination_differences"]["new"])
        self.assertTrue(any("telemetry-sync9.test" in s for s in new))
        self.assertIn("cookies", comparison["permission_differences"]["high_risk_added"])
        self.assertGreater(comparison["feature_difference_vector"]["exfil_credential_events"], 0)
        self.assertEqual(comparison["comparability"]["problems"], [])
        self.assertGreaterEqual(score(report), 80)
        self.assertEqual(report["G_verdict"]["verdict"], "Critical behaviour detected")

        unchanged_signature = "net:GET:api.readermode.test/v2/config"
        self.assertNotIn(unchanged_signature, new, "behaviour both versions share must not count as new")
        for name in ("baseline", "candidate"):
            self.assertTrue((directory / name / "trace.normalised.jsonl").exists())
            self.assertTrue((directory / name / "features.json").exists())
            self.assertTrue((directory / name / "raw" / "gateway" / "flows.jsonl").exists())

    def test_6b_benign_update_is_not_called_malicious(self):
        report, _ = run_pair("pair_v1", "pair_v1_1_benign", self.browser, self.tmp.name)
        self.assertCompleted(report)
        self.assertLess(score(report), 40, report["F_risk_assessment"]["score_explanation"])
        self.assertNotIn("credential_exfiltration", indicators(report))
        destinations = report["E_version_comparison"]["network_destination_differences"]["new"]
        self.assertIn("fonts.readercdn.test", destinations)

    def test_7a_invalid_package_returns_a_clear_failure(self):
        for name in ("invalid_json", "invalid_no_manifest", "invalid_missing_script"):
            with self.subTest(sample=name):
                report, _ = run_single(name, self.browser, self.tmp.name)
                self.assertEqual(report["status"], "FAILED")
                self.assertEqual(report["G_verdict"]["verdict"], "Inconclusive analysis")
                self.assertEqual(report["G_verdict"]["failure"]["stage"], "validation")

    def test_7b_a_package_the_browser_refuses_returns_a_clear_failure(self):
        report, _ = run_single("rejected_by_browser", self.browser, self.tmp.name)
        self.assertEqual(report["status"], "FAILED")
        self.assertEqual(report["G_verdict"]["verdict"], "Inconclusive analysis")
        self.assertEqual(report["G_verdict"]["failure"]["stage"], "extension_loading")
        self.assertIsNone(score(report))
        self.assertNothingLeftBehind()

    # -- monitoring and isolation -----------------------------------------------------------

    def test_isolation_is_proved_and_nothing_is_left_behind(self):
        report, directory = run_single("benign", self.browser, self.tmp.name, scenarios=["general-browsing"])
        self.assertCompleted(report)
        checks = report["isolation"]["checks"]
        for role in ("browser", "gateway"):
            self.assertTrue(checks[role]["passed"], checks[role])
            names = {c["name"] for c in checks[role]["checks"]}
            self.assertLessEqual({"runs_as_non_root", "no_effective_capabilities", "egress_blocked",
                                  "external_dns_blocked", "docker_socket_absent",
                                  "root_filesystem_read_only", "seccomp_filter_active"}, names)
        browser_names = {c["name"] for c in checks["browser"]["checks"] if c["passed"]}
        self.assertIn("gateway_reachable", browser_names)
        self.assertNothingLeftBehind()
        self.assertTrue((directory / "report.html").exists())

    def test_no_report_or_trace_contains_a_raw_synthetic_secret(self):
        from engine.sandbox.markers import MARKERS
        _, directory = run_pair("pair_v1", "pair_v2", self.browser, self.tmp.name, scenarios=["financial-portal-login"])
        checked = 0
        for path in directory.rglob("*"):
            if path.is_file() and path.suffix in (".json", ".jsonl", ".md", ".html", ".log"):
                text = path.read_text(encoding="utf-8", errors="replace")
                checked += 1
                for marker in MARKERS:
                    self.assertNotIn(marker.value, text, f"{marker.id} in {path}")
        self.assertGreater(checked, 10)

    def test_beaconing_is_detected(self):
        report, _ = run_single("beacon", self.browser, self.tmp.name, scenarios=["idle-background"])
        self.assertCompleted(report)
        self.assertIn("beaconing", indicators(report))

    def test_form_hijack_through_the_page_is_caught(self):
        report, directory = run_single("form_hijack", self.browser, self.tmp.name, scenarios=["financial-portal-login"])
        self.assertCompleted(report)
        self.assertIn("form_tampering", indicators(report))
        posts = [e for e in events_of(directory) if e.get("destination") == "form-capture.test"]
        self.assertTrue(posts, "the redirected form post did not reach the gateway")
        self.assertNotEqual(posts[0]["source_context"], "page")
        self.assertTrue(any(i.startswith("marker:") for i in posts[0]["risk_indicators"]))

    def test_comparison_with_noise_measurement(self):
        report, _ = run_pair("pair_v1", "pair_v1", self.browser, self.tmp.name, aa_check=True,
                             scenarios=["general-browsing"])
        self.assertCompleted(report)
        comparison = report["E_version_comparison"]
        self.assertTrue(comparison["noise_floor_applied"])
        self.assertEqual(comparison["newly_introduced_and_suspicious"], [])
        self.assertLess(score(report), 20)

    def test_replay_bundle_is_served_and_recorded_identically(self):
        from engine.pipeline.orchestrator import AnalysisPipeline
        from engine.sandbox.replay import Bundle, add_response
        bundle = Bundle("test-bundle", entry_urls=("http://recorded-site.test/",))
        add_response(bundle, "http://recorded-site.test/", 200, "text/html",
                     b"<!doctype html><html><body><h1>Recorded</h1>"
                     b"<form><input type=password name=password></form></body></html>")
        file = Path(self.tmp.name) / "bundle.json"
        bundle.to_file(file)
        pipeline = AnalysisPipeline(browser=self.browser, out_root=self.tmp.name, bundle_file=file)
        report = pipeline.compare(CONTROLLED / "pair_v1", CONTROLLED / "pair_v1")
        self.assertEqual(report["status"], "COMPLETED", report["G_verdict"].get("failure"))
        self.assertEqual(report["E_version_comparison"]["comparability"]["problems"], [])
        self.assertEqual(report["E_version_comparison"]["comparability"]["bundle_digest"], bundle.digest)
        self.assertEqual(report["reproducibility"]["scenarios"], ["replay-browse"])


@unittest.skipUnless(_docker_ready(), "set EXTDRIFT_DOCKER_TESTS=1, with Docker running and images built")
class PackagesAndLimitsE2E(unittest.TestCase):
    """Package formats through the whole pipeline, and the wall-clock limit."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="extdrift-e2e-")
        self.addCleanup(self.tmp.cleanup)

    def _zip_of(self, extension: str) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for path in (CONTROLLED / extension).rglob("*"):
                if path.is_file():
                    archive.write(path, path.relative_to(CONTROLLED / extension).as_posix())
        return buffer.getvalue()

    def test_crx_package_runs_in_chromium(self):
        from engine.pipeline.orchestrator import AnalysisPipeline
        package = Path(self.tmp.name) / "sample.crx"
        package.write_bytes(b"Cr24" + struct.pack("<II", 3, 0) + self._zip_of("combined"))
        report = AnalysisPipeline(browser="chromium", scenarios=["financial-portal-login"],
                                  out_root=self.tmp.name).analyse(package)
        self.assertEqual(report["status"], "COMPLETED", report["G_verdict"].get("failure"))
        self.assertIn("credential_exfiltration", indicators(report))

    def test_xpi_package_runs_in_firefox(self):
        from engine.pipeline.orchestrator import AnalysisPipeline
        package = Path(self.tmp.name) / "sample.xpi"
        package.write_bytes(self._zip_of("combined"))
        report = AnalysisPipeline(browser="firefox", scenarios=["financial-portal-login"],
                                  out_root=self.tmp.name).analyse(package)
        self.assertEqual(report["status"], "COMPLETED", report["G_verdict"].get("failure"))
        self.assertIn("credential_exfiltration", indicators(report))

    def test_exceeding_the_time_limit_kills_the_run_and_reports_failure(self):
        from engine.pipeline.config import load_sandbox_config
        from engine.pipeline.orchestrator import AnalysisPipeline
        from engine.sandbox.docker_manager import wait_until_removed
        config = load_sandbox_config()
        config["limits"]["run_timeout_seconds"] = 8
        report = AnalysisPipeline(browser="chromium", scenarios=["idle-background"], out_root=self.tmp.name,
                                  sandbox_config=config).analyse(CONTROLLED / "benign")
        self.assertEqual(report["status"], "FAILED")
        self.assertEqual(report["G_verdict"]["verdict"], "Inconclusive analysis")
        self.assertIn("limit", report["G_verdict"]["failure"]["reason"])
        self.assertEqual(wait_until_removed(), {"containers": [], "networks": [], "volumes": []})

    def test_a_recorded_bundle_replays_through_the_gateway(self):
        import http.server
        import threading

        from engine.pipeline.orchestrator import AnalysisPipeline
        from engine.sandbox.replay import load_bundle, record_urls

        class Page(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                body = b"<!doctype html><html><body><h1>Recorded page</h1></body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Page)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        try:
            bundle_path = Path(self.tmp.name) / "recorded.json"
            url = f"http://127.0.0.1:{server.server_address[1]}/"
            try:
                recorded = record_urls([url], bundle_path, name="local-recording")
            except Exception as exc:  # noqa: BLE001 - recording uses the host's Playwright browser
                self.skipTest(f"no usable browser on the host for recording: {exc}")
            self.assertEqual(load_bundle(bundle_path).digest, recorded.digest)
            report = AnalysisPipeline(browser="chromium", out_root=self.tmp.name, bundle_file=bundle_path).compare(
                CONTROLLED / "pair_v1", CONTROLLED / "pair_v1")
            self.assertEqual(report["status"], "COMPLETED", report["G_verdict"].get("failure"))
            self.assertEqual(report["E_version_comparison"]["comparability"]["bundle_digest"], recorded.digest)
        finally:
            server.server_close()


@unittest.skipUnless("firefox" in BROWSERS and _docker_ready(), "Firefox end-to-end not requested")
class FirefoxE2E(DockerE2E):
    browser = "firefox"

    def test_7b_a_package_the_browser_refuses_returns_a_clear_failure(self):
        report, _ = run_single("incompatible_runtime", self.browser, self.tmp.name)
        self.assertEqual(report["status"], "FAILED")
        self.assertEqual(report["G_verdict"]["verdict"], "Inconclusive analysis")
        self.assertIsNone(score(report))
        self.assertNothingLeftBehind()


@unittest.skipUnless("chromium" in BROWSERS and _docker_ready(), "Chromium-only checks not requested")
class ChromiumOnlyE2E(unittest.TestCase):
    def test_browser_process_sandbox_is_on(self):
        with tempfile.TemporaryDirectory(prefix="extdrift-e2e-") as tmp:
            report, _ = run_single("benign", "chromium", tmp, scenarios=["general-browsing"])
        self.assertTrue(report["isolation"]["browser_process_sandbox"]["adequate"])

    def test_monitoring_surface_reaches_every_dimension(self):
        with tempfile.TemporaryDirectory(prefix="extdrift-e2e-") as tmp:
            report, directory = run_single("full_surface", "chromium", tmp, scenarios=["financial-portal-login"])
            events = events_of(directory)
        self.assertEqual(report["status"], "COMPLETED")
        types = {(e["category"], e["event_type"]) for e in events}
        for expected in (("dom", "field_read"), ("dom", "query"), ("dom", "cookie_read"), ("dom", "script_injected"),
                         ("dom", "html_injected"), ("dom", "form_modified"), ("dom", "form_data_read"),
                         ("dom", "listener"), ("storage", "read"), ("storage", "write"), ("storage", "delete"),
                         ("api", "api_call"), ("api", "event_listener"), ("network", "http_request"),
                         ("network", "websocket_open"), ("network", "websocket_message")):
            self.assertIn(expected, types)
        areas = {e["metadata"].get("area") for e in events if e["category"] == "storage"}
        self.assertLessEqual({"local_storage", "session_storage", "indexeddb", "extension_local", "extension_sync"}, areas)
        apis = {e["operation"] for e in events if e["category"] == "api"}
        self.assertLessEqual({"tabs.query", "alarms.create", "webRequest.onBeforeRequest.addListener",
                              "permissions.getAll"}, apis)
        self.assertTrue(any(h["marker"] == "api_key" for e in events if e["event_type"] == "websocket_message"
                            for h in e["metadata"].get("marker_hits", [])))


if __name__ == "__main__":
    unittest.main()
