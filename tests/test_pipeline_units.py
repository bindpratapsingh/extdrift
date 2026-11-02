"""Validation, sandbox configuration, reports and failure handling, without Docker."""

from __future__ import annotations

import base64
import io
import json
import struct
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from engine.pipeline.config import load_sandbox_config
from engine.pipeline.orchestrator import AnalysisPipeline
from engine.pipeline.states import State
from engine.pipeline.validation import ValidationError, validate_package
from engine.report import security_report
from engine.sandbox import docker_manager, preflight
from engine.sandbox.replay import Bundle, add_response, builtin_bundle, load_bundle
from engine.sandbox.rewrite import instrument_extension
from engine.unpack.crx import CrxError, safe_extract

ROOT = Path(__file__).resolve().parent.parent
CONTROLLED = ROOT / "data" / "corpus" / "controlled"
CONFIG = load_sandbox_config()
GOOD = {"manifest_version": 3, "name": "Good", "version": "1.2", "permissions": ["storage"],
        "host_permissions": ["https://a.test/*"],
        "background": {"service_worker": "sw.js"},
        "content_scripts": [{"matches": ["<all_urls>"], "js": ["c.js"]}],
        "web_accessible_resources": [{"resources": ["x.png"], "matches": ["<all_urls>"]}]}


def write_ext(root: Path, manifest=GOOD) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (root / "sw.js").write_text("// sw")
    (root / "c.js").write_text("// c")
    return root


def zip_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def crx3(payload: bytes) -> bytes:
    return b"Cr24" + struct.pack("<II", 3, 0) + payload


FILES = {"manifest.json": json.dumps(GOOD).encode(), "sw.js": b"//", "c.js": b"//"}


class TestValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_unpacked_directory(self):
        info = validate_package(write_ext(self.dir / "e"), self.dir / "w")
        meta = info.metadata
        self.assertEqual((meta["name"], meta["version"], meta["manifest_version"]), ("Good", "1.2", 3))
        self.assertEqual(meta["permissions"], ["storage"])
        self.assertEqual(meta["host_permissions"], ["https://a.test/*"])
        self.assertEqual(meta["service_worker"], "sw.js")
        self.assertEqual(meta["content_scripts"][0]["js"], ["c.js"])
        self.assertEqual(len(meta["web_accessible_resources"]), 1)
        self.assertEqual(info.format, "directory")

    def test_xpi_and_crx_packages_are_accepted(self):
        (self.dir / "a.xpi").write_bytes(zip_bytes(FILES))
        (self.dir / "a.crx").write_bytes(crx3(zip_bytes(FILES)))
        self.assertEqual(validate_package(self.dir / "a.xpi", self.dir / "w1").format, "zip")
        self.assertEqual(validate_package(self.dir / "a.crx", self.dir / "w2").format, "crx3")

    def test_problems_are_reported_in_plain_language(self):
        for manifest, expected in (
            ({**GOOD, "manifest_version": 9}, "manifest_version"),
            ({k: v for k, v in GOOD.items() if k != "name"}, "name"),
            ({**GOOD, "background": {"service_worker": "ghost.js"}}, "does not exist"),
            ({**GOOD, "background": {"service_worker": "../../etc/passwd"}}, "outside"),
        ):
            with self.subTest(expected=expected):
                path = write_ext(self.dir / f"e-{expected}", manifest)
                with self.assertRaises(ValidationError) as ctx:
                    validate_package(path, self.dir / "w")
                self.assertTrue(any(expected in p for p in ctx.exception.problems), ctx.exception.problems)

    def test_controlled_invalid_samples_are_rejected(self):
        for name in ("invalid_json", "invalid_no_manifest", "invalid_missing_script"):
            with self.subTest(sample=name), self.assertRaises(ValidationError):
                validate_package(CONTROLLED / name, self.dir / name)

    def test_missing_path_and_garbage_file(self):
        with self.assertRaises(ValidationError):
            validate_package(self.dir / "nothing.crx", self.dir / "w")
        (self.dir / "junk.crx").write_bytes(b"this is not an archive")
        with self.assertRaises(ValidationError):
            validate_package(self.dir / "junk.crx", self.dir / "w")

    def test_mv2_warns_rather_than_fails(self):
        manifest = {"manifest_version": 2, "name": "Two", "version": "1"}
        info = validate_package(write_ext(self.dir / "m2", manifest), self.dir / "w")
        self.assertTrue(any("Manifest V2" in w for w in info.warnings))

    def test_localised_name_is_resolved(self):
        manifest = {"manifest_version": 3, "name": "__MSG_app__", "version": "1", "default_locale": "en"}
        root = write_ext(self.dir / "loc", manifest)
        (root / "_locales" / "en").mkdir(parents=True)
        (root / "_locales" / "en" / "messages.json").write_text('{"app": {"message": "Real Name"}}')
        self.assertEqual(validate_package(root, self.dir / "w").metadata["name"], "Real Name")

    def test_extension_id_prefers_real_identity(self):
        key = base64.b64encode(b"public-key").decode()
        info = validate_package(write_ext(self.dir / "k", {**GOOD, "key": key}), self.dir / "w")
        self.assertEqual(info.metadata["extension_id_source"], "manifest_key")
        self.assertEqual(len(info.metadata["extension_id"]), 32)
        gecko = {**GOOD, "browser_specific_settings": {"gecko": {"id": "x@y"}}}
        info = validate_package(write_ext(self.dir / "g", gecko), self.dir / "w")
        self.assertEqual(info.metadata["extension_id"], "x@y")


class TestArchiveLimits(unittest.TestCase):
    def test_extraction_stops_at_the_byte_limit(self):
        archive = zipfile.ZipFile(io.BytesIO(zip_bytes({"big.bin": b"\0" * 5000})))
        with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(CrxError, "limit"):
            safe_extract(archive, Path(tmp), max_total_bytes=1000)

    def test_too_many_files_are_refused(self):
        archive = zipfile.ZipFile(io.BytesIO(zip_bytes({f"f{i}": b"x" for i in range(5)})))
        with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(CrxError, "entries"):
            safe_extract(archive, Path(tmp), max_files=3)


class TestHardening(unittest.TestCase):
    """If one of these flags ever disappears, the sandbox has silently become weaker."""

    def test_browser_container_flags(self):
        args = docker_manager.browser_arguments(CONFIG)
        joined = " ".join(args)
        for flag in ("--read-only", "--cap-drop ALL", "no-new-privileges", "--user 1000:1000",
                     "--memory", "--memory-swap", "--cpus", "--pids-limit", "seccomp=",
                     "noexec,nosuid,nodev"):
            self.assertIn(flag, joined)

    def test_gateway_container_flags(self):
        joined = " ".join(docker_manager.gateway_arguments(CONFIG))
        for flag in ("--read-only", "--cap-drop ALL", "no-new-privileges", "--memory", "--pids-limit"):
            self.assertIn(flag, joined)

    def test_dangerous_options_never_appear(self):
        for args in (docker_manager.browser_arguments(CONFIG), docker_manager.gateway_arguments(CONFIG)):
            joined = " ".join(args)
            for banned in ("--privileged", "docker.sock", "--cap-add", "--network host", "--pid host",
                           "seccomp=unconfined", "--env-file"):
                self.assertNotIn(banned, joined)

    def test_seccomp_profile_is_deny_by_default_without_ptrace(self):
        profile = json.loads((ROOT / CONFIG["security"]["seccomp_profile"]).read_text())
        self.assertEqual(profile["defaultAction"], "SCMP_ACT_ERRNO")
        names = {n for rule in profile["syscalls"] if rule["action"] == "SCMP_ACT_ALLOW" for n in rule["names"]}
        self.assertNotIn("ptrace", names)
        self.assertIn("unshare", names)

    def test_no_host_directory_is_mounted_by_the_run_commands(self):
        source = (ROOT / "engine" / "sandbox" / "docker_manager.py").read_text()
        self.assertNotIn("--mount", source)
        self.assertNotIn("REPO_ROOT}:", source)

    def test_image_build_context_excludes_data_and_secrets(self):
        ignore = (ROOT / ".dockerignore").read_text().splitlines()
        self.assertIn("*", ignore)
        for line in ignore:
            if line.startswith("!"):
                self.assertTrue(line[1:].startswith("engine/"), line)


class TestCollection(unittest.TestCase):
    def tar(self, entries):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name, data, kind in entries:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.size = len(data)
                if kind == tarfile.SYMTYPE:
                    info.linkname = "/etc/passwd"
                archive.addfile(info, io.BytesIO(data))
        buffer.seek(0)
        return buffer

    def test_traversal_and_symlinks_are_refused(self):
        stream = self.tar([("ok.txt", b"ok", tarfile.REGTYPE), ("../evil.txt", b"x", tarfile.REGTYPE),
                           ("link", b"", tarfile.SYMTYPE)])
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out"
            notes = docker_manager.safe_extract_stream(stream, dest, max_total=1000, max_file=1000)
            self.assertTrue((dest / "ok.txt").exists())
            self.assertFalse((Path(tmp) / "evil.txt").exists())
            self.assertFalse((dest / "link").exists())
            self.assertTrue(notes["truncated"])

    def test_size_ceiling_truncates_and_is_recorded(self):
        stream = self.tar([("a", b"x" * 100, tarfile.REGTYPE)])
        with tempfile.TemporaryDirectory() as tmp:
            notes = docker_manager.safe_extract_stream(stream, Path(tmp) / "o", max_total=1000, max_file=10)
            self.assertEqual((Path(tmp) / "o" / "a").stat().st_size, 10)
            self.assertIn("a", notes["truncated"])


class TestBrowserRegistry(unittest.TestCase):
    def test_only_tested_browsers_are_marked_supported(self):
        supported = {name for name, entry in CONFIG["browsers"].items() if entry["supported"]}
        self.assertEqual(supported, {"chromium", "firefox"})

    def test_untested_browser_produces_an_inconclusive_failure_report(self):
        for browser in ("chrome", "edge", "brave", "safari"):
            with tempfile.TemporaryDirectory() as tmp, self.subTest(browser=browser):
                pipeline = AnalysisPipeline(browser=browser, out_root=tmp)
                report = pipeline.analyse(CONTROLLED / "benign")
                self.assertEqual(report["status"], "FAILED")
                self.assertEqual(report["G_verdict"]["verdict"], "Inconclusive analysis")
                self.assertIn("not supported", report["G_verdict"]["failure"]["reason"])


class TestFailureHandling(unittest.TestCase):
    def test_invalid_package_gives_a_failure_report_not_a_benign_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            pipeline = AnalysisPipeline(out_root=tmp)
            report = pipeline.analyse(CONTROLLED / "invalid_json")
            self.assertEqual(report["status"], "FAILED")
            self.assertEqual(report["G_verdict"]["verdict"], "Inconclusive analysis")
            self.assertEqual(report["G_verdict"]["failure"]["stage"], "validation")
            self.assertIsNone(report["F_risk_assessment"]["overall_risk_score"])
            directory = Path(report["artefacts"]["directory"])
            status = json.loads((directory / "status.json").read_text())
            self.assertEqual(status["state"], State.FAILED.value)
            self.assertTrue((directory / "report.html").exists())
            self.assertIn("failed", (directory / "report.md").read_text().lower())

    def test_docker_unavailable_is_an_explicit_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            pipeline = AnalysisPipeline(out_root=tmp)
            error = docker_manager.DockerError("cannot reach the Docker daemon")
            with mock.patch.object(docker_manager, "image_id", side_effect=error):
                report = pipeline.analyse(CONTROLLED / "benign")
            self.assertEqual(report["status"], "FAILED")
            self.assertEqual(report["G_verdict"]["verdict"], "Inconclusive analysis")
            self.assertIn("Docker", report["G_verdict"]["failure"]["reason"])

    def test_compare_fails_if_either_version_is_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = AnalysisPipeline(out_root=tmp).compare(CONTROLLED / "benign", CONTROLLED / "invalid_json")
            self.assertEqual(report["G_verdict"]["verdict"], "Inconclusive analysis")

    def test_states_are_recorded_in_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            pipeline = AnalysisPipeline(out_root=tmp)
            pipeline.analyse(CONTROLLED / "invalid_json")
            history = [h["state"] for h in json.loads((pipeline.out_dir / "status.json").read_text())["history"]]
            self.assertEqual(history[:2], ["QUEUED", "VALIDATING"])
            self.assertEqual(history[-1], "FAILED")
            lines = (pipeline.out_dir / "pipeline.log").read_text().splitlines()
            self.assertTrue(all(json.loads(line) for line in lines))


@unittest.skipUnless(Path("/proc/self/status").exists(), "preflight reads Linux /proc")
class TestPreflight(unittest.TestCase):
    def test_this_host_fails_the_isolation_checks(self):
        result = preflight.run_checks("gateway")
        names = {c["name"]: c["passed"] for c in result["checks"]}
        self.assertFalse(result["passed"])
        self.assertFalse(names["seccomp_filter_active"] and names["memory_limit_applied"])


class TestEventFuzzing(unittest.TestCase):
    def test_fuzzing_suppresses_default_actions_so_it_cannot_navigate(self):
        from engine.sandbox.scenarios import EVENT_FUZZING_JS
        self.assertIn("preventDefault", EVENT_FUZZING_JS)
        self.assertIn("removeEventListener", EVENT_FUZZING_JS)


class TestReplay(unittest.TestCase):
    def test_digest_is_stable_and_sensitive_to_content(self):
        self.assertEqual(builtin_bundle().digest, builtin_bundle().digest)
        self.assertNotEqual(builtin_bundle().digest, builtin_bundle(["x.example.com"]).digest)

    def test_builtin_bundle_has_the_pages_scenarios_use(self):
        from engine.sandbox.scenarios import DEFAULT_SUITE, SCENARIOS
        bundle = builtin_bundle()
        from urllib.parse import urlsplit
        for name in DEFAULT_SUITE:
            for url in SCENARIOS[name].pages:
                parts = urlsplit(url)
                with self.subTest(url=url):
                    self.assertIsNotNone(bundle.lookup(parts.hostname, parts.path or "/"))

    def test_pages_contain_no_time_or_randomness(self):
        for host, paths in builtin_bundle().pages.items():
            for path, response in paths.items():
                text = response.body.decode("utf-8", "ignore")
                for banned in ("Date.now", "new Date", "Math.random"):
                    self.assertNotIn(banned, text, f"{host}{path}")

    def test_round_trip_through_a_file(self):
        bundle = Bundle("t")
        add_response(bundle, "https://a.test/x?y=1", 200, "text/html", b"<p>\xff</p>")
        add_response(bundle, "https://a.test/x?y=2", 200, "text/html", b"ignored, first wins")
        add_response(bundle, "http://a.test/old", 302, "text/plain", b"", "https://a.test/x")
        with tempfile.TemporaryDirectory() as tmp:
            bundle.to_file(Path(tmp) / "b.json")
            loaded = load_bundle(Path(tmp) / "b.json")
        self.assertEqual(loaded.digest, bundle.digest)
        self.assertEqual(loaded.lookup("a.test", "/x").body, b"<p>\xff</p>")
        self.assertEqual(dict(loaded.lookup("a.test", "/old").headers)["Location"], "https://a.test/x")


class TestInstrumentationAdditions(unittest.TestCase):
    def build(self, tmp):
        src = write_ext(Path(tmp) / "src")
        (src / "popup.js").write_text("// popup")
        (src / "_metadata").mkdir()
        (src / "_metadata" / "verified_contents.json").write_text("{}")
        (src / "legacy.js").write_bytes(b"var a = '\xff\xfe';")
        return src

    def test_all_scripts_reaches_files_the_manifest_does_not_declare(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = instrument_extension(self.build(tmp), Path(tmp) / "w", all_scripts=True)
            self.assertIn("popup.js", result["instrumented_scripts"])
            self.assertIn(b"__extdriftInstalled", (result["path"] / "popup.js").read_bytes())

    def test_default_behaviour_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = instrument_extension(self.build(tmp), Path(tmp) / "w")
            self.assertNotIn("popup.js", result["instrumented_scripts"])

    def test_store_metadata_is_removed_because_chromium_refuses_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = instrument_extension(self.build(tmp), Path(tmp) / "w")
            self.assertFalse((result["path"] / "_metadata").exists())

    def test_non_utf8_scripts_survive_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = instrument_extension(self.build(tmp), Path(tmp) / "w", all_scripts=True)
            self.assertTrue((result["path"] / "legacy.js").read_bytes().endswith(b"var a = '\xff\xfe';"))

    def test_manifest_patch_grants_nothing_but_the_report_channel(self):
        from engine.sandbox.container_runner import patch_manifest_for_capture
        with tempfile.TemporaryDirectory() as tmp:
            root = write_ext(Path(tmp) / "e", {**GOOD, "content_security_policy": {"extension_pages": "connect-src 'self'"}})
            patch_manifest_for_capture(root, "chromium")
            chromium = json.loads((root / "manifest.json").read_text())
            self.assertEqual(chromium["permissions"], GOOD["permissions"])
            self.assertEqual(chromium["host_permissions"], GOOD["host_permissions"])
            self.assertIn("extdrift-report.test", chromium["content_security_policy"]["extension_pages"])
            root = write_ext(Path(tmp) / "f")
            changes = patch_manifest_for_capture(root, "firefox")
            firefox = json.loads((root / "manifest.json").read_text())
            self.assertEqual(firefox["permissions"], GOOD["permissions"])
            added = set(firefox["host_permissions"]) - set(GOOD["host_permissions"])
            self.assertEqual(added, {"*://extdrift-report.test/*"})
            self.assertEqual(len(changes), 1)


class TestReportRendering(unittest.TestCase):
    def analysis(self, **kw):
        finding = {
            "indicator": "credential_exfiltration", "summary": "Synthetic values were sent to <evil>.test",
            "why": "reason", "weight": 0.97, "effective_weight": 0.97, "cluster": "exfiltration",
            "direct_evidence": True, "attribution_confidence": "confirmed", "change": "new",
            "counted_in_score": True, "risk_contribution": 97.0,
            "behaviours": [{"signature": "net:POST:x", "label": "POST <script>", "category": "network", "count": 1,
                            "scenarios": ["s"], "contexts": ["service_worker"], "first_timestamp": "t",
                            "details": {"markers": [{"kind": "password", "encoding": "base64", "location": "body"}]}}],
        }
        base = {
            "mode": "single", "analysis_id": "a1", "browser": "chromium", "started_at": "2026", "status": "COMPLETED",
            "verdict": "Critical behaviour detected", "duration_s": 1.0,
            "candidate_meta": {"name": "<img src=x onerror=1>", "version": "1", "extension_id": "e",
                               "permissions": ["cookies"], "host_permissions": [], "content_scripts": []},
            "candidate": {"summary": {"network_requests_total": 3}, "coverage": {"dimensions": {"network": "ok"}, "problems": [], "notes": []}},
            "risk": {"score": 97, "classification": "Critical observed risk", "findings": [finding],
                     "explanation": ["Risk score: 97/100.", "Because."]},
            "combined": {"combined_score": 97, "rule_applied": "rules_only", "classification": "Critical observed risk"},
            "ml": {"status": "not_applicable", "reason": "single version"}, "scenarios": ["s"],
        }
        base.update(kw)
        return base

    def test_all_sections_exist(self):
        report = security_report.build_report(self.analysis())
        for key in ("A_summary", "B_manifest", "C_runtime_summary", "D_suspicious_activity",
                    "E_version_comparison", "F_risk_assessment", "G_verdict"):
            self.assertIn(key, report)

    def test_limitation_statement_is_always_present(self):
        report = security_report.build_report(self.analysis())
        text = " ".join(report["G_verdict"]["limitations"])
        self.assertIn("dormant", text)
        self.assertIn("does not show that an extension is safe", text)
        self.assertIn("dormant", security_report.render_markdown(report))
        self.assertIn("dormant", security_report.render_html(report))

    def test_html_escapes_values_from_the_sample(self):
        html_text = security_report.render_html(security_report.build_report(self.analysis()))
        self.assertNotIn("<img src=x", html_text)
        self.assertNotIn("POST <script>", html_text)
        self.assertIn("&lt;img src=x", html_text)

    def test_marker_values_are_scrubbed_from_every_format(self):
        secret = "XDRFT-Bank-Pw-7f3a91c2"
        analysis = self.analysis()
        analysis["risk"]["findings"][0]["summary"] = f"sent {secret}"
        report = security_report.build_report(analysis)
        for text in (security_report.render_json(report), security_report.render_markdown(report),
                     security_report.render_html(report)):
            self.assertNotIn(secret, text)

    def test_failure_report_renders_with_no_scoring_data(self):
        analysis = {"mode": "compare", "analysis_id": "a", "browser": "firefox", "started_at": "n",
                    "status": "FAILED", "verdict": "Inconclusive analysis",
                    "failure": {"stage": "extension_loading", "reason": "refused", "details": {"problems": ["bad"]}}}
        report = security_report.build_report(analysis)
        self.assertIn("refused", security_report.render_markdown(report))
        self.assertIn("refused", security_report.render_html(report))
        self.assertIsNone(report["F_risk_assessment"]["overall_risk_score"])


class TestSyntheticDataIsFake(unittest.TestCase):
    def test_marker_values_are_obviously_synthetic(self):
        from engine.sandbox.markers import MARKERS
        for marker in MARKERS:
            with self.subTest(marker=marker.id):
                if marker.kind == "card":
                    # The well-known public test card number.
                    self.assertTrue(marker.value.replace(" ", "") == "4111111111111111")
                elif marker.id == "ssn":
                    self.assertTrue(marker.value.startswith("000-"))  # area 000 is never issued
                elif marker.id == "phone":
                    self.assertIn("555-01", marker.value)  # reserved for fiction
                else:
                    lowered = marker.value.lower()
                    self.assertTrue(any(t in lowered for t in ("xdrft", "fixture", "demo-", "example.test")),
                                    marker.value)


if __name__ == "__main__":
    unittest.main()
