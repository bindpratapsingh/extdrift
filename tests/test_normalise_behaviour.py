"""Normalisation, attribution, features and diffing, on hand-written evidence files.

These inputs are test data shaped like gateway output. Real captures are exercised by
tests/test_docker_e2e.py.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from engine.features.behaviour import (
    BEACON_MIN_INTERVAL_S,
    FEATURE_ORDER,
    detect_beacons,
    extract_behaviours,
    extract_features,
    feature_digest,
)
from engine.features.behaviour_diff import classify_behaviour, compare_versions, noise_floor
from engine.features.delta import behavioral_delta
from engine.features.extract import extract_features as legacy_features
from engine.features.schema import legacy_view, validate_trace
from engine.sandbox.attribution import CONFIRMED, INFERRED, attribute_flow
from engine.sandbox.normalise import (
    NORMALISED_FIELDS,
    RunContext,
    classify_field,
    events_from_legacy_trace,
    normalise_run,
    targeted_hosts_from_manifests,
)

T0 = 1_700_000_000.0
MANIFEST = {"manifest_version": 3, "name": "T", "version": "1.0",
            "background": {"service_worker": "sw.js"},
            "content_scripts": [{"matches": ["<all_urls>"], "js": ["c.js"]}]}


def flow(seq, method, url, host, **extra):
    record = {"kind": "http", "seq": seq, "t": T0 + seq, "method": method, "url": url, "host": host,
              "headers": {}, "marker_hits": [], "body_len": 0, "response": {"status": 200, "source": "sink"}}
    record.update(extra)
    return record


def report(seq, t, realm="content_script", **event):
    return {"arrival": T0 + t, "scenario": "s1",
            "event": {"realm": realm, "realm_id": realm + "-1", "report_seq": seq,
                      "t_wall": (T0 + t) * 1000, **event}}


def write_run(root: Path, flows, reports, *, status="completed", extra_run=None) -> Path:
    (root / "gateway").mkdir(parents=True)
    (root / "browser").mkdir()
    (root / "gateway" / "flows.jsonl").write_text("\n".join(json.dumps(f) for f in flows))
    (root / "gateway" / "reports.jsonl").write_text("\n".join(json.dumps(r) for r in reports))
    (root / "gateway" / "control.jsonl").write_text(json.dumps({"t": T0, "command": "start", "scenario": "s1"}))
    (root / "gateway" / "bundle.json").write_text(json.dumps({"digest": "d", "hosts": ["secure-bank.test"]}))
    run = {"status": status, "extension_loaded": True,
           "scenarios": [{"name": "s1", "status": "completed", "pages": ["https://secure-bank.test/login"]}]}
    run.update(extra_run or {})
    (root / "browser" / "run.json").write_text(json.dumps(run))
    return root


def ctx(manifest=None, version="1.0"):
    return RunContext("a", "ext", version, "chromium", manifest or MANIFEST, ["google.com"])


NAV = flow(0, "GET", "https://secure-bank.test/login", "secure-bank.test",
           headers={"sec-fetch-mode": "navigate"})
STARTS = [report(1, 0.1, event="realm_start", channel="meta", page="x"),
          report(1, 0.1, realm="service_worker", event="realm_start", channel="meta", page="")]


def norm(tmp, flows, reports, **kw):
    return normalise_run(write_run(Path(tmp) / "r", flows, reports, **kw), ctx())


class TestSchema(unittest.TestCase):
    def test_every_event_has_the_central_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = norm(tmp, [NAV], STARTS + [
                report(2, 1, channel="dom", event="read", target="input#password",
                       field={"type": "password", "tag": "input"}),
                report(3, 2, channel="storage", api="localStorage.getItem", key="auth_token"),
                report(2, 3, realm="service_worker", channel="api", api="chrome.tabs.query", args=[]),
            ])
        self.assertTrue(run.events)
        for event in run.events:
            for name in NORMALISED_FIELDS:
                self.assertIn(name, event)

    def test_legacy_trace_is_schema_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = norm(tmp, [NAV], STARTS)
        validate_trace(run.legacy_trace)

    def test_events_share_one_clock(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = norm(tmp, [flow(5, "POST", "http://x.test/", "x.test")], STARTS + [
                report(2, 3.0, channel="dom", event="read", target="document.cookie")])
        times = {e["event_type"]: e["ts"] for e in run.events}
        self.assertLess(times["cookie_read"], times["http_request"])

    def test_duplicate_reports_are_dropped(self):
        duplicate = report(2, 1, channel="dom", event="read", target="document.cookie")
        with tempfile.TemporaryDirectory() as tmp:
            run = norm(tmp, [NAV], STARTS + [duplicate, duplicate])
        self.assertEqual(sum(1 for e in run.events if e["event_type"] == "cookie_read"), 1)
        self.assertEqual(run.coverage["duplicate_reports_dropped"], 1)

    def test_corrupt_evidence_lines_are_counted_not_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = write_run(Path(tmp) / "r", [NAV], STARTS)
            with (root / "gateway" / "flows.jsonl").open("a") as handle:
                handle.write("\n{not json\n")
            run = normalise_run(root, ctx())
        self.assertEqual(run.parse_problems["flows"], 1)


class TestFieldClassification(unittest.TestCase):
    def test_structure_outranks_name(self):
        self.assertEqual(classify_field({"type": "password", "name": "x"}), "password")
        self.assertEqual(classify_field({"type": "text", "autocomplete": "cc-number", "name": "x"}), "payment")
        self.assertEqual(classify_field({"type": "password", "autocomplete": "cc-csc"}), "payment")
        self.assertEqual(classify_field({"type": "hidden", "name": "misc"}), "hidden")

    def test_name_is_the_fallback(self):
        self.assertEqual(classify_field({"type": "text", "name": "user_password"}), "password")
        self.assertEqual(classify_field({"type": "hidden", "name": "csrf_token"}), "auth_token")
        self.assertIsNone(classify_field({"type": "search", "name": "q"}))


class TestAttribution(unittest.TestCase):
    BUNDLE = {"secure-bank.test"}

    def attribute(self, record, report_item=None, driver=None):
        return attribute_flow(record, report=report_item, driver=driver, bundle_hosts=self.BUNDLE,
                              noise_domains=["google.com"])

    def test_self_report_is_confirmed_with_its_realm(self):
        out = self.attribute(flow(1, "POST", "http://x.test/", "x.test"), {"realm": "service_worker"})
        self.assertEqual((out.context, out.confidence), ("service_worker", CONFIRMED))

    def test_extension_origin_header_is_confirmed(self):
        record = flow(1, "POST", "http://x.test/", "x.test", headers={"origin": "chrome-extension://abc"})
        out = self.attribute(record)
        self.assertEqual((out.context, out.confidence), ("extension", CONFIRMED))

    def test_scripted_navigation_within_fixed_web_is_the_page(self):
        out = self.attribute(NAV)
        self.assertEqual((out.context, out.confidence), ("page", CONFIRMED))

    def test_host_outside_fixed_web_with_page_referer_is_inferred_extension_induced(self):
        record = flow(1, "GET", "http://x.test/p.gif", "x.test", headers={"referer": "https://secure-bank.test/"})
        out = self.attribute(record)
        self.assertEqual((out.context, out.confidence), ("extension_induced", INFERRED))

    def test_browser_service_is_only_noise_while_it_carries_no_marker(self):
        quiet = flow(1, "GET", "https://update.google.com/x", "update.google.com")
        self.assertEqual(self.attribute(quiet).context, "browser_internal")
        marked = flow(2, "POST", "https://update.google.com/x", "update.google.com",
                      marker_hits=[{"marker": "password", "kind": "password", "sensitivity": "credential",
                                    "encoding": "plain", "location": "body"}])
        self.assertEqual(self.attribute(marked).context, "unattributed")


class TestSchemeUpgrade(unittest.TestCase):
    def test_a_browser_upgraded_request_is_one_event_not_a_phantom_blocked_attempt(self):
        upgraded = flow(2, "POST", "https://x.test/up", "x.test", body_len=10)
        with tempfile.TemporaryDirectory() as tmp:
            run = norm(tmp, [NAV, upgraded], STARTS + [
                report(2, 1.9, realm="background_page", channel="network", url="http://x.test/up",
                       method="POST", body_len=10)])
        events = [e for e in run.events if e["destination"] == "x.test"]
        self.assertEqual([e["event_type"] for e in events], ["http_request"])
        self.assertEqual(events[0]["source_context"], "background_page")


class TestWebSocketMatching(unittest.TestCase):
    def test_socket_report_matches_its_upgrade_request(self):
        upgrade = flow(2, "GET", "https://x.test/socket", "x.test",
                       response={"status": 101, "source": "websocket"})
        with tempfile.TemporaryDirectory() as tmp:
            run = norm(tmp, [NAV, upgrade], STARTS + [
                report(2, 1.5, realm="service_worker", channel="network", url="wss://x.test/socket",
                       method="WEBSOCKET", resource_type="websocket")])
        kinds = [e["event_type"] for e in run.events if e["destination"] == "x.test"]
        self.assertEqual(kinds, ["websocket_open"])
        opened = next(e for e in run.events if e["event_type"] == "websocket_open")
        self.assertEqual(opened["source_context"], "service_worker")


class TestBlockedAttempts(unittest.TestCase):
    def test_an_upload_blocked_before_the_wire_still_counts_as_an_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = norm(tmp, [NAV], STARTS + [
                report(2, 1.0, channel="dom", event="read", target="input#password",
                       field={"type": "password", "tag": "input"}),
                report(3, 1.5, channel="network", url="http://sink.test/up", method="POST", body_len=40)])
        event = next(e for e in run.events if e["event_type"] == "attempt_not_on_wire")
        self.assertIn("upload", event["risk_indicators"])
        behaviours = behaviours_of(run.events)
        self.assertIn("after_sensitive_read", behaviours["net:unobserved:POST:sink.test"]["tags"])


class TestCoverage(unittest.TestCase):
    def test_full_coverage_is_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(norm(tmp, [NAV], STARTS).coverage["complete"])

    def test_silent_background_is_a_problem_not_a_clean_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = norm(tmp, [NAV], [STARTS[0]])
        self.assertFalse(run.coverage["complete"])
        self.assertTrue(any("background" in p for p in run.coverage["problems"]))

    def test_no_wire_traffic_is_a_problem(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = norm(tmp, [], STARTS)
        self.assertFalse(run.coverage["complete"])
        self.assertEqual(run.coverage["dimensions"]["network"], "failed")

    def test_scripts_that_never_matched_are_noted_not_failed(self):
        manifest = {**MANIFEST, "background": {},
                    "content_scripts": [{"matches": ["https://only.example.test/*"], "js": ["c.js"]}]}
        with tempfile.TemporaryDirectory() as tmp:
            root = write_run(Path(tmp) / "r", [NAV], [])
            run = normalise_run(root, ctx(manifest))
        self.assertTrue(run.coverage["complete"])
        self.assertTrue(any("do not match" in n for n in run.coverage["notes"]))

    def test_lost_reports_are_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = norm(tmp, [NAV], STARTS + [report(9, 1, channel="dom", event="read", target="x")])
        self.assertGreater(run.coverage["reports_lost"], 0)


def behaviours_of(events, manifest=None, bundle=("secure-bank.test",), declared=()):
    return extract_behaviours(events, manifest or MANIFEST, set(bundle), set(declared))


class TestBehavioursAndFeatures(unittest.TestCase):
    def build(self, tmp):
        return norm(tmp, [NAV, flow(3, "POST", "http://evil9-sync.test/up", "evil9-sync.test", body_len=500,
                                    body_entropy=3.0,
                                    marker_hits=[{"marker": "password", "kind": "password", "sensitivity": "credential",
                                                  "encoding": "base64", "location": "body"}])],
                    STARTS + [report(2, 2.0, channel="dom", event="read", target="input#password",
                                     field={"type": "password", "tag": "input"}),
                              report(3, 2.5, channel="network", url="http://evil9-sync.test/up", method="POST")])

    def test_exfil_is_tagged_from_the_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.build(tmp)
        behaviours = behaviours_of(run.events)
        post = behaviours["net:POST:evil9-sync.test/up"]
        self.assertIn("exfil:credential", post["tags"])
        self.assertEqual(post["attribution_confidence"], "confirmed")
        self.assertEqual(post["contexts"], ["content_script"])

    def test_page_login_post_to_its_own_host_is_not_extension_behaviour(self):
        page_post = flow(1, "POST", "https://secure-bank.test/session", "secure-bank.test",
                         headers={"sec-fetch-mode": "navigate"},
                         marker_hits=[{"marker": "bank_password", "kind": "password", "sensitivity": "credential",
                                       "encoding": "plain", "location": "body"}])
        with tempfile.TemporaryDirectory() as tmp:
            run = norm(tmp, [NAV, page_post], STARTS)
        self.assertFalse([b for b in behaviours_of(run.events).values() if b["category"] == "network"])

    def test_cookie_header_on_a_request_is_not_exfiltration(self):
        record = flow(1, "GET", "https://x.test/", "x.test", headers={"referer": "https://secure-bank.test/"},
                      marker_hits=[{"marker": "bank_session", "kind": "session", "sensitivity": "session",
                                    "encoding": "plain", "location": "header:cookie"}])
        with tempfile.TemporaryDirectory() as tmp:
            run = norm(tmp, [NAV, record], STARTS)
        behaviour = behaviours_of(run.events)["net:GET:x.test/"]
        self.assertFalse([t for t in behaviour["tags"] if t.startswith("exfil:")])

    def test_features_cover_the_full_catalogue_and_are_reproducible(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.build(tmp)
        behaviours = behaviours_of(run.events)
        first = extract_features(run.events, behaviours, MANIFEST, {"secure-bank.test"}, set())
        second = extract_features(run.events, behaviours, MANIFEST, {"secure-bank.test"}, set())
        self.assertEqual(tuple(first), FEATURE_ORDER)
        self.assertEqual(feature_digest(first), feature_digest(second))
        self.assertEqual(first["dom_password_field_reads"], 1)
        self.assertEqual(first["exfil_credential_events"], 1)

    def test_beacon_needs_regular_spacing_and_a_real_interval(self):
        def net(ts):
            return {"category": "network", "event_type": "http_request", "source_context": "service_worker",
                    "operation": "POST", "destination": "x.test", "metadata": {"url": "http://x.test/b"},
                    "ts": ts}
        regular = [net(float(t) * 3) for t in range(6)]
        self.assertTrue(detect_beacons(regular))
        burst = [net(t * (BEACON_MIN_INTERVAL_S / 5)) for t in range(6)]
        self.assertFalse(detect_beacons(burst))
        irregular = [net(t) for t in (0.0, 1.0, 9.0, 10.0, 40.0, 41.0)]
        self.assertFalse(detect_beacons(irregular))


class TestDiff(unittest.TestCase):
    def b(self, count=2, **kw):
        return {"count": count, "parameters": kw.get("parameters", []), "signature": kw.get("signature", "s")}

    def test_every_class(self):
        self.assertEqual(classify_behaviour(None, self.b())[0], "new")
        self.assertEqual(classify_behaviour(self.b(), None)[0], "removed")
        self.assertEqual(classify_behaviour(self.b(2), self.b(6))[0], "increased")
        self.assertEqual(classify_behaviour(self.b(6), self.b(2))[0], "decreased")
        self.assertEqual(classify_behaviour(self.b(4), self.b(5))[0], "unchanged")
        changed = classify_behaviour(self.b(2, parameters=["body=small"]),
                                     self.b(2, parameters=["body=small", "marker=password"]))
        self.assertEqual(changed[0], "changed_parameters")
        self.assertIn("marker=password", changed[1]["added_parameters"])

    def test_noise_tolerance_absorbs_a_small_change(self):
        self.assertEqual(classify_behaviour(self.b(2), self.b(6), tolerance=3)[0], "unchanged")

    def test_noise_floor_marks_behaviour_present_in_only_one_baseline_run(self):
        floor = noise_floor({"a": {"count": 2}, "c": {"count": 1}}, {"a": {"count": 3}, "b": {"count": 1}})
        self.assertEqual(floor["tolerance"]["a"], 1)
        self.assertCountEqual(floor["unstable"], ["b", "c"])

    def test_unstable_behaviour_is_excluded_rather_than_called_new(self):
        behaviour = {"signature": "x", "category": "net", "label": "X", "count": 1, "parameters": [],
                     "tags": [], "targets": [], "scenarios": [], "attribution_confidence": "confirmed"}
        comparison = compare_versions({}, {"x": behaviour}, {"f": 0.0}, {"f": 1.0}, {},
                                      {"tolerance": {}, "unstable": ["x"]})
        self.assertEqual(comparison["classes"]["new"], [])
        self.assertEqual(len(comparison["classes"]["unstable"]), 1)
        self.assertEqual(comparison["feature_delta"]["f"], 1.0)


class TestLegacyMeaningUnchanged(unittest.TestCase):
    """The trained model depends on these features. New event kinds must never change them."""

    FIXTURE = Path(__file__).resolve().parent.parent / "data" / "fixtures" / "weaponised_pair"

    def test_extended_events_do_not_move_legacy_features(self):
        trace = json.loads((self.FIXTURE / "v2.trace.json").read_text(encoding="utf-8"))
        before = legacy_features(trace)
        trace = json.loads(json.dumps(trace))
        trace["dom"].append({"ts": 1.0, "event": "read", "target": "input#password", "extended": True})
        trace["storage"].append({"ts": 1.0, "api": "chrome.cookies.getAll", "extended": True})
        trace["api"].append({"ts": 1.0, "api": "chrome.scripting.executeScript", "extended": True})
        trace["network"].append({"ts": 1.0, "url": "http://a.test/", "method": "POST", "initiator": "extension",
                                 "body_len": 999, "extended": True})
        self.assertEqual(legacy_features(trace), before)
        self.assertFalse(any(e.get("extended") for e in legacy_view(trace)["dom"]))

    def test_extended_events_do_not_enter_legacy_evidence(self):
        v1 = json.loads((self.FIXTURE / "v1.trace.json").read_text(encoding="utf-8"))
        v2 = json.loads(json.dumps(v1))
        v2["api"].append({"ts": 1.0, "api": "chrome.alarms.create", "extended": True})
        self.assertEqual(behavioral_delta(v1, v2)["evidence"]["new_apis"], [])

    def test_legacy_traces_can_be_normalised_for_evaluation(self):
        trace = json.loads((self.FIXTURE / "v2.trace.json").read_text(encoding="utf-8"))
        events = events_from_legacy_trace(trace)
        self.assertTrue(any(e["category"] == "network" for e in events))
        for event in events:
            for name in NORMALISED_FIELDS:
                self.assertIn(name, event)


class TestTargetedHosts(unittest.TestCase):
    def test_literal_hosts_from_every_version_are_united_and_ordered(self):
        v1 = {"content_scripts": [{"matches": ["https://b.example.com/*"], "js": ["c.js"]}]}
        v2 = {"host_permissions": ["*://*.a.example.org/*", "<all_urls>", "https://x.test/*"]}
        hosts = targeted_hosts_from_manifests([v1, v2], {"bank.test"}, 8)
        self.assertEqual(hosts, ["b.example.com", "www.a.example.org"])

    def test_the_limit_applies(self):
        manifest = {"host_permissions": [f"https://h{i}.example.com/*" for i in range(20)]}
        self.assertEqual(len(targeted_hosts_from_manifests([manifest], set(), 3)), 3)


if __name__ == "__main__":
    unittest.main()
