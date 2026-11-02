"""The complete pipeline: packages in, one report out.

    validate -> sandbox -> load -> scenarios -> capture -> normalise -> features -> diff
             -> rule score -> ML -> combined assessment -> report -> cleanup

Every failure ends in a report with an Inconclusive verdict and an explicit reason. Nothing in this
file can turn a failure into a low score, because scoring only runs on a run that completed, and a
run with incomplete coverage can only report what it positively observed.
"""

from __future__ import annotations

import json
import secrets
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from engine.features.behaviour import (
    extract_behaviours,
    extract_features,
    feature_digest,
)
from engine.features.behaviour_diff import compare_versions, noise_floor
from engine.features.delta import behavioral_delta
from engine.ml.inference import predict_slices
from engine.pipeline.config import load_risk_config, load_sandbox_config
from engine.pipeline.states import AnalysisFailure, State, StateTracker, utc_now
from engine.pipeline.validation import PackageInfo, ValidationError, validate_package
from engine.report import security_report
from engine.sandbox import docker_manager
from engine.sandbox.markers import redact
from engine.sandbox.normalise import (
    NormalisedRun,
    RunContext,
    declared_hosts,
    normalise_run,
    slice_legacy_trace,
    targeted_hosts_from_manifests,
)
from engine.sandbox.replay import builtin_bundle, load_bundle
from engine.sandbox.scenarios import DEFAULT_SUITE
from engine.scoring.combined import combine
from engine.scoring.risk import behaviours_to_score, score_behaviours, verdict_for
from engine.scoring.rules import score_delta
from engine.unpack.manifest import diff_manifests

_RUNNER_EXIT_MEANING = {
    3: ("preflight", "the isolation checks failed inside the browser container"),
    4: ("gateway", "the monitoring gateway never became reachable"),
    5: ("instrumentation", "the extension could not be instrumented"),
    6: ("extension_loading", "the browser refused to load the extension"),
    7: ("execution", "the browser run crashed"),
}
_STATE_FROM_RUNNER = {"SANDBOX_CHECK": State.SANDBOX_INITIALISING,
                      "EXTENSION_LOADING": State.EXTENSION_LOADING,
                      "EXECUTING": State.EXECUTING, "CAPTURING": State.CAPTURING}

DETERMINISM_NOTES = [
    "Both versions received the same bundle of pages, proven by its content hash, and the same "
    "scripted actions in the same order. Timing and event ordering inside the browser are not "
    "controlled, so small count differences can occur between otherwise identical runs.",
]


@dataclass
class VersionResult:
    role: str
    info: PackageInfo
    run: NormalisedRun
    outcome: docker_manager.RunOutcome
    behaviours: dict[str, dict]
    features: dict[str, float]
    summary: dict = field(default_factory=dict)

    def view(self) -> dict:
        return {
            "summary": self.summary, "coverage": self.run.coverage, "features": self.features,
            "feature_digest": feature_digest(self.features),
            "browser_version": self.run.run_info.get("browser_version"),
        }


class AnalysisPipeline:
    """Runs one analysis. Create one object per analysis."""

    def __init__(self, *, browser: str = "chromium", scenarios: list[str] | None = None,
                 out_root: str | Path = "out/analyses", progress=None, analysis_id: str | None = None,
                 aa_check: bool = False, bundle_file: str | Path | None = None,
                 sandbox_config: dict | None = None, risk_config: dict | None = None):
        self.config = sandbox_config or load_sandbox_config()
        self.risk_config = risk_config or load_risk_config()
        self.browser = browser
        self.requested_scenarios = list(scenarios) if scenarios else None
        self.analysis_id = analysis_id or (time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3))
        self.out_dir = Path(out_root) / self.analysis_id
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.tracker = StateTracker(self.analysis_id, self.out_dir, progress=progress)
        self.aa_check = aa_check
        self.bundle_file = Path(bundle_file) if bundle_file else None
        self.hash_salt = secrets.token_hex(16)
        self.started_at = utc_now()
        self.started_clock = time.monotonic()
        self.work = Path(tempfile.mkdtemp(prefix="extdrift-unpack-"))
        self.environment: dict = {}
        self.scenarios: list[str] = []
        self.targeted_hosts: list[str] = []
        self.replay_urls: list[str] = []
        self.isolation_checks: dict = {}

    # -- public entry points ----------------------------------------------------------------

    def analyse(self, package: str | Path) -> dict:
        """Mode A: one extension in isolation."""
        analysis = self._new_analysis("single")
        try:
            info = self._validate(package, "candidate")
            analysis.update(candidate_meta=info.metadata, validation_warnings=info.warnings)
            self._plan_scenarios([info.manifest])
            analysis["scenarios"] = self.scenarios
            result = self._run_version("candidate", info)
            self.tracker.advance(State.SCORING)
            risk = score_behaviours(list(result.behaviours.values()), self.risk_config,
                                    manifest=info.manifest, manifest_features=result.features)
            risk["scored_input"] = "every behaviour observed in this version"
            result.summary = security_report.runtime_summary(result.run.events, result.behaviours, risk["findings"])
            analysis.update(candidate=result.view(), risk=risk,
                            ml={"status": "not_applicable",
                                "reason": "the classifier scores the change between two versions, "
                                          "so it does not apply to a single version"})
            analysis["combined"] = {"rule_score": risk["score"], "combined_score": risk["score"],
                                    "rule_applied": "rules_only", "agreement": "not_applicable",
                                    "classification": risk["classification"],
                                    "explanation": "Single-version analysis uses the rule score alone."}
            complete = result.run.coverage["complete"]
            analysis["verdict"] = verdict_for(risk["score"], risk["risk_indicators_fired"],
                                              config=self.risk_config, complete=complete)
            self._attach_run_facts(analysis, [result])
            return self._finish(analysis)
        except (AnalysisFailure, ValidationError, docker_manager.DockerError) as failure:
            return self._fail(analysis, failure)
        finally:
            self._cleanup()

    def compare(self, baseline: str | Path, candidate: str | Path) -> dict:
        """Mode B: was anything in the candidate update newly dangerous?"""
        analysis = self._new_analysis("compare")
        try:
            base_info = self._validate(baseline, "baseline")
            cand_info = self._validate(candidate, "candidate")
            analysis.update(baseline_meta=base_info.metadata, candidate_meta=cand_info.metadata,
                            validation_warnings=base_info.warnings + cand_info.warnings,
                            manifest_diff=diff_manifests(base_info.manifest, cand_info.manifest))
            self._plan_scenarios([base_info.manifest, cand_info.manifest])
            analysis["scenarios"] = self.scenarios

            base = self._run_version("baseline", base_info)
            noise = None
            if self.aa_check:
                repeat = self._run_version("baseline-repeat", base_info)
                noise = noise_floor(base.behaviours, repeat.behaviours)
                self.tracker.log("noise floor measured", tolerance=len(noise["tolerance"]),
                                 unstable=len(noise["unstable"]))
            cand = self._run_version("candidate", cand_info)

            self.tracker.advance(State.ANALYSING, detail="comparing versions")
            comparison = compare_versions(base.behaviours, cand.behaviours, base.features,
                                          cand.features, analysis["manifest_diff"], noise)
            self._write_json("diff.json", comparison)

            self.tracker.advance(State.SCORING)
            risk = score_behaviours(behaviours_to_score(comparison), self.risk_config,
                                    manifest=cand_info.manifest, manifest_diff=analysis["manifest_diff"])
            risk["scored_input"] = "behaviours the update introduced, increased or changed"
            baseline_risk = score_behaviours(list(base.behaviours.values()), self.risk_config,
                                             manifest=base_info.manifest, manifest_features=base.features)
            base.summary = security_report.runtime_summary(base.run.events, base.behaviours, baseline_risk["findings"])
            cand.summary = security_report.runtime_summary(cand.run.events, cand.behaviours, risk["findings"])

            legacy = behavioral_delta(base.run.legacy_trace, cand.run.legacy_trace)
            ml = predict_slices(base.run.legacy_trace, cand.run.legacy_trace,
                                self._scenario_slices(base, cand))
            combined = combine(risk["score"], risk["direct_evidence"], ml, self.risk_config)
            comparability = self._comparability(base, cand)

            analysis.update(
                baseline=base.view(), candidate=cand.view(), comparison=comparison, risk=risk,
                ml=ml, combined=combined, comparability=comparability,
                baseline_risk={k: baseline_risk[k] for k in ("score", "classification", "explanation")},
                legacy_rules=score_delta(legacy), legacy_delta=legacy["numeric"],
            )
            complete = (cand.run.coverage["complete"] and base.run.coverage["complete"]
                        and not comparability["problems"])
            if base.run.coverage["complete"]:
                analysis["verdict"] = verdict_for(combined["combined_score"], risk["risk_indicators_fired"],
                                                  config=self.risk_config, complete=complete)
            else:
                # Without a trustworthy baseline, "new" cannot be told apart from "unseen before".
                analysis["verdict"] = "Inconclusive analysis"
            self._attach_run_facts(analysis, [base, cand])
            return self._finish(analysis)
        except (AnalysisFailure, ValidationError, docker_manager.DockerError) as failure:
            return self._fail(analysis, failure)
        finally:
            self._cleanup()

    # -- stages -----------------------------------------------------------------------------

    def _new_analysis(self, mode: str) -> dict:
        return {"mode": mode, "analysis_id": self.analysis_id, "browser": self.browser,
                "started_at": self.started_at, "status": "RUNNING", "verdict": "Inconclusive analysis"}

    def _validate(self, package: str | Path, role: str) -> PackageInfo:
        self.tracker.advance(State.VALIDATING, version=role)
        browsers = self.config["browsers"]
        entry = browsers.get(self.browser)
        if entry is None or not entry.get("supported"):
            reason = entry["note"] if entry else f"{self.browser!r} is not a known browser"
            raise AnalysisFailure("validation", f"Browser {self.browser!r} is not supported: {reason}")
        try:
            info = validate_package(package, self.work / role)
        except ValidationError as error:
            raise AnalysisFailure("validation", f"{role} package rejected",
                                  details={"problems": error.problems}) from error
        self._write_json(f"{role}.metadata.json", info.metadata)
        self.tracker.log("validated", version=role, name=info.metadata["name"], extension_version=info.metadata["version"])
        return info

    def _plan_scenarios(self, manifests: list[dict]) -> None:
        """Fix the scenario list once, from all versions, so each run is given the same one."""
        if self.bundle_file:
            bundle = load_bundle(self.bundle_file)
            self.replay_urls = list(bundle.entry_urls)
            self.scenarios = ["replay-browse"]
            bundle_hosts = bundle.hosts
        else:
            bundle_hosts = builtin_bundle().hosts
            self.scenarios = list(self.requested_scenarios or DEFAULT_SUITE)
        settings = self.config["scenarios"]
        self.targeted_hosts = targeted_hosts_from_manifests(
            manifests, bundle_hosts, settings["targeted_host_limit"],
            extra=settings.get("extra_targeted_hosts"))
        if self.targeted_hosts and not self.bundle_file and not self.requested_scenarios:
            self.scenarios.append("manifest-targeted")

    def _run_version(self, role: str, info: PackageInfo) -> VersionResult:
        tracker = self.tracker
        tracker.advance(State.SANDBOX_INITIALISING, version=role)
        version_dir = self.out_dir / role
        raw_dir = version_dir / "raw"
        job = {
            "browser": self.browser, "scenarios": self.scenarios,
            "targeted_hosts": self.targeted_hosts, "replay_urls": self.replay_urls,
            "navigation_timeout_ms": self.config["scenarios"]["navigation_timeout_ms"],
            "chromium_sandbox": True,
        }
        last = {"state": None}

        def on_state(name: str) -> None:
            state = _STATE_FROM_RUNNER.get(name)
            if state and state != last["state"] and state != State.SANDBOX_INITIALISING:
                last["state"] = state
                tracker.advance(state, version=role)

        # The salt goes only to the gateway, which the extension's container cannot read.
        gateway_env = {"EXTDRIFT_TARGETED_HOSTS": json.dumps(self.targeted_hosts),
                       "EXTDRIFT_HASH_SALT": self.hash_salt}
        name = f"extdrift-{self.analysis_id.lower()}-{role}"
        with docker_manager.SandboxRun(
                name, self.config, browser=self.browser, job=job, extension_dir=info.directory,
                raw_dir=raw_dir, gateway_env=gateway_env, bundle_file=self.bundle_file,
                on_state=on_state) as sandbox:
            outcome = sandbox.execute()
        tracker.log("sandbox finished", version=role, exit_code=outcome.exit_code,
                    timed_out=outcome.timed_out, collected=outcome.collect_notes)
        self.environment.setdefault(role, outcome.environment)

        ctx = RunContext(
            analysis_id=self.analysis_id, extension_id=info.metadata["extension_id"],
            extension_version=info.metadata["version"], browser=self.browser, manifest=info.manifest,
            noise_domains=self.config["attribution"]["browser_noise_domains"],
            report_window=self.config["attribution"]["report_match_window_seconds"])

        if outcome.timed_out:
            raise AnalysisFailure("execution", f"{role}: the browser run exceeded the "
                                  f"{self.config['limits']['run_timeout_seconds']} second limit and was killed")
        run_file = raw_dir / "browser" / "run.json"
        if not run_file.exists():
            raise AnalysisFailure("execution", f"{role}: the browser container produced no result "
                                  f"(exit code {outcome.exit_code})",
                                  details={"log_tail": redact(outcome.logs.get("browser", ""))[-1500:]})
        self._check_isolation(raw_dir, role)
        if outcome.exit_code != 0:
            run_info = json.loads(run_file.read_text(encoding="utf-8"))
            stage, meaning = _RUNNER_EXIT_MEANING.get(
                outcome.exit_code, ("execution", f"the browser container exited with code {outcome.exit_code}"))
            raise AnalysisFailure(stage, f"{role}: {meaning}", details={
                "problems": [redact(str(run_info.get("error", "no further detail")))],
                "browser_status": {k: run_info.get(k) for k in ("stage", "status", "extension_status")}})

        tracker.advance(State.ANALYSING, version=role, detail="normalising the trace")
        run = normalise_run(raw_dir, ctx)
        sandbox_state = run.run_info.get("browser_sandbox") or {}
        if sandbox_state.get("adequate") is False and not self.config["security"]["allow_degraded_browser_sandbox"]:
            raise AnalysisFailure("sandbox", f"{role}: the browser's own process sandbox did not start",
                                  details={"problems": [str(sandbox_state.get("summary"))]})

        bundle_hosts = set(run.bundle.get("hosts") or [])
        declared = declared_hosts(info.manifest)
        behaviours = extract_behaviours(run.events, info.manifest, bundle_hosts, declared)
        features = extract_features(run.events, behaviours, info.manifest, bundle_hosts, declared)
        result = VersionResult(role, info, run, outcome, behaviours, features)
        self._write_version_artefacts(version_dir, result)
        return result

    def _check_isolation(self, raw_dir: Path, role: str) -> None:
        checks = {}
        for name, path in (("browser", raw_dir / "browser" / "preflight.json"),
                           ("gateway", raw_dir / "gateway" / "preflight.json")):
            try:
                checks[name] = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                raise AnalysisFailure("preflight", f"{role}: no isolation evidence from the {name} container") from None
        self.isolation_checks[role] = checks
        failed = [f"{name}: {c['name']} ({c['detail']})" for name, check in checks.items()
                  for c in check.get("checks", []) if not c["passed"]]
        if failed:
            raise AnalysisFailure("preflight", f"{role}: isolation checks failed, so the run was not scored",
                                  details={"problems": failed})

    def _write_version_artefacts(self, version_dir: Path, result: VersionResult) -> None:
        run = result.run
        with (version_dir / "trace.normalised.jsonl").open("w", encoding="utf-8") as handle:
            for event in run.events:
                handle.write(redact(json.dumps(event, sort_keys=True)) + "\n")
        (version_dir / "trace.json").write_text(redact(json.dumps(run.legacy_trace, indent=1)), encoding="utf-8")
        with (version_dir / "behaviour.log").open("w", encoding="utf-8") as handle:
            for event in run.events:
                destination = f" -> {event['destination']}" if event.get("destination") else ""
                tags = f" [{','.join(event['risk_indicators'])}]" if event["risk_indicators"] else ""
                handle.write(redact(
                    f"{event['ts']:9.3f} {event['scenario']:<24} {event['category']:<8} "
                    f"{event['event_type']:<20} {event['source_context']:<20} "
                    f"{event['attribution_confidence']:<10} {event['operation']}{destination}{tags}") + "\n")
        (version_dir / "behaviours.json").write_text(redact(json.dumps(result.behaviours, indent=1)), encoding="utf-8")
        (version_dir / "features.json").write_text(json.dumps({
            "features": result.features, "digest": feature_digest(result.features),
            "legacy_features_are_in": "trace.json, computed by engine.features.extract",
        }, indent=1), encoding="utf-8")
        (version_dir / "coverage.json").write_text(json.dumps(run.coverage, indent=1), encoding="utf-8")

    def _scenario_slices(self, base: VersionResult, cand: VersionResult) -> list[dict]:
        slices = []
        pages = {s["name"]: s.get("pages", []) for s in cand.run.run_info.get("scenarios", [])}
        done = lambda r: {s["name"] for s in r.run.run_info.get("scenarios", []) if s.get("status") == "completed"}
        for scenario in self.scenarios:
            if scenario in done(base) and scenario in done(cand):
                slices.append({
                    "scenario": scenario,
                    "baseline": slice_legacy_trace(base.run.legacy_trace, base.run.events, scenario, pages.get(scenario, [])),
                    "candidate": slice_legacy_trace(cand.run.legacy_trace, cand.run.events, scenario, pages.get(scenario, [])),
                })
        return slices

    def _comparability(self, base: VersionResult, cand: VersionResult) -> dict:
        """Were the two runs truly under the same conditions? Differences are reported, not hidden."""
        problems: list[str] = []
        if base.run.bundle.get("digest") != cand.run.bundle.get("digest"):
            problems.append("the two versions received different page bundles")
        if base.outcome.environment.get("sandbox_image") != cand.outcome.environment.get("sandbox_image"):
            problems.append("the two runs used different sandbox images")
        if base.run.run_info.get("browser_version") != cand.run.run_info.get("browser_version"):
            problems.append("the two runs used different browser versions")
        names = lambda r: [s.get("name") for s in r.run.run_info.get("scenarios", [])]
        if names(base) != names(cand):
            problems.append("the two runs executed different scenarios")
        status = lambda r: {s.get("name"): s.get("status") for s in r.run.run_info.get("scenarios", [])}
        if status(base) != status(cand):
            problems.append("a scenario completed in one run but not in the other")
        notes: list[str] = []
        if base.info.metadata["extension_id"] != cand.info.metadata["extension_id"] and \
                "derived" not in base.info.metadata["extension_id_source"]:
            notes.append("the two packages carry different extension identifiers")
        if base.info.metadata["name"] != cand.info.metadata["name"]:
            notes.append("the two packages have different names")
        if base.info.metadata["version"] == cand.info.metadata["version"]:
            notes.append("both packages declare the same version number")
        page_a, page_b = sorted(set(base.run.page_traffic)), sorted(set(cand.run.page_traffic))
        only_base = sorted(set(page_a) - set(page_b))
        only_cand = sorted(set(page_b) - set(page_a))
        if only_base or only_cand:
            notes.append(f"page traffic differed slightly ({len(only_base)} requests only in the "
                         f"baseline, {len(only_cand)} only in the candidate)")
        return {"problems": problems, "notes": notes,
                "bundle_digest": cand.run.bundle.get("digest"),
                "page_requests_only_in_baseline": only_base[:10],
                "page_requests_only_in_candidate": only_cand[:10]}

    def _attach_run_facts(self, analysis: dict, results: list[VersionResult]) -> None:
        analysis["isolation"] = {"checks": self.isolation_checks.get("candidate") or
                                 self.isolation_checks.get("baseline"),
                                 "hardening": (self.environment.get("candidate") or {}).get("hardening"),
                                 "browser_process_sandbox": results[-1].run.run_info.get("browser_sandbox"),
                                 "instrumentation": results[-1].run.run_info.get("instrumentation")}
        analysis["reproducibility"] = {
            "scenarios": self.scenarios, "targeted_hosts": self.targeted_hosts,
            "bundle": results[-1].run.bundle,
            "images": {k: self.environment.get("candidate", {}).get(k) for k in ("sandbox_image", "gateway_image")},
            "docker_server_version": self.environment.get("candidate", {}).get("docker_server_version"),
            "browser_version": results[-1].run.run_info.get("browser_version"),
            "determinism_notes": DETERMINISM_NOTES + (
                ["A second run of the baseline measured the noise floor, and behaviours that varied "
                 "between those runs were excluded from scoring."] if self.aa_check else
                ["No second baseline run was made, so run-to-run noise was not measured for this "
                 "analysis. Use --aa-check to measure it."]),
        }

    # -- ending -----------------------------------------------------------------------------

    def _write_json(self, name: str, payload: object) -> None:
        (self.out_dir / name).write_text(redact(json.dumps(payload, indent=1, default=str)), encoding="utf-8")

    def _finish(self, analysis: dict) -> dict:
        self.tracker.advance(State.REPORT_GENERATION)
        analysis["status"] = State.COMPLETED.value
        report = self._write_report(analysis)
        self.tracker.advance(State.COMPLETED, detail=analysis["verdict"])
        return report

    def _fail(self, analysis: dict, failure: Exception) -> dict:
        if isinstance(failure, AnalysisFailure):
            stage, reason, details = failure.stage, failure.reason, failure.details
        elif isinstance(failure, ValidationError):
            stage, reason, details = "validation", str(failure), {"problems": failure.problems}
        else:
            stage, reason, details = "sandbox", str(failure), {}
        analysis.update(status=State.FAILED.value, verdict="Inconclusive analysis",
                        failure={"stage": stage, "reason": redact(reason), "details": details})
        if self.isolation_checks:
            checks = self.isolation_checks.get("candidate") or self.isolation_checks.get("baseline")
            analysis["isolation"] = {"checks": checks}
        self.tracker.log("analysis failed", stage=stage, reason=reason)
        self.tracker.advance(State.REPORT_GENERATION, detail="failure report")
        report = self._write_report(analysis)
        self.tracker.advance(State.FAILED, detail=f"{stage}: {reason}")
        return report

    def _write_report(self, analysis: dict) -> dict:
        analysis["duration_s"] = round(time.monotonic() - self.started_clock, 1)
        analysis["artefacts"] = {"directory": str(self.out_dir)}
        report = security_report.build_report(analysis)
        (self.out_dir / "report.json").write_text(security_report.render_json(report), encoding="utf-8")
        (self.out_dir / "report.md").write_text(security_report.render_markdown(report), encoding="utf-8")
        (self.out_dir / "report.html").write_text(security_report.render_html(report), encoding="utf-8")
        return report

    def _cleanup(self) -> None:
        shutil.rmtree(self.work, ignore_errors=True)
        self.tracker.close()
