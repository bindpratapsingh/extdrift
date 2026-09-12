"""Run one extension version under instrumentation and write a schema-valid trace.

This is the capture half of the pipeline and the only module that needs the heavy stack
(Playwright + a Chromium that can load an unpacked extension), so Playwright is imported
lazily: the rest of ``engine`` must stay importable and testable on a machine that
cannot run a browser at all.

How a run is made deterministic
-------------------------------
* The pages come from :mod:`engine.sandbox.testsite`, an in-process server whose bodies
  are byte-identical on every request, so both versions see the same web.
* ``--host-resolver-rules`` maps every ``.test`` name to that server, so no DNS query
  and no packet leaves the machine - the sandbox's egress control for this stage.
* The extension is instrumented by static prelude injection
  (:mod:`engine.sandbox.rewrite`), which reaches content scripts in the isolated world
  and the MV3 service worker alike.

The instrumentation reports events by POSTing to ``extdrift-report.invalid``; we read
those payloads off the outgoing CDP request event and strip them from the trace, so the
reporting channel never appears as extension behaviour and never actually connects.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from engine.features.schema import empty_trace, validate_trace
from engine.sandbox import scenarios
from engine.sandbox.rewrite import instrument_extension
from engine.sandbox.testsite import COLLECTOR_HOSTS, TestSite

REPORT_HOST = "extdrift-report.invalid"


class CaptureError(RuntimeError):
    """Raised when a run cannot be set up or completed."""


def _require_playwright():
    """Import Playwright with an actionable message when it is not installed."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - depends on the host machine
        raise CaptureError(
            "Playwright is not installed in this environment. The capture stage needs "
            "it (plus a Chromium build); the analysis stage does not. Install with:\n"
            "    pip install playwright && playwright install chromium"
        ) from exc
    return sync_playwright


def _initiator_for(url: str, frame_url: str, extension_origin: str) -> str:
    """Attribute a request to page / extension / service_worker.

    'the page fetched an ad' and 'the extension uploaded your cookies' are the same HTTP
    request until you know who started it, so this attribution matters more than any one
    feature. Frame URL is what Playwright gives us cheaply; the service-worker case is
    caught by the empty frame URL that a worker-originated request carries.
    """
    if extension_origin and extension_origin in (url or ""):
        return "extension"
    if extension_origin and extension_origin in (frame_url or ""):
        return "content_script"
    if not frame_url:
        return "service_worker"
    return "page"


def capture(
    unpacked_dir: str | Path,
    scenario_name: str,
    *,
    out_path: str | Path,
    work_dir: str | Path = ".extdrift-work",
    headless: bool = True,
    replay_bundle: str = "local-testsite-v1",
    noise: bool = False,
) -> dict:
    """Run *unpacked_dir* through *scenario_name* against the local test site.

    Returns the validated trace and also writes it to *out_path*. When *noise* is True the
    test site injects a unique third-party resource per page load (the determinism-ablation
    "noisy web"); leave it False for normal deterministic analysis.
    """
    sync_playwright = _require_playwright()
    scenario = scenarios.get(scenario_name)
    unpacked_dir = Path(unpacked_dir)
    work_dir = Path(work_dir)

    prepared = instrument_extension(unpacked_dir, work_dir / "ext")
    manifest = prepared["manifest"]
    # Chromium resolves --load-extension against its own working directory, not ours, so
    # a relative path silently fails to load the extension. Always pass an absolute one.
    extension_path = str(Path(prepared["path"]).resolve())

    trace = empty_trace(
        ext_id=manifest.get("key_id") or unpacked_dir.parent.name,
        name=manifest.get("name", "unknown"),
        version=manifest.get("version", "0"),
        browser="chromium",
        scenario=scenario.name,
    )
    trace["manifest"] = manifest
    started = time.monotonic()

    def ts() -> float:
        return round(time.monotonic() - started, 3)

    with TestSite(noise=noise) as site:
        trace["run"].update({
            "pages": list(scenario.pages),
            "replay_bundle": (replay_bundle if not noise else "noisy-web-ablation"),
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "instrumentation": {
                "technique": prepared["technique"],
                "instrumented_scripts": prepared["instrumented_scripts"],
                "testsite_port": site.port,
            },
        })

        # Chromium's *old* headless mode cannot load extensions at all; the *new*
        # headless mode can. Playwright's headless=True selects old headless, so we
        # launch with headless=False and add --headless=new ourselves to get a windowless
        # run that still loads the extension.
        launch_args = [
            f"--disable-extensions-except={extension_path}",
            f"--load-extension={extension_path}",
            f"--host-resolver-rules={site.host_resolver_rules}",
            "--no-first-run",
            "--no-default-browser-check",
        ]
        if headless:
            launch_args.insert(0, "--headless=new")

        with sync_playwright() as playwright:
            context = playwright.chromium.launch_persistent_context(
                user_data_dir=str(Path(work_dir / "profile").resolve()),
                headless=False,
                args=launch_args,
            )
            try:
                extension_origin = _wait_for_extension_origin(context)
                _wire_request_capture(context, trace, extension_origin, ts)

                page = context.pages[0] if context.pages else context.new_page()
                _run_steps(page, scenario)
                page.wait_for_timeout(int(scenario.settle_seconds * 1000))
                # Give a service-worker beacon a moment to be emitted after the payload.
                page.wait_for_timeout(500)
            finally:
                trace["run"]["duration_s"] = round(time.monotonic() - started, 2)
                context.close()

        # The fake collector's log is ground truth: it says what actually left the
        # browser, independent of what our instrumentation happened to catch.
        trace["run"]["collector_received"] = list(site.collected)

    for channel in ("network", "dom", "storage", "api"):
        trace[channel].sort(key=lambda event: event.get("ts", 0.0))

    validate_trace(trace, source=str(out_path))
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(trace, indent=2), encoding="utf-8")
    return trace


def _wait_for_extension_origin(context, timeout_ms: int = 5000) -> str:
    """Discover the loaded extension's chrome-extension:// origin.

    The origin is only known once the service worker (MV3) or background page (MV2)
    registers, so we wait for it; without it every request would be mis-attributed to
    the page.
    """
    worker = None
    if context.service_workers:
        worker = context.service_workers[0]
    else:
        try:
            worker = context.wait_for_event("serviceworker", timeout=timeout_ms)
        except Exception:
            worker = None
    if worker:
        return worker.url.rsplit("/", 1)[0] + "/"
    for bg in getattr(context, "background_pages", []):
        return bg.url.rsplit("/", 1)[0] + "/"
    return "chrome-extension://"


def _wire_request_capture(context, trace, extension_origin, ts) -> None:
    """Record every outgoing request, splitting off the instrumentation's own reports."""

    def on_request(request):
        url = request.url
        frame_url = ""
        try:
            frame_url = request.frame.url if request.frame else ""
        except Exception:
            frame_url = ""

        if REPORT_HOST in url:
            _absorb_report(trace, request, ts)
            return

        initiator = _initiator_for(url, frame_url, extension_origin)
        body = request.post_data or ""
        trace["network"].append({
            "ts": ts(),
            "url": url,
            "method": request.method,
            "initiator": initiator,
            "resource_type": request.resource_type,
            "body_len": len(body),
        })

    context.on("request", on_request)


def _absorb_report(trace, request, ts) -> None:
    """Turn one instrumentation report request into a dom/storage/api trace event."""
    raw = request.post_data
    if not raw:
        return
    try:
        event = json.loads(raw)
    except json.JSONDecodeError:
        return
    channel = event.pop("channel", None)
    if channel not in ("dom", "storage", "api"):
        return
    event.setdefault("ts", ts())
    trace[channel].append(event)


def _run_steps(page, scenario) -> None:
    """Execute the scenario's fixed script.

    A missing selector is skipped, not fatal: the page may legitimately not have the
    element, and aborting would throw away the whole trace over one click. Both versions
    get the same sequence of attempts either way.
    """
    for step in scenario.steps:
        if step.action == "goto":
            page.goto(step.value, wait_until="load")
        elif step.action == "wait":
            page.wait_for_timeout(int(step.seconds * 1000))
        elif step.action == "scroll":
            page.mouse.wheel(0, 2000)
            page.wait_for_timeout(int(step.seconds * 1000))
        elif step.action in ("fill", "click"):
            try:
                element = page.wait_for_selector(step.selector, timeout=3000)
            except Exception:
                continue
            if step.action == "fill":
                element.fill(step.value or "")
            else:
                element.click()
        else:
            raise CaptureError(f"unknown scenario step action: {step.action!r}")
