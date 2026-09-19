"""Capture a Firefox extension's behaviour into the SAME trace schema as the Chromium run.

This is the second capture engine. Its whole reason to exist is that the AMO collector
gives us real Firefox update pairs (full version history + direct .xpi), so a Firefox
capture turns that real code into real *behavioural* deltas that drop straight into the
same dataset the Chromium/synthetic rows use — one feature space, one model.

Why it is built differently from the Chromium engine
----------------------------------------------------
Playwright + Chromium gave us three things this engine has to reproduce another way:
  * a fixed web and sealed egress — here via :class:`engine.sandbox.proxy.CaptureProxy`
    (Firefox has no ``--host-resolver-rules``);
  * a way to read the instrumentation's reports — Selenium cannot read request bodies, so
    the prelude self-reports over the proxy (dom/storage/api/network channels);
  * loading an unsigned, instrumented build — Firefox refuses that except as a *temporary*
    add-on, which is exactly what ``driver.install_addon(path, temporary=True)`` installs.

Everything the browser does *not* need (instrumentation, the proxy, trace assembly) is in
plain modules that this file drives, so the browser-specific surface stays small.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from engine.features.schema import empty_trace, validate_trace
from engine.sandbox import scenarios
from engine.sandbox.proxy import REPORT_HOST, CaptureProxy
from engine.sandbox.rewrite import instrument_extension

#: Hosts the instrumented extension must be allowed to reach for reporting + the test web,
#: added to the manifest so content-script reports are not blocked by cross-origin rules.
_CAPTURE_HOSTS = [f"http://{REPORT_HOST}/*", "http://*.test/*", "https://*.test/*"]

#: Firefox prefs that quiet the browser's own background traffic, so the trace and the
#: proxy's blackhole log reflect the extension, not Firefox telemetry / update / captive
#: portal / safe-browsing chatter.
_QUIET_PREFS = {
    "toolkit.telemetry.enabled": False,
    "datareporting.healthreport.uploadEnabled": False,
    "datareporting.policy.dataSubmissionEnabled": False,
    "app.update.enabled": False,
    "app.update.auto": False,
    "extensions.update.enabled": False,
    "browser.safebrowsing.malware.enabled": False,
    "browser.safebrowsing.phishing.enabled": False,
    "network.captive-portal-service.enabled": False,
    "network.connectivity-service.enabled": False,
    "browser.newtabpage.enabled": False,
    "browser.startup.homepage": "about:blank",
    "extensions.webextensions.restrictedDomains": "",
}


class FirefoxCaptureError(RuntimeError):
    """Raised when a Firefox capture cannot be set up or completed."""


def _require_selenium():
    try:
        from selenium import webdriver
        from selenium.webdriver.firefox.options import Options
        return webdriver, Options
    except ImportError as exc:  # pragma: no cover - depends on the host machine
        raise FirefoxCaptureError(
            "Selenium is not installed. The Firefox capture stage needs it (plus a Firefox "
            "binary; Selenium Manager fetches geckodriver automatically). Install with:\n"
            "    pip install selenium   # and install Firefox"
        ) from exc


def _patch_manifest_for_capture(ext_dir: Path) -> dict:
    """Grant the instrumented copy the host access its reports need, and relax CSP.

    Only the *analysed copy* is touched (rewrite.py already worked on a scratch copy), and
    the change travels in the trace so it is never hidden. Without this, Firefox can block a
    content script's report to the proxy as a disallowed cross-origin request.
    """
    manifest_path = ext_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    mv = manifest.get("manifest_version", 2)

    if mv >= 3:
        hosts = set(manifest.get("host_permissions", []) or [])
        hosts.update(_CAPTURE_HOSTS)
        manifest["host_permissions"] = sorted(hosts)
    else:
        perms = list(manifest.get("permissions", []) or [])
        for h in _CAPTURE_HOSTS:
            if h not in perms:
                perms.append(h)
        manifest["permissions"] = perms

    # A strict extension CSP can forbid the prelude's connect; widen connect-src only.
    csp = manifest.get("content_security_policy")
    if isinstance(csp, str) and "connect-src" in csp:
        manifest["content_security_policy"] = csp.replace(
            "connect-src", f"connect-src http://{REPORT_HOST} http://*.test https://*.test")

    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def _run_steps(driver, scenario) -> None:
    """Execute the scenario's fixed script through Selenium (mirrors the Chromium runner)."""
    from selenium.webdriver.common.by import By
    from engine.sandbox.scenarios import EVENT_FUZZING_JS
    for step in scenario.steps:
        if step.action == "goto":
            driver.get(step.value)
        elif step.action == "wait":
            time.sleep(step.seconds)
        elif step.action == "fire_events":
            try:
                driver.execute_script(EVENT_FUZZING_JS)   # Hulk-style event-handler fuzzing
            except Exception:
                pass
        elif step.action == "scroll":
            driver.execute_script("window.scrollBy(0, 2000);")
            time.sleep(step.seconds)
        elif step.action in ("fill", "click"):
            try:
                el = driver.find_element(By.CSS_SELECTOR, step.selector)
            except Exception:
                continue          # a missing selector is skipped, not fatal (same as Chromium)
            if step.action == "fill":
                el.clear(); el.send_keys(step.value or "")
            else:
                el.click()
        else:
            raise FirefoxCaptureError(f"unknown scenario step action: {step.action!r}")


def capture_firefox(
    unpacked_dir: str | Path,
    scenario_name: str,
    *,
    out_path: str | Path,
    work_dir: str | Path = ".extdrift-work-ff",
    headless: bool = True,
    replay_bundle: str = "local-proxy-v1",
) -> dict:
    """Run *unpacked_dir* (an unpacked .xpi) through *scenario_name* and write a trace."""
    webdriver, Options = _require_selenium()
    scenario = scenarios.get(scenario_name)
    unpacked_dir, work_dir = Path(unpacked_dir), Path(work_dir)

    prepared = instrument_extension(unpacked_dir, work_dir / "ext")
    ext_path = Path(prepared["path"]).resolve()
    manifest = _patch_manifest_for_capture(ext_path)

    trace = empty_trace(
        ext_id=(manifest.get("browser_specific_settings", {}) or {}).get("gecko", {}).get("id")
        or manifest.get("applications", {}).get("gecko", {}).get("id")
        or unpacked_dir.parent.name,
        name=manifest.get("name", "unknown"),
        version=manifest.get("version", "0"),
        browser="firefox",
        scenario=scenario.name,
    )
    trace["manifest"] = manifest
    started = time.monotonic()

    with CaptureProxy() as proxy:
        options = Options()
        if headless:
            options.add_argument("-headless")
        options.set_preference("network.proxy.type", 1)
        options.set_preference("network.proxy.http", "127.0.0.1")
        options.set_preference("network.proxy.http_port", proxy.port)
        options.set_preference("network.proxy.ssl", "127.0.0.1")
        options.set_preference("network.proxy.ssl_port", proxy.port)
        options.set_preference("network.proxy.allow_hijacking_localhost", True)
        options.set_preference("network.proxy.no_proxies_on", "")
        for key, value in _QUIET_PREFS.items():
            options.set_preference(key, value)

        trace["run"].update({
            "pages": list(scenario.pages),
            "replay_bundle": replay_bundle,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "instrumentation": {
                "technique": prepared["technique"],
                "instrumented_scripts": prepared["instrumented_scripts"],
                "proxy_port": proxy.port,
                "manifest_patched_for_capture": True,
            },
        })

        driver = webdriver.Firefox(options=options)
        try:
            driver.install_addon(str(ext_path), temporary=True)
            time.sleep(1.0)                                   # let the add-on initialise
            _run_steps(driver, scenario)
            time.sleep(scenario.settle_seconds + 0.5)
        finally:
            trace["run"]["duration_s"] = round(time.monotonic() - started, 2)
            try:
                driver.quit()
            except Exception:
                pass

        for channel in ("network", "dom", "storage", "api"):
            trace[channel].extend(proxy.channels[channel])
        trace["run"]["collector_received"] = list(proxy.collected)
        trace["run"]["blocked_egress"] = list(proxy.blocked)

    for channel in ("network", "dom", "storage", "api"):
        trace[channel].sort(key=lambda event: event.get("ts", 0.0))

    validate_trace(trace, source=str(out_path))
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(trace, indent=2), encoding="utf-8")
    return trace
