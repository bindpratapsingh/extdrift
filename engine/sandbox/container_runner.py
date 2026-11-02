"""The program that runs inside the browser container.

Input arrives on a read-only volume: ``/input/job.json`` and the unpacked extension in
``/input/ext``. It proves the isolation (preflight), instruments a scratch copy of the extension,
launches the browser, runs the scenarios, and writes its own view to ``/output``. It never decides
anything about the extension: the authoritative network record is in the gateway container, out of
this container's reach, and this container's output is treated as untrusted by the host.

Exit codes tell the host which stage failed. Progress lines on stdout are drive pipeline states.
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback
import urllib.request
from pathlib import Path

from engine.sandbox import preflight, scenarios
from engine.sandbox.markers import redact
from engine.sandbox.rewrite import instrument_extension

EXIT_OK = 0
EXIT_PREFLIGHT = 3
EXIT_GATEWAY = 4
EXIT_INSTRUMENT = 5
EXIT_LOAD = 6
EXIT_EXECUTION = 7

INPUT = Path("/input")
OUTPUT = Path("/output")
WORK = Path("/tmp/work")
CONTROL_HOST = "extdrift-control.test"
REPORT_HOST = "extdrift-report.test"
GECKODRIVER = "/usr/local/bin/geckodriver"
FIREFOX = "/usr/bin/firefox-esr"


class RunFailure(RuntimeError):
    def __init__(self, code: int, stage: str, message: str):
        super().__init__(message)
        self.code, self.stage = code, stage


def state(name: str) -> None:
    print(f"EXTDRIFT_STATE {name}", flush=True)


def write_json(name: str, payload: dict) -> None:
    (OUTPUT / name).write_text(json.dumps(payload, indent=2), encoding="utf-8")


class Control:
    """Messages to the gateway. Carries a token the extension's JavaScript has no way to read."""

    def __init__(self, gateway: str, token: str):
        self.base = f"http://{CONTROL_HOST}/{token}"
        proxy = urllib.request.ProxyHandler({"http": f"http://{gateway}"})
        self.opener = urllib.request.build_opener(proxy)

    def send(self, *parts: str, timeout: float = 5.0) -> dict:
        url = "/".join((self.base, *parts))
        with self.opener.open(url, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def wait_ready(self, deadline_s: float) -> dict:
        end = time.monotonic() + deadline_s
        last = None
        while time.monotonic() < end:
            try:
                return self.send("health")
            except Exception as exc:  # noqa: BLE001 - the gateway may still be starting
                last = exc
                time.sleep(0.5)
        raise RunFailure(EXIT_GATEWAY, "gateway", f"gateway never answered: {last}")


def patch_manifest_for_capture(ext_dir: Path, browser: str) -> list[str]:
    """Make the minimum manifest change that lets reports leave, and list what changed.

    Only the reporting host is ever added. A Content-Security-Policy with a ``connect-src`` would
    otherwise silently block every report from extension pages. No API permission and no site
    access is ever granted to the sample.
    """
    path = ext_dir / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    changes: list[str] = []
    allow = f"http://{REPORT_HOST} https://{REPORT_HOST}"

    def widen(csp: str) -> str:
        return csp.replace("connect-src", f"connect-src {allow}") if "connect-src" in csp else csp

    csp = manifest.get("content_security_policy")
    if isinstance(csp, str) and "connect-src" in csp:
        manifest["content_security_policy"] = widen(csp)
        changes.append("content_security_policy: added the report host to connect-src")
    elif isinstance(csp, dict):
        for key, value in list(csp.items()):
            if isinstance(value, str) and "connect-src" in value:
                csp[key] = widen(value)
                changes.append(f"content_security_policy.{key}: added the report host to connect-src")

    if browser == "firefox":
        # Firefox drops cross-origin requests from content scripts lacking host access.
        pattern = f"*://{REPORT_HOST}/*"
        key = "host_permissions" if manifest.get("manifest_version", 2) >= 3 else "permissions"
        entries = list(manifest.get(key, []) or [])
        if pattern not in entries:
            entries.append(pattern)
            manifest[key] = entries
            changes.append(f"{key}: added {pattern} (reporting channel only)")
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return changes


class DriverLog:
    """This container's view of the run. Low trust: used for attribution hints, never as proof."""

    def __init__(self) -> None:
        self.fh = (OUTPUT / "driver.jsonl").open("a", encoding="utf-8", buffering=1)

    def write(self, kind: str, **fields) -> None:
        self.fh.write(json.dumps({"kind": kind, "t": time.time(), **fields}) + "\n")


# ------------------------------------------------------------------------------------------
# Chromium
# ------------------------------------------------------------------------------------------

def _chromium_extension_status(context) -> dict:
    """Ask Chromium which extensions it loaded, via its own diagnostics page.

    This is what separates "loaded, and quiet" from "refused at load": a content-script-only
    extension has no service worker to observe until a page matches.
    """
    page = context.new_page()
    try:
        page.goto("chrome://extensions-internals")
        page.wait_for_timeout(300)
        entries = json.loads(page.inner_text("body"))
    except Exception as exc:  # noqa: BLE001 - the page's format is not a stable interface
        return {"installed": None, "error": f"{type(exc).__name__}: {exc}"[:300]}
    finally:
        page.close()
    for entry in entries:
        # The location, not the name, identifies it: a manifest name can be a locale placeholder.
        if "COMPONENT" not in str(entry.get("location")).upper():
            return {"installed": True, "id": entry.get("id"), "name": entry.get("name"),
                    "location": entry.get("location"), "manifest_version": entry.get("manifest_version")}
    return {"installed": False, "seen": [e.get("location") for e in entries][:20]}


def _run_chromium(job: dict, ext_path: Path, control: Control, log: DriverLog) -> dict:
    from playwright.sync_api import sync_playwright

    from engine.sandbox.capture import _run_steps

    gateway = job["gateway"]
    profile = WORK / "profile"
    args = [
        "--headless=new",
        f"--disable-extensions-except={ext_path}",
        f"--load-extension={ext_path}",
        f"--proxy-server=http://{gateway}",
        "--proxy-bypass-list=<-loopback>",
        "--ignore-certificate-errors",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-features=DisableLoadExtensionCommandLineSwitch",
        "--disable-gpu",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-sync",
        "--disable-domain-reliability",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    info: dict = {"browser": "chromium", "extension_loaded": False}

    with sync_playwright() as playwright:
        context = playwright.chromium.launch_persistent_context(
            user_data_dir=str(profile), headless=False, args=args,
            chromium_sandbox=job.get("chromium_sandbox", True), ignore_https_errors=True,
            viewport={"width": 1280, "height": 900}, service_workers="allow",
        )
        try:
            info["browser_version"] = context.browser.version if context.browser else None

            def on_request(request) -> None:
                try:
                    from_worker = request.service_worker is not None
                except Exception:  # noqa: BLE001 - property differs across Playwright versions
                    from_worker = False
                try:
                    frame_url = request.frame.url
                except Exception:  # noqa: BLE001 - worker requests have no frame
                    frame_url = ""
                if REPORT_HOST in request.url or CONTROL_HOST in request.url:
                    return
                log.write("request", url=redact(request.url), method=request.method,
                          resource_type=request.resource_type, from_service_worker=from_worker,
                          frame_url=redact(frame_url),
                          navigation=request.is_navigation_request())

            context.on("request", on_request)
            context.on("serviceworker", lambda worker: log.write("service_worker_started", url=worker.url))
            context.on("weberror", lambda error: log.write("page_error", text=redact(str(error.error))[:300]))

            # Worker start is asynchronous, so allow it a moment before reading the status.
            worker_url = None
            try:
                worker = (context.service_workers[0] if context.service_workers
                          else context.wait_for_event("serviceworker", timeout=4000))
                worker_url = worker.url
            except Exception:  # noqa: BLE001 - extensions without a worker are legitimate
                pass
            background = [p.url for p in context.background_pages]
            time.sleep(0.5)
            status = _chromium_extension_status(context)
            info.update({
                "extension_status": status, "service_worker_url": worker_url,
                "background_pages": background,
                "extension_loaded": bool(status.get("installed") or worker_url or background),
            })
            if not info["extension_loaded"]:
                raise RunFailure(EXIT_LOAD, "extension_loading",
                                 "Chromium did not install the extension. The manifest was valid "
                                 "JSON, so the browser itself rejected it.")
            state("EXECUTING")

            page = context.pages[0] if context.pages else context.new_page()
            page.set_default_navigation_timeout(job.get("navigation_timeout_ms", 20000))
            page.goto("chrome://sandbox")
            page.wait_for_timeout(500)
            sandbox_text = page.inner_text("body")
            info["browser_sandbox"] = {
                "adequate": "adequately sandboxed" in sandbox_text,
                "summary": " | ".join(line.strip() for line in sandbox_text.splitlines()[:5]),
            }
            info["scenarios"] = _run_scenarios(
                job, control, log,
                run=lambda scenario: _chromium_scenario(page, scenario, _run_steps))
        finally:
            context.close()
    return info


def _chromium_scenario(page, scenario, run_steps) -> list[str]:
    skipped = run_steps(page, scenario)
    page.wait_for_timeout(int(scenario.settle_seconds * 1000))
    return skipped


# ------------------------------------------------------------------------------------------
# Firefox
# ------------------------------------------------------------------------------------------

def _run_firefox(job: dict, ext_path: Path, control: Control, log: DriverLog) -> dict:
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options
    from selenium.webdriver.firefox.service import Service

    from engine.sandbox.firefox_capture import _QUIET_PREFS, _run_steps

    host, _, port = job["gateway"].partition(":")
    options = Options()
    options.binary_location = FIREFOX
    options.add_argument("-headless")
    options.accept_insecure_certs = True
    # A sample can raise a dialog (or trigger a browser warning) to stall a scripted run.
    options.set_capability("unhandledPromptBehavior", "accept")
    prefs = {
        "network.proxy.type": 1, "network.proxy.http": host, "network.proxy.http_port": int(port),
        "network.proxy.ssl": host, "network.proxy.ssl_port": int(port),
        "network.proxy.allow_hijacking_localhost": True, "network.proxy.no_proxies_on": "",
        "network.proxy.socks_remote_dns": True, "network.dns.disablePrefetch": True,
        "network.prefetch-next": False, "media.peerconnection.ice.proxy_only": True,
        "dom.cookieStore.enabled": True, "security.warn_submit_secure_to_insecure": False,
    }
    prefs.update({k: v for k, v in _QUIET_PREFS.items()
                  if k != "extensions.webextensions.restrictedDomains"})
    for key, value in prefs.items():
        options.set_preference(key, value)

    info: dict = {"browser": "firefox", "extension_loaded": False}
    service = Service(executable_path=GECKODRIVER, log_output=str(OUTPUT / "geckodriver.log"))
    driver = webdriver.Firefox(options=options, service=service)
    try:
        info["browser_version"] = driver.capabilities.get("browserVersion")
        driver.set_page_load_timeout(job.get("navigation_timeout_ms", 20000) / 1000)
        driver.implicitly_wait(2)
        try:
            addon_id = driver.install_addon(str(ext_path), temporary=True)
        except Exception as exc:  # noqa: BLE001 - selenium raises several types here
            raise RunFailure(EXIT_LOAD, "extension_loading",
                             f"Firefox rejected the extension: {redact(str(exc))[:500]}") from exc
        info.update({"extension_loaded": True, "extension_status": {"installed": True, "id": addon_id}})
        time.sleep(1.0)
        state("EXECUTING")
        # Firefox has no equivalent of chrome://sandbox readable from content. Its process
        # sandbox is on by default and is not disabled here, which is all that can be stated.
        info["browser_sandbox"] = {"adequate": None, "summary": "Firefox default sandbox, not probed"}

        def run(scenario) -> list[str]:
            skipped = _run_steps(driver, scenario)
            time.sleep(scenario.settle_seconds)
            return skipped

        info["scenarios"] = _run_scenarios(job, control, log, run=run)
    finally:
        try:
            driver.quit()
        except Exception:  # noqa: BLE001
            pass
    return info


# ------------------------------------------------------------------------------------------

def scenario_list(job: dict) -> list[scenarios.Scenario]:
    """The scenarios for this job, in order. Identical jobs produce identical scripts."""
    out = []
    for name in job["scenarios"]:
        if name == "manifest-targeted":
            hosts = job.get("targeted_hosts") or []
            if hosts:
                out.append(scenarios.targeted_scenario(hosts))
        elif name == "replay-browse":
            out.append(scenarios.replay_scenario(job.get("replay_urls") or []))
        else:
            out.append(scenarios.get(name))
    return out


def _run_scenarios(job: dict, control: Control, log: DriverLog, *, run) -> list[dict]:
    results = []
    for scenario in scenario_list(job):
        started = time.time()
        control.send("scenario", "start", scenario.name)
        log.write("scenario_start", scenario=scenario.name)
        outcome: dict = {"name": scenario.name, "pages": list(scenario.pages), "status": "completed"}
        try:
            outcome["skipped_selectors"] = run(scenario)
        except RunFailure:
            raise
        except Exception as exc:  # noqa: BLE001 - one scenario must not lose the others
            outcome.update(status="failed", error=redact(f"{type(exc).__name__}: {exc}")[:400])
            log.write("scenario_failed", scenario=scenario.name, error=outcome["error"])
        outcome["seconds"] = round(time.time() - started, 2)
        control.send("scenario", "end", scenario.name)
        log.write("scenario_end", scenario=scenario.name)
        results.append(outcome)
    return results


def main() -> int:
    OUTPUT.mkdir(exist_ok=True)
    Path(os.environ.get("HOME", "/tmp/home")).mkdir(parents=True, exist_ok=True)
    job = json.loads((INPUT / "job.json").read_text(encoding="utf-8"))
    result: dict = {"status": "failed", "stage": "preflight"}
    started = time.time()
    try:
        state("SANDBOX_CHECK")
        check = preflight.run_checks("browser", job["gateway"])
        write_json("preflight.json", check)
        if not check["passed"]:
            failed = [c["name"] for c in check["checks"] if not c["passed"]]
            raise RunFailure(EXIT_PREFLIGHT, "preflight", f"isolation checks failed: {failed}")

        control = Control(job["gateway"], os.environ.get("EXTDRIFT_CONTROL_TOKEN", ""))
        result["stage"] = "gateway"
        control.wait_ready(job.get("gateway_wait_s", 30))

        state("EXTENSION_LOADING")
        result["stage"] = "instrumentation"
        WORK.mkdir(parents=True, exist_ok=True)
        try:
            prepared = instrument_extension(INPUT / "ext", WORK / "ext", all_scripts=True)
            changes = patch_manifest_for_capture(prepared["path"], job["browser"])
        except Exception as exc:  # noqa: BLE001 - hostile input; all failures are this one outcome
            raise RunFailure(EXIT_INSTRUMENT, "instrumentation",
                             f"could not instrument the extension: {exc}") from exc
        result["instrumentation"] = {
            "technique": prepared["technique"],
            "instrumented_scripts": prepared["instrumented_scripts"],
            "declared_but_missing": prepared["declared_but_missing"],
            "manifest_changes": changes,
        }

        log = DriverLog()
        result["stage"] = "extension_loading"
        run = _run_firefox if job["browser"] == "firefox" else _run_chromium
        info = run(job, Path(prepared["path"]).resolve(), control, log)
        result.update(info)
        result["status"] = "completed"
        result["stage"] = "done"
        state("CAPTURING")
        return EXIT_OK
    except RunFailure as failure:
        result.update(status="failed", stage=failure.stage, error=redact(str(failure))[:1000])
        return failure.code
    except Exception as exc:  # noqa: BLE001 - reported to the host, which fails the analysis
        result.update(status="failed", error=redact(f"{type(exc).__name__}: {exc}")[:1000],
                      traceback=redact(traceback.format_exc())[-2000:])
        return EXIT_EXECUTION
    finally:
        result["seconds"] = round(time.time() - started, 2)
        write_json("run.json", result)


if __name__ == "__main__":
    sys.exit(main())
