# The Docker analysis pipeline

How to run an extension through the isolated sandbox, what it observes, and what it cannot.
Design reasoning is in [design/DOCKER_PIPELINE_ASSESSMENT.md](design/DOCKER_PIPELINE_ASSESSMENT.md),
and scoring evaluation in [design/RISK_CALIBRATION.md](design/RISK_CALIBRATION.md).

## Quick start

Requires Docker, Python 3.11 and `pip install -r requirements.txt`. The first build compiles
geckodriver, so it takes several minutes.

```bash
# Build the two images (once, and again after changing engine/sandbox/)
python -m engine.cli sandbox-build

# Mode B, the main mode: did this update change behaviour dangerously?
python -m engine.cli compare path/to/version_n path/to/version_n_plus_1 --browser chromium

# Mode A: analyse one extension on its own
python -m engine.cli analyze path/to/extension.crx --browser chromium

# A safe demonstration with the controlled samples
python -m engine.cli compare data/corpus/controlled/pair_v1 data/corpus/controlled/pair_v2
```

Inputs may be a `.crx`, a `.xpi`, a `.zip` or an unpacked directory. Useful options:

| Option | Meaning |
|---|---|
| `--browser firefox` | Use Firefox instead of Chromium |
| `--scenarios a,b` | Run only these scenarios, for a quicker result |
| `--aa-check` | With `compare`: run the baseline twice, and exclude behaviour that varies on its own |
| `--bundle file.json` | Browse a recorded replay bundle instead of the synthetic web |
| `--fail-at 60` | Exit with status 2 at this score, for automation |
| `--out-dir path` | Where results go (default `out/analyses`) |

Exit status: `0` analysis completed, `2` score reached `--fail-at`, `3` analysis failed.
After a crash of the host process, `python -m engine.cli sandbox-clean` removes leftovers.

## What a run produces

Everything is under `out/analyses/<analysis-id>/`.

| File | Contents |
|---|---|
| `report.html`, `report.md`, `report.json` | The security report |
| `status.json`, `pipeline.log` | Pipeline states and a structured log |
| `<version>/behaviour.log` | One readable line for every observed event |
| `<version>/trace.normalised.jsonl` | Events in the central schema |
| `<version>/trace.json` | The same run in the original v0.1 schema |
| `<version>/behaviours.json`, `features.json`, `coverage.json` | Grouped behaviours, the feature vector, and what could be observed |
| `<version>/raw/gateway/*.jsonl` | Raw wire record and prelude reports |
| `<version>/raw/browser/*` | Driver log, run record, isolation check |
| `diff.json` | Behaviour comparison |
| `<role>.metadata.json` | Extension metadata extracted from the manifest |

## Architecture

```
HOST (trusted)   validate + unpack -> create sandbox -> collect -> normalise -> features
                                                                    -> diff -> score -> ML -> report
   | docker CLI only. No bind mounts. Data moves as bounded tar streams through named volumes.
   v
per-run --internal Docker network: no gateway, no NAT, no route to host or internet
   |- browser container   the extension. Chromium or Firefox, driver, preflight.
   |      | every request goes through the proxy setting
   |- gateway container   mitmproxy addon. Answers everything locally, records it.
                          Writes evidence to a volume the browser container cannot reach.
```

Each version runs in a new network, new containers and new volumes, all deleted afterwards.
Both versions get the same scenario list, fixed before either runs, and the same page bundle.

### Pipeline states

`QUEUED`, `VALIDATING`, `SANDBOX_INITIALISING`, `EXTENSION_LOADING`, `EXECUTING`, `CAPTURING`,
`ANALYSING`, `SCORING`, `REPORT_GENERATION`, then `COMPLETED` or `FAILED`. A failure at any stage
produces a report with an Inconclusive verdict and the reason. It never produces a low score.

| Condition | Result |
|---|---|
| Package invalid, or browser not supported | `FAILED` at validation |
| Isolation check fails in either container | `FAILED`, run not scored |
| Browser refuses the extension | `FAILED` at extension loading |
| Time limit exceeded | Container killed, `FAILED` |
| Declared background or content script never reported starting | Coverage incomplete: Inconclusive, unless strong positive evidence was seen |
| Baseline coverage incomplete | Inconclusive, as "new" behaviour cannot be told from behaviour missed earlier |

## Isolation

### What is enforced

Each item below is checked from inside the container on every run by
[preflight.py](../engine/sandbox/preflight.py). The results are in the report, and a failure stops
the analysis.

| Control | How | Verified at run time |
|---|---|---|
| Non-root | `--user 1000:1000` | Yes |
| No Linux capabilities | `--cap-drop ALL` | Yes, `CapEff` is 0 |
| No privilege escalation | `no-new-privileges` | Yes |
| Syscall filter | Docker default profile with ptrace-family calls removed. Namespace calls are added so the browser's own sandbox can run ([build_seccomp.py](../docker/build_seccomp.py)) | Yes |
| Read-only root | `--read-only`, with a `noexec,nosuid,nodev` tmpfs for `/tmp` | Yes |
| CPU, memory, process limits | `--cpus`, `--memory`, `--memory-swap`, `--pids-limit` | Memory and PIDs |
| Time limit | Container killed at `run_timeout_seconds` | Covered by an end-to-end test, not per run |
| No Docker socket, no host mounts | None are ever passed, with data moved by tar stream | Yes |
| Clean environment | Only explicit `--env` values; nothing inherited | Yes |
| Default-deny network | `--internal` network, plus a gateway that never connects upstream | Yes: TCP probes to public IPs, the Docker host and cloud metadata, plus an external DNS lookup, must all fail, while the gateway must be reachable |
| Clean-up | Network, containers and volumes removed; labelled so they can be found | Covered by end-to-end tests, not per run |
| Browser process sandbox | Chromium's sandbox stays on. A run in which it cannot start fails by default | Yes for Chromium (`chrome://sandbox`). Firefox's is left at its defaults and is not probed |

Output from a container is treated as hostile. Reading it back refuses non-regular files and path
traversal and enforces size ceilings. The HTML report escapes every value that could come from the
sample. Package unpacking is the only step that touches hostile bytes on the host. It refuses
traversal and symlinks and is limited in size and file count. No extension code runs on the host.

### What remains: Docker is one layer

Containers share the host's kernel, so **this sandbox does not stop a kernel exploit**.

| Remaining risk | Why it matters | Mitigation for higher-risk samples |
|---|---|---|
| Linux kernel vulnerability | A shared kernel is the classic container escape | Use gVisor (`--runtime=runsc`) or Kata Containers, or run Docker inside a disposable VM |
| Browser exploit chain | A renderer exploit gets code execution inside the container | The container holds nothing of value, but pair this with a VM for samples believed to be weaponised |
| Docker or runc vulnerability | The runtime itself can have escape bugs | Keep Docker patched; prefer rootless Docker or a dedicated analysis host |
| Docker Desktop specifics | On macOS and Windows the containers run in a VM, which helps. On Linux they run directly on the host kernel | On Linux, prefer a VM for untrusted samples |
| Resource exhaustion | Limits are per container, so many concurrent runs add up | Run a bounded number at a time |
| Hostile content in the report | A sample's strings appear in the report | Escaped in HTML; review `report.md` as untrusted text |

**Recommended for unknown or suspected-malicious samples:** a disposable VM with no shared folders
and no credentials on it, snapshotted and reset between analyses. Docker alone is appropriate for
samples you created or a reasonably trusted corpus.

## Browser support

Only what has been run is claimed. Others are refused with an explanation.

| Browser | Status | Evidence |
|---|---|---|
| Chromium (Playwright build) | Supported | Hardened container, extension loading, all scenarios, end-to-end tests |
| Firefox ESR (Debian, with geckodriver) | Supported | Hardened container, temporary add-on loading, end-to-end tests |
| Chrome | Refused | Branded Chrome 137+ removed `--load-extension`, and no arm64 Linux build exists |
| Edge, Brave | Refused | Not installed and never tested. Similar APIs do not prove loading works |

Current Chromium no longer runs Manifest V2 extensions, and Firefox refuses service-worker-only
MV3 manifests. Each surfaces as a load failure, not as a quiet result.

## What is observable, and what is not

Instrumentation code is prepended to every `.js` file in a scratch copy of the extension. Running
inside the extension's own execution contexts is what makes content scripts and service workers
visible at all, because a hook placed from a page cannot see an isolated world. The gateway's wire
record is independent of this. The only manifest change is letting reports reach the reporting
host. No permission or site access is ever added to the sample, and the report lists the changes.

### Network (mitmproxy, in the gateway)

**Observed:** every proxied HTTP(S) and WebSocket request, including URL, method, headers,
body metadata, frames, redirects, and TLS and connection failures. Raw TCP through the proxy is also
recorded. Bodies are searched for synthetic markers in plain, URL, base64, hex, reversed, rot13,
UTF-16 and gzip forms, and as MD5, SHA-1 or SHA-256 digests.

**Not observed:**
* Keyed or custom encryption of a stolen value. Only the weaker timing-based candidate can suggest this.
* Non-proxied traffic: WebRTC UDP and direct sockets. These have no route, so nothing leaves, but
  the attempt itself is mostly invisible. `RTCPeerConnection` construction is hooked as a partial signal.
* DNS as a channel. External lookups fail, and individual queries are not logged.
* Destination IPs, because no request is ever really connected. Only IP literals in URLs are known.

**Attribution** is recorded per request as `confirmed` (prelude self-report, extension `Origin`
header, or the browser's own service-worker flag) or `inferred` (the fixed web cannot have asked for
this host, or the host is a known browser service). An extension that avoids the hooked APIs reaches
at most `inferred`. A request to a browser-service domain with no marker and no other link to
the extension is treated as browser traffic, which is a blind spot an attacker could use.

### DOM

**Observed, in contexts where the prelude runs:** `.value` reads with field type and class, sensitive
`querySelector` and `getElementById` lookups, `document.forms`, `form.elements`, `getAttribute("value")`,
`FormData`, sensitive `textContent`/`innerText`/`innerHTML` reads, `document.cookie`, listeners for keys
and form events, `appendChild` and friends, `innerHTML`/`insertAdjacentHTML`/`document.write`,
`setAttribute`, `form.action`, script and iframe creation, `form.submit`, `navigator.clipboard`.

**Not observed:**
* Reads through other DOM paths: `TreeWalker`, `Range`, `selection`, `outerHTML`, attribute maps, and
  `input.defaultValue`.
* Ordinary non-sensitive reads are only counted, not listed individually.
* A sample can capture native functions from another realm, such as a fresh iframe, to bypass hooks.
* Scripts running in the page's own world are partly visible. They are labelled `page_injected`, and
  the page's own activity can appear mixed with theirs.
* `eval` and `new Function` are not hooked, because wrapping `eval` changes its scoping semantics.

### Storage and cookies

**Observed:** `localStorage` and `sessionStorage` through methods and direct property access, IndexedDB
open and object-store operations, `chrome.storage.*`/`browser.storage.*` by area with key names,
`chrome.cookies.*`, `cookieStore`, `document.cookie`. Values are never recorded, only key names.

**Not observed:** `IDBCursor` traversal beyond the initial open, the Cache API, the Origin Private
File System, and the content of what a cookie API call returned.

### Extension APIs

**Observed:** methods and event subscriptions on the namespaces listed in
[prelude.js](../engine/sandbox/prelude.js), in every instrumented context, with parameter metadata
limited to keys and identifying fields.

**Not observed:** API objects reached through an uninstrumented frame or a realm created before the
prelude runs, namespaces outside the list, and return values. A web-accessible page's inline
behaviour depends on whether its scripts are `.js` files in the package.

### Evading the monitor

Instrumentation lives in the sample's own JavaScript, so a careful sample can detect the global
marker, compare `fetch.toString()`, or forge or suppress reports. Three things limit this: the wire
record does not depend on it; a realm that never reports makes coverage incomplete; and report
sequence gaps are counted. Environmental checks, such as looking for headless browsers, are not
defeated. Prepending also removes a file-level `"use strict"` directive, which changes the
semantics of unusual code. Both versions get the same treatment, so the comparison stays fair.

## Determinism

**Controlled:** page bytes (content hash in the report), scenario list and order, synthetic values,
browser and image versions (recorded), and no time or randomness in the synthetic pages.

**Not controlled, and recorded as such:** browser scheduling, service-worker lifetimes, the timing of
asynchronous code, and extensions' own use of time and randomness. Each run's small count variations
are absorbed by a frequency threshold, and `--aa-check` measures the remaining noise directly.
Execution is therefore comparable rather than perfectly deterministic. Time-bomb payloads are not
triggered, as the clock is not shifted.

## Replay bundles

The default is the synthetic web. For other pages, record once and replay:

```bash
python -m engine.cli record-bundle https://example.com/ --out bundle.json   # no extension loaded
python -m engine.cli compare v1 v2 --bundle bundle.json
```

A bundle is keyed by host and path. Recording runs on the host with no extension, and needs
`playwright install chromium` there. Replay runs sealed. Query strings are not part of the key, and
pages whose own scripts use time or randomness will still vary. Recording and replay are tested end
to end against a local web server. Recording real websites has not been exercised, and real pages
may well depend on things this simple keying cannot reproduce.

## What was not exercised

* **Platforms.** Everything was run on one machine: macOS on Apple Silicon with Docker Desktop.
  Plain Linux hosts and x86-64 have not been run. A Linux host may also need its AppArmor settings
  changed before Chromium's sandbox can create user namespaces, in which case the run fails with an
  explicit error rather than continuing unsandboxed.
* **Real malicious extensions.** All malicious samples here are controlled test extensions and
  synthetic payloads. The Docker pipeline has not been run on real-world extensions at all.
* **Extension UI.** Toolbar popups and options pages are instrumented but are never opened by a
  scenario, and `action.onClicked` never fires, so behaviour behind those is missed.
* **Time-gated and server-gated behaviour.** The clock is not shifted, and no sink ever returns
  a command, so payloads waiting on a date or on instructions from a server stay dormant.

## Tests

```bash
python -m pytest tests/ -q                                     # all fast tests, no Docker needed
EXTDRIFT_DOCKER_TESTS=1 python -m pytest tests/test_docker_e2e.py -v   # real runs, about 20 minutes
```

The fast suite has 222 passing tests, and 2 skip on this platform. It includes two live Chromium tests
of the original host-side path, which skip when no matching browser is installed. The Docker suite
has 36 tests, all passing on both browsers where applicable, and runs real browsers in real containers.

Real example output from the full scenario suite is in [examples/](examples/).

## Tuning

* [config/sandbox.toml](../config/sandbox.toml): images, limits, timeouts, browsers, noise domains.
* [config/risk_scoring.toml](../config/risk_scoring.toml): indicator weights, clusters, bands, combination.
