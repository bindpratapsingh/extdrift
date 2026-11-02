# Docker pipeline: architecture assessment and implementation plan

Written after reading every engine module, experiment, test and document, and before any code
was changed. Baseline when written: branch `mac-captures` at `cbf6e08`, **108 tests passed, 3
skipped**. Two of the skips are the live Chromium tests, which cannot run on this host because the
installed Playwright (1.63) expects browser build 1243 and the cache holds 1228.

## 1. Existing architecture

```
collector/ -> unpack/ -> sandbox/{rewrite,prelude} -> sandbox/{capture|firefox_capture}
                                                      |  against testsite.py / proxy.py
                                                      v
                                     trace.json (schema v0.1, four channels)
                                                      v
             features/extract -> features/delta -> scoring/rules + ml/predict -> report/render
synth/ + weaponiser/ -> batch.py -> data/dataset/deltas.csv -> ml/bakeoff -> models/winner.joblib
```

| Component | What it does | Status | Reuse |
|---|---|---|---|
| `unpack/crx.py` | CRX2/CRX3/XPI/dir unpack with Zip Slip + symlink refusal | Works; no size or file-count limit, so a zip bomb exhausts the host | Reuse, add limits |
| `unpack/manifest.py` | MV2/MV3 normalisation, permission diff | Works | Reuse as is |
| `sandbox/rewrite.py` | Prepends `prelude.js` to declared scripts on a scratch copy | Works; misses popup/options scripts and dynamically injected files; crashes on non-UTF-8 JS; keeps `_metadata`, which Chromium refuses for unpacked loads | Reuse, extend |
| `sandbox/prelude.js` | Hooks cookie, `.value`, `appendChild`, `getItem`, fetch/XHR/beacon, API methods | Works, with gaps listed in section 3 | Extend, without changing legacy event meaning |
| `sandbox/capture.py` | Chromium via Playwright on the **host**, sealed by `--host-resolver-rules` | Worked when last validated; not runnable here right now | Keep for dataset work; reuse `_run_steps` |
| `sandbox/firefox_capture.py` | Firefox via Selenium on the **host**, temporary add-on | Validated on real extensions | Keep; reuse `_run_steps`, prefs, manifest patch |
| `sandbox/proxy.py` | Local forward proxy, no HTTPS interception (refuses `CONNECT`) | Works | Keep; superseded inside Docker by mitmproxy |
| `sandbox/testsite.py` | Byte-identical local web plus fake collector | Works | Reuse its `SITE` content |
| `sandbox/scenarios.py` | Four scripted scenarios, Hulk-style event fuzzing | Works | Extend |
| `features/schema.py` | Trace contract v0.1 | Works | Keep; add the normalised event schema alongside |
| `features/extract.py`, `delta.py` | 26 features, Δ, set-level evidence | Works; feeds the trained model | **Must not change meaning**, see section 9 |
| `scoring/rules.py` | 12 delta-only rules, noisy-OR, 0..1 | Works; pinned by tests | Keep as the control; add a new 0..100 scorer beside it |
| `ml/bakeoff.py`, `predict.py` | 6-model race. **The saved winner is a Random Forest** (PR-AUC 0.984 under group CV, trained on synthetic plus real benign plus weaponised rows). `winner.joblib` is gitignored | Works; `predict_pair` hides every failure as `None` | Reuse; add a detailed wrapper that reports why ML is unavailable |
| `ml/anomaly.py` | Novelty layer | Works | Out of scope for the report's score; not modified |
| `weaponiser/`, `synth/` | Payload injection, synthetic pairs | Works | Reuse for evaluation |
| `report/render.py` | Text + JSON verdict, MALICIOUS/SUSPICIOUS/BENIGN | Works | Keep; new sectioned report beside it |
| `runner.py`, `cli.py` | Host-side `run-pair` | Works | Keep; add `analyze` and `compare` commands |
| Docker | **Nothing exists.** No Dockerfile, no seccomp profile, no container code | Missing | New |
| mitmproxy | Mentioned in docs as "next"; **no implementation** | Missing | New |

## 2. Working today

Unpacking, manifest diff, the four-channel prelude, both host capture engines, deterministic site,
scenarios, 26-feature delta, 12-rule scorer, Random Forest inference, weaponiser, synthetic corpus,
dataset of 1,152 labelled rows, and all evaluation experiments.

## 3. Incomplete, or incorrect in ways that matter here

These were found by reading the code and are reported rather than quietly worked around.

1. **The "sandbox" is not a sandbox.** Extensions execute directly on the host. The README's "sealed
   sandbox" means network sealing only. There is no filesystem, process or credential isolation.
2. **Chromium content-script requests are attributed to the page.** `_initiator_for` looks for the
   extension origin in `request.frame.url`, but a content script's frame URL is the web page's. Its
   upload therefore does not count as an extension-initiated flow. `tests/test_sandbox.py` pins the
   current function behaviour, so the legacy function stays; the new path attributes differently.
3. **Timestamps are not on one clock.** Prelude events use seconds since *that realm's* start, while
   network events use seconds since run start, so the 10-second exfil window compares different
   clocks in Chromium captures.
4. **`chrome.storage.local.*` is invisible.** The API wrapper only wraps direct function properties.
   `chrome.storage.local` is a nested object, and event objects (`runtime.onMessage`,
   `webRequest.onBeforeRequest`) are not wrapped at all.
5. **Background pages are labelled `content_script`.** The prelude treats any realm with `window` as a
   content script, including MV2 background pages and popups.
6. **Monitored DOM surface is narrow.** No `querySelector`, `addEventListener`, `innerHTML`,
   `setAttribute`, `FormData`, `textContent`, form-action changes, `localStorage.setItem/removeItem/clear`,
   IndexedDB, or WebSocket.
7. **Failures look like benign results.** A prelude blocked by an extension CSP, a content script that
   never matched a test URL, or a dead reporting path all produce an empty trace, which scores BENIGN.
8. **HTTPS exfiltration payloads are not observed on the wire.** The Firefox proxy refuses `CONNECT`;
   only the prelude's self-report (which an extension can bypass) sees them.
9. **Exfiltration is inferred from timing only.** There is no check that the stolen value actually
   appears in the outgoing request.
10. **The Firefox manifest patch over-grants.** It adds `*.test` host access, an unnecessary capability
    that can change behaviour. The dataset depends on it, so only the new path uses a narrower patch.

## 4. Missing

Docker sandbox and hardening, default-deny network, mitmproxy capture, record/replay bundles, central
event schema with raw/normalised split, attribution with confidence, data-flow evidence, the extended
features, a behaviour-level differ, a 0..100 scorer with Mode A, combined ML/rules assessment, the
sectioned report, pipeline states and failure handling, input validation, controlled test extensions.

## 5. Dependencies that constrain the design

`extract_features` -> `FEATURE_ORDER` -> `deltas.csv` -> `winner.joblib`. The model only means what it
was trained to mean if those 26 features keep their definitions. `rule_score` is also stored per row,
and `tests/test_pipeline.py` pins the verdicts for the three fixture pairs.

## 6. Proposed integration architecture

Host orchestrator (trusted) plus two disposable containers per version, on a per-run network that has
no route to anywhere:

```
HOST (trusted): validate + unpack -> create volumes/network -> collect -> normalise -> features
   |                                                         -> diff -> score -> ML -> report
   | docker CLI only. No bind mounts. Data moves as size-limited tar streams through volumes.
   v
per-run  --internal  Docker network (no gateway, no NAT, default deny)
   +- browser container: non-root, cap-drop ALL, no-new-privileges, seccomp, read-only rootfs,
   |    tmpfs /tmp, CPU/mem/pid limits, private volume for input and the driver log
   |    Chromium (Playwright) or Firefox (Selenium) + instrumented extension + scenarios
   |         | all traffic via proxy
   +- gateway container: non-root, read-only; mitmproxy addon
        answers every request locally from the replay bundle, sinks everything else,
        scans for synthetic markers, writes raw evidence to a volume the browser cannot reach
```

Key decisions:

* **Two independent network barriers.** The addon never connects upstream, and even if it did, the
  gateway has no route out. Default deny comes from the network topology, not from an allow-list.
* **The wire is the primary record of network behaviour.** mitmproxy sees requests that a hooked
  `fetch` would miss. Prelude reports annotate wire events with their realm, and any disagreement
  between the two views is itself reported.
* **Canary markers replace "temporal adjacency" as the strongest exfil evidence.** Every synthetic
  secret is unique and is searched for in each request under common encodings. Only marker IDs are
  stored, never values.
* **A failed monitor means Inconclusive, never low risk.** Isolation preflight, extension-load check,
  realm heartbeats, report sequence-gap detection and a wire check all feed a coverage record.
* **The trained model keeps its meaning.** New prelude events carry `extended: true`, and the legacy
  feature code ignores them, so the existing features, dataset and model stay valid.

## 7. Existing files to modify

`engine/sandbox/prelude.js`, `rewrite.py`, `scenarios.py`, `testsite.py` (adds new pages to `SITE`),
`engine/features/schema.py`, `extract.py`, `delta.py` (ignore `extended` events), `engine/unpack/crx.py`
(extraction limits), `engine/cli.py` (new commands), `.gitignore`, `README.md`, `docs/STATUS.md`,
`docs/PROJECT_REPORT.md`, `requirements.txt` (comment only: mitmproxy lives in the gateway image).

## 8. New files

```
docker/{sandbox,gateway}.Dockerfile, docker/seccomp-browser.json, .dockerignore
config/sandbox.toml, config/risk_scoring.toml
engine/sandbox/{markers,synthetic_web,gateway_addon,container_runner,preflight,
                docker_manager,replay,normalise,attribution}.py
engine/features/{behaviour,behaviour_diff}.py
engine/scoring/{risk,combined}.py
engine/ml/inference.py
engine/report/security_report.py
engine/pipeline/{__init__,config,states,validation,orchestrator}.py
data/corpus/controlled/<test extensions>
experiments/risk_calibration.py, scripts/analyse_demo.sh
tests/test_{normalise,markers,behaviour,risk_scoring,security_report,pipeline_units,docker_e2e}.py
docs/SANDBOX.md
```

## 9. Compatibility issues

| Issue | Handling |
|---|---|
| Model's training distribution | `extended` event flag; legacy features unchanged; test asserts this. The model was trained on Firefox and synthetic deltas, so Chromium-in-Docker predictions are out-of-distribution to some extent. The report says so |
| mitmproxy 12 needs Python >= 3.12; host venv is 3.11 | Gateway image uses 3.12 and only imports stdlib-compatible modules. mitmproxy is not added to the host |
| Chromium's own sandbox needs user namespaces | A custom seccomp profile (Docker default plus namespace syscalls) keeps it enabled. If it cannot start, the degraded mode is recorded in the report instead of hidden |
| Apple Silicon | Playwright Chromium and Debian `firefox-esr` both ship arm64. Chrome and Edge have no arm64 Linux builds, and branded Chrome 137+ removed `--load-extension`. They are rejected with a clear error, not claimed |
| Firefox refuses `service_worker`-only MV3 | Surfaces as a load failure and an Inconclusive report |
| `--internal` network on Docker Desktop | Verified by an egress probe in every run, not assumed |
| `test_steps_only_use_known_actions` | Real keystrokes are expressed as a `fill` step with a per-key delay, so no new step action is needed |

## 10. Implementation phases and acceptance

| Phase | Work | Accepted when |
|---|---|---|
| 2 Docker | Images, seccomp, manager, preflight | Probe proves non-root, no caps, no egress, no socket; nothing left behind after a run |
| 3 Execution | Runner, scenarios, synthetic web | A real extension loads in both browsers inside the container and runs through the scenarios |
| 4 Monitoring | Prelude, addon, attribution | All four dimensions recorded from a real run of controlled extensions |
| 5 Normalise | Central schema, raw and normalised JSONL | Validated from real runs |
| 6 Features | Extended vector | Reproducible; two runs of the same trace give the same vector |
| 7 Diff | Signature-level differ | Test 6 identifies only the introduced behaviour |
| 8 Scoring | Rules, ML, combination | Tests 1-5; evaluated on the labelled dataset |
| 9 Report | JSON, Markdown, HTML | All sections A-G from real data |
| 10 E2E | All seven required tests | Pass in Docker; existing suite still green |
