# extdrift — Build Status (living document)

> **This is a living document. Update it on every change** — whenever a feature is added, changed,
> or removed, edit the relevant row and add a dated line to the Changelog at the bottom. Keep it in
> sync with the code; it is the single place to see "what exists and what's left" at a glance.
> The full narrative is in [PROJECT_REPORT.md](PROJECT_REPORT.md).

**Last updated:** 2026-11-06 · **tests:** 231 fast passing + 38 skipped · **dataset:**
1,152 pairs (1,000 synthetic + 150 real + 2 fixtures) **+ a new 17-extension REAL-MALWARE
validation set** (executed sealed; see §4/§7). **Model:** XGBoost (bake-off now selects by
FPR@90%recall — see §5).

**Done this session:** merged the Docker analysis pipeline into `main`; built `demo/` — a local
web front end that runs a pair end to end and shows the process (see `docs/DEMO_MANUAL.md`);
**fixed a capture-determinism defect** in which a service worker's first instrumentation reports
could be emitted before the driver was listening, so an MV3 listener registration appeared in some
runs of an extension and not others — a false difference between two runs of identical code. The
prelude now buffers and re-posts its reports and both absorbers drop duplicates by
`(realm_id, report_seq)`; five consecutive runs of each version now produce identical behaviour
sets. **Remaining:** P4 real-malicious live, P6 GNN, the 24% empty-capture problem in the real
benign corpus, and the written deliverables. See §6.

**Legend:** ✅ done & tested · 🟡 partial / needs validation · ⬜ not started · ❌ blocked (with reason)

---

## 1. Built — core system

| Component | Status | Where |
|---|:--:|---|
| Package unpacking (.crx/.xpi/.zip/dir, CRX2/CRX3, safe-extract) | ✅ | `engine/unpack/crx.py` |
| Manifest normalisation + static permission diff | ✅ | `engine/unpack/manifest.py` |
| Deterministic in-process test site (+ fake collector) | ✅ | `engine/sandbox/testsite.py` |
| Firefox capture proxy (serve + absorb + sealed egress) | ✅ | `engine/sandbox/proxy.py` |
| Instrumentation (prelude injection; content/MV2 bg-page/MV3 SW) | ✅ | `engine/sandbox/rewrite.py`, `prelude.js` |
| Scenarios + HoneyPage + event-handler fuzzing (Hulk) | ✅ | `engine/sandbox/scenarios.py` |
| Chromium capture engine (Playwright) | ✅ | `engine/sandbox/capture.py` — validated on a real MV3 extension (SW reached; weaponised diff MALICIOUS) via `experiments/chrome_spike.py` |
| Firefox capture engine (Selenium, temp add-on) | ✅ | `engine/sandbox/firefox_capture.py` — validated on 15 real extensions |
| Trace schema + validation | ✅ | `engine/features/schema.py` |
| Behavioural feature extractor (26 features) | ✅ | `engine/features/extract.py` |
| Behavioural delta + evidence | ✅ | `engine/features/delta.py` |
| Static-code features (27, You've Changed method + adopted APIs) | ✅ | `engine/features/static_code.py` |
| AST/token-diff baseline | ✅ | `engine/features/ast_diff.py` |
| Rules scorer (12 rules, thresholds) | ✅ | `engine/scoring/rules.py` |
| ML bake-off (6 models, leakage-free CV + temporal + SMOTE opt) | ✅ | `engine/ml/bakeoff.py` |
| Anomaly layer (leave-one-family-out + **on real data**) | ✅ | `engine/ml/anomaly.py` — `--real`: 93% detect / 13% FPR / ROC-AUC 0.989 on real, fit on synthetic-benign only |
| Predict bridge (trained model on one pair) | ✅ | `engine/ml/predict.py` |
| Report rendering (text + JSON verdict) | ✅ | `engine/report/render.py` |
| End-to-end runner + CLI | ✅ | `engine/runner.py`, `engine/cli.py` |
| Local web front end (upload two versions, watch the run, see the verdict) | ✅ | `demo/server.py`, `demo/analysis.py`, `demo/ui/` — three bundled sample pairs covering MALICIOUS / BENIGN / NO CHANGE |

## 1b. Built — Docker analysis pipeline

| Component | Status | Where |
|---|:--:|---|
| Hardened sandbox (non-root, no caps, seccomp, read-only, limits, no-route network, disposable) | ✅ | `engine/sandbox/docker_manager.py`, `docker/` |
| Run-time isolation proof (preflight) | ✅ | `engine/sandbox/preflight.py` |
| In-container driver: Chromium + Firefox ESR | ✅ | `engine/sandbox/container_runner.py` |
| mitmproxy gateway: replay, sink, wire record, markers | ✅ | `engine/sandbox/gateway_addon.py`, `markers.py` |
| Synthetic web + 6 new scenarios + manifest-targeted hosts | ✅ | `engine/sandbox/synthetic_web.py`, `scenarios.py` |
| Replay bundles (fixed web, content hash, recording) | 🟡 | `engine/sandbox/replay.py` — record and replay tested end to end against a local server; recording real websites not exercised |
| Extended instrumentation (DOM, storage, IndexedDB, nested APIs, realms) | ✅ | `engine/sandbox/prelude.js` |
| Attribution with confidence + central event schema + coverage | ✅ | `engine/sandbox/attribution.py`, `normalise.py` |
| Extended features + behaviour diff | ✅ | `engine/features/behaviour.py`, `behaviour_diff.py` |
| 0-100 risk score + ML combination | ✅ | `engine/scoring/risk.py`, `combined.py`, `config/risk_scoring.toml` |
| Random Forest integration with stated availability | ✅ | `engine/ml/inference.py` |
| Sectioned JSON / Markdown / HTML report | ✅ | `engine/report/security_report.py` |
| Orchestration, validation, states, failure reports | ✅ | `engine/pipeline/`, `engine/cli.py` |
| Score evaluation on labelled data | ✅ | `experiments/risk_calibration.py`, `docs/design/RISK_CALIBRATION.md` |
| Chrome, Edge, Brave | ⬜ | Refused with an explanation; not tested |

## 2. Built — data generation

| Component | Status | Where |
|---|:--:|---|
| Synthetic generator (12 personas, 9 families, hard overlap) | ✅ | `engine/synth/generate.py` |
| Weaponiser (5 real-grounded families + evasion layer, clean + obfuscated, MV2-safe) | ✅ | `engine/weaponiser/` — cookie_theft, credential_theft, sw_beacon, **history_exfil** (DataSpii browsing-data exfil, the #1 real behaviour), **ad_affiliate** (affiliate-link replacement); **`evasion=True`** layers the observed OPSEC (IP-recon + DNS-over-HTTPS exfil, `.test` stand-ins); `demo/build_weaponised_pairs.py --family/--evasion` |
| Dataset assembler (synthetic + captured → one schema) | ✅ | `engine/batch.py` |

## 3. Built — real-data collection

| Component | Status | Where |
|---|:--:|---|
| Firefox AMO collector + popularity crawl | ✅ | `engine/collector/amo.py` |
| Chrome Web Store collector (current CRX) + delisting probe | ✅ | `engine/collector/chrome.py` |
| crx4chrome historical resolver (best-effort) | 🟡 | `engine/collector/chrome.py` — works for popular, patchy for obscure |
| extensiondeltas corpus adapter (download + discriminative APIs) | ✅ | `engine/collector/extensiondeltas.py` |
| GitHub-tag / update-endpoint downloader; disk snapshotter; corpus manifest | ✅ | `engine/collector/{download,snapshot,corpus}.py` |

## 4. Built — experiments (evidence)

| Study | Status | Where |
|---|:--:|---|
| Static-vs-dynamic head-to-head (obfuscation) | ✅ | `experiments/headtohead.py` |
| Determinism ablation | ✅ | `experiments/ablation.py` |
| Feature-group ablation | ✅ | `experiments/feature_ablation.py` |
| Learning curve | ✅ | `experiments/learning_curve.py` |
| AST-diff vs semantic static baseline | ✅ | `experiments/ast_diff_baseline.py` |
| Real static-code dataset (real code) | ✅ | `experiments/real_static_dataset.py` |
| Firefox feasibility spike | ✅ | `experiments/firefox_spike.py` |
| Real AMO behavioural capture (benign) | ✅ | `experiments/capture_amo_behavioural.py` |
| Real weaponised behavioural capture (malicious) | ✅ | `experiments/capture_weaponised_behavioural.py` |
| Real-data eval + synthetic→real transfer | ✅ | `experiments/real_behavioural_eval.py` |
| Chrome delisting / pair-feasibility probe | ✅ | `experiments/chrome_delisting_probe.py` |
| Statistical rigor (bootstrap CIs + ML-vs-rules significance) | ✅ | `experiments/statistical_rigor.py` |
| Locked held-out test + calibrated operating point | ✅ | `experiments/operating_point.py` |
| You've Changed head-to-head (static vs dynamic, real code) | ✅ | `experiments/youve_changed_headtohead.py` |
| Adware sub-study (zero-shot detection of unseen ad-injection) | ✅ | `experiments/adware_study.py` |
| Chromium-on-real + MV3 validation | ✅ | `experiments/chrome_spike.py` |
| Performance characterization | ✅ | `experiments/performance.py` |

## 5. Current dataset & headline results

- **Behavioural dataset:** 1,047 pairs · 266 extensions · 449 malicious / 598 benign
  (1,000 synthetic + 30 weaponised-real + 15 real-benign + 2 fixtures).
- **Static-code track:** 40 rows · 10 real extensions.
- **Bake-off winner:** XGBoost, CV PR-AUC 0.981, **FPR@90%-recall 0.011** (rules: 0.892 / 0.408);
  RF/HistGB tied within 0.003 PR-AUC. Selection is now **FPR-primary** (the operational metric
  for a differencing tool) rather than PR-AUC-primary — which also lands on a gradient-boosted
  model (the advisor's "beyond RF"). Retrained 2026-11-06 on the current `deltas.csv`.
- **Real-malware validation (NEW, 2026-11-06):** 17 confirmed-malicious extensions (Edge
  "Two Heads" + still-live mallorybowes) executed in the **sealed** sandbox → **14/17 (82%)
  flagged**; **19 distinct real exfil/C2 backends intercepted** locally (flipshope, urban-vpn
  analytics, ipify IP-recon, DNS-over-HTTPS evasion, …), nothing left the machine. Proves the
  features fire on real malware, not only synthetic payloads. See `out/real_malicious/` and
  `docs/research/P0_DATA_ACQUISITION.md`.
- **Synthetic→real held-out transfer:** PR-AUC 0.998, recall 0.93, precision 1.0, 0% FPR.
- **Rules on real weaponised:** 30/30 = 100% recall.

---

## 6. Remaining — to fully complete the project

**[E]** = essential to call it complete · **[S]** = stretch · **[❌]** = blocked (reason given).

### Data
- ⬜ **[E, Mac/P2]** Scale real benign corpus to hundreds of pairs (infra + `scripts/scale_capture.sh` ready).
- ⬜ **[E, Mac/P4]** Capture genuinely-malicious *live* Chrome extensions in the sealed sandbox.
- ✅ **[E]** Adware sub-study — `experiments/adware_study.py` (zero-shot: supervised 0%, anomaly 49%).
- 🟡 Real malicious *update pairs* — **still infeasible** (same id, benign→malicious: Chrome serves
  only current; Wayback holds no CRX binaries — confirmed 2026-11-06). **But** real malicious
  *extensions* are now obtained and executed: a **17-extension sealed real-malware validation
  set** (82% flagged). Weaponise substitute stands for *training*; real malware validates it.
  Sources: `engine/collector/{edge,wayback}.py`, `experiments/{harvest,capture}_real_malicious.py`.

### Method completeness
- ✅ **[E]** Validate the Chromium engine on real extensions — `experiments/chrome_spike.py`.
- ✅ **[E]** MV3 service-worker capture on a real MV3 extension — verified in the same spike.
- ⬜ **[S]** Broader trigger elicitation (dynamic querySelector synthesis, time-bomb handling).

### Model & evaluation rigor  — **[P1, essentials DONE]**
- ✅ **[E]** Confidence intervals + significance testing — `experiments/statistical_rigor.py`
  (HistGB vs rules +0.115 PR-AUC, 95% CI [0.093, 0.137], significant).
- ✅ **[E]** Threshold / operating-point calibration + locked held-out test —
  `experiments/operating_point.py` (held-out PR-AUC 0.976, FPR@90%rec 0.020).
- ✅ **[E]** Anomaly layer evaluated on **real** deltas — `engine/ml/anomaly.py --real`.
- ✅ **[E]** Head-to-head reproduction of prior work (You've Changed) on real code —
  `experiments/youve_changed_headtohead.py` (static clean 21/21, obfuscated 0/21).
- ⬜ **[S]** Tier-2 dependency-graph (GNN) model — the advisor's "go beyond RF."

### System & usability
- ✅ **[E]** Throughput / performance characterization — `experiments/performance.py`.
- ✅ **[E]** One-command reproducibility package — `scripts/reproduce.sh`.
- ✅ **[S]** CI (tests on push) — `.github/workflows/tests.yml`.
- ✅ **[E]** Analyst-facing interface beyond CLI text/JSON — `demo/server.py` (local web UI).

### Academic deliverables
- ⬜ **[E]** Final report / thesis (much raw material exists in `docs/`).
- ⬜ **[E]** End-sem panel presentation.
- ⬜ **[E]** Limitations & threats-to-validity section (drafted in PROJECT_REPORT §17).
- ⬜ **[S]** Paper draft.

**Recommended order:** scale + real-malicious data → evaluation rigor → method completeness → graph
model → report & presentation.

---

## 7. Changelog (newest first)

- **2026-11-07** — **P1 weaponiser parity (steps 1 + 2).**
  **(1) Two new families.** Registered the real-grounded payload families that were drafted but
  inert in `engine/weaponiser/payloads.py`: **`history_exfil`** (DataSpii browsing-data
  exfiltration — the single most common real malicious-update behaviour, 14/20 of the labelled
  Two Heads samples) and **`ad_affiliate`** (affiliate-link replacement / redirect). Weaponiser
  now ships **5 families** (was 3), each injecting cleanly in clean + obfuscated form,
  MV2/MV3-safe. `demo/build_weaponised_pairs.py` gains `--family`.
  **(2) Evasion layer.** `weaponise(evasion=True)` layers the OPSEC we actually captured from
  real malware in P0 onto any family: **IP-recon fingerprinting** and **DNS-over-HTTPS exfil
  tunnelling**. Endpoints are `.test` stand-ins for the real `api.ipify.org` / `dns.google`
  hosts, registered in `testsite.COLLECTOR_HOSTS`, so the behaviour (a distinct IP-recon host +
  a `application/dns-message` POST) is reproduced with **nothing leaving the machine** —
  directly answering "synthetic malware has no evasion" with behaviours taken from captures.
  `--evasion` flag on the demo builder. Obfuscation now also hides the DoH/IP-recon URL
  literals. Added two end-to-end tests; full suite **233 passed / 38 skipped**. Next (step 3,
  Mac): rebuild weaponised pairs with the new families + evasion, re-capture, fold into the
  dataset, retrain.
- **2026-11-06** — **Real-data acquisition (P0).** Pivoted off the "real malicious data is
  unobtainable" assumption using the Gemini research (`Researches/`, digested in
  `docs/research/P0_DATA_ACQUISITION.md`). Built `engine/collector/wayback.py` (Internet-Archive
  recovery — honest negative result: IA holds no CRX binaries) and `engine/collector/edge.py`
  (Edge store still serves extensions removed from Chrome). Harvested **18 real malicious
  extensions** (Two Heads Edge set + still-live mallorybowes) via
  `experiments/harvest_real_malicious.py`. Added a **`seal_all` sandbox mode** (host-resolver
  maps every hostname to the local collector so real malware cannot phone home) and ran them:
  `experiments/capture_real_malicious.py` → **14/17 flagged, 19 real backends intercepted**.
  Retrained the model on the current dataset and switched bake-off selection to **FPR-primary**
  → winner **XGBoost** (FPR@90 0.011). `.gitignore` hardened to a blanket `data/real/*` (malware
  never committable). 231 tests pass.
- **2026-11-03** — Demo upgrade for the mid-sem review. (1) The front end now runs real
  published extensions (21 AMO pairs) and **weaponised-real pairs** — a real extension plus one
  injected documented attack (cookie-jar theft/exfil) as N+1, built by
  `demo/build_weaponised_pairs.py`; both corpora are git-ignored and discovered at runtime.
  MV3 pairs (Old Reddit Redirect, FoxyProxy) come out MALICIOUS with the exfil proven by the
  collector. (2) Each run produces a one-page HTML/PDF **report** (`demo/report.py`,
  `/api/report`) stating the verdict, what the update is doing, the indicators, and the declared
  capability change. (3) UI redesign: one-click loadouts, an accent colour and a prominent action,
  and a version-vs-version **bar chart**. (4) `host_of()` no longer counts the extension's own
  `chrome-extension://` origin as a network host (it changes per load), which had made every real
  pair report phantom host churn. (5) The sealed collector now answers CORS preflight, so
  content-script beacons actually land. (6) `docs/DEMO_BRIEF.pdf` — the run-of-show + talking
  points for the review. Full suite 231 passed / 38 skipped.
- **2026-11-03** — Capture determinism fix: the prelude buffers every report and re-posts it at
  t+2s and t+6s; `capture.py` and `proxy.py` drop repeats by `(realm_id, report_seq)`. Before the
  fix, 1 run in 4 of an unchanged extension lost `chrome.runtime.onMessage.addListener` and so
  produced a spurious behavioural difference; after it, 5/5 runs of both `readerlite/1.0.0` and
  `readerlite/1.1.0` are byte-identical in their behaviour key sets.
- **2026-11-03** — Added `demo/`: a dependency-free local web front end that takes two packages,
  runs the real pipeline, and shows stages, per-version behaviour with the new rows marked, the
  collector's ground-truth log and the explained verdict. Run-of-show in `docs/DEMO_MANUAL.md`.
- **2026-11-03** — Merged the Docker analysis pipeline branch into `main`.
- **2026-11-02** — Docker analysis pipeline: hardened sandbox, mitmproxy gateway, marker-based
  exfiltration evidence, attribution, behaviour diff, 0-100 risk score with ML combination, JSON /
  Markdown / HTML reports, controlled test extensions, end-to-end tests. See `docs/SANDBOX.md`.
- **2026-09-21** — P3 done: Chromium engine validated on a real MV3 extension (`9509109`) + P7
  performance characterization (`c3fb8ba`). All laptop-only essentials complete.
- **2026-09-21** — P5 adware sub-study (`3a91346`); report updated with rigor results (`41ad263`);
  P7 CI + `scripts/reproduce.sh` (`fe3ada0`).
- **2026-09-21** — P1 essentials done: You've Changed head-to-head on real code (static clean
  21/21, obfuscated 0/21) (`6d9212a`); held-out test + operating point (PR-AUC 0.976) (`fd6ae30`);
  anomaly-on-real (93% detect / ROC-AUC 0.989) (`fcb56bd`).
- **2026-09-21** — Mac hand-off: resumable captures, `scripts/scale_capture.sh`, `docs/MAC_RUNBOOK.md`,
  `.gitattributes` (LF for scripts) (`3b3f54d`).
- **2026-09-21** — P1 started: `experiments/statistical_rigor.py` — bootstrap 95% CIs + ML-vs-rules
  significance (HistGB 0.983 [0.976, 0.989] vs rules 0.868; gain CI [0.093, 0.137], significant). (`23e7df9`)
- **2026-09-21** — Pushed `PROJECT_REPORT.md` to GitHub (`19a77b6`). STATUS.md kept local.
- **2026-09-21** — Added `PROJECT_REPORT.md` (full knowledge document) and this `STATUS.md`.
- **2026-09-21** — Scaled real captures to 15 extensions (45 real pairs); dataset → 1,047 rows;
  synthetic→real transfer PR-AUC 0.998 on 45 held-out real rows. (`8c2fe97`)
- **2026-09-21** — Chrome pair-feasibility: 0/15 live-malicious IDs have archived predecessors →
  real malicious pairs infeasible; documented. (`chrome_delisting_probe --history`)
- **2026-09-21** — extensiondeltas fold-in: adopted You've Changed discriminative-API tokens into
  `static_code.py` (23→27 features); real-static PR-AUC → 1.0. (`2b4e510`)
- **2026-09-20** — Chrome Web Store CRX collector + delisting probe (~40% live / ~60% delisted).
- **2026-09-19** — HoneyPage/Hulk scenario + isolated-world realm fix (real recall 70% → 100%);
  first real behavioural dataset; Firefox engine built and validated.
- **earlier** — synthetic generator, weaponiser, feature extractor, rules, ML bake-off, anomaly
  layer, AMO collector, ablations, Chromium engine, README.

---

<sub>Maintenance: when you add/change/remove a feature, update the matching row above (status +
file), refresh the "Last updated / dataset / results" header, and prepend a Changelog line.</sub>
