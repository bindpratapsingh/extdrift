# extdrift — Build Status (living document)

> **This is a living document. Update it on every change** — whenever a feature is added, changed,
> or removed, edit the relevant row and add a dated line to the Changelog at the bottom. Keep it in
> sync with the code; it is the single place to see "what exists and what's left" at a glance.
> The full narrative is in [PROJECT_REPORT.md](PROJECT_REPORT.md).

**Last updated:** 2026-09-21 · **at commit:** `6d9212a` · **tests:** 111 passing · **dataset:**
1,047 pairs (1,000 synthetic + 45 real + 2 fixtures), 266 extensions.

**Active priority:** P1 — evaluation rigor: **essentials done** (CIs, anomaly-on-real, held-out +
operating point, You've Changed head-to-head). Next: P3 (Chromium-on-real, MV3) + P7 (reproducibility/CI). See §6.

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
| Chromium capture engine (Playwright) | 🟡 | `engine/sandbox/capture.py` — validated on synthetic + fixture; **not yet on real extensions** |
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

## 2. Built — data generation

| Component | Status | Where |
|---|:--:|---|
| Synthetic generator (12 personas, 9 families, hard overlap) | ✅ | `engine/synth/generate.py` |
| Weaponiser (real payloads, clean + obfuscated, MV2-safe) | ✅ | `engine/weaponiser/` |
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

## 5. Current dataset & headline results

- **Behavioural dataset:** 1,047 pairs · 266 extensions · 449 malicious / 598 benign
  (1,000 synthetic + 30 weaponised-real + 15 real-benign + 2 fixtures).
- **Static-code track:** 40 rows · 10 real extensions.
- **Bake-off winner:** HistGradientBoosting, PR-AUC 0.983, FPR@90%-recall 0.008 (rules: 0.868 / 0.450).
- **Synthetic→real held-out transfer:** PR-AUC 0.998, recall 0.93, precision 1.0, 0% FPR.
- **Rules on real weaponised:** 30/30 = 100% recall.

---

## 6. Remaining — to fully complete the project

**[E]** = essential to call it complete · **[S]** = stretch · **[❌]** = blocked (reason given).

### Data
- ⬜ **[E]** Scale real benign corpus to hundreds of pairs (infra ready; compute time — Mac helps).
- ⬜ **[E]** Capture genuinely-malicious *live* Chrome extensions in the sealed sandbox as real samples.
- ⬜ **[E]** Adware-specific sub-study (known adware IDs + `sc_ad_inject` features), reported separately.
- ❌ Real malicious *update pairs* — **blocked:** no public source (60% delisted; 0/15 archived). Documented; weaponise substitute stands.

### Method completeness
- ⬜ **[E]** Validate the Chromium engine on real extensions (currently synthetic + fixture only).
- ⬜ **[E]** Verify MV3 service-worker capture on real MV3 extensions end-to-end.
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
- ⬜ **[E]** Throughput / performance characterization (extensions per hour, bottlenecks).
- ⬜ **[E]** One-command reproducibility package (reproduce every figure/number).
- ⬜ **[S]** Analyst-facing report dashboard beyond CLI text/JSON.
- ⬜ **[S]** CI (tests on push).

### Academic deliverables
- ⬜ **[E]** Final report / thesis (much raw material exists in `docs/`).
- ⬜ **[E]** End-sem panel presentation.
- ⬜ **[E]** Limitations & threats-to-validity section (drafted in PROJECT_REPORT §17).
- ⬜ **[S]** Paper draft.

**Recommended order:** scale + real-malicious data → evaluation rigor → method completeness → graph
model → report & presentation.

---

## 7. Changelog (newest first)

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
