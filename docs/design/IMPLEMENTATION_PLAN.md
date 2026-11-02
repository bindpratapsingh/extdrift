# extdrift — Full Implementation Plan (scratch → end)

**Owner team:** Bind (infrastructure) · Suhani (data & ML) · **Advisor:** Dr. Sweta Mishra
**Decided scope (this semester / Project-1):** **Focused core** — Chromium only; hybrid
static+dynamic capture; **dual/triple scoring** (rules + ML bake-off + anomaly layer); rigorous
evaluation incl. the **obfuscation head-to-head** and the **determinism ablation**. Firefox and
deep sequence/graph models are **Project-2**.
**Data decision:** build a small **collector and start snapshotting real benign pairs now**.
**Replay decision:** keep the **synthetic deterministic test-site** now; **mitmproxy real-site
replay is stretch.**
**Near-term anchor:** next advisor meeting (**~2–3 weeks**) → Phase 0 + start of Phase 1.

> This plan is the execution contract. We build it **step by step**; each step has concrete
> files, acceptance criteria, and a verification. Nothing here gets committed/pushed without an
> explicit instruction.

---

## 0. Invariants — the aspects to hold in mind at *every* step

These are non-negotiable design rules; every step is checked against them.

1. **Score the *change*, not the extension** — everything operates on `Δ = f(T_v2) − f(T_v1)`.
2. **Determinism is load-bearing** — both versions must see byte-identical input (synthetic
   test-site now; mitmproxy later). Never diff two runs against different inputs.
3. **Explainability always** — every verdict lists fired rules + (for ML) SHAP attribution.
4. **Honest scoping** — we detect *malicious behavioural change*. We do **not** claim: zero-day
   *vulnerability* discovery, consumer pre-execution prevention, or language-aware detection.
5. **No data leakage** — **extension-level** and **time-based** splits only (§Phase 3/eval).
6. **False-positive rate is the headline metric** — report PR-AUC + FPR@fixed-recall, not accuracy.
7. **Ground truth** — the fake collector's log independently confirms real exfiltration.
8. **ML must earn its place** — the learned model is reported only if it beats the rule baseline.
9. **Safety** — only synthetic/self-contained malware, egress-blocked, `.test` hosts to loopback,
   dummy credentials, no redistribution.
10. **Hardware split** — heavy capture + ML training on the **MacBook**; the pure-stdlib analysis
    half runs anywhere (the 4 GB laptop is fine for coding, dataset labelling, rules, reports).

---

## 1. What already exists (Phases A–D of the old roadmap — DONE)

Foundation is built and green (72 tests). Reuse these; do not rebuild.

| Capability | Module / function |
|---|---|
| `.crx`/`.xpi` unpack + safe unzip | `engine/unpack/crx.py` → `unpack_extension()` |
| Manifest normalise + permission diff | `engine/unpack/manifest.py` → `diff_manifests()` |
| Trace schema + validator | `engine/features/schema.py` |
| Instrumented live capture (Playwright, MV3 SW, egress-blocked) | `engine/sandbox/capture.py` → `capture()`; `rewrite.py` → `instrument_extension()`; `prelude.js`; `testsite.py` → `TestSite`; `scenarios.py` |
| 24 features + Δ | `engine/features/extract.py` → `extract_features()`, `FEATURE_ORDER`; `delta.py` → `behavioral_delta()`, `delta_vector()` |
| 12 explainable rules | `engine/scoring/rules.py` → `score_delta()` |
| Text + JSON report | `engine/report/render.py` |
| One-pair orchestration | `engine/runner.py` → `run_pair()` |
| CLI | `engine/cli.py` (`run-pair`, `diff`, `features`, `rules`, `unpack`, `manifest-diff`, `validate`) |

**The gap this plan fills:** dataset engine (real + synthetic at scale), batch capture → dataset
table, the **ML tier** (`engine/ml/`), the **anomaly layer**, a **static code-delta baseline**,
the **evaluation harness** (head-to-head + ablation + metrics), and doc reconciliation.

---

## PHASE 0 — Reconcile the meeting packet (for the ~2–3 week meeting) · **owner: both**

Make every meeting doc tell the *same* story as the Part I/II research (narrow + reframe; the two
corrections). **Pure doc edits, no code.**

- **Fix the Karami citation** everywhere it appears (`docs/literature/LITERATURE_REVIEW.md`,
  `docs/meeting/CORE_PAPERS_AND_STRATEGY.md`, `docs/meeting/TALKING_POINTS.md`,
  `engine/sandbox/scenarios.py` docstring comment): recharacterise as *web* service workers, or
  cite Chrome MV3 docs — remove the "MV3 extension SW" mischaracterisation.
- **Add "You've Changed (CCS 2020)" as the closest prior work** and state our wedge as *dynamic +
  deterministic + obfuscation-resistant* update-diffing, in `LITERATURE_REVIEW.md`,
  `CORE_PAPERS_AND_STRATEGY.md`, `METHODOLOGY.md`, `README.md`.
- **Drop the two overreaches** ("language-aware analysis"; "consumer pre-execution prevention")
  and reframe positioning as **store/enterprise/researcher** across `README.md`, `METHODOLOGY.md`,
  `CORE_PAPERS_AND_STRATEGY.md`.
- **State the ML plan as a bake-off** (not assumed XGBoost) and add the **no-zero-day** boundary in
  `METHODOLOGY.md` and `ML_Models_Research.md` cross-refs.
- **Acceptance:** a reader moving across README → literature → methodology → talking points → Part
  I/II PDFs finds no contradiction; the Karami cite is correct or replaced everywhere.

---

## PHASE 1 — Dataset engine (real collector + synthetic weaponiser) · **owner: Bind builds, Suhani labels**

Two new packages. Start real collection **immediately** so pairs accrue over the semester.

### 1a. `engine/collector/` — obtain real version pairs
- `github.py` — download two consecutive **tagged releases** of open-source extensions (build/zip
  → unpacked dirs). Seed list: uBlock Origin, Dark Reader, Stylus, Privacy Badger, Vimium, etc.
- `crx.py` — download historical `.crx` (Google update endpoint for current; **crx4chrome** for old
  versions), reuse `unpack_extension()`.
- `snapshot.py` — copy currently-installed extensions from the Chrome profile dir
  (`.../Default/Extensions/<id>/<version>/`); re-run weekly to catch **real auto-updates** → real
  benign N→N+1 pairs.
- `corpus.py` — a **corpus manifest** (`data/corpus/manifest.jsonl`): one row per pair
  `{pair_id, ext_id, name, v1, v2, source, label, obfuscated?, collected_at}`. Labels: `benign`
  (real updates) / `malicious` (synthetic) / `unknown` (real, unlabelled).
- **Acceptance:** `python -m engine.collector github <repo> <tagA> <tagB>` produces two unpacked
  dirs + a manifest row; ≥ 5 real benign pairs collected in week 1.

### 1b. `engine/weaponiser/` — generate labelled malicious pairs at scale
Take any benign `v1`, inject a known payload → labelled malicious `v2`. This is our training breadth.
- `payloads/` — a **family library**, each with a clean and an **obfuscated** variant (for the
  head-to-head): `cookie_theft`, `credential_theft`, `sw_beacon` (MV3), `ad_affiliate_inject`,
  `keylogger`, `history_exfil`.
- `inject.py` — insert the payload into the extension's content script / service worker, rewrite
  the manifest if the payload needs a permission (mark the escalation), keep everything else
  byte-identical to `v1`. Every output is clearly stamped **SYNTHETIC**.
- `obfuscate.py` — a light obfuscator (string-encode, eval-decode, dead-code) applied to the
  payload variant so a *static* diff can't read intent but the *runtime effect* is unchanged.
- **Acceptance:** from one benign base, generate ≥ 6 malicious pairs (one per family) + their
  obfuscated twins; each still exfiltrates to the local collector when captured.

### 1c. Assemble the working corpus
- Target for the semester: **~30–50 real benign pairs**, **~40–80 synthetic malicious pairs**
  (families × bases × {clean, obfuscated}), + the **reconstructed Cyberhaven** anchor.
- **Safety review** of every synthetic sample before it lands in `data/corpus/`.

---

## PHASE 2 — Batch capture → feature dataset · **owner: Bind (runs on MacBook)**

Turn the corpus into the ML-ready table.

- `engine/batch.py` — iterate the manifest; for each pair call the existing `capture()` for `v1`
  and `v2` under a fixed scenario, compute `behavioral_delta()` + `diff_manifests()`, and append a
  row: `[pair_id, ext_id, collected_at, source, label, obfuscated, <24 Δ features>, <static-diff
  features>]` → `data/dataset/deltas.parquet` (+ CSV mirror).
- Keep the raw traces + `report.json` per pair for auditing and the ground-truth collector log.
- Parallelise across browser instances on the MacBook; each pair is independent.
- **Acceptance:** `python -m engine.batch data/corpus/manifest.jsonl` produces `deltas.parquet`
  with one clean row per pair, `ext_id` + `collected_at` present for grouped/time splits, and the
  synthetic-malicious rows show non-zero exfil features.

---

## PHASE 3 — The ML tier: the bake-off + anomaly layer · **owner: Suhani (MacBook)**

New package `engine/ml/`. This is the direct answer to the professor's "why this model / prove it".

### 3a. Task (fixed, precise)
`Input:` a pair `(v1, v2)` → `Features:` the Δ vector (+ static-diff features) →
`Model:` bake-off winner → `Prediction:` `P(update introduced malicious behavioural change) ∈ [0,1]`
→ `Action:` rank/flag + explain. **Binary classification of an update-pair.** Not "is this
extension malicious", not vulnerability discovery.

### 3b. The bake-off (`engine/ml/bakeoff.py`)
- Candidates on the **same Δ features**: **rules-as-classifier** (wrap `score_delta`, the control),
  **Logistic Regression** (floor), **Random Forest**, **XGBoost/LightGBM**, **SVM (RBF)**.
- **Cross-validation:** `sklearn` **GroupKFold by `ext_id`** (extension-level, no leakage) **and** a
  separate **time-based split** (train older, test newer) to expose concept drift.
- **Imbalance:** class weights / stratification; report on the natural (imbalanced) distribution.
- **Metrics:** accuracy, precision, recall, F1, ROC-AUC, **PR-AUC**, confusion matrix, and
  **FPR at fixed recall (e.g. 0.90)**. **Selection rule: highest PR-AUC subject to acceptable FPR.**
- **Explainability:** SHAP on the winner (`engine/ml/explain.py`).
- **Persistence:** save the winner + its metrics card (`engine/ml/models/`).

### 3c. Anomaly layer for novelty (`engine/ml/anomaly.py`)
- Train **IsolationForest / One-Class SVM / a small autoencoder** on **benign Δ only** → flag
  updates whose behavioural delta is anomalous vs normal benign updates (catches *unseen* malicious
  changes without a matching training label). Report separately; never claim zero-day *vuln* finding.

### 3d. Integrate into the report
- Extend `engine/report/render.py` to show **three signals**: rule score, ML probability, anomaly
  flag — plus their **agreement** (a confidence signal). Reuse `FEATURE_DOCS` provenance for SHAP
  labels.
- **Acceptance:** `python -m engine.ml.bakeoff data/dataset/deltas.parquet` prints the full metrics
  table, saves the winner, and a report on any pair now shows rule+ML+anomaly with SHAP.

---

## PHASE 4 — Static baseline + the two proof experiments · **owner: both**

This is what demonstrates *added value over the closest prior work* — the professor's key test.

### 4a. Static code-delta baseline (`engine/baseline/static_delta.py`)
A deliberately *static*, "You've-Changed-style" scorer: unzip both versions, diff the JS, flag
**added calls to abused APIs** (`cookies`, `webRequest`, `fetch` to new hosts in source, etc.). No
runtime. This is the thing we out-perform.

### 4b. Experiment A — obfuscation head-to-head (`experiments/headtohead.py`)
On the **obfuscated** synthetic pairs: show the **static baseline misses / mis-scores** them while
our **dynamic behavioural diff still flags** them (runtime effect is observable regardless of code
form). Output a table + a short write-up.

### 4c. Experiment B — determinism ablation (`experiments/ablation.py`)
On **real benign** pairs: measure **false-positive rate with vs. without record/replay determinism**
(run once against the fixed synthetic site, once against a deliberately noisy/varying page). Show
determinism drives FPs toward zero. Needs **no malicious data** — a clean, self-contained result.

### 4d. Evaluation report (`experiments/report.py`)
PR curves, confusion matrix, FPR bars, the head-to-head table, the ablation table → figures for the
write-up. **Acceptance:** both experiments reproduce with one command each and produce the figures.

---

## PHASE 5 — Hardening, optional dashboard, write-up · **owner: both**

- Consolidate CLI (`run-pair` shows triple score; add `batch`, `bakeoff`, `headtohead`, `ablation`).
- **Optional** Streamlit demo (upload two versions → verdict + SHAP + evidence) for the final demo.
- Final evaluation pass on the full corpus; **paper/report draft** (positioned store/enterprise/
  researcher; cite You've Changed as the static predecessor).
- **Stretch (Project-2 / if time):** mitmproxy real-site record/replay; Firefox second engine;
  Tier-2 sequence/graph model.

---

## ML — what / how / why (one place, for the meeting)

- **What it predicts:** `P(malicious behavioural change | Δ)` for an update-pair. Decision-support,
  ranked + explained. **Cannot** prove intent, see untriggered payloads, or find code vulnerabilities.
- **Why these models:** our Δ is **tabular + small** → tree ensembles beat deep nets (Grinsztajn,
  NeurIPS 2022). Rules are the **control** ("is ML even needed?"). XGBoost is the **prior**, proven
  only if it wins the bake-off. Anomaly models handle **novel** malicious changes.
- **How chosen:** experimentally — GroupKFold(ext) + time-split, selected by **PR-AUC + FPR**, not
  by convention. Sequence/graph (the "more SOTA" representation change) = Project-2.

## Dataset — real + synthetic (one place)

- **Real benign pairs** (FP evaluation): GitHub tagged releases (guaranteed) + crx4chrome archives +
  weekly self-snapshots → **start now**.
- **Synthetic malicious pairs** (detection training/breadth): the weaponiser (§1b) — families ×
  bases × {clean, obfuscated}, always stamped SYNTHETIC, collector-verified.
- **Real anchors** (external validity): reconstructed Cyberhaven + IDs from `mallorybowes/
  chrome-mal-ids` where a prior benign version is archivable.
- **No public labelled update-pair dataset exists → we construct our own.** Synthetic-train /
  real-validate is the honest framing.

## How each Phase answers the professor

| Professor ask | Addressed by |
|---|---|
| Reproduce SOTA first, then improve | Rules + static baseline (§4a) reproduced; ML bake-off + dynamic diff improve on them |
| Beyond Random Forest / why this model | Bake-off (§3b), evidence-based selection |
| Get the heuristics / why ML | 12 rules (built) as control; ML must beat them (§3) |
| Multiple browsers | Chromium family now; Firefox = Project-2 (confirm with advisor) |
| Real dataset / prove it | Collector (§1a) + weaponiser (§1b); FP metric on real pairs |
| Beyond Cyberhaven / recurring problem | Corpus spans multiple incident types; Part II evidence |
| Detect unknown threats | Anomaly layer (§3c) — behaviour-novelty, not zero-day vuln |
| Static vs dynamic / honeytrap | Hybrid: thin static + dynamic + deterministic deception site (§Invariants, §4) |
| Explainability | Rules + SHAP in the report (§3d) |

## What we need from you (Bind & Suhani)

1. **Start the snapshot pipeline this week** — pick ~15 installed extensions to watch; we script the
   weekly copy. (Real auto-updates take weeks to appear — starting now is the highest-leverage action.)
2. **MacBook** designated for heavy capture + ML runs; install deps there
   (`pip install -r requirements.txt && playwright install chromium`, plus `scikit-learn xgboost
   shap pandas pyarrow`).
3. **Confirm with the advisor** whether Firefox is expected this semester or is Project-2 (affects
   workload; our plan assumes Project-2).
4. **Pick the payload families** you want to prioritise for the weaponiser (default: the 6 listed).
5. **Grab 2–3 open-source extension release pairs** from GitHub now to seed Phase 1/2 before
   auto-updates arrive.
6. Decide if the **optional Streamlit dashboard** is wanted for the final demo.

## Division of work

- **Bind (infra):** collector (§1a), weaponiser/obfuscator (§1b), batch capture (§2), static
  baseline (§4a), experiment harnesses (§4b/c), CLI.
- **Suhani (data & ML):** corpus labelling & safety review (§1c), the ML bake-off + anomaly + SHAP
  (§3), metrics & evaluation report (§4d), the write-up's results section.

## Verification (per phase)

- **Every phase:** the existing 72 tests stay green; new modules ship with unit tests (stdlib
  `unittest`, matching current style).
- **Phase 1:** collector produces valid unpacked pairs + manifest rows; each synthetic sample, when
  captured, actually reaches the local collector (ground-truth check).
- **Phase 2:** `deltas.parquet` has correct shape, `ext_id`/`collected_at` populated, malicious rows
  show exfil features > 0, benign rows near-zero.
- **Phase 3:** bake-off runs GroupKFold + time-split, prints all metrics; the winner beats the rule
  baseline on PR-AUC **or** we honestly report it does not; SHAP renders.
- **Phase 4:** head-to-head shows static-miss / dynamic-catch on obfuscated pairs; ablation shows
  FPR drop with determinism; figures regenerate from one command each.
- **Phase 5:** end-to-end `run-pair` shows triple score + SHAP; optional dashboard loads; report
  draft compiles.

## Risks & mitigations

- **Real auto-updates may not arrive in time** → seed with GitHub release pairs + crx4chrome now;
  don't depend solely on snapshots.
- **Synthetic corpus over-fitting** → obfuscated + multi-family + real-validate; report FPR on real
  benign pairs as the headline.
- **ML doesn't beat rules at small scale** → that's a *valid, honest finding*; the determinism
  ablation + head-to-head stand on their own.
- **Capture flakiness on real extensions** (build failures, MV2/MV3 quirks) → the pipeline skips and
  logs a bad pair rather than aborting the batch.

## Timeline

- **Now → next meeting (~2–3 wks):** Phase 0 (reconcile docs) + stand up Phase 1a collector, start
  snapshots, seed 5–10 real pairs; present Part I/II + the reconciled packet + the working prototype.
- **Weeks 3–5:** finish Phase 1 (weaponiser) + Phase 2 (batch dataset).
- **Weeks 6–8:** Phase 3 (bake-off + anomaly + SHAP + report integration).
- **Weeks 9–11:** Phase 4 (static baseline + head-to-head + ablation + eval report).
- **Weeks 11–13:** Phase 5 (hardening, optional dashboard, write-up); stretch if time.
