# CSD493 Progress Report — extdrift

**Project:** Behavioural-Diff Detection of Malicious Browser-Extension Updates
**Team:** Bind Pratap Singh (2310110084) · Suhani Deepak Agrawat (2310110717)
**Advisor:** Dr. Sweta Mishra · **Specialisation:** Cybersecurity
**Reporting period:** ~25 working days since proposal approval · **Prepared:** August 2026

---

## TL;DR for the meeting

We moved from an approved proposal to a **working, tested prototype**. The core pipeline
runs **end-to-end on a real browser**: it loads two versions of an extension, drives an
identical scripted user session against deterministic pages, records what each version
actually does across four channels, diffs them, and emits an **explainable verdict**.

On our first real test pair it correctly returns:
- **MALICIOUS (0.99)** for a weaponised update that steals credentials + cookies — and the
  independent ground-truth collector confirms the data really left the browser;
- **BENIGN (0.25)** for a genuine feature update — no false alarm.

**~3,100 lines of Python + ~300 lines of instrumentation JS, 72 automated tests, all
green** (including 2 that launch a real Chromium and verify the full pipeline).

---

## 1. What we were asked to show today

From the advisor's notes and our approval thread, the questions to answer are:
1. What research have we done — which papers, how do they work, what are their gaps?
2. What is our strategy going forward?
3. Have we implemented anything?

This report answers all three. The short version: **literature reviewed and mapped to a
concrete design; strategy is reproduce-then-improve with a tiered model plan; and yes —
the infrastructure and the heuristic detector are implemented and demonstrably working.**

## 2. Research done (Q1)

We studied and wrote up **7 papers** spanning the static → dynamic → ML arc of extension
security, each analysed for *how it works*, *its limitation*, and *what we take or fix*.
Full detail in **[../literature/LITERATURE_REVIEW.md](../literature/LITERATURE_REVIEW.md)**.
Headlines:

- **VEX (USENIX 2010)** — static analysis; blind to runtime/obfuscated payloads → we go
  dynamic.
- **Hulk (USENIX 2014)** — elicits hidden behaviour by fuzzing; single-version,
  non-deterministic → we add version-diffing + determinism.
- **ExtPrivA (IEEE S&P 2023, our base paper)** — emulate interaction, watch network,
  attribute initiator; **single-version** → **we lift it to the update setting**.
- **Karami (NDSS 2021)** — MV3 service workers leak with no page → we instrument the SW and
  detect it (rule R09).
- **WRIT (IEEE TDSC 2024)** — request-integrity → motivates our encoded-payload rule.
- **"It's not Easy" (2025)** — 98% lab accuracy, useless in the wild (FP explosion) → the
  bottleneck is determinism/data, **not** the model → shapes our priorities.
- **Grinsztajn (NeurIPS 2022)** — trees beat deep nets on tabular data → justifies our
  tiered model choice.

**The gap we own:** every one of these analyses a *single version*. The real threat is a
*malicious update* to a trusted extension (Cyberhaven, Dec 2024, ~400k users in hours).
**No open framework does update-aware behavioural diffing with record/replay determinism
and explainable output.** That is our thesis.

## 3. Strategy going forward (Q2)

**Reproduce, then improve** — exactly as advised:

- **Tier 1 (baseline, this semester):** transparent weighted rules *(done)* → Random Forest
  → **XGBoost** (tabular SOTA) + SHAP. The rules double as the "why is ML needed at all?"
  control.
- **Tier 2 (novelty, stretch):** change the *representation* to a **sequence** (Transformer/
  BiLSTM) or **data-flow graph** (GNN), then **diff across versions** — the genuinely
  publishable contribution. Our trace schema already timestamps every event for this.

Detail and rationale in **[../design/METHODOLOGY.md](../design/METHODOLOGY.md)** and
**[../../Reference Docs/ML_Models_Research.md](../../Reference%20Docs/ML_Models_Research.md)**.

## 4. What we implemented (Q3) — the part that proves progress

### 4.1 A runnable system, not slideware

| Component | Module | Status |
|---|---|---|
| `.crx`/`.xpi` unpacker (CRX2+CRX3, Zip-Slip-safe) | `engine/unpack/crx.py` | ✅ done, tested |
| Manifest normalise + static permission diff | `engine/unpack/manifest.py` | ✅ done, tested |
| Trace schema + validator | `engine/features/schema.py` | ✅ done, tested |
| Browser instrumentation (DOM/cookie/storage/API, incl. service worker) | `engine/sandbox/prelude.js` | ✅ done |
| Deterministic sandbox run (Playwright, egress-blocked, scripted user) | `engine/sandbox/capture.py`, `scenarios.py`, `testsite.py` | ✅ done |
| Feature extraction `f(·)` — 24 features, each cited to a paper | `engine/features/extract.py` | ✅ done, tested |
| Behavioural delta `Δ = f(T2) − f(T1)` | `engine/features/delta.py` | ✅ done, tested |
| Heuristic scorer — 12 weighted rules, explainable | `engine/scoring/rules.py` | ✅ done, tested |
| Report renderer (text + JSON) | `engine/report/render.py` | ✅ done, tested |
| CLI (`diff`, `run-pair`, `features`, `rules`, `unpack`, `manifest-diff`, `validate`) | `engine/cli.py` | ✅ done |
| End-to-end orchestrator | `engine/runner.py` | ✅ done |
| Test suite | `tests/` | ✅ 72 tests green |

Maps onto the implementation guide's Phase A → D (foundations, first trace, diff,
determinism/sandbox) — **complete**. Phases E (ML) and F (dashboard, Firefox, evaluation)
are next.

### 4.2 The live demo (this is the headline)

We wrote a small **real, benign** extension (*Reader Lite v1.0.0*) and two updates of it:
- **v1.0.1** — a harmless "reading-time badge" feature (the benign-update case);
- **v1.1.0** — a **synthetically weaponised** update whose injected payload harvests the
  login form, dumps the cookie jar from the **service worker**, and beacons it to a
  collector — modelled on the Cyberhaven attack.

Running the pipeline on each pair:

```
$ python -m engine.cli run-pair data/corpus/readerlite/1.0.0 data/corpus/readerlite/1.1.0

  VERDICT   : MALICIOUS   Score 0.99   (6/12 rules fired)
  [R01] New exfiltration flow → collect-analytics.test
  [R02] New bulk cookie read (getAll)
  [R03] New credential-field access: input#password
  [R09] MV3 service worker beaconing to a new host
  ...
  [ground truth] collector received data: True     ← the leak really happened
```
```
$ python -m engine.cli run-pair data/corpus/readerlite/1.0.0 data/corpus/readerlite/1.0.1

  VERDICT   : BENIGN      Score 0.25   (1/12 rules fired)
  [ground truth] collector received data: False    ← no false alarm
```

Reproduce in two commands: `python scripts/demo.py` (live, needs Chromium) or
`python scripts/demo_offline.py` (no browser). A third, **gray-zone** fixture (a scraper
that starts sending contacts to a new partner) lands at **SUSPICIOUS (0.68)** — showing the
detector is not a blunt yes/no.

### 4.3 Why the results are trustworthy

- **Determinism:** both versions see byte-identical pages from an in-process test site, so
  the diff reflects the *extension*, not web noise — the fix for the 2025 FP problem.
- **Egress control:** all `.test` hosts resolve only to loopback; nothing leaves the
  machine, so we can run real malicious behaviour safely.
- **Ground truth:** the fake collector logs exactly what was exfiltrated, so verdicts are
  checked against reality, not just our own labels.
- **Explainability:** every verdict lists the rules that fired and the paper each came from.
- **Honesty:** the report states its own caveats (rule weights are uncalibrated priors;
  exfil flows are temporal-adjacency candidates, not proven taint).

## 5. Division of work so far

- **Bind (infrastructure):** unpacker, sandbox capture, service-worker + DOM instrumentation,
  deterministic test site, trace schema, CLI/orchestration, test harness.
- **Suhani (data & ML):** feature catalogue and provenance, rule design and weighting, the
  synthetic weaponisation corpus, scoring/report logic; leading the RF/XGBoost tier next.

## 6. Risks and honest gaps

- **Real update-pair scarcity** → synthetic-train / real-validate strategy (stated, not
  hidden).
- **Hardware:** heavy browser runs target the Mac / a cloud VM; Bind's i3/4 GB laptop runs
  the pure-stdlib analysis half (which needs nothing installed).
- **Instrumentation perturbs the sample** (static prelude injection) → both versions get
  identical treatment and the change is recorded in every trace and report.
- **Real-site replay** (mitmproxy) is the next determinism step beyond the in-process site.

## 7. Next 3–4 weeks

1. mitmproxy **record/replay** for real sites (Phase D completion).
2. Grow the synthetic corpus (more payload families: keylogging, ad-injection, affiliate
   hijack) and add 2–3 **real** incident pairs as held-out validation.
3. **Random Forest + XGBoost + SHAP** on the delta vectors; compare against the rule
   baseline (reproduce-then-improve, measured on FPR).
4. Begin the **Firefox** second engine via Playwright.

---

*Everything above is in the repository and reproducible today: `python scripts/demo_offline.py`
for the browser-free proof, `python -m unittest discover -s tests` for the 72-test suite.*
