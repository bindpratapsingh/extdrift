# Methodology — Reproduce, then Improve

**Advisor directives this document answers** (from `Reference Docs/Instructions.txt`):
1. Work across **multiple browsers**.
2. Go beyond **Random Forest** — consider a state-of-the-art model.
3. **Implement the existing state of the art first, reproduce its result, then compare and
   show improvement.**
4. Get the **heuristics**; understand the **malicious approach** on existing browsers;
   justify **why ML** is needed at all.
5. A clear **step-by-step** approach.

---

## 1. The pipeline (what is actually built)

```
 Extension v1 (baseline)     Extension v2 (candidate)
        │                            │
   unpack + instrument          unpack + instrument      engine/unpack, engine/sandbox/rewrite
        │                            │
   run in sandbox  ◄── identical ──► run in sandbox       engine/sandbox/capture + testsite
   (scripted user, deterministic pages, egress-blocked)
        │                            │
     Trace T1                     Trace T2                 4 channels: network/dom/storage/api
        └─────────────┬──────────────┘
             Δ = f(T2) − f(T1)                             engine/features
                       │
              ┌────────┴─────────┐
        Tier 1 rules        Tier 2 ML (planned)            engine/scoring  |  future engine/ml
        (heuristics)      (RF/XGBoost → seq/graph)
                       │
             explainable REPORT (+ JSON)                   engine/report
```

Determinism is the load-bearing idea. Browsing a real site twice differs on its own (ads,
nonces, timestamps), so a naive trace diff fills with noise. We fix the web the two
versions see — today via an in-process deterministic test site
(`engine/sandbox/testsite.py`) whose bytes are identical on every request and whose hosts
resolve only to loopback; next via mitmproxy record/replay for real sites. That leaves the
**extension version as the only variable**, which is what makes the diff meaningful. This
directly targets the false-positive problem the 2025 ML paper identified.

## 2. The four observation channels

| Channel | What it captures | Why it matters |
|---|---|---|
| `network` | every outbound request + its **initiator** (page / content-script / service-worker) | separates "the page fetched an ad" from "the extension uploaded your cookies" — ExtPrivA's core idea |
| `dom` | reads of form fields / `document.cookie`, node injection | credential and secret access |
| `storage` | cookie / localStorage / `chrome.storage` calls | session-token theft (Cyberhaven) |
| `api` | `chrome.*` / `browser.*` calls | capability use, incl. service-worker-only paths (Karami) |

## 3. Why heuristics *and* why ML (both, deliberately)

**Heuristics first (Tier 1, built).** 12 weighted rules over the delta
(`engine/scoring/rules.py`), each tied to a paper. They are the **control experiment for
ML**: a learned model only earns its place if it beats these rules on the same data. They
also work when labelled malicious pairs are scarce (which they are), and every fired rule
names the behaviour and its source — so a verdict is defensible line by line. Weights are
currently expert priors from the literature; the report says so explicitly.

**Why ML is nonetheless needed.** Rules are brittle at the boundary (the gray-zone case),
cannot weigh many weak signals as well as a fitted model, and cannot adapt to new payloads
without a human editing rules. The ML tier learns those weightings from data and gives a
calibrated probability to complement the transparent score.

## 4. The model plan — reproduce, then improve (directive #3)

This is a two-tier plan so we can *reproduce a baseline first* and *then* show improvement.

**Tier 1 — reproducible baseline (must-have this semester).**
- Weighted-rule scorer (done) = the heuristics + the "why ML?" control.
- **Random Forest** — the standard explainable tabular baseline.
- **XGBoost/LightGBM** — the tabular **state of the art** (Grinsztajn 2022); a trivial add
  that already answers "why not something better than Random Forest?".
- **SHAP** for per-verdict feature attribution.
- Evaluation: train on the synthetic corpus, validate on held-out real incident pairs;
  report precision/recall/AUC and, critically, **false-positive rate** vs the rule baseline.

**Tier 2 — the "more state-of-the-art" model + our novelty (stretch / Phase 2).**
The frontier is not a fancier tabular model — it is **changing the representation**:
- **Sequence:** turn each trace into an ordered event sequence (`read cookie → open socket
  → POST`) and run a small **Transformer/BiLSTM**. Our schema already timestamps every
  event for exactly this.
- **Graph:** build a data-flow graph (`cookie-read → variable → network-POST`) and run a
  **GNN/GCN** — the natural model for exfiltration. Our `exfil_flows` feature is the tabular
  stand-in for what the graph would learn properly.
- **The genuine novelty:** *diffing* these sequence/graph representations across two
  versions — no published work does cross-version behavioural diffing with seq/graph models.

Full model reasoning (all acronyms spelled out) is in
[../../Reference Docs/ML_Models_Research.md](../../Reference%20Docs/ML_Models_Research.md).

## 5. Multi-browser (directive #1)

Chromium family (Chrome/Edge/Brave) is primary — one MV3 `.crx` + `chrome.*` back-end
covers all three, and it is the family Cyberhaven hit. Firefox (Gecko, `.xpi`, `browser.*`)
is the **second engine** for genuine cross-engine coverage (Playwright drives both). Safari
is out of scope. The unpacker already accepts `.xpi`; the capture layer is written against
Playwright's cross-browser API.

## 6. Data strategy (honest about scarcity)

Confirmed malicious **update pairs** are rare in the wild — a handful of documented
campaigns. So we **train primarily on a synthetic weaponisation corpus** (clean extensions
with a known bad behaviour injected to create labelled `(v1, v2)` pairs — see
`data/corpus/readerlite/`) and **reserve real 2024–25 incidents as a held-out validation
set**. This is the defensible framing and pre-empts the "your dataset is tiny" question.

## 7. Ground-truth verification (a bonus we get for free)

Because the malicious sample exfiltrates to a **fake collector that is part of our test
site**, the collector's log is independent ground truth: it records exactly what left the
browser. Every run cross-checks the verdict against it (`ground_truth` in `report.json`),
so we can measure detection against reality, not just against our own labels.

## 8. Step-by-step approach (directive #5) — see the [PROGRESS_REPORT](../progress/PROGRESS_REPORT.md)

Phases A–D (foundations → first trace → diff → determinism/sandbox) are **implemented and
running**. Phases E (ML tier) and F (dashboard, Firefox, evaluation, write-up) are next.
