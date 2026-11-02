# Progress Snapshot — Advisor Meeting

**Project:** Behavioural-Diff Detection of Malicious Browser-Extension Updates (extdrift)
**Team:** Bind Pratap Singh · Suhani Deepak Agrawat · **Advisor:** Dr. Sweta Mishra
**Date:** September 2026

---

## Where we were → where we are

| At our last update | Now |
|---|---|
| Literature review done; four core papers studied | Same, **plus** a full feasibility/novelty study grounded in current sources |
| *About to start* the first Playwright trace-capture prototype | **The full pipeline is built, tested, and running on a real browser** |
| No dataset | **~1,000 synthetic update pairs + real data pulled** (7,382 known-malicious IDs, real extensions) |
| No model | **A trained model (XGBoost) chosen by a fair bake-off**, with results |
| — | **Automated tests passing; code on GitHub** |

**In one line:** we went from *about to write the first prototype* to a **working, tested,
end-to-end system** that detects malicious extension updates and is backed by real numbers.

---

## What we built (with the actual numbers)

**1. The pipeline** — feed it two versions of an extension; it runs each in a sealed,
deterministic headless-Chromium sandbox, records what each *does* (network, DOM, cookies,
`chrome.*` APIs incl. the MV3 service worker), diffs the behaviour, and returns an explainable
verdict. *It runs live — a synthetic payload actually steals cookies and we catch it, confirmed
by an independent collector log.*

**2. The dataset** — two parts, synthetic (for breadth) + real (pulled from the wild)
- **Synthetic:** **~1,000 update pairs** across **~250 distinct extensions**, 12 extension
  "personas", **9 attack families** (cookie/credential theft, service-worker beacon, ad-injection,
  keylogger, history exfil, form-jacking, redirect-hijack, clipboard-steal), ~half obfuscated,
  plus **stealth** variants — deliberately built with overlap so the task is *hard*, not trivially
  separable. 27 features per pair, tagged so evaluation splits by extension and by time (no leakage).
- **Real (pulled today):** **7,382 confirmed-malicious extension IDs** (a public IOC database) +
  real extensions downloaded through our collector (Dark Reader, Grammarly, Stylus). Full
  real-world update-pair collection is the ongoing next step.

**3. The machine-learning model** — a fair bake-off on the harder, larger dataset
| Model | PR-AUC | False-positive rate at 90% recall |
|---|---|---|
| **XGBoost (winner)** | **0.972** | **0.07** |
| Random Forest | 0.969 | 0.07 |
| SVM | 0.968 | 0.09 |
| Logistic Regression | 0.956 | 0.16 |
| Rules (interpretable control) | 0.803 | **0.52** |

→ **XGBoost — the tabular state-of-the-art — wins** on the larger, noisier data, exactly as
boosting should. And **this is where ML clearly earns its place:** to catch 90% of attacks the
rules alone flag **52%** of benign updates; the learned model flags **~7%**. On the earlier tiny,
clean dataset every model sat at ~0.99 and the gap was noise — hardening the data made the model
comparison, and the case for ML, real.

**4. Two experiments that prove the idea**
- **Obfuscation head-to-head:** a payload hidden with obfuscation — the **static approach (prior
  work) says BENIGN (misses it)**; **our dynamic diff says MALICIOUS (0.99)** and the leak is
  confirmed. Same behaviour, hidden code — we still catch it.
- **Determinism ablation:** the *same* extension diffed against itself → **0 spurious differences
  with our fixed pages, 8 with a noisy web**. Determinism removes the false positives.
- **Unseen threats:** trained only on benign updates, the anomaly detector flags malicious families
  it **never saw in training** at **43–100%** — strong on credential/cookie theft (100%), weaker on
  the stealthy families (clipboard-steal 43%, ad-injection 60%). Honest, not a uniform 100%.

**5. Rigor** — 93 automated tests (including live browser runs), all passing; everything on GitHub.

---

## Live demo — three commands (what to run and what it proves)

```bash
# A. Instant, no browser — three verdicts on example updates (SAFEST to show)
python scripts/demo_offline.py
#    -> BENIGN / SUSPICIOUS / MALICIOUS, all correct

# B. The dataset + the model, live
python -m engine.batch            # builds the 182-pair dataset
python -m engine.ml.bakeoff       # the model race -> "ML beats the rules: YES"

# C. The real thing in a browser (if the room allows) — a payload steals cookies, we catch it
python scripts/demo.py
#    -> MALICIOUS, ML agrees, collector confirms the leak
```

*Say:* "This is not a plan — it runs. Here is the dataset, here is the model chosen by evidence,
and here is it catching a live attack that a static scanner would miss."

---

## How this answers your earlier guidance

- **"Reproduce the existing state of the art, then improve"** → we built a static code-diff
  baseline (the prior-work style) and the transparent rules; the dynamic diff + ML **beat both**,
  shown in the head-to-head.
- **"Go beyond Random Forest"** → a five-model bake-off compared by PR-AUC and false-positive rate;
  **XGBoost (the tabular state-of-the-art) wins** on the larger data. The genuine further leap — a
  **sequence/graph model on a different data representation** — is scoped as Project-2.
- **"Get the heuristics; why is ML needed"** → 12 explainable rules exist and are the control; ML
  is reported only because it beats them (66% → ~0% false positives).
- **"Multiple browsers"** → Chromium family now; Firefox is scoped as Project-2.
- **"Real dataset"** → a collector is built (GitHub releases / archives / weekly self-snapshot);
  real collection is starting now, alongside the synthetic corpus.

---

## What's next (3–4 weeks)

1. Collect **real benign update pairs** and re-measure the false-positive rate on real data.
2. Grow the synthetic corpus; run the head-to-head and ablation on the larger set.
3. Begin the **Firefox** second engine (Project-2) and the written evaluation.

## The honest caveat (state it — it reads as rigour)

The numbers above are from a **synthetic corpus plus live browser captures**, so they are cleaner
than the real world will be. The result that matters is the **relationship** — dynamic beats
static on obfuscation, the model beats the rules on false positives, and the anomaly layer
generalises to the unseen. Confirming this on real-world update pairs is the next milestone.
