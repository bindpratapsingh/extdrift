# extdrift

**Catch a browser extension the moment an update turns it malicious — by diffing what it *does*, not what its code says.**

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB)
![Tests](https://img.shields.io/badge/tests-93%20passing-2ea44f)
![Analysis](https://img.shields.io/badge/analysis-dynamic%20%2B%20ML-0f766e)
![Status](https://img.shields.io/badge/status-working%20prototype-a4690a)
![License](https://img.shields.io/badge/license-academic-lightgrey)

A browser extension you trust can become spyware **overnight** through a single silent
auto-update — the browser grants its trust *once*, at install, and never re-checks it. The
**December 2024 Cyberhaven attack** did exactly this: a phished developer account pushed a
cookie-stealing update to ~2.6M users across dozens of extensions. Store review, permission
prompts, and code signing had all already passed the *benign* version.

**extdrift scores the *change*.** Give it two consecutive versions of the same extension; it
runs each in a sealed, deterministic sandbox, records what each actually does, diffs the
behaviour, and returns an **explainable verdict** — with transparent rules, a machine-learning
model, and an anomaly detector for the unseen.

---

## How it works

```mermaid
flowchart TD
    A["Extension v1 (trusted) + v2 (candidate)"] --> B["Unpack + instrument<br/>(reaches content scripts and the MV3 service worker)"]
    B --> C1["Sandbox run — v1<br/>headless Chromium · scripted user · egress blocked"]
    B --> C2["Sandbox run — v2<br/>identical script · byte-identical pages"]
    C1 --> D["Δ = f(T2) − f(T1)<br/>behavioural delta · 24 features"]
    C2 --> D
    D --> E1["Rules<br/>12 explainable heuristics"]
    D --> E2["ML model<br/>P(malicious update)"]
    D --> E3["Anomaly<br/>flags the unseen"]
    E1 --> F["Verdict + evidence<br/>BENIGN / SUSPICIOUS / MALICIOUS"]
    E2 --> F
    E3 --> F
```

Both versions see **identical pages**, so the extension version is the *only* variable — the
difference is the extension, not the noise of the live web. Each run is recorded across four
channels: **network, DOM, storage/cookies, and `chrome.*` API calls** (including the MV3
service worker, a common exfiltration blind spot).

---

## Results that matter

Obfuscation hides the *code*, but the *runtime effect* is still visible — which is why a
dynamic diff beats static analysis on the case that matters most:

| On a payload that steals cookies | Static code-diff (prior work) | **extdrift (dynamic)** |
|---|---|---|
| Clean code | MALICIOUS ✓ | MALICIOUS ✓ |
| **Obfuscated code** | **BENIGN ✗ (missed)** | **MALICIOUS ✓ (0.99, leak confirmed)** |

And the machine-learning tier earns its place on the metric that decides whether a detector is
usable — the false-positive rate:

| To catch 90% of malicious updates… | False positives |
|---|---|
| Transparent rules alone | flags **66%** of benign updates |
| **Learned model (Random Forest)** | flags **~0%** |

*Anomaly layer:* trained only on benign updates, it flags **100% of malicious families it never
saw in training**. *All figures are from a synthetic corpus + live browser captures;
real-world validation is the next milestone.*

---

## Quickstart

```bash
pip install -r requirements.txt && playwright install chromium

# No browser — score three example update pairs instantly:
python scripts/demo_offline.py

# The real thing — load an extension in Chromium; a synthetic payload actually steals
# cookies, and we catch it:
python scripts/demo.py
```

```text
VERDICT   : MALICIOUS
Rules     : 0.99  [################################]   (6/12 fired)
ML model  : 0.84  [###########################-----]   (ml-rf, MALICIOUS; rules agree)
[ground truth] collector received data: True     ← the leak really happened
```

---

## The machine-learning approach

The model is chosen by **evidence, not convention**: five candidates race on the same
behavioural-delta features, judged by PR-AUC and false-positive rate under **cross-validation
that splits by extension and by time** (so it can't memorise an extension).

```mermaid
flowchart LR
    P["Labelled update pairs<br/>benign + synthetic malicious"] --> V["Δ feature vectors"]
    V --> BO["Bake-off<br/>rules · logreg · RF · XGBoost · SVM"]
    BO --> S["Select by PR-AUC + FPR"]
    S --> M["Saved model<br/>+ SHAP-style attribution"]
    V --> AN["Anomaly detector<br/>(benign-only) → unseen threats"]
```

Predicts exactly one thing — `P(this update introduced malicious behavioural change)` — and
never claims more (no zero-day *vulnerability* discovery). The rules stay as the interpretable
control, and the learned model is reported only when it beats them.

---

## Repository layout

```
engine/
  unpack/       .crx/.xpi unpacking + static manifest diff
  sandbox/      instrumented browser capture (Playwright) + deterministic test-site
  features/     trace schema, feature extraction f(·), Δ = f(v2) − f(v1)
  scoring/      12 explainable heuristic rules
  synth/        synthetic update-pair corpus generator
  weaponiser/   real JS payloads (clean + obfuscated) → labelled malicious versions
  baseline/     static code-delta scorer (the prior-work baseline we beat)
  ml/           model bake-off, anomaly layer, live prediction
  collector/    real version-pair collection (disk snapshot + GitHub/crx)
  report/       explainable text + JSON verdicts
experiments/    head-to-head (obfuscation) · determinism ablation
tests/          93 tests (incl. live browser integration)
```

## Tech stack

**Python** · **Playwright** (Chromium automation) · **scikit-learn** + **XGBoost** (the model
tier) · **pandas / NumPy** · standard-library sandbox test-site. The analysis + ML half is
dependency-light and runs on a laptop; only live browser capture needs Chromium.

## Scope & honesty

- **This project:** dynamic, behavioural, cross-version diffing with record/replay determinism
  and explainable output — the open gap next to static update-diffing (*You've Changed*, CCS
  2020) and single-version dynamic analysis (*Hulk*; *ExtPrivA*, IEEE S&P 2023).
- **Deliberately out of scope:** consumer-side prevention before an update runs, discovery of
  unknown code vulnerabilities, and language-specific analysis — positioned instead for
  store / enterprise / researcher use.
- **Safety:** only synthetic, self-contained samples run, inside a network-restricted sandbox
  against fake pages with dummy credentials. Nothing is redistributed or hosted.

---

<sub>**CSD493 Project-1** · B.Tech CSE · Shiv Nadar Institution of Eminence · Bind Pratap Singh
& Suhani Deepak Agrawat · Advisor: Dr. Sweta Mishra. Academic research prototype for defensive
security research.</sub>
