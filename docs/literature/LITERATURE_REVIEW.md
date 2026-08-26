# Literature Review — Behavioural-Diff Detection of Malicious Browser-Extension Updates

**Course:** CSD493 Project-1 (Monsoon 2026) · B.Tech CSE · Shiv Nadar IoE
**Team:** Bind Pratap Singh (2310110084), Suhani Deepak Agrawat (2310110717)
**Advisor:** Dr. Sweta Mishra

This review positions our work against the papers we have studied. For each, we record
*what it does*, *how it works*, *its limitation*, and *what our project takes from it or
fixes*. The recurring theme — and our thesis — is that prior work analyses a **single
version** of an extension, whereas the real-world threat (Cyberhaven, Dec 2024) is a
**malicious update to a previously-trusted extension**. We score the *change*, not the
extension.

---

## The threat that frames the project — Cyberhaven (December 2024)

A trusted extension with a valid Chrome Web Store listing pushed a **silent auto-update**
whose new version stole cookies and session tokens. It reached ~400,000 users within
hours, and the same campaign compromised dozens of other extensions. The browser grants
an extension's trust **once**, at install, and never re-checks it on update. Every static
review, permission prompt and store-review step had already been passed by the benign
version. This is the exact gap our method targets: **re-verify behaviour on every
update**, automatically.

---

## 1. VEX — Bandhakavi et al., USENIX Security 2010

- **What.** Static information-flow analysis of extension JavaScript to flag suspicious
  flows (e.g. an HTTP response reaching `eval`).
- **How.** Builds def-use / flow graphs over the source and pattern-matches known-dangerous
  flows without running the code.
- **Limitation.** Static analysis is blind to behaviour that only appears at runtime —
  obfuscated, minified, dynamically-fetched, time-delayed, or condition-gated code. A
  payload that is downloaded or decoded at run time is invisible to it.
- **We take / fix.** We keep the cheap static signal (a **permission/manifest diff**, one
  of our rules) but make the core of the system **dynamic**: we run both versions and watch
  what they actually do. Our synthetic payload is deliberately gated on a `submit`/timeout
  event — the precise case VEX cannot see and our runtime capture does.

## 2. Hulk — Kapravelos et al., USENIX Security 2014

- **What.** The seminal work on *eliciting* hidden malicious behaviour in extensions by
  running them dynamically.
- **How.** **HoneyPages** (a page that satisfies any selector the extension looks for) plus
  **event fuzzing** to trigger dormant handlers, while monitoring network and API activity.
- **Limitation.** Single-version, and its dynamism introduces run-to-run non-determinism;
  it detects "bad now", not "changed to bad since the last version".
- **We take / fix.** Our **scenario scripts** (`engine/sandbox/scenarios.py`) are a focused
  descendant of Hulk's elicitation — drive a realistic user interaction so the payload
  fires. We add the two things Hulk lacks for our problem: **cross-version diffing** and
  **record/replay determinism** so the diff is not swamped by run-to-run web noise.

## 3. ExtPrivA — Bui, Tang, Shin, IEEE S&P 2023 *(base paper)*

- **What.** Detects inconsistencies between an extension's stated privacy practices and its
  actual data-collection behaviour.
- **How.** **Emulates user interaction**, monitors **outbound network requests** and
  attributes each request's **initiator**, then compares observed data flows against the
  declared privacy policy. ~85% precision.
- **Limitation.** Explicitly **single-version**: it audits one release against its own
  stated policy. It has no notion of an update, and no baseline-vs-candidate comparison.
- **We take / fix.** This is our methodological backbone. We reuse *emulate-interaction +
  watch-network + attribute-initiator* almost verbatim (our capture layer attributes every
  request to page / content-script / service-worker, exactly ExtPrivA's initiator idea).
  Our **contribution is to lift it from single-version to the update setting**: the baseline
  *is* the reference, so we need no declared policy — we ask "what does the new version do
  that the trusted one did not?"

## 4. Karami et al. — NDSS 2021

- **What.** Shows Manifest V3 **service workers** can leak data with **no active web page**.
- **How.** Demonstrates background-context exfiltration paths that page-centric monitors
  miss entirely.
- **Limitation.** A demonstration of an attack surface, not a detector.
- **We take / fix.** We **instrument the service worker directly** (static prelude injection
  reaches the SW, which has no DOM to hook), and we carry a dedicated feature
  (`net_worker_initiated`) and rule (**R09**, service-worker beaconing). Our weaponised
  sample exfiltrates *from the service worker* precisely to prove we cover this blind spot —
  and R09 fires on it in the live run.

## 5. WRIT — Vasiliadis et al., IEEE TDSC 2024

- **What.** Web Request Integrity: defends against malicious extensions tampering with or
  exfiltrating via web requests.
- **We take.** Motivates our **encoded-payload** feature (`net_encoded_params`, rule **R05**)
  — detecting data smuggled into URL parameters via base64/high-entropy blobs.

## 6. "It's not Easy" — Applying Supervised ML to detect malicious extensions, arXiv 2025

- **What.** Trains supervised classifiers on static/metadata features. **98% lab accuracy**,
  but in the wild it flagged **>1,000** extensions of which **only 68** were truly malicious.
- **Lesson (crucial).** The bottleneck is **not the classifier** — it is false positives and
  concept drift in the real world. A 98%-accurate model can be operationally useless.
- **We take / fix.** This directly shapes our priorities: our headline contribution is the
  **deterministic record/replay diff** that attacks the false-positive source, *not* a fancy
  model. We also state concept drift as a limitation rather than hiding it.

## 7. Grinsztajn et al. — NeurIPS 2022 (model-choice anchor)

- **What.** Shows tree ensembles still beat deep learning on **tabular** data, especially
  with limited data.
- **We take.** Justifies our **tiered model plan**: because our `Δ = f(T2) − f(T1)` is
  tabular, Random Forest / XGBoost are genuinely near-SOTA there (Tier 1). The "more
  state-of-the-art" step is not a fancier tabular model but a **representation change** to
  sequences/graphs (Tier 2). See [../design/METHODOLOGY.md](../design/METHODOLOGY.md).

---

## The gap, in one paragraph

Every detector above analyses a **single version** of an extension. Static tools (VEX)
miss runtime payloads; dynamic tools (Hulk, ExtPrivA) catch runtime behaviour but have no
concept of an *update*, and their non-determinism makes naive version comparison noisy;
the MV3 service-worker channel (Karami) is a known blind spot; and ML detectors drown in
false positives (2025). **No open framework performs update-aware behavioural diffing with
record/replay determinism and explainable output.** That is the gap `extdrift` fills, and
the December 2024 Cyberhaven attack is the real-world instance that proves it matters.

## How the gap maps to what we built

| Paper | Its gap | Our mechanism | Where in the code |
|---|---|---|---|
| VEX | static-only | dynamic capture + static perm-diff as one signal | `engine/sandbox/`, rule R06 |
| Hulk | single-version, non-deterministic | cross-version diff + deterministic pages | `engine/features/delta.py`, `engine/sandbox/testsite.py` |
| ExtPrivA | single-version, needs policy | baseline-as-reference update diff | `engine/features/delta.py` |
| Karami | SW blind spot (a demo) | SW instrumentation + R09 | `engine/sandbox/prelude.js`, rule R09 |
| WRIT | — | encoded-payload detection R05 | `engine/features/extract.py` |
| 2025 ML | false positives dominate | record/replay determinism | `engine/sandbox/testsite.py` |

*References with links are consolidated in [../../Reference Docs/ML_Models_Research.md](../../Reference%20Docs/ML_Models_Research.md) §9.*
