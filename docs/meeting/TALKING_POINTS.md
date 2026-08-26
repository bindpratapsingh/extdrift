# Advisor Meeting — Talking Points & Q&A Prep

Keep it to ~10 minutes of talking, then run the demo live. Order below is the order to
speak in.

## Opening (30 sec)
"Since approval we've gone from proposal to a working, tested prototype. The core pipeline
runs end-to-end on a real browser and correctly catches a malicious update while not
flagging a benign one. Here's what we read, what we decided, and what we built."

## 1. Research (2 min)
- Studied 7 papers; wrote them up with *how it works / its gap / what we take*.
- The through-line: **all prior work analyses a single version.** VEX is static (misses
  runtime payloads); Hulk and our base paper ExtPrivA are dynamic but single-version and
  non-deterministic; Karami shows the MV3 service-worker blind spot; the 2025 ML paper
  shows 98% lab accuracy can still mean a false-positive flood.
- **Our gap:** the real threat is a malicious *update* to a trusted extension — Cyberhaven,
  Dec 2024, ~400k users in hours. Nobody does update-aware behavioural diffing with
  determinism. That's us.

## 2. Strategy — reproduce then improve (2 min)
- Exactly as you advised: **Tier 1** reproduces the tabular baseline — heuristics (done) →
  Random Forest → XGBoost + SHAP. **Tier 2** is the real novelty: change the representation
  to a sequence (Transformer) or data-flow graph (GNN) and *diff across versions*.
- Heuristics come first on purpose — they're the control that answers "why is ML even
  needed?" ML has to beat them to earn its place.

## 3. Implementation — then run the demo (4 min)
- "We didn't just write docs — here's the system." Show numbers: ~3,100 LOC Python, 72
  tests green, 2 of them launch a real Chromium.
- **Run it live:**
  - `python scripts/demo_offline.py` — instant, no browser: BENIGN / SUSPICIOUS / MALICIOUS
    on three fixtures.
  - `python scripts/demo.py` — the real thing: loads our extension in Chromium, the payload
    actually steals credentials + cookies, we catch it (MALICIOUS 0.99), and the
    **ground-truth collector confirms the leak**; the benign update stays BENIGN.
- Point out the explainable output: every verdict lists the rules + the paper each came
  from.

## 4. Honesty slide (1 min)
- Rule weights are literature priors, not yet calibrated — the report says so itself.
- Real malicious update pairs are scarce → synthetic-train / real-validate.
- Next: mitmproxy replay for real sites, the RF/XGBoost tier, then Firefox.

---

## Anticipated questions

**"Is this just a permission check?"**
No — permissions are one static rule (R06) among 12. The core is *runtime* behaviour: we
watch the extension read the password field and beacon cookies from the service worker,
which no manifest inspection could reveal. Our weaponised payload is deliberately gated on
a form-submit so static analysis can't see it.

**"How do you avoid false positives?"**
Determinism. Both versions see byte-identical pages, so anything in the diff is the
extension, not web randomness. That's the exact failure mode of the 2025 ML paper, and
it's our main contribution — more than the model.

**"Why not go straight to deep learning / why still Random Forest?"**
Our feature vector is tabular, and on tabular data trees beat deep nets (Grinsztajn,
NeurIPS 2022), especially with little data. The "more state-of-the-art" step isn't a
fancier tabular model — it's changing the representation to sequences/graphs. We do RF/
XGBoost as the reproducible baseline first, then the deep model as the improvement.

**"Your dataset is tiny."**
Confirmed real update-pairs are genuinely rare (a handful of campaigns). So we train on a
synthetic weaponisation corpus and hold out real incidents for validation — the honest
framing. We also verify against the collector's ground-truth log, not just labels.

**"Does modifying the extension to instrument it invalidate the result?"**
Both versions get identical instrumentation, so the *diff* is unaffected, and every trace
records exactly what was changed. It's the standard trade-off in dynamic analysis and we
document it.

**"Multiple browsers — where are you?"**
Chromium family (Chrome/Edge/Brave) share MV3 `.crx` + `chrome.*`, so one back-end covers
all three — that's what runs today. Firefox is the second engine via Playwright, scoped as
the next milestone. Safari is deliberately out.

**"What's genuinely new / publishable here?"**
Cross-engine, update-aware behavioural diffing with record/replay determinism and
explainable dual-scored output. To our knowledge no open framework does it. The Tier-2
version-diffing of sequence/graph representations is the paper.
