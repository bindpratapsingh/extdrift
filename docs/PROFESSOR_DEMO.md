# extdrift — Demo Guide (what to show the professor, and how)

A run-of-show for a ~15-minute live demo, with the exact commands, what each output proves, and
what to say. Ordered for impact and reliability. Everything except the two live-browser steps runs
offline in seconds from committed data.

> **Golden rule:** run the whole flow once **before** the meeting (see §0). Keep this file open on a
> second screen. If any live command misbehaves, the saved output under `out/` is your fallback (§7).

---

## 0. Before the meeting (10 min, once)

```bash
cd extdrift
source .venv/bin/activate            # or: .venv\Scripts\activate on Windows
python -m pytest tests/ -q           # sanity: ~110 passed, 1 skipped
# pre-run the slow ones so their output is cached and ready to show:
python -m experiments.youve_changed_headtohead   # ~2-3 min (needs data/real/amo source)
python scripts/demo.py               # the live-capture demo — confirm it ends MALICIOUS + leak
```
If `youve_changed_headtohead` says "No AMO source on disk", regenerate it first:
`python -m engine.collector.amo top -n 20 --pairs 1` (downloads real extensions, a few minutes).

Have these open in tabs: `README.md`, `docs/PROJECT_REPORT.md` (the architecture diagram in §5), and
the GitHub repo page.

---

## 1. The 30-second pitch (say this first)

> "A browser extension you trust can turn malicious in a **silent auto-update** — that's exactly the
> Cyberhaven attack of Dec 2024. The stores review an extension once, not the *change* between
> versions. extdrift runs two consecutive versions of an extension in a sealed sandbox, records what
> each one *does*, and flags the update when the **behaviour changes** in a dangerous way — it scores
> the *change*, not the extension. And because it watches behaviour, obfuscation doesn't hide the
> attack the way it hides it from static code scanners."

Show the architecture diagram in `docs/PROJECT_REPORT.md` §5 while saying it.

---

## 2. Demo step 1 — three verdicts, no browser (2 min, always works)

```bash
python scripts/demo_offline.py
```
**Shows:** the full pipeline scoring three committed fixture pairs → a **BENIGN**, a **SUSPICIOUS**,
and a **MALICIOUS** verdict, each with the *evidence* (the new behaviours that fired).
**Say:** "This is the whole analysis in one command — delta, rules, ML, anomaly, and an explainable
verdict. No browser needed for the analysis half; it runs on a 4 GB laptop."

## 3. Demo step 2 — the live capture (the 'wow') (3 min)

```bash
python scripts/demo.py
```
**Shows:** a benign update scored **BENIGN**, and a malicious update scored **MALICIOUS** with the
fake collector confirming the leak (ground truth — data actually reached the collector, sealed
locally).
**Say:** "Here it's real: we load an extension in a real browser, a synthetic payload tries to steal
cookies, and our sandbox both catches the behaviour change *and* proves the leak — while blackholing
it so nothing leaves the machine."

## 4. Demo step 3 — why XGBoost, and rules aren't enough (2 min)

```bash
python -m engine.ml.bakeoff data/dataset/deltas.csv
```
**Shows:** the six-model table. Point at two rows: **Rules FPR@90%recall = 0.45** vs the boosted
model **≈ 0.01**. **Say:** "We don't assume XGBoost — we bake off six models under leakage-free,
extension-level cross-validation and a temporal split. The gradient-boosting family wins; to catch
90% of attacks the transparent rules would false-positive on **45%** of benign updates, the model on
under **2%**. That's why ML earns its place."

## 5. Demo step 4 — it works on REAL extensions (2 min, the key result)

```bash
python -m experiments.real_behavioural_eval
```
**Shows:** `Rules on real data: 30/30 = 100% recall` and `Synthetic -> real transfer: PR-AUC 0.998,
recall 0.93, precision 1.0`. **Say:** "The important question is generalisation. We train the model on
**synthetic data only**, then test it on **real extensions it never saw** — 15 real ones, weaponised
with a real payload. It catches them at PR-AUC 0.998 with zero false positives. The synthetic
distribution transfers to the real world."

## 6. Demo step 5 — beating prior work / obfuscation (2 min)

```bash
python -m experiments.youve_changed_headtohead     # (pre-run in §0; show the output)
```
**Shows:** across **21 real extensions**, static (You've Changed style) catches the clean payload
**21/21** but the obfuscated one **0/21**; our dynamic diff catches both. **Say:** "This is the whole
argument for dynamic analysis in one table. The prior static method is completely blinded by
obfuscation on real code; we aren't, because we watch the effect, not the source text."

## 7. Demo step 6 — the rigor (2 min, for the panel)

```bash
python -m experiments.statistical_rigor            # ML-vs-rules is statistically significant
python -m experiments.operating_point              # locked held-out test + chosen threshold
python -m engine.ml.anomaly --real                 # anomaly layer catches unseen, on real data
```
**Shows:** 95% confidence intervals (ML gain over rules CI [0.093, 0.137], excludes 0 → significant);
a by-extension **held-out** test (PR-AUC 0.976) with the threshold chosen before seeing the test set;
and the novelty layer flagging 93% of real weaponised extensions trained on benign only.
**Say:** "The numbers are not point estimates — they have confidence intervals, a locked held-out
test, and a calibrated operating point. The evaluation follows the protocol strong security papers
use."

---

## 8. If something fails live — fallbacks

Every experiment writes its result to `out/<name>/results.json` (or a log). If a live run stalls:
- Show the JSON: e.g. `type out\statistical_rigor\results.json` (Windows) / `cat` (Mac).
- Or open `docs/PROJECT_REPORT.md` §16 (Results) — every number above is written there with context.
- The offline demo (`demo_offline.py`) never needs a browser and is the safe anchor.

---

## 9. Numbers to have memorised (cheat sheet)

| Claim | Number | Command |
|---|---|---|
| Dataset | 1,047 pairs, 266 exts (1,000 synth + 45 real) | `engine.batch` |
| ML vs rules (false positives @90% recall) | ~1% vs 45% | `engine.ml.bakeoff` |
| ML beats rules — significant | +0.115 PR-AUC, CI [0.093, 0.137] | `statistical_rigor` |
| Held-out test | PR-AUC 0.976 | `operating_point` |
| Synthetic → real transfer | PR-AUC 0.998, recall 0.93, precision 1.0 | `real_behavioural_eval` |
| Rules on real weaponised | 30/30 = 100% recall | `real_behavioural_eval` |
| Static (You've Changed) vs obfuscation | 21/21 clean, **0/21** obfuscated | `youve_changed_headtohead` |
| Anomaly on real (unseen) | 93% detect, ROC-AUC 0.989 | `anomaly --real` |
| Cross-browser | Firefox + Chromium, both on real, MV3 | `chrome_spike` / captures |
| Analysis speed | 0.22 ms/pair | `performance` |

---

## 10. Likely questions → where the answer lives

`docs/PROJECT_REPORT.md` §18 is a written Q&A for: why not the stores, how you get two versions
(and why real malicious *pairs* can't be sourced — 60% delisted, 0/15 archived), why not static,
why XGBoost, does synthetic generalise, how you avoid ML mistakes, is it significant, is adware
malicious, what it outputs, and what it can't do. Read §18 the night before.

---

## 11. Two demo lengths

- **10-minute version:** steps 1 (offline), 2 (live capture), 3 (bake-off), 5 (real transfer). Done.
- **15-minute version:** add step 6 (You've Changed) and step 7 (rigor).

Reproduce everything at once with `bash scripts/reproduce.sh` (offline; ~1 min).
