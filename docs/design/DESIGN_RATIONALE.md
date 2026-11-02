# Design Rationale — the reasoning behind extdrift

*A methodology-section-style justification of every design choice, written to the standard
security papers are held to (threat model → approach → features → data → evaluation →
limitations). This is the document to defend in the panel.*

**Project:** Behavioural-Diff Detection of Malicious Browser-Extension Updates
**Team:** Bind Pratap Singh · Suhani Deepak Agrawat · **Advisor:** Dr. Sweta Mishra

---

## 1. Threat model (who we defend against, and what is out of scope)

Security papers begin here, so we do too.

- **Adversary.** An attacker who controls a *future version* of an extension the user already
  trusts — via a **compromised developer account** (Cyberhaven, Dec 2024), an **ownership
  transfer / sale** (The Great Suspender, Nano Adblocker), or an **insider**. We do **not**
  assume the attacker can defeat the browser's process sandbox or the OS.
- **Capability.** The malicious version ships through the normal store pipeline and
  auto-updates silently. It can obfuscate its code, fetch configuration remotely, and gate its
  payload on conditions (a specific site, a delay, a server command).
- **What we protect.** The behavioural *integrity of an update*: we answer "does version N+1 do
  something security-relevant that version N did not?"
- **Explicitly out of scope** (stated for honesty, as papers do): consumer-side *prevention*
  before an update runs (the browser gives an external tool no veto); discovery of unknown
  *code vulnerabilities* (a different problem); and analysis of the *language/runtime* (JS is
  memory-safe; risk lives in capability, not language). We position as a **store / enterprise /
  researcher** re-verification method.

---

## 2. Why a behavioural *diff* (the core reasoning)

Three established results force the design:

1. **Static analysis is evadable** (VEX, USENIX'10; and *You've Changed*, CCS'20 — the static
   update-diff prior work, which its own authors note is defeated by obfuscation). Therefore we
   analyse **runtime behaviour**, not source.
2. **Single-version dynamic analysis has no notion of an update** (Hulk, USENIX'14; ExtPrivA,
   S&P'23). The threat is a *change*, so we score the **difference between two versions**, not
   one version in isolation. This also kills a large class of false positives: a password
   manager reading a password field is normal — it is only alarming when it is *new*.
3. **The bottleneck is false positives, not accuracy** ("It's not Easy", 2025: 98% lab, >1,000
   wild flags, 68 real). Two runs of the live web differ on their own (ads, nonces), so a naïve
   diff is noisy. We enforce **determinism** (§5) so the only variable is the extension version.

**One-line justification:** *score the change, not the extension; observe effects, not code;
hold the inputs fixed so the difference is the extension.*

---

## 3. The behaviour model — four observation channels (why these)

An extension's security-relevant actions are fully covered by four channels; anything it does
that matters to the user falls into one of them:

| Channel | Captures | Why it is necessary |
|---|---|---|
| **Network** | every outbound request + its *initiator* | exfiltration and C2 are network events; initiator attribution ("page vs extension vs service-worker") is ExtPrivA's core idea and separates "the page loaded an ad" from "the extension uploaded your cookies" |
| **DOM** | reads of form fields / `document.cookie`, node injection | credential/secret capture and ad/overlay injection are DOM events |
| **Storage** | cookie / `chrome.storage` access | session-token theft (Cyberhaven) is a storage/cookie event |
| **API** | `chrome.*` / `browser.*` calls incl. the MV3 **service worker** | capability use, and the background-worker exfiltration path that page-centric monitors miss (Karami, NDSS'21) |

We instrument the extension's *own* code (static prelude injection) so these are observed in
both content scripts (isolated world) and the service worker.

---

## 4. Feature design — the parameters, and why *only* these (the panel's question)

We extract **27 features** from the behavioural delta: **24 dynamic** (from the four channels)
plus **3 static** (from the manifest). Every feature is (a) cheap, (b) explainable in one
sentence, and (c) traceable to a behaviour a prior paper observed in real malware — that
provenance is the justification for *why this feature and not an arbitrary one*.

**Design principles (why not more, why not fewer):**
- **Grounded, not exhaustive.** Each feature encodes a behaviour documented in the literature or
  in a real incident; we do not add features with no threat behind them (that only adds noise and
  overfitting risk on a small dataset).
- **Behaviour, not identity.** No feature keys on *which* extension/library it is — only on what
  changed — so the model cannot memorise an extension (anti-leakage, §8).
- **Diff-shaped.** Every feature is measured as `v2 − v1`, so "reads passwords" is not a feature;
  "*newly* reads passwords" is.

### Network (9) — where exfiltration shows up
`net_requests`, `net_hosts`, `net_third_party_hosts`, `net_ext_initiated` *(ExtPrivA S&P'23)* ·
`net_posts`, `net_upload_bytes`, `net_max_upload_bytes` *(Hulk USENIX'14 — volume/direction of
data leaving)* · `net_encoded_params` *(WRIT TDSC'24 — data smuggled as base64/high-entropy URL
params)* · `net_worker_initiated` *(Karami NDSS'21 — background exfiltration with no page)*.

### DOM (4) — where secrets are read and pages are tampered
`dom_reads` *(VEX)* · `dom_sensitive_reads` (credential/secret fields) and `dom_identity_reads`
(email/username, tracked separately so scraping ≠ credential theft) *(ExtPrivA)* ·
`dom_injections` *(VEX — ad/overlay/fake-form injection)*.

### Storage (3) — session-token theft
`storage_calls`, `cookie_reads`, `cookie_bulk_reads` (whole-jar `getAll`) *(Cyberhaven Dec'24 —
the exact signature of the campaign)*.

### API (3) — capability use
`api_calls`, `api_distinct` *(Hulk)* · `api_high_risk` (calls into `cookies`/`webRequest`/
`scripting`/`debugger`/… namespaces) *(MV3 permission model)*.

### Static manifest (3+2) — the one pre-execution signal
`perm_count`, `perm_high_risk`, `host_perm_breadth` *(VEX)* plus the manifest-diff features
`stat_added_highrisk_perms`, `stat_escalated_broad_host`, `stat_added_hosts`. Cheap, available
before the extension runs, and the "silent permission creep" real updates exhibit.

### Derived — the exfiltration signal
`exfil_flows` (a **sensitive read followed by an outbound request** within a short window) and
`exfil_flows_third_party` (…to a party the baseline never contacted) *(ExtPrivA + Cyberhaven)*.
This is a **lightweight taint approximation** (temporal adjacency, not full data-flow tracking);
we report it as a *candidate* flow, and the proper data-flow graph is the Tier-2 stretch (§9).

> **Ablation (planned, §8):** we will drop each feature group and re-measure to show which
> features carry the signal — the standard way papers justify a feature set rather than assert it.

---

## 5. The behavioural delta Δ, and determinism (why the numbers are trustworthy)

- **Δ = f(T₂) − f(T₁)** is computed only when the two runs are *comparable* — same extension ID,
  same interaction scenario, same page bundle — and the tool refuses/​warns otherwise, because
  diffing runs against different inputs is the easiest way to manufacture a false positive.
- **Determinism.** Both versions are driven through an **identical scripted user session**
  (`engine/sandbox/scenarios.py`) against **byte-identical pages** served by an in-process test
  site (`testsite.py`), with **network egress blocked** (`.test` hosts resolve to loopback only).
  So the extension version is the *only* variable. Our **determinism ablation** quantifies this:
  the same extension diffed against itself yields **0** spurious differences with fixed pages and
  several with a noisy web.
- **Ground truth.** The sandbox includes a fake collector; its log records what *actually*
  exfiltrated, giving an independent check on every verdict.
- **Record/replay for real sites** (mitmproxy) is the planned upgrade from the synthetic site to
  real page content, keeping the determinism guarantee.

---

## 6. How we obtain old and new versions (the acquisition methodology)

This is the hardest data problem and papers are explicit about it, so we are too.

- **Deployment framing:** extdrift is an update-*monitoring* method. In real use (store review,
  enterprise, a research crawler) every version is **archived as it ships** and the new one is
  diffed against the last-known-good — you never "hunt" for the past.
- **For building/evaluating now:**
  1. **Real benign pairs (abundant):** two consecutive **GitHub tagged releases** of open-source
     extensions; **crx4chrome / chrome-stats** historical `.crx`; and **self-snapshots** of
     installed extensions captured weekly as they auto-update. The collector
     (`engine/collector/`) implements all three; the Chrome **update endpoint** downloads the
     current `.crx` directly (verified working — we pulled Dark Reader, Grammarly, Stylus).
  2. **Real malicious indicators:** the **7,382-ID** `chrome-mal-ids` IOC database (committed to
     `data/real/`), and reconstruction of documented incidents (Cyberhaven).
  3. **Synthetic malicious pairs (breadth):** a real/clean benign `v1` with an injected known
     payload → labelled `v2` (`engine/weaponiser/`, `engine/synth/`), always stamped SYNTHETIC.
- **The honest framing (as papers use):** confirmed real malicious *update pairs* are
  fundamentally scarce (a handful of campaigns worldwide), so we **train primarily on synthetic**
  and **validate on real** — the standard, defensible design when attack data is rare.

---

## 7. Scope of "malice" — including adware (the advisor's question)

Working position (to be finalised against the literature review, Gemini Prompt B):
**adware / ad-injection / affiliate-fraud is in scope as a malice class.** Justification: the
largest documented extension-abuse campaigns (DataSpii; Palant's PDF-Toolbox/SeaSearch reaching
~87M installs; Nano Adblocker) were precisely ad-injection / data-collection, and the research
community treats them as malicious. Behaviourally it is well-covered by our features
(`dom_injections`, new third-party hosts, `declarativeNetRequest` redirects), and we already
generate an `ad_affiliate` family. **The one nuance to resolve from papers:** distinguishing
malicious ad-injection from a *legitimate* ad-blocker/coupon extension — the diff helps (a benign
ad-blocker's ad behaviour is present in *both* versions), but we will adopt the exact
discriminating features the literature uses.

---

## 8. Evaluation protocol (paper-grade, leakage-free)

- **Extension-level splitting** (GroupKFold by `ext_id`): all versions of one extension go
  entirely into train or test — the single most important anti-leakage rule; without it the model
  memorises an extension and the score is meaningless.
- **Time-based split** (train older, test newer) to expose **concept drift** (documented for
  extensions, Rosenzweig TWeb'25).
- **Metrics:** **PR-AUC** and **false-positive rate at fixed recall** (not accuracy — the classes
  are imbalanced); plus ROC-AUC, precision/recall/F1, and the confusion matrix.
- **Ablations:** leave-one-family-out (novelty / unseen threats), the feature-group ablation
  (§4), and the **determinism ablation** (§5).
- **Baselines to beat:** the transparent rules (control) and a **static code-delta** baseline
  (the *You've Changed* style) — the **head-to-head on obfuscation** shows the static baseline
  missing an obfuscated payload our dynamic diff catches.
- **Learning curve:** performance vs dataset size, to state honestly how much data we need.

---

## 9. Model selection rationale (the panel focus)

- **Rules first, as the control.** A learned model is reported only if it beats the transparent
  rules — the direct test of "is ML even needed."
- **Tabular ⇒ tree ensembles.** The delta is a fixed-length numeric vector; on tabular data,
  tree ensembles beat deep nets, especially with limited data (Grinsztajn, NeurIPS'22). So the
  bake-off is rules, Logistic Regression (floor), Random Forest, **XGBoost + HistGradientBoosting**
  (two boosting implementations), and an SVM — **chosen by PR-AUC and FPR under the §8 protocol,
  not by assumption.**
- **The genuine "more state-of-the-art" step** is not a fancier tabular model but a **change of
  representation** — a **sequence** model (Transformer/BiLSTM over the ordered event trace) or a
  **data-flow graph** model (GNN over cookie-read → network-send), and *diffing* those across
  versions, which no prior work does. Scoped as Tier-2 / Project-2 (needs more data → the Mac).

---

## 10. Limitations & threats to validity (as every paper states)

- Current results are on a **synthetic corpus + a few live captures**; cleaner than the wild.
  Real-data validation is the next milestone.
- The exfil-flow feature is a **temporal-adjacency approximation**, not true taint.
- Dynamic analysis has **trigger-coverage limits**: a payload gated on a real C2 command may not
  fire in our scenarios (accepted, field-wide).
- Instrumentation **perturbs the sample**; both versions get identical treatment and the change is
  recorded in every trace.
- **Single engine** so far (Chromium); Firefox is Project-2.

*Companion docs: [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) (build order),
[METHODOLOGY.md](METHODOLOGY.md) (reproduce-then-improve), and the feasibility/novelty study in
`docs/research/`.*
