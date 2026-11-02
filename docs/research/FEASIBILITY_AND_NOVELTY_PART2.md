# Feasibility & Novelty — Part II: Extended Faculty Validation

**Project:** Behavioural-Diff Detection of Malicious Browser-Extension Updates (extdrift)
**Companion to:** [FEASIBILITY_AND_NOVELTY.md](FEASIBILITY_AND_NOVELTY.md) (Part I)
**Purpose:** answer the additional validation questions the faculty requires *before
implementation* — problem recurrence beyond Cyberhaven, technical difficulty, a full
vulnerability taxonomy, post-update recovery, model selection (not assuming XGBoost), the
precise ML task, datasets, unknown-threat handling, the static/dynamic/honeypage question,
and a defensible evaluation methodology — then re-synthesise the strongest project.

**Tag key:** **[FACT]** established/vendor-documented · **[FINDING]** from a cited
source · **[ASSUMPTION]** reasonable, unverified · **[OURS]** our interpretation/design.
Figures read at search level are marked *verify in source*.

> **Headline for the faculty:** the problem is **recurring** (a decade of incidents, tens
> of millions of users), the task is **genuinely hard** (obfuscation, dynamic behaviour,
> data scarcity — each only partially solved in the literature), and the honest project is
> **narrowed and reframed**, not rejected: *deterministic dynamic behavioural update-diffing,
> store/enterprise/researcher-positioned, with an experimentally-chosen model.*

---

## 1. Problem Validation Beyond Cyberhaven — it is recurring, not a one-off

**[FINDING]** Malicious/compromised/abandoned-then-subverted extensions are a **decade-long,
repeating** pattern across independent actors and entry vectors:

| Incident (year) | What happened | Entry vector | Users affected | Why defences failed | Would our diff catch it? |
|---|---|---|---|---|---|
| **DataSpii** (2019) | 8+ extensions exfiltrated browsing history/PII | Permission abuse + undisclosed collection | ~4M | Behaviour was *disclosed-adjacent*; runtime exfiltration unmonitored | **Partly** — new exfil hosts show in a diff if introduced by update |
| **Nano Adblocker/Defender** (2020) | Sold; new owner added data collection | **Ownership transfer** | ~300k | Trust not re-checked after sale | **Yes** — new outbound behaviour vs prior version |
| **The Great Suspender** (2021) | Sold; tracking + remote code added | **Ownership transfer** | ~2M | Update passed; no behavioural re-check | **Yes** — new network/exec behaviour on update |
| **Palant "SeaSearch" campaign** (2023) | Hidden JS-injection API in 34 extensions | Malicious code shipped in updates / from origin | **~87M installs** *(verify)* | Obfuscated, dormant until server-triggered; static review missed | **Yes for the *update* variants** — injection is observable at runtime |
| **Cyberhaven + campaign** (Dec 2024) | Cookie/token theft pushed via update | **OAuth phishing of dev accounts** | **~2.6M across ~35 exts** | Account compromise, not analysis; update passed review | **Yes** — sudden cookie-read → new-host POST from SW |
| **Chrome+Edge spyware wave** (2025) | 18–19 extensions spying / hijacking search | Mixed (fake tools, subverted) | **"millions"** *(Malwarebytes)* | Long-dormant, trusted listings | **Partly/Yes** depending on update-vs-origin |
| **Crypto-stealer extensions** (2025–26) | Popular extensions weaponised for wallet theft | Subverted popular extensions | ~80k (one) | Targeted, condition-gated payloads | **Yes** — new sensitive-read → exfil flow |

Sources: [BleepingComputer — 75M installs removed](https://www.bleepingcomputer.com/news/security/malicious-chrome-extensions-with-75m-installs-removed-from-web-store/) ·
[Kaspersky — 87M](https://www.kaspersky.com/blog/dangerous-chrome-extensions-87-million/48562/) ·
[Sekoia — Cyberhaven campaign](https://blog.sekoia.io/targeted-supply-chain-attack-against-chrome-browser-extensions/) ·
[Malwarebytes — millions spied on (2025)](https://www.malwarebytes.com/blog/news/2025/07/millions-of-people-spied-on-by-malicious-browser-extensions-in-chrome-and-edge) ·
[Infosecurity — 18 malicious Chrome/Edge](https://www.infosecurity-magazine.com/news/18-malicious-chrome-edge-extensions/) ·
[The Register — Great Suspender](https://www.theregister.com/2021/01/07/great_suspender_malware/) ·
[mallorybowes/chrome-mal-ids (IOC list)](https://github.com/mallorybowes/chrome-mal-ids).

**[OURS] Conclusion:** the project is **not designed around one famous incident**. Two
sub-patterns recur independently — **(a) supply-chain/account compromise** (Cyberhaven) and
**(b) ownership-transfer / acquire-and-subvert** (Great Suspender, Nano) — and **both express
as a behavioural change between a trusted version and its successor**, which is exactly what
we score. Palant's campaigns also show the **obfuscation/dormancy** that defeats static
review, motivating our dynamic stance.

---

## 2. What Makes This Difficult — challenge-by-challenge, with prior-art status

**[FINDING/OURS]** For each challenge: is it **solved / partial / open**, and where do we sit?

| Challenge | Prior-art status | Notes & our exposure |
|---|---|---|
| **Obfuscation / minification** | **Partial** | Defeats static (VEX, You've-Changed admit this). Dynamic sidesteps it — *our advantage.* Forced-execution engines (FV8, Fakeium) help but add complexity. |
| **Dynamic / condition-gated behaviour** | **Partial** | Hulk elicits via HoneyPages; coverage is never complete; **server-gated payloads can stay dormant** — an accepted open limitation. |
| **Run-to-run non-determinism** | **Weakly solved** | Live web varies → noisy diffs. Record/replay determinism (ours) is the mitigation; **this is our core methodological contribution.** |
| **Third-party dependencies / supply chain** | **Partial** | Detected reactively; behavioural diff catches the *effect* regardless of source. |
| **Large, diverse permission sets & browser APIs** | **Partial** | Declaration ≠ behaviour; MV2/MV3 + `chrome.*`/`browser.*` differences complicate normalisation (we normalise in `unpack/manifest.py`). |
| **Static vs dynamic trade-off** | **Known** | Each alone is insufficient; **hybrid** is the consensus direction. |
| **False positives / negatives** | **Open (the real bottleneck)** | 2025 "It's not Easy": 98% lab, but **>1,000 wild flags, only 68 real**. Determinism + diff target FPs directly. |
| **Previously-unknown payloads** | **Open** | Supervised models classify *known* patterns; novelty needs anomaly methods (see §8). |
| **Runtime monitoring depth (MV3 SW)** | **Partial** | Service-worker exfiltration is a blind spot for page-centric tools; we instrument it. |
| **Scalability** | **Solved (engineering)** | Hulk analysed ~48k extensions via parallel automation; embarrassingly parallel — not a research blocker. |
| **Dataset scarcity (labelled *update pairs*)** | **Open** | No public labelled update-pair set exists (§7) → synthetic-train + real-validate. |
| **Cross-version data acquisition** | **Partial** | Stores serve only latest; GitHub/archives/self-snapshot fill benign pairs (§7). |

**[OURS]** The concentration of **"partial/open"** rows — especially **determinism, false
positives, unknown payloads, and update-pair data** — is exactly what makes this a *research*
project rather than an implementation exercise. We are not solving all of them; we are
attacking **determinism + false positives on the update-diff**, which is the open cell nearest
our closest prior work.

---

## 3. Vulnerability Taxonomy (beyond code injection)

**[OURS, synthesised from the literature]** Extension risk is far broader than XSS. The table
maps each class to *how it occurs → detectability → relevance to us*. (Detectability: **S**=static,
**D**=dynamic/runtime, **ML?**=whether learning realistically helps on our features.)

| # | Vulnerability class | How it occurs / requirements | Impact | S | D | ML? | Relevance to extdrift |
|---|---|---|---|:-:|:-:|:-:|---|
| 1 | **Malicious update / supply-chain** | Trusted ext updated with bad code (compromise, sale, insider) | Mass data theft | ~ | ✔ | ✔ | **Core target** — the diff *is* this |
| 2 | **Credential / token / cookie theft** | Read login fields or `cookies.getAll`, exfiltrate | Account takeover | ~ | ✔ | ✔ | **Core** — R01–R03 fire on it |
| 3 | **Data exfiltration** | Read page/PII → outbound to new host | Privacy breach | ~ | ✔ | ✔ | **Core** — exfil-flow feature |
| 4 | **Excessive / escalating permissions** | Update adds `<all_urls>`, `cookies`… | Widened capability | ✔ | ~ | ✔ | Static signal (R06/R07) |
| 5 | **MV3 service-worker abuse** | Background beaconing with no page | Stealth exfil | ✗ | ✔ | ✔ | **Core** — R09; SW instrumentation |
| 6 | **Browser-API misuse** | `webRequest`/`declarativeNetRequest`/`scripting` abuse | Traffic tamper, injection | ~ | ✔ | ✔ | Behavioural + perm diff |
| 7 | **DOM/content-script injection & UXSS** | Inject nodes / bypass isolation | Page hijack, XSS | ~ | ✔ | ~ | Injection feature; partial |
| 8 | **Insecure message passing / cross-extension** | Unvalidated `runtime.onMessage`, exposed `externally_connectable` | Privilege bridging | ✔ | ~ | ~ | Static manifest signal |
| 9 | **Origin-validation failures** | Content script trusts page data | Injection/escalation | ✔ | ~ | ✗ | Secondary |
| 10 | **Insecure native messaging** | Talks to a native host | Sandbox escape | ✔ | ~ | ~ | Manifest flag; out of core scope |
| 11 | **CSP / policy weakening** | Relaxed CSP, remote code (MV2) / rules channel (MV3) | RCE-like | ✔ | ~ | ~ | Manifest diff; MV3-aware |
| 12 | **Affiliate / ad / search hijack** | Redirect via DNR rules, inject scripts | Fraud, tamper | ~ | ✔ | ✔ | Behavioural diff |
| 13 | **Fingerprinting / privacy violation** | Probe environment, track | Deanonymisation | ~ | ✔ | ~ | Behavioural, secondary |
| 14 | **Logic flaws / vulnerable benign ext** (VEX class) | Exploitable flow in *benign* code | Web-page-triggered escalation | ✔ | ~ | ✗ | **Out of scope** (we target *malice*, not *bugs*) |

**[OURS]** extdrift centres on **classes 1–6 and 12** — the **behavioural / capability**
classes that (a) are the actual attack payloads in §1's incidents and (b) are **best seen
dynamically**. Classes 8–11 and 14 (largely static, code-vulnerability-flavoured) are
**explicitly out of scope**; conflating them is the over-broad "vulnerability detection"
objective the faculty warned against (§6).

---

## 4. After a Malicious Update Reaches a User — Detect → Block → Disable → Rollback → Recover

**[FACT]** These are **five different capabilities**, held by **different parties**:

| Stage | Chrome/Chromium | Firefox | Edge | End user? | Notes |
|---|---|---|---|:-:|---|
| **Detect** | Google review/telemetry; Safety Check | AMO review + blocklist | MS review | **No (limited)** | Detection is mostly vendor/store-side, often **after** exposure |
| **Block (new installs)** | CWS takedown + blocklist | AMO blocklist | Add-ons takedown | No | Stops *further* spread, not those already updated |
| **Disable (installed)** | **Google remote kill-switch**: flag as malware → auto-disabled; enterprise `ExtensionInstallBlocklist` | Blocklist auto-disables | Similar | Partially (uninstall) | A **malware-flagged** ext can't be re-enabled by the user |
| **Rollback (to prev version)** | **Not available to users**; enterprise can **pin a version** via `ExtensionInstallForcelist`/`ExtensionSettings` | No user rollback | No user rollback | **No** | Stores hold all versions and *could* revert with "perfect fidelity" (You've-Changed) — users cannot |
| **Recover (undo damage)** | Out of browser scope | — | — | **No** | Stolen cookies/tokens are already exfiltrated → **rotate credentials, revoke sessions** at the *service* side |

Sources: [Chrome enterprise extension policies](https://developer.chrome.com/docs/webstore/review-process) ·
[Tech Lockdown — blocklist/ExtensionInstallForcelist](https://www.techlockdown.com/articles/how-to-block-chrome-extensions).

**[OURS] Blunt conclusions for the faculty:**
- **Prevention/rollback for an individual user is essentially not available** — updates are
  silent, there is no user-facing "revert extension" button, and by the time a malicious update
  runs, **exfiltration may already be complete** (the damage is *irreversible* at the browser
  layer; only service-side credential rotation helps).
- **Disable/block exist but are vendor- or enterprise-controlled and usually post-exposure.**
- **This is precisely why our value is early *detection* at the store/enterprise/researcher
  tier — before propagation — not consumer-side recovery.** An update-diff that flags a bad
  version *as it is published* is worth far more than any after-the-fact user action, because
  the after-the-fact actions barely exist.

---

## 5. Model Selection — evidence-based, *not* "XGBoost because everyone uses it"

**[FINDING] What the extension/security literature actually uses.** Published extension
detectors are dominated by **classic tabular ML on static/metadata features** — studies
compare **SVM, RF, KNN, XGBoost** on self-collected sets, and combined ML+feature-engineering
work reports **>95% lab** ([Springer 2023](https://link.springer.com/chapter/10.1007/978-3-031-28332-1_13)).
On tabular data generally, **gradient-boosted trees (XGBoost) usually edge out RF/SVM**
(Grinsztajn, NeurIPS 2022) — so XGBoost is a **reasonable prior, not a proven winner for us**.

**[OURS] Candidate comparison for *our* representation (the delta feature vector Δ):**

| Model | Fit for Δ (tabular, small) | Interpretability | Train/infer cost | FP control | Verdict for us |
|---|---|---|---|---|---|
| **Logistic Regression** | Weak-moderate | High | Trivial | Baseline | **Floor baseline** — if we can't beat it, stop |
| **Weighted rules (ours)** | Good (hand-tuned) | **Highest** | None | Good | **Control** — ML must beat this |
| **Random Forest** | **Strong** | High (importances) | Low | Good | **Baseline** — robust on small data |
| **XGBoost / LightGBM** | **Strong (usually best tabular)** | Med (+SHAP) | Low-med | Good with tuning | **Leading candidate** — but *prove it* |
| **SVM (RBF)** | Moderate | Low | Med | Med | Secondary baseline |
| **MLP / deep nets** | **Weak on small tabular** | Low | High | Overfits | **Reject for Tier 1** (Grinsztajn) |
| **Sequence (Transformer/LSTM)** | N/A for Δ; needs event sequence | Low (+attention) | High | Data-hungry | **Tier 2** (representation change) |
| **Graph (GNN)** | N/A for Δ; needs data-flow graph | Low | High | Data-hungry | **Tier 2** (novelty) |
| **Anomaly (OC-SVM/IsoForest/AE)** | Good for *unknown* | Med | Low-med | Tunable | **Complementary** (§8) |

**[OURS] The defensible procedure (this is the answer):** we do **not** pre-declare a winner.
We run a **bake-off** — LogReg (floor), the rule scorer (control), RF, XGBoost, SVM — on the
**same Δ features**, and **select by PR-AUC and false-positive-rate at a fixed recall**, under
**time-based, extension-level cross-validation** (§10), reporting **accuracy, precision,
recall, F1, ROC-AUC, PR-AUC, and the confusion matrix**, with class imbalance handled
(class weights / stratified resampling) and **SHAP** for explanation. **The final model is
whatever wins that bake-off** — our prior is XGBoost, but it must earn it. *(Adjacent-task
figures — XGBoost ~86–94% on malicious-URL/phishing — are indicative only, not evidence for
our task.)*

---

## 6. What Exactly Will the Model Predict? (one precise task)

**[OURS] The task — binary classification of an *update pair*, not "vulnerability detection":**

```
INPUT     : two versions (v_N trusted baseline, v_{N+1} candidate) of the SAME extension
FEATURES  : Δ = f(T_{N+1}) − f(T_N)  — the 24-dim behavioural-difference vector
            (+ static manifest/permission delta)
MODEL     : the bake-off winner (§5) → probability
PREDICTION: P(the update introduced malicious/security-relevant behavioural change) ∈ [0,1]
ACTION    : rank/flag the update for review + explainable evidence (fired rules + SHAP)
```

**[OURS] What it is *not*, and what it *cannot* establish (state this plainly):**
- It is **not** "is this extension malicious" (single-version), **not** code-vulnerability
  discovery, **not** zero-day *vulnerability* finding.
- It **cannot** prove intent or legality; **cannot** find payloads that **never trigger** in
  our scripted run (server-gated/time-bombed); **cannot** reliably judge behaviours **absent
  from training** without the anomaly layer (§8); **cannot** generalise across unseen extension
  *families* without care to avoid memorisation (§10).
- Its output is **decision support** (a ranked, explained flag), not an automated verdict.

---

## 7. Dataset Strategy — what exists, and why we must construct our own

**[FINDING] Available sources and their limits:**

| Source | Samples | Ecosystem | Labels | Versions? | Limits |
|---|---|---|---|:-:|---|
| **mallorybowes/chrome-mal-ids** | thousands of malicious **IDs/IOCs** | Chrome/Edge | malicious | No | IDs only, not code/versions |
| **"It's not Easy" ground truth (2025)** | **341 malicious** exts from disclosures | Chrome | malicious | No | Small; single-version |
| **Antivirus-for-extensions set** | **990 malware / 22 benign** CRX *(verify)* | Chrome | both | No | Tiny benign side; single-version |
| **You've Changed corpus** | **~922k versions / 6 yr** | Chrome | weakly (rating-anomaly) | **Yes** | Static-oriented; labels weak; not a clean public download |
| **chrome-stats.com / crx4chrome** | version histories, old `.crx` | Chrome | none | **Yes** | Unofficial; integrity caveats; popular exts only |
| **GitHub open-source extensions** | many | all | none (benign) | **Yes (tags)** | The best **real benign update-pair** source |
| **Web Store crawl** | ~100k+ | Chrome | none | latest only | No history; unlabeled |

**[OURS] There is no public, labelled dataset of malicious *update pairs*.** Every source is
single-version, ID-only, or unlabeled-with-history. Therefore we **construct our own**:
1. **Real benign pairs** — consecutive **GitHub releases** of open-source extensions +
   archive versions (crx4chrome) + our own **weekly self-snapshots** → the **false-positive**
   evaluation set (the metric that matters).
2. **Synthetic malicious pairs** — real benign `v1` + injected payload families (cookie/token
   theft, ad/affiliate injection, keylogging, SW beaconing) → the **detection** training set.
3. **Real malicious anchors** — reconstruct **Cyberhaven** and IDs from `chrome-mal-ids` where
   a prior benign version is archivable → **held-out external validity**.

This is the honest **synthetic-train / real-validate** design, and it is *forced* by the
evidence, not a shortcut.

---

## 8. Unknown / Hidden Threats — classification vs discovery (be honest)

**[OURS] Two different claims, kept strictly separate:**
- **(A) Classification of known malicious *behaviour patterns*** — supervised model on Δ.
  Realistic and what we primarily do.
- **(B) Discovery of previously-unknown *vulnerabilities* (zero-days)** — **we do NOT claim
  this.** Finding novel *vulnerabilities* is a different research problem; our system detects
  *malicious behavioural change*, not latent code flaws.

**[FINDING] What is realistic for *unseen malicious updates* (payloads not in training):**
anomaly/novelty methods learn "**normal benign-update behaviour**" and flag **deviation** —
**One-Class SVM, Isolation Forest, autoencoders** are the standard tools
([Deep Learning for Zero-day Malware, ACM CSUR 2023](https://dl.acm.org/doi/10.1145/3605775)).
Because our **baseline is the extension's own prior version**, "normal" is unusually
well-defined, which *helps* novelty detection. So:

- **[OURS] Realistic:** flag an update whose behavioural delta is **anomalous relative to
  benign updates** even if its exact payload was never seen — a *complementary anomaly layer*
  on Δ (semi-supervised, trained on benign deltas).
- **[OURS] Not realistic / do not claim:** "our ML finds zero-day vulnerabilities." We detect
  **novel malicious *behaviour changes***, not novel *code vulnerabilities*, and even then only
  behaviours our scenarios **trigger**.

---

## 9. Static, Dynamic & Honeytrap Pages — what we actually need

**[OURS] Necessity analysis, tied to the evidence:**
- **Static analysis:** keep a **thin** layer only — manifest/permission diff (cheap, pre-execution,
  §3 classes 4/8/11). **Not** the core: obfuscation/WASM/dynamic code defeat it (Part I §3;
  You've-Changed's stated weakness).
- **Dynamic execution + browser instrumentation + runtime monitoring:** **required.** It is the
  only way to see obfuscated/condition-gated payloads and MV3 service-worker exfiltration — our
  whole thesis. Already implemented.
- **Honeytrap / deception pages (Hulk-style HoneyPages):** **partially adopt, don't over-invest.**
  HoneyPages *elicit* dormant behaviour by satisfying any selector an extension probes — powerful
  for coverage, but **adaptive pages are non-deterministic**, which fights our record/replay
  requirement. **[OURS] We use *scripted deterministic scenarios + a fixed deception test-site*
  (fake bank/webmail/collector)** — a lighter, determinism-friendly descendant of HoneyPages.
  Full adaptive HoneyPages are a **stretch** (coverage vs. determinism trade-off; adds FP risk).
- **Taint / data-flow analysis:** **stretch (Tier 2 graph model).** True taint is the ideal
  exfiltration signal but heavy; our temporal-adjacency `exfil_flows` feature is the lightweight
  stand-in.
- **Hybrid static+dynamic:** **the recommended architecture** (§ Synthesis).

**[OURS] Verdict:** dynamic analysis is **necessary, not optional**; honeytrap *deception content*
is useful and already present in lightweight form; **full adaptive HoneyPages and full taint are
scope-inflating** and belong in the stretch tier.

---

## 10. Evaluation Methodology — defensible, leakage-free

**[OURS] Design (this is what makes results credible, not just high):**
- **Extension-level splitting, never file-level.** All versions/pairs of one extension go
  **entirely** into train **or** test — otherwise the model memorises an extension's style and
  inflates scores. This is the single most important anti-leakage rule.
- **Time-based split** for the temporal/version dimension: train on older pairs, test on newer
  → measures real deployment (and exposes **concept drift**, documented for extensions —
  [Rosenzweig, TWeb 2025](https://aurore54f.github.io/papers/2025-tweb_rosenzweig_extensionsconcdrift.pdf)).
- **Class imbalance:** malicious ≪ benign → report **PR-AUC** (not just ROC-AUC) and **FPR at
  fixed recall**; use class weights / stratified CV; **never** accuracy alone.
- **Zero-day/unknown evaluation:** hold out **entire payload families** from training; test
  whether the anomaly layer (§8) still flags them → measures generalisation to unseen malice.
- **Cross-extension & cross-browser generalisation:** test on extensions (and, stretch, Firefox)
  unseen in training.
- **Anti-memorisation guards:** strip library/vendor identifiers from features; ensure the model
  keys on **behavioural change**, not on which library or extension it is.
- **Ground truth:** the fake collector's log independently confirms what actually exfiltrated,
  so detection is measured against reality, not only labels.

---

## Final Synthesis

1. **Problem validation** — **[FINDING]** A decade of independent incidents (DataSpii → Nano →
   Great Suspender → Palant 87M → Cyberhaven → 2025 spyware waves), tens of millions of users,
   via two recurring vectors (**supply-chain/account compromise** and **ownership transfer**),
   both expressed as **behavioural change on update**. Not a one-incident project.
2. **Technical difficulty** — **[FINDING]** The load-bearing challenges (determinism, false
   positives, unknown payloads, labelled update-pair data) are **partially or not solved** in
   prior work; that is what makes it research.
3. **Vulnerability taxonomy** — **[OURS]** 14 classes; we own the **behavioural/capability**
   ones (malicious update, credential/cookie theft, exfiltration, permission/API abuse, SW
   abuse, hijacking) and explicitly exclude static code-vulnerability classes.
4. **End-to-end security position** — **[FINDING]** Detect (vendor/store, often late), Block/
   Disable (vendor/enterprise), **Rollback (not for users)**, Recover (**irreversible** at
   browser layer; service-side credential rotation only). → value = **early detection before
   propagation**, not consumer recovery.
5. **ML strategy** — **[OURS]** Predict **P(update introduced malicious behavioural change)** on
   the version-difference vector Δ; decision-support output; clear "cannot" boundaries.
6. **Model selection** — **[OURS]** **Bake-off** (rules, LogReg, RF, XGBoost, SVM) on Δ, chosen
   by **PR-AUC + FPR** under time/extension-level CV; XGBoost is the prior, not the assumption;
   sequence/graph = Tier-2; anomaly layer = novelty.
7. **Dataset strategy** — **[FINDING/OURS]** No public labelled update-pair set exists →
   **construct our own**: real benign pairs (GitHub/archives/snapshots) + synthetic malicious +
   real anchors (Cyberhaven, `chrome-mal-ids`).
8. **Unknown-threat detection** — **[OURS]** Realistic: **anomaly on Δ** flags novel malicious
   *behaviour change*; **not** claimed: zero-day *vulnerability* discovery.
9. **Recommended architecture** — **[OURS]** **Hybrid:** thin **static** (manifest/perm diff) +
   **dynamic** behavioural capture (deterministic scenarios + deception test-site) + **update
   diff** + **dual scoring** (rules + bake-off ML on Δ) + optional **anomaly** layer. **Not**
   full adaptive HoneyPages / full taint / GNN in Project-1 (stretch).
10. **Final project recommendation** — **[OURS] NARROW + REFRAME (keep the core, cut the
    overreach).** Keep: dynamic behavioural update-diffing + determinism + explainability. Drop:
    "language-aware analysis," consumer pre-execution prevention, zero-day *vulnerability*
    discovery. Reposition for **store/enterprise/researcher** deployment. This is stronger and
    fully defensible; **do not reject** the idea, and **do cite You've Changed (CCS 2020)** as
    the static predecessor we improve on dynamically.

---

## Complete Faculty Validation — 12 direct answers

1. **Why is this problem important?** Trusted, auto-updating, high-privilege code can turn
   malicious after every existing check, silently, to millions — repeatedly.
2. **Evidence beyond Cyberhaven?** DataSpii (2019), Nano (2020), Great Suspender (2021), Palant's
   ~87M-install campaign (2023), 2025 Chrome/Edge spyware waves, 2025–26 crypto stealers — §1.
3. **Why technically difficult?** Obfuscation defeats static; dynamic behaviour must be *elicited*
   and separated from web noise; labelled update-pair data is scarce; false positives are the
   field's real bottleneck (98% lab ≠ usable) — §2.
4. **Which vulnerabilities beyond code injection?** Malicious updates, credential/cookie/token
   theft, data exfiltration, permission/API abuse, MV3 service-worker abuse, ad/search hijack,
   message-passing & native-messaging flaws, CSP weakening, privacy/fingerprinting — §3.
5. **What happens when a malicious update reaches a user?** It usually **executes and exfiltrates
   before detection**; damage at the browser layer is **irreversible** — §4.
6. **Can it be detected/blocked/disabled/reverted?** Detect/block/disable: yes, but **vendor- or
   enterprise-side and often late**. **Rollback: not for users.** Recovery: service-side
   credential rotation only — §4.
7. **Why use ML?** To learn feature *combinations* and *weightings* over the diff that hand rules
   can't tune, and to give a calibrated, rankable score — **but only if it beats the rule
   baseline** (the control) — §5.
8. **Why XGBoost — or another model?** XGBoost is the **tabular prior**, not a foregone
   conclusion; the choice is settled by a **bake-off** on our Δ features measured on PR-AUC/FPR —
   §5.
9. **What data trains/evaluates it?** A **self-constructed** corpus — real benign update pairs +
   synthetic malicious + real anchors — because **no public labelled update-pair dataset
   exists** — §7.
10. **How to handle previously-unseen threats?** An **anomaly layer** on Δ flags novel malicious
    *behaviour change*; we **do not** claim zero-day *vulnerability* discovery — §8.
11. **Role of static / dynamic / honeytrap?** **Dynamic is the core** (necessary), **static is a
    thin cheap layer**, **deception content is a lightweight deterministic test-site**; full
    adaptive HoneyPages/taint are stretch — §9.
12. **Strongest defensible version of the project?** *Deterministic dynamic behavioural
    update-diffing of consecutive extension versions, hybrid static+dynamic, dual-scored
    (rules + experimentally-chosen ML on Δ) with an anomaly layer for novelty, explainable, and
    positioned for store/enterprise/researcher deployment* — §Synthesis.

---

## Additional References (Part II)

- Malicious Chrome extensions, 75M installs removed. *BleepingComputer.* [link](https://www.bleepingcomputer.com/news/security/malicious-chrome-extensions-with-75m-installs-removed-from-web-store/)
- Dangerous Chrome extensions, 87M downloads. *Kaspersky.* [link](https://www.kaspersky.com/blog/dangerous-chrome-extensions-87-million/48562/)
- Millions spied on by malicious Chrome/Edge extensions (2025). *Malwarebytes.* [link](https://www.malwarebytes.com/blog/news/2025/07/millions-of-people-spied-on-by-malicious-browser-extensions-in-chrome-and-edge)
- 18 Malicious Chrome/Edge extensions. *Infosecurity Magazine.* [link](https://www.infosecurity-magazine.com/news/18-malicious-chrome-edge-extensions/)
- mallorybowes/chrome-mal-ids — malicious extension IOC list. *GitHub.* [link](https://github.com/mallorybowes/chrome-mal-ids)
- Detecting Malicious Browser Extensions by Combining ML and Feature Engineering. *Springer 2023.* [link](https://link.springer.com/chapter/10.1007/978-3-031-28332-1_13)
- Deep Learning for Zero-day Malware Detection and Classification: A Survey. *ACM Computing Surveys 2023.* [DOI](https://dl.acm.org/doi/10.1145/3605775)
- Grinsztajn et al. Why do tree-based models still outperform deep learning on tabular data? *NeurIPS 2022.* [arXiv](https://arxiv.org/abs/2207.08815)
- Rosenzweig et al. Concept drift in extension detection. *TWeb 2025.* [PDF](https://aurore54f.github.io/papers/2025-tweb_rosenzweig_extensionsconcdrift.pdf)
- Towards Browser Controls to Protect Cookies from Malicious Extensions (CREAM). *arXiv 2405.06830.* [PDF](https://arxiv.org/pdf/2405.06830)
- Chrome enterprise extension management (ExtensionInstallForcelist / blocklist). [Tech Lockdown](https://www.techlockdown.com/articles/how-to-block-chrome-extensions)

*(Part I references — You've Changed CCS 2020, ExtPrivA, Hulk, VEX, MV3 Unveiled, Palant remote-code, Sekoia, Arcanum, etc. — are not repeated here.)*
