# Literature Alignment — how extdrift follows top-tier security-paper methodology

*Advisor directive (18 Sep 2026): read how strong security papers (IEEE S&P, USENIX, NDSS,
ACM CCS, UNB-CIC) are written and adopt their techniques and parameters. This document maps
every part of extdrift onto that literature, shows we avoid the pitfalls those papers warn
about, and lists the concrete gaps to close. Source: the Gemini deep-research survey in
`Reference Docs/Research Gemini/` (39+ cited works).*

---

## 1. Our design maps directly onto the top-tier methodology

| Paper-established technique | Source | What extdrift does |
|---|---|---|
| **Bait-and-switch / update-delta threat model** — score the *change* between versions, not the extension | *You've Changed* (CCS'20) | This **is** our threat model and unit of analysis (`Δ = f(v2) − f(v1)`) |
| **Permission *shifts*, not absolute permissions** | *You've Changed* | `stat_added_highrisk_perms`, `stat_escalated_broad_host`, `stat_added_hosts` (manifest diff) |
| **Dynamic behavioural capture** (obfuscation defeats static) | Hulk (USENIX'14), Arcanum (USENIX'24) | our 4-channel sandbox capture; the head-to-head shows static missing an obfuscated payload we catch |
| **Eliciting dormant behaviour** (HoneyPages, event fuzzing) | Hulk | scripted user scenarios that drive login/interaction to trigger payloads |
| **Dynamic taint: sensitive source → network sink** | Arcanum, CodeX (CODASPY'25) | `exfil_flows` / `exfil_flows_third_party` (a temporal-adjacency *approximation* of taint) |
| **MV3 service-worker exfiltration channel** | Karami-lineage, MV3 studies | SW instrumentation + `net_worker_initiated`; a `sw_beacon` family |
| **Network-topology / C2 features** | multiple | `net_third_party_hosts`, `net_encoded_params` (DGA/encoded-payload proxy), new-upload-host detection |
| **Model choice: RF + XGBoost for tabular, heterogeneous, sparse features; interpretable** | consensus across the survey | our bake-off; **XGBoost wins**; SHAP-style importances for explainability |
| **Zero-shot / embedding detection for novel classes (concept drift)** | *You've Changed* (ZSL) | our **anomaly layer** (one-class on benign deltas → flags unseen families) |
| **Metrics: Precision/Recall/F1/FPR, not accuracy** | all | we report exactly these + PR-AUC |
| **Temporal cross-validation (train past, test future)** | concept-drift studies | time-based split (being strengthened to strict temporal, §3) |
| **Ablation studies to justify each component** | all top-tier | `experiments/feature_ablation.py` (implemented) |
| **Class-imbalance handling (SMOTE / balancing)** | CICMalDroid (UNB-CIC) | class-weighting now; SMOTE is an easy add |
| **VirusTotal is unreliable for extensions** (tuned for PE/APK) | survey | we do **not** use VT; ground truth is behavioural + threat-intel IOC list |

**Takeaway for the panel:** our architecture is not ad-hoc — every component corresponds to a
technique used in a top-tier paper, and our headline choices (update-delta, dynamic behaviour,
RF/XGBoost, anomaly layer, PR-AUC/FPR, ablation) are the field's standard rigour.

---

## 2. The six "student pitfalls" the survey names — and how we avoid each

| Pitfall (junior projects) | Expert approach | extdrift status |
|---|---|---|
| **1. Ignoring multi-component architecture** (content script can't call `chrome.cookies`; must message the worker) | model inter-component message passing (DoubleX's Extension Dependence Graph) | **Partial** — we instrument content scripts *and* the service worker and attribute request initiators; full message-passing *graph* is our Tier-2 GNN |
| **2. Failing to isolate the update delta** (diffing whole codebases is noisy) | feature vector from the *delta* only | **Done** — everything is `Δ = f(v2) − f(v1)` |
| **3. Underestimating dilatory evasion** (fixed 10 s, no triggers) | HoneyPages + event-handler fuzzing to elicit dormant payloads | **Partial** — scripted login/interaction scenarios trigger payloads; broader elicitation is a planned upgrade |
| **4. Ignoring MV3 constraints** (assuming MV2 remote code) | parse for MV3 evasion (relaxed CSP, `declarativeNetRequest` ruleset abuse) | **Done** — MV3-aware; a `redirect_hijack` family abuses `declarativeNetRequest` |
| **5. Temporal data leakage** (random 80/20 lets you train on the future) | strict temporal split (train year N, test N+1) | **Strengthening** (§3) — extension-level split done; strict temporal next |
| **6. No ablation study** (unjustified component complexity) | disable feature sets, measure F1 drop | **Done** — `experiments/feature_ablation.py` |

We can honestly tell the panel: *of the six pitfalls the literature flags, three are fully
addressed, and the other three are explicitly scoped (message-passing graph and broader
elicitation as Tier-2; strict temporal split in progress).*

---

## 3. Concrete upgrades this survey justifies (our near-term backlog)

Status as of 2026-09-19 — items 1–5 implemented; 6 seeded; the extensiondeltas fold-in has a
working adapter and awaits the multi-GB download (the data-acquisition / Mac-scale step).

1. **Strict temporal split** (pitfall #5) — DONE (commit 5d40f54). Train on earlier updates, test
   on later; reported as a first-class row in the bake-off. Winner holds up (RF temporal PR-AUC
   0.977 vs rules 0.851), so the model generalises to future updates, not just memorised ones.
2. **SMOTE / explicit class balancing** — DONE (commit fabb9bf). Dependency-free SMOTE applied to
   TRAIN folds only, behind `--smote`. Finding: equivalent to `class_weight='balanced'` here
   (RF ≈ 0.98 either way) — reported honestly, not cherry-picked.
3. **AST-diff static baseline** — DONE (commit bd840b7). `engine/features/ast_diff.py` reduces JS
   to a structural token skeleton (renaming ≠ churn) and diffs it linearly; the You've Changed
   structural-similarity idea as a *baseline*. `experiments/ast_diff_baseline.py` scores it head to
   head against the semantic static-code deltas on real AMO pairs (leave-one-extension-out RF).
4. **Message-passing signal** — DONE (commit fabb9bf). `msg_passing` counts cross-component IPC
   (runtime/tabs message-passing); the generator splits the kill-chain across content script and
   service worker so it is a soft, overlapping signal. Ablation: weak alone (0.475), complementary
   — an evasion-robustness feature, not a separator. The full Extension Dependence Graph is Tier-2.
5. **Domain-reputation feature** — DONE (commit fabb9bf). `net_lowrep_hosts` scores upload
   destinations by DGA/NRD-like lexical reputation (Antonakakis USENIX'12); soft by design
   (legitimate vendor-telemetry domains trip it too), lifting network-alone PR-AUC 0.858 → 0.893.
6. **NLP policy-consistency feature** (ExtPrivA/AudAgent) — SEEDED. The extensiondeltas adapter
   (`engine/collector/extensiondeltas.py`) can stream the corpus's store-description text, which is
   the raw material for a stated-purpose-vs-observed-behaviour signal. *(stretch — feature not yet
   built)*

**Public corpus fold-in — extensiondeltas** (Pantelaios, Nikiforakis, Kapravelos, CCS'20):
adapter DONE (commit bd840b7). `sample_descriptions` pulls the plain-text descriptions from GitHub
now; `load_local_corpus` reads the unzipped `clusters` labels + `apiCategories` tables once the
full multi-GB corpus is downloaded and unzipped — that download is the remaining data step.

---

## 4. Datasets & version-acquisition the survey confirms (our data plan, evidenced)

**Public datasets that exist (and how we use them):**
- **chrome-mal-ids (TPCI), CC BY 4.0** — 7,382 malicious IDs *(committed to `data/real/`)*; its
  schema carries `THREAT-TYPE` and an **`OWNERSHIP-TRANSFER`** flag — directly our bait-and-switch
  cases. Use as a real-malicious reference / validation list.
- **`extensiondeltas` corpus ("You've Changed", public: github.com/wspr-ncsu/extensiondeltas)** —
  152k extensions, 922k versions, 5,151 static feature records; both classes. The closest public
  update-pair corpus — a target to fold in.
- **WasmMal-15K, GenAI-341, ISCX-URL** — adjacent (WASM / GenAI / URL); not core to update-diffing.

**Version acquisition (how we get old + new versions), evidenced:**
- **Mozilla AMO v5 API** — full version history + direct `.xpi` URLs → **the gold standard for
  real benign pairs**. **Implemented** (`engine/collector/amo.py`); 10 real pairs pulled.
- **Chrome Omaha update endpoint** — current version only; **implemented** (used to pull Dark
  Reader/Grammarly/Stylus).
- **crx4chrome / chrome-stats** — historical CRX, best for *malicious* old versions.
- **GitHub releases** — open-source benign source pairs.
- **Self-snapshot** — capture real auto-updates over time; **implemented**.

**Ground-truth labelling (the survey's hybrid standard, which we adopt):** Google/AMO takedowns
(lagging) + third-party threat-intel IOC lists (our chrome-mal-ids) + manual verification;
synthetic pairs are ground-truth-by-construction. **We explicitly avoid VirusTotal** because the
literature shows it is tuned for PE/APK and unreliable for JS extensions.

---

## 5. Adware — the advisor's specific question, answered from the literature

**Verdict: adware / ad-injection / affiliate-fraud IS a malice class**, and the literature treats
it so: Hulk catalogued ad-injection and affiliate abuse; DataSpii was mass data-harvesting; the
2025 malicious-GenAI study includes traffic redirection; CREAM (2024) targets cookie/session
abuse. Behaviourally it is covered by `dom_injections`, new third-party hosts, and
`declarativeNetRequest` redirects — we already generate `ad_affiliate` and `redirect_hijack`
families. **The one discriminator to add (from the survey):** separate malicious ad-injection from
a *legitimate* ad-blocker/coupon extension — the update-delta helps (a benign ad-blocker's ad
behaviour is present in *both* versions), and we will document the exact features per the papers.

*Companion: [../design/DESIGN_RATIONALE.md](../design/DESIGN_RATIONALE.md) (our methodology),
[FEASIBILITY_AND_NOVELTY.md](FEASIBILITY_AND_NOVELTY.md) and Part II (the gap we fill).*
