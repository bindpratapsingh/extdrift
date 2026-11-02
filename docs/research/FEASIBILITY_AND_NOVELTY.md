# Feasibility, Security Gap & Novelty — an Evidence-Based Study

**Project:** Behavioural-Diff Detection of Malicious Browser-Extension Updates (extdrift)
**Purpose:** answer, from the literature and vendor documentation rather than from our own
optimism, the three questions Dr. Mishra raised — (1) does the extension's
language/runtime affect its security, (2) can we realistically protect an end user, and
(3) how are we different from what browsers/stores already do — and to decide, honestly,
whether the project is novel and feasible.

**Method note.** Claims are tagged **[FACT]** (established / vendor-documented),
**[FINDING]** (from a specific paper/report — cited), **[ASSUMPTION]** (reasonable but
unverified), **[OURS]** (our interpretation/design choice). Numbers taken from search-level
reading of papers are marked *verify in source* — confirm the exact figure in the PDF
before quoting it to an examiner.

---

## ⚠️ Two corrections this research forces on our own materials

1. **The core idea is *partly taken* — and we must reposition, not retreat.** There is a
   top-tier paper doing *update-delta* detection of malicious extensions:
   **Pantelaios, Nikiforakis, Kapravelos, "You've Changed: Detecting Malicious Browser
   Extensions through their Update Deltas," ACM CCS 2020**
   ([DOI](https://dl.acm.org/doi/10.1145/3372297.3423343) ·
   [PDF](https://kapravelos.com/publications/extensiondeltas-CCS20.pdf)). It analyses
   **922,684 extension versions over six years** and finds **143 malicious extensions in 21
   clusters** *(verify in source)*. **But it is STATIC code-delta analysis** — it locates
   the *code* added between versions and encodes the delta by the **APIs the new code
   abuses**; its first stage even triggers on **anomalous rating patterns**, not behaviour.
   The authors and follow-up work note it is **vulnerable to obfuscation/evasion** — the
   known weakness of static analysis. **Our wedge is therefore not "diff two versions" (that
   exists) but "diff two versions *dynamically, by behaviour, with deterministic inputs*,"
   which is obfuscation-resistant by construction.** See §7.

2. **Our "Karami (NDSS 2021)" citation is misattributed — fix it before the meeting.** The
   real paper is **Karami, Ilia, Polakis, "Awakening the Web's Sleeper Agents: Misusing
   Service Workers for Privacy Leakage," NDSS 2021** — but it is about the **Service Worker
   *web* API abused by *websites*** for tracking/leakage, **not** about Manifest V3
   *extension* background service workers. Citing it for "MV3 extension service workers leak
   without a page" is a mischaracterisation an examiner could catch. Either recharacterise it
   accurately (web service workers as a background-exfiltration precedent) or cite the MV3
   extension architecture directly (Chrome MV3 docs) plus a MV3-security paper (§3). Karami
   is *also* the author of **Carnus (NDSS 2020)**, on extension *fingerprinting* — don't
   conflate the two.

Neither is fatal. Both make us look **more** rigorous if *we* raise them first.

---

## 1. Executive Summary

- **[FINDING] Extension insecurity is not a language/runtime problem.** Extensions are
  JavaScript/HTML/CSS running in a memory-safe engine; the dominant risks are **permissions,
  host access, powerful browser APIs, third-party/supply-chain code, and human/account
  compromise** — not buffer overflows or the choice of JS vs WASM. WebAssembly and native
  messaging add niche risk but are rarely the vector. *Implication: the "language-aware
  analysis" angle in our original pitch is weak and should be dropped or de-emphasised.* (§3)
- **[FINDING] For an ordinary end user, prevention-before-execution is largely infeasible for
  an external tool.** Updates are silent and automatic; the browser gives outside tools
  little pre-execution visibility or veto. Realistic value is at the **store / enterprise /
  researcher tier** (pre-distribution or fleet monitoring) and as **fast detection + response**,
  not as consumer-grade prevention. (§6) This reshapes our positioning.
- **[FACT] Browsers/stores already do a lot** — package signing, manifest/permission
  validation, automated static + manual review (applied to updates too), malware/reputation,
  isolation/CSP, and MV3's remote-code ban. **[FINDING] But these are bypassable** by
  obfuscation, dormant/condition-gated payloads, staged rollouts, and — above all —
  **compromised-legitimate extensions** whose malicious *update* passes review. Cyberhaven
  (Dec 2024) was **not** an extension-analysis failure; it was an **OAuth/developer-account
  compromise** whose malicious update then shipped normally. (§4, §5)
- **[OURS] The honest, defensible gap:** *deterministic, dynamic, behavioural diffing of
  consecutive versions to catch security-relevant behavioural change introduced by an
  update — especially in compromised-legitimate extensions — with explainable output.* The
  static version of this (You've Changed) exists; the **dynamic, determinism-anchored,
  obfuscation-resistant** version is open. (§7)

---

## 2. Extension Security Architecture (dev → store → install → runtime)

**[FACT] Build & languages.** Modern extensions (Chrome/Chromium, Edge, Firefox, Safari)
are **web apps**: JavaScript/TypeScript, HTML, CSS, JSON manifest; optionally WebAssembly,
and — via **native messaging** — a separately-installed native host. They run as
**content scripts** (injected into pages), a **background service worker** (MV3) or page
(MV2), and optional UI pages. Capabilities are gated by declared **permissions** and
**host permissions** ([Chrome MV3 docs](https://developer.chrome.com/docs/extensions/develop/migrate/what-is-mv3)).

**[FACT] Distribution & update.** Extensions ship through a **store** (Chrome Web Store,
Firefox AMO, Edge Add-ons, Safari via an Xcode-built app). The browser **auto-updates**
them silently in the background; the user is not asked to re-approve unchanged permissions,
and some permission additions do not raise a clear prompt (**"silent permission creep"** —
[Pluto Security](https://pluto.security/blog/chrome-extension-supply-chain-attacks-permission-creep/)).

**[FACT] Store review (Chrome).** Every submission — **including updates** — goes through
**automated analysis then human review**: malware-signature scanning, obfuscation and
dangerous-API heuristics, policy checks, manifest validity, install testing
([review-process docs](https://developer.chrome.com/docs/webstore/review-process)).

**[FACT] Runtime model.** Content scripts run in an **isolated world**; the extension is
constrained by **CSP** and the permission set; **MV3 forbids remotely-hosted code**
([improve-security docs](https://developer.chrome.com/docs/extensions/develop/migrate/improve-security)).
Once installed, though, an extension with broad host access effectively **sits in the middle
of the user's web traffic** ([Island](https://www.island.io/education/browser-extension-security-defending-against-excessive-permissions)).

---

## 3. Language / Runtime Security — does the language matter? (Q1)

**Short answer: [FINDING] No, not materially.** The evidence points to *permissions, APIs,
logic, dependencies, and human/supply-chain factors* as the real sources of risk, not the
language or runtime.

- **[FACT] Memory safety is a non-issue.** Extension code runs in the browser's JS engine,
  which is memory-safe; classic C/C++ bugs (buffer overflow, UAF) don't arise from extension
  JS. So the "unsafe-language" class of vulnerability is essentially absent by construction.
- **[FINDING] The real vectors are capability- and logic-level:** over-broad host
  permissions, abuse of powerful APIs (`cookies`, `webRequest`/`declarativeNetRequest`,
  `scripting`, `tabs`), insecure message passing, DOM injection, and **dynamic code
  execution** patterns — plus **third-party/supply-chain** code pulled into the bundle
  ([Island supply-chain](https://www.island.io/education/browser-extension-security-defending-against-supply-chain-compromises),
  [Aikido](https://www.aikido.dev/blog/browser-extensions-supply-chain-attack)).
- **[FINDING] JS-specific weaknesses (e.g., prototype pollution) exist but are logic bugs,
  not runtime faults** — they come from unsafe object handling in code/dependencies.
- **[FINDING] WebAssembly / native components add analysis *difficulty*, not a dominant
  attack class.** WASM and obfuscation make code *harder to inspect statically*, and native
  messaging widens the trust boundary, but these are minorities of real incidents. Their main
  relevance to us: **they defeat static analysis**, which is an argument *for* dynamic
  analysis, not for "language-aware" analysis.
- **[FINDING] MV3 reduced the runtime attack surface** — removed remote code, deprecated
  **~87.8% of vulnerable APIs** *(verify in source:*
  [Manifest V3 Unveiled, arXiv 2404.08310](https://arxiv.org/pdf/2404.08310)*)* — yet
  **~29.8% of analysed malicious extensions remained operational after V3 conversion** and
  **~56% adapted** via web-accessible resources *(verify in source, same paper)*. The
  remote-code ban is **circumventable** by shipping *configuration/rules* instead of code
  ([Palant, 2025](https://palant.info/2025/01/20/malicious-extensions-circumvent-googles-remote-code-ban/)).

**[OURS] Consequence for difficulty & design.** Because risk lives in *behaviour and
capability*, not in the language, a reliable analyser must observe **what the extension does
at runtime with its permissions**, not what language it is written in. This is *why* static
analysis is hard (obfuscation/WASM/dynamic code hide intent) and *why* our dynamic,
behavioural stance is the right lever. It also means we should **not** claim
"language-aware detection" as a contribution — the evidence doesn't support it.

---

## 4. Existing Browser / Store Defences — what they catch, where they stop (Q3)

**[FACT] What exists (Chromium family unless noted):**

| Mechanism | What it does | **[FINDING] Where it stops** |
|---|---|---|
| Package signing / CRX validation | Integrity + provenance of the package | Doesn't judge *behaviour*; a signed update from a *compromised* account is still trusted |
| Manifest & permission validation | Enforces declared capabilities | Declaration ≠ intent; **silent permission creep** on update is often unprompted |
| Automated static review | Malware signatures, obfuscation & dangerous-API heuristics | **Bypassable** by obfuscation, WASM, dynamic code, **dormant/condition-gated payloads** |
| Human review | Manual code/policy check | Not exhaustive; can't run every trigger path; **post-review updates** & staged rollouts evade |
| Malware/reputation + blocklist | Flags known-bad, revokes | **Reactive** — needs prior knowledge; zero-day updates slip until reported |
| Isolation / CSP / MV3 no-remote-code | Shrinks runtime surface | **~30% of malicious extensions still function post-MV3**; rules/config channels evade |
| Store review applies to updates | Same pipeline for updates | Same weaknesses; **trusted-then-malicious** update is the blind spot |

**[FINDING] Cross-browser differences.**
- **Firefox AMO** signs every add-on after **automated validation**, with **manual review at
  any time**; historically stricter data-use disclosure
  ([Extension Workshop](https://extensionworkshop.com/documentation/publish/signing-and-distribution-overview/)).
  A long-standing critique is that **automated scanning is limited** ("security theatre" —
  [Stillman 2015](https://danstillman.com/2015/11/23/firefox-extension-scanning-is-security-theater)).
- **Safari** ships extensions **inside a signed macOS/iOS app built with Xcode** — a
  different artifact and review queue, and (relevant to us) a **macOS-only, structurally
  different** target, which is why we exclude it.

**[OURS] The pattern:** existing defences are strong on **integrity, declaration, and
known-bad**, and weak on **novel behavioural change on update**, especially **obfuscated /
dormant** payloads and **compromised-legitimate** extensions.

---

## 5. Real-World Incidents — where exactly did security fail?

| Incident | What happened | **[FINDING] Failure locus** | Detected |
|---|---|---|---|
| **Cyberhaven + campaign (Dec 2024)** | OAuth-phishing of developer accounts ("Privacy Policy Extensions" OAuth app) → malicious updates to ~**35 extensions / 2.6M users** exfiltrating cookies/session tokens | **Account/OAuth compromise + supply-chain**, *not* an extension-analysis failure; the malicious update then shipped through the normal pipeline | **After** exposure — malicious build live **~24h+** ([Sekoia](https://blog.sekoia.io/targeted-supply-chain-attack-against-chrome-browser-extensions/), [SecurityWeek](https://www.securityweek.com/cyberhaven-chrome-extension-hack-linked-to-widening-supply-chain-campaign/)) |
| **The Great Suspender (2021)** | Extension (2M+ users) **sold to unknown party**, which added tracking/remote-code | **Ownership transfer + trust hand-off**; malicious code arrived via update | After; Google later removed it ([The Register](https://www.theregister.com/2021/01/07/great_suspender_malware/)) |
| **Nano Adblocker/Defender (2020)** | Devs **sold rights**; new owner added data-collection | **Ownership transfer / acquire-and-subvert** | After user reports ([LWN](https://lwn.net/Articles/846272/)) |
| **DataSpii (2019)** | Several extensions exfiltrated browsing/PII at scale | **Permission abuse + undisclosed data collection** | After investigation (Jadali) |

**[FINDING] The distinction the professor drew is correct and central.**
*Developer-account/OAuth compromise ≠ extension-analysis failure.* In Cyberhaven, no static
or dynamic *extension analyser* was defeated at upload time in the classic sense — the
**account** was taken and the update **passed review**. **[OURS] This is exactly the case a
behavioural *update-diff* addresses:** it doesn't care *how* the bad code got in (phishing,
sale, insider); it asks **"does this new version suddenly *do* something the trusted one
didn't?"** — the one question that catches trusted-then-malicious regardless of entry vector.

---

## 6. End-User Feasibility — can we protect the user before the update runs? (Q2)

**[OURS] Honest conclusion: for an ordinary end user, an external tool generally *cannot*
prevent a malicious update from executing — it can, at best, *detect fast and respond*.
Real prevention lives one tier up (store / enterprise / researcher).** Reasoning:

- **[FACT] Updates are silent and automatic.** The user never sees the new version before it
  runs; there is no natural interception point for a third party on a consumer machine.
- **[FACT] The browser gives outside tools little pre-execution power.** Another extension
  can't reliably inspect or veto a *sibling* extension's update; an OS agent sees the files
  but not the browser-internal behaviour without deep, privileged instrumentation.

**Deployment models, assessed [FINDING/OURS]:**

| Model | Pre-exec prevention? | Visibility | Notes |
|---|---|---|---|
| **Browser-integrated** (vendor) | **Yes** | Full | Only the vendor can do this; not us |
| **Store-side scanning** (pre-distribution) | **Yes** — before users get it | Full (all versions) | The natural home for update-diffing; "perfect fidelity" as *You've Changed* itself notes |
| **Enterprise policy / fleet monitoring** | **Partial** (allowlist + fast pull) | High | Realistic, valuable, deployable |
| **Endpoint/EDR agent** | Detect > prevent | Medium | Sees files/network, not browser internals |
| **A security *extension*** | **No** (can't veto siblings) | Low | Weakest option; avoid claiming consumer prevention |
| **Researcher/analyst tool (ours today)** | Detect (offline) | Full (lab) | Where our prototype sits; strongest for evaluation & evidence |

**[OURS] So we reposition the value proposition:** extdrift is a **pre-distribution /
enterprise / researcher** method — "re-verify behaviour on every update before (or as) it
propagates" — **not** a consumer shield. Said plainly to the professor: *"We can't stand
between Google's silent auto-update and one user's browser; we can give whoever governs the
update channel — a store reviewer, an enterprise, a researcher — an automatic behavioural
re-check of every new version, which is exactly the check nobody runs today."*

---

## 7. Research Gap & Novelty — classified honestly

**Solved well [FACT]:** package signing/integrity; permission *declaration* & isolation;
CSP; MV3 remote-code ban; known-malware/reputation blocklisting; store review pipeline.

**Partially solved [FINDING]:** static review of updates (bypassable by obfuscation/dormancy);
permission-change surfacing (silent creep); **static update-delta detection** — *this is
solved by You've Changed (CCS 2020), but statically and thus obfuscation-limited*.

**Weakly solved [FINDING]:** scalable **dynamic behavioural** analysis of extensions (Hulk
2014, ExtPrivA S&P 2023, Arcanum USENIX 2024, Fakeium 2024 exist, but are **single-version**);
detecting **dormant/condition-gated** payloads; explainable verdicts.

**Open / unsolved [OURS]:** **dynamic, behavioural, cross-version diffing with
record/replay determinism** — i.e., scoring the *behavioural change* of an update
obfuscation-resistantly, and specifically targeting **compromised-legitimate** extensions,
with **explainable** output. No work we found occupies this exact cell.

**The novelty wedge, stated defensibly:**

> Prior update-aware detection (You've Changed, CCS 2020) is **static code-delta** and, by
> the authors' own account, evadable by obfuscation. Prior dynamic behavioural analysis
> (Hulk, ExtPrivA, Arcanum) is **single-version**. **extdrift sits at the intersection:
> behavioural update-diffing made reliable by record/replay determinism** — which is
> obfuscation-resistant (we observe effects, not code) and false-positive-resistant (both
> versions see byte-identical input, so the diff is the extension, not web noise).

**[OURS] What we should *drop* from the original idea:** "language-aware analysis" (Q1 shows
it doesn't matter) and any claim of **consumer pre-execution prevention** (Q2 shows it's
infeasible for an external tool).

---

## 8. Required Comparison Table

*(“~” = partial; claims limited to what evidence supports.)*

| Capability | Chrome/Chromium | Firefox | Edge | Safari | **extdrift (ours)** |
|---|---|---|---|---|---|
| Static / package checks | Yes | Yes | Yes | Yes (app-signed) | ~ (manifest/perm diff only) |
| Permission checks | Yes | Yes | Yes | Yes | Yes (+ escalation diff) |
| Malware / reputation | Yes | Yes | Yes | Yes | No (not our aim) |
| Update validation | Yes (integrity + re-review) | Yes | Yes | Yes | **Yes — behavioural** |
| Runtime protection (isolation/CSP/MV3) | Yes | Yes | Yes | Yes | No (we analyse, not enforce) |
| Pre-installation protection | Yes (store) | Yes (store) | Yes | Yes | ~ (only if store/enterprise-deployed) |
| **Runtime behavioural detection** | ~ (limited) | ~ | ~ | ~ | **Yes** |
| **Update-to-update *behavioural* comparison** | **No** | **No** | **No** | **No** | **Yes (our core)** |
| Protection from **compromised-legitimate** extensions | **~ (reactive)** | ~ | ~ | ~ | **Yes (design target)** |
| Obfuscation-resistant update analysis | ~ (static, evadable) | ~ | ~ | ~ | **Yes (dynamic)** |
| Explainable per-verdict output | No (opaque) | No | No | No | **Yes (rules + SHAP)** |

Static code-delta update analysis (You've Changed) is **not a browser feature** and so isn't
a column, but it is our nearest *research* neighbour — the row that matters against it is
**"obfuscation-resistant update analysis,"** where our dynamic approach is the differentiator.

---

## 9. Recommended (Narrowed) Research Problem

**[OURS] Rewrite the problem statement to this:**

> *Given two consecutive versions of the same browser extension, detect — dynamically and
> obfuscation-resistantly — whether the update introduces security-relevant behavioural
> change (new data access, new exfiltration, new capability use), with an explainable
> verdict, using record/replay determinism to suppress false positives; targeted at
> compromised-legitimate extensions and positioned for store-side / enterprise / researcher
> deployment rather than consumer pre-execution prevention.*

Why this is the strongest version: it (a) **concedes** the prior static update-delta work and
claims only the open dynamic/deterministic cell; (b) **drops** the two indefensible claims
(language-aware; consumer prevention); (c) foregrounds **determinism + explainability**, the
parts that address the field's real bottleneck (false positives — the 2025 "It's not Easy"
result) rather than chasing model accuracy.

---

## 10. Suggested Experiment to Prove Added Value

**[OURS] The one experiment that proves we add something over the closest prior work:**

> **Head-to-head on obfuscation.** Take a set of update pairs where the malicious `v2`
> carries an **obfuscated / dynamically-decoded / condition-gated** payload. Show that a
> **static code-delta** approach (the You've-Changed style: diff the code, flag abused APIs)
> **misses or mis-scores** it, while our **dynamic behavioural diff** still flags it because
> the payload's *runtime effect* (cookie read → new-host POST from the service worker) is
> observable regardless of how the code is written.

Plus two supporting results we can already produce:
1. **False-positive rate on real benign updates** (GitHub-release pairs of open-source
   extensions) — the metric that actually matters — **with vs. without record/replay
   determinism** (the ablation), showing determinism drives FPs toward zero.
2. **Detection + ground truth** on the synthetic weaponisation corpus and the reconstructed
   **Cyberhaven** pair, each with an explainable verdict.

Our current prototype already does (1)-partial and (2); the obfuscation head-to-head is the
new experiment that most directly answers *"why not just use the 2020 static method?"*

---

## 11. References (year · venue/org · link)

**Closest prior work / core papers**
- Pantelaios, Nikiforakis, Kapravelos. *You've Changed: Detecting Malicious Browser Extensions through their Update Deltas.* **ACM CCS 2020.** [DOI 10.1145/3372297.3423343](https://dl.acm.org/doi/10.1145/3372297.3423343) · [PDF](https://kapravelos.com/publications/extensiondeltas-CCS20.pdf)
- Bui, Tang, Shin. *Detection of Inconsistencies in Privacy Practices of Browser Extensions (ExtPrivA).* **IEEE S&P 2023.**
- Kapravelos, Grier, Chachra, Kruegel, Vigna, Paxson. *Hulk: Eliciting Malicious Behavior in Browser Extensions.* **USENIX Security 2014.**
- Bandhakavi, King, Madhusudan, Winslett. *VEX: Vetting Browser Extensions for Security Vulnerabilities.* **USENIX Security 2010.**
- Karami, Ilia, Polakis. *Awakening the Web's Sleeper Agents: Misusing Service Workers for Privacy Leakage.* **NDSS 2021.** *(About web service workers, not extension MV3 — see the correction at top.)*
- Karami, Ilia, Solomos, Polakis. *Carnus: Exploring the Privacy Threats of Browser Extension Fingerprinting.* **NDSS 2020.** [PDF](https://www.cs.uic.edu/~skarami/files/carnus/carnus-ndss20.pdf)

**Platform / MV3 / defences**
- Chrome for Developers. *What is Manifest V3* · *Improve extension security* · *Review process.* [what-is-mv3](https://developer.chrome.com/docs/extensions/develop/migrate/what-is-mv3) · [improve-security](https://developer.chrome.com/docs/extensions/develop/migrate/improve-security) · [review-process](https://developer.chrome.com/docs/webstore/review-process)
- *Manifest V3 Unveiled: Navigating the New Era of Browser Extensions.* **arXiv 2404.08310, 2024.** [PDF](https://arxiv.org/pdf/2404.08310) *(MV3 API-deprecation and residual-malice figures — verify in source.)*
- Palant. *Malicious extensions circumvent Google's remote code ban.* 2025. [link](https://palant.info/2025/01/20/malicious-extensions-circumvent-googles-remote-code-ban/)
- Mozilla. *Add-ons signing & distribution.* [Extension Workshop](https://extensionworkshop.com/documentation/publish/signing-and-distribution-overview/) · Stillman, *Firefox Extension Scanning is Security Theater*, 2015. [link](https://danstillman.com/2015/11/23/firefox-extension-scanning-is-security-theater)

**Recent dynamic / analysis work**
- Khandelwal, Nayak, Fernandes, Fawaz. *Experimental Security Analysis of Sensitive Data Access by Browser Extensions.* **ACM WWW 2024.** [DOI](https://dl.acm.org/doi/10.1145/3589334.3645683)
- Xie et al. *Arcanum: Detecting and Evaluating the Privacy Risks of Browser Extensions.* **USENIX Security 2024.** [PDF](https://www.usenix.org/system/files/usenixsecurity24-xie-qinge.pdf)
- *CodeX: Contextual Flow Tracking for Browser Extensions.* **CODASPY 2025.** [DOI](https://dl.acm.org/doi/10.1145/3714393.3726495)
- *Fakeium: A Dynamic Execution Environment for JavaScript Program Analysis.* **arXiv 2410.20862, 2024.** [PDF](https://arxiv.org/pdf/2410.20862)
- *A Study on Malicious Browser Extensions in 2025.* **arXiv 2503.04292.** [PDF](https://arxiv.org/pdf/2503.04292)

**Incidents / supply chain**
- Sekoia. *Targeted supply chain attack against Chrome browser extensions.* 2025. [link](https://blog.sekoia.io/targeted-supply-chain-attack-against-chrome-browser-extensions/)
- SecurityWeek. *Cyberhaven Chrome Extension Hack Linked to Widening Supply Chain Campaign.* [link](https://www.securityweek.com/cyberhaven-chrome-extension-hack-linked-to-widening-supply-chain-campaign/)
- The Register. *The Great Suspender.* 2021. [link](https://www.theregister.com/2021/01/07/great_suspender_malware/)
- LWN. *Malware in open-source web extensions (Nano Adblocker).* [link](https://lwn.net/Articles/846272/)
- Pluto Security. *Chrome Extension Supply Chain Attacks: silent permission creep.* [link](https://pluto.security/blog/chrome-extension-supply-chain-attacks-permission-creep/)

---

## What We Should Tell Our Professor (direct answers)

1. **Why is this problem difficult?** Because malice is **behavioural and can be hidden** —
   obfuscated, dynamically decoded, or condition-gated — so static inspection is evadable,
   and dynamic inspection has to *trigger* the behaviour and *distinguish it from web noise*.
   Add scarce labelled data and silent auto-updates, and reliable detection is genuinely hard.
2. **What makes extension security technically challenging?** Extensions are **trusted,
   auto-updating code with mid-traffic privilege**; the trust is granted once and never
   re-checked; the malicious change usually arrives **after** all the checks, via an update.
3. **Does language/runtime choice materially matter?** **No.** Extensions are memory-safe JS;
   risk comes from **permissions, APIs, logic, dependencies, and account/supply-chain
   compromise** — not the language. (So we're dropping the "language-aware" angle.)
4. **Can the end user be protected before a malicious update executes?** **Not by an external
   tool, realistically.** Updates are silent/automatic and the browser gives outsiders no
   veto. Prevention belongs to the **vendor or the store**; our realistic value is **store-side
   / enterprise / researcher re-verification** and **fast detection**, not a consumer shield.
5. **What do browsers already check?** Signing/integrity, manifest/permissions, automated +
   manual review (updates included), malware/reputation, isolation/CSP, MV3 no-remote-code.
6. **Where do those defences actually fail?** Obfuscated/dormant payloads, silent permission
   creep, and **compromised-legitimate extensions** whose malicious *update* passes review —
   as in Cyberhaven, which was an **OAuth/account** compromise, **not** an analysis failure.
7. **How can our approach be different?** **Dynamic, behavioural, cross-version diffing with
   record/replay determinism** — obfuscation-resistant (we watch effects, not code) and
   false-positive-resistant (identical inputs isolate the extension), with **explainable**
   verdicts. This is the open cell next to the *static* update-delta work (You've Changed,
   CCS 2020) and the *single-version* dynamic work (Hulk, ExtPrivA).
8. **What should we change/narrow in our idea?** Drop **language-aware analysis** and
   **consumer pre-execution prevention**; reposition as a **store/enterprise/researcher**
   update-re-verification method; foreground **determinism + explainability** over model
   accuracy; and **cite You've Changed explicitly** as prior work we improve on dynamically.
9. **Strongest research problem to pursue?** The narrowed statement in §9 — *deterministic
   dynamic behavioural update-diffing for compromised-legitimate extensions, explainable,
   store/enterprise-deployed.*
10. **What experiment proves we add value?** The **obfuscation head-to-head** (§10): a payload
    that static code-delta misses but our dynamic behavioural diff still catches — plus the
    **determinism ablation** on real benign updates (false-positive rate with/without
    record/replay). Together they show *why dynamic, and why determinism.*
