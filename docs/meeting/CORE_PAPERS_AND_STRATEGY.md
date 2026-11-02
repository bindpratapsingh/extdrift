# Core Papers, ML Rationale & Strategy — Meeting Brief

**For:** the CSD493 progress meeting with Dr. Sweta Mishra
**Prepared by:** Bind Pratap Singh & Suhani Deepak Agrawat
**Purpose:** the deep reference behind the four-paper summary we emailed on 21 Jul 2026 —
enough detail on each paper (who, when, how, why, novelty, whether they built it,
shortcomings) to answer follow-up questions, plus *why/how* we use ML and our strategy
forward.

> This is the study document. The terse in-room script is
> [TALKING_POINTS.md](TALKING_POINTS.md); the method detail is
> [../design/METHODOLOGY.md](../design/METHODOLOGY.md); the model reasoning with every
> acronym spelled out is [../../Reference Docs/ML_Models_Research.md](../../Reference%20Docs/ML_Models_Research.md).

---

## ⚠️ Two things to verify before you quote them

1. **Karami et al. (NDSS 2021)** — confirm the exact **title, authors, and venue/year**
   from your own notes/proposal before citing it out loud. If it turns out shaky, anchor
   the service-worker point on something you can verify (the official Chrome MV3
   service-worker docs, or a MV3 security-analysis paper you can name). A wrong citation
   is the easiest thing for an examiner to catch.
2. **ExtPrivA's exact precision/scale numbers** — quote the figures from the PDF, not from
   memory. Below we describe the method precisely but hedge the exact percentages.

---

## 0. The 30-second story these four papers tell together

They are not four random papers — they form a **deliberate arc** that leads straight to our
gap:

1. **VEX (2010)** — try to catch bad extensions *statically*, without running them.
   → *Lesson: static analysis is blind to runtime/obfuscated/hidden behaviour.*
2. **Hulk (2014)** — so run them *dynamically* and actively *provoke* the hidden behaviour.
   → *Lesson: dynamic elicitation works, but it's single-version and non-deterministic.*
3. **ExtPrivA (2023, our base)** — a modern dynamic system: emulate the user, watch the
   network, catch privacy violations. → *Lesson: still analyses **one version** at a time.*
4. **Karami (2021)** — and there's a specific blind spot: MV3 **service workers** can leak
   with no page open. → *Lesson: you must instrument the background context too.*

**Our project = take ExtPrivA's dynamic machinery, add Hulk's elicitation, cover Karami's
service-worker blind spot, and do the one thing none of them do — compare two consecutive
*versions* to score the *update*.** That is the gap, and the Dec 2024 Cyberhaven attack
(a trusted extension turned malicious via a silent update, ~400k users in hours) is the
real-world proof that the gap matters.

---

## 1. VEX — Vetting Browser Extensions for Security Vulnerabilities

| | |
|---|---|
| **Who** | Sruthi Bandhakavi, Samuel T. King, P. Madhusudan, Marianne Winslett |
| **Where/when** | University of Illinois at Urbana-Champaign · **USENIX Security 2010** (extended version later in *Communications of the ACM*, 2011) |
| **Type** | **Static** analysis |

**What problem.** In 2010 the dominant extension platform was **Firefox** (the old
XUL/XPCOM model), where extensions ran with very high privilege. A *benign* extension with
a careless coding pattern could be **exploited by a malicious web page** to run code with
those privileges. VEX hunts for those exploitable patterns.

**How it works.** VEX performs **static information-flow analysis** on the extension's
JavaScript. It tracks how data flows from **untrusted sources** (web-page content) to
**dangerous sinks** (`eval`, `innerHTML`, `evalInSandbox`, etc.) and flags a fixed set of
**"flow patterns"** known to be dangerous — e.g. unsanitised page content reaching `eval`.
It never runs the extension; it reasons over the code.

**Novelty.** One of the **first** to apply static information-flow analysis specifically to
browser extensions, and to codify the dangerous flow patterns for that setting.

**Did they build/evaluate it?** Yes. They ran VEX over **~2,400 Firefox extensions** and
flagged a **handful** with genuine vulnerabilities, including some **previously unknown**
ones — a real, concrete result.

**Shortcomings (the important part for us).**
- **Static → blind to runtime behaviour:** obfuscated code, `eval` of a *downloaded* string,
  time-delayed or condition-gated logic — VEX cannot see any of it. **This is precisely the
  gap we say we fix.**
- **False positives:** static flow analysis over-approximates; flagged flows need manual
  review.
- **Threat-model nuance:** VEX targets *vulnerabilities in benign extensions* (exploitable
  flaws), not deliberately *malicious* extensions that actively hide behaviour. Adversarial
  evasion is out of its scope.
- **Dated platform:** it targets the legacy **Firefox XPCOM** model, which no longer exists.
  Modern WebExtensions (MV2/MV3) are more sandboxed. VEX's *specifics* are obsolete; its
  *lesson* (static is insufficient) is what endures.

**Likely questions.**
- *"Isn't VEX about vulnerabilities, not malware?"* — Yes, correct, and we're precise about
  that: we cite it as the canonical **static** approach and for its enduring lesson that
  static analysis misses runtime/obfuscated behaviour — which is why our method is dynamic.
- *"Why cite a 2010 Firefox paper for a 2026 MV3 project?"* — For the methodological point,
  not the implementation. It anchors the static-vs-dynamic argument that justifies our whole
  design.

---

## 2. Hulk — Eliciting Malicious Behavior in Browser Extensions

| | |
|---|---|
| **Who** | Alexandros Kapravelos, Chris Grier, Neha Chachra, Christopher Kruegel, Giovanni Vigna, Vern Paxson |
| **Where/when** | UC Santa Barbara + UC Berkeley/ICSI · **USENIX Security 2014** |
| **Type** | **Dynamic** analysis, at scale |

**What problem.** Malicious extensions often stay **dormant** — they only act on specific
sites, after specific events, or on specific DOM elements. Just loading one and watching
usually shows nothing. Hulk's goal is to **provoke** ("elicit") the hidden behaviour and
then classify it.

**How it works — two signature techniques.**
1. **HoneyPages.** Dynamically-generated web pages that **adapt to whatever the extension
   asks for**. If the extension does `querySelector('.bank-login')`, the HoneyPage *creates*
   that element on the fly, so the extension keeps executing down its malicious path instead
   of giving up. This defeats site/element gating.
2. **Event fuzzing.** It fires the browser/extension events the extension listens for, so
   dormant handlers actually run.
   While doing this it **monitors network requests and API/DOM activity** and labels each
   extension as **malicious / suspicious / benign** using behavioural signals (ad injection,
   affiliate-link fraud, information/password theft, social-network abuse, etc.).

**Novelty.** The first **large-scale dynamic elicitation** of hidden extension behaviour;
**HoneyPages** is the standout novel idea; it also produced an early **taxonomy** of how
extensions monetise/abuse users.

**Did they build/evaluate it?** Yes, at real scale — on the order of **~48,000 Chrome
extensions** (Web Store + a malware feed). It identified **over a hundred clearly malicious**
extensions and **thousands of suspicious** ones, with concrete named behaviours.

**Shortcomings (what we improve on).**
- **Single-version, single point in time** — no concept of an *update* or of behaviour
  *drifting* across versions. **This is our gap.**
- **Non-determinism:** running against adaptive/honeypot pages varies run-to-run, so naive
  comparison across runs is noisy. **This is exactly why we add record/replay determinism.**
- **Trigger completeness:** even HoneyPages + fuzzing can't guarantee every dormant path
  fired; **server-gated payloads / time-bombs** (C2 only serves the payload under certain
  conditions) can stay hidden.
- **Sandbox evasion:** an extension can detect the analysis environment and behave.
- **Known-signal bias:** labelling leaned on known-bad behaviours; genuinely novel payloads
  can slip.

**Relevance to us.** Our **scenario scripts** (`engine/sandbox/scenarios.py`) are a focused
descendant of Hulk's elicitation — drive a realistic user session so the payload fires. We
inherit its dynamic stance and fix its two weaknesses for our problem: **version-diffing**
and **determinism**.

**Likely questions.**
- *"How is your elicitation different from HoneyPages?"* — We use **fixed, realistic scripted
  scenarios** against **deterministic** pages (so both versions see identical input), rather
  than adaptive honeypots. We trade some trigger-generality for **reproducibility**, which is
  what makes a *version diff* meaningful.
- *"Doesn't Hulk already detect malicious extensions?"* — Yes, for a single version at a
  point in time. It cannot tell a **benign v1 from a malicious v2** of the *same* extension,
  which is the update threat we target.

---

## 3. ExtPrivA — Detection of Inconsistencies in Privacy Practices of Browser Extensions *(BASE PAPER)*

| | |
|---|---|
| **Who** | Duc Bui, Brian Tang, Kang G. Shin |
| **Where/when** | University of Michigan · **IEEE Symposium on Security & Privacy (S&P) 2023** |
| **Type** | **Dynamic** behavioural analysis + **NLP** on policy text |

**What problem.** Extensions *declare* privacy practices (in their Chrome Web Store privacy
disclosures / privacy policies), but what they *actually do* may differ. ExtPrivA detects
the **inconsistency between the stated practice and the observed behaviour**.

**How it works (this is our blueprint).**
1. **Extract the declared practices** — NLP over the extension's privacy-policy / Web Store
   privacy disclosures to get what it *claims* to collect.
2. **Emulate user interaction** — automatically drive the extension so it actually does its
   thing (the elicitation idea again).
3. **Monitor the network** — capture outbound requests, identify what **personal/identifiable
   data** leaves and **to whom**, and crucially **attribute the request's initiator** (was it
   the page or the extension?).
4. **Compare** declared vs. observed and flag the mismatches.

**Novelty.** Marrying **NLP-extracted declared privacy practices** with **dynamic behavioural
observation** to detect the *policy-vs-behaviour* gap, automatically and at scale.

**Did they build/evaluate it?** Yes — a full pipeline evaluated on real Chrome Web Store
extensions, reporting **strong precision** at finding inconsistencies. *(Quote the exact
precision/recall and dataset size straight from the paper — don't cite a number from
memory.)*

**Shortcomings / nuances.**
- **Single-version** — audits one release against its own policy; **no update/temporal
  dimension.** This is the gap our cross-version diff fills.
- **Depends on a declared policy** — many extensions have vague, boilerplate, or missing
  policies, which limits it. **Our method needs no policy at all** — the *previous version*
  is the reference. Worth stating as an advantage.
- **Detects inconsistency-with-policy, not maliciousness per se** — an extension that
  *fully discloses* a data grab would not be "inconsistent." Interesting corollary: our diff
  would **still flag** that grab if it were *new in an update*, even when disclosed.
- Shares the **trigger-completeness** and **server-gated behaviour** limits of all dynamic
  tools; needs re-running as extensions change (concept drift).

**Why it's our base paper.** Its core machinery — *emulate interaction → observe outbound
requests → attribute initiator → reason about data flows* — **is exactly our capture layer**
(`engine/sandbox/`, which attributes every request to page / content-script /
service-worker). We **reuse the methodology** and **change the comparison target**: instead
of "declared policy vs. observed behaviour of one version," we do **"behaviour of version N
vs. behaviour of version N+1."** That single change drops the NLP/policy dependency and lifts
the whole approach from single-version auditing to **update-aware detection**.

**Likely questions.**
- *"What exactly do you extend?"* — The *comparison*. ExtPrivA compares behaviour to a stated
  policy; we compare behaviour to the **prior version's behaviour**. Same observation
  machinery, new (and policy-free) reference.
- *"Is that enough to be a project, not just a tweak?"* — The version-diff brings its own hard
  problems that ExtPrivA never faced: **determinism** (two runs of the web differ), **the
  service-worker channel**, and **data acquisition of version pairs** — each a real
  contribution. See the Strategy section.

---

## 4. Karami et al. (NDSS 2021) — MV3 service-worker data leakage  ⚠️ *verify citation*

| | |
|---|---|
| **Who / where / when** | **⚠️ Confirm exact authors, title, venue, year before quoting** (see the note at the top) |
| **Type** | Attack demonstration on the Manifest V3 model |

**The technical point we take from it (this part is sound regardless of the exact cite).**
Manifest V3 replaced persistent background pages with **service workers** — event-driven
background scripts that can wake, run, and **make network requests with no visible page and
no user present**. That means an extension can exfiltrate data from the **background context**
entirely outside anything a page-focused monitor would watch. A detector that only hooks the
DOM/page will **miss** it.

**Why it matters to us.** It justifies a specific engineering decision: we **instrument the
service worker directly**. Our instrumentation is injected into the extension's *own* bundle
(static prelude injection), so it reaches the service worker, which has no DOM to hook. We
carry a dedicated feature (`net_worker_initiated`) and a rule (**R09**, service-worker
beaconing), and our weaponised sample deliberately exfiltrates **from the service worker** to
prove we cover this blind spot — and in the live run, **R09 fires**.

**Likely questions.**
- *"Why single out service workers?"* — Because MV3 made the background context the modern
  exfiltration path, and it's invisible to page-level monitoring. Covering it is a concrete
  differentiator of our capture layer.
- *"Which paper exactly?"* — **Have the verified citation ready.** If unsure, say you're
  motivated by the MV3 service-worker architecture (cite Chrome's MV3 docs) and will confirm
  the specific paper.

---

## 5. What we've *progressed* since the last email (the honest update)

Last email (21 Jul): "read four papers; internships on; will start the Playwright prototype."
Since then we've gone from that to a **working, tested prototype**:

- **The full pipeline runs end-to-end on a real browser.** It loads two versions of an
  extension, drives an identical scripted user session against **deterministic** pages,
  records what each version does across **four channels** (network / DOM / storage / API,
  including the **service worker**), diffs them, and emits an **explainable verdict**.
- **On our first real test pair it is correct:** a synthetically weaponised update →
  **MALICIOUS (0.99)**, and an independent fake-collector log **confirms the data actually
  left the browser**; a genuine feature update → **BENIGN (0.25)**, no false alarm; a
  gray-zone case → **SUSPICIOUS (0.68)**.
- **~3,100 lines of Python + ~300 of instrumentation JS, 72 automated tests all green**
  (2 of which launch a real Chromium and verify the whole pipeline).
- Concretely implemented: `.crx`/`.xpi` unpacker, trace schema, browser capture + a
  deterministic local test-site with egress control, 24 behavioural features, the behavioural
  delta `Δ = f(T2) − f(T1)`, a **12-rule explainable heuristic scorer**, and a text+JSON
  report — all driven from one CLI. See [../progress/PROGRESS_REPORT.md](../progress/PROGRESS_REPORT.md).

Maps onto the implementation-guide **Phases A–D (foundations → first trace → diff →
determinism/sandbox): complete.** Phases E (ML) and F (dashboard, Firefox, evaluation) are
next.

---

## 6. The ML plan — *why* we use it, and *how* (Dr. Mishra's direct questions)

She asked three things in the earlier meeting: consider a model **beyond Random Forest**;
**reproduce the existing state of the art first, then improve**; and get the **heuristics**
and justify **why ML is even needed**.

### Why ML at all? (and why we built the rules *first*)
- The **12 weighted rules are the heuristics** she asked for — and they are also the
  **control experiment for ML**: a learned model only earns its place if it **beats the
  transparent rules** on the same data. Building rules first is how we *answer* "why is ML
  needed," rather than assuming it.
- Rules alone are brittle at the boundary (the gray-zone case), they can't optimally weigh
  **many weak signals** together, and they can't adapt to a **novel payload** without a human
  rewriting them. A fitted model learns those weightings from data and gives a **calibrated
  probability** to complement the transparent score. **Agreement between the two** is itself a
  confidence signal.

### How — a two-tier plan that literally *is* "reproduce, then improve"
- **Tier 1 — reproduce the tabular baseline (this semester).** Our `Δ = f(T2) − f(T1)` is a
  **tabular** feature vector, so:
  - **Random Forest** — the standard explainable baseline.
  - **XGBoost / LightGBM** — the **tabular state of the art** (trees still beat deep nets on
    tabular data — *Grinsztajn et al., NeurIPS 2022*), a trivial add that directly answers
    "why not something better than Random Forest?"
  - **SHAP** for per-verdict feature attribution, keeping every prediction explainable.
  - Evaluate against the rule baseline, reporting precision/recall/AUC **and especially
    false-positive rate**.
- **Tier 2 — the "more state-of-the-art" model + our novelty (stretch / Phase 2).** The
  frontier isn't a fancier tabular model — it's **changing the representation**:
  - **Sequence:** order the trace events (`read cookie → open socket → POST`) and run a small
    **Transformer / BiLSTM** — captures *order*. (Our schema already timestamps every event
    for exactly this.)
  - **Graph:** build a **data-flow graph** (`cookie-read → variable → network-POST`) and run a
    **GNN/GCN** — the natural model for exfiltration.
  - **The genuine novelty:** *diffing* these sequence/graph representations **across two
    versions** — no published work does cross-version behavioural diffing with seq/graph
    models.

### The honest caveat (say it — it makes us look *more* rigorous)
Deep models need lots of data; confirmed **real** malicious *update pairs* are scarce, so a
Transformer/GNN would overfit on them. Hence: **train on a synthetic weaponisation corpus,
hold out real incidents for validation**, and keep the deep model as the **stretch** tier
while RF/XGBoost is the must-have. The 2025 "It's not Easy" result (98% lab accuracy, useless
in the wild) is our reminder that **the classifier is not the hero — determinism and data
quality are.**

Full reasoning, every acronym expanded:
[../../Reference Docs/ML_Models_Research.md](../../Reference%20Docs/ML_Models_Research.md).

---

## 7. Strategy forward (the next 3–4 weeks, concretely)

1. **Real-site record/replay via mitmproxy** — extend determinism from our in-process test
   site to real websites (completes Phase D for real targets).
2. **Grow the corpus + get real pairs.** Add more synthetic payload families (keylogging,
   ad-injection, affiliate hijack). Get **real benign** update pairs from **open-source
   extensions on GitHub** (guaranteed, verifiable) and **third-party archives** (crx4chrome,
   chrome-stats); reconstruct the **Cyberhaven** pair as the marquee real malicious case.
3. **Tier-1 ML** — train **Random Forest + XGBoost + SHAP** on the delta vectors and **compare
   against the rule baseline**, measured on **false-positive rate** (reproduce → improve).
4. **Firefox** — begin the second engine via Playwright's cross-browser API for genuine
   cross-engine coverage.

### The one framing that pre-empts the hardest question
If she asks *"how will you ever get two versions of every extension?"* — our honest answer is
that **extdrift is an update-*monitoring* method, not a lookup tool**: whoever runs it (a
vendor, an enterprise whitelist, a store's review pipeline, or our own crawler) **archives
every version as it ships and diffs new-vs-last-known** — you never hunt for the past, you
keep the present. **Real benign pairs are easy** (GitHub releases, archives, our own
snapshotting) which supports the all-important false-positive claim; **real malicious pairs
are scarce** so we use synthetic weaponisation for breadth + the real Cyberhaven case for
external validity. We scope the claim narrowly and honestly: *detect security-relevant
behavioural change between two versions, explainably, with fewer false positives than naive
diffing* — not "find all malware in the wild."

---

## 8. Rapid-fire Q&A cheat sheet

| If she asks… | Say… |
|---|---|
| "What's genuinely new vs. ExtPrivA?" | The comparison target: prior-version behaviour instead of a declared policy → update-aware, policy-free. Plus determinism + the SW channel. |
| "Isn't VEX about vulnerabilities, not malware?" | Yes — we cite it for the enduring *static-is-insufficient* lesson, not its threat model. |
| "Why still Random Forest?" | It's the reproducible tabular baseline + control for "why ML"; XGBoost is the tabular SOTA; the real upgrade is a representation change (seq/graph), not a fancier tabular model. |
| "How do you avoid false positives?" | Record/replay determinism — both versions see identical pages, so the diff is the extension, not web noise. It's the field's real bottleneck (2025 paper). |
| "Your dataset is tiny." | Real update pairs are genuinely rare; synthetic-train + real-validate is the honest, standard framing; we also verify against a ground-truth collector log. |
| "Which Karami paper?" | *(Have the verified citation ready.)* Motivated by the MV3 service-worker exfiltration path. |
| "How will you get two versions?" | It's a monitoring method — you archive every version and diff new-vs-last-known; you don't hunt for the past. |
