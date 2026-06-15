# Implementation Guide — Behavioral-Diff Detection of Malicious Browser Extension Updates

**Audience:** Bind & Suhani — written assuming you have done course projects but never
built a system like this. Every term is defined. Read top to bottom once, then use it as
a reference.

---

## 0. THE BIG PICTURE — what are we actually building?

We are building a **lab in software**. You feed it **two versions of the same browser
extension** (the old "safe" one and the new "updated" one). The lab runs each version
inside a safe, sealed environment, watches everything it does, compares the two, and
tells you: *"The update added new suspicious behaviour — here's exactly what."*

**Analogy:** Think of airport customs. A person (the extension) was cleared once (the old
version). They go on a trip and come back looking the same (the update). Instead of
trusting them blindly, we put both the "before" and "after" through the same scanner under
identical conditions and **diff** the results. If the "after" suddenly has a hidden
compartment full of stolen cookies, we flag it.

### Is this a product with real users, or a research thing?
It is a **research prototype / analysis framework** — closer to a lab instrument than to a
consumer app.

- There is **no public user base**, no millions of users, nothing that must stay online 24/7.
- The "user" is a **security analyst or researcher** who wants to check an extension update.
- They interact by **giving it two extension files** (or an extension ID + two version
  numbers) and **getting back a report**.
- It runs **locally on a capable machine** (the Mac, a lab PC, or a free cloud VM). For the
  demo we build a small **dashboard** that runs on `localhost` (your own machine). Nothing
  needs to be hosted publicly — and we deliberately would NOT host malware analysis on a
  public server.

So: **local-first batch analysis tool + a small local dashboard for the demo.** That is a
completely normal and respected shape for a security research project.

---

## 1. CORE CONCEPTS & DEFINITIONS (read this once, refer back often)

**Browser extension** — a small program that adds features to a browser (ad blockers,
password managers, etc.). It is just a ZIP of files. Inside:
- `manifest.json` — the "ID card": name, version, **permissions** it requests, and which
  scripts to run.
- **background script / service worker** — code that runs in the background, even when no
  page is open. In modern Chrome this is a *service worker* (see Manifest V3 below).
- **content scripts** — code the extension injects **into the web pages you visit**. This is
  the dangerous part: a content script on `bank.com` can read what you type.

**`.crx` / `.xpi`** — the packaged extension file. `.crx` = Chrome/Chromium format.
`.xpi` = Firefox format. Both are basically renamed ZIP files.

**Manifest V2 vs V3 (MV2 / MV3)** — two generations of the extension rulebook. Chrome now
requires **MV3**, which replaced always-running background *pages* with on-demand
**service workers** and changed how extensions modify network requests
(`declarativeNetRequest`). The Cyberhaven attack was MV3. **We target MV3.**

**`chrome.*` / `browser.*` API** — the special functions only extensions can call, e.g.
`chrome.cookies.getAll()` (read cookies), `chrome.tabs` (see your tabs). Chromium uses the
`chrome.*` namespace; Firefox uses `browser.*`. Same idea, different name — this is *why*
multi-browser support takes extra work.

**DOM (Document Object Model)** — the live, in-memory tree of everything on a web page
(every button, text box, link). When code "reads the DOM," it reads page contents; when it
"writes the DOM," it changes the page (e.g., injects a fake login form).

**Static analysis** — inspecting code/files *without running them* (like proofreading).
Fast, but blind to obfuscated or hidden behaviour.

**Dynamic analysis** — *actually running* the code and watching what it does. Slower, but
catches behaviour that only appears at runtime. **Our project is dynamic analysis.**

**Sandbox** — a sealed, throwaway environment where you can run untrusted/dangerous code so
it **cannot touch your real computer, files, or network**. (Full section below.)

**Container / Docker** — the technology we use to build that sandbox. A **container** is a
lightweight, isolated "mini-computer" running inside your computer. **Docker** is the tool
that creates and manages containers from a recipe file. (Full section below.)

**Headless browser** — a real browser (Chromium/Firefox) running **with no visible window**,
controlled entirely by code. Same engine as the browser you use, just invisible and
scriptable.

**Browser automation** — driving a browser with code instead of hands ("go to this URL,
click that button, type here"). We use **Playwright** for this.

**Proxy** — a piece of software that sits **between the browser and the internet**, so all
traffic flows through it and can be recorded or blocked. We use **mitmproxy**.

**TLS / HTTPS interception** — websites use HTTPS (encrypted). To read that traffic, our
proxy installs its own trusted certificate **inside the sandbox** so it can decrypt and log
requests *within the lab only*. (This is fine in our own controlled sandbox; it would be
malicious on someone else's machine.)

**Trace** — the full recorded log of what one extension version did during a run: every
network request, every page change, every storage access. We collect a trace for v1 (call
it `T1`) and for v2 (`T2`).

**Feature extraction `f(·)`** — turning a messy trace into a tidy list of numbers a computer
can compare, e.g. `[number_of_new_domains=3, reads_cookies=1, posts_form_data=1, ...]`.

**Behavioral delta `Δ`** — the **difference** between the two feature lists:
`Δ = f(T2) − f(T1)`. This is the heart of the project: we score the *change*, not the
extension in isolation.

**Classifier / Random Forest** — a machine-learning model that learns from examples to put
a new input into a category (here: "benign update" vs "malicious update"). A **Random
Forest** is a collection of many simple decision trees that vote; it is reliable, works on
small data, and can tell you *which features mattered* (good for explainability).

**False positive (FP)** — crying wolf: flagging a harmless update as malicious. **False
negative (FN)** — missing a real attack. Good detectors keep both low; our record/replay
trick mainly fights false positives.

**Determinism / record-replay** — making each run repeatable. If you load `bank.com` twice,
the ads and tokens differ each time, which would look like "new behaviour" even with no
extension change. We **record** the network responses once and **replay** the *exact same*
responses to both v1 and v2, so the only thing that can differ is the extension itself.

---

## 2. ARCHITECTURE (with diagrams)

### 2.1 The whole system, end to end

```
                 ┌─────────────────────────────────────────────────┐
   INPUT  ─────► │   Extension v1 (.crx/.xpi)   Extension v2        │
                 └───────────────┬──────────────────┬──────────────┘
                                 │                  │
                       ┌─────────▼──────┐   ┌───────▼─────────┐
   STAGE 1  ──────────►│ Unpack & load  │   │ Unpack & load   │
   Sandbox build       │ (read manifest)│   │ (read manifest) │
                       └─────────┬──────┘   └───────┬─────────┘
                                 │                  │
              ┌──────────────────▼───┐   ┌──────────▼───────────────┐
   STAGE 2/3  │  SANDBOX (Docker)    │   │  SANDBOX (Docker)        │
   Run + trace│  headless browser    │   │  headless browser        │
              │  + extension v1      │   │  + extension v2          │
              │  driven by Playwright│   │  driven by Playwright    │
              │  watched by mitmproxy│   │  watched by mitmproxy    │
              └──────────┬───────────┘   └──────────┬───────────────┘
                   Trace T1                    Trace T2
                         │                          │
              ┌──────────▼──────────────────────────▼───────────────┐
   STAGE 4    │  FEATURE EXTRACTION:  f(T1), f(T2)                   │
   Diff       │  DIFF:                Δ = f(T2) − f(T1)              │
              └───────────────────────┬─────────────────────────────┘
                                      │
              ┌───────────────────────▼─────────────────────────────┐
   STAGE 5    │  SCORING                                             │
   Decide     │   (a) transparent weighted rules                    │
              │   (b) Random Forest classifier                      │
              └───────────────────────┬─────────────────────────────┘
                                      │
              ┌───────────────────────▼─────────────────────────────┐
   OUTPUT     │  REPORT (dashboard + JSON file)                     │
              │  "v2 added: reads cookies on bank.com, POSTs form   │
              │   data to evil-collect.com  →  MALICIOUS (0.92)"    │
              └─────────────────────────────────────────────────────┘
```

### 2.2 Inside ONE sandbox (the most important diagram)

```
  DOCKER CONTAINER  — a sealed mini-computer; cannot see your real files or internet
  ┌──────────────────────────────────────────────────────────────────────┐
  │                                                                        │
  │   ┌───────────────┐    commands    ┌──────────────────────────────┐   │
  │   │  Playwright   │ ─────────────► │  Headless Chromium / Firefox  │   │
  │   │  (the robot:  │                │   • the extension is loaded   │   │
  │   │  open URL,    │ ◄───────────── │   • our injected JS watches   │   │
  │   │  click, type) │   page events  │     DOM reads/writes          │   │
  │   └───────────────┘                └───────────────┬──────────────┘   │
  │                                      ALL network    │                  │
  │                                      traffic flows  ▼                  │
  │                                     ┌──────────────────────────────┐   │
  │                                     │  mitmproxy                    │   │
  │                                     │   • logs every request/URL    │   │
  │                                     │   • REPLAYS recorded responses│   │
  │                                     │   • BLOCKS real exfiltration   │   │
  │                                     └───────────────┬──────────────┘   │
  │                                                     ▼                  │
  │                                          writes ► trace.json           │
  │                                                                        │
  └──────────────────────────────────────────────────────────────────────┘
        ▲
        └── EGRESS FIREWALL: the container is not allowed to reach the real
            internet, so even real malware cannot actually steal anything.
```

### 2.3 What the captured trace looks like (conceptually)

```
trace.json (for one version)
{
  "network":  [ {"url":"https://bank.com/login","method":"GET"},
                {"url":"https://evil-collect.com/c","method":"POST","body_len":812} ],
  "dom":      [ {"event":"read","target":"input#password"},
                {"event":"inject","node":"<form>fake login</form>"} ],
  "storage":  [ {"api":"cookies.getAll","count":42} ],
  "manifest": { "permissions":["cookies","<all_urls>","scripting"] }
}
```
The **diff** between v1's and v2's traces is what gets scored.

---

## 3. HOW WE ANALYSE ONE EXTENSION — a full walk-through

Imagine the tool is finished and we analyse one update pair. Step by step:

1. **Inputs arrive.** We have `cyberhaven-v3.0.crx` (safe) and `cyberhaven-v3.1.crx`
   (suspected). Each is just a ZIP; we unzip it and read `manifest.json`.

2. **Permission diff (static, free signal).** We compare the two manifests. Did v3.1 add
   `cookies` or `<all_urls>`? That alone is a yellow flag. (This is the one *static* step;
   everything else is dynamic.)

3. **Record the web once.** Before comparing, we visit our test sites (a fake bank login,
   a fake webmail) through mitmproxy in **record mode** and save every server response.
   Now both versions will see byte-identical pages.

4. **Run v1 in a fresh sandbox.** Docker spins up a clean container with a headless browser,
   loads `v3.0`, and mitmproxy **replays** the recorded pages. Playwright (the robot) drives
   a fixed script: open the fake bank, type a dummy username/password, click login, wait,
   open webmail, etc. Everything the extension does is logged → `T1`.

5. **Run v2 in another fresh sandbox.** Exact same script, same replayed pages, but with
   `v3.1` loaded → `T2`. The container is then destroyed.

6. **Extract features.** Convert `T1` and `T2` into number lists: how many distinct
   destinations were contacted, were cookies read, was form data sent out, how many DOM
   nodes injected, permission delta, etc.

7. **Compute the diff `Δ`.** Subtract: what's *new* in v2 that wasn't in v1.

8. **Score it twice.** (a) A simple weighted-rule scorer ("new outbound POST of form data
   to a never-seen domain = +0.5") gives an explainable score. (b) The trained Random Forest
   gives a learned probability. If both agree it's malicious, confidence is high.

9. **Produce the report.** A human-readable summary + a JSON file:
   *"v3.1 introduced a POST of captured login-form fields to `evil-collect.com`, a domain not
   contacted by v3.0, while reading `document.cookie` on banking pages. Verdict: MALICIOUS
   (RF=0.92, rules=0.88)."*

That single pipeline, run over many pairs, is the whole project. Everything else is making
each step robust and measuring how well it works.

---

## 4. GETTING THE TWO VERSIONS — how to obtain extensions to analyse

The pipeline needs **two versions of the same extension** (`v1` baseline, `v2` candidate).
The hard part of the whole project is **data acquisition**, because Google's Web Store only
ever serves the *current* version. This section explains how to get them in practice.

### 4.0 Key mental shift
Your tool analyses extension **files**, not a live browser. An installed Chrome extension is
just a folder of files on disk (already unzipped). So *"analyse an extension I use"* means
*"extract its files + obtain a second version's files → diff."* You never need the extension
to be 'running in your Chrome' to analyse it.

### 4.1 Step 1 — find the extension's ID
Every extension has a 32-character ID. Two ways to read it:
- Open `chrome://extensions`, enable **Developer mode** (top-right) — each card shows its **ID**.
- Or read it from the Web Store URL: `chromewebstore.google.com/detail/<name>/`**`<long-string>`**.

### 4.2 Step 2 — get the CURRENTLY installed version (easy)

**Option A — copy it straight off disk (already unpacked):**
- **Windows:** `C:\Users\<you>\AppData\Local\Google\Chrome\User Data\Default\Extensions\<ID>\<version>\`
- **Mac:** `~/Library/Application Support/Google/Chrome/Default/Extensions/<ID>/<version>/`

The folder is named after the version (e.g., `124.0.6367.60`). Copy that whole folder — that
is `v1`, ready to load into the sandbox. (If you use multiple Chrome profiles it may be under
`Profile 1` instead of `Default`.)

**Option B — download the `.crx` from Google's update endpoint:**
```
https://clients2.google.com/service/update2/crx?response=redirect&acceptformat=crx2,crx3&prodversion=120&x=id%3D<EXTENSION_ID>%26uc
```
Substitute your Chrome version + the extension ID; it redirects to the `.crx`. A `.crx` is a
renamed ZIP — extract it to get the files. (Tools like "CRX Downloader" or the `crx-dl`
script just wrap this URL.) **This only ever returns the latest version.**

### 4.3 Step 3 — get a SECOND version (the real challenge)

Four routes, best-to-worst for a specific extension:

1. **Self-monitor over time (the honest, "production" way).** Snapshot the current version
   now (Step 2). Let Chrome auto-update it (or force a check at `chrome://extensions` →
   "Update"). When the on-disk version folder changes, **copy the new folder before Chrome
   deletes the old one.** Now you have a *real* `N → N+1` pair. This is exactly how the tool
   would run in real deployment: keep snapshotting, diff each update against the last
   known-good. Downside: a given extension may not update during your semester.

2. **Third-party version archives (best for getting an old version *right now*).**
   `crx4chrome.com` hosts **old `.crx` files** and per-extension version history for popular
   extensions (good for widely-used ones like Chrome Remote Desktop). `chrome-stats.com` is
   great for *seeing* an extension's version timeline (which versions existed and when).
   ⚠️ These are **unofficial** archives — you cannot fully verify an old file's integrity, so
   state that limitation in the write-up.

3. **GitHub (only for open-source extensions).** Download any two tagged releases. Cleanest
   source when it applies; does not apply to closed-source extensions.

4. **Synthetic `v2` (what you'll actually use to demo a *malicious* verdict).** Real updates
   of legitimate extensions are benign, so they won't trigger a malicious alert. Take the
   real current version as `v1` (benign baseline) and create `v2` by injecting a known bad
   behaviour (e.g., read `document.cookie` + POST it to a collector domain). This is the
   "synthetic weaponisation" from the data plan — always clearly labelled as synthetic.

### 4.4 Worked examples (and why they make good test cases)

| Extension | What it tests | Where to get versions |
|---|---|---|
| **Chrome Remote Desktop** (Google-made, popular, *benign*) | Does the tool correctly say **BENIGN** on a real legit update (no false positive)? | Two real consecutive versions from **crx4chrome** |
| **Email Finder – GetProspect** (a scraper: legitimately reads page contacts + makes network calls) | Can the features tell **"legitimate data access" apart from "malicious exfiltration"**? Great gray-area stress test. | Current from disk/endpoint; old version from crx4chrome if archived, else synthetic `v2` |
| **Either, weaponised** | Does the tool correctly say **MALICIOUS** when an update turns bad? | real `v1` + **synthetic** `v2` |

This mirrors the dataset strategy in miniature: **real pairs validate "no false alarms,"
synthetic pairs prove "it catches attacks."**

### 4.5 Step 4 — feed both into the pipeline
Load `v1` and `v2` each into the sandbox → trace → `Δ = f(T2) − f(T1)` → score → report.

### 4.6 Legal / safety notes
- Downloading extensions for security analysis is fine; **do not redistribute** them.
- Scraper-type extensions (e.g., GetProspect) live in a ToS gray zone — only run them in your
  sandbox against your **fake test pages**, never to scrape real sites.
- Treat every downloaded `.crx` as untrusted: only ever load it inside the sandbox.

---

## 5. THE SANDBOX, EXPLAINED PROPERLY

**Why we need it:** we will literally run real malware (malicious extensions). If we ran it
normally, it could steal *our* data or call home to attackers. A sandbox makes that
impossible while still letting us watch the malware behave.

**What a sandbox actually is:** an isolated execution environment with three walls:
1. **Filesystem isolation** — the code sees only a fake, throwaway filesystem, not your real
   files. When the container is deleted, everything it did vanishes.
2. **Network isolation (egress control)** — we cut off or tightly control its access to the
   real internet, so "phone home" / data-theft attempts hit a wall (or hit our proxy, which
   logs them and refuses to forward).
3. **Process isolation** — it cannot see or interfere with other programs on the host.

**How we build it — Docker.** Docker creates **containers** from a recipe called a
**Dockerfile**. The recipe says: "start from a minimal Linux, install a headless browser,
install Playwright and mitmproxy, copy in our scripts." Each analysis run gets a **fresh
container** from that image, so every run starts from an identical clean state (great for
science) and is thrown away afterwards (great for safety).

```
   Dockerfile (recipe)  ──build──►  Image (frozen template)  ──run──►  Container (live, throwaway)
   "install browser,                "a snapshot ready to go"          "one analysis run,
    playwright, mitmproxy,                                              then deleted"
    copy scripts"
```

**Container vs Virtual Machine (VM):** a VM emulates a whole computer (heavy, GBs of RAM); a
container shares the host's OS kernel and is much lighter (starts in seconds). For untrusted
*native* malware you'd want a VM; for *browser-extension* malware (which runs inside the
browser's own sandbox anyway), a Docker container with network egress control is the
standard, practical choice and is light enough for student hardware.

---

## 6. THE TOOLBOX — every tool, what it is, what it does, why we use it

| Tool | One-line definition | What it does for us | Why this one |
|---|---|---|---|
| **Python 3.11+** | A popular, readable programming language. | The glue language for the whole pipeline. | Best ecosystem for automation + ML; what the field uses. |
| **Git + GitHub** | Version control: saves every change, lets two people collaborate. | Stores the code, tracks who changed what, enables Codespaces. | Industry standard; you already use GitHub. |
| **Docker / Docker Desktop** | Builds and runs isolated containers. | Creates the safe sandbox; guarantees clean, identical runs. | The standard for isolation; recipe is reproducible. |
| **Playwright (Python)** | Browser-automation library by Microsoft. | The "robot" that opens pages, clicks, types; can load extensions; can inject our watcher JS; drives Chromium **and** Firefox. | One library, multiple browsers — perfect for our multi-browser goal. |
| **mitmproxy** | A scriptable HTTPS proxy. | Records all network traffic, replays it for determinism, blocks real exfiltration. Python "addons" let us customise it. | Free, scriptable in Python, has record/replay built in. |
| **Chrome DevTools Protocol (CDP)** | The low-level control channel inside Chromium (Playwright uses it under the hood). | Lets us capture network + console + more directly from the browser when needed. | Already available via Playwright; deeper signal if we want it. |
| **pandas / NumPy** | Python libraries for tables and math. | Hold and crunch the feature data. | Standard data-science tooling. |
| **scikit-learn** | Classic machine-learning library. | Trains/evaluates the Random Forest, does cross-validation. | Beginner-friendly, perfect for Random Forest on small data. |
| **XGBoost** *(optional)* | A stronger gradient-boosting ML library. | A secondary, possibly more accurate model to compare. | Nice-to-have for the evaluation; not required for v1. |
| **FastAPI** *(optional)* | A framework for building web APIs in Python. | Exposes "analyse this pair" as a callable service. | Clean way to connect dashboard ↔ engine; optional early on. |
| **Streamlit** | Turns a Python script into a simple web dashboard. | The demo UI: upload two versions → see the report and charts. | Easiest possible UI; no web-dev knowledge needed. |
| **web-ext** *(Firefox)* | Mozilla's tool for running/loading Firefox extensions. | Helps load `.xpi` extensions for the Firefox runs. | The supported way to drive Firefox extensions. |
| **VS Code** | Code editor (you're in it now). | Where you write and run everything. | You already have it; works great with Python + Docker + Codespaces. |

You do **not** need all of these on day one. The minimum to get the first result:
**Python + Playwright + mitmproxy** (run the browser, capture traffic). ML, Docker
hardening, and the dashboard come later.

---

## 7. WHERE DOES IT RUN, AND WHO IS THE "USER"?

There are three "places" code can run; we use the first for almost everything:

1. **Locally, on a capable machine (default).** The engine runs on the Mac / a lab PC / a
   cloud VM. The analyst runs a command or opens the local Streamlit dashboard at
   `http://localhost:8501`. Everything stays on that machine.

2. **A free cloud VM (recommended for the heavy runs).** Because the i3/4 GB laptop is weak
   (Section 8), we put the heavy sandbox engine on a free cloud machine and connect to it.
   Options: **GitHub Codespaces** (free monthly hours, VS Code in the browser), **Oracle
   Cloud Always-Free** (a genuinely powerful ARM VM, free forever), or a university lab
   server if available.

3. **Publicly hosted? No.** We deliberately do **not** put this on the public internet.
   It runs malware; hosting it publicly would be a security risk and serves no purpose for a
   research project. The dashboard is for *local* demos and your project evaluation.

**The interaction model (what a "user" does):**
```
   Analyst                         Our Tool
   ───────                         ────────
   provides two extension     ──►  unpacks, runs both in sandboxes,
   versions (files or ID)          captures + diffs + scores
                              ◄──  returns a report:
                                   verdict + the exact new behaviours + charts
```
That's it. It is a **decision-support tool for analysts**, not a consumer app. This is the
normal shape for academic security tools (Hulk, ExtPrivA, etc. all work this way).

---

## 8. YOUR HARDWARE — the honest plan

Your machines:
- **Suhani — MacBook:** the better machine. This becomes the **primary engine** for running
  browsers + sandboxes during development.
- **Bind — Intel i3, 4 GB RAM, Windows:** **too small** to comfortably run Docker + a
  headless browser + ML at the same time. 4 GB RAM will swap (thrash) and crawl. This is a
  real constraint we design around — not a blocker.

**The plan that works on this hardware:**

| Task | Where to run it | Why |
|---|---|---|
| Writing code, Git, docs, dataset labelling | **Both laptops** (light work) | Editing text/code needs almost nothing. |
| Running browsers + sandboxes (the heavy part) | **Mac** for dev; **cloud VM** for batch runs | Needs 6–8 GB RAM realistically. |
| ML training (Random Forest on modest data) | **Mac** or **cloud**; small datasets OK on the i3 | RF on a few thousand rows is light. |
| The actual graded batch experiments | **Cloud VM** (Oracle Always-Free / Codespaces) or **lab PC** | Free, powerful, nobody's laptop melts. |

**Concretely for Bind (i3/4 GB):**
- Use **GitHub Codespaces** as your main "computer" for anything heavy: it gives you a
  cloud Linux machine with VS Code in your browser, and the free tier is enough for this
  project. Your laptop just shows the editor; the work happens in the cloud.
- Alternatively spin up an **Oracle Cloud Always-Free** ARM VM (up to 24 GB RAM, free
  forever) and SSH into it — overkill-good for the sandbox runs.
- Keep local work to coding, writing, dataset prep, and light ML.
- Optional: a lightweight Linux (Xubuntu/Lubuntu) on the i3 frees ~1–1.5 GB vs Windows, but
  Codespaces/cloud makes this unnecessary.

**Apple-Silicon note (if the Mac is M1/M2/M3):** Playwright runs browsers natively on ARM
just fine. If you use Docker on the Mac, prefer ARM (`linux/arm64`) base images so you don't
pay an emulation penalty. For most development you can run Playwright **without** Docker on
the Mac (faster, lighter) and only add Docker for the safety-isolation runs with real
malware.

---

## 9. STEP-BY-STEP SETUP (do these in order)

> You can do **Phase A** on either laptop today. Heavier phases should target the Mac or a
> Codespace.

### Phase A — Foundations (Week 1)
1. **Install Git** and sign in to GitHub (you already have a repo: `CSD Project`).
2. **Install Python 3.11+** (python.org, or `brew install python` on Mac).
3. **Install VS Code** + the **Python** extension (you're already in VS Code).
4. **Create a project structure** in the repo:
   ```
   CSD-Project/
     engine/          # the analysis pipeline (Python)
       sandbox/       # Docker + browser-run code
       features/      # feature extraction
       scoring/       # rules + ML
     data/            # extensions, recorded web, datasets
     dashboard/       # Streamlit app
     docs/            # proposal, this guide, notes
   ```
5. **Create a Python virtual environment** (an isolated set of Python libraries for this
   project so it doesn't clash with anything else):
   ```bash
   python -m venv .venv
   # Windows:  .venv\Scripts\activate
   # Mac:      source .venv/bin/activate
   pip install playwright mitmproxy pandas scikit-learn streamlit
   playwright install chromium firefox
   ```

### Phase B — First runtime trace, no Docker yet (Weeks 2–3)
*Goal: prove you can run an extension and capture what it does.*
6. Write a tiny Python script using **Playwright** that launches Chromium, loads a simple
   known extension, opens a test page, and clicks around.
7. Start **mitmproxy** (`mitmdump`) and route the browser through it; confirm you can see
   the list of URLs the browser/extension requested.
8. Save that list to `trace.json`. **You now have `T` for one version.** This is a huge
   milestone — most of the project is built on this.

### Phase C — The diff (Weeks 3–4)
9. Run two versions of the *same* extension; produce `T1` and `T2`.
10. Write **feature extraction**: convert each trace to a number list.
11. Compute `Δ = f(T2) − f(T1)` and print "what's new in v2." First end-to-end result. 🎉

### Phase D — Determinism + sandbox hardening (Weeks 4–6)
12. Add **mitmproxy record/replay** so both versions see identical pages.
13. Write the **Dockerfile**; move the browser run **inside a container** with network
    egress blocked. Now it's safe for real malware.

### Phase E — Data + scoring (Weeks 6–9)
14. Build the **synthetic weaponisation corpus**: take clean extensions, inject known bad
    behaviours (cookie read + POST to a collector) to create labelled `(v1, v2)` pairs.
15. Implement the **weighted-rule scorer**.
16. Train the **Random Forest** in scikit-learn; evaluate with cross-validation.
17. Validate on the few **real** 2024–25 incident pairs you can obtain.

### Phase F — Dashboard + multi-browser + write-up (Weeks 9–13)
18. Build the **Streamlit dashboard**: upload two versions → show verdict + the new
    behaviours + charts.
19. Add the **Firefox** back-end (second engine) via Playwright/`web-ext` (stretch).
20. Run the full **evaluation**, make the plots, and write the report/paper draft.

---

## 10. SUGGESTED TIMELINE (≈ one semester, two people)

| Weeks | Milestone | Owner (lead) |
|---|---|---|
| 1 | Setup, repo structure, tools installed | Both |
| 2–3 | First Playwright + mitmproxy trace of one extension | Bind (infra) |
| 3–4 | Two-version diff working end to end | Bind + Suhani |
| 4–6 | Record/replay determinism + Docker sandbox | Bind |
| 6–9 | Synthetic dataset + rule scorer + Random Forest | Suhani |
| 9–11 | Streamlit dashboard + real-incident validation | Both |
| 11–13 | Firefox engine (stretch) + full evaluation + report | Both |

Map this onto the proposal's phasing: **Chromium core is the must-have; Firefox + polished
dashboard + evasion experiments are the stretch / Project-2 material.**

---

## 11. WHAT TO DO THIS WEEK (your first concrete steps)

1. Both: install Python + VS Code Python extension; create the repo folder structure.
2. Bind: set up a **GitHub Codespace** on the repo (this becomes your heavy-lifting machine).
3. Suhani: install Playwright on the Mac and get `playwright install chromium` working.
4. Together: run the tiny Playwright script that opens a page and prints the page title —
   the "hello world" that proves the toolchain works.
5. Read the **base paper** (Bui et al., ExtPrivA, IEEE S&P 2023) once together — it does
   exactly steps 6–8 above for a single version; you'll reuse its ideas constantly.

---

## 12. MINI-GLOSSARY (quick lookups)

- **Headless** — running with no visible window.
- **Egress** — outbound network traffic (data leaving the machine).
- **Instrumentation** — extra code we add to watch/record what the target does.
- **Corpus** — a collection of data samples (here: extensions and update pairs).
- **Weaponisation** — turning a clean sample malicious on purpose, for training data.
- **Cross-validation** — testing an ML model on data it didn't train on, to measure honesty.
- **Service worker** — a background script (MV3) that wakes on demand.
- **Content script** — extension code injected into the web pages you visit.
- **Localhost** — your own machine (`127.0.0.1`); a "local" web app only you can see.
- **SSH** — secure remote login to another computer (e.g., a cloud VM) from your terminal.

---

*Keep this file open while you build. When something is unclear, search this doc first —
nearly every term you'll hit in the next few months is defined above.*
