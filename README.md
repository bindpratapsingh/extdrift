# extdrift - Behavioral-Diff Detection of Malicious Browser Extension Updates

> A sandboxed, cross-browser **runtime-analysis framework** that detects when a browser-extension
> *update* turns malicious — by running two consecutive versions under identical conditions and
> **diffing what they actually do**.

**Course:** CSD493 Project-1 (Monsoon 2026) · B.Tech CSE · Shiv Nadar Institution of Eminence
**Status:** 📄 *Proposal & design stage — documentation only, no code yet.*

---

## TL;DR — what is this?

A browser extension you trust can become malicious **overnight** through a single silent
auto-update — the browser grants its trust *once* at install and never re-checks it. The
**December 2024 Cyberhaven attack** pushed a cookie-stealing update to **400,000 users within
hours**, and the same campaign hit dozens more extensions. Static review and permission checks
can't catch this: malicious code can be obfuscated, time-delayed, or only triggered under
specific conditions.

**`extdrift` scores the *change*, not the extension.** Give it two versions of the same
extension (old = trusted baseline, new = suspected). It runs each in a sealed sandbox, records
everything it does, compares the two, and produces an **explainable report**:

> *"v3.1 now reads `document.cookie` on banking pages and POSTs form data to `evil-collect.com`
> — a domain v3.0 never contacted. Verdict: **MALICIOUS** (Random Forest = 0.92, rules = 0.88)."*

It is a **local research/lab tool for security analysts**, not a hosted consumer product.

---

## How it works (the pipeline)

```
  Extension v1 (.crx/.xpi)        Extension v2
        │                              │
   ┌────▼─────────┐             ┌──────▼───────┐
   │  SANDBOX 1   │             │  SANDBOX 2   │   Docker container, egress-blocked,
   │ headless     │             │ headless     │   headless browser driven by Playwright,
   │ browser + v1 │             │ browser + v2 │   all traffic through mitmproxy
   └────┬─────────┘             └──────┬───────┘   (same RECORD/REPLAYED pages for both)
     Trace T1                       Trace T2
        │                              │
        └──────────┬───────────────────┘
              Δ = f(T2) − f(T1)        ← feature diff: what's NEW in v2
                   │
            ┌──────▼───────┐
            │   SCORING    │  (a) transparent weighted rules  (heuristics)
            │              │  (b) machine-learning classifier (RF / XGBoost; deep model later)
            └──────┬───────┘
                   ▼
            REPORT: verdict + exactly which new behaviours fired (+ JSON)
```

Each trace captures **four dimensions**: network requests, DOM access (reading form fields /
cookies), storage/cookie access, and extension-API calls (`chrome.*` / `browser.*`). The
**record/replay** step makes both versions see byte-identical pages, so the extension is the
*only* variable — this kills the main source of false positives.

---

## Repository structure

```
extdrift/
├── README.md                     ← you are here
└── Reference Docs/
    ├── IMPLEMENTATION_GUIDE.md   ← THE build guide (read this first); every term defined
    ├── ML_Models_Research.md     ← which ML model & why (beginner-friendly, all acronyms spelled out)
    ├── CHANGES.txt               ← what changed from the first proposal draft, and why
    ├── Instructions.txt          ← raw advisor-meeting notes
    ├── Detailed_Proposal_CSD493.pdf / .tex   ← the full detailed proposal
    ├── Project_Proposal_CSD493.pdf           ← the official one-page proposal form
    └── Proposal Latex/           ← LaTeX sources for both proposals
```

> **Planned code layout** (once we start building, per the implementation guide):
> ```
> engine/{sandbox,features,scoring}/   data/   dashboard/   docs/
> ```

---

## 📚 Documentation index — start here

| If you want to… | Read |
|---|---|
| **Understand & build the system** (every concept explained from zero) | [Reference Docs/IMPLEMENTATION_GUIDE.md](Reference%20Docs/IMPLEMENTATION_GUIDE.md) |
| **Understand the ML model choice** (RF vs XGBoost vs deep learning, all acronyms) | [Reference Docs/ML_Models_Research.md](Reference%20Docs/ML_Models_Research.md) |
| **Read the formal proposal** | [Reference Docs/Detailed_Proposal_CSD493.pdf](Reference%20Docs/Detailed_Proposal_CSD493.pdf) |
| **See what changed from draft 1 and why** | [Reference Docs/CHANGES.txt](Reference%20Docs/CHANGES.txt) |
| **See the advisor's raw notes** | [Reference Docs/Instructions.txt](Reference%20Docs/Instructions.txt) |

---

## Tech stack

| Layer | Tool | Why |
|---|---|---|
| Language | **Python 3.11+** | best ecosystem for automation + ML |
| Browser automation | **Playwright** | one library drives Chromium **and** Firefox; can load extensions |
| Traffic capture | **mitmproxy** | scriptable HTTPS proxy with built-in record/replay |
| Sandbox | **Docker** | isolated, reproducible, network-egress-controlled containers |
| ML | **scikit-learn** (Random Forest), **XGBoost**; deep models later (Transformer/GNN) | tabular baseline now, state-of-the-art stretch later — see the model doc |
| Data | **pandas / NumPy** | feature tables and math |
| API / UI | **FastAPI** (optional) + **Streamlit** | local dashboard for the demo |
| Firefox (stretch) | **web-ext** | loading `.xpi` extensions |

---

## Scope & roadmap

**This semester (must-have):** Chromium-family core pipeline (Chrome/Edge/Brave share the
Manifest V3 `.crx` format + `chrome.*` API) → record/replay determinism → 4-dimension trace →
synthetic weaponisation corpus → weighted-rule baseline + Random Forest/XGBoost → end-to-end diff
report on a small set of real incidents.

**Stretch / Phase 2:** Firefox (Gecko, `.xpi`, `browser.*`) second engine · Streamlit dashboard ·
a state-of-the-art **sequence/graph deep model** · evasion-resistance experiments · paper-grade
evaluation. **Safari is explicitly out of scope.**

| Weeks | Milestone |
|---|---|
| 1 | Setup, repo structure, tools installed |
| 2–3 | First Playwright + mitmproxy trace of one extension |
| 3–4 | Two-version diff working end to end |
| 4–6 | Record/replay determinism + Docker sandbox |
| 6–9 | Synthetic dataset + rule scorer + Random Forest / XGBoost |
| 9–11 | Streamlit dashboard + real-incident validation |
| 11–13 | Firefox engine (stretch) + full evaluation + report |

*(Full week-by-week plan with setup commands is in the implementation guide.)*

---

## Quick start (when development begins)

> Heavy runs (browser + sandbox) target **Suhani's Mac** or a **cloud VM / GitHub Codespaces** —
> Bind's i3/4 GB laptop is for coding, writing, and light ML only.

```bash
git clone https://github.com/<owner>/extdrift.git
cd extdrift

python -m venv .venv
# Windows:  .venv\Scripts\activate
# Mac/Linux: source .venv/bin/activate

pip install playwright mitmproxy pandas scikit-learn xgboost streamlit
playwright install chromium firefox
```

The first concrete goal (implementation guide, Phase B): a small Playwright script that launches
Chromium, loads a known extension, visits a test page, and routes traffic through `mitmdump` to
save the list of requested URLs to `trace.json`. **That first trace is the foundation everything
else builds on.**

---

## Academic context

- **Base paper:** D. Bui, B. Tang, K. G. Shin, *"Detection of Inconsistencies in Privacy
  Practices of Browser Extensions (ExtPrivA),"* IEEE S&P 2023 — analyses a *single* version; we
  extend it to the **update / version-diff** setting.
- **Lineage:** Hulk (USENIX Security 2014), WRIT (IEEE TDSC 2024), VEX, Tranco (NDSS 2019).
- **Novelty:** to our knowledge, no open framework does **cross-engine, update-aware behavioural
  diffing with record/replay determinism and explainable dual-scored output** — a natural fit for
  a short paper/workshop if the results hold.

---

## ⚠️ Safety & ethics

This project **runs real malware** (malicious extensions) for analysis. Therefore:
- Everything runs inside an **egress-restricted Docker sandbox** — malware cannot reach the real
  internet or steal anything.
- Only **dummy credentials** and **fake test pages** are ever used.
- TLS interception happens **only inside the local sandbox**, never on third-party machines.
- Downloaded extensions are for **analysis only — never redistributed**.
- The tool is **never** hosted publicly.

---

## Team

| Member | SNU ID | Role |
|---|---|---|
| **Bind Pratap Singh** | 2310110084 | Infrastructure — sandbox, Docker, Playwright, mitmproxy, instrumentation, tracing |
| **Suhani Deepak Agrawat** | 2310110717 | Data & ML — corpus, feature engineering, scoring models, dashboard |

**Advisor:** Dr. Sweta Mishra · **Area of Specialization:** Cybersecurity

---

*This is an academic research prototype built for CSD493 and is provided as-is for educational and
defensive security research purposes only.*
