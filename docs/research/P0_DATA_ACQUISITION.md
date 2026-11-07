# P0 — Real-data acquisition: decision log

> Running log of the data-acquisition work (the panel's hardest-graded axis). Local only,
> not pushed. Written as decisions + *why*, newest work appended at the bottom.

## Why this work exists

The project's biggest weakness, confirmed by the Gemini deep-research reports (in
`Researches/`) and the panel-readiness analysis, is the **dataset**: ~87% synthetic, the
malicious class entirely weaponised (we wrote the attacks), and a small real corpus. The
standing assumption was *"real malicious data is unobtainable."* The research disproves
that. Real malicious extension **code**, and even some real malicious **update pairs**, are
openly downloadable with no author contact required (our author emails have gone unanswered
for a week, so every route here is deliberately **self-serve**).

Core strategy shift: **stop being synthetic-only.** Feed real malicious extensions through
the sandbox we already built to produce *real* malicious behavioural traces, and recover
*real* benign→malicious version pairs where they exist.

## Sources the research surfaced (self-serve, ranked by how runnable they are)

| Source | What | Yields | Access |
|---|---|---|---|
| **AMO v5 API** | Firefox version history + `.xpi` + sha256 + `is_disabled_*` flags | real benign pairs at scale; pulled/disabled versions | free REST (have `engine/collector/amo.py`) |
| **Wayback CDX API** | byte-for-byte archived CRX/XPI from the original CDNs | historical versions → real pairs, signature-verifiable | free (`web.archive.org/cdx`) |
| **mallorybowes** (on disk) | 7,382 malicious Chrome IDs, CC BY 4.0 | seed list; the still-live ones download now | local `data/real/mallorybowes/` |
| **`abdchau/two-heads-are-better`** (NDSS'26) | ~13–20 real malicious exts removed from Chrome, still live on **Edge** | real runnable malware | GitHub IDs → Edge CRX endpoint |
| **Manifest V3 Unveiled** (Pantelaios'24) | 517 malicious as V2→V3 **pairs** | real malicious pairs | GitHub |
| **`its-not-easy/tweb25`** (TWEB'26) | 7,140 malicious + 99k benign (features/IDs) | labels + IDs to pull | GitHub |
| **Chrome update endpoint** | current signed CRX of a listed id | still-live malicious current versions | `clients2.google.com` (have `chrome.py`) |

Rejected / de-prioritised, with reasons:
- **VirusTotal labels** — Rosenzweig et al. report **>97% false-negative** on extensions; using
  VT would contaminate the benign class. We explicitly do **not** use VT. (Good panel point.)
- **crx4chrome** — real history but an *untrusted* mirror (possible repacking); only usable
  with mandatory CRX3-signature verification. Kept as a last-resort behind verification.
- **Chrome-Stats** — best historical coverage incl. malware-removal flags, but commercial
  (~100 req/month free) and binaries redirect to Google's CDN anyway. Not worth paying yet.
- **dam.io archive** — real CWS history but hard cutoff **Feb 2019** (pre-MV3). Baseline only.

## Verification is mandatory for any file from an untrusted source

Every downloaded CRX3 is verified before use: parse the `Cr24` header, extract the public
key, SHA-256 → a–p id, confirm it equals the expected extension id, and check the signature
over the ZIP payload. We already have this in `engine/unpack/crx.py` (`read_crx_header`,
`crx_id_from_key`). XPI integrity is checked against the AMO-provided sha256. A file that
fails is discarded — this neutralises the supply-chain risk of third-party mirrors.

## P0 plan (execute in order)

1. **Wayback collector** (`engine/collector/wayback.py`) — recover historical CRX/XPI for a
   given id from the Internet Archive, verify each, group into versions → candidate real
   pairs. Reliable for Firefox XPI; best-effort for Chrome (IA mostly archived the XML
   update manifests, binaries are sparser).
2. **Real-malware harvester + capture** — download the still-live malicious extensions
   (mallorybowes STILL-ACTIVE + the `two-heads` Edge ids), run each through the existing
   capture engine → real malicious behavioural traces in the same schema as everything else.
3. **Scale real benign pairs via AMO** — grow from ~21 to low-hundreds; also harvest
   `is_disabled`-flagged versions as a real pulled-version signal.

Safety: untrusted extension code only ever runs inside the sealed, offline sandbox; all of
`data/real/**` stays git-ignored (no redistribution).

---

## Log

### 2026-11-06 — kickoff
- Read all four Gemini reports; built the source table above and the reject list.
- Confirmed on disk: `data/real/mallorybowes/malicious-extension-ids.txt` (7,382 ids),
  a working `engine/collector/amo.py`, and CRX verification in `engine/unpack/crx.py`.
- Network probe: archive.org reachable; the CDX API returns captures for
  `clients2.google.com/service/update2/crx` (these are the **XML** update manifests, status
  200) — so Chrome binaries need the CDN-host query, which is sparser. Firefox XPI captures
  are the reliable binary route. Decision: build the Wayback collector to handle **both**
  the manifest captures (to enumerate versions) and binary captures (to fetch+verify), and
  lean on AMO for reliable Firefox pairs.

### 2026-11-06 — Wayback: honest negative result (built `engine/collector/wayback.py`)
- Built the collector (CDX query → raw `id_` capture fetch → CRX3/XPI signature + id
  verification → dedup by manifest version). It is correct and will recover versions where
  IA has them.
- **But IA does not actually hold the binaries.** Probes: `x-chrome-extension` mimetype
  captures of the Chrome update host = **empty**; `clients2.googleusercontent.com/crx/blobs`
  = empty; AMO-download prefix with a slug wildcard = empty (CDX prefix-match can't filter
  by a mid-URL slug). So Wayback is **not a viable primary binary source** for either store.
  This mirrors the earlier chrome-delisting negative result — a real finding, not a failure.
- **Decision / pivot:** keep `wayback.py` as a documented best-effort tool (it still helps
  for a specific delisted id IA happened to crawl), but move P0's weight to the two routes
  that demonstrably work:
  1. **AMO v5 direct history** — confirmed it returns **50+ versions per addon** going back
     years (privacy-badger to 2018). This is the real, reliable Firefox-pair source; no
     Wayback needed. Scale it, and build *many* consecutive pairs per extension, plus pull
     `is_disabled_by_mozilla` versions as real pulled→benign pairs.
  2. **Real-malicious capture** — download still-live malicious Chrome CRX (the ~40% of
     mallorybowes ids not yet delisted) and the Edge-live `two-heads` ids, run each through
     the sandbox for **real malicious behavioural traces**, used to (a) validate our
     features fire on real malice and (b) ground-truth the weaponiser (P1).
- Note on the differential framing: a lone real malicious extension is not a *pair*. Its
  scientific use is (i) a real single-version malice test set that must trip our features,
  and (ii) a behaviour reference to prove our synthetic families reproduce real attacks.
  Real *pairs* come from AMO history (benign→benign and benign→pulled).

### 2026-11-06 — REAL malicious corpus harvested + captured (the headline win)
- **New source found:** the Two Heads dataset ships `manual-analysis.json` — 48 entries, **20
  confirmed-malicious** (edge_malware=true) with edge_id + chrome_id + version + a hand-written
  `malware_type` (browsing-data exfiltration, facebook-cookie exfiltration, affiliate-link
  replacement, rce, scam, arbitrary redirects…). Saved to `data/real/two-heads/`.
- **Liveness:** sampled mallorybowes → **~25% still downloadable** from Chrome (≈1,800 of 7,382).
  Edge: the correct update URL needs `prodversion` + `acceptformat` (else 204); fixed in
  `engine/collector/edge.py`.
- **Built:** `engine/collector/edge.py`, `experiments/harvest_real_malicious.py`. Harvested
  **18 real malicious extensions** (3 Edge-labelled + 15 live-Chrome mallorybowes) →
  `data/real/malicious/` with a `catalog.json`. (Several Two-Heads Edge ids have since been
  delisted → 204; the paper is from 2025.)
- **SAFETY — sealed execution.** Real malware must not phone home. Added a `seal_all` mode to
  `TestSite`/`capture`: the host-resolver maps **every** hostname (not just `.test`) to the
  local collector, so exfil beacons land in our own sink. Verified: a POST to
  `evil-c2.example.com` is captured locally, nothing leaves. **Residual risk:** host-resolver
  does not remap *literal-IP* connections; extension malware overwhelmingly uses domains, and
  the Docker `--internal` pipeline is the full-isolation path for anything higher-risk. The
  `.gitignore` was tightened to a blanket `data/real/*` (keeping only the CC-BY IOC list) so no
  malware code can ever be staged.
- **Built + ran:** `experiments/capture_real_malicious.py` (seal_all, diff vs an empty baseline
  = "what does this do on cold install", score with the existing rules). **Pilot 3/3 → MALICIOUS**,
  5–9 rules each, 9–12 exfil attempts intercepted locally. Full 18-extension batch running.
- **Why this matters:** our rules/features fire on *real* malware, not only our synthetic
  payloads — the single strongest rebuttal to "the malicious class is all synthetic." Report
  separates the extension's real exfil targets from Chromium's own update/connectivity noise.

### 2026-11-06 — real-malware result (final tally)
- Background Playwright capture stalls after the first item (same issue as the weaponised
  validate run) — it is only reliable in the **foreground**. Ran in foreground batches; added
  `--start`/resume so batches accumulate into one `results.json`.
- **Headline numbers (17 real malicious extensions captured, 1 crashed the browser — handled):**
  - **14 / 17 (82%) flagged** (5 MALICIOUS + 9 SUSPICIOUS) by the existing rules, scoring each
    against an empty baseline.
  - **12 had a real exfil/C2 backend intercepted** by the sealed sandbox — **19 distinct real
    domains**, nothing left the machine: `data.flipshope.com`, `api.primrose-analytics.com`,
    the `*.urban-vpn.com` analytics/auth family, `api.ipify.org` (IP recon), `www.google-
    analytics.com`, `onlinesearchtool.org`, and **DNS-over-HTTPS endpoints** (`dns.google`,
    `cloudflare-dns.com`, `dns.alidns.com`) — i.e. real evasion, observed.
  - The 3 unflagged are search-hijacker/scam types whose payload triggers on search queries our
    scenario doesn't simulate → honest limitation, motivates richer scenarios (P1).
- Artifacts: `experiments/capture_real_malicious.py`, `out/real_malicious/results.json`, per-id
  traces under `out/real_malicious/<id>/`. This is a **real-malware validation set**, kept
  separate from the training deltas (single-version, so not update pairs).
- **Panel line:** "We executed 17 confirmed-malicious extensions in the sealed sandbox; our
  rules flagged 82%, and we intercepted their real beacons to 19 live backends — including
  DNS-over-HTTPS evasion — without a byte leaving the machine."

### 2026-11-06 — P0-A benign scale (status) + model retrain + selection-criterion fix
- **Benign scale:** the capture pipeline works and **all 21 downloaded AMO pairs are already
  captured** (51 real benign rows). Growing further needs *new* extensions, which is
  capture-bound; per the project's division of labour that is the **Mac's** job
  (`scripts/scale_capture.sh`, `docs/MAC_RUNBOOK.md`). Added 2 fresh slugs to the pool
  (`i-dont-care-about-cookies`, `web-scrobbler`); noted the pool manifest (`pairs.json`) is
  only updated by `collect_top`, not by a single-slug pull — a small fix for the Mac workflow.
  **Not productive to grind hundreds of Firefox captures here where background Playwright
  stalls; handed off to the Mac with the pool pre-seeded.**
- **Model retrain (closes the stale-model gap):** the committed `winner.joblib` was from
  2026-09-21 but `deltas.csv` was rebuilt 2026-11-03. Retrained on the current data.
- **Selection-criterion change (deliberate, documented).** On the current data RF, XGBoost and
  HistGB are tied on PR-AUC (within 0.003); the old selector picked the PR-AUC max (RF).
  Changed `engine/ml/bakeoff.py` to select by **FPR at 90% recall** (PR-AUC breaks ties),
  because:
  1. FPR is the operational metric for a differencing tool — the entire ML-over-rules case is
     that rules cry wolf (~41% FPR here) and the model does not (~1%).
  2. Among statistically-tied ensembles, FPR should decide — and it favours **gradient
     boosting**, which answers the advisor's "go beyond Random Forest / RF reads as dated".
  New winner: **XGBoost**, CV PR-AUC 0.981, **FPR@90%recall 0.011** (rules 0.408); temporal
  split holds (PR-AUC ~0.974). All 231 tests pass; the demo loads the new model.
  **Flag for the team:** confirm you're happy presenting XGBoost (or HistGB — identical FPR
  0.011) as the Tier-1 winner; the real "beyond RF" answer is still the Tier-2 graph model
  (stretch).

### 2026-11-06 — synthetic↔real coverage (a validation WIN) + weaponiser roadmap (P1)
Using the real attack-type labels from Two Heads against our family sets:

| Real attack type (count) | Our **synthetic generator** family | Our **weaponiser** family |
|---|---|---|
| browsing-data exfiltration (14) | `history_exfil` (41 rows) ✓ | **missing** |
| google analytics / telemetry (4) | `ad_affiliate` / `sw_beacon` ✓ | partial (`sw_beacon`) |
| facebook cookie exfiltration (2) | `cookie_theft` (93) ✓ | `cookie_theft` ✓ |
| affiliate link replacement (1) | `ad_affiliate` (43) ✓ | **missing** |
| arbitrary redirects (1) | `redirect_hijack` (58) ✓ | **missing** |
| search-history exfiltration (1) | `history_exfil` ✓ | **missing** |
| iframe injection (1) | `redirect_hijack`/`form_jacking` ~✓ | **missing** |
| scam (2), rce (1), screenshot (1) | out of behavioural scope / minor gap | — |

**Finding (use this with the panel):** the synthetic **generator's 9 families map onto the
real-world attack vocabulary** — the single most common real attack (browsing-data exfil) is
exactly our `history_exfil` family, and it is well-represented (41 rows). So the training
corpus is *not* an arbitrary invention; its classes are the classes real malware uses. This is
a direct, data-grounded answer to "does your synthetic match real?".

**The real gap is the WEAPONISER, not the generator.** The weaponiser (real-extension
injection, used for the demo pairs and real-grounded malicious) has only 3 families
(cookie/credential/sw_beacon) vs the generator's 9. **P1 roadmap** (next session / Mac):
1. Port `history_exfil` (webNavigation/tabs URL scraping → beacon — the DataSpii/#1 pattern)
   and `ad_affiliate` into `engine/weaponiser/payloads.py`.
2. Add the evasion we *observed in real malware*: DNS-over-HTTPS exfil (`dns.google`,
   `cloudflare-dns.com`) and IP-recon (`api.ipify.org`) as optional payload behaviours — this
   closes the "synthetic has no OPSEC/evasion" criticism with behaviours taken from captures.
3. Rebuild the weaponised demo pairs + re-capture (Mac), fold into the dataset, retrain.

## P0 status: DONE
- Wayback collector (honest negative result) ✓ · Edge collector + real-malware harvest ✓ ·
  sealed `seal_all` capture + 17-extension real-malware validation (82% flagged, 19 real
  backends) ✓ · benign-scale assessed (Mac job, pool seeded) ✓ · model retrained + FPR-primary
  selection → XGBoost ✓ · STATUS.md + PROJECT_REPORT §17 reconciled ✓. Nothing pushed.

---

## Log (P1 — weaponiser parity with the real attack vocabulary)

### 2026-11-07 — P1 step 1 DONE: `history_exfil` + `ad_affiliate` registered
- The two templates had been drafted in `payloads.py` but were **never added to the
  `PAYLOADS` dict**, so the weaponiser still exposed only 3 families (confirmed by import).
  Registered both:
  - `history_exfil` — CS reports each visited page to the worker; SW pulls every open tab's
    URL (`chrome.tabs.query`) and beacons the lot (+ a `webNavigation.onCompleted` hook,
    `&&`-guarded so it degrades where the API/permission is absent). Permission: `tabs`.
    This is the DataSpii pattern and the single most common real behaviour (14/20 Two Heads).
  - `ad_affiliate` — CS rewrites commerce links to append the attacker's referral tag and
    beacons which origins were touched. No extra permission (pure DOM + content-script fetch).
- Verified the **full weaponise path** end-to-end on `data/corpus/readerlite/1.0.0`, clean and
  obfuscated: files injected, marker present, `tabs` added for `history_exfil`, none for
  `ad_affiliate`, version bumped, `_extdrift_synthetic.family` stamped. Obfuscation hides the
  collector literal in every injected file.
- `demo/build_weaponised_pairs.py` gained `--family {…}` (argparse-validated against the
  registry) so demo pairs can now be built from any family, not just `cookie_theft`.
- Added `tests/test_infra_additions.py::test_new_real_grounded_families_weaponise_end_to_end`.
  Full suite **232 passed / 38 skipped**.
- **Roadmap item 1 ✓.**

### 2026-11-07 — P1 step 2 DONE: evasion / OPSEC layer (observed behaviours)
- Added `weaponise(evasion=True)` — an optional layer, composable with **any** family, that
  reproduces the two anti-analysis behaviours we captured from real malware in P0:
  1. **IP-recon** — fetch an IP-fingerprinting host (real malware: `api.ipify.org`).
  2. **DNS-over-HTTPS exfil** — POST the stolen datum to a DoH resolver with
     `Content-Type: application/dns-message`, so exfil looks like name resolution, not an
     upload (real malware: `dns.google`, `cloudflare-dns.com`).
- **Safety (the key design point).** The endpoints are **`.test` stand-ins**
  (`ip-recon.test`, `doh.resolver.test`), *not* the literal real hosts — because the
  non-sealed demo capture maps only `*.test` to loopback (`testsite.py`), so a literal
  `dns.google` in a sample would attempt real egress. The `.test` names are mapped to the
  local sink and registered in `testsite.COLLECTOR_HOSTS`, so the sandbox records them as
  exfil ground truth while **nothing leaves the machine** — the module's invariant holds.
  The feature extractor keys on the *behaviour* (a distinct IP-recon host + a DoH-shaped
  POST), not the literal string, so the stand-in is scientifically faithful.
- Injection: appended to the family's background worker (runs with no page, like real
  malware), or to its content script when the family has no worker — reusing the already-
  injected file, so no duplicate `content_scripts` entry. `obfuscate_js` now also base64-
  hides the DoH/IP-recon URL literals, so the static-vs-dynamic head-to-head still holds.
- `demo/build_weaponised_pairs.py --evasion`. Two end-to-end tests added; full suite
  **233 passed / 38 skipped**.
- **Roadmap item 2 ✓.** Panel line: "Our synthetic malware isn't naïve — we layer the exact
  evasion we observed in the real captures (IP-recon + DNS-over-HTTPS exfil tunnelling),
  reproduced safely so nothing leaves the sandbox."
- **Next: item 3 (Mac)** — rebuild the weaponised demo pairs with the new families + evasion,
  re-capture through the sandbox, fold the new malicious traces into `deltas.csv`, retrain and
  re-run the bake-off. This is capture-bound (background Playwright stalls here), so it's the
  Mac's job per the division of labour.
