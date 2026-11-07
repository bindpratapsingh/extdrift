# Mac Step 3 — Capture the new malicious families + evasion (for Suhani)

**Who this is for:** Suhani, on the Mac, in VS Code. You do **not** need the ML details — just run
the commands in order. If something about setup is unclear, the fuller guide is
[`docs/MAC_RUNBOOK.md`](MAC_RUNBOOK.md); this file is only the new weaponiser job.

**What you're doing in one line:** Bind added two new malicious behaviours (`history_exfil`,
`ad_affiliate`) and an "evasion" layer. Your Mac turns real extensions into these malicious
versions, captures what they *do* in the sealed browser, folds the results into the training
table, and you push that table + the new capture folders. The i3 laptop can't run the browser
captures reliably — that's why it's your Mac.

**Everything is sealed and offline-safe:** no captured extension can reach the internet; the
sandbox blackholes all egress and logs it as evidence. Don't change any proxy/sandbox setting.

---

## 0. One-time setup (skip if you already did the earlier capture job)

Open **VS Code → Terminal → New Terminal**:

```bash
cd ~/Documents
git clone https://github.com/bindpratapsingh/extdrift.git   # only if you don't have it yet
cd extdrift
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
brew install --cask firefox          # the capture engine drives Firefox
```

Pick the `.venv` interpreter in VS Code: **Cmd+Shift+P → "Python: Select Interpreter" → the
`.venv` one**.

---

## 1. Get Bind's latest code (REQUIRED — do not skip)

The new families and the `--families` / `--evasion` options only exist in Bind's latest commit.
If you skip this, the commands below will error.

```bash
cd ~/Documents/extdrift
git checkout main
git pull origin main
source .venv/bin/activate
pip install -r requirements.txt        # in case anything changed
```

Quick sanity check that you have the new code (should print all 5 families incl. the new two):

```bash
python -c "from engine.weaponiser.payloads import PAYLOADS; print(sorted(PAYLOADS))"
# expect: ['ad_affiliate', 'cookie_theft', 'credential_theft', 'history_exfil', 'sw_beacon']
```

---

## 2. Make sure real extensions are on disk

The capture reads real extension pairs from `data/real/amo/pairs.json` (git-ignored, so a fresh
clone won't have them). This crawls the Firefox store and downloads them. Start with 30.

```bash
python -m engine.collector.amo top -n 30 --pairs 1
```

If you already ran the earlier scaling job and `data/real/amo/pairs.json` exists, you can skip
this — but re-running it is harmless (it skips what's already downloaded).

---

## 3. The job — capture the new families, then the evasion variants

**Confidence pass first (≈20–40 min).** Run on 5 extensions to confirm it works on your machine
before committing hours:

```bash
python -m experiments.capture_weaponised_behavioural --exts 5 --families history_exfil ad_affiliate
```

You should see lines like `… history_exfil: captured (collector leak events: 7)`. A non-zero
leak-event count means the sealed sandbox caught the malware's exfil — that's the evidence we
want. If you see that, you're good; continue.

**Full run — two commands.** Run these one after the other (the second won't start until the
first finishes). Each is **resumable**: if you Ctrl-C, lose power, or close the lid, just run the
same command again — it prints `already captured, skipping` and continues.

```bash
# (A) the two new families, plain
python -m experiments.capture_weaponised_behavioural --exts 30 --families history_exfil ad_affiliate

# (B) the evasion layer (IP-recon + DNS-over-HTTPS exfil) on top of three families
python -m experiments.capture_weaponised_behavioural --exts 30 --families history_exfil ad_affiliate cookie_theft --evasion
```

Command (B) writes **separate** folders ending in `_evasion`, so it never overwrites (A).

### How long it takes

- Per extension, the tool captures one baseline + one run per family. Small extensions take
  seconds; big ad-blockers take 2–4 minutes (normal).
- Rough estimates: **(A) ≈ 1.5–2.5 h**, **(B) ≈ 2–3 h** for 30 extensions — so set aside an
  afternoon, or run it overnight. Because it's resumable you can stop and resume any time.
- Want a smaller, faster deliverable? Use `--exts 15` on both (≈ half the time). More extensions
  = more training rows = a stronger result, but 15–30 is plenty for this step.
- Watch a capture happen (optional): add `--show` to see the Firefox window.

---

## 4. Fold the captures into the training table and check it trained

```bash
# rebuild the training table from synthetic + ALL captured traces (yours now included)
python -m engine.batch --extensions 250 --updates 4 --captured data/dataset/captured --out data/dataset/deltas.csv

# retrain + print the model table (this REGENERATES the model locally — you do NOT push it)
python -m engine.ml.bakeoff data/dataset/deltas.csv

# sanity: real-data behaviour eval
python -m experiments.real_behavioural_eval
```

**What "good" looks like:** `engine.batch` prints a higher total row count than before (your new
malicious rows added), and `engine.ml.bakeoff` prints its 6-model table without errors and picks
a winner. You don't need to interpret the numbers — Bind does — you just need it to run clean.

---

## 5. Push your results (branch `mac-captures`)

You push **exactly two things**: the updated training table and the new capture folders. Nothing
else. (The trained model `engine/ml/models/winner.joblib` is git-ignored on purpose — Bind
regenerates it from your data, so don't try to add it. Never add anything under `data/real/` —
that's downloaded third-party code and must not be redistributed; it's already git-ignored.)

```bash
git checkout -b mac-captures            # first time only; later just: git checkout mac-captures
git add data/dataset/deltas.csv data/dataset/captured/amo_*
git status                              # CONFIRM: only deltas.csv + amo_* folders are staged
git commit -m "Mac: captured history_exfil + ad_affiliate families and the evasion layer"
git push -u origin mac-captures
```

Then message Bind: **"mac-captures pushed — new families + evasion captured, ready to merge."**
He merges `mac-captures` into `main` (they're new files, so it merges cleanly) and re-runs the
evaluation.

**If `git push` is rejected (you're not a collaborator yet):** ask Bind to add you (GitHub → repo
→ Settings → Collaborators). Fallback if that's not possible right now — zip and send:

```bash
zip -r mac-captures.zip data/dataset/deltas.csv data/dataset/captured/amo_*
```

and send `mac-captures.zip` to Bind; he unzips it into the repo at the same paths and commits.

---

## 6. If something goes wrong

| Symptom | Fix |
|---|---|
| `error: unrecognized arguments: --families` / `--evasion` | You didn't pull Bind's latest code. Redo **§1**. |
| `ModuleNotFoundError` | You forgot `source .venv/bin/activate`, or `pip install -r requirements.txt` didn't finish. |
| `No AMO pairs on disk` | Run **§2** first (`engine.collector.amo top -n 30 --pairs 1`). |
| "Firefox not found" | `brew install --cask firefox`; confirm `/Applications/Firefox.app` exists. |
| A capture hangs on one extension | Ctrl-C, re-run the same command — it skips the done ones. Big ad-blockers are just slow. |
| `collector leak events: 0` on everything | Tell Bind before pushing — it may mean the payload didn't fire on those extensions (expected for some, a bug if all). |
| `git add` is pulling in huge files under `data/real/` | Don't. Only `data/dataset/deltas.csv` and `data/dataset/captured/amo_*`. |

---

## 7. The exact command cheat-sheet (copy-paste)

```bash
cd ~/Documents/extdrift && git checkout main && git pull origin main && source .venv/bin/activate
python -m engine.collector.amo top -n 30 --pairs 1
python -m experiments.capture_weaponised_behavioural --exts 5  --families history_exfil ad_affiliate      # confidence pass
python -m experiments.capture_weaponised_behavioural --exts 30 --families history_exfil ad_affiliate      # (A)
python -m experiments.capture_weaponised_behavioural --exts 30 --families history_exfil ad_affiliate cookie_theft --evasion   # (B)
python -m engine.batch --extensions 250 --updates 4 --captured data/dataset/captured --out data/dataset/deltas.csv
python -m engine.ml.bakeoff data/dataset/deltas.csv
git checkout -b mac-captures
git add data/dataset/deltas.csv data/dataset/captured/amo_*
git commit -m "Mac: captured history_exfil + ad_affiliate families and the evasion layer"
git push -u origin mac-captures
```
