# extdrift — Mac capture job: new malicious families + evasion (for Suhani)

Hi Suhani — this is one self-contained job for the Mac. You don't need the ML details, just run
the commands in order. Everything else (the code) you already get from the GitHub repo.

**What you're doing in one line:** Bind added two new malicious behaviours (`history_exfil`,
`ad_affiliate`) and an "evasion" layer. Your Mac turns real extensions into these malicious
versions, captures what they *do* in the sealed browser, folds the results into the training
table, and you push that table + the new capture folders.

**It's all sealed and offline-safe:** no captured extension can reach the internet — the sandbox
blackholes every outbound request and logs it as evidence. Don't change any proxy/sandbox setting.

**It's resumable:** any capture step can be stopped (Ctrl-C, closed lid, power loss) and resumed
by re-running the same command — it skips what's already done.

---

## 0. One-time setup (skip if you already ran the earlier capture job)

In **VS Code → Terminal → New Terminal**:

```bash
cd ~/Documents
git clone https://github.com/bindpratapsingh/extdrift.git     # only if you don't have it yet
cd extdrift
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
brew install --cask firefox            # the capture engine drives Firefox
```

In VS Code pick the interpreter: **Cmd+Shift+P → "Python: Select Interpreter" → the `.venv` one**.

---

## 1. Get the latest code (REQUIRED — don't skip)

The new families and the `--families` / `--evasion` options only exist in Bind's latest commit.
Skip this and the commands below will error.

```bash
cd ~/Documents/extdrift
git checkout main
git pull origin main
source .venv/bin/activate
pip install -r requirements.txt
```

Sanity check — should print all 5 families including the new two:

```bash
python -c "from engine.weaponiser.payloads import PAYLOADS; print(sorted(PAYLOADS))"
# expect: ['ad_affiliate', 'cookie_theft', 'credential_theft', 'history_exfil', 'sw_beacon']
```

---

## 2. Make sure real extensions are on disk

The capture reads real extension pairs from `data/real/amo/pairs.json` (not in git, so a fresh
clone won't have them). This crawls the Firefox store and downloads 30 of them:

```bash
python -m engine.collector.amo top -n 30 --pairs 1
```

(If you ran the earlier scaling job and `data/real/amo/pairs.json` already exists, you can skip
this — re-running is harmless, it skips what's already downloaded.)

---

## 3. Capture — a quick test, then the full run

**Confidence pass first (~20–40 min).** Run on 5 extensions to make sure it works on your Mac
before committing hours:

```bash
python -m experiments.capture_weaponised_behavioural --exts 5 --families history_exfil ad_affiliate
```

You should see lines like `… history_exfil: captured (collector leak events: 7)`. A non-zero
leak-event count means the sealed sandbox caught the malware's exfil — that's the evidence we
want. If you see that, you're good.

**Full run — two commands, one after the other** (the second won't start until the first ends):

```bash
# (A) the two new families, plain
python -m experiments.capture_weaponised_behavioural --exts 30 --families history_exfil ad_affiliate

# (B) the evasion layer (IP-recon + DNS-over-HTTPS exfil) on top of three families
python -m experiments.capture_weaponised_behavioural --exts 30 --families history_exfil ad_affiliate cookie_theft --evasion
```

Command (B) writes **separate** folders ending in `_evasion`, so it never overwrites (A).

### How long it takes

- Per extension: one baseline run + one run per family. Small extensions take seconds; big
  ad-blockers take 2–4 minutes (that's normal).
- Rough estimate for 30 extensions: **(A) ≈ 1.5–2.5 h**, **(B) ≈ 2–3 h** — so set aside an
  afternoon or run it overnight. It's resumable, so you can stop and continue any time.
- Want it faster? Use `--exts 15` on both (about half the time). 15–30 extensions is plenty.
- To watch a capture happen, add `--show` to see the Firefox window.

---

## 4. Fold the captures in and confirm it trained

```bash
# rebuild the training table from synthetic + ALL captured traces (yours now included)
python -m engine.batch --extensions 250 --updates 4 --captured data/dataset/captured --out data/dataset/deltas.csv

# retrain + print the model table (this regenerates the model locally — you do NOT push it)
python -m engine.ml.bakeoff data/dataset/deltas.csv
```

**What "good" looks like:** `engine.batch` prints a higher total row count than before (your new
malicious rows added), and `engine.ml.bakeoff` prints its 6-model table without errors and picks
a winner. You don't need to read the numbers — Bind does — it just has to run clean.

---

## 5. Push your results (branch `mac-captures`)

You push **exactly two things**: the updated training table and the new capture folders.

```bash
git checkout -b mac-captures            # first time; next time just: git checkout mac-captures
git add data/dataset/deltas.csv data/dataset/captured/amo_*
git status                              # CONFIRM: only deltas.csv + amo_* folders are staged
git commit -m "Mac: captured history_exfil + ad_affiliate families and the evasion layer"
git push -u origin mac-captures
```

Then message Bind: **"mac-captures pushed — new families + evasion captured, ready to merge."**
He merges `mac-captures` into `main` (new files, so it merges cleanly) and re-runs the evaluation.

**Don't commit anything else.** Never `git add` under `data/real/` (downloaded third-party
extension code — must not be redistributed) or `out/` (scratch). They're already git-ignored, so a
plain `git add data/dataset/...` won't touch them — just don't force-add them. And don't push the
model file `engine/ml/models/winner.joblib` — it's git-ignored on purpose; Bind regenerates it
from your data.

---

## 6. If something goes wrong

| Symptom | Fix |
|---|---|
| `unrecognized arguments: --families` / `--evasion` | You didn't pull the latest code. Redo **§1**. |
| `ModuleNotFoundError` | You forgot `source .venv/bin/activate`, or `pip install -r requirements.txt` didn't finish. |
| `No AMO pairs on disk` | Run **§2** first. |
| "Firefox not found" | `brew install --cask firefox`; confirm `/Applications/Firefox.app` exists. |
| A capture hangs on one extension | Ctrl-C, re-run the same command — it skips the done ones. Big ad-blockers are just slow. |
| `collector leak events: 0` on everything | Tell Bind before pushing — the payload may not have fired (expected on a few, a bug if all). |
| `git add` is pulling in huge files under `data/real/` | Don't. Only `data/dataset/deltas.csv` and `data/dataset/captured/amo_*`. |

---

## 7. Copy-paste cheat-sheet

```bash
cd ~/Documents/extdrift && git checkout main && git pull origin main && source .venv/bin/activate
python -m engine.collector.amo top -n 30 --pairs 1
python -m experiments.capture_weaponised_behavioural --exts 5  --families history_exfil ad_affiliate      # test pass
python -m experiments.capture_weaponised_behavioural --exts 30 --families history_exfil ad_affiliate      # (A)
python -m experiments.capture_weaponised_behavioural --exts 30 --families history_exfil ad_affiliate cookie_theft --evasion   # (B)
python -m engine.batch --extensions 250 --updates 4 --captured data/dataset/captured --out data/dataset/deltas.csv
python -m engine.ml.bakeoff data/dataset/deltas.csv
git checkout -b mac-captures
git add data/dataset/deltas.csv data/dataset/captured/amo_*
git commit -m "Mac: captured history_exfil + ad_affiliate families and the evasion layer"
git push -u origin mac-captures
```

Questions the code can't answer: the full write-up is `docs/PROJECT_REPORT.md`, live status is
`docs/STATUS.md`. — Bind
