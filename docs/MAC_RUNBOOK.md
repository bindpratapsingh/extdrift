# extdrift — Mac Runbook (for Suhani)

**Who this is for:** Suhani, running the compute-heavy part of extdrift on the Mac, using VS Code.
**Goal:** grow the *real* dataset from 15 extensions to 100+ by capturing real Firefox extensions,
then push the results so Bind can merge and re-evaluate on either machine. You do **not** need to
understand the ML internals to do this — just follow the steps. If you want the full picture of the
project, read `docs/PROJECT_REPORT.md` (it's in the repo).

**Your job in one line:** run one script, let it capture extensions for a few hours (it is
resumable — you can stop and restart any time), then push the generated data files.

---

## 0. What you are producing and where it goes (the big picture)

- You run browser captures on the Mac. Each real extension becomes JSON *trace* files under
  `data/dataset/captured/amo_<name>/` (benign) and `data/dataset/captured/amo_<name>_mal_<family>/`
  (malicious). These are **our own measurements** (safe to commit; they contain no third-party
  source code).
- The captures are then folded into the training table `data/dataset/deltas.csv`.
- You **push exactly two things**: `data/dataset/deltas.csv` and the new
  `data/dataset/captured/amo_*` folders. Nothing else.
- **Never commit** anything under `data/real/` (downloaded third-party extension code — legally must
  not be redistributed) or `out/` (scratch). These are already git-ignored, so normal `git add`
  won't pick them up — just don't force-add them.

```
Mac:  crawl store -> download .xpi -> capture in sealed browser -> trace JSON -> deltas.csv -> git push
Bind: git pull -> already merged (they are new files) -> re-run bake-off / eval on laptop or Mac
```

---

## 1. One-time setup (about 15 minutes)

Open **VS Code → Terminal → New Terminal** and run these one block at a time.

**1a. Install the tools** (Homebrew is the Mac package manager; skip anything already installed):
```bash
# Homebrew (if you don't have it): https://brew.sh
brew install git python@3.11
brew install --cask firefox        # the browser the capture engine drives
brew install --cask visual-studio-code   # if not already installed
```

**1b. Get the code:**
```bash
cd ~/Documents
git clone https://github.com/bindpratapsingh/extdrift.git
cd extdrift
code .                              # opens the project in VS Code
```

**1c. Python environment + dependencies:**
```bash
python3.11 -m venv .venv
source .venv/bin/activate          # do this in every new terminal (prompt shows (.venv))
pip install --upgrade pip
pip install -r requirements.txt    # selenium, scikit-learn, xgboost, pandas, numpy, joblib, playwright
```
> In VS Code, pick this interpreter: **Cmd+Shift+P → "Python: Select Interpreter" → the `.venv` one**,
> so the integrated terminal and the Run button use it automatically.

**1d. Verify everything works before you start (takes ~2 minutes):**
```bash
python -m pytest tests/ -q         # expect ~111 passed, 1 skipped
python -m experiments.firefox_spike    # proves Firefox capture works on your Mac
```
The spike should end with `VERDICT: PASS`. If it does, you are ready. (Geckodriver — the Firefox
automation driver — is fetched automatically by Selenium; you do not install it yourself.)

---

## 2. The main job — scale the real dataset

**One command does everything** (crawl → capture benign → capture weaponised → rebuild → evaluate).
`N` is how many top extensions to process. Start with 30 to confirm it runs, then do 100.

```bash
source .venv/bin/activate          # if not already active
bash scripts/scale_capture.sh 30   # ~1.5-2 hours; then try: bash scripts/scale_capture.sh 100
```

**It is resumable.** If you close the laptop, lose power, or press Ctrl-C, just run the same command
again — it prints `already captured, skipping` for everything finished and continues where it left
off. Nothing is redone or lost.

When it finishes it prints a summary and the exact `git` commands to send results back (§4).

### If you prefer to run the steps yourself (or the script fails on one step)
Each line is independent and resumable; run them in order:
```bash
python -m engine.collector.amo top -n 100 --pairs 1          # 1. crawl + download real pairs
python -m experiments.capture_amo_behavioural --limit 100    # 2. capture benign updates (long)
python -m experiments.capture_weaponised_behavioural --exts 100   # 3. capture weaponised (long)
python -m engine.batch --extensions 250 --updates 4 --captured data/dataset/captured   # 4. rebuild dataset
python -m engine.ml.bakeoff data/dataset/deltas.csv          # 5. train + show the model table
python -m experiments.real_behavioural_eval                  # 6. synthetic->real transfer result
```

**What "good" looks like:** step 6 prints `Rules on real data: ... recall` and a `Synthetic -> real
transfer` line with a PR-AUC. More extensions = a more credible number. That is the deliverable.

### Where each command "lives" in the codebase (so you know what runs)
| Command | Source file it runs | What it does |
|---|---|---|
| `engine.collector.amo top` | `engine/collector/amo.py` | Crawls Firefox AMO by popularity, downloads each extension's two latest versions into `data/real/amo/` (git-ignored), writes `data/real/amo/pairs.json`. |
| `experiments.capture_amo_behavioural` | `experiments/capture_amo_behavioural.py` | Runs each real v1 and v2 in Firefox (via `engine/sandbox/firefox_capture.py`), writes benign trace pairs to `data/dataset/captured/amo_<slug>/`. |
| `experiments.capture_weaponised_behavioural` | `experiments/capture_weaponised_behavioural.py` | Injects a real payload (`engine/weaponiser/`) into each real extension and captures it → malicious trace pairs in `data/dataset/captured/amo_<slug>_mal_<family>/`. |
| `engine.batch` | `engine/batch.py` | Turns every trace pair into one row of `data/dataset/deltas.csv`. |
| `engine.ml.bakeoff` | `engine/ml/bakeoff.py` | Trains the 6-model bake-off and prints the results table. |
| `experiments.real_behavioural_eval` | `experiments/real_behavioural_eval.py` | Scores only the real rows + the synthetic→real transfer test. |

---

## 3. Rules to keep the data clean (important)

- **Only** these get committed: `data/dataset/deltas.csv` and `data/dataset/captured/amo_*/`.
- **Never** commit `data/real/**` (downloaded extension code — do not redistribute) or `out/**`
  (scratch/logs). They are git-ignored already; do not use `git add -f` on them.
- The capture scripts already delete the instrumented copies of extensions after each run, so no
  third-party source is left lying around. Don't disable that.
- Everything runs **locally and sealed** — no captured extension can send data to the internet
  (the sandbox blackholes all egress). This is by design; don't change the proxy/sandbox settings.

---

## 4. Sending your results back (git)

**Preferred: Bind adds you as a collaborator** (GitHub → repo → Settings → Collaborators → add
Suhani). Then push to a branch so nothing is overwritten:

```bash
git checkout -b mac-captures                       # first time only; later: git checkout mac-captures
git add data/dataset/deltas.csv data/dataset/captured/amo_*
git status                                         # confirm ONLY deltas.csv + amo_* folders are staged
git commit -m "Mac: scaled real captures to top-100 extensions"
git push -u origin mac-captures
```
Then tell Bind — he merges `mac-captures` into `main` (they are new files, so it merges cleanly).

**If you cannot push** (not a collaborator yet): either
- fork the repo on GitHub, `git remote add fork <your-fork-url>`, push to the fork, open a Pull
  Request; **or**
- the simplest fallback — zip the two things and send them to Bind:
  ```bash
  zip -r mac-captures.zip data/dataset/deltas.csv data/dataset/captured/amo_*
  ```
  Bind unzips into his copy of the repo (same paths) and commits. Because these are new files under
  `data/dataset/captured/`, there are no merge conflicts.

**Keep in sync before starting each session:** `git pull origin main` so you have the latest code.

---

## 5. How Bind merges and re-tests (on the laptop or Mac)

```bash
git pull origin main                 # or: git merge mac-captures
python -m engine.batch --extensions 250 --updates 4 --captured data/dataset/captured  # rebuild (if needed)
python -m engine.ml.bakeoff data/dataset/deltas.csv
python -m experiments.real_behavioural_eval
python -m experiments.statistical_rigor     # 95% confidence intervals on the numbers
python -m pytest tests/ -q                   # everything still green
```
Because the whole pipeline reads from `data/dataset/`, folding in more real captures needs no code
changes — just rebuild and re-evaluate. It runs on the i3/4GB laptop too (the ML is light); the Mac
is only needed for the *capture* volume.

---

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| `firefox_spike` fails / "Firefox not found" | Install Firefox: `brew install --cask firefox`. Confirm `/Applications/Firefox.app` exists. |
| `ModuleNotFoundError` | You forgot `source .venv/bin/activate`, or `pip install -r requirements.txt` didn't finish. |
| Selenium/geckodriver error | Update Selenium: `pip install -U selenium`. It fetches geckodriver automatically; you need internet the first time. |
| A capture hangs on one extension | Ctrl-C; re-run the same command — it skips the done ones and continues. Large ad-blockers are slow (2-4 min each); that's normal. |
| Runs out of disk | Downloaded `.xpi` files pile up in `data/real/amo/` (git-ignored). Safe to delete that folder any time; the captured traces you already made are kept. |
| `git add` wants to add huge files under `data/real/` | Don't. Only add `data/dataset/deltas.csv` and `data/dataset/captured/amo_*`. |
| Want to watch a capture visually | Add `--show` to a capture command to see the browser window. |

---

## 7. Optional / later — the Tier-2 graph model (heavy ML training)

This is the one part that is *actual model training* and benefits from the Mac's GPU. It is **not
built yet** — Bind will add the model + training script. When it exists, training runs on the Mac
(Apple-Silicon GPU via PyTorch MPS). Until then, your job is only §2 (scaling the real data), which
is what everything else depends on.

---

## 8. Quick command cheat-sheet

```bash
source .venv/bin/activate                     # start of every session
git pull origin main                          # get latest code
bash scripts/scale_capture.sh 100             # the whole job (resumable)
# ...or step by step: see §2...
git checkout -b mac-captures                  # first time
git add data/dataset/deltas.csv data/dataset/captured/amo_*
git commit -m "Mac: scaled real captures" && git push -u origin mac-captures
```

Questions Bind can't answer from the code: the full write-up is `docs/PROJECT_REPORT.md`, and the
live status of what's built vs remaining is `docs/STATUS.md`.
