# extdrift — Mac capture job: scale the real dataset (for Suhani)

Hi Suhani — this is one job for the Mac: grow our **real** dataset to ~100 extensions, capturing
both the benign and the new malicious behaviours. You don't need the ML details — run one command
and let it work. The code you already get from the GitHub repo.

**What it does:** for the top-100 real Firefox extensions, your Mac captures what each one *does*
in a sealed browser — the real **benign** update, and the real **malicious** versions (4 attack
families + an evasion layer) — then folds it all into the training table.

**It's all sealed and offline-safe:** no captured extension can reach the internet; the sandbox
blackholes every outbound request and logs it as evidence. Don't change any proxy/sandbox setting.

**It runs in chunks and resumes.** The script works 10 extensions at a time and saves progress
after each chunk. If it stops for any reason — Ctrl-C, closed lid, power loss, an error — just run
**the same command again**: it skips everything already done (fast) and continues where it left
off. You'll do this over several sittings; that's expected.

---

## 0. One-time setup (skip if you already ran a capture job)

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

The script and the new families only exist in Bind's latest commit.

```bash
cd ~/Documents/extdrift
git checkout main
git pull origin main
source .venv/bin/activate
pip install -r requirements.txt
```

Sanity check — should print 5 families including the new two:

```bash
python -c "from engine.weaponiser.payloads import PAYLOADS; print(sorted(PAYLOADS))"
# expect: ['ad_affiliate', 'cookie_theft', 'credential_theft', 'history_exfil', 'sw_beacon']
```

---

## 2. Run it

**Confidence pass first (~45–60 min).** Do the first 5 extensions fully, to confirm it all works
on your Mac before the long run:

```bash
bash scripts/capture_all.sh 5 5
```

Watch for lines like `… history_exfil: captured (collector leak events: 7)`. A non-zero
leak-event count means the sealed sandbox caught the malware's exfil — that's the evidence we
want. If the run finishes and prints a model table at the end, you're good.

**The full job — 100 extensions, in chunks of 10:**

```bash
bash scripts/capture_all.sh 100 10
```

That's the whole thing: crawl → benign capture → malicious capture (4 families) → malicious +
evasion (3 families) → rebuild dataset → retrain. It checkpoints after every 10 extensions.

### How long it takes

- Each extension is captured several times (one baseline + benign + each family). Small
  extensions take seconds; big ad-blockers take 2–4 minutes (normal).
- **Budget ~15–20 hours of capture total for 100** — but you do it in sittings. Run it, let it go
  for a few hours, Ctrl-C when you need the machine, and re-run `bash scripts/capture_all.sh 100 10`
  later to continue. Nothing is lost or redone.
- Want fewer/more: the first number is the target. `bash scripts/capture_all.sh 50 10` for 50,
  `… 150 10` for 150. 100 is the goal we agreed on.
- To watch a capture happen, you can run a single step with `--show` (see §5), but the bundled
  script runs headless (faster).

---

## 3. When it finishes

The script ends by printing a model table and the exact git commands. You don't need to read the
numbers — Bind does — it just has to finish without errors. If it printed the table, the dataset
trained cleanly with your new data in it.

---

## 4. Push your results (branch `mac-captures`)

You push **exactly two things**: the updated training table and the new capture folders.

```bash
git checkout -b mac-captures            # first time; next time just: git checkout mac-captures
git add data/dataset/deltas.csv data/dataset/captured/amo_*
git status                              # CONFIRM: only deltas.csv + amo_* folders are staged
git commit -m "Mac: scaled real dataset to top-100 (benign + new families + evasion)"
git push -u origin mac-captures
```

Then message Bind: **"mac-captures pushed."** He merges it into `main` and re-runs the evaluation.

You can push a partial result any time (e.g. after 40 extensions) and push again later — just
re-commit `deltas.csv` + the new `amo_*` folders. Pushing progress as you go is encouraged.

**Don't commit anything else.** Never `git add` under `data/real/` (downloaded third-party
extension code — must not be redistributed) or `out/` (scratch); they're git-ignored already. And
don't push the model file `engine/ml/models/winner.joblib` — it's git-ignored on purpose; Bind
regenerates it from your data.

---

## 5. If something goes wrong

| Symptom | Fix |
|---|---|
| `No such file … scripts/capture_all.sh` or the families check fails | You didn't pull the latest code. Redo **§1**. |
| `ModuleNotFoundError` | You forgot `source .venv/bin/activate`, or `pip install -r requirements.txt` didn't finish. |
| "Firefox not found" | `brew install --cask firefox`; confirm `/Applications/Firefox.app` exists. |
| It stopped / you closed the lid | Just re-run `bash scripts/capture_all.sh 100 10` — it resumes. |
| One extension hangs forever | Ctrl-C, re-run the same command — it skips the done ones and moves past it. Big ad-blockers are just slow. |
| `collector leak events: 0` on **everything** | Tell Bind before pushing — the payloads may not have fired (expected on a few, a bug if all). |
| `git add` is pulling in huge files under `data/real/` | Don't. Only `data/dataset/deltas.csv` and `data/dataset/captured/amo_*`. |
| Want to run just one step with a visible browser | e.g. `python -m experiments.capture_weaponised_behavioural --exts 3 --families history_exfil --show` |

---

## 6. One-line cheat-sheet

```bash
cd ~/Documents/extdrift && git checkout main && git pull origin main && source .venv/bin/activate
bash scripts/capture_all.sh 5 5        # confidence pass (~45-60 min)
bash scripts/capture_all.sh 100 10     # the full job, in chunks (resumable — re-run to continue)
git checkout -b mac-captures
git add data/dataset/deltas.csv data/dataset/captured/amo_*
git commit -m "Mac: scaled real dataset to top-100 (benign + new families + evasion)"
git push -u origin mac-captures
```

Questions the code can't answer: `docs/PROJECT_REPORT.md` is the full write-up, `docs/STATUS.md`
is the live status. — Bind
