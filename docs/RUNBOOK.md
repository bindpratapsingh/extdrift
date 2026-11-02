# Runbook — how to run everything (local)

Practical command reference for the team. Every command is run from the repo root. Heavy
browser capture wants the MacBook; the analysis/ML half runs anywhere.

## 0. Setup (once)
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Mac/Linux: source .venv/bin/activate
pip install -r requirements.txt          # playwright + scikit-learn + xgboost + pandas + joblib
playwright install chromium              # only needed for live capture
python -m pytest tests/ -q               # ~107 tests OK (1 live-capture test skips without Chromium)
```

## 1. The offline demo (no browser) — three verdicts from fixtures
```bash
python scripts/demo_offline.py
```

## 2. Live capture — the real pipeline on a running extension
```bash
# malicious update -> MALICIOUS, collector confirms the leak; benign -> BENIGN
python scripts/demo.py
# a single pair, with the triple score (rules + ML if a model is present):
python -m engine.cli run-pair data/corpus/readerlite/1.0.0 data/corpus/readerlite/1.1.0 --out-dir out/rl
```

## 2b. Firefox engine — REAL behavioural data from AMO .xpi pairs (Windows OK)
```bash
pip install selenium && winget install Mozilla.Firefox   # geckodriver auto-fetched by Selenium
python -m experiments.firefox_spike                      # feasibility probe (one extension)
# real BENIGN behavioural rows from the AMO pairs the collector downloaded:
python -m experiments.capture_amo_behavioural            # --limit N for a subset
# real MALICIOUS rows: real extension + real payload, captured (sealed egress):
python -m experiments.capture_weaponised_behavioural --exts 3
# both land in data/dataset/captured/<name>/{v1,v2}.trace.json (+ label.json)
```

## 3. Build the dataset (synthetic; add --captured to fold in real pairs)
```bash
python -m engine.batch --extensions 250 --updates 4 --seed 1234 --out data/dataset/deltas.csv
# fold in the real captured pairs (synthetic + Chromium + Firefox, one schema):
python -m engine.batch --captured data/dataset/captured --out data/dataset/deltas.csv
```

## 4. Train + evaluate the model
```bash
python -m engine.ml.bakeoff  data/dataset/deltas.csv    # rules vs LogReg/RF/XGBoost/SVM; saves winner
python -m engine.ml.anomaly  data/dataset/deltas.csv    # leave-one-family-out, unseen-threat test
```

## 5. Proof + rigour experiments
```bash
python -m experiments.headtohead          # (Chromium) static misses obfuscated payload; dynamic catches it
python -m experiments.ablation            # (Chromium) determinism removes web-noise false positives
python -m experiments.feature_ablation    # leave-one-group-out: which feature groups earn their place
python -m experiments.learning_curve      # PR-AUC vs dataset size (synthetic plateaus -> need real data)
python -m experiments.real_static_dataset # static-code deltas on REAL AMO code (+ weaponised)
python -m experiments.ast_diff_baseline   # AST/token churn baseline vs semantic static features
python -m engine.ml.bakeoff data/dataset/deltas.csv --smote   # class-imbalance ablation
```

## 6. Generate synthetic malicious extensions (weaponiser)
```python
from engine.weaponiser import weaponise
weaponise("data/corpus/readerlite/1.0.0", "out/mal",     family="cookie_theft")               # clean
weaponise("data/corpus/readerlite/1.0.0", "out/mal_obf", family="cookie_theft", obfuscated=True)
```

## 7. Collect real version pairs
```python
# snapshot installed extensions off disk (run weekly to catch real auto-updates)
from engine.collector import snapshot_installed, list_installed
list_installed()                                  # what's installed + versions
snapshot_installed("data/snapshots/2026-09-12")   # copy current versions
# or download two GitHub tags (needs network):
from engine.collector.download import github_tag_pair
github_tag_pair("gorhill/uBlock", "1.55.0", "1.56.0", "out/ublock")
```
```bash
# Firefox AMO: full version history + direct .xpi (gold-standard real benign pairs)
python -m engine.collector.amo slugs -n 20           # crawl top extensions by install base
python -m engine.collector.amo top -n 20 --pairs 1   # download + merge real pairs -> pairs.json
python -m engine.collector.amo pull darkreader --pairs 2
# Chrome Web Store: current version only (no public history) — official update endpoint
python -m engine.collector.chrome probe <ext_id>     # is it still listed?
python -m engine.collector.chrome get <ext_id>       # download + unpack the current CRX
python -m engine.collector.chrome history <ext_id>   # best-effort crx4chrome historical (fragile)
python -m experiments.chrome_delisting_probe --sample 120   # % of malicious IDs still live (~40%)
# extensiondeltas corpus (You've Changed, CCS'20) — ~90 MB, one-step download
python -m engine.collector.extensiondeltas download   # apiCategories + clusters + anomalies
python -m engine.collector.extensiondeltas apis       # the discriminative API tokens we adopted
python -m engine.collector.extensiondeltas sample -n 50   # store-description text (for NLP)
```

## Other CLI commands
```bash
python -m engine.cli diff <v1.trace.json> <v2.trace.json>   # score two existing traces
python -m engine.cli rules                                   # print the heuristic catalogue
python -m engine.cli manifest-diff <v1dir> <v2dir>           # static permission diff
python -m engine.cli unpack <ext.crx> out/                   # unpack a .crx/.xpi
```

## Where things land
- `data/dataset/deltas.csv` — the ML dataset (gitignored)
- `engine/ml/models/winner.joblib` + `metrics.json` — the trained model (gitignored)
- `out/**/report.txt` + `report.json` — per-run reports
- `out/headtohead/result.json`, `out/ablation/result.json` — experiment outputs
