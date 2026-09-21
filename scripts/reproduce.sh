#!/usr/bin/env bash
# reproduce.sh — reproduce every headline result from the committed data, in order.
#
# All of this runs offline on a laptop (no browser, no network): it uses the committed dataset
# (data/dataset/deltas.csv) and the committed real captured traces (data/dataset/captured/).
# The parts that need re-downloaded extension SOURCE or a browser are listed at the end and are
# skipped here (see docs/MAC_RUNBOOK.md to regenerate those).
#
# Usage:  bash scripts/reproduce.sh

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
export PYTHONWARNINGS=ignore

line() { printf '\n============================================================\n%s\n============================================================\n' "$1"; }

line "0. Tests (analysis + ML pipeline; browser tests skip)"
python -m pytest tests/ -q

line "1. Rebuild the dataset (synthetic seed 1234 + committed real captures)"
python -m engine.batch --extensions 250 --updates 4 --captured data/dataset/captured

line "2. Model bake-off (6 models, leakage-free CV + temporal split)"
python -m engine.ml.bakeoff data/dataset/deltas.csv

line "3. Statistical rigor (bootstrap 95% CIs + ML-vs-rules significance)"
python -m experiments.statistical_rigor

line "4. Locked held-out test + calibrated operating point"
python -m experiments.operating_point

line "5. Anomaly / novelty layer (leave-one-family-out + on real data)"
python -m engine.ml.anomaly --real

line "6. Real-data behavioural eval (synthetic -> real transfer)"
python -m experiments.real_behavioural_eval

line "7. Feature-group ablation"
python -m experiments.feature_ablation

line "8. Learning curve (PR-AUC vs dataset size)"
python -m experiments.learning_curve

line "DONE — headline results reproduced from committed data."
echo "Parts that need re-downloaded extension SOURCE or a browser (not run here):"
echo "  - experiments.youve_changed_headtohead   (needs data/real/amo source)"
echo "  - experiments.real_static_dataset         (needs data/real/amo source)"
echo "  - experiments.ast_diff_baseline           (needs data/real/amo source)"
echo "  - experiments.headtohead / ablation       (need a browser)"
echo "  - experiments.chrome_delisting_probe      (needs network)"
echo "  Regenerate the source with:  python -m engine.collector.amo top -n 20 --pairs 1"
