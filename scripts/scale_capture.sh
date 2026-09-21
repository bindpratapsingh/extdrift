#!/usr/bin/env bash
# scale_capture.sh — one-command real-data scale-up (for Suhani's Mac).
#
# Crawls the top-N Firefox extensions, captures each as a real benign update AND weaponised
# (malicious), rebuilds the dataset, and evaluates. Every capture step is RESUMABLE: stop it
# (Ctrl-C) and re-run and it skips whatever is already done. See docs/MAC_RUNBOOK.md.
#
# Usage:   bash scripts/scale_capture.sh [N]     # N = how many top extensions (default 50)
#
# It never deletes anything and never commits; when it finishes it prints the git commands.

set -uo pipefail
N="${1:-50}"
cd "$(dirname "$0")/.." || exit 1
export PYTHONWARNINGS=ignore

echo "=================================================================="
echo " extdrift real-data scale-up  |  top-$N extensions  |  $(date)"
echo "=================================================================="

echo; echo "== [1/5] Crawl top $N AMO extensions and download real update pairs =="
python -m engine.collector.amo top -n "$N" --pairs 1

echo; echo "== [2/5] Capture real BENIGN updates (resumable; Firefox) =="
python -m experiments.capture_amo_behavioural --limit "$N"

echo; echo "== [3/5] Capture real WEAPONISED (malicious) updates (resumable; Firefox) =="
python -m experiments.capture_weaponised_behavioural --exts "$N"

echo; echo "== [4/5] Rebuild the dataset (synthetic + all captured, one schema) =="
python -m engine.batch --extensions 250 --updates 4 --captured data/dataset/captured

echo; echo "== [5/5] Evaluate =="
python -m engine.ml.bakeoff data/dataset/deltas.csv
python -m experiments.real_behavioural_eval

echo
echo "=================================================================="
echo " DONE. To send the results back to the shared repo, run:"
echo
echo "   git checkout -b mac-captures    # first time only"
echo "   git add data/dataset/deltas.csv data/dataset/captured/amo_*"
echo "   git commit -m 'Mac: scaled real captures to top-$N extensions'"
echo "   git push -u origin mac-captures"
echo
echo " Do NOT 'git add' anything under data/real/ or out/ (third-party code / scratch)."
echo "=================================================================="
