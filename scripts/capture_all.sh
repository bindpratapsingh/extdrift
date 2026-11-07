#!/usr/bin/env bash
# capture_all.sh — full, chunked, RESUMABLE real-data capture for the Mac.
#
# Captures, for the top-N real Firefox extensions:
#   * real BENIGN update pairs                  (experiments.capture_amo_behavioural)
#   * real MALICIOUS, 4 families                (experiments.capture_weaponised_behavioural)
#       history_exfil, ad_affiliate, cookie_theft, credential_theft
#   * real MALICIOUS + EVASION layer, 3 families (… --evasion: IP-recon + DoH exfil)
# then rebuilds the training table and retrains.
#
# It works in CHUNKS of CHUNK extensions and rebuilds data/dataset/deltas.csv after each chunk,
# so progress is checkpointed. Every capture step is resumable: if you Ctrl-C, lose power, or
# close the lid, just run the SAME command again — it skips everything already done (fast) and
# continues from where it stopped.
#
# Usage:   bash scripts/capture_all.sh [N] [CHUNK]
#            N     = total extensions to capture   (default 100)
#            CHUNK = extensions advanced per step   (default 10)
#
# Safe: everything runs in the sealed offline sandbox; no captured extension can reach the
# internet. It never commits — it prints the git commands at the end.

set -uo pipefail
N="${1:-100}"
CHUNK="${2:-10}"
cd "$(dirname "$0")/.." || exit 1
export PYTHONWARNINGS=ignore

# Families chosen because each has a content-script component, so it runs even on an MV2
# extension whose background we deliberately preserve. (sw_beacon is SW-only — left out.)
PLAIN_FAMILIES="history_exfil ad_affiliate cookie_theft credential_theft"
EVASION_FAMILIES="history_exfil ad_affiliate cookie_theft"

echo "=================================================================="
echo " extdrift full capture  |  N=$N  chunk=$CHUNK  |  $(date)"
echo "=================================================================="

echo; echo "== Crawl top $N AMO extensions (resumable; skips already-downloaded) =="
python -m engine.collector.amo top -n "$N" --pairs 1

rebuild() {
  python -m engine.batch --extensions 250 --updates 4 \
      --captured data/dataset/captured --out data/dataset/deltas.csv
}

k="$CHUNK"
while : ; do
  step="$k"; [ "$step" -gt "$N" ] && step="$N"
  echo
  echo "============ chunk: first $step of $N extensions   ($(date +%H:%M)) ============"

  echo "-- [1/3] benign real updates --"
  python -m experiments.capture_amo_behavioural --limit "$step"

  echo "-- [2/3] malicious, plain families --"
  python -m experiments.capture_weaponised_behavioural --exts "$step" --families $PLAIN_FAMILIES

  echo "-- [3/3] malicious, evasion layer --"
  python -m experiments.capture_weaponised_behavioural --exts "$step" --families $EVASION_FAMILIES --evasion

  echo "-- checkpoint: rebuild dataset so this chunk's progress is saved --"
  rebuild
  echo "   [checkpoint] dataset rebuilt through extension $step/$N"

  [ "$step" -ge "$N" ] && break
  k=$(( k + CHUNK ))
done

echo; echo "== Train + show the model table (regenerates the model locally; do NOT push it) =="
python -m engine.ml.bakeoff data/dataset/deltas.csv

echo
echo "=================================================================="
echo " DONE — captured up to $N extensions. To send the results back:"
echo
echo "   git checkout -b mac-captures      # first time only"
echo "   git add data/dataset/deltas.csv data/dataset/captured/amo_*"
echo "   git commit -m 'Mac: scaled real dataset to top-$N (benign + new families + evasion)'"
echo "   git push -u origin mac-captures"
echo
echo " Do NOT git add anything under data/real/ or out/ (third-party code / scratch)."
echo "=================================================================="
