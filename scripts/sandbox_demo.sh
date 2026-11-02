#!/usr/bin/env bash
# Show the Docker pipeline on the controlled samples: a harmless update, then a malicious one.
# Needs Docker and the images (python -m engine.cli sandbox-build). Takes a few minutes.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
samples=data/corpus/controlled
python -m engine.cli compare "$samples/pair_v1" "$samples/pair_v1_1_benign" --quiet --out-dir out/demo
python -m engine.cli compare "$samples/pair_v1" "$samples/pair_v2" --quiet --out-dir out/demo
