#!/bin/sh
# S7-E2 (Binius64 variant): admission proof cost matrix; one JSON row per line.
#   REPEAT=5 scripts/benchlock core/experiments/S7E2binius/matrix.sh
# Rows go to core/results/S7E2binius/<timestamp>/results.jsonl (and to stdout).
set -eu
cd "$(dirname "$0")/../../.."
B=${B:-core/binius/target/release/oob-bench}
REPEAT=${REPEAT:-3}
OUT=core/results/S7E2binius/$(date +%Y%m%dT%H%M%S)
mkdir -p "$OUT"
for threads in 10; do for rate in 1 2 4; do for node in full; do
  RAYON_NUM_THREADS=$threads "$B" --repeat "$REPEAT" --log-inv-rate $rate admission --node-hash $node
done; done; done | tee "$OUT/results.jsonl"
