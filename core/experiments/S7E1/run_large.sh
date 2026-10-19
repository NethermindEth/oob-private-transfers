#!/bin/sh
# S7-E1 holder-configuration sweep.
# 9 (k,n,q) configurations x 2 seal modes (fragment_kzg; whole_epoch = baseline) x m_e in {1024, 4096, 16384} x 5 reps,
# recovery policies all + minimal + minimal_parity. One invocation per m_e so that each writes its own raw file and a
# failure in one does not lose the others. Each run waits for the 1-min load <= 8 before starting (--cooldown-load).
# Raw output: core/results/S7E1/large-m<m_e>/s7e1_raw.json.
set -eu
cd "$(dirname "$0")/../../.."
export PYTHONPATH="$PWD"
B="$PWD/scripts/benchlock"
PY=.venv/bin/python
CONFIGS=2,8,5:4,8,6:6,8,7:4,16,10:8,16,12:12,16,14:8,32,20:16,32,24:24,32,28
for M in 1024 4096 16384; do
  "$B" "$PY" -m core.experiments.S7E1.run_s7e1 --configs "$CONFIGS" --modes fragment_kzg,whole_epoch --m-e "$M" --reps 5 \
     --policies all,minimal,minimal_parity --cooldown-load 8 --label "S7E1 large sweep m_e=$M" --out "large-m$M"
done
