#!/bin/bash
# S7-E4 per-epoch sweep: m_e in {1024, 4096, 16384} x layout {default (as in the provider), best}; 50 reads each.
# Each run takes the benchlock itself. Usage: sweep_perepoch.sh STAMP
set -u
cd "$(dirname "$0")"
STAMP=$1
for N in 1024 4096 16384; do
  for L in default best; do
    python3 run_perepoch.py --count $N --reads 50 --layout $L --stamp "$STAMP"
  done
done
