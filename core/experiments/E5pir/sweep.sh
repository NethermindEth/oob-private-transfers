#!/bin/bash
# E5 PIR sweep (each run takes the benchlock itself). Usage: sweep.sh STAMP [main|big]
set -euo pipefail
cd "$(dirname "$0")"
STAMP=$1; PART=${2:-main}
if [ "$PART" = main ]; then
  for N in 16 256 1024 4096 65536; do
    for L in default best; do
      python3 run.py --count $N --reads 200 --layout $L --stamp "$STAMP" --label "m=$N $L"
    done
  done
  # crossover (formula-derived) and layout table
  ../../../scripts/benchlock sh -c "echo '{\"op\":\"crossover\",\"max_count\":65536}' | ../../simplepir/oob-pir > ../../results/E5pir/$STAMP/crossover.json"
else
  for L in default best; do
    python3 run.py --count 1048576 --reads 50 --layout $L --stamp "$STAMP" --label "m=2^20 $L"
  done
fi
