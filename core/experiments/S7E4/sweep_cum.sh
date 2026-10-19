#!/bin/bash
# S7-E4 cumulative-DB points (secondary): column-append delta check, row-append m=4096 at N=2^14, 2^16.
set -u
cd "$(dirname "$0")"
S=$1
python3 run_cum.py --stamp "$S" -- -mode cadelta -count 4096 -me 1024
python3 run_cum.py --stamp "$S" -- -mode ra -count 16384 -cols 4096 -epochs 4 -reads 12
python3 run_cum.py --stamp "$S" -- -mode ra -count 65536 -cols 4096 -epochs 5 -reads 10
