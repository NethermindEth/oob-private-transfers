#!/bin/bash
# S7-E4 scanning baseline: trial-decryption cost (core/halo2 src/bin/s7e4-scan.rs) under benchlock + load gate.
# Usage: run_scan.sh STAMP [rep]
set -euo pipefail
cd "$(dirname "$0")/../../.."
S=$1; REP=${2:-1}
OUT=core/results/S7E4/$S; mkdir -p $OUT
L0=$(sysctl -n vm.loadavg)
scripts/benchlock python3 core/experiments/E5pir/loadgate.py --gate 8 --max-wait 600 -- \
  core/halo2/target/release/s7e4-scan --n 200 --batch 4000 > $OUT/scan-$REP.json 2> $OUT/scan-$REP.stderr
echo "{\"load_submit\": \"$L0\", \"load_end\": \"$(sysctl -n vm.loadavg)\", \"commit\": \"$(git rev-parse HEAD)\", \"bin_sha256\": \"$(shasum -a 256 core/halo2/target/release/s7e4-scan | cut -d' ' -f1)\"}" > $OUT/scan-$REP.meta.json
cat $OUT/scan-$REP.stderr
