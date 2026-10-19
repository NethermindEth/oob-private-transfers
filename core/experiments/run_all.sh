#!/bin/bash
# Sequential component experiments and table generation.
set -euo pipefail
cd "$(dirname "$0")/../.."
export PYTHONPATH="$PWD"
PY="$PWD/.venv/bin/python"
B="$PWD/scripts/benchlock"
"$B" "$PY" -m core.tests.run_e4svc
"$B" "$PY" -m core.experiments.E1.run_e1 --runs 10
"$PY" core/experiments/E1/make_table.py
"$B" "$PY" -m core.experiments.E2.run_e2 --reps 5
"$PY" core/experiments/E2/make_table.py
"$B" "$PY" -m core.experiments.E3.run_e3
"$PY" core/experiments/E3/make_table.py
"$B" "$PY" -m core.experiments.E6.run_e6
"$PY" core/experiments/E6/make_table.py
"$B" "$PY" -m core.experiments.E5base.run_e5base
"$B" "$PY" -m core.experiments.E5base.run_backup --trials 50 --sizes 16,4096
