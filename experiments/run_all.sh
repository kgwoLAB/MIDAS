#!/usr/bin/env bash
set -euo pipefail

BASE_DIR=${BASE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}
OLD_DIR=${OLD_DIR:-"${BASE_DIR}/../old"}
MODEL=${MODEL:-"${BASE_DIR}/models/midas_hybrid_rnn.npz"}

mkdir -p "${BASE_DIR}/experiments/results"

python3 "${BASE_DIR}/src/midas.py" offline \
  --data-dir "${OLD_DIR}" \
  --glob "*.json" \
  --exclude "test*.json" \
  --exclude "int*.json" \
  --model "${MODEL}" \
  --summary-out "${BASE_DIR}/experiments/results/old_summary.json" \
  --actions-out "${BASE_DIR}/experiments/results/old_actions.jsonl"

python3 "${BASE_DIR}/experiments/aggregate_results.py" \
  --input "${BASE_DIR}/experiments/results/*_summary.json" \
  --output "${BASE_DIR}/experiments/results/summary.csv"
