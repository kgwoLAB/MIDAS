#!/usr/bin/env bash
set -euo pipefail

ARM_ROOT=${ARM_ROOT:-/opt/midas}
PORT=${PORT:-44991}
OUT_DIR=${OUT_DIR:-/var/tmp/midas_arm}
MODEL=${MODEL:-${ARM_ROOT}/models/midas_hybrid_rnn.npz}
DPA_COMMAND=${DPA_COMMAND:-}
ENFORCE_COMMAND=${ENFORCE_COMMAND:-}
POLICY_BACKEND=${POLICY_BACKEND:-tc}
PROMETHEUS_TEXTFILE=${PROMETHEUS_TEXTFILE:-${OUT_DIR}/midas.prom}

cd "${ARM_ROOT}"
cmd=(
  python3 "${ARM_ROOT}/arm_midas_worker.py"
  --host 0.0.0.0
  --port "${PORT}"
  --out-dir "${OUT_DIR}"
  --model "${MODEL}"
  --policy-backend "${POLICY_BACKEND}"
  --prometheus-textfile "${PROMETHEUS_TEXTFILE}"
)
if [[ -n "${DPA_COMMAND}" ]]; then
  cmd+=(--dpa-command "${DPA_COMMAND}")
fi
if [[ -n "${ENFORCE_COMMAND}" ]]; then
  cmd+=(--enforce-command "${ENFORCE_COMMAND}")
fi
exec "${cmd[@]}"
