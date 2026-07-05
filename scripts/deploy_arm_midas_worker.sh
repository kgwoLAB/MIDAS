#!/usr/bin/env bash
set -euo pipefail

BASE_DIR=${BASE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
ARM_HOST=${ARM_HOST:-bluefield-arm.local}
ARM_USER=${ARM_USER:-ubuntu}
ARM_PORT=${ARM_PORT:-22}
ARM_ROOT=${ARM_ROOT:-/opt/midas}
SSH_OPTS=${SSH_OPTS:-"-o StrictHostKeyChecking=accept-new -o ConnectTimeout=5"}

echo "[1/3] checking Arm reachability: ${ARM_USER}@${ARM_HOST}:${ARM_PORT}"
ssh ${SSH_OPTS} -p "${ARM_PORT}" "${ARM_USER}@${ARM_HOST}" "uname -a; id"

echo "[2/3] creating ${ARM_ROOT}"
ssh ${SSH_OPTS} -p "${ARM_PORT}" "${ARM_USER}@${ARM_HOST}" \
  "sudo mkdir -p '${ARM_ROOT}/models' '${ARM_ROOT}/out' && sudo chown -R '${ARM_USER}:${ARM_USER}' '${ARM_ROOT}'"

echo "[3/3] copying MIDAS Arm worker and enforcement helpers"
files=(
  "${BASE_DIR}/src/midas.py"
  "${BASE_DIR}/src/arm_midas_worker.py"
  "${BASE_DIR}/src/arm_qp_enforcer.py"
  "${BASE_DIR}/src/manager/mitigation_plan.py"
  "${BASE_DIR}/scripts/start_worker_qp_enforce_dpa_arm.sh"
  "${BASE_DIR}/scripts/start_worker_dpa_arm.sh"
)
if [[ -f "${BASE_DIR}/models/midas_hybrid_rnn.npz" ]]; then
  files+=("${BASE_DIR}/models/midas_hybrid_rnn.npz")
fi
ssh ${SSH_OPTS} -p "${ARM_PORT}" "${ARM_USER}@${ARM_HOST}" "mkdir -p '${ARM_ROOT}/manager'"
scp ${SSH_OPTS} -P "${ARM_PORT}" "${BASE_DIR}/src/midas.py" "${BASE_DIR}/src/arm_midas_worker.py" "${BASE_DIR}/src/arm_qp_enforcer.py" "${BASE_DIR}/scripts/start_worker_qp_enforce_dpa_arm.sh" "${BASE_DIR}/scripts/start_worker_dpa_arm.sh" "${ARM_USER}@${ARM_HOST}:${ARM_ROOT}/"
scp ${SSH_OPTS} -P "${ARM_PORT}" "${BASE_DIR}/src/manager/mitigation_plan.py" "${ARM_USER}@${ARM_HOST}:${ARM_ROOT}/manager/"
if [[ -f "${BASE_DIR}/models/midas_hybrid_rnn.npz" ]]; then
  scp ${SSH_OPTS} -P "${ARM_PORT}" "${BASE_DIR}/models/midas_hybrid_rnn.npz" "${ARM_USER}@${ARM_HOST}:${ARM_ROOT}/"
fi

ssh ${SSH_OPTS} -p "${ARM_PORT}" "${ARM_USER}@${ARM_HOST}" \
  "mkdir -p '${ARM_ROOT}/models'; if [ -f '${ARM_ROOT}/midas_hybrid_rnn.npz' ]; then mv '${ARM_ROOT}/midas_hybrid_rnn.npz' '${ARM_ROOT}/models/midas_hybrid_rnn.npz'; fi; chmod +x '${ARM_ROOT}'/*.py '${ARM_ROOT}'/*.sh"

echo "deployed:"
echo "  ${ARM_USER}@${ARM_HOST}:${ARM_ROOT}/arm_midas_worker.py"
