#!/usr/bin/env bash
set -euo pipefail

BASE_DIR=${BASE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
CONTAINER=${CONTAINER:-c_midas_vf0}
PEER_IP=${PEER_IP:-192.168.200.102}
PORT=${PORT:-18523}
DURATION=${DURATION:-8}
DEVICE=${DEVICE:-mlx5_2}
GID_INDEX=${GID_INDEX:-3}
MODEL=${MODEL:-${BASE_DIR}/models/midas_hybrid_rnn.npz}
PASS=${SUDO_PASS:-}

sudo_run() {
  if [[ -n "${PASS}" ]]; then
    echo "${PASS}" | sudo -S "$@"
  else
    sudo "$@"
  fi
}

mkdir -p "${BASE_DIR}/live" "${BASE_DIR}/out"

LOG="${BASE_DIR}/live/vf_ib_write_bw_${PORT}.log"
JSONL="${BASE_DIR}/live/vf_perftest_${PORT}.jsonl"
ACTIONS="${BASE_DIR}/out/vf_actions_${PORT}.jsonl"
SUMMARY="${BASE_DIR}/out/vf_summary_${PORT}.json"

echo "[1/3] running VF RDMA client in ${CONTAINER}"
sudo_run timeout "${DURATION}" docker exec "${CONTAINER}" \
  ib_write_bw -d "${DEVICE}" -x "${GID_INDEX}" -p "${PORT}" \
  --run_infinitely --duration 1 --report_gbits "${PEER_IP}" \
  > "${LOG}" 2>&1 || true

echo "[2/3] converting QP exchange and bandwidth rows"
python3 "${BASE_DIR}/src/perftest_to_midas_jsonl.py" \
  --input "${LOG}" \
  --output "${JSONL}"

echo "[3/3] running MIDAS"
MIDAS_ARGS=(
  offline
  --data-dir "${BASE_DIR}/live"
  --glob "$(basename "${JSONL}")"
  --summary-out "${SUMMARY}"
  --actions-out "${ACTIONS}"
)
if [[ -f "${MODEL}" ]]; then
  MIDAS_ARGS+=(--model "${MODEL}")
fi
python3 "${BASE_DIR}/src/midas.py" "${MIDAS_ARGS[@]}"

echo "done:"
echo "  ${LOG}"
echo "  ${JSONL}"
echo "  ${SUMMARY}"
echo "  ${ACTIONS}"
