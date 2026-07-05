#!/usr/bin/env bash
set -euo pipefail

BASE_DIR=${BASE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
PEER_IP=${PEER_IP:-192.168.200.102}
PORT=${PORT:-18515}
DURATION=${DURATION:-8}
MODEL=${MODEL:-${BASE_DIR}/models/midas_hybrid_rnn.npz}
ENFORCE=${ENFORCE:-0}
LIMIT_RATE=${LIMIT_RATE:-100mbit}

mkdir -p "${BASE_DIR}/live" "${BASE_DIR}/out"

echo "[1/3] running ib_write_bw client for ${DURATION}s"
timeout "${DURATION}" ib_write_bw -d mlx5_0 "${PEER_IP}" -p "${PORT}" \
  --run_infinitely --duration 1 --report_gbits \
  > "${BASE_DIR}/live/client_ib_write_bw_${PORT}.log" 2>&1 || true

echo "[2/3] converting perftest log to MIDAS JSONL"
python3 "${BASE_DIR}/src/perftest_to_midas_jsonl.py" \
  --input "${BASE_DIR}/live/client_ib_write_bw_${PORT}.log" \
  --output "${BASE_DIR}/live/perftest_${PORT}.jsonl"

echo "[3/3] running MIDAS detector/manager"
MIDAS_ARGS=(
  offline
  --data-dir "${BASE_DIR}/live"
  --glob "perftest_${PORT}.jsonl"
  --summary-out "${BASE_DIR}/out/live_summary.json"
  --actions-out "${BASE_DIR}/out/live_actions.jsonl"
)
if [[ -f "${MODEL}" ]]; then
  MIDAS_ARGS+=(--model "${MODEL}")
fi
python3 "${BASE_DIR}/src/midas.py" "${MIDAS_ARGS[@]}"

if [[ "${ENFORCE}" == "1" ]]; then
  echo "[4/4] applying MIDAS enforcement"
  SUDO_PASS="${SUDO_PASS:-}" python3 "${BASE_DIR}/src/midas_enforcer.py" \
    --actions "${BASE_DIR}/out/live_actions.jsonl" \
    --summary "${BASE_DIR}/out/live_summary.json" \
    --iface enp1s0f0np0 \
    --rate "${LIMIT_RATE}"
fi

echo "done:"
echo "  ${BASE_DIR}/live/client_ib_write_bw_${PORT}.log"
echo "  ${BASE_DIR}/live/perftest_${PORT}.jsonl"
echo "  ${BASE_DIR}/out/live_summary.json"
echo "  ${BASE_DIR}/out/live_actions.jsonl"
