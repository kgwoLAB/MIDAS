#!/usr/bin/env bash
set -euo pipefail

BASE_DIR=${BASE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
INT=${INT:-int0}
DURATION=${DURATION:-10}
PCAP=${PCAP:-${BASE_DIR}/live/ovs_mirror_roce.pcap}
JSONL=${JSONL:-${BASE_DIR}/live/ovs_mirror_roce.jsonl}
MODEL=${MODEL:-${BASE_DIR}/models/midas_hybrid_rnn.npz}
SUDO_PASS=${SUDO_PASS:-}

mkdir -p "${BASE_DIR}/live" "${BASE_DIR}/out"

echo "[1/3] capturing mirrored RoCEv2 packets on ${INT} for ${DURATION}s"
if [[ -n "${SUDO_PASS}" ]]; then
  echo "${SUDO_PASS}" | sudo -S timeout "${DURATION}" tcpdump -i "${INT}" -nn -s 256 \
    -w "${PCAP}" "udp port 4791" || true
else
  sudo timeout "${DURATION}" tcpdump -i "${INT}" -nn -s 256 \
    -w "${PCAP}" "udp port 4791" || true
fi

echo "[2/3] converting pcap to MIDAS JSONL"
python3 "${BASE_DIR}/src/pcap_roce_to_midas_jsonl.py" \
  --input "${PCAP}" \
  --output "${JSONL}"

echo "[3/3] running MIDAS"
ARGS=(
  offline
  --data-dir "$(dirname "${JSONL}")"
  --glob "$(basename "${JSONL}")"
  --summary-out "${BASE_DIR}/out/ovs_mirror_summary.json"
  --actions-out "${BASE_DIR}/out/ovs_mirror_actions.jsonl"
)
if [[ -f "${MODEL}" ]]; then
  ARGS+=(--model "${MODEL}")
fi
python3 "${BASE_DIR}/src/midas.py" "${ARGS[@]}"

echo "done:"
echo "  ${PCAP}"
echo "  ${JSONL}"
echo "  ${BASE_DIR}/out/ovs_mirror_summary.json"
echo "  ${BASE_DIR}/out/ovs_mirror_actions.jsonl"
