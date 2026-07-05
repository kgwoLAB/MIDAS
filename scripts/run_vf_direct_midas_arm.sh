#!/usr/bin/env bash
set -euo pipefail

BASE_DIR=${BASE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
ARM_HOST=${ARM_HOST:-bluefield-arm.local}
ARM_PORT=${ARM_PORT:-44991}
PORT=${PORT:-18531}
FOLLOW=${FOLLOW:-0}

"${BASE_DIR}/scripts/run_vf_direct_midas.sh"

JSONL="${BASE_DIR}/live/vf_perftest_${PORT}.jsonl"
if [[ ! -s "${JSONL}" ]]; then
  echo "missing telemetry: ${JSONL}" >&2
  exit 2
fi

args=(
  python3 "${BASE_DIR}/src/host_to_arm_forwarder.py"
  --input "${JSONL}"
  --arm-host "${ARM_HOST}"
  --arm-port "${ARM_PORT}"
  --validate
)
if [[ "${FOLLOW}" == "1" ]]; then
  args+=(--follow)
fi

exec "${args[@]}"
