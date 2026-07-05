#!/usr/bin/env bash
set -euo pipefail

BASE_DIR=${BASE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
PF=${PF:-enp1s0f0np0}
VF=${VF:-enp1s0f0v0}
MIRROR=${MIRROR:-int0}
DURATION=${DURATION:-3}

mkdir -p "${BASE_DIR}/out"
python3 "${BASE_DIR}/src/monitor/capture_matrix.py" \
  --pf "${PF}" \
  --vf "${VF}" \
  --mirror "${MIRROR}" \
  --duration "${DURATION}" \
  --output "${BASE_DIR}/out/capture_matrix.json"
