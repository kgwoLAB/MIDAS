#!/usr/bin/env bash
set -euo pipefail

BASE_DIR=${BASE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
PORT=${PORT:-18515}
DEVICE=${DEVICE:-mlx5_0}
GID_INDEX=${GID_INDEX:-3}

mkdir -p "${BASE_DIR}/live"
fuser -k "${PORT}/tcp" 2>/dev/null || true
nohup ib_write_bw -d "${DEVICE}" -x "${GID_INDEX}" -p "${PORT}" --run_infinitely --duration 1 \
  --report_gbits > "${BASE_DIR}/live/peer_ib_write_bw_${PORT}.log" 2>&1 &
echo $! > "${BASE_DIR}/live/peer_ib_write_bw_${PORT}.pid"
echo "peer perftest server started:"
echo "  pid=$(cat "${BASE_DIR}/live/peer_ib_write_bw_${PORT}.pid")"
echo "  log=${BASE_DIR}/live/peer_ib_write_bw_${PORT}.log"
