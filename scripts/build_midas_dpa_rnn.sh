#!/usr/bin/env bash
set -euo pipefail

BASE_DIR=${BASE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
TRACE=${TRACE:-${BASE_DIR}/live/perftest.jsonl}
BUILD_DIR=${BUILD_DIR:-/tmp/midas_dpa_rnn_build}

cd "${BASE_DIR}"
python3 src/classifier/export_rnn_to_dpa_fixed.py \
  --trace "${TRACE}" \
  --weights-output dpa/midas_dpa_rnn/device/midas_rnn_fixed_weights.h \
  --input-output dpa/midas_dpa_rnn/device/midas_rnn_fixed_input.h

rm -rf "${BUILD_DIR}"
meson "${BUILD_DIR}" "${BASE_DIR}/dpa/midas_dpa_rnn"
ninja -C "${BUILD_DIR}"

echo "MIDAS DPA RNN build complete:"
echo "  host executable: ${BUILD_DIR}/doca_midas_dpa_rnn"
echo "  DPA program:     ${BUILD_DIR}/midas_dpa_rnn/device/build_dpacc/midas_dpa_rnn_program.a"
