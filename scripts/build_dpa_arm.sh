#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"
export PATH="/opt/mellanox/doca/tools:${PATH}"
export PKG_CONFIG_PATH="/opt/mellanox/doca/lib/aarch64-linux-gnu/pkgconfig:/opt/mellanox/doca/lib/x86_64-linux-gnu/pkgconfig:/opt/mellanox/doca/lib/pkgconfig:${PKG_CONFIG_PATH:-}"

MODEL=${MODEL:-models/midas_hybrid_rnn.npz}
TRACE=${TRACE:-/var/tmp/midas_arm/arm_windows.jsonl}
if [[ ! -s "${TRACE}" ]]; then
  TRACE=/var/tmp/midas_arm/arm_actions.jsonl
fi

python3 src/classifier/export_rnn_to_dpa_fixed.py \
  --model "${MODEL}" \
  --trace "${TRACE}" \
  --weights-output dpa/midas_dpa_rnn/device/midas_rnn_fixed_weights.h \
  --input-output dpa/midas_dpa_rnn/device/midas_rnn_fixed_input.h

rm -rf /tmp/midas_dpa_rnn_build_arm
meson setup /tmp/midas_dpa_rnn_build_arm dpa/midas_dpa_rnn
ninja -C /tmp/midas_dpa_rnn_build_arm

ls -l /tmp/midas_dpa_rnn_build_arm/doca_midas_dpa_rnn \
      /tmp/midas_dpa_rnn_build_arm/midas_dpa_rnn/device/build_dpacc/midas_dpa_rnn_program.a
