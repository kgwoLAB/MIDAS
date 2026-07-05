#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR=${BUILD_DIR:-/tmp/midas_dpa_rnn_build}
DEVICE=${DEVICE:-}
LOG=${LOG:-/tmp/midas_dpa_rnn_run.log}
SUDO_PASS=${SUDO_PASS:-}

cmd=("${BUILD_DIR}/doca_midas_dpa_rnn" -l 60 --sdk-log-level 30)
if [[ -n "${DEVICE}" ]]; then
  cmd+=(--pf-device "${DEVICE}")
fi

if [[ -n "${SUDO_PASS}" ]]; then
  echo "${SUDO_PASS}" | sudo -S "${cmd[@]}" 2>&1 | tee "${LOG}"
else
  sudo "${cmd[@]}" 2>&1 | tee "${LOG}"
fi
