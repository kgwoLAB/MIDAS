#!/usr/bin/env bash
set -euo pipefail

BASE_DIR=${BASE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
OUT=${OUT:-"${BASE_DIR}/build/midas_arm_native"}
SRC=${SRC:-"${BASE_DIR}/src/arm_native/midas_arm_native.cpp"}
if [[ ! -f "${SRC}" && -f "${BASE_DIR}/arm_native/midas_arm_native.cpp" ]]; then
  SRC="${BASE_DIR}/arm_native/midas_arm_native.cpp"
fi

mkdir -p "$(dirname "${OUT}")"
g++ -std=c++17 -O2 -Wall -Wextra \
  "${SRC}" \
  -o "${OUT}"

echo "built ${OUT}"
