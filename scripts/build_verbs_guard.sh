#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/build"
mkdir -p "${OUT_DIR}"

cc -O2 -Wall -Wextra -fPIC -shared \
  "${ROOT_DIR}/src/manager/midas_verbs_guard.c" \
  -o "${OUT_DIR}/libmidas_verbs_guard.so" \
  -ldl -lpthread -libverbs

echo "${OUT_DIR}/libmidas_verbs_guard.so"
