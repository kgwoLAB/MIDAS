#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/build"
mkdir -p "${OUT_DIR}"

export PKG_CONFIG_PATH="/opt/mellanox/doca/lib/aarch64-linux-gnu/pkgconfig:/opt/mellanox/doca/lib/x86_64-linux-gnu/pkgconfig:/opt/mellanox/doca/lib/pkgconfig:${PKG_CONFIG_PATH:-}"

if pkg-config --exists doca-flow doca-common 2>/dev/null; then
  DOCA_CFLAGS="$(pkg-config --cflags doca-flow doca-common)"
  DOCA_LIBS="$(pkg-config --libs doca-flow doca-common)"
else
  ARCH="$(uname -m)"
  DOCA_CFLAGS="-I/opt/mellanox/doca/include"
  DOCA_LIBS="-L/opt/mellanox/doca/lib/${ARCH}-linux-gnu -Wl,-rpath,/opt/mellanox/doca/lib/${ARCH}-linux-gnu -ldoca_flow -ldoca_common"
fi

cc -O2 -Wall -Wextra -D DOCA_ALLOW_EXPERIMENTAL_API \
  ${DOCA_CFLAGS} \
  "${ROOT_DIR}/src/manager/doca_flow_enforcer.c" \
  -o "${OUT_DIR}/midas_doca_flow_enforcer" \
  ${DOCA_LIBS}

echo "${OUT_DIR}/midas_doca_flow_enforcer"
