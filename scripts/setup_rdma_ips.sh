#!/usr/bin/env bash
set -euo pipefail

ROLE=${1:-}
SUDO_PASS=${SUDO_PASS:-}

if [[ -z "${ROLE}" || ! "${ROLE}" =~ ^(server|client)$ ]]; then
  echo "Usage: SUDO_PASS=... $0 <server|client>"
  exit 2
fi

run_root() {
  if [[ -n "${SUDO_PASS}" ]]; then
    echo "${SUDO_PASS}" | sudo -S bash -c "$*"
  else
    sudo bash -c "$*"
  fi
}

if [[ "${ROLE}" == "server" ]]; then
  run_root 'ip addr add 192.168.200.101/24 dev enp1s0f0np0 2>/dev/null || true; ip addr add 192.168.201.101/24 dev enp1s0f1np1 2>/dev/null || true; ip link set enp1s0f0np0 up; ip link set enp1s0f1np1 up'
  ip -br addr show enp1s0f0np0
  ip -br addr show enp1s0f1np1
else
  run_root 'ip addr add 192.168.200.102/24 dev enp10s0f0np0 2>/dev/null || true; ip addr add 192.168.201.102/24 dev enp10s0f1np1 2>/dev/null || true; ip link set enp10s0f0np0 up; ip link set enp10s0f1np1 up'
  ip -br addr show enp10s0f0np0
  ip -br addr show enp10s0f1np1
fi
