#!/usr/bin/env bash
set -euo pipefail

IFACE=${IFACE:-enp1s0f0np0}
SUDO_PASS=${SUDO_PASS:-}

if [[ -n "${SUDO_PASS}" ]]; then
  echo "${SUDO_PASS}" | sudo -S tc qdisc del dev "${IFACE}" root 2>/dev/null || true
else
  sudo tc qdisc del dev "${IFACE}" root 2>/dev/null || true
fi

echo "cleared tc qdisc on ${IFACE}"
tc qdisc show dev "${IFACE}" || true
