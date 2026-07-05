#!/usr/bin/env bash
set -euo pipefail

IFACE=${IFACE:-enp1s0f0np0}
DST_IP=${DST_IP:-192.168.200.102}
RATE=${RATE:-100mbit}
SUDO_PASS=${SUDO_PASS:-}

run_root() {
  if [[ -n "${SUDO_PASS}" ]]; then
    echo "${SUDO_PASS}" | sudo -S bash -c "$*"
  else
    sudo bash -c "$*"
  fi
}

run_root "tc qdisc replace dev ${IFACE} root handle 1: htb default 30; \
tc class replace dev ${IFACE} parent 1: classid 1:1 htb rate 100gbit ceil 100gbit; \
tc class replace dev ${IFACE} parent 1:1 classid 1:10 htb rate ${RATE} ceil ${RATE}; \
tc class replace dev ${IFACE} parent 1:1 classid 1:30 htb rate 100gbit ceil 100gbit; \
tc filter replace dev ${IFACE} protocol ip parent 1: prio 1 u32 match ip dst ${DST_IP}/32 flowid 1:10"

echo "applied tc rate limit: iface=${IFACE} dst=${DST_IP} rate=${RATE}"
tc qdisc show dev "${IFACE}" || true
tc class show dev "${IFACE}" || true
tc filter show dev "${IFACE}" parent 1: || true
