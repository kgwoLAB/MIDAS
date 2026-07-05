#!/usr/bin/env bash
set -u

PASS=${SUDO_PASS:-}
TRIES=${TRIES:-60}
SLEEP=${SLEEP:-10}
TMFIFO_HOST_IP=${TMFIFO_HOST_IP:-192.168.100.1/30}
ARM_HOST=${ARM_HOST:-bluefield-arm.local}

sudo_run() {
  if [[ -n "${PASS}" ]]; then
    echo "${PASS}" | sudo -S "$@"
  else
    sudo "$@"
  fi
}

echo "---post_bfb_misc"
sudo_run cat /dev/rshim0/misc 2>/dev/null || true
echo "---wait_arm"

for i in $(seq 1 "${TRIES}"); do
  sudo_run ip addr add "${TMFIFO_HOST_IP}" dev tmfifo_net0 2>/dev/null || true
  sudo_run ip link set tmfifo_net0 up >/dev/null 2>&1 || true

  v4=closed
  timeout 1 bash -lc "</dev/tcp/${ARM_HOST}/22" >/dev/null 2>&1 && v4=open

  v6=closed
  python3 - <<'PY' >/dev/null 2>&1 && v6=open || true
import socket
host = 'fe80::21a:caff:feff:ff01'
scope = socket.if_nametoindex('tmfifo_net0')
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.settimeout(1)
s.connect((host, 22, 0, scope))
s.close()
PY

  echo "try=${i} ipv4_ssh=${v4} ipv6_ssh=${v6}"
  if [[ "${v4}" == "open" || "${v6}" == "open" ]]; then
    break
  fi
  sleep "${SLEEP}"
done

echo "---addr"
ip -br addr show tmfifo_net0
echo "---neigh"
ip -6 neigh show dev tmfifo_net0 || true
ip neigh show dev tmfifo_net0 || true
echo "---misc2"
sudo_run cat /dev/rshim0/misc 2>/dev/null || true
