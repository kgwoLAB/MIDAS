#!/usr/bin/env bash
set -euo pipefail

PASS=${SUDO_PASS:-}
PF=${PF:-enp1s0f0np0}
VF=${VF:-enp1s0f0v0}
CONTAINER=${CONTAINER:-c_midas_vf0}
IMAGE=${IMAGE:-rdma_0}
IP_CIDR=${IP_CIDR:-192.168.200.110/24}

sudo_run() {
  if [[ -n "${PASS}" ]]; then
    echo "${PASS}" | sudo -S "$@"
  else
    sudo "$@"
  fi
}

sudo_run docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true

sudo_run sh -c "echo 0 > /sys/class/net/${PF}/device/sriov_numvfs"
sleep 1
sudo_run sh -c "echo 1 > /sys/class/net/${PF}/device/sriov_numvfs"
sleep 2
sudo_run ip link set "${VF}" up

sudo_run docker run -dit --name "${CONTAINER}" --network none --privileged \
  --device=/dev/infiniband/uverbs2 \
  --device=/dev/infiniband/rdma_cm \
  --device=/dev/infiniband/umad2 \
  "${IMAGE}" bash >/dev/null

PID=$(sudo_run docker inspect -f '{{.State.Pid}}' "${CONTAINER}")
sudo_run ip link set "${VF}" netns "${PID}"
sudo_run nsenter -t "${PID}" -n ip link set "${VF}" name eth1
sudo_run nsenter -t "${PID}" -n ip addr add "${IP_CIDR}" dev eth1
sudo_run nsenter -t "${PID}" -n ip link set eth1 up
sleep 2

echo "VF container ready:"
sudo_run docker exec "${CONTAINER}" ip -br addr
sudo_run docker exec "${CONTAINER}" bash -lc \
  'for f in /sys/class/infiniband/mlx5_2/ports/1/gids/{0..3}; do printf "%s " "$f"; cat "$f" 2>/dev/null || true; done'
