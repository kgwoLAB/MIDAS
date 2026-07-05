#!/usr/bin/env bash
set -euo pipefail

BR=${BR:-ovsbr1}
SRC=${SRC:-enp1s0f0np0}
INT=${INT:-int0}
MIRROR=${MIRROR:-m0}
SUDO_PASS=${SUDO_PASS:-}

run_root() {
  if [[ -n "${SUDO_PASS}" ]]; then
    echo "${SUDO_PASS}" | sudo -S bash -c "$*"
  else
    sudo bash -c "$*"
  fi
}

run_root "ovs-vsctl --may-exist add-br ${BR}"
run_root "ovs-vsctl --may-exist add-port ${BR} ${SRC}"
run_root "ovs-vsctl --may-exist add-port ${BR} ${INT} -- set Interface ${INT} type=internal"
run_root "ip link set ${BR} up || true"
run_root "ip link set ${SRC} up || true"
run_root "ip link set ${INT} up || true"

run_root "ovs-vsctl -- --id=@src get Port ${SRC} -- --id=@out get Port ${INT} -- --id=@m create Mirror name=${MIRROR} select-src-port=@src select-dst-port=@src output-port=@out -- set Bridge ${BR} mirrors=@m"

echo "configured OVS mirror:"
echo "  bridge=${BR}"
echo "  source=${SRC}"
echo "  output=${INT}"
sudo ovs-vsctl show
ip -br link show "${BR}" "${SRC}" "${INT}" || true
