#!/usr/bin/env bash
set -euo pipefail

BR=${BR:-ovsbr1}
PF=${PF:-enp1s0f0np0}
VF=${VF:-enp1s0f0v0}
VF_INDEX=${VF_INDEX:-0}
VF_IP=${VF_IP:-192.168.200.110/24}
INT=${INT:-int0}
MIRROR=${MIRROR:-m_vf0}
SUDO_PASS=${SUDO_PASS:-}

run_root() {
  if [[ -n "${SUDO_PASS}" ]]; then
    echo "${SUDO_PASS}" | sudo -S bash -c "$*"
  else
    sudo bash -c "$*"
  fi
}

run_root "ip link set ${PF} vf ${VF_INDEX} trust on 2>/dev/null || true; ip link set ${PF} vf ${VF_INDEX} spoofchk off 2>/dev/null || true; ip link set ${PF} vf ${VF_INDEX} state enable 2>/dev/null || true"
run_root "ip addr add ${VF_IP} dev ${VF} 2>/dev/null || true; ip link set ${VF} up"

run_root "ovs-vsctl --may-exist add-br ${BR}"
run_root "ovs-vsctl --may-exist add-port ${BR} ${VF}"
run_root "ovs-vsctl --may-exist add-port ${BR} ${INT} -- set Interface ${INT} type=internal"
run_root "ip link set ${BR} up || true; ip link set ${INT} up || true"
run_root "ovs-vsctl -- --id=@src get Port ${VF} -- --id=@out get Port ${INT} -- --id=@m create Mirror name=${MIRROR} select-src-port=@src select-dst-port=@src output-port=@out -- set Bridge ${BR} mirrors=@m"

echo "configured VF OVS mirror:"
echo "  bridge=${BR}"
echo "  vf=${VF} (${VF_IP})"
echo "  output=${INT}"
ip -br addr show "${VF}" || true
ip -br addr show "${INT}" || true
sudo ovs-vsctl show
