#!/usr/bin/env bash
set -euo pipefail

BR=${BR:-ovsbr1}
INT=${INT:-int0}
DEL_BR=${DEL_BR:-0}
SUDO_PASS=${SUDO_PASS:-}

run_root() {
  if [[ -n "${SUDO_PASS}" ]]; then
    echo "${SUDO_PASS}" | sudo -S bash -c "$*"
  else
    sudo bash -c "$*"
  fi
}

run_root "ovs-vsctl --if-exists clear Bridge ${BR} mirrors"
run_root "ovs-vsctl --if-exists del-port ${BR} ${INT}"
if [[ "${DEL_BR}" == "1" ]]; then
  run_root "ovs-vsctl --if-exists del-br ${BR}"
fi
echo "cleared OVS mirror on ${BR}"
sudo ovs-vsctl show || true
