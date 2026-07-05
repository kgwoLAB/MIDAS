#!/usr/bin/env bash
set -euo pipefail

IFACES=${IFACES:-pf0hpf,pf1hpf,p0,p1,en3f0pf0sf0,en3f1pf1sf0}
MODE=${MODE:-drop}
DPA_COMMAND=${DPA_COMMAND:-/tmp/midas_dpa_rnn_build_arm/doca_midas_dpa_rnn -l 60 --sdk-log-level 30 --pf-device mlx5_0}
POLICY_BACKEND=${POLICY_BACKEND:-tc}
PROMETHEUS_TEXTFILE=${PROMETHEUS_TEXTFILE:-/var/tmp/midas_arm/midas.prom}

for pid in $(pgrep -f '^python3 /opt/midas/arm_midas_worker.py' || true); do
  kill "${pid}" || true
done

mkdir -p /var/tmp/midas_arm /opt/midas/out
rm -rf /var/tmp/midas_arm/*

ENFORCE_COMMAND="/opt/midas/arm_qp_enforcer.py ${MODE} --iface ${IFACES} --action-json {action_json}"

setsid python3 /opt/midas/arm_midas_worker.py \
  --host 0.0.0.0 \
  --port 44991 \
  --out-dir /var/tmp/midas_arm \
  --model /opt/midas/models/midas_hybrid_rnn.npz \
  --policy-backend "${POLICY_BACKEND}" \
  --prometheus-textfile "${PROMETHEUS_TEXTFILE}" \
  --enforce-command "${ENFORCE_COMMAND}" \
  --dpa-command "${DPA_COMMAND}" \
  > /opt/midas/out/arm_worker_qp_enforce_dpa.log 2>&1 < /dev/null &

sleep 2
echo "---proc"
pgrep -af '^python3 /opt/midas/arm_midas_worker.py' || true
echo "---port"
timeout 2 bash -lc '</dev/tcp/127.0.0.1/44991' && echo worker_open || echo worker_closed
echo "---log"
tail -20 /opt/midas/out/arm_worker_qp_enforce_dpa.log
