# Arm/ECPF Runtime

The live runtime is split between a host-side telemetry producer and a
BlueField Arm/ECPF worker.

## Components

- Host side:
  - `src/perftest_to_midas_jsonl.py`
  - `src/pcap_roce_to_midas_jsonl.py`
  - `src/host_to_arm_forwarder.py`
- Arm/ECPF side:
  - `src/midas.py`
  - `src/arm_midas_worker.py`
  - `src/arm_qp_enforcer.py`
  - optional user-trained `models/midas_hybrid_rnn.npz`
  - optional DPA executable built from `dpa/midas_dpa_rnn/`

If the model file is absent, the worker falls back to the heuristic classifier
for smoke tests. Train/export `models/midas_hybrid_rnn.npz` before evaluating
the LSTM-GRU path.

## Start Worker

For live offloaded RoCE traffic:

```bash
MODE=drop-roce IFACES=p0 /opt/midas/start_worker_qp_enforce_dpa_arm.sh
```

For exact-QP software-visible traffic:

```bash
MODE=drop IFACES=p0 /opt/midas/start_worker_qp_enforce_dpa_arm.sh
```

`drop-roce` is the verified hardware enforcement mode for live offload paths.
`drop` uses exact BTH destination-QP matching and is useful for mirror/software
capture paths.

## Forward Telemetry

```bash
ARM_HOST=bluefield-arm.local \
python3 src/host_to_arm_forwarder.py \
  --input live/perftest.jsonl \
  --arm-port 44991 \
  --validate
```

## Manual Enforcement Checks

Show filters:

```bash
SUDO_PASS=... /opt/midas/arm_qp_enforcer.py show --iface p0
```

Install live RoCE hardware drop:

```bash
SUDO_PASS=... /opt/midas/arm_qp_enforcer.py drop-roce --iface p0 --hw-prio 1
```

Clear MIDAS-installed filters:

```bash
SUDO_PASS=... /opt/midas/arm_qp_enforcer.py clear --iface p0 --hw-prio 1
```

## Notes

On many BlueField/OVS offload paths, OVS installs an early hardware redirect
rule. To block live RoCE traffic, the MIDAS `drop-roce` rule is installed with a
higher priority than that redirect rule. Exact BTH QP matching through `tc u32`
can install successfully but often remains `not_in_hw`, so it is not sufficient
for live offloaded packets.
