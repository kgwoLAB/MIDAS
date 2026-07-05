# MIDAS

MIDAS (Microarchitectural Isolation Defense Against Saturation) is a QP-aware RoCEv2 defense prototype for BlueField-style SmartNIC
environments. MIDAS monitors RDMA queue-pair behavior, detects anomalous
traffic with EWMA-CUSUM and a hybrid LSTM-GRU classifier, and applies mitigation
from the BlueField Arm/ECPF side.

MIDAS is designed for high-performance RDMA systems where packet visibility and
enforcement depend heavily on NIC offload behavior. It supports both
software-visible RoCEv2 packet paths, such as mirrored pcap traces, and live
offloaded RoCEv2 paths, where hardware steering can bypass ordinary software
filters.

The artifact includes telemetry converters, a detector, a classifier, a QP
policy manager, an Arm/ECPF worker, an Arm-native detector/manager binary,
Linux traffic-control enforcement, a libibverbs QP guard, a DOCA Flow QP-drop
backend, threshold tuning helpers, Prometheus textfile metrics, and a DOCA DPA
fixed-point RNN path. Private lab addresses, credentials, paper PDFs, and raw
legacy datasets are kept outside the public artifact.

## Working Modes

MIDAS works in three practical modes.

### Offline Analysis Mode

Offline mode analyzes existing MIDAS JSONL telemetry files. It is useful for
reproducing detector/classifier results, checking labeled traces, and generating
policy actions without touching the network.

```bash
python3 src/midas.py offline \
  --data-dir traces \
  --glob "*.jsonl" \
  --model models/midas_hybrid_rnn.npz \
  --summary-out out/summary.json \
  --actions-out out/actions.jsonl
```

### Mirrored RoCEv2 Mode

Mirrored mode parses software-visible RoCEv2 packets from a pcap file. MIDAS
extracts the InfiniBand BTH destination QP, PSN, opcode, and optional RETH
RKey, then feeds the extracted QP-level stream into the detector.

```bash
python3 src/pcap_roce_to_midas_jsonl.py \
  --input roce.pcap \
  --output live/roce.jsonl

python3 src/midas.py tail \
  --input live/roce.jsonl \
  --print-all
```

### Live Arm/ECPF Mode

Live mode runs a MIDAS worker on the BlueField Arm/ECPF side. The host forwards
QP telemetry to the worker, the worker detects attack windows, and the Arm/ECPF
side applies mitigation and optionally launches the DPA RNN executable.

```bash
MODE=drop-roce IFACES=p0 /opt/midas/start_worker_qp_enforce_dpa_arm.sh
```

Then forward telemetry from the host:

```bash
ARM_HOST=bluefield-arm.local \
python3 src/host_to_arm_forwarder.py \
  --input live/perftest.jsonl \
  --arm-port 44991 \
  --validate
```

## Detection and Classification

MIDAS implements the following detection pipeline:

```text
QP telemetry
  -> EWMA rate tracking
  -> CUSUM anomaly accumulation
  -> hot-QP/window summary
  -> LSTM-GRU attack classification
  -> QP-targeted mitigation action
```

MIDAS classifies windows into five classes:

```text
0: Benign
1: QueueFlooding
2: CacheDepletion
3: VerbsFlooding
4: VerbsAmplification
```

Train and export the LSTM-GRU model before using the `--model` option:

```bash
python3 src/train_hybrid_classifier.py \
  --data-dir traces \
  --output models/midas_hybrid_rnn.npz \
  --qat-int8
```

The exported model path is:

```text
models/midas_hybrid_rnn.npz
```

Model weights are produced from the operator's labeled windows. If `--model` is
omitted, MIDAS uses the heuristic fallback classifier so that the telemetry and
policy pipeline can still be exercised.

The classifier consumes an 11-feature window:

```text
rate_log, ewma_log, cusum_log, op_norm, len_log, delta_psn_log,
rx_data_log, tx_data_log, pause_log, pause_dur_log, cache_hit_log
```

## Enforcement

MIDAS supports four enforcement paths.

### Exact-QP Enforcement

Exact-QP enforcement uses `tc u32` to match the RoCEv2 BTH destination QP:

```text
match u32 (dest_qp << 8) 0xffffff00 at 32
```

This mode is appropriate when RoCEv2 packets are software-visible, for example
through a mirror or a non-offloaded path.

```bash
SUDO_PASS=... /opt/midas/arm_qp_enforcer.py drop \
  --iface p0 \
  --dqp 1520
```

### Live-Offload Enforcement

On the validated BlueField/OVS offload path, exact `tc u32` rules install as
`not_in_hw` and do not see live offloaded packets. For that case MIDAS provides
`drop-roce`, which installs a hardware flower rule for UDP/4791 before the OVS
redirect rule.

```bash
SUDO_PASS=... /opt/midas/arm_qp_enforcer.py drop-roce \
  --iface p0 \
  --hw-prio 1
```

This is the verified live-offload enforcement mode.

### Verbs QP Guard

For applications that use libibverbs directly, MIDAS can enforce the
attack-specific plan at `ibv_post_send` time:

```bash
scripts/build_verbs_guard.sh
MIDAS_VERBS_PLAN=/tmp/midas_plan.json \
MIDAS_VERBS_LOG=/tmp/midas_verbs_guard.jsonl \
LD_PRELOAD=build/libmidas_verbs_guard.so ./rdma_app
```

The guard applies queue-depth caps, remote address/RKey diversity limits, token
buckets, and WQE pacing to the plan's `target_qps`.

### DOCA Flow QP Drop

On BlueField images with DOCA Flow RoCEv2 parser support, MIDAS can install
hardware drop rules keyed by BTH destination QP:

```bash
scripts/build_doca_flow_enforcer.sh
build/midas_doca_flow_enforcer --plan /tmp/midas_plan.json --devargs mlx5_0
```

Use `--dry-run` to print the rule set without touching hardware.

When launched from `arm_midas_worker.py`, use `{plan_json}` in
`--enforce-command`; the worker writes the current mitigation plan to that path
before invoking the command.

## Performance and Validation

### Reported detection/classification accuracy

The MIDAS accuracy results are reported in the paper, measured on the
BlueField-3 testbed:

```text
Anomaly detection:      average TPR 92.0% (per-sample, 100 ms bins)
Attack classification:  macro F1 0.905, weighted F1 0.918 (5-fold CV)
Mitigation overhead:    < 4% on legitimate RDMA workloads
```

### Prototype validation (this repository)

The results below verify that the released prototype runs end to end: telemetry
ingestion, EWMA-CUSUM detection, LSTM-GRU classification, QP-targeted policy
selection, and live hardware enforcement. The accuracy figures above are
evaluated in the paper; the checks here validate the released code path.

```text
Offline pipeline (labeled MIDAS windows):
  detector -> classifier -> policy action verified end to end

Live RDMA write baseline:
  37.09 Gbps

Live hardware enforcement:
  98,304 packets dropped in hardware
  RDMA client completion error observed

After clearing enforcement:
  37.09 Gbps restored
```

More details are in:

```text
docs/TEST_RESULTS.md
docs/IMPLEMENTATION_OVERVIEW.md
docs/ARM_ECPF_RUNTIME.md
```

## Quick Start

### Step 1: Install Python Dependencies

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

`numpy` is required for inference. `torch` is only needed for training or
exporting the hybrid classifier. The Python runtime expects Python 3.10 or
newer.

### Step 2: Convert Telemetry

From `ib_write_bw` output:

```bash
python3 src/perftest_to_midas_jsonl.py \
  --input ib_write_bw.log \
  --output live/perftest.jsonl
```

From a mirrored RoCEv2 pcap:

```bash
python3 src/pcap_roce_to_midas_jsonl.py \
  --input roce.pcap \
  --output live/roce.jsonl
```

Attach port counters from the Arm/ECPF or host interface:

```bash
python3 src/monitor/port_counter_enricher.py \
  --input live/roce.jsonl \
  --output live/roce.f11.jsonl \
  --iface p0 \
  --interval-ms 100 \
  --allow-missing
```

### Step 3: Train or Provide a Model

Train the LSTM-GRU model from your own labeled windows:

```bash
python3 src/train_hybrid_classifier.py \
  --data-dir traces \
  --output models/midas_hybrid_rnn.npz \
  --qat-int8
```

Tune detector thresholds on labeled windows:

```bash
python3 experiments/tune_thresholds.py \
  --data-dir traces \
  --csv-out experiments/threshold_sweep.csv \
  --json-out experiments/threshold_best.json
```

If you want to build the C inference path, export the generated C header from
your trained model:

```bash
python3 src/classifier/export_rnn_to_c.py \
  --model models/midas_hybrid_rnn.npz \
  --output src/classifier/generated/midas_rnn_weights.h
```

You can skip this step for a smoke test; MIDAS will use the heuristic fallback
classifier when no model is provided.

### Step 4: Run MIDAS

```bash
python3 src/midas.py offline \
  --data-dir live \
  --glob "*.jsonl" \
  --model models/midas_hybrid_rnn.npz \
  --actions-out out/actions.jsonl
```

By default MIDAS recomputes EWMA-CUSUM alerts from the selected thresholds.
Use `--trust-input-alert` only when replaying telemetry whose existing alert
fields should be treated as authoritative.

For a smoke test without a trained model:

```bash
python3 src/midas.py offline \
  --data-dir live \
  --glob "*.jsonl" \
  --actions-out out/actions.jsonl
```

### Step 5: Start the Arm/ECPF Worker

Copy the project to the BlueField Arm side, or deploy it with:

```bash
ARM_HOST=bluefield-arm.local \
ARM_USER=ubuntu \
scripts/deploy_arm_midas_worker.sh
```

Start the worker:

```bash
MODE=drop-roce IFACES=p0 \
PROMETHEUS_TEXTFILE=/var/tmp/midas_arm/midas.prom \
/opt/midas/start_worker_qp_enforce_dpa_arm.sh
```

Build the Arm-native detector/manager path:

```bash
scripts/build_arm_native.sh
build/midas_arm_native --input live/perftest.jsonl
```

### Step 6: Forward Host Telemetry

```bash
ARM_HOST=bluefield-arm.local \
python3 src/host_to_arm_forwarder.py \
  --input live/perftest.jsonl \
  --arm-port 44991 \
  --validate
```

## DPA RNN

The DPA implementation is in:

```text
dpa/midas_dpa_rnn/
```

After training, the host model is exported as LSTM-GRU numpy weights. For DPA
execution, MIDAS converts the model into scaled integer fixed-point headers.
The trainer also provides `--qat-int8` fake-quantization during training, so the
exported host model and DPA fixed-point path follow the same INT8-oriented
workflow.

Build on an Arm/ECPF environment with DOCA and DPACC installed:

```bash
scripts/build_dpa_arm.sh
```

The worker can launch the DPA executable for attack windows through the
`--dpa-command` hook.

## Repository Layout

```text
configs/      Example detector, classifier, and deployment configuration.
dpa/          DOCA DPA fixed-point LSTM-GRU sample.
docs/         Public implementation notes and validation summaries.
experiments/  Reproduction helpers.
models/       Placeholder for user-trained exported LSTM-GRU weights.
scripts/      Local, Arm/ECPF, and RDMA test helpers.
src/          MIDAS detector, classifier, telemetry, manager, and enforcer code.
```

## Applications

MIDAS is intended for research on:

- RDMA/RoCEv2 denial-of-service defense.
- SmartNIC/BlueField in-network security.
- Queue-pair level monitoring and mitigation.
- DPA-assisted inference for network defense.
- Containerized or virtualized RDMA environments where packet visibility depends
  on offload behavior.

## Operational Hygiene

Do not commit private infrastructure details. Provide hostnames, users, and
sudo automation through environment variables:

```bash
ARM_HOST=...
ARM_USER=...
SUDO_PASS=...
BASE_DIR=...
```

`SUDO_PASS` is supported only as a lab automation convenience. Prefer narrowly
scoped passwordless sudo rules for repeatable experiments.

## License

MIDAS is released under the Apache License 2.0. See the [LICENSE](LICENSE) and
[NOTICE](NOTICE) files for details.

## Citation

If you use this artifact in academic work, please cite the corresponding MIDAS
paper once the final citation is available.

## Contact

Please use GitHub issues for questions, bugs, and reproducibility reports.

- Gunwoo Kim: kgwo0528@gmail.com
- Jinwoo Kim: jinwookim@cbnu.ac.kr
