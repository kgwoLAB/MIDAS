# Implementation Overview

MIDAS is organized as a QP-aware detection and mitigation pipeline.

## Pipeline

```text
RoCEv2/perftest telemetry
  -> MIDAS JSONL records
  -> EWMA-CUSUM detector
  -> LSTM-GRU attack classifier
  -> QP-targeted policy action
  -> Arm/ECPF enforcement, Prometheus metrics, and optional DPA inference
```

## Telemetry

MIDAS accepts two practical telemetry sources:

- `src/perftest_to_midas_jsonl.py`
  - Converts `ib_write_bw` output into JSONL records.
  - Preserves QP exchange fields such as local/remote QP, PSN, RKey, and rate.
- `src/pcap_roce_to_midas_jsonl.py`
  - Parses Ethernet/IPv4/UDP/RoCEv2 BTH from pcap.
  - Extracts `dest_qp`, PSN, opcode, and optional RETH RKey.
- `src/monitor/port_counter_enricher.py`
  - Reads interface counters with `ethtool -S`.
  - Adds per-port `rx_data`, `tx_data`, `pause`, `pause_dur`, and `cache_hit`
    fields to MIDAS JSONL records.

The pcap path is used when RoCE packets are software-visible through a mirror.
The perftest path is used when NIC offload hides UDP/4791 payloads from normal
capture tools.

The classifier feature schema is 11-dimensional:

```text
rate_log, ewma_log, cusum_log, op_norm, len_log, delta_psn_log,
rx_data_log, tx_data_log, pause_log, pause_dur_log, cache_hit_log
```

The converter paths emit per-QP RoCE fields and leave port counters unset. The
counter enricher adds live interface deltas when run on the host or Arm/ECPF
interface that can read the BlueField/Linux counters.

## Detection

`src/midas.py` implements:

- EWMA-CUSUM signal tracking.
- Hot-QP summarization.
- Interval-bucketed per-container active-QP density tracking.
- Numpy inference for user-exported LSTM-GRU weights.
- Heuristic fallback classification.
- QP policy action generation.
- Prometheus textfile metrics from the Arm/ECPF worker.
- An Arm-native C++ detector/manager path in `src/arm_native/`.

Train and export the LSTM-GRU model with:

```bash
python3 src/train_hybrid_classifier.py \
  --data-dir traces \
  --output models/midas_hybrid_rnn.npz
```

At runtime, omit `--model` to use the heuristic fallback classifier for smoke
tests, or pass the exported `.npz` file for LSTM-GRU inference.

Generated model artifacts, including `.npz` files and C weight headers under
`src/classifier/generated/`, are local build outputs and are ignored by git.

The trainer performs stratified 5-fold validation by default and then exports a
final model trained on the supplied labeled windows. Add `--qat-int8` to train
with INT8 fake-quantized weights before export.

The detector recomputes `midas_alert` from the configured thresholds by default.
Existing telemetry `alert` fields are used only when `--trust-input-alert` is
set, which keeps threshold sweeps independent from converter-side defaults.

Container-density tracking is bucketed by the sampling interval. Within each
interval, the count is updated as records arrive and the active-QP set is reset
when the next interval bucket begins.

## Enforcement

MIDAS provides four enforcement paths:

- `drop` and `police`
  - Exact BTH destination-QP match with Linux `tc u32`.
  - Match offset: IPv4-relative BTH destination QP at offset 32.
  - Intended for software-visible or mirrored RoCE packets.
- `drop-roce`
  - Hardware flower drop for UDP/4791 RoCEv2 traffic.
  - Intended for live BlueField/OVS offload paths where `u32` cannot be
    offloaded and therefore does not see packets.
- `src/manager/midas_verbs_guard.c`
  - libibverbs `LD_PRELOAD` guard for QP-level queue-depth limiting,
    remote-address/RKey diversity limiting, token buckets, and WQE pacing.
- `src/manager/doca_flow_enforcer.c`
  - DOCA Flow RoCEv2/BTH hardware drop rules keyed by destination QP when the
    BlueField image exposes RoCEv2 parser fields.

`src/arm_midas_worker.py` runs on the BlueField Arm/ECPF side. It receives
telemetry over TCP, emits actions, can call the enforcer, and can launch the DPA
RNN executable for attack windows.

The policy manager emits attack-specific plan parameters. Runtime backends bind
those parameters to the available enforcement mechanism: `tc u32` exact-QP
drop/police for software-visible packets, the verbs guard for QP-management
controls, and DOCA Flow RoCEv2/BTH hardware drop entries on BlueField images
that expose those parser fields.

`src/manager/mitigation_plan.py` expands each attack class into concrete plan
parameters:

- QueueFlooding: target QPs, queue depth, rate, burst.
- CacheDepletion: target QPs/DIPs/RKeys and remote-region diversity cap.
- VerbsFlooding and VerbsAmplification: token bucket, WQE pacing, rate, burst.

## DPA

`dpa/midas_dpa_rnn/` contains a DOCA DPA sample for the hybrid RNN path. After
training, the host-side exported LSTM-GRU model is converted into scaled integer
fixed-point headers for DPA execution. This is the INT8/QAT-style DPA path used
by the prototype, because common DPA compiler targets reject floating point
device code.

The DPA kernel accepts runtime DPA-visible input and output addresses. Each DPA
thread maps to one QP/window slot, with the generated fixed input retained only
as the standalone sample fallback.

## Reproduction Helpers

`experiments/tune_thresholds.py` sweeps `tau_qp` and `tau_cont` over labeled
MIDAS windows and writes both a CSV sweep table and a JSON file containing the
best threshold pair.
