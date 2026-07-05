# Test Results Summary

This file contains the public validation summary. Private hostnames, addresses,
passwords, and raw lab traces are kept out of the repository.

## Reported accuracy (from the paper)

The MIDAS detection and classification accuracy is evaluated in the paper on the
BlueField-3 testbed, not in this repository:

```text
Anomaly detection:      average TPR 92.0% (per-sample, 100 ms bins)
Attack classification:  macro F1 0.905, weighted F1 0.918 (5-fold CV)
```

## Offline pipeline validation

The released code path supports offline validation with labeled windows and an
exported model. This path verifies that the EWMA-CUSUM detector, hybrid
LSTM-GRU classifier, and policy stage run end to end. The accuracy figures are
evaluated in the paper and reported above.

```text
End-to-end pipeline: OK
Labeled windows are separated correctly.
```

The LSTM-GRU path uses a user-trained exported numpy model at
`models/midas_hybrid_rnn.npz`. Use `src/train_hybrid_classifier.py` to
train/export one from your own labeled windows.

## C Classifier Parity

The exported C classifier path in `src/classifier/` was compile-tested and
matched the numpy classifier on representative traces.

## Arm/ECPF Worker

The Arm worker was tested by forwarding host-side MIDAS JSONL telemetry over
TCP. The worker emitted QP-targeted actions and recorded enforcement and DPA
results for attack windows.

Representative action fields:

```json
{
  "attack_class": 3,
  "attack_name": "VerbsFlooding",
  "target_qps": [328, 329],
  "enforce_result": {"returncode": 0},
  "dpa_result": {"returncode": 0}
}
```

## DPA

The DOCA DPA fixed-point RNN sample built and launched on the Arm/ECPF side.
Attack windows triggered the DPA executable and completed the DPA kernel.

Representative success markers:

```text
MIDAS DPA RNN kernel completed
MIDAS DPA fixed LSTM-GRU class=0 expected=0
```

## Live RoCE Enforcement

Live RDMA write traffic was tested between a BlueField Arm/ECPF endpoint and a
separate RDMA client endpoint.

Baseline:

```text
ib_write_bw average bandwidth: 37.09 Gbps
```

Exact BTH QP match:

```text
tc u32 match word for QP 1520:
  0005f000/ffffff00 at 32
```

The exact-QP rule installed successfully but remained `not_in_hw` on the live
offload path, so it did not count packets. This mode is retained for
software-visible or mirrored RoCE packets.

Hardware live-offload enforcement:

```bash
SUDO_PASS=... /opt/midas/arm_qp_enforcer.py drop-roce --iface p0 --hw-prio 1
```

Result:

```text
RDMA client completion error observed.
Hardware counter: 98,304 packets dropped.
Dropped bytes: 106,389,504.
```

After clearing the MIDAS hardware rule, the same perftest returned to the
baseline bandwidth.

## Interpretation

MIDAS performs QP-level detection and QP-targeted action selection. On
software-visible or mirrored RoCE paths, exact BTH destination-QP enforcement is
available through `tc u32`. On live BlueField offload paths, the verified
enforcement mechanism is hardware flower `drop-roce`, because the offload path
bypasses software `u32` classification.
