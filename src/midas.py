#!/usr/bin/env python3
"""Dependency-light MIDAS runner.

This file is intentionally usable on the BlueField/server host without torch or
sklearn. It implements the core online logic:

- JSONL telemetry ingestion.
- EWMA-CUSUM anomaly detection per QP.
- Container/QP-count anomaly detection.
- Fixed-window feature summarization.
- Attack-classifier interface with a heuristic fallback.
- Dry-run QP Manager policy output.

The fallback classifier is not a substitute for the paper's LSTM/GRU model. The
repository also includes numpy LSTM-GRU inference and a DPA export path that
converts the exported model weights into scaled integer fixed-point headers for
device execution.
"""

from __future__ import annotations

import argparse
import fnmatch
import glob
import json
import math
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

try:
    from manager.mitigation_plan import build_plan
except ImportError:
    build_plan = None


ATTACK_CLASSES = {
    0: "Benign",
    1: "QueueFlooding",
    2: "CacheDepletion",
    3: "VerbsFlooding",
    4: "VerbsAmplification",
}


@dataclass
class DetectorConfig:
    alpha: float = 0.3
    k_qp: float = 0.0
    k_cont: float = 0.0
    tau_qp: float = 1_000_000.0
    tau_cont: float = 10.0
    warm_ratio: float = 0.5
    hot_level: int = 2
    interval_ms: int = 100
    trust_input_alert: bool = False


@dataclass
class QPState:
    ewma: Optional[float] = None
    cusum: float = 0.0
    samples: int = 0
    hot_samples: int = 0
    warm_samples: int = 0
    last_psn: Optional[int] = None
    last_ts: Optional[float] = None


@dataclass
class ContainerState:
    ewma: Optional[float] = None
    cusum: float = 0.0


@dataclass
class Detection:
    record: dict
    recomputed_ewma: float
    recomputed_cusum: float
    recomputed_alert: int
    container_cusum: float
    container_alert: int
    is_hot: bool


@dataclass
class WindowSummary:
    source: str
    label: Optional[int]
    samples: int = 0
    unique_qps: int = 0
    unique_dips: int = 0
    avg_rate: float = 0.0
    avg_ewma: float = 0.0
    max_cusum: float = 0.0
    hot_ratio: float = 0.0
    warm_ratio: float = 0.0
    top_op: Optional[int] = None
    avg_len: float = 0.0
    attack_class: int = 0
    action: str = "allow"
    mitigation_plan: Optional[dict] = None


def read_jsonl(path: Path) -> Iterator[dict]:
    with path.open("r", encoding="utf-8-sig", errors="replace") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"[warn] {path}:{line_no}: bad JSON: {exc}", file=sys.stderr)


def infer_label_from_name(path: Path) -> Optional[int]:
    """Infer binary attack label from recovered trace names.

    The server has `int*.json` for attack windows and `int_raw*.json` for
    normal windows. The local old folder additionally uses alternating
    `0_10.json`, `10_20.json`, ... names.
    """
    name = path.name
    if name.startswith("int_raw"):
        return 0
    if name.startswith("int"):
        return 1

    stem = path.stem.replace("_", "-")
    attack_windows = {"0-10", "20-30", "40-50", "60-70", "80-90", "100-110"}
    benign_windows = {"10-20", "30-40", "50-60", "70-80", "90-100", "110-120"}
    if stem in attack_windows:
        return 1
    if stem in benign_windows:
        return 0
    return None


class EwmaCusumDetector:
    def __init__(self, config: DetectorConfig):
        self.config = config
        self.qps: Dict[Tuple[str, int], QPState] = {}
        self.containers: Dict[str, ContainerState] = {}
        self.active_qps_by_dip: Dict[str, set] = {}
        self.active_bucket_by_dip: Dict[str, int] = {}

    def process(self, record: dict) -> Detection:
        dip = str(record.get("dip", "unknown"))
        dqp = int(record.get("dqp", -1))
        key = (dip, dqp)
        rate = float(record.get("rate", 0.0))

        state = self.qps.setdefault(key, QPState())
        if state.ewma is None:
            ewma = rate
        else:
            ewma = self.config.alpha * rate + (1.0 - self.config.alpha) * state.ewma
        cusum = max(0.0, state.cusum + rate - ewma - self.config.k_qp)

        state.ewma = ewma
        state.cusum = cusum
        state.samples += 1
        state.last_ts = float(record.get("ts", 0.0))
        if "psn" in record:
            try:
                state.last_psn = int(record["psn"])
            except (TypeError, ValueError):
                pass

        qp_alert = self.alert_level(cusum, self.config.tau_qp)
        if qp_alert == 2:
            state.hot_samples += 1
        elif qp_alert == 1:
            state.warm_samples += 1

        ts = float(record.get("ts", time.time()))
        interval_s = max(self.config.interval_ms / 1000.0, 1e-6)
        bucket = int(ts / interval_s)
        if self.active_bucket_by_dip.get(dip) != bucket:
            self.active_qps_by_dip[dip] = set()
            self.active_bucket_by_dip[dip] = bucket
        qps = self.active_qps_by_dip.setdefault(dip, set())
        qps.add(dqp)
        count = float(len(qps))
        cstate = self.containers.setdefault(dip, ContainerState())
        if cstate.ewma is None:
            cont_ewma = count
        else:
            cont_ewma = self.config.alpha * count + (1.0 - self.config.alpha) * cstate.ewma
        cont_cusum = max(0.0, cstate.cusum + count - cont_ewma - self.config.k_cont)
        cstate.ewma = cont_ewma
        cstate.cusum = cont_cusum
        cont_alert = self.alert_level(cont_cusum, self.config.tau_cont)

        out = dict(record)
        out["midas_ewma"] = ewma
        out["midas_cusum"] = cusum
        input_alert = int(record.get("midas_alert", record.get("alert", 0)) or 0) if self.config.trust_input_alert else 0
        out["midas_alert"] = max(input_alert, qp_alert, cont_alert)

        return Detection(
            record=out,
            recomputed_ewma=ewma,
            recomputed_cusum=cusum,
            recomputed_alert=qp_alert,
            container_cusum=cont_cusum,
            container_alert=cont_alert,
            is_hot=out["midas_alert"] == self.config.hot_level,
        )

    def alert_level(self, score: float, threshold: float) -> int:
        if threshold <= 0:
            return 2 if score > 0 else 0
        if score >= threshold:
            return 2
        if score >= threshold * self.config.warm_ratio:
            return 1
        return 0


class HeuristicAttackClassifier:
    """Fallback classifier used until the LSTM/GRU model is deployed."""

    def classify(self, records: List[dict], summary: WindowSummary) -> int:
        if summary.hot_ratio < 0.05:
            return 0

        ops = [int(r.get("op", -1)) for r in records]
        lens = [float(r.get("len", 0.0)) for r in records]
        unique_ops = len(set(ops))
        zero_len_ratio = sum(1 for x in lens if x <= 0) / max(1, len(lens))

        if summary.unique_qps >= 2 and zero_len_ratio > 0.8:
            return 1
        if unique_ops >= 3:
            return 3
        if summary.avg_len <= 16 and summary.avg_rate > 0 and summary.hot_ratio > 0.5:
            return 4
        return 1


class NumpyHybridRNNClassifier:
    """Numpy inference for the exported PyTorch LSTM+GRU classifier."""

    def __init__(self, model_path: Path):
        import numpy as np

        self.np = np
        self.weights = np.load(model_path)
        self.mean = self.weights["feature_mean"]
        self.std = self.weights["feature_std"]
        self.timesteps = int(self.weights["timesteps"][0])
        if int(self.mean.shape[0]) != 11:
            raise ValueError(
                f"{model_path} has feature_dim={self.mean.shape[0]}, but MIDAS expects F=11. "
                "Retrain/export the model with the current train_hybrid_classifier.py."
            )

    def classify(self, records: List[dict], summary: WindowSummary) -> int:
        x = self._build_sequence(records)
        x = (x - self.mean) / self.std
        lstm_h = self._lstm_forward(x)
        gru_h = self._gru_forward(x)
        merged = self.np.concatenate([lstm_h, gru_h], axis=0)
        logits = self.weights["fc__weight"].dot(merged) + self.weights["fc__bias"]
        return int(self.np.argmax(logits))

    def _build_sequence(self, records: List[dict]):
        np = self.np
        feats = []
        prev_psn = None
        for r in records:
            rate = float(r.get("rate", 0.0))
            ewma = float(r.get("ewma", r.get("midas_ewma", 0.0)))
            cusum = float(r.get("cusum", r.get("midas_cusum", 0.0)))
            op = float(r.get("op", 0.0))
            length = float(r.get("len", 0.0))
            psn = float(r.get("psn", 0.0))
            rx_data = float(r.get("rx_data", r.get("port_rx_data", 0.0)))
            tx_data = float(r.get("tx_data", r.get("port_tx_data", 0.0)))
            pause = float(r.get("pause", r.get("port_pause", 0.0)))
            pause_dur = float(r.get("pause_dur", r.get("port_pause_dur", 0.0)))
            cache_hit = float(r.get("cache_hit", r.get("port_cache_hit", 0.0)))
            if prev_psn is None or psn < prev_psn:
                delta_psn = 0.0
            else:
                delta_psn = psn - prev_psn
            prev_psn = psn
            feats.append([
                np.log1p(rate),
                np.log1p(ewma),
                np.log1p(cusum),
                op / 255.0,
                np.log1p(length),
                np.log1p(delta_psn),
                np.log1p(rx_data),
                np.log1p(tx_data),
                np.log1p(pause),
                np.log1p(pause_dur),
                np.log1p(cache_hit),
            ])
        if not feats:
            feats = [[0.0] * 11]
        seq = np.asarray(feats, dtype=np.float32)
        if seq.shape[0] >= self.timesteps:
            return seq[:self.timesteps]
        pad = np.repeat(seq[-1:, :], self.timesteps - seq.shape[0], axis=0)
        return np.concatenate([seq, pad], axis=0)

    def _sigmoid(self, x):
        x = self.np.clip(x, -60.0, 60.0)
        return 1.0 / (1.0 + self.np.exp(-x))

    def _lstm_forward(self, x):
        np = self.np
        w_ih = self.weights["lstm__weight_ih_l0"]
        w_hh = self.weights["lstm__weight_hh_l0"]
        b = self.weights["lstm__bias_ih_l0"] + self.weights["lstm__bias_hh_l0"]
        hidden = w_hh.shape[1]
        h = np.zeros(hidden, dtype=np.float32)
        c = np.zeros(hidden, dtype=np.float32)
        for xt in x:
            gates = w_ih.dot(xt) + w_hh.dot(h) + b
            i, f, g, o = np.split(gates, 4)
            i = self._sigmoid(i)
            f = self._sigmoid(f)
            g = np.tanh(g)
            o = self._sigmoid(o)
            c = f * c + i * g
            h = o * np.tanh(c)
        return h

    def _gru_forward(self, x):
        np = self.np
        w_ih = self.weights["gru__weight_ih_l0"]
        w_hh = self.weights["gru__weight_hh_l0"]
        b_ih = self.weights["gru__bias_ih_l0"]
        b_hh = self.weights["gru__bias_hh_l0"]
        hidden = w_hh.shape[1]
        h = np.zeros(hidden, dtype=np.float32)
        for xt in x:
            gi = w_ih.dot(xt) + b_ih
            gh = w_hh.dot(h) + b_hh
            i_r, i_z, i_n = np.split(gi, 3)
            h_r, h_z, h_n = np.split(gh, 3)
            r = self._sigmoid(i_r + h_r)
            z = self._sigmoid(i_z + h_z)
            n = np.tanh(i_n + r * h_n)
            h = (1.0 - z) * n + z * h
        return h


class QPManager:
    def decide(self, summary: WindowSummary) -> str:
        if summary.attack_class == 0:
            return "allow"
        if summary.attack_class == 1:
            return "queue_depth_limit_or_qp_reallocation"
        if summary.attack_class == 2:
            return "address_diversity_limit"
        if summary.attack_class in (3, 4):
            return "token_bucket_or_wqe_pacing"
        return "rate_limit"


def summarize_window(source: Path, label: Optional[int], detections: List[Detection]) -> WindowSummary:
    records = [d.record for d in detections]
    samples = len(records)
    if samples == 0:
        return WindowSummary(source=str(source), label=label)

    rates = [float(r.get("rate", 0.0)) for r in records]
    ewmas = [float(r.get("midas_ewma", r.get("ewma", 0.0))) for r in records]
    cusums = [float(r.get("midas_cusum", r.get("cusum", 0.0))) for r in records]
    alerts = [int(r.get("midas_alert", r.get("alert", 0))) for r in records]
    lens = [float(r.get("len", 0.0)) for r in records]
    ops: Dict[int, int] = {}
    for r in records:
        op = int(r.get("op", -1))
        ops[op] = ops.get(op, 0) + 1

    return WindowSummary(
        source=str(source),
        label=label,
        samples=samples,
        unique_qps=len({int(r.get("dqp", -1)) for r in records}),
        unique_dips=len({str(r.get("dip", "unknown")) for r in records}),
        avg_rate=sum(rates) / samples,
        avg_ewma=sum(ewmas) / samples,
        max_cusum=max(cusums),
        hot_ratio=sum(1 for a in alerts if a == 2) / samples,
        warm_ratio=sum(1 for a in alerts if a == 1) / samples,
        top_op=max(ops.items(), key=lambda kv: kv[1])[0] if ops else None,
        avg_len=sum(lens) / samples,
    )


def collect_paths(data_dir: Path, patterns: List[str]) -> List[Path]:
    paths: List[Path] = []
    for pattern in patterns:
        paths.extend(Path(p) for p in glob.glob(str(data_dir / pattern)))
    return sorted(set(paths), key=lambda p: p.name)


def compute_binary_metrics(summaries: List[WindowSummary]) -> dict:
    labeled = [s for s in summaries if s.label is not None]
    tp = sum(1 for s in labeled if s.label == 1 and s.attack_class != 0)
    fn = sum(1 for s in labeled if s.label == 1 and s.attack_class == 0)
    fp = sum(1 for s in labeled if s.label == 0 and s.attack_class != 0)
    tn = sum(1 for s in labeled if s.label == 0 and s.attack_class == 0)
    tpr = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    return {
        "labeled_windows": len(labeled),
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "tpr": tpr,
        "fpr": fpr,
    }


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_actions(path: Path, summaries: List[WindowSummary]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for s in summaries:
            fh.write(json.dumps({
                "source": s.source,
                "label": s.label,
                "samples": s.samples,
                "unique_qps": s.unique_qps,
                "hot_ratio": s.hot_ratio,
                "max_cusum": s.max_cusum,
                "attack_class": s.attack_class,
                "attack_name": ATTACK_CLASSES.get(s.attack_class, "Unknown"),
                "action": s.action,
                "mitigation_plan": s.mitigation_plan,
            }, sort_keys=True) + "\n")


def run_offline(args: argparse.Namespace) -> int:
    cfg = DetectorConfig(
        alpha=args.alpha,
        k_qp=args.k_qp,
        k_cont=args.k_cont,
        tau_qp=args.tau_qp,
        tau_cont=args.tau_cont,
        interval_ms=args.interval_ms,
        trust_input_alert=args.trust_input_alert,
    )
    if args.model:
        classifier = NumpyHybridRNNClassifier(Path(args.model))
    else:
        classifier = HeuristicAttackClassifier()
    manager = QPManager()

    patterns = args.glob or ["*.json"]
    paths = collect_paths(Path(args.data_dir), patterns)
    if args.exclude:
        paths = [p for p in paths if not any(fnmatch.fnmatch(p.name, pat) for pat in args.exclude)]
    if not paths:
        print(f"[err] no input files under {args.data_dir} matching {patterns}", file=sys.stderr)
        return 2

    summaries: List[WindowSummary] = []
    for path in paths:
        detector = EwmaCusumDetector(cfg)
        detections = [detector.process(r) for r in read_jsonl(path)]
        label = infer_label_from_name(path)
        summary = summarize_window(path, label, detections)
        records = [d.record for d in detections]
        summary.attack_class = classifier.classify(records, summary)
        summary.action = manager.decide(summary)
        if build_plan is not None:
            summary.mitigation_plan = build_plan(records, summary.attack_class, "tc").to_dict()
        summaries.append(summary)
        print(
            f"{path.name:16s} label={label} samples={summary.samples:5d} "
            f"qps={summary.unique_qps:3d} hot={summary.hot_ratio:5.3f} "
            f"max_cusum={summary.max_cusum:12.2f} "
            f"class={summary.attack_class}:{ATTACK_CLASSES[summary.attack_class]} "
            f"action={summary.action}"
        )

    metrics = compute_binary_metrics(summaries)
    payload = {
        "config": cfg.__dict__,
        "metrics": metrics,
        "windows": [s.__dict__ for s in summaries],
    }

    if args.summary_out:
        write_json(Path(args.summary_out), payload)
    if args.actions_out:
        write_actions(Path(args.actions_out), summaries)

    print("\n=== Binary detection metrics inferred from filenames ===")
    print(json.dumps(metrics, indent=2, sort_keys=True))
    return 0


def follow_jsonl(path: Path, sleep_s: float = 0.2) -> Iterator[dict]:
    with path.open("r", encoding="utf-8-sig", errors="replace") as fh:
        fh.seek(0, os.SEEK_END)
        while True:
            line = fh.readline()
            if not line:
                time.sleep(sleep_s)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def run_tail(args: argparse.Namespace) -> int:
    cfg = DetectorConfig(
        alpha=args.alpha,
        k_qp=args.k_qp,
        tau_qp=args.tau_qp,
        tau_cont=args.tau_cont,
        trust_input_alert=args.trust_input_alert,
    )
    detector = EwmaCusumDetector(cfg)
    path = Path(args.input)
    print(f"[info] tailing {path}; press Ctrl-C to stop")
    for record in follow_jsonl(path):
        det = detector.process(record)
        if det.is_hot or args.print_all:
            print(json.dumps({
                "ts": det.record.get("ts"),
                "dip": det.record.get("dip"),
                "dqp": det.record.get("dqp"),
                "rate": det.record.get("rate"),
                "midas_cusum": det.recomputed_cusum,
                "midas_alert": det.record.get("midas_alert"),
                "container_cusum": det.container_cusum,
            }, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MIDAS rebuild runner")
    sub = parser.add_subparsers(dest="cmd", required=True)

    offline = sub.add_parser("offline", help="run MIDAS over JSONL trace files")
    offline.add_argument("--data-dir", default=".")
    offline.add_argument("--glob", action="append", help="input glob; repeatable")
    offline.add_argument("--exclude", action="append", default=[])
    offline.add_argument("--summary-out")
    offline.add_argument("--actions-out")
    offline.add_argument("--alpha", type=float, default=0.3)
    offline.add_argument("--k-qp", type=float, default=0.0)
    offline.add_argument("--k-cont", type=float, default=0.0)
    offline.add_argument("--tau-qp", type=float, default=1_000_000.0)
    offline.add_argument("--tau-cont", type=float, default=1_000_000.0)
    offline.add_argument("--interval-ms", type=int, default=100)
    offline.add_argument("--model", help="exported .npz LSTM+GRU classifier")
    offline.add_argument("--trust-input-alert", action="store_true", help="reuse alert fields already present in input telemetry")
    offline.set_defaults(func=run_offline)

    tail = sub.add_parser("tail", help="follow a live JSONL telemetry file")
    tail.add_argument("--input", required=True)
    tail.add_argument("--print-all", action="store_true")
    tail.add_argument("--alpha", type=float, default=0.3)
    tail.add_argument("--k-qp", type=float, default=0.0)
    tail.add_argument("--tau-qp", type=float, default=1_000_000.0)
    tail.add_argument("--tau-cont", type=float, default=1_000_000.0)
    tail.add_argument("--trust-input-alert", action="store_true", help="reuse alert fields already present in input telemetry")
    tail.set_defaults(func=run_tail)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
