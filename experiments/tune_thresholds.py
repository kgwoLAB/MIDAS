#!/usr/bin/env python3
"""Sweep EWMA-CUSUM thresholds for labeled MIDAS windows."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from midas import (  # noqa: E402
    DetectorConfig,
    EwmaCusumDetector,
    HeuristicAttackClassifier,
    NumpyHybridRNNClassifier,
    QPManager,
    collect_paths,
    infer_label_from_name,
    read_jsonl,
    summarize_window,
)


def parse_grid(text: str) -> List[float]:
    return [float(part) for part in text.split(",") if part.strip()]


def f1(tp: int, fp: int, fn: int) -> float:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return 2.0 * precision * recall / (precision + recall) if precision + recall else 0.0


def evaluate(paths: List[Path], cfg: DetectorConfig, model: str | None) -> Dict[str, float]:
    classifier = NumpyHybridRNNClassifier(Path(model)) if model else HeuristicAttackClassifier()
    manager = QPManager()
    tp = tn = fp = fn = 0
    labeled = 0
    for path in paths:
        label = infer_label_from_name(path)
        if label is None:
            continue
        detector = EwmaCusumDetector(cfg)
        detections = [detector.process(r) for r in read_jsonl(path)]
        summary = summarize_window(path, label, detections)
        summary.attack_class = classifier.classify([d.record for d in detections], summary)
        summary.action = manager.decide(summary)
        pred_attack = summary.attack_class != 0
        true_attack = label == 1
        labeled += 1
        if true_attack and pred_attack:
            tp += 1
        elif true_attack and not pred_attack:
            fn += 1
        elif not true_attack and pred_attack:
            fp += 1
        else:
            tn += 1
    accuracy = (tp + tn) / labeled if labeled else 0.0
    return {
        "labeled": float(labeled),
        "tp": float(tp),
        "tn": float(tn),
        "fp": float(fp),
        "fn": float(fn),
        "accuracy": accuracy,
        "f1": f1(tp, fp, fn),
        "tpr": tp / (tp + fn) if tp + fn else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--glob", action="append")
    parser.add_argument("--model")
    parser.add_argument("--alpha", type=float, default=0.3)
    parser.add_argument("--k-qp", type=float, default=0.0)
    parser.add_argument("--k-cont", type=float, default=0.0)
    parser.add_argument("--tau-qp-grid", default="100000,250000,500000,1000000,2500000,5000000")
    parser.add_argument("--tau-cont-grid", default="4,8,10,16,32,64")
    parser.add_argument("--interval-ms", type=int, default=100)
    parser.add_argument("--csv-out", default="experiments/threshold_sweep.csv")
    parser.add_argument("--json-out", default="experiments/threshold_best.json")
    args = parser.parse_args()

    paths = collect_paths(Path(args.data_dir), args.glob or ["*.json"])
    if not paths:
        raise RuntimeError(f"no input files under {args.data_dir}")

    rows = []
    best = None
    for tau_qp in parse_grid(args.tau_qp_grid):
        for tau_cont in parse_grid(args.tau_cont_grid):
            cfg = DetectorConfig(
                alpha=args.alpha,
                k_qp=args.k_qp,
                k_cont=args.k_cont,
                tau_qp=tau_qp,
                tau_cont=tau_cont,
                interval_ms=args.interval_ms,
            )
            score = evaluate(paths, cfg, args.model)
            row = {"tau_qp": tau_qp, "tau_cont": tau_cont, **score}
            rows.append(row)
            if best is None or (row["f1"], row["accuracy"], -row["fpr"]) > (
                best["f1"],
                best["accuracy"],
                -best["fpr"],
            ):
                best = row

    csv_path = Path(args.csv_out)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    json_path = Path(args.json_out)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(best, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(best, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
