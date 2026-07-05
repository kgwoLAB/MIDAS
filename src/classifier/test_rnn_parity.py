#!/usr/bin/env python3
"""Compare C MIDAS RNN inference against the Python numpy reference."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def find_root() -> Path:
    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        if (parent / "models" / "midas_hybrid_rnn.npz").exists():
            return parent
    return here.parents[2]


ROOT = find_root()
for item in [ROOT / "src", ROOT]:
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))

from midas import NumpyHybridRNNClassifier, read_jsonl, summarize_window, EwmaCusumDetector, DetectorConfig  # noqa: E402


def compile_c(source_dir: Path, output: Path) -> None:
    cmd = [
        "gcc",
        "-std=c11",
        "-O2",
        "-DMIDAS_RNN_MAIN",
        str(source_dir / "midas_rnn_infer.c"),
        "-lm",
        "-o",
        str(output),
    ]
    subprocess.run(cmd, check=True)


def python_class(model: Path, trace: Path) -> int:
    detector = EwmaCusumDetector(DetectorConfig())
    detections = [detector.process(r) for r in read_jsonl(trace)]
    summary = summarize_window(trace, None, detections)
    classifier = NumpyHybridRNNClassifier(model)
    return classifier.classify([d.record for d in detections], summary)


def c_class(binary: Path, trace: Path) -> int:
    proc = subprocess.run([str(binary), str(trace)], check=True, text=True, capture_output=True)
    return int(json.loads(proc.stdout)["class"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=str(ROOT / "models" / "midas_hybrid_rnn.npz"))
    parser.add_argument("--trace", action="append", required=True)
    parser.add_argument("--binary", default=str(ROOT / "experiments" / "midas_rnn_infer"))
    args = parser.parse_args()

    source_dir = Path(__file__).resolve().parent
    binary = Path(args.binary)
    binary.parent.mkdir(parents=True, exist_ok=True)
    compile_c(source_dir, binary)

    ok = True
    for item in args.trace:
        trace = Path(item)
        py_cls = python_class(Path(args.model), trace)
        c_cls = c_class(binary, trace)
        print(f"{trace}: python={py_cls} c={c_cls}")
        ok = ok and py_cls == c_cls
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
