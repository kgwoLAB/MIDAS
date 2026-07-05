#!/usr/bin/env python3
"""Export MIDAS RNN weights and one input window as DPA fixed-point headers.

The paper model is represented in the host runtime as exported LSTM-GRU numpy
weights. For DPA execution, this script converts those floating-point weights
and one normalized input window into scaled integer arrays. This is the DPA
fixed-point/INT8-style path; the DPA device compiler does not execute the
original floating-point model directly.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

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

from midas import NumpyHybridRNNClassifier, read_jsonl, EwmaCusumDetector, DetectorConfig, summarize_window  # noqa: E402


def qarr(arr: np.ndarray, scale: int) -> np.ndarray:
    return np.rint(arr.astype(np.float64) * scale).astype(np.int32)


def emit_i32(name: str, arr: np.ndarray) -> str:
    flat = arr.reshape(-1)
    values = ", ".join(str(int(v)) for v in flat)
    return f"static const int {name}[{flat.size}] = {{ {values} }};\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="")
    parser.add_argument("--trace", required=True)
    parser.add_argument("--weights-output", required=True)
    parser.add_argument("--input-output", required=True)
    parser.add_argument("--scale", type=int, default=1024)
    args = parser.parse_args()

    root = find_root()
    model = Path(args.model) if args.model else root / "models" / "midas_hybrid_rnn.npz"
    classifier = NumpyHybridRNNClassifier(model)
    weights = np.load(model)

    wout = Path(args.weights_output)
    wout.parent.mkdir(parents=True, exist_ok=True)
    parts = [
        "/* Auto-generated fixed-point DPA weights. */\n",
        "#ifndef MIDAS_RNN_FIXED_WEIGHTS_H\n#define MIDAS_RNN_FIXED_WEIGHTS_H\n\n",
        f"#define MIDAS_Q {args.scale}\n",
        f"#define MIDAS_FEATURE_DIM {weights['feature_mean'].shape[0]}\n",
        f"#define MIDAS_HIDDEN_DIM {weights['lstm__weight_hh_l0'].shape[1]}\n",
        f"#define MIDAS_TIMESTEPS {int(weights['timesteps'][0])}\n",
        f"#define MIDAS_CLASSES {weights['fc__bias'].shape[0]}\n\n",
    ]
    for key in [
        "lstm__weight_ih_l0",
        "lstm__weight_hh_l0",
        "lstm__bias_ih_l0",
        "lstm__bias_hh_l0",
        "gru__weight_ih_l0",
        "gru__weight_hh_l0",
        "gru__bias_ih_l0",
        "gru__bias_hh_l0",
        "fc__weight",
        "fc__bias",
    ]:
        parts.append(emit_i32("midas_" + key.replace("__", "_") + "_q", qarr(weights[key], args.scale)))
    parts.append("\n#endif\n")
    wout.write_text("".join(parts), encoding="ascii")

    detector = EwmaCusumDetector(DetectorConfig())
    detections = [detector.process(r) for r in read_jsonl(Path(args.trace))]
    summary = summarize_window(Path(args.trace), None, detections)
    raw = classifier._build_sequence([d.record for d in detections])
    norm = ((raw - classifier.mean) / classifier.std).astype(np.float32)
    cls = classifier.classify([d.record for d in detections], summary)

    iout = Path(args.input_output)
    iout.parent.mkdir(parents=True, exist_ok=True)
    iout.write_text(
        "/* Auto-generated fixed-point DPA input. */\n"
        "#ifndef MIDAS_RNN_FIXED_INPUT_H\n#define MIDAS_RNN_FIXED_INPUT_H\n\n"
        f"#define MIDAS_EXPECTED_CLASS {cls}\n"
        + emit_i32("midas_input_window_q", qarr(norm, args.scale))
        + "\n#endif\n",
        encoding="ascii",
    )
    print(f"wrote {wout} and {iout}; expected_class={cls}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
