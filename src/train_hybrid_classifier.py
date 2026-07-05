#!/usr/bin/env python3
"""Train and export MIDAS LSTM+GRU attack classifier.

The exported `.npz` file is intentionally consumable by the dependency-light
server runtime in `midas.py`, so the server does not need PyTorch installed.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

import numpy as np
import torch
import torch.nn as nn


WINDOW_TO_CLASS = {
    "10-20": 0,
    "30-40": 0,
    "50-60": 0,
    "70-80": 0,
    "90-100": 0,
    "110-120": 0,
    "0-10": 1,
    "80-90": 1,
    "20-30": 2,
    "100-110": 2,
    "40-50": 3,
    "60-70": 4,
}


def read_jsonl(path: Path) -> List[dict]:
    rows = []
    with path.open("r", encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def build_sequence(records: List[dict]) -> np.ndarray:
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
    return np.asarray(feats, dtype=np.float32)


def pad_or_trim(seq: np.ndarray, timesteps: int) -> np.ndarray:
    if seq.shape[0] >= timesteps:
        return seq[:timesteps]
    pad = np.repeat(seq[-1:, :], timesteps - seq.shape[0], axis=0)
    return np.concatenate([seq, pad], axis=0)


def augment(seq: np.ndarray) -> np.ndarray:
    out = seq.copy()
    cont_idx = [0, 1, 2, 4, 5, 6, 7, 8, 9, 10]
    scale = np.random.uniform(0.92, 1.08)
    noise = np.random.normal(0.0, 0.015, size=(seq.shape[0], len(cont_idx)))
    for j, idx in enumerate(cont_idx):
        out[:, idx] = out[:, idx] * scale + noise[:, j]
    return out.astype(np.float32)


class HybridRNN(nn.Module):
    def __init__(self, input_dim: int = 11, hidden_dim: int = 16, num_classes: int = 5):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, batch_first=True)
        self.gru = nn.GRU(input_dim, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim * 2, num_classes)

    def forward(self, x):
        lstm_out, _ = self.lstm(x)
        gru_out, _ = self.gru(x)
        h = torch.cat([lstm_out[:, -1, :], gru_out[:, -1, :]], dim=1)
        return self.fc(h)


def load_dataset(data_dir: Path, timesteps: int, aug_per_sample: int) -> Tuple[np.ndarray, np.ndarray]:
    X, y = [], []
    for name, cls in WINDOW_TO_CLASS.items():
        candidates = [data_dir / f"{name.replace('-', '_')}.json", data_dir / f"{name}.json"]
        path = next((p for p in candidates if p.exists()), None)
        if path is None:
            continue
        seq = pad_or_trim(build_sequence(read_jsonl(path)), timesteps)
        X.append(seq)
        y.append(cls)
        for _ in range(aug_per_sample):
            X.append(augment(seq))
            y.append(cls)
    if not X:
        raise RuntimeError(f"no training windows found in {data_dir}")
    return np.stack(X).astype(np.float32), np.asarray(y, dtype=np.int64)


def normalize(X: np.ndarray, mean: np.ndarray | None = None, std: np.ndarray | None = None):
    if mean is None:
        mean = X.reshape(-1, X.shape[-1]).mean(axis=0)
    if std is None:
        std = X.reshape(-1, X.shape[-1]).std(axis=0)
    std = np.where(std < 1e-6, 1.0, std)
    return (X - mean) / std, mean, std


def stratified_kfold_indices(y: np.ndarray, folds: int, seed: int) -> List[Tuple[np.ndarray, np.ndarray]]:
    if folds < 2:
        return []
    rng = np.random.default_rng(seed)
    by_class: Dict[int, List[int]] = {}
    for idx, cls in enumerate(y.tolist()):
        by_class.setdefault(int(cls), []).append(idx)
    splits: List[List[int]] = [[] for _ in range(folds)]
    for indices in by_class.values():
        shuffled = np.asarray(indices, dtype=np.int64)
        rng.shuffle(shuffled)
        for part, fold_indices in enumerate(np.array_split(shuffled, folds)):
            splits[part].extend(fold_indices.tolist())
    all_idx = np.arange(len(y), dtype=np.int64)
    out = []
    for fold in range(folds):
        val_idx = np.asarray(sorted(splits[fold]), dtype=np.int64)
        train_mask = np.ones(len(y), dtype=bool)
        train_mask[val_idx] = False
        out.append((all_idx[train_mask], val_idx))
    return out


def metrics(y_true: np.ndarray, y_pred: np.ndarray, num_classes: int = 5) -> Dict[str, float]:
    f1s, supports = [], []
    for cls in range(num_classes):
        tp = int(((y_true == cls) & (y_pred == cls)).sum())
        fp = int(((y_true != cls) & (y_pred == cls)).sum())
        fn = int(((y_true == cls) & (y_pred != cls)).sum())
        support = int((y_true == cls).sum())
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2.0 * precision * recall / (precision + recall) if precision + recall else 0.0
        f1s.append(f1)
        supports.append(support)
    supports_arr = np.asarray(supports, dtype=np.float64)
    macro_f1 = float(np.mean(f1s))
    weighted_f1 = float(np.average(f1s, weights=supports_arr)) if supports_arr.sum() else 0.0
    accuracy = float((y_true == y_pred).mean()) if len(y_true) else 0.0
    return {"accuracy": accuracy, "macro_f1": macro_f1, "weighted_f1": weighted_f1}


def fake_quant_tensor(tensor: torch.Tensor, bits: int = 8) -> torch.Tensor:
    qmax = (1 << (bits - 1)) - 1
    max_abs = tensor.detach().abs().max()
    if float(max_abs) < 1e-12:
        return tensor
    scale = max_abs / qmax
    quant = torch.clamp(torch.round(tensor / scale), -qmax - 1, qmax)
    return quant * scale


def apply_weight_fake_quant(model: nn.Module, bits: int = 8) -> None:
    with torch.no_grad():
        for param in model.parameters():
            param.copy_(fake_quant_tensor(param, bits=bits))


def train_model(
    Xn: np.ndarray,
    y: np.ndarray,
    epochs: int,
    seed: int,
    verbose: bool = False,
    qat_int8: bool = False,
) -> HybridRNN:
    torch.manual_seed(seed)
    model = HybridRNN(input_dim=Xn.shape[-1])
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.CrossEntropyLoss()
    xb = torch.from_numpy(Xn.astype(np.float32))
    yb = torch.from_numpy(y.astype(np.int64))

    for epoch in range(1, epochs + 1):
        model.train()
        opt.zero_grad()
        logits = model(xb)
        loss = loss_fn(logits, yb)
        loss.backward()
        opt.step()
        if qat_int8:
            apply_weight_fake_quant(model, bits=8)
        if verbose and (epoch == 1 or epoch % 25 == 0 or epoch == epochs):
            pred = logits.argmax(dim=1)
            acc = (pred == yb).float().mean().item()
            print(f"epoch={epoch:03d} loss={loss.item():.4f} train_acc={acc:.3f}")
    return model


def cross_validate(X: np.ndarray, y: np.ndarray, folds: int, epochs: int, seed: int, qat_int8: bool) -> None:
    scores = []
    for fold_no, (train_idx, val_idx) in enumerate(stratified_kfold_indices(y, folds, seed), start=1):
        X_train, mean, std = normalize(X[train_idx])
        X_val, _, _ = normalize(X[val_idx], mean, std)
        model = train_model(X_train, y[train_idx], epochs=epochs, seed=seed + fold_no, qat_int8=qat_int8)
        model.eval()
        with torch.no_grad():
            pred = model(torch.from_numpy(X_val.astype(np.float32))).argmax(dim=1).cpu().numpy()
        score = metrics(y[val_idx], pred)
        scores.append(score)
        print(
            f"fold={fold_no} accuracy={score['accuracy']:.3f} "
            f"macro_f1={score['macro_f1']:.3f} weighted_f1={score['weighted_f1']:.3f} n={len(val_idx)}"
        )
    if scores:
        avg = {k: float(np.mean([s[k] for s in scores])) for k in scores[0]}
        print(
            f"cv_mean accuracy={avg['accuracy']:.3f} "
            f"macro_f1={avg['macro_f1']:.3f} weighted_f1={avg['weighted_f1']:.3f}"
        )


def export_npz(model: HybridRNN, mean: np.ndarray, std: np.ndarray, output: Path, timesteps: int):
    state = model.state_dict()
    payload = {
        "feature_mean": mean.astype(np.float32),
        "feature_std": std.astype(np.float32),
        "timesteps": np.asarray([timesteps], dtype=np.int64),
    }
    for key, val in state.items():
        payload[key.replace(".", "__")] = val.detach().cpu().numpy().astype(np.float32)
    output.parent.mkdir(parents=True, exist_ok=True)
    np.savez(output, **payload)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timesteps", type=int, default=100)
    parser.add_argument("--epochs", type=int, default=200)
    parser.add_argument("--cv-folds", type=int, default=5)
    parser.add_argument("--cv-epochs", type=int, default=80)
    parser.add_argument("--aug-per-sample", type=int, default=30)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--qat-int8", action="store_true", help="apply INT8 fake-quantization during training")
    args = parser.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)

    X, y = load_dataset(Path(args.data_dir), args.timesteps, args.aug_per_sample)
    if args.cv_folds >= 2:
        cross_validate(X, y, folds=args.cv_folds, epochs=args.cv_epochs, seed=args.seed, qat_int8=args.qat_int8)

    Xn, mean, std = normalize(X)
    model = train_model(Xn, y, epochs=args.epochs, seed=args.seed, verbose=True, qat_int8=args.qat_int8)

    model.eval()
    with torch.no_grad():
        pred = model(torch.from_numpy(Xn.astype(np.float32))).argmax(dim=1).cpu().numpy()
    print("final predictions:")
    for cls in range(5):
        mask = y == cls
        if mask.any():
            print(f"  class {cls}: acc={(pred[mask] == y[mask]).mean():.3f} n={mask.sum()}")

    export_npz(model, mean, std, Path(args.output), args.timesteps)
    print(f"exported {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
