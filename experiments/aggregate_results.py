#!/usr/bin/env python3
"""Aggregate MIDAS summary JSON files into a compact CSV."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def rows_from_summary(path: Path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    metrics = payload.get("metrics", {})
    for window in payload.get("windows", []):
        yield {
            "summary": str(path),
            "source": window.get("source"),
            "label": window.get("label"),
            "attack_class": window.get("attack_class"),
            "action": window.get("action"),
            "samples": window.get("samples"),
            "unique_qps": window.get("unique_qps"),
            "hot_ratio": window.get("hot_ratio"),
            "max_cusum": window.get("max_cusum"),
            "tpr": metrics.get("tpr"),
            "fpr": metrics.get("fpr"),
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", action="append", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    paths = []
    for pattern in args.input:
        paths.extend(Path().glob(pattern))

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "summary",
        "source",
        "label",
        "attack_class",
        "action",
        "samples",
        "unique_qps",
        "hot_ratio",
        "max_cusum",
        "tpr",
        "fpr",
    ]
    with out.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for path in sorted(set(paths)):
            for row in rows_from_summary(path):
                writer.writerow(row)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
