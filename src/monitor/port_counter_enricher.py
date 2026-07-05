#!/usr/bin/env python3
"""Attach BlueField/Linux port-counter features to MIDAS JSONL telemetry."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, TextIO


COUNTER_RE = re.compile(r"^\s*([^:]+):\s*(-?\d+)\s*$")


@dataclass
class PortSample:
    ts: float
    counters: Dict[str, int]


def parse_ethtool_stats(text: str) -> Dict[str, int]:
    counters: Dict[str, int] = {}
    for line in text.splitlines():
        match = COUNTER_RE.match(line)
        if match:
            counters[match.group(1).strip()] = int(match.group(2))
    return counters


def read_ethtool_stats(iface: str) -> Dict[str, int]:
    proc = subprocess.run(
        ["ethtool", "-S", iface],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return parse_ethtool_stats(proc.stdout)


def sum_matching(counters: Dict[str, int], includes: Iterable[str], excludes: Iterable[str] = ()) -> int:
    includes_l = tuple(s.lower() for s in includes)
    excludes_l = tuple(s.lower() for s in excludes)
    total = 0
    for name, value in counters.items():
        lname = name.lower()
        if all(part in lname for part in includes_l) and not any(part in lname for part in excludes_l):
            total += value
    return total


def first_positive(counters: Dict[str, int], names: Iterable[str]) -> int:
    for name in names:
        if name in counters:
            return max(0, counters[name])
    return 0


def derive_features(current: Dict[str, int], previous: Dict[str, int] | None) -> Dict[str, int]:
    prev = previous or {}
    delta = {name: max(0, value - prev.get(name, value)) for name, value in current.items()}

    rx_data = first_positive(
        delta,
        [
            "rx_bytes",
            "rx_vport_rdma_unicast_bytes",
            "rx_vport_unicast_bytes",
            "rx_prio0_bytes",
        ],
    )
    tx_data = first_positive(
        delta,
        [
            "tx_bytes",
            "tx_vport_rdma_unicast_bytes",
            "tx_vport_unicast_bytes",
            "tx_prio0_bytes",
        ],
    )
    if rx_data == 0:
        rx_data = sum_matching(delta, ["rx", "bytes"])
    if tx_data == 0:
        tx_data = sum_matching(delta, ["tx", "bytes"])

    pause = (
        sum_matching(delta, ["pause"], ["duration", "prio"])
        + sum_matching(delta, ["pause", "frames"])
        + sum_matching(delta, ["pause", "packets"])
    )
    pause_dur = (
        sum_matching(delta, ["pause", "duration"])
        + sum_matching(delta, ["pause", "time"])
        + sum_matching(delta, ["pause", "quanta"])
    )
    cache_hit = sum_matching(delta, ["cache", "hit"])
    return {
        "rx_data": int(rx_data),
        "tx_data": int(tx_data),
        "pause": int(pause),
        "pause_dur": int(pause_dur),
        "cache_hit": int(cache_hit),
    }


def iter_jsonl(path: Path | None, follow: bool) -> Iterator[dict]:
    if path is None:
        for line in sys.stdin:
            line = line.strip()
            if line:
                yield json.loads(line)
        return

    with path.open("r", encoding="utf-8-sig", errors="replace") as fh:
        while True:
            pos = fh.tell()
            line = fh.readline()
            if line:
                line = line.strip()
                if line:
                    yield json.loads(line)
                continue
            if not follow:
                break
            fh.seek(pos)
            time.sleep(0.05)


def open_output(path: Path | None) -> TextIO:
    if path is None:
        return sys.stdout
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("w", encoding="utf-8")


def enrich_stream(
    input_path: Path | None,
    output_path: Path | None,
    iface: str,
    interval_ms: int,
    follow: bool,
    allow_missing: bool,
) -> int:
    previous: Dict[str, int] | None = None
    features = {"rx_data": 0, "tx_data": 0, "pause": 0, "pause_dur": 0, "cache_hit": 0}
    next_sample = 0.0
    rows = 0

    with open_output(output_path) as out:
        for rec in iter_jsonl(input_path, follow):
            now = float(rec.get("ts", time.time()))
            if now >= next_sample:
                try:
                    current = read_ethtool_stats(iface)
                    features = derive_features(current, previous)
                    previous = current
                except (FileNotFoundError, subprocess.CalledProcessError) as exc:
                    if not allow_missing:
                        raise RuntimeError(f"failed to read ethtool counters for {iface}: {exc}") from exc
                    features = {"rx_data": 0, "tx_data": 0, "pause": 0, "pause_dur": 0, "cache_hit": 0}
                next_sample = now + max(interval_ms, 1) / 1000.0

            for key, value in features.items():
                rec[key] = value
                rec[f"port_{key}"] = value
            out.write(json.dumps(rec, sort_keys=True) + "\n")
            out.flush()
            rows += 1
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", help="MIDAS JSONL input; stdin when omitted")
    parser.add_argument("--output", help="enriched JSONL output; stdout when omitted")
    parser.add_argument("--iface", required=True)
    parser.add_argument("--interval-ms", type=int, default=100)
    parser.add_argument("--follow", action="store_true")
    parser.add_argument("--allow-missing", action="store_true")
    args = parser.parse_args()

    rows = enrich_stream(
        Path(args.input) if args.input else None,
        Path(args.output) if args.output else None,
        args.iface,
        args.interval_ms,
        args.follow,
        args.allow_missing,
    )
    print(f"enriched {rows} records", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
