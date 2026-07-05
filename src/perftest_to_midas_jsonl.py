#!/usr/bin/env python3
"""Convert perftest output into MIDAS JSONL telemetry.

This is a live-test adapter for the rebuilt MIDAS control plane. It lets the
server-side runner consume real `ib_write_bw --run_infinitely --duration 1`
logs before the packet-header RNIC monitor is fully restored.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from typing import Iterable, Optional


ADDR_RE = re.compile(
    r"(?P<side>local|remote) address:\s+"
    r"LID\s+(?P<lid>[0-9a-fA-F]+)\s+"
    r"QPN\s+0x(?P<qpn>[0-9a-fA-F]+)\s+"
    r"PSN\s+0x(?P<psn>[0-9a-fA-F]+)\s+"
    r"RKey\s+0x(?P<rkey>[0-9a-fA-F]+)",
)
IPV4_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
ROCE_V4_GID_RE = re.compile(r"GID:\s*(?:[0-9a-fA-F]+:){10}255:255:(\d+):(\d+):(\d+):(\d+)")
ROW_RE = re.compile(
    r"^\s*(?P<bytes>\d+)\s+"
    r"(?P<iters>\d+)\s+"
    r"(?P<peak>[\d.]+)\s+"
    r"(?P<avg>[\d.]+)\s+"
    r"(?P<msg>[\d.]+)",
    re.MULTILINE,
)


def parse_log(text: str):
    addrs = {}
    for m in ADDR_RE.finditer(text):
        addrs[m.group("side")] = {
            "lid": int(m.group("lid"), 16),
            "qpn": int(m.group("qpn"), 16),
            "psn": int(m.group("psn"), 16),
            "rkey": int(m.group("rkey"), 16),
        }

    gids = IPV4_RE.findall(text)
    if not gids:
        gids = [".".join(parts) for parts in ROCE_V4_GID_RE.findall(text)]
    sip = gids[0] if len(gids) >= 1 else "0.0.0.0"
    dip = gids[1] if len(gids) >= 2 else "0.0.0.0"
    local = addrs.get("local", {})
    remote = addrs.get("remote", {})

    rows = []
    for idx, m in enumerate(ROW_RE.finditer(text)):
        avg_gbps = float(m.group("avg"))
        bytes_per_sec = avg_gbps * 1_000_000_000.0 / 8.0
        rows.append({
            "idx": idx,
            "len": int(m.group("bytes")),
            "iters": int(m.group("iters")),
            "rate": bytes_per_sec,
            "avg_gbps": avg_gbps,
        })
    return sip, dip, local, remote, rows


def convert(input_path: Path, output_path: Path, op: int, start_ts: Optional[float]) -> int:
    text = input_path.read_text(encoding="utf-8", errors="replace")
    sip, dip, local, remote, rows = parse_log(text)
    dqp = int(remote.get("qpn", 0))
    srcqp = int(local.get("qpn", 0))
    psn_base = int(local.get("psn", 0x10000))
    output_path.parent.mkdir(parents=True, exist_ok=True)

    ewma = None
    cusum = 0.0
    alpha = 0.3
    ts0 = start_ts if start_ts is not None else time.time()

    with output_path.open("w", encoding="utf-8") as fh:
        for row in rows:
            rate = row["rate"]
            if ewma is None:
                ewma = rate
            else:
                ewma = alpha * rate + (1.0 - alpha) * ewma
            cusum = max(0.0, cusum + rate - ewma)
            alert = 2 if cusum >= 1_000_000.0 else (1 if cusum >= 500_000.0 else 0)
            rec = {
                "ts": ts0 + row["idx"],
                "sip": sip,
                "dip": dip,
                "op": op,
                "dqp": dqp,
                "srcqp": srcqp,
                "psn": psn_base + row["idx"],
                "remote_psn": int(remote.get("psn", 0)) + row["idx"],
                "r_key": int(remote.get("rkey", 0)),
                "local_r_key": int(local.get("rkey", 0)),
                "len": row["len"],
                "rate": round(rate, 2),
                "ewma": round(ewma, 2),
                "cusum": round(cusum, 2),
                "alert": alert,
                "source": str(input_path),
                "avg_gbps": row["avg_gbps"],
            }
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
    return len(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--op", type=int, default=17)
    parser.add_argument("--start-ts", type=float)
    args = parser.parse_args()

    count = convert(Path(args.input), Path(args.output), args.op, args.start_ts)
    print(f"converted {count} samples -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
