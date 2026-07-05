#!/usr/bin/env python3
"""Canonical MIDAS RoCE/QP telemetry event schema."""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional


@dataclass
class RoceQpEvent:
    ts: float
    sip: str
    dip: str
    dqp: int
    op: int = 17
    srcqp: int = 0
    psn: int = 0
    remote_psn: int = 0
    r_key: int = 0
    len: int = 0
    rate: float = 0.0
    ewma: float = 0.0
    cusum: float = 0.0
    alert: int = 0
    source: str = ""

    @classmethod
    def from_mapping(cls, data: dict, source: str = "") -> "RoceQpEvent":
        now = time.time()
        return cls(
            ts=float(data.get("ts", now)),
            sip=str(data.get("sip", "0.0.0.0")),
            dip=str(data.get("dip", "0.0.0.0")),
            srcqp=int(data.get("srcqp", data.get("sqpn", 0)) or 0),
            dqp=int(data.get("dqp", data.get("destqp", 0)) or 0),
            psn=int(data.get("psn", 0) or 0),
            remote_psn=int(data.get("remote_psn", 0) or 0),
            op=int(data.get("op", data.get("opcode", 17)) or 17),
            r_key=int(data.get("r_key", data.get("rkey", 0)) or 0),
            len=int(float(data.get("len", data.get("length", 0)) or 0)),
            rate=float(data.get("rate", 0.0) or 0.0),
            ewma=float(data.get("ewma", 0.0) or 0.0),
            cusum=float(data.get("cusum", 0.0) or 0.0),
            alert=int(data.get("alert", 0) or 0),
            source=str(data.get("source", source)),
        )

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


def read_events(path: Path) -> Iterator[RoceQpEvent]:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield RoceQpEvent.from_mapping(json.loads(line), f"{path}:{line_no}")
            except Exception as exc:
                print(f"[warn] {path}:{line_no}: {exc}", file=sys.stderr)


def validate_file(input_path: Path, output_path: Optional[Path]) -> int:
    count = 0
    out = output_path.open("w", encoding="utf-8") if output_path else None
    try:
        for event in read_events(input_path):
            count += 1
            if out:
                out.write(event.to_json() + "\n")
    finally:
        if out:
            out.close()
    print(f"validated {count} events")
    return 0 if count else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output")
    args = parser.parse_args()
    return validate_file(Path(args.input), Path(args.output) if args.output else None)


if __name__ == "__main__":
    raise SystemExit(main())
