#!/usr/bin/env python3
"""Forward host-side MIDAS telemetry JSONL to a BlueField Arm worker."""

from __future__ import annotations

import argparse
import json
import os
import socket
import time
from pathlib import Path
from typing import Iterator


def iter_existing(path: Path) -> Iterator[str]:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield line


def iter_tail(path: Path, sleep_s: float) -> Iterator[str]:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        fh.seek(0, 2)
        while True:
            line = fh.readline()
            if not line:
                time.sleep(sleep_s)
                continue
            line = line.strip()
            if line:
                yield line


def validate_json(line: str) -> bool:
    try:
        json.loads(line)
        return True
    except json.JSONDecodeError:
        return False


def connect(host: str, port: int, retry_s: float) -> socket.socket:
    while True:
        last_error = None
        try:
            infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        except OSError as exc:
            infos = []
            last_error = exc
        for family, socktype, proto, _, sockaddr in infos:
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(5)
            try:
                sock.connect(sockaddr)
                sock.settimeout(None)
                return sock
            except OSError as exc:
                last_error = exc
                sock.close()
        print(f"[forwarder] connect failed: {last_error}; retrying in {retry_s}s", flush=True)
        time.sleep(retry_s)


def forward(args: argparse.Namespace) -> int:
    path = Path(args.input)
    iterator = iter_tail(path, args.sleep) if args.follow else iter_existing(path)
    sock = connect(args.arm_host, args.arm_port, args.retry)
    sent = 0
    try:
        for line in iterator:
            if args.validate and not validate_json(line):
                print("[forwarder] skipping invalid JSON line", flush=True)
                continue
            payload = (line + "\n").encode("utf-8")
            while True:
                try:
                    sock.sendall(payload)
                    sent += 1
                    if args.verbose:
                        print(f"[forwarder] sent {sent}", flush=True)
                    break
                except OSError as exc:
                    print(f"[forwarder] send failed: {exc}; reconnecting", flush=True)
                    sock.close()
                    sock = connect(args.arm_host, args.arm_port, args.retry)
            if args.rate_limit > 0:
                time.sleep(1.0 / args.rate_limit)
    finally:
        sock.close()
    print(f"[forwarder] done; sent={sent}", flush=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Forward MIDAS JSONL telemetry to BlueField Arm")
    parser.add_argument("--input", required=True, help="JSONL telemetry file")
    parser.add_argument("--arm-host", default=os.environ.get("ARM_HOST", "bluefield-arm.local"))
    parser.add_argument("--arm-port", type=int, default=44991)
    parser.add_argument("--follow", action="store_true")
    parser.add_argument("--sleep", type=float, default=0.2)
    parser.add_argument("--retry", type=float, default=2.0)
    parser.add_argument("--rate-limit", type=float, default=0.0, help="records per second; 0 disables")
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main() -> int:
    return forward(build_parser().parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
