#!/usr/bin/env python3
"""Apply MIDAS QP Manager actions.

Current production-safe backend:
- Linux `tc` HTB per destination IP on the RDMA netdev.

This is not a firmware QP resize implementation. It is the restored, working
enforcement path available on the current commodity BlueField host. It maps
MIDAS QP/container decisions to traffic shaping on the RDMA egress interface.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Optional


def run(cmd: list[str], sudo_pass: Optional[str] = None) -> subprocess.CompletedProcess:
    if sudo_pass:
        proc = subprocess.run(
            ["sudo", "-S", *cmd],
            input=sudo_pass + "\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    else:
        proc = subprocess.run(
            ["sudo", *cmd],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    print("+", " ".join(["sudo", *cmd]))
    print(proc.stdout, end="")
    return proc


def apply_rate_limit(iface: str, dst_ip: str, rate: str, sudo_pass: Optional[str]) -> int:
    commands = [
        ["tc", "qdisc", "replace", "dev", iface, "root", "handle", "1:", "htb", "default", "30"],
        ["tc", "class", "replace", "dev", iface, "parent", "1:", "classid", "1:1", "htb", "rate", "100gbit", "ceil", "100gbit"],
        ["tc", "class", "replace", "dev", iface, "parent", "1:1", "classid", "1:10", "htb", "rate", rate, "ceil", rate],
        ["tc", "class", "replace", "dev", iface, "parent", "1:1", "classid", "1:30", "htb", "rate", "100gbit", "ceil", "100gbit"],
        ["tc", "filter", "replace", "dev", iface, "protocol", "ip", "parent", "1:", "prio", "1", "u32", "match", "ip", "dst", f"{dst_ip}/32", "flowid", "1:10"],
    ]
    rc = 0
    for cmd in commands:
        proc = run(cmd, sudo_pass)
        rc = rc or proc.returncode
    return rc


def clear(iface: str, sudo_pass: Optional[str]) -> int:
    proc = run(["tc", "qdisc", "del", "dev", iface, "root"], sudo_pass)
    if proc.returncode not in (0, 2):
        return proc.returncode
    return 0


def latest_action(actions_path: Path) -> Optional[dict]:
    if not actions_path.exists():
        return None
    last = None
    with actions_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                last = json.loads(line)
    return last


def infer_dst_ip(action: dict, summary_path: Optional[Path]) -> Optional[str]:
    if action.get("dst_ip"):
        return action["dst_ip"]
    if not summary_path or not summary_path.exists():
        return None
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    windows = summary.get("windows", [])
    if not windows:
        return None
    source = action.get("source")
    for win in windows:
        if win.get("source") == source and win.get("unique_dips") == 1:
            # Summary does not store the concrete DIP; use source JSONL.
            src = Path(source)
            if src.exists():
                with src.open("r", encoding="utf-8") as fh:
                    for line in fh:
                        if line.strip():
                            return json.loads(line).get("dip")
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--actions", required=True)
    parser.add_argument("--summary")
    parser.add_argument("--iface", default="enp1s0f0np0")
    parser.add_argument("--rate", default="100mbit")
    parser.add_argument("--dst-ip", help="override destination IP")
    parser.add_argument("--clear", action="store_true")
    parser.add_argument("--sudo-pass", default=os.environ.get("SUDO_PASS"))
    args = parser.parse_args()

    if args.clear:
        return clear(args.iface, args.sudo_pass)

    action = latest_action(Path(args.actions))
    if not action:
        print("no action found")
        return 2
    if action.get("attack_class", 0) == 0 or action.get("action") == "allow":
        print("latest action is allow; clearing limiter")
        return clear(args.iface, args.sudo_pass)

    dst_ip = args.dst_ip or infer_dst_ip(action, Path(args.summary) if args.summary else None)
    if not dst_ip:
        print("could not infer dst_ip; pass --dst-ip")
        return 2

    print(f"applying MIDAS enforcement: action={action.get('action')} dst={dst_ip} rate={args.rate}")
    return apply_rate_limit(args.iface, dst_ip, args.rate, args.sudo_pass)


if __name__ == "__main__":
    raise SystemExit(main())
