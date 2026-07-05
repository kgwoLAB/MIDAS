#!/usr/bin/env python3
"""Probe which RoCE capture paths are usable on the current host."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List


@dataclass
class ProbeResult:
    name: str
    available: bool
    detail: str


def sudo_cmd(cmd: List[str]) -> List[str]:
    password = os.environ.get("SUDO_PASS", "")
    if not password:
        return cmd
    return ["sudo", "-S", *cmd]


def run(cmd: List[str], timeout: int = 5) -> subprocess.CompletedProcess:
    password = os.environ.get("SUDO_PASS", "")
    return subprocess.run(
        cmd,
        input=(password + "\n") if cmd[:2] == ["sudo", "-S"] else None,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def command_probe(name: str, cmd: str) -> ProbeResult:
    path = shutil.which(cmd)
    return ProbeResult(name, path is not None, path or "not found")


def iface_probe(iface: str) -> ProbeResult:
    path = Path("/sys/class/net") / iface
    return ProbeResult(f"iface:{iface}", path.exists(), str(path))


def tcpdump_probe(iface: str, capture_filter: str, duration: int) -> ProbeResult:
    if shutil.which("tcpdump") is None:
        return ProbeResult(f"tcpdump:{iface}", False, "tcpdump not found")
    cmd = sudo_cmd([
        "tcpdump",
        "-i",
        iface,
        "-c",
        "1",
        "-nn",
        capture_filter,
    ])
    try:
        proc = run(cmd, timeout=duration + 2)
        ok = proc.returncode == 0
        detail = (proc.stdout + proc.stderr).strip().splitlines()
        return ProbeResult(f"tcpdump:{iface}:{capture_filter}", ok, detail[-1] if detail else "no output")
    except Exception as exc:
        return ProbeResult(f"tcpdump:{iface}:{capture_filter}", False, str(exc))


def rdma_probe() -> ProbeResult:
    if shutil.which("rdma") is None:
        return ProbeResult("rdma link", False, "rdma command not found")
    try:
        proc = run(["rdma", "link"], timeout=5)
        ok = proc.returncode == 0 and "mlx5" in proc.stdout
        return ProbeResult("rdma link", ok, proc.stdout.strip() or proc.stderr.strip())
    except Exception as exc:
        return ProbeResult("rdma link", False, str(exc))


def ovs_probe() -> ProbeResult:
    if shutil.which("ovs-vsctl") is None:
        return ProbeResult("ovs-vsctl", False, "ovs-vsctl not found")
    try:
        proc = run(sudo_cmd(["ovs-vsctl", "show"]), timeout=5)
        return ProbeResult("ovs-vsctl show", proc.returncode == 0, proc.stdout.strip() or proc.stderr.strip())
    except Exception as exc:
        return ProbeResult("ovs-vsctl show", False, str(exc))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pf", default="enp1s0f0np0")
    parser.add_argument("--vf", default="enp1s0f0v0")
    parser.add_argument("--mirror", default="int0")
    parser.add_argument("--duration", type=int, default=3)
    parser.add_argument("--output")
    args = parser.parse_args()

    results = [
        command_probe("tcpdump", "tcpdump"),
        command_probe("tshark", "tshark"),
        command_probe("ibdump", "ibdump"),
        command_probe("ovs-vsctl", "ovs-vsctl"),
        command_probe("devlink", "devlink"),
        rdma_probe(),
        ovs_probe(),
        iface_probe(args.pf),
        iface_probe(args.vf),
        iface_probe(args.mirror),
        tcpdump_probe(args.pf, "udp port 4791", args.duration),
        tcpdump_probe(args.vf, "udp port 4791", args.duration),
        tcpdump_probe(args.mirror, "udp port 4791", args.duration),
    ]
    payload = {"results": [asdict(r) for r in results]}
    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
