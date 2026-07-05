#!/usr/bin/env python3
"""Apply QP-level MIDAS enforcement on BlueField Arm/ECPF.

This enforcer targets RoCEv2 packets in software-visible Arm/ECPF netdevs. It
matches the InfiniBand BTH destination QP in UDP/4791 packets using `tc u32`.

For Ethernet + IPv4(no options) + UDP + BTH:
  IP header offset 20, UDP header offset 28, BTH dest_qp offset 32.
The u32 word at offset 32 contains dest_qp in the top 24 bits and ACKREQ in the
low byte, so the match is:
  match u32 (dqp << 8) 0xffffff00 at 32
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Iterable, List, Optional


ROCE_UDP_PORT = 4791
DEFAULT_IFACES = ("pf0hpf", "pf1hpf", "p0", "p1", "en3f0pf0sf0", "en3f1pf1sf0")
MIDAS_PRIO_SPAN = 100


def run(cmd: List[str], sudo_pass: Optional[str] = None, check: bool = False) -> subprocess.CompletedProcess:
    full = ["sudo", "-S", *cmd] if sudo_pass else ["sudo", *cmd]
    proc = subprocess.run(
        full,
        input=(sudo_pass + "\n") if sudo_pass else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    print("+", " ".join(full))
    print(proc.stdout, end="")
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, full, proc.stdout)
    return proc


def qdisc_ensure(iface: str, sudo_pass: Optional[str]) -> None:
    proc = run(["tc", "qdisc", "add", "dev", iface, "ingress"], sudo_pass)
    if proc.returncode != 0 and "File exists" not in proc.stdout:
        raise RuntimeError(f"failed to install ingress qdisc on {iface}")


def delete_filter_prio(iface: str, prio: int, sudo_pass: Optional[str]) -> int:
    proc = run(
        [
            "tc", "filter", "del", "dev", iface,
            "parent", "ffff:", "protocol", "ip", "prio", str(prio), "u32",
        ],
        sudo_pass,
    )
    return 0 if proc.returncode in (0, 2) else proc.returncode


def clear_midas_filters(iface: str, prio_base: int, sudo_pass: Optional[str]) -> int:
    rc = 0
    for prio in range(prio_base, prio_base + MIDAS_PRIO_SPAN):
        rc = rc or delete_filter_prio(iface, prio, sudo_pass)
    return rc


def delete_flower_prio(iface: str, prio: int, sudo_pass: Optional[str]) -> int:
    proc = run(
        [
            "tc", "filter", "del", "dev", iface,
            "parent", "ffff:", "protocol", "ip", "prio", str(prio), "flower",
        ],
        sudo_pass,
    )
    return 0 if proc.returncode in (0, 2) else proc.returncode


def dqp_match_word(dqp: int) -> str:
    if dqp < 0 or dqp > 0xFFFFFF:
        raise ValueError(f"dqp out of 24-bit range: {dqp}")
    return f"0x{dqp << 8:08x}"


def add_drop_filter(iface: str, dqp: int, prio: int, sudo_pass: Optional[str]) -> int:
    qdisc_ensure(iface, sudo_pass)
    delete_filter_prio(iface, prio, sudo_pass)
    # u32 offsets are relative to the IPv4 header start.
    cmd = [
        "tc", "filter", "add", "dev", iface,
        "parent", "ffff:", "protocol", "ip", "prio", str(prio),
        "u32",
        "match", "ip", "protocol", "17", "0xff",
        "match", "ip", "dport", str(ROCE_UDP_PORT), "0xffff",
        "match", "u32", dqp_match_word(dqp), "0xffffff00", "at", "32",
        "action", "drop",
    ]
    return run(cmd, sudo_pass).returncode


def add_police_filter(iface: str, dqp: int, prio: int, rate: str, burst: str, sudo_pass: Optional[str]) -> int:
    qdisc_ensure(iface, sudo_pass)
    delete_filter_prio(iface, prio, sudo_pass)
    cmd = [
        "tc", "filter", "add", "dev", iface,
        "parent", "ffff:", "protocol", "ip", "prio", str(prio),
        "u32",
        "match", "ip", "protocol", "17", "0xff",
        "match", "ip", "dport", str(ROCE_UDP_PORT), "0xffff",
        "match", "u32", dqp_match_word(dqp), "0xffffff00", "at", "32",
        "action", "police", "rate", rate, "burst", burst, "conform-exceed", "drop",
    ]
    return run(cmd, sudo_pass).returncode


def add_roce_hw_drop_filter(
    iface: str,
    prio: int,
    sudo_pass: Optional[str],
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
) -> int:
    qdisc_ensure(iface, sudo_pass)
    run(["tc", "filter", "del", "dev", iface, "parent", "ffff:", "protocol", "ip", "prio", str(prio), "flower"], sudo_pass)
    cmd = [
        "tc", "filter", "add", "dev", iface,
        "parent", "ffff:", "protocol", "ip", "prio", str(prio),
        "flower", "ip_proto", "udp", "dst_port", str(ROCE_UDP_PORT),
    ]
    if src_ip:
        cmd.extend(["src_ip", src_ip])
    if dst_ip:
        cmd.extend(["dst_ip", dst_ip])
    cmd.extend(["action", "drop"])
    return run(cmd, sudo_pass).returncode


def show(ifaces: Iterable[str], sudo_pass: Optional[str]) -> int:
    rc = 0
    for iface in ifaces:
        proc = run(["tc", "-s", "filter", "show", "dev", iface, "parent", "ffff:"], sudo_pass)
        rc = rc or proc.returncode
    return rc


def qps_from_action(path: Path) -> List[int]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return sorted({int(qp) for qp in payload.get("target_qps", []) if int(qp) >= 0})


def load_action(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def latest_action(path: Path) -> Optional[dict]:
    last = None
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                last = json.loads(line)
    return last


def qps_from_actions_log(path: Path) -> List[int]:
    action = latest_action(path)
    if not action or int(action.get("attack_class", 0)) == 0:
        return []
    return sorted({int(qp) for qp in action.get("target_qps", []) if int(qp) >= 0})


def parse_ifaces(value: str) -> List[str]:
    if value == "auto":
        return list(DEFAULT_IFACES)
    return [item for item in value.split(",") if item]


def main() -> int:
    parser = argparse.ArgumentParser(description="QP-level RoCEv2 enforcer for BlueField Arm")
    parser.add_argument("cmd", choices=["drop", "police", "drop-roce", "clear", "show"])
    parser.add_argument("--iface", default="auto", help="comma-separated ifaces or auto")
    parser.add_argument("--dqp", type=int, action="append", default=[])
    parser.add_argument("--action-json")
    parser.add_argument("--actions-log")
    parser.add_argument("--rate", default="100mbit")
    parser.add_argument("--burst", default="1mb")
    parser.add_argument("--prio-base", type=int, default=300)
    parser.add_argument("--hw-prio", type=int, default=1)
    parser.add_argument("--src-ip")
    parser.add_argument("--dst-ip")
    parser.add_argument("--sudo-pass", default=os.environ.get("SUDO_PASS"))
    args = parser.parse_args()

    ifaces = parse_ifaces(args.iface)
    if args.cmd == "clear":
        rc = 0
        for iface in ifaces:
            rc = rc or clear_midas_filters(iface, args.prio_base, args.sudo_pass)
            rc = rc or delete_flower_prio(iface, args.hw_prio, args.sudo_pass)
        return rc
    if args.cmd == "show":
        return show(ifaces, args.sudo_pass)

    if args.cmd == "drop-roce":
        rc = 0
        for iface in ifaces:
            rc = rc or add_roce_hw_drop_filter(iface, args.hw_prio, args.sudo_pass, args.src_ip, args.dst_ip)
        return rc

    qps = list(args.dqp)
    action_payload = None
    if args.action_json:
        action_payload = load_action(Path(args.action_json))
        plan = action_payload.get("mitigation_plan", action_payload)
        qps.extend(int(qp) for qp in plan.get("target_qps", []) if int(qp) >= 0)
        args.rate = str(plan.get("rate", args.rate))
        args.burst = str(plan.get("burst", args.burst))
    if args.actions_log:
        qps.extend(qps_from_actions_log(Path(args.actions_log)))
    qps = sorted(set(qps))
    if not qps:
        print("no target QPs")
        return 2

    rc = 0
    for iface in ifaces:
        for idx, dqp in enumerate(qps):
            prio = args.prio_base + idx
            if args.cmd == "drop":
                rc = rc or add_drop_filter(iface, dqp, prio, args.sudo_pass)
            elif args.cmd == "police":
                rc = rc or add_police_filter(iface, dqp, prio, args.rate, args.burst, args.sudo_pass)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
