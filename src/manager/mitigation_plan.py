#!/usr/bin/env python3
"""Attack-specific MIDAS mitigation planning.

The plan is backend-neutral: Arm/ECPF runtimes can map it to tc, DOCA Flow,
verbs-control helpers, or operator-specific container orchestration.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List


ATTACK_NAMES = {
    0: "Benign",
    1: "QueueFlooding",
    2: "CacheDepletion",
    3: "VerbsFlooding",
    4: "VerbsAmplification",
}


@dataclass
class MitigationPlan:
    attack_class: int
    attack_name: str
    primary_action: str
    backend: str
    target_qps: List[int] = field(default_factory=list)
    target_dips: List[str] = field(default_factory=list)
    target_rkeys: List[int] = field(default_factory=list)
    tc_mode: str = "police"
    rate: str = "100mbit"
    burst: str = "1mb"
    queue_depth: int = 128
    max_remote_regions: int = 4
    token_rate: int = 4096
    token_burst: int = 8192
    wqe_pacing_ns: int = 1000
    migration_max_send_wr: int = 64
    migration_max_recv_wr: int = 64
    migration_max_inline_data: int = 0

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def load_jsonl(path: Path) -> List[dict]:
    rows = []
    with path.open("r", encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def int_field(row: dict, *names: str, default: int = -1) -> int:
    for name in names:
        value = row.get(name)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return default


def hot_records(events: Iterable[dict]) -> List[dict]:
    out = []
    for row in events:
        alert = int_field(row, "midas_alert", "alert", default=0)
        if alert >= 1:
            out.append(row)
    return out


def top_qps(events: List[dict], limit: int = 8) -> List[int]:
    counts: Dict[int, int] = {}
    for row in events:
        dqp = int_field(row, "dqp", "dest_qp", default=-1)
        if dqp >= 0:
            counts[dqp] = counts.get(dqp, 0) + 1
    return [qp for qp, _ in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]]


def unique_dips(events: Iterable[dict]) -> List[str]:
    return sorted({str(row.get("dip", "0.0.0.0")) for row in events if row.get("dip")})


def unique_rkeys(events: Iterable[dict]) -> List[int]:
    keys = set()
    for row in events:
        key = int_field(row, "r_key", "reth_r_key", "remote_rkey", default=-1)
        if key >= 0:
            keys.add(key)
    return sorted(keys)


def build_plan(events: List[dict], attack_class: int, backend: str = "tc") -> MitigationPlan:
    active = hot_records(events) or events
    qps = top_qps(active)
    dips = unique_dips(active)
    rkeys = unique_rkeys(active)
    name = ATTACK_NAMES.get(attack_class, "Unknown")

    if attack_class == 0:
        return MitigationPlan(attack_class, name, "allow", backend, [], [], [], tc_mode="none")
    if attack_class == 1:
        return MitigationPlan(
            attack_class,
            name,
            "queue_depth_limit_or_qp_reallocation",
            backend,
            qps,
            dips,
            rkeys,
            tc_mode="police",
            rate="100mbit",
            burst="1mb",
            queue_depth=128,
            migration_max_send_wr=64,
            migration_max_recv_wr=64,
        )
    if attack_class == 2:
        return MitigationPlan(
            attack_class,
            name,
            "address_diversity_limit",
            backend,
            qps,
            dips,
            rkeys,
            tc_mode="police",
            rate="200mbit",
            burst="2mb",
            max_remote_regions=4,
        )
    if attack_class in (3, 4):
        return MitigationPlan(
            attack_class,
            name,
            "token_bucket_or_wqe_pacing",
            backend,
            qps,
            dips,
            rkeys,
            tc_mode="police",
            rate="50mbit",
            burst="512kb",
            token_rate=2048,
            token_burst=4096,
            wqe_pacing_ns=2000,
        )
    return MitigationPlan(attack_class, name, "rate_limit", backend, qps, dips, rkeys)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", required=True)
    parser.add_argument("--attack-class", type=int, required=True)
    parser.add_argument("--backend", default="tc")
    parser.add_argument("--output")
    args = parser.parse_args()

    plan = build_plan(load_jsonl(Path(args.events)), args.attack_class, args.backend)
    text = json.dumps(plan.to_dict(), sort_keys=True)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
