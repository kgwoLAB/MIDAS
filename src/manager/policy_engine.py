#!/usr/bin/env python3
"""Backend-neutral MIDAS mitigation policy engine."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from manager.mitigation_plan import build_plan


def _load_events(path: Path) -> List[dict]:
    events = []
    with path.open("r", encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def action_from_events(source: Path, attack_class: int, backend: str = "tc") -> dict:
    events = _load_events(source)
    payload = build_plan(events, attack_class, backend).to_dict()
    payload["source"] = str(source)
    payload["dry_run"] = backend == "dry_run"
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", required=True)
    parser.add_argument("--attack-class", type=int, required=True)
    parser.add_argument("--backend", default="tc", choices=["dry_run", "tc", "doca", "verbs"])
    parser.add_argument("--output")
    args = parser.parse_args()

    action = action_from_events(Path(args.events), args.attack_class, args.backend)
    text = json.dumps(action, sort_keys=True)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
