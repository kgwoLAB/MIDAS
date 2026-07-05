#!/usr/bin/env python3
"""MIDAS worker intended to run on the BlueField Arm/ECPF side.

The host collector sends QP-level telemetry as newline-delimited JSON over TCP.
This worker keeps the MIDAS detector state on the Arm side, emits policy
actions per window, and can optionally launch the DPA RNN executable when the
Arm-side DOCA/DPA runtime is available.
"""

from __future__ import annotations

import argparse
import json
import shlex
import socket
import subprocess
import time
from pathlib import Path
from typing import List, Optional

from midas import (
    ATTACK_CLASSES,
    DetectorConfig,
    EwmaCusumDetector,
    HeuristicAttackClassifier,
    NumpyHybridRNNClassifier,
    QPManager,
    summarize_window,
)
from manager.mitigation_plan import build_plan


def _json_default(value):
    if hasattr(value, "item"):
        return value.item()
    return str(value)


class ArmMidasWorker:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.cfg = DetectorConfig(
            alpha=args.alpha,
            k_qp=args.k_qp,
            k_cont=args.k_cont,
            tau_qp=args.tau_qp,
            tau_cont=args.tau_cont,
            interval_ms=args.interval_ms,
            trust_input_alert=args.trust_input_alert,
        )
        self.detector = EwmaCusumDetector(self.cfg)
        if args.model and Path(args.model).is_file():
            self.classifier = NumpyHybridRNNClassifier(Path(args.model))
        else:
            self.classifier = HeuristicAttackClassifier()
        self.manager = QPManager()
        self.records: List[dict] = []
        self.detections = []
        self.window_started = time.time()
        self.window_id = 0
        self.out_dir = Path(args.out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.action_log = self.out_dir / "arm_actions.jsonl"
        self.window_log = self.out_dir / "arm_windows.jsonl"
        self.metrics_path = Path(args.prometheus_textfile) if args.prometheus_textfile else None
        self.total_windows = 0
        self.total_attacks = 0
        self.total_enforced = 0

    def add_record(self, record: dict) -> Optional[dict]:
        detection = self.detector.process(record)
        self.records.append(detection.record)
        self.detections.append(detection)
        now = time.time()
        if len(self.records) >= self.args.window_records:
            return self.flush("record_count")
        if now - self.window_started >= self.args.window_seconds:
            return self.flush("time")
        return None

    def flush(self, reason: str) -> Optional[dict]:
        if not self.detections:
            self.window_started = time.time()
            return None
        source = Path(f"arm-window-{self.window_id:06d}.jsonl")
        summary = summarize_window(source, None, self.detections)
        summary.attack_class = self.classifier.classify(self.records, summary)
        summary.action = self.manager.decide(summary)
        payload = {
            "window_id": self.window_id,
            "reason": reason,
            "source": str(source),
            "samples": summary.samples,
            "unique_qps": summary.unique_qps,
            "unique_dips": summary.unique_dips,
            "hot_ratio": summary.hot_ratio,
            "max_cusum": summary.max_cusum,
            "attack_class": summary.attack_class,
            "attack_name": ATTACK_CLASSES.get(summary.attack_class, "Unknown"),
            "action": summary.action,
            "target_qps": sorted({int(r.get("dqp", -1)) for r in self.records if int(r.get("dqp", -1)) >= 0}),
            "target_dips": sorted({str(r.get("dip", "unknown")) for r in self.records}),
            "ts": time.time(),
        }
        plan = build_plan(self.records, summary.attack_class, self.args.policy_backend)
        payload["mitigation_plan"] = plan.to_dict()
        payload["action"] = plan.primary_action
        self._append_json(self.window_log, payload)
        if self.args.enforce_command and summary.attack_class != 0:
            payload["enforce_result"] = self.run_action_command(self.args.enforce_command, payload, "enforce")
            if int(payload["enforce_result"].get("returncode", 1)) == 0:
                self.total_enforced += 1
        if self.args.dpa_command and summary.attack_class != 0:
            payload["dpa_result"] = self.run_action_command(self.args.dpa_command, payload, "dpa")
        self._append_json(self.action_log, payload)
        self.total_windows += 1
        if summary.attack_class != 0:
            self.total_attacks += 1
        self.write_prometheus_metrics(payload)
        self.window_id += 1
        self.records = []
        self.detections = []
        self.window_started = time.time()
        return payload

    def run_action_command(self, command: str, payload: dict, name: str) -> dict:
        env_path = self.out_dir / f"last_action_for_{name}.json"
        plan_path = self.out_dir / f"last_plan_for_{name}.json"
        env_path.write_text(json.dumps(payload, sort_keys=True, default=_json_default) + "\n", encoding="utf-8")
        plan_path.write_text(
            json.dumps(payload.get("mitigation_plan", {}), sort_keys=True, default=_json_default) + "\n",
            encoding="utf-8",
        )
        cmd = [
            part.format(action_json=str(env_path), plan_json=str(plan_path))
            for part in shlex.split(command)
        ]
        try:
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=self.args.command_timeout)
            return {
                "returncode": proc.returncode,
                "stdout": proc.stdout[-4096:],
                "stderr": proc.stderr[-4096:],
            }
        except Exception as exc:
            return {"returncode": -1, "error": repr(exc)}

    def write_prometheus_metrics(self, payload: dict) -> None:
        if self.metrics_path is None:
            return
        plan = payload.get("mitigation_plan", {})
        lines = [
            "# HELP midas_windows_total Total MIDAS windows processed by the Arm worker.",
            "# TYPE midas_windows_total counter",
            f"midas_windows_total {self.total_windows}",
            "# HELP midas_attack_windows_total Total non-benign MIDAS windows.",
            "# TYPE midas_attack_windows_total counter",
            f"midas_attack_windows_total {self.total_attacks}",
            "# HELP midas_enforced_windows_total Total windows with a successful enforcement command.",
            "# TYPE midas_enforced_windows_total counter",
            f"midas_enforced_windows_total {self.total_enforced}",
            "# HELP midas_last_attack_class Last classified MIDAS attack class.",
            "# TYPE midas_last_attack_class gauge",
            f"midas_last_attack_class {int(payload.get('attack_class', 0))}",
            "# HELP midas_last_hot_ratio Last MIDAS hot-QP ratio.",
            "# TYPE midas_last_hot_ratio gauge",
            f"midas_last_hot_ratio {float(payload.get('hot_ratio', 0.0))}",
            "# HELP midas_last_max_cusum Last MIDAS maximum CUSUM value.",
            "# TYPE midas_last_max_cusum gauge",
            f"midas_last_max_cusum {float(payload.get('max_cusum', 0.0))}",
            "# HELP midas_last_target_qps Last MIDAS target QP count.",
            "# TYPE midas_last_target_qps gauge",
            f"midas_last_target_qps {len(plan.get('target_qps', []))}",
        ]
        self.metrics_path.parent.mkdir(parents=True, exist_ok=True)
        self.metrics_path.write_text("\n".join(lines) + "\n", encoding="ascii")

    @staticmethod
    def _append_json(path: Path, payload: dict) -> None:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, sort_keys=True, default=_json_default) + "\n")


def serve(args: argparse.Namespace) -> int:
    worker = ArmMidasWorker(args)
    bind = (args.host, args.port)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(bind)
        srv.listen(args.backlog)
        print(f"[arm-worker] listening on {args.host}:{args.port}", flush=True)
        while True:
            conn, addr = srv.accept()
            print(f"[arm-worker] connection from {addr[0]}:{addr[1]}", flush=True)
            with conn, conn.makefile("r", encoding="utf-8-sig", errors="replace") as fh:
                try:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError as exc:
                            print(f"[arm-worker] bad json: {exc}", flush=True)
                            continue
                        action = worker.add_record(record)
                        if action is not None:
                            text = json.dumps(action, sort_keys=True, default=_json_default)
                            print(text, flush=True)
                            try:
                                conn.sendall((text + "\n").encode("utf-8"))
                            except OSError:
                                pass
                except OSError as exc:
                    print(f"[arm-worker] connection closed: {exc}", flush=True)
                action = worker.flush("disconnect")
                if action is not None:
                    print(json.dumps(action, sort_keys=True, default=_json_default), flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Arm/ECPF-side MIDAS telemetry worker")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=44991)
    parser.add_argument("--backlog", type=int, default=8)
    parser.add_argument("--out-dir", default="/var/tmp/midas_arm")
    parser.add_argument("--model", default="/opt/midas/models/midas_hybrid_rnn.npz")
    parser.add_argument("--window-records", type=int, default=32)
    parser.add_argument("--window-seconds", type=float, default=1.0)
    parser.add_argument("--alpha", type=float, default=0.3)
    parser.add_argument("--k-qp", type=float, default=0.0)
    parser.add_argument("--k-cont", type=float, default=0.0)
    parser.add_argument("--tau-qp", type=float, default=1_000_000.0)
    parser.add_argument("--tau-cont", type=float, default=1_000_000.0)
    parser.add_argument("--interval-ms", type=int, default=100)
    parser.add_argument("--dpa-command", default="")
    parser.add_argument("--enforce-command", default="")
    parser.add_argument("--command-timeout", type=float, default=10.0)
    parser.add_argument("--policy-backend", default="tc", choices=["tc", "doca", "verbs", "dry_run"])
    parser.add_argument("--prometheus-textfile", default="")
    parser.add_argument("--trust-input-alert", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return serve(args)


if __name__ == "__main__":
    raise SystemExit(main())
