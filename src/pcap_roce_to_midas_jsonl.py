#!/usr/bin/env python3
"""Parse mirrored RoCEv2 pcap into MIDAS JSONL.

This is a tiny parser for Ethernet/IPv4/UDP/RoCEv2 BTH packets. It avoids
tshark/scapy dependencies on the server.
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
from pathlib import Path


PCAP_MAGIC_USEC = 0xA1B2C3D4
PCAP_MAGIC_USEC_SWAPPED = 0xD4C3B2A1
PCAP_MAGIC_NSEC = 0xA1B23C4D
PCAP_MAGIC_NSEC_SWAPPED = 0x4D3CB2A1
ROCE_UDP_PORT = 4791


def inet(b: bytes) -> str:
    return socket.inet_ntoa(b)


def parse_packets(path: Path):
    data = path.read_bytes()
    if len(data) < 24:
        return
    magic = struct.unpack("<I", data[:4])[0]
    if magic in (PCAP_MAGIC_USEC, PCAP_MAGIC_NSEC):
        endian = "<"
        nsec = magic == PCAP_MAGIC_NSEC
    elif magic in (PCAP_MAGIC_USEC_SWAPPED, PCAP_MAGIC_NSEC_SWAPPED):
        endian = ">"
        nsec = magic == PCAP_MAGIC_NSEC_SWAPPED
    else:
        raise ValueError(f"unsupported pcap magic: 0x{magic:08x}")

    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl_len]
        off += incl_len
        ts = ts_sec + (ts_frac / (1_000_000_000 if nsec else 1_000_000))
        rec = parse_packet(pkt)
        if rec:
            rec["ts"] = ts
            yield rec


def parse_packet(pkt: bytes):
    if len(pkt) < 14:
        return None
    eth_type = struct.unpack("!H", pkt[12:14])[0]
    pos = 14
    if eth_type == 0x8100 and len(pkt) >= 18:
        eth_type = struct.unpack("!H", pkt[16:18])[0]
        pos = 18
    if eth_type != 0x0800 or len(pkt) < pos + 20:
        return None

    ip0 = pos
    ver_ihl = pkt[ip0]
    ihl = (ver_ihl & 0x0F) * 4
    proto = pkt[ip0 + 9]
    if proto != 17 or len(pkt) < ip0 + ihl + 8:
        return None
    sip = inet(pkt[ip0 + 12:ip0 + 16])
    dip = inet(pkt[ip0 + 16:ip0 + 20])

    udp0 = ip0 + ihl
    sport, dport, udp_len = struct.unpack("!HHH", pkt[udp0:udp0 + 6])
    if sport != ROCE_UDP_PORT and dport != ROCE_UDP_PORT:
        return None

    bth = udp0 + 8
    if len(pkt) < bth + 12:
        return None
    opcode = pkt[bth]
    dest_qp = int.from_bytes(pkt[bth + 5:bth + 8], "big") & 0xFFFFFF
    psn = int.from_bytes(pkt[bth + 9:bth + 12], "big") & 0xFFFFFF

    # RETH is present for RDMA WRITE/READ style opcodes in many captures.
    rkey = None
    reth = bth + 12
    if len(pkt) >= reth + 16:
        rkey = int.from_bytes(pkt[reth + 8:reth + 12], "big")

    payload_len = max(0, udp_len - 8 - 12)
    return {
        "sip": sip,
        "dip": dip,
        "op": opcode,
        "dqp": dest_qp,
        "psn": psn,
        "len": payload_len,
        "reth_r_key": rkey,
    }


def convert(input_path: Path, output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    per_qp = {}
    count = 0
    with output_path.open("w", encoding="utf-8") as out:
        for rec in parse_packets(input_path):
            key = (rec["dip"], rec["dqp"])
            state = per_qp.setdefault(key, {"last_ts": None, "ewma": None, "cusum": 0.0})
            last_ts = state["last_ts"]
            if last_ts is None or rec["ts"] <= last_ts:
                rate = 0.0
            else:
                rate = float(rec["len"]) / (rec["ts"] - last_ts)
            ewma = rate if state["ewma"] is None else 0.3 * rate + 0.7 * state["ewma"]
            cusum = max(0.0, state["cusum"] + rate - ewma)
            alert = 2 if cusum >= 1_000_000 else (1 if cusum >= 500_000 else 0)
            state.update({"last_ts": rec["ts"], "ewma": ewma, "cusum": cusum})
            rec.update({
                "rate": round(rate, 2),
                "ewma": round(ewma, 2),
                "cusum": round(cusum, 2),
                "alert": alert,
            })
            out.write(json.dumps(rec, sort_keys=True) + "\n")
            count += 1
    print(f"converted {count} RoCEv2 packets -> {output_path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    convert(Path(args.input), Path(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
