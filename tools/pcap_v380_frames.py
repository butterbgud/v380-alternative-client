#!/usr/bin/env python3
"""Summarize V380 frames after TCP stream reassembly.

Only endpoint and frame metadata are printed. Payload bytes are never shown.
This is intentionally a small pcapng reader for Ethernet/IPv4/TCP captures.
"""

from __future__ import annotations

import argparse
import collections
import ipaddress
import sys
import struct
from pathlib import Path

# Allow both `python3 tools/...py` and `python3 -m tools...` from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v380client.framing import HEADER_SIZE, MAGIC, MAX_PAYLOAD

EPB = 0x00000006


def captured_packets(path: Path):
    data = path.read_bytes()
    offset = 0
    while offset + 12 <= len(data):
        block_type, block_length = struct.unpack_from("<II", data, offset)
        if block_length < 12 or offset + block_length > len(data):
            raise ValueError(f"invalid pcapng block at offset {offset}")
        body = data[offset + 8 : offset + block_length - 4]
        if block_type == EPB and len(body) >= 20:
            captured_length = struct.unpack_from("<I", body, 12)[0]
            yield body[20 : 20 + captured_length]
        offset += block_length


def tcp_segment(frame: bytes):
    if len(frame) < 34 or frame[12:14] != b"\x08\x00":
        return None
    packet = frame[14:]
    ip_header_length = (packet[0] & 0x0F) * 4
    if len(packet) < ip_header_length + 20 or packet[9] != 6:
        return None
    source = str(ipaddress.ip_address(packet[12:16]))
    destination = str(ipaddress.ip_address(packet[16:20]))
    source_port, destination_port, sequence = struct.unpack_from("!HHI", packet, ip_header_length)
    tcp_header_length = (packet[ip_header_length + 12] >> 4) * 4
    payload = packet[ip_header_length + tcp_header_length :]
    return source, source_port, destination, destination_port, sequence, payload


def reassemble(segments):
    """Merge TCP segments by sequence number, tolerating retransmissions."""
    stream = bytearray()
    end = None
    for sequence, payload in sorted(segments):
        if not payload:
            continue
        if end is None:
            end = sequence
        if sequence > end:
            # Preserve a gap as a boundary; parsing after it would be unsafe.
            stream.extend(b"\x00" * (sequence - end))
        start = max(sequence - (end or sequence), 0)
        if sequence >= (end or sequence):
            stream.extend(payload)
            end = sequence + len(payload)
        elif sequence + len(payload) > end:
            stream.extend(payload[end - sequence :])
            end = sequence + len(payload)
    return bytes(stream)


def summarize(stream: bytes):
    """Find and validate frame envelopes in a stream without exposing payloads."""
    offset = 0
    counts = collections.Counter()
    while offset + HEADER_SIZE <= len(stream):
        marker = stream.find(bytes([MAGIC]), offset)
        if marker < 0 or marker + HEADER_SIZE > len(stream):
            break
        header = stream[marker : marker + HEADER_SIZE]
        total = int.from_bytes(header[3:5], "little")
        number = int.from_bytes(header[5:7], "little")
        length = int.from_bytes(header[7:9], "little")
        if not total or number > total or length > MAX_PAYLOAD:
            offset = marker + 1
            continue
        end = marker + HEADER_SIZE + length
        if end > len(stream):
            break
        counts[(header[1], total)] += 1
        offset = end
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--port", type=int, default=8800)
    args = parser.parse_args()

    streams = collections.defaultdict(list)
    for frame in captured_packets(args.capture):
        segment = tcp_segment(frame)
        if segment is None:
            continue
        source, source_port, destination, destination_port, sequence, payload = segment
        if source_port == args.port or destination_port == args.port:
            streams[(source, source_port, destination, destination_port)].append((sequence, payload))

    for flow, segments in sorted(streams.items()):
        data = reassemble(segments)
        counts = summarize(data)
        print(f"{flow[0]}:{flow[1]} -> {flow[2]}:{flow[3]}")
        print(f"  captured TCP payload bytes: {sum(len(p) for _, p in segments)}")
        print(f"  recognized V380 frames: {sum(counts.values())}")
        for (frame_type, total), count in sorted(counts.items()):
            print(f"    type=0x{frame_type:02x} total={total}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
