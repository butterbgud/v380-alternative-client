#!/usr/bin/env python3
"""Print safe endpoint and V380-frame statistics from a pcapng capture.

This intentionally never prints packet payloads. It supports the common
pcapng Enhanced Packet Block format and Ethernet/IPv4 packets.
"""

from __future__ import annotations

import argparse
import collections
import ipaddress
import struct
from pathlib import Path


EPB = 0x00000006


def packets(path: Path):
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


def ipv4_packet(frame: bytes):
    if len(frame) < 34 or frame[12:14] != b"\x08\x00":
        return None
    packet = frame[14:]
    header_length = (packet[0] & 0x0F) * 4
    if len(packet) < header_length or header_length < 20:
        return None
    source = str(ipaddress.ip_address(packet[12:16]))
    destination = str(ipaddress.ip_address(packet[16:20]))
    protocol = packet[9]
    source_port = destination_port = None
    payload = b""
    if protocol == 6 and len(packet) >= header_length + 20:
        source_port, destination_port = struct.unpack_from("!HH", packet, header_length)
        tcp_header_length = (packet[header_length + 12] >> 4) * 4
        payload = packet[header_length + tcp_header_length :]
    elif protocol == 17 and len(packet) >= header_length + 8:
        source_port, destination_port = struct.unpack_from("!HH", packet, header_length)
        payload = packet[header_length + 8 :]
    return source, destination, protocol, source_port, destination_port, payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()

    flows = collections.Counter()
    v380_frames = collections.Counter()
    packet_count = 0
    for frame in packets(args.capture):
        packet = ipv4_packet(frame)
        if packet is None:
            continue
        packet_count += 1
        source, destination, protocol, source_port, destination_port, payload = packet
        transport = {6: "TCP", 17: "UDP"}.get(protocol, str(protocol))
        flows[(source, source_port, destination, destination_port, transport)] += 1
        if payload.startswith(b"\x7f"):
            v380_frames[(source, source_port, destination, destination_port)] += 1

    print(f"IPv4 packets: {packet_count}")
    print("Endpoint flows:")
    for flow, count in flows.most_common():
        print(f"  {count:5d}  {flow[0]}:{flow[1]} -> {flow[2]}:{flow[3]} ({flow[4]})")
    print("Payloads beginning with 0x7f:")
    for flow, count in v380_frames.most_common():
        print(f"  {count:5d}  {flow[0]}:{flow[1]} -> {flow[2]}:{flow[3]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
