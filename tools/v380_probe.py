#!/usr/bin/env python3
"""Opt-in read-only V380 relay probe."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v380client.probe import probe_relay


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="authorized relay host or LAN address")
    parser.add_argument("--port", type=int, default=8800)
    parser.add_argument("--device-id", type=int, required=True)
    parser.add_argument("--domain", default="")
    parser.add_argument("--username", required=True)
    args = parser.parse_args()
    password = getpass.getpass("V380 password (not echoed or saved): ")
    try:
        result = probe_relay(
            args.host,
            args.device_id,
            args.username,
            password,
            domain=args.domain,
            port=args.port,
        )
    except Exception as exc:
        print(f"Probe failed: {exc}", file=sys.stderr)
        return 1
    print(f"Authenticated: result={result.auth.result} ticket_received=yes")
    print(f"Stream: status={result.stream.status} {result.stream.width}x{result.stream.height} @ {result.stream.fps}fps")
    print(f"First stream byte: 0x{result.first_stream_marker:02x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
