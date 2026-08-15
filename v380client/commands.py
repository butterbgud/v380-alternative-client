"""Known V380 command identifiers observed in authorized captures."""

from __future__ import annotations

from enum import IntEnum


class Command(IntEnum):
    AUTH_REQUEST = 1167
    AUTH_RESPONSE = 1168
    STREAM_LOGIN = 301
    STREAM_LOGIN_RESPONSE = 401
    STREAM_START = 303


def command_id(packet: bytes) -> int | None:
    """Return a little-endian command ID when a packet has a 4-byte prefix."""
    if len(packet) < 4:
        return None
    return int.from_bytes(packet[:4], "little")


def classify_command(packet: bytes) -> Command | None:
    """Map a packet prefix to a known command without inspecting payloads."""
    value = command_id(packet)
    try:
        return Command(value) if value is not None else None
    except ValueError:
        return None
