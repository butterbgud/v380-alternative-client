"""Credential-safe builders/parsers for the observed V380 handshake.

This module does not open sockets. Callers supply credentials at runtime and
receive bytes or parsed metadata; secrets are never logged or stored.
"""

from __future__ import annotations

import secrets
import string
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .commands import Command, command_id


# The captured relay variant uses a 520-byte auth request. The older LAN
# implementation used a shorter layout, which is why reusing it failed.
AUTH_PACKET_SIZE = 520
STREAM_PACKET_SIZE = 256
STATIC_KEY = b"macrovideo+*#!^@"
PRINTABLE = string.ascii_letters + string.digits + "!@#$%^&*()_+-="


def _aes_ecb(data: bytes, key: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def encrypted_password(password: str, random_key: bytes | None = None) -> bytes:
    """Return the V380 random-key plus double-AES-ECB password blob."""
    key = random_key or "".join(secrets.choice(PRINTABLE) for _ in range(16)).encode()
    if len(key) != 16:
        raise ValueError("random_key must be exactly 16 bytes")
    raw = password.encode()
    padding = 16 - (len(raw) % 16)
    padded = raw + (b"\x00" * padding)
    first = _aes_ecb(padded, STATIC_KEY)
    second = _aes_ecb(first, key)
    return key + second


def build_auth_request(device_id: int, username: str, password: str, domain: str = "") -> bytes:
    """Build command 1167 without exposing any credential in the result logs."""
    packet = bytearray(AUTH_PACKET_SIZE)
    struct.pack_into("<I", packet, 0, Command.AUTH_REQUEST)
    struct.pack_into("<I", packet, 4, 1022)
    packet[8] = 2
    struct.pack_into("<I", packet, 9, 1)
    struct.pack_into("<I", packet, 13, device_id)
    for offset, value in ((17, domain), (71, username)):
        encoded = value.encode()[:31]
        packet[offset : offset + len(encoded)] = encoded
    blob = encrypted_password(password)
    packet[103 : 103 + min(len(blob), 32)] = blob[:32]
    return bytes(packet)


@dataclass(frozen=True)
class AuthResponse:
    result: int
    auth_ticket: int
    session: int


def parse_auth_response(packet: bytes) -> AuthResponse:
    if len(packet) < 21 or command_id(packet) != Command.AUTH_RESPONSE:
        raise ValueError("not a V380 authentication response")
    return AuthResponse(
        result=struct.unpack_from("<i", packet, 4)[0],
        auth_ticket=struct.unpack_from("<I", packet, 13)[0],
        session=struct.unpack_from("<I", packet, 17)[0],
    )


def build_stream_login(device_id: int, auth_ticket: int, resolution: int = 0) -> bytes:
    packet = bytearray(STREAM_PACKET_SIZE)
    struct.pack_into("<I", packet, 0, Command.STREAM_LOGIN)
    struct.pack_into("<I", packet, 4, device_id)
    struct.pack_into("<H", packet, 12, 20)
    struct.pack_into("<I", packet, 14, auth_ticket)
    struct.pack_into("<I", packet, 22, 4097)
    struct.pack_into("<I", packet, 26, resolution)
    return bytes(packet)


def build_cloud_stream_login(
    device_id: int, auth_ticket: int, session: int, domain: str
) -> bytes:
    """Build the extended relay/cloud form observed in the official capture."""
    packet = bytearray(STREAM_PACKET_SIZE)
    struct.pack_into("<I", packet, 0, Command.STREAM_LOGIN)
    struct.pack_into("<I", packet, 4, 1022)
    encoded = domain.encode()[:31]
    packet[8 : 8 + len(encoded)] = encoded
    struct.pack_into("<I", packet, 62, device_id)
    struct.pack_into("<I", packet, 66, auth_ticket)
    struct.pack_into("<I", packet, 70, session)
    packet[78] = 20
    struct.pack_into("<I", packet, 79, 0x00010101)
    return bytes(packet)


@dataclass(frozen=True)
class StreamResponse:
    status: int
    fps: int
    width: int
    height: int


def parse_stream_response(packet: bytes) -> StreamResponse:
    if len(packet) < 16 or command_id(packet) != Command.STREAM_LOGIN_RESPONSE:
        raise ValueError("not a V380 stream-login response")
    return StreamResponse(
        status=struct.unpack_from("<i", packet, 8)[0],
        fps=struct.unpack_from("<I", packet, 12)[0],
        width=struct.unpack_from("<I", packet, 16)[0],
        height=struct.unpack_from("<I", packet, 20)[0],
    )


def build_stream_start(status: int) -> bytes:
    packet = bytearray(STREAM_PACKET_SIZE)
    struct.pack_into("<I", packet, 0, Command.STREAM_START)
    struct.pack_into("<i", packet, 4, status)
    return bytes(packet)


def build_cloud_stream_start(response: bytes) -> bytes:
    """Build the relay start packet observed after a cloud stream response."""
    if len(response) < 16:
        raise ValueError("stream response is too short")
    packet = bytearray(STREAM_PACKET_SIZE)
    struct.pack_into("<I", packet, 0, Command.STREAM_START)
    struct.pack_into("<I", packet, 4, 0x3001)
    packet[8:16] = response[8:16]
    return bytes(packet)
