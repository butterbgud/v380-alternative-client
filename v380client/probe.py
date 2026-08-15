"""Read-only V380 relay handshake probe."""

from __future__ import annotations

import socket
from dataclasses import dataclass

from .handshake import (
    AuthResponse,
    StreamResponse,
    build_auth_request,
    build_stream_login,
    build_stream_start,
    parse_auth_response,
    parse_stream_response,
)


def read_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("V380 peer closed before the response was complete")
        chunks.extend(chunk)
    return bytes(chunks)


@dataclass(frozen=True)
class ProbeResult:
    auth: AuthResponse
    stream: StreamResponse
    first_stream_marker: int


def probe_relay(
    host: str,
    device_id: int,
    username: str,
    password: str,
    *,
    domain: str = "",
    port: int = 8800,
    timeout: float = 5.0,
) -> ProbeResult:
    """Perform auth and stream negotiation without saving or logging secrets."""
    with socket.create_connection((host, port), timeout=timeout) as auth_socket:
        auth_socket.sendall(build_auth_request(device_id, username, password, domain))
        auth_response = parse_auth_response(read_exact(auth_socket, 520))

    if auth_response.result != 1001:
        raise PermissionError(f"V380 authentication result: {auth_response.result}")

    with socket.create_connection((host, port), timeout=timeout) as stream_socket:
        stream_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        stream_socket.sendall(build_stream_login(device_id, auth_response.auth_ticket))
        stream_response = parse_stream_response(read_exact(stream_socket, 32))
        stream_socket.sendall(build_stream_start(stream_response.status))
        first = read_exact(stream_socket, 1)[0]

    return ProbeResult(auth_response, stream_response, first)
