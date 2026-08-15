"""Parsing for the legacy V380 stream frame envelope.

This module deliberately does not decrypt or interpret media payloads. It only
turns a byte stream into validated frame envelopes. TCP can split one frame
across reads, so ``iter_frames`` accepts arbitrary chunks and retains partial
data between calls.
"""

from __future__ import annotations

from dataclasses import dataclass


HEADER_SIZE = 12
MAGIC = 0x7F
MAX_PAYLOAD = 500


@dataclass(frozen=True)
class V380Frame:
    """One V380 frame envelope and its opaque payload."""

    frame_type: int
    total_frames: int
    frame_number: int
    payload: bytes


class FrameParser:
    """Incremental parser suitable for data returned by a TCP socket."""

    def __init__(self, *, max_payload: int = MAX_PAYLOAD) -> None:
        if max_payload <= 0:
            raise ValueError("max_payload must be positive")
        self.max_payload = max_payload
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[V380Frame]:
        self._buffer.extend(data)
        frames: list[V380Frame] = []
        while True:
            if len(self._buffer) < HEADER_SIZE:
                break
            if self._buffer[0] != MAGIC:
                raise ValueError(f"unexpected frame marker 0x{self._buffer[0]:02x}")
            frame_type = self._buffer[1]
            total_frames = int.from_bytes(self._buffer[3:5], "little")
            frame_number = int.from_bytes(self._buffer[5:7], "little")
            payload_length = int.from_bytes(self._buffer[7:9], "little")
            if total_frames == 0 or frame_number > total_frames:
                raise ValueError("invalid V380 frame counters")
            if payload_length > self.max_payload:
                raise ValueError("V380 payload exceeds configured safety limit")
            end = HEADER_SIZE + payload_length
            if len(self._buffer) < end:
                break
            payload = bytes(self._buffer[HEADER_SIZE:end])
            del self._buffer[:end]
            frames.append(V380Frame(frame_type, total_frames, frame_number, payload))
        return frames

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer)


def iter_frames(chunks, *, max_payload: int = MAX_PAYLOAD):
    """Yield frames from an iterable of arbitrary byte chunks."""

    parser = FrameParser(max_payload=max_payload)
    for chunk in chunks:
        yield from parser.feed(chunk)
    if parser.buffered_bytes:
        raise ValueError("incomplete V380 frame at end of stream")
