"""Safe parsing of the cloud relay's outer stream envelope.

The authenticated cloud path starts with a 12-byte ``0x1f`` envelope and
then carries the familiar ``0x7f`` frame stream.  The meaning of the inner
fields is not yet fully established, so this module preserves them as opaque
metadata rather than guessing at codec or dimensions.
"""

from __future__ import annotations

from dataclasses import dataclass

from .framing import FrameParser, V380Frame


OUTER_HEADER_SIZE = 12
OUTER_MAGIC = 0x1F


@dataclass(frozen=True)
class OuterHeader:
    """The observed cloud-stream prefix, without speculative field names."""

    magic: int
    raw: bytes


def parse_outer_header(data: bytes) -> OuterHeader:
    """Validate and return the fixed cloud-stream prefix."""
    if len(data) < OUTER_HEADER_SIZE:
        raise ValueError("cloud stream prefix is incomplete")
    raw = bytes(data[:OUTER_HEADER_SIZE])
    if raw[0] != OUTER_MAGIC:
        raise ValueError(f"unexpected cloud stream marker 0x{raw[0]:02x}")
    return OuterHeader(magic=raw[0], raw=raw)


def parse_inner_frames(data: bytes, *, max_payload: int = 65535) -> list[V380Frame]:
    """Parse inner V380 frames after the outer 12-byte prefix.

    The returned payloads remain opaque.  Callers should avoid logging them
    because authenticated streams can contain private audio/video data.
    """
    parse_outer_header(data)
    return FrameParser(max_payload=max_payload).feed(data[OUTER_HEADER_SIZE:])


def assemble_fragments(frames: list[V380Frame]) -> bytes:
    """Join one complete fragmented media group without interpreting it.

    Cloud captures use the normal V380 counters, but several groups can be
    interleaved with control/audio envelopes.  This helper accepts one group,
    verifies its type/counters, and returns only the opaque concatenated data.
    """
    if not frames:
        raise ValueError("fragment group is empty")
    frame_type = frames[0].frame_type
    total = frames[0].total_frames
    if len(frames) != total:
        raise ValueError("fragment group is incomplete")
    ordered = sorted(frames, key=lambda frame: frame.frame_number)
    if any(frame.frame_type != frame_type for frame in ordered):
        raise ValueError("fragment types do not match")
    if [frame.frame_number for frame in ordered] != list(range(total)):
        raise ValueError("fragment counters are not contiguous")
    return b"".join(frame.payload for frame in ordered)
