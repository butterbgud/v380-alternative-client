"""Small, dependency-free building blocks for V380 protocol research."""

from .framing import V380Frame, iter_frames

__all__ = ["V380Frame", "iter_frames"]
