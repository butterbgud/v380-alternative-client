import unittest

from v380client.framing import V380Frame
from v380client.stream import assemble_fragments, parse_inner_frames, parse_outer_header


class OuterStreamTests(unittest.TestCase):
    def test_parses_observed_prefix(self):
        prefix = bytes.fromhex("1f8002d00214001001000000")
        header = parse_outer_header(prefix)
        self.assertEqual(header.magic, 0x1F)
        self.assertEqual(header.raw, prefix)

    def test_rejects_wrong_marker(self):
        with self.assertRaises(ValueError):
            parse_outer_header(b"\x7f" + b"\0" * 11)

    def test_parses_inner_frame(self):
        prefix = bytes.fromhex("1f8002d00214001001000000")
        frame = bytes([0x7F, 0x29, 0, 1, 0, 1, 0, 3, 0, 0, 0, 0]) + b"abc"
        parsed = parse_inner_frames(prefix + frame)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].frame_type, 0x29)
        self.assertEqual(parsed[0].payload, b"abc")

    def test_assembles_complete_fragment_group(self):
        frames = [
            V380Frame(0x28, 2, 1, b"second"),
            V380Frame(0x28, 2, 0, b"first"),
        ]
        self.assertEqual(assemble_fragments(frames), b"firstsecond")

    def test_rejects_incomplete_fragment_group(self):
        with self.assertRaisesRegex(ValueError, "incomplete"):
            assemble_fragments([V380Frame(0x28, 2, 0, b"only")])


if __name__ == "__main__":
    unittest.main()
