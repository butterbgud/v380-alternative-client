import unittest

from v380client.framing import FrameParser, iter_frames


def frame(frame_type, total, number, payload):
    header = bytes([0x7F, frame_type, 0])
    header += total.to_bytes(2, "little")
    header += number.to_bytes(2, "little")
    header += len(payload).to_bytes(2, "little")
    header += b"\x00\x00\x00"
    return header + payload


class FrameParserTests(unittest.TestCase):
    def test_parser_handles_tcp_chunk_boundaries(self):
        data = frame(0x29, 2, 1, b"abc") + frame(0x18, 2, 2, b"xyz")
        parser = FrameParser()
        result = []
        for chunk in (data[:2], data[2:11], data[11:19], data[19:]):
            result.extend(parser.feed(chunk))
        self.assertEqual(result[0].payload, b"abc")
        self.assertEqual(result[1].frame_type, 0x18)
        self.assertEqual(parser.buffered_bytes, 0)

    def test_iter_frames_rejects_incomplete_final_frame(self):
        with self.assertRaisesRegex(ValueError, "incomplete"):
            list(iter_frames([frame(1, 1, 1, b"payload")[:-1]]))

    def test_parser_rejects_bad_marker(self):
        with self.assertRaisesRegex(ValueError, "marker"):
            FrameParser().feed(b"bad frame data")


if __name__ == "__main__":
    unittest.main()
