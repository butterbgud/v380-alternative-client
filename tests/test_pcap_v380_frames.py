import unittest

from tools.pcap_v380_frames import reassemble, summarize


class CaptureFrameTests(unittest.TestCase):
    def test_reassemble_orders_segments(self):
        self.assertEqual(reassemble([(20, b"world"), (15, b"hello")]), b"helloworld")

    def test_summarize_counts_frame_types_without_payload_output(self):
        header = b"\x7f\x29\x00\x01\x00\x01\x00\x03\x00\x00\x00\x00"
        counts = summarize(header + b"abc")
        self.assertEqual(counts[(0x29, 1)], 1)


if __name__ == "__main__":
    unittest.main()
