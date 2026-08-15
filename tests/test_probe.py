import unittest

from v380client.probe import read_exact


class ChunkedSocket:
    def __init__(self, *chunks):
        self.chunks = list(chunks)

    def recv(self, size):
        return self.chunks.pop(0)[:size]


class ProbeTests(unittest.TestCase):
    def test_read_exact_handles_short_reads(self):
        self.assertEqual(read_exact(ChunkedSocket(b"ab", b"cde"), 5), b"abcde")


if __name__ == "__main__":
    unittest.main()
