import unittest

from v380client.commands import Command
from v380client.handshake import (
    build_auth_request,
    build_cloud_stream_login,
    build_cloud_stream_start,
    build_stream_login,
    build_stream_start,
    encrypted_password,
    parse_auth_response,
    parse_stream_response,
)


class HandshakeTests(unittest.TestCase):
    def test_password_blob_is_random_key_plus_blocks(self):
        blob = encrypted_password("example", random_key=b"0123456789abcdef")
        self.assertEqual(len(blob), 32)
        self.assertNotIn(b"example", blob)

    def test_builders_have_expected_commands_and_sizes(self):
        auth = build_auth_request(89799160, "user", "password", "device.example")
        self.assertEqual(len(auth), 520)
        self.assertEqual(auth[71:75], b"user")
        self.assertEqual(auth[49:54], b"\x00" * 5)
        self.assertEqual(int.from_bytes(auth[:4], "little"), Command.AUTH_REQUEST)
        login = build_stream_login(89799160, 1234)
        self.assertEqual(int.from_bytes(login[:4], "little"), Command.STREAM_LOGIN)
        self.assertEqual(int.from_bytes(build_stream_start(-11)[:4], "little"), Command.STREAM_START)
        cloud = build_cloud_stream_login(89799160, 1234, 5678, "device.example")
        self.assertEqual(len(cloud), 256)
        self.assertEqual(cloud[8:22].split(b"\0", 1)[0], b"device.example")
        self.assertEqual(int.from_bytes(build_cloud_stream_start(bytes(32))[4:8], "little"), 0x3001)

    def test_response_parsers_return_metadata_only(self):
        auth = bytearray(21)
        auth[:4] = (1168).to_bytes(4, "little")
        auth[4:8] = (1001).to_bytes(4, "little", signed=True)
        auth[13:17] = (42).to_bytes(4, "little")
        auth[17:21] = (7).to_bytes(4, "little")
        self.assertEqual(parse_auth_response(auth).auth_ticket, 42)
        stream = bytearray(18)
        stream[:4] = (401).to_bytes(4, "little")
        stream[4:8] = (101).to_bytes(4, "little", signed=True)
        stream[8:12] = (402).to_bytes(4, "little", signed=True)
        stream[12:16] = (20).to_bytes(4, "little")
        stream[16:20] = (640).to_bytes(4, "little")
        stream[20:24] = (480).to_bytes(4, "little")
        self.assertEqual(parse_stream_response(stream).width, 640)


if __name__ == "__main__":
    unittest.main()
