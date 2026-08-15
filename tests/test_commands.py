import unittest

from v380client.commands import Command, classify_command, command_id


class CommandTests(unittest.TestCase):
    def test_command_ids_are_little_endian(self):
        self.assertEqual(command_id((1167).to_bytes(4, "little")), 1167)
        self.assertEqual(classify_command((303).to_bytes(4, "little")), Command.STREAM_START)

    def test_unknown_or_short_packets_are_not_commands(self):
        self.assertIsNone(command_id(b"\x01\x02"))
        self.assertIsNone(classify_command((9999).to_bytes(4, "little")))


if __name__ == "__main__":
    unittest.main()
