import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import analysis_oracle as oracle


class IndependentAnalysisEvidenceTests(unittest.TestCase):
    def test_binary_checksum_known_vectors_and_full_tuple(self):
        self.assertEqual(oracle.calculate(b""), (0, 0, 0xCBF29CE484222325))
        self.assertEqual(oracle.calculate(b"a"), (1, 0, 0xAF63DC4C8601EC8C))
        self.assertEqual(oracle.calculate(b"hello"), (5, 0, 0xA430D84680AABD0B))
        for length in (1, 7, 8, 9, 127, 128):
            self.assertEqual(oracle.calculate(b"\n" * length)[:2], (length, length))
            self.assertEqual(oracle.calculate(b"\0" * length)[:2], (length, 0))
        self.assertEqual(oracle.calculate(b"\x00\xff\x0a\x80\x00\x0a")[:2], (6, 2))
        self.assertNotEqual(oracle.calculate(b"aaaa"), oracle.calculate(b"bbbb"))
        with self.assertRaises(AssertionError):
            oracle.calculate(bytes(129))
        with self.assertRaises(AssertionError):
            oracle.calculate("text")

    def test_snapshot_full_issuer_service_tag_serial_placement_scope(self):
        self.assertEqual(oracle.snapshot_parts(0x102, 0x1A1), (0x102, 1, 0))
        maximum = oracle.SNAPSHOT_SERIAL_LIMIT << 8 | 0xA2
        self.assertEqual(oracle.snapshot_parts(0xFFFFFFFE02, maximum), (0xFFFFFFFE02, oracle.SNAPSHOT_SERIAL_LIMIT, 1))
        for issuer, token in ((0, 0x1A1), (0x101, 0x1A1), (0x2, 0x1A1), (0x102, 0),
                              (0x102, 0xA1), (0x102, 0x1A0), (0x102, 0x1A3),
                              (0x102, 0x180), (0x102, 0x101), (0x102, 0x161)):
            with self.subTest(issuer=issuer, token=token), self.assertRaises(AssertionError):
                oracle.snapshot_parts(issuer, token)

    def test_snapshot_raw_words_and_decoded_extents_cannot_disagree(self):
        def event(operation, words, sender=0x106, target=0x102):
            f = dict(cell=(sender & 255) - 1, identity=1001, generation=sender >> 8, tick=1, sender=sender, target=target,
                     cap=0x1111, operation=operation, length=32, request=words[0], handle=words[1],
                     offset=words[2] & 0xFFFFFFFF, result=words[2] >> 32, data=words[3], outcome=0,
                     **{f"raw{i}": word for i, word in enumerate(words)})
            return oracle.host.Event(0, "snapshot-ipc-enqueue", f, 0)
        incoming = event(18, (0x123456789ABCDEF, 0x1A1, 0x102, 127 | 8 << 16))
        packet = oracle.SnapshotPacket.from_event(incoming)
        self.assertEqual(packet.read(), (0x102, 127, 8))
        for key in ("raw0", "raw1", "raw2", "raw3", "request", "handle", "offset", "result", "data"):
            changed = dict(incoming.fields)
            changed[key] ^= 1
            with self.subTest(key=key), self.assertRaises(AssertionError):
                oracle.SnapshotPacket.from_event(oracle.host.Event(0, incoming.name, changed, 0))
        control = event(17, (1, 0x100000101, 0, 1))
        self.assertEqual(oracle.SnapshotPacket.from_event(control).control(), (1, 0))
        malformed = event(17, (1, 0x100000101, 0, 1 | 1 << 8))
        with self.assertRaises(AssertionError):
            oracle.SnapshotPacket.from_event(malformed).control()
        control_reply = event(19, (1, 0x1A1, 0x101, 128 | 1 << 16 | 2 << 24 | 1 << 56), sender=0x102, target=0x106)
        self.assertEqual(oracle.SnapshotPacket.from_event(control_reply).control_reply(), (128, 0, 1, 2))
        # Eight delivered bytes cross raw2 and raw3; they are not a string.
        data = b"\0\xff\n\x80\0\nAB"
        reply = event(19, (2, 0x1A1, 120 | 8 << 16 | int.from_bytes(data[:4], "little") << 32,
                           int.from_bytes(data[4:], "little") | 2 << 56), sender=0x102, target=0x106)
        self.assertEqual(oracle.SnapshotPacket.from_event(reply).read_reply(), (120, 8, 0, data))

    def test_contract_full_raw_words_match_version_and_decoded_tuple_fields(self):
        packed = 1 | 12 << 8 | 1 << 24
        f = dict(cell=4, identity=1000, generation=1, tick=2, sender=0x105, target=0x106, cap=0xF0F,
                 operation=15, length=32, request=4, command=packed, reserved=0, argument=0x10500000280,
                 value=128, version=1, service_command=12, kind=0, detail=1, token=0x10500000280, data=128,
                 result=0, raw0=4, raw1=packed, raw2=0x10500000280, raw3=128)
        self.assertEqual(oracle.ContractPacket.from_event(oracle.host.Event(0, "host-ipc-enqueue", f, 0)).data, 128)
        for key in ("raw0", "raw1", "raw2", "raw3", "command", "reserved", "argument", "value", "version", "service_command", "detail", "token", "data"):
            changed = dict(f)
            changed[key] ^= 1
            with self.subTest(key=key), self.assertRaises(AssertionError):
                oracle.ContractPacket.from_event(oracle.host.Event(0, "host-ipc-enqueue", changed, 0))

    def test_raw_signed_word_and_exact_endpoint(self):
        self.assertEqual(oracle.signed32(0xFFFFFFF8), -8)
        self.assertEqual(oracle.signed32(8), 8)
        for value in (-1, 1 << 32, oracle.MASK64):
            with self.assertRaises(AssertionError):
                oracle.signed32(value)


if __name__ == "__main__":
    unittest.main()
