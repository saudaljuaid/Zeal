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

    def test_serialized_snapshot_outcomes_disambiguate_same_local_ids_after_overlapping_dequeues(self):
        def event(index, name="storage-fs", **changed):
            fields = dict(cell=1, identity=200, generation=1, tick=index, request=3, operation=18, result=8)
            fields.update(changed)
            return oracle.host.Event(index, name, fields, index)
        def request(sender, token, index):
            packet = oracle.SnapshotPacket(sender, 0x102, 18, 3, token, 0x102, bytes.fromhex("0800080000000000"))
            return event(index, "snapshot-ipc-deliver"), packet
        def reply(target, token, amount=8, operation=19, transaction=3, sender=0x102):
            data = bytes(amount)
            word = 8 | amount << 16 | int.from_bytes(data[:4], "little") << 32
            tail = data[4:].ljust(4, b"\0") + b"\0\0\0\2"
            return oracle.SnapshotPacket(sender, target, operation, transaction, token, word, tail)
        first, first_request = request(0x506, 0x5A1, 1)
        second, second_request = request(0x207, 0x6A2, 2)
        first_outcome, second_outcome = event(3, result=7), event(5)
        ledger = oracle.SnapshotOutcomes()
        ledger.observe(first_outcome)
        assigned = ledger.consume(first, first_request, event(4, "snapshot-ipc-enqueue"), reply(0x506, 0x5A1, 7))
        self.assertEqual([first_outcome], assigned)
        ledger.observe(second_outcome)
        assigned = ledger.consume(second, second_request, event(6, "snapshot-ipc-enqueue"), reply(0x207, 0x6A2))
        self.assertEqual([second_outcome], assigned)
        ledger.finish()
        self.assertEqual({3, 5}, ledger.used)
        # The old delivery-interval key gives both outcomes to the second read.
        self.assertEqual(2, len([e for e in (first_outcome, second_outcome) if second.index < e.index < 6]))
        for mutation in ("missing", "duplicate", "orphan", "reordered", "id", "operation", "result", "generation", "identity", "ordinary_dispatch", "ordinary_reply", "client_scope", "reconsume"):
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                bad = oracle.SnapshotOutcomes()
                report = event(3)
                answer = reply(0x506, 0x5A1)
                publication = event(4, "snapshot-ipc-enqueue")
                if mutation == "missing":
                    bad.consume(first, first_request, publication, answer)
                    continue
                if mutation == "id": report = event(3, request=4)
                if mutation == "operation": report = event(3, operation=20)
                if mutation == "result": report = event(3, result=7)
                if mutation == "generation": report = event(3, generation=2)
                if mutation == "identity": report = event(3, identity=201)
                bad.observe(report)
                if mutation == "duplicate": bad.observe(event(4))
                if mutation == "orphan": bad.finish()
                if mutation == "reordered": publication = event(2, "snapshot-ipc-enqueue")
                if mutation == "ordinary_dispatch": bad.observe(event(4, operation=11))
                if mutation == "ordinary_reply": bad.observe(event(4, "storage-ipc", operation=14))
                if mutation == "client_scope": answer = reply(0x207, 0x5A1)
                bad.consume(first, first_request, publication, answer)
                if mutation == "reconsume": bad.consume(first, first_request, publication, answer)
                bad.finish()

    def test_snapshot_control_release_and_inventory_have_separate_exact_serialized_publication(self):
        def event(index, name="storage-fs", **extra):
            fields = dict(cell=1, identity=200, generation=1, tick=index)
            fields.update(extra)
            return oracle.host.Event(index, name, fields, index)
        for operation in (17, 20):
            with self.subTest(operation=operation):
                ledger = oracle.SnapshotOutcomes()
                incoming = oracle.SnapshotPacket(0x104, 0x102, operation, 1, 0x1A1, 0x102 if operation == 20 else 0, b"\5" + bytes(7))
                if operation == 17:
                    packet = oracle.SnapshotPacket(0x102, 0x104, 19, 1, 0x1A1, 0x101, bytes([0, 0, 5, 3, 0, 0, 0, 1]))
                else:
                    packet = oracle.SnapshotPacket(0x102, 0x104, 19, 1, 0x1A1, 0, bytes([0, 0, 0, 0, 0, 0, 0, 2]))
                ledger.observe(event(2, request=1, operation=operation, result=0))
                ledger.consume(event(1, "snapshot-ipc-deliver"), incoming, event(3, "snapshot-ipc-enqueue"), packet)
                ledger.finish()
        ledger = oracle.SnapshotOutcomes()
        incoming = oracle.SnapshotPacket(0x104, 0x102, 17, 72, 1, 0, b"\10" + bytes(7))
        packet = oracle.SnapshotPacket(0x102, 0x104, 19, 72, 0, 0x101, bytes([0, 0, 8, 0, 0, 0, 0, 1]))
        with self.assertRaises(AssertionError):
            ledger.observe(event(2, "snapshot-inventory", value=0, extra=0, identity=201))
        ledger.observe(event(2, "snapshot-inventory", value=0, extra=0))
        ledger.consume(event(1, "snapshot-ipc-deliver"), incoming, event(3, "snapshot-ipc-enqueue"), packet, inventory=True)
        ledger.finish()
        self.assertEqual({2}, ledger.inventory_used)
        with self.assertRaises(AssertionError):
            ledger.consume(event(1, "snapshot-ipc-deliver"), incoming, event(4, "snapshot-ipc-enqueue"), packet, inventory=True)


if __name__ == "__main__":
    unittest.main()
