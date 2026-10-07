import pathlib
import sys
import types
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import contract_oracle as oracle


def event(**changes):
    fields = dict(cell=3, identity=400, generation=1, tick=2, sender=0x104, target=0x105,
        cap=0x801, operation=15, length=32, request=1, command=0x01000101, reserved=0,
        argument=0, value=17, version=1, service_command=1, kind=0, detail=1, token=0, data=17, result=0)
    fields.update(changes)
    return oracle.host.Event(0, "host-ipc-enqueue", fields, 0)


class IndependentContractEvidenceTests(unittest.TestCase):
    def test_wire_crosschecks_authoritative_raw_and_decoded_bytes(self):
        self.assertEqual(oracle.Packet.from_event(event()).data, 17)
        for change in (dict(version=2), dict(reserved=1), dict(command=0x01000100), dict(argument=1),
                       dict(value=18), dict(operation=16), dict(length=31), dict(request=0),
                       dict(service_command=0), dict(kind=4), dict(detail=256)):
            with self.subTest(change=change), self.assertRaises(AssertionError):
                oracle.Packet.from_event(event(**change))

    def test_full_issuer_service_type_serial_and_record_scope(self):
        value = (0x105 << 32) | (1 << 9) | 0x80
        self.assertEqual(oracle.token_parts(value), (0, 1, 0x105))
        maximum = (0xffffff08 << 32) | (0x7fffff << 9) | (1 << 8) | 0x80
        self.assertEqual(oracle.token_parts(maximum), (1, 0x7fffff, 0xffffff08))
        for bad in (0, value ^ 1, 0x80 | (0x105 << 32), (1 << 9) | 0x80,
                    (0x100 << 32) | (1 << 9) | 0x80, (0x109 << 32) | (1 << 9) | 0x80):
            with self.subTest(bad=bad), self.assertRaises(AssertionError):
                oracle.token_parts(bad)
        # These are legitimate kernel object encodings; none is a service token.
        for tag in (0x01, 0x20, 0x41, 0x51, 0x61, 0x71):
            with self.subTest(tag=tag), self.assertRaises(AssertionError):
                oracle.token_parts((0x105 << 32) | (1 << 9) | tag)

    def test_snapshot_reserved_bits_and_exact_two_page_backing(self):
        offered = 1 | (1 << 8) | (1 << 40) | (2 << 48)
        self.assertEqual(oracle.flag_fields(offered), (1, 1, 0, 0, 0, 1, 2, 0))
        for altered in (offered | (1 << 57), offered ^ (1 << 48), offered | 8,
                        offered | (2 << 16), offered | (3 << 24), offered | (9 << 32)):
            with self.subTest(altered=altered), self.assertRaises(AssertionError):
                oracle.flag_fields(altered)

    def test_offer_highwater_rejects_earlier_consumed_namespace_without_mapping(self):
        observed = oracle.Observer([], oracle.host.SealedRoots(0), {})
        observed.broker = lambda: types.SimpleNamespace(endpoint=0x105)
        observed.offer_highwater[0x104] = 8
        request = oracle.Packet(0x104, 0x105, 15, 2, 1, 0, 1, 0, 17)
        self.assertEqual(observed.request_error(request), 3)
        self.assertEqual(observed.request_error(oracle.Packet(0x104, 0x105, 15, 9, 1, 0, 1, 0, 17)), 0)
        observed.offer_keys[(0x104, 2)] = types.SimpleNamespace(retained=True, profile=1, input=17)
        self.assertEqual(observed.request_error(request), 0)
        self.assertEqual(observed.request_error(oracle.Packet(0x104, 0x105, 15, 2, 1, 0, 1, 0, 18)), 2)

    def test_success_markers_exit_codes_and_exhaustion_cannot_replace_evidence(self):
        marker = "ZEAL boot abi=4 x86_64\nMANIFEST_ACCEPT version=2\nRESEARCH_PASS scenario=0x0000000000000018\n"
        for code in (0, 3, 5, -9):
            with self.subTest(code=code), self.assertRaises(AssertionError):
                oracle.verify(marker, code)
        for exhausted in ("HOSTING_TRACE_EXHAUSTED", "STORAGE_TRACE_EXHAUSTED"):
            with self.subTest(exhausted=exhausted), self.assertRaises(AssertionError):
                oracle.verify(marker + exhausted + "\n", 1)


if __name__ == "__main__":
    unittest.main()
