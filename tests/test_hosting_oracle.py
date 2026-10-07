import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("hosting_oracle", ROOT / "tests/hosting_oracle.py")
oracle = importlib.util.module_from_spec(SPEC)
# dataclasses resolves postponed annotations through the imported module name.
import sys
sys.modules[SPEC.name] = oracle
SPEC.loader.exec_module(oracle)


class StructuredHostingEvidenceTests(unittest.TestCase):
    def test_known_scalar_challenge_vector_and_byte_order(self):
        self.assertEqual(oracle.calculate(0), 0xc56fdba9d66e39cc)
        self.assertNotEqual(oracle.calculate(1), oracle.calculate(1 << 56))
        self.assertEqual(oracle.expected(2, 0x1029384756abcdef),
                         oracle.calculate(0x1029384756abcdef) ^
                         oracle.calculate(0x1029384756abcdef ^ oracle.NESTED_SALT))
        self.assertEqual(oracle.expected(8, 2), (-8) & oracle.MASK64)

    def test_duplicate_missing_width_and_noncanonical_fields_are_rejected(self):
        valid = "EVENT host-entry cell=0x4 identity=0x3e8 generation=0x1 tick=0x2\n"
        event = oracle.records(valid)[0]
        self.assertEqual(event.need("cell", "identity", "generation", "tick"), [4, 1000, 1, 2])
        with self.assertRaises(AssertionError):
            event.need("instance")
        for malformed in (valid.replace("tick=0x2", "cell=0x2"),
                          valid.replace("tick=0x2", "tick=0x10000000000000000"),
                          valid.replace("tick=0x2", "tick=-2"),
                          valid.replace("tick=0x2", "tick=2"),
                          valid.replace("tick=0x2", "tick=0xZ")):
            with self.subTest(malformed=malformed), self.assertRaises(AssertionError):
                oracle.records(malformed)

    def test_completion_markers_and_wrong_exit_cannot_substitute_for_proof(self):
        marker = "ZEAL boot abi=4 x86_64\nMANIFEST_ACCEPT version=2\nRESEARCH_PASS scenario=0x0000000000000015\n"
        for code in (0, 3, 5, -9):
            with self.subTest(code=code), self.assertRaises(AssertionError):
                oracle.verify(marker, code, 21)
        with self.assertRaises(AssertionError):
            oracle.verify(marker + "HOSTING_TRACE_EXHAUSTED\n", 1, 21)
        with self.assertRaises(AssertionError):
            oracle.verify(marker + "STORAGE_TRACE_EXHAUSTED\n", 1, 21)

    def test_signed_results_preserve_failure_bits(self):
        for result in range(-8, 1):
            self.assertEqual(oracle.signed(result & oracle.MASK64), result)


if __name__ == "__main__":
    unittest.main()
