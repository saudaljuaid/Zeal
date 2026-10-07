import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("footprint", ROOT / "tools/footprint.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SupervisorFootprintTests(unittest.TestCase):
    def symbols(self, loaded=module.LOADED_BYTES_MAX, end=module.STATIC_END_MAX - 16):
        return {"__kernel_start": module.LOAD_START,
                "__kernel_load_end": module.LOAD_START + loaded,
                "__bss_start": 0x200000, "__bss_end": end, "__kernel_end": end}

    def test_exact_payload_limit_and_static_footprint_are_reported(self):
        report = module.footprint(bytes(module.LOADED_BYTES_MAX), self.symbols())
        self.assertEqual(report["loaded_kernel_bytes"], module.LOADED_BYTES_MAX)
        self.assertEqual(report["static_address_end"], module.STATIC_END_MAX - 16)
        self.assertEqual(report["static_supervisor_bytes"],
                         module.LOADED_BYTES_MAX + module.STATIC_END_MAX - 16 - 0x200000)

    def test_payload_overflow_or_linker_sentinel_omissions_fail(self):
        for data in (b"", bytes(module.LOADED_BYTES_MAX + 1)):
            with self.assertRaises(ValueError):
                module.footprint(data, self.symbols())
        with self.assertRaises(ValueError):
            module.footprint(bytes(65), self.symbols(loaded=64))

    def test_static_end_bss_order_and_missing_symbols_fail(self):
        for end in (module.STATIC_END_MAX, module.STATIC_END_MAX + 1, 0x1fffff):
            with self.assertRaises(ValueError):
                module.footprint(b"x", self.symbols(loaded=1, end=end))
        symbols = self.symbols()
        symbols["__bss_start"] = -1
        with self.assertRaises(ValueError):
            module.footprint(b"x", symbols)
        del symbols["__kernel_end"]
        with self.assertRaises(ValueError):
            module.footprint(b"x", symbols)


if __name__ == "__main__":
    unittest.main()
