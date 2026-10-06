import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("manifest", ROOT / "tools" / "manifest.py")
manifest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manifest)


class ManifestCompilerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = pathlib.Path(self.temp.name)
        self.source = self.directory / "manifest.toml"
        self.output = self.directory / "manifest.bin"
        self.text = (ROOT / "cells" / "manifest.toml").read_text()
        self.images = []
        for number in range(4):
            path = self.directory / f"image-{number}.bin"
            path.write_bytes(bytes([number + 1]) * 64)
            self.images.append(path)

    def tearDown(self):
        self.temp.cleanup()

    def compile(self, text=None, **kwargs):
        self.source.write_text(self.text if text is None else text)
        manifest.compile_manifest(self.source, self.output, self.images, **kwargs)
        return self.output.read_bytes()

    def rejects(self, text, **kwargs):
        self.source.write_text(text)
        with self.assertRaises((ValueError, TypeError, KeyError)):
            manifest.compile_manifest(self.source, self.output, self.images, **kwargs)

    def test_fixed_format_round_trip_size_and_solo_mask(self):
        artifact = self.compile(scenario=18)
        header = manifest.struct.unpack_from("<IIIIIIII", artifact)
        self.assertEqual(header, (0x4C41455A, 1, len(artifact), 4, 6, 0, 0, 0))
        self.assertEqual(len(artifact), 32 + 4 * 64 + 6 * 16)
        self.assertEqual(manifest.struct.unpack_from("<I", artifact, 32 + 3 * 64 + 36)[0], 18)
        solo = self.compile(solo=2)
        flags = [manifest.struct.unpack_from("<I", solo, 32 + n * 64 + 12)[0] for n in range(4)]
        self.assertEqual(flags, [0, 0, 1, 0])
        waiting = self.compile(scenario=19)
        configs = [manifest.struct.unpack_from("<I", waiting, 32 + n * 64 + 36)[0] for n in range(4)]
        self.assertEqual(configs, [0, 0, 19, 19])
        self.assertEqual(manifest.struct.unpack_from("<IIII", waiting, 32 + 4 * 64 + 5 * 16),
                         (300, 400, 16, 0))

    def test_rejects_bad_versions_ids_names_images_entries_and_widths(self):
        for old, new in (("version = 1", "version = 2"),
                         ("identity = 100", "identity = 0"),
                         ("identity = 200", "identity = 100"),
                         ('name = "block"', 'name = "invalid name"'),
                         ("image = 4", "image = 99"),
                         ("entry = 0x40000000", "entry = 18446744073709551616"),
                         ("abi = 2", "abi = 4294967296")):
            with self.subTest(old=old, new=new):
                self.rejects(self.text.replace(old, new, 1))

    def test_rejects_budget_lifecycle_and_grant_errors(self):
        invalid = (
            ("stack_budget = 16384", "stack_budget = 0"),
            ("writable_budget = 81920", "writable_budget = 81921"),
            ("restart_limit = 3", "restart_limit = 4"),
            ("restart_delay = 4", "restart_delay = 0"),
            ('rights = ["read_reply"]', 'rights = []'),
            ('rights = ["read_reply"]', 'rights = ["read_reply", "read_reply"]'),
            ("target = 200", "target = 999"),
            ("holder = 100", "holder = 0"),
        )
        for old, new in invalid:
            with self.subTest(old=old, new=new):
                self.rejects(self.text.replace(old, new, 1))

    def test_rejects_overlarge_images_scenarios_and_solo_slots(self):
        self.images[0].write_bytes(b"x" * 65537)
        with self.assertRaises(ValueError):
            self.compile()
        for kwargs in ({"scenario": 20}, {"solo": 4}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.compile(**kwargs)


if __name__ == "__main__":
    unittest.main()
