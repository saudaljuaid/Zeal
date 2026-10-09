import ctypes
import importlib.util
import os
import pathlib
import shlex
import subprocess
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
        header = manifest.struct.unpack_from("<IIIIIIIIII", artifact)
        self.assertEqual(header, (0x4C41455A, 2, len(artifact), 4, 6, 0, 0, 0, 0, 0))
        self.assertEqual(len(artifact), 40 + 4 * 64 + 6 * 16)
        self.assertEqual(manifest.struct.unpack_from("<I", artifact, 40 + 3 * 64 + 36)[0], 18)
        solo = self.compile(solo=2)
        flags = [manifest.struct.unpack_from("<I", solo, 40 + n * 64 + 12)[0] for n in range(4)]
        self.assertEqual(flags, [0, 0, 1, 0])
        waiting = self.compile(scenario=19)
        configs = [manifest.struct.unpack_from("<I", waiting, 40 + n * 64 + 36)[0] for n in range(4)]
        self.assertEqual(configs, [0, 0, 19, 19])
        self.assertEqual(manifest.struct.unpack_from("<IIII", waiting, 40 + 4 * 64 + 5 * 16),
                         (300, 400, 16, 0))
        storage = self.compile(scenario=20)
        configs = [manifest.struct.unpack_from("<I", storage, 40 + n * 64 + 36)[0] for n in range(4)]
        self.assertEqual(configs, [20, 20, 20, 20])
        self.assertEqual([manifest.struct.unpack_from("<I", storage, 40 + n * 64 + 8)[0]
                          for n in range(4)], [4] * 4)

    def test_console_authority_is_explicit_single_root_and_nondelegable(self):
        text = self.text.replace('name = "client"', 'name = "client"\nconsole = true', 1)
        for scenario in (26, 27):
            artifact = self.compile(text, scenario=scenario)
            flags = [manifest.struct.unpack_from("<I", artifact, 40 + n * 64 + 12)[0] for n in range(4)]
            self.assertEqual(flags, [1, 1, 5, 1])
            self.assertEqual(manifest.struct.unpack_from("<I", artifact, 40 + 2 * 64 + 36)[0], scenario)
            self.assertEqual(manifest.struct.unpack_from("<I", artifact, 40 + 3 * 64 + 36)[0], scenario)
            self.assertEqual(len(artifact), 40 + 4 * 64 + 6 * 16)
            self.rejects(self.text, scenario=scenario)
            self.rejects(text, scenario=scenario, solo=2)
        self.rejects(text.replace('name = "block"', 'name = "block"\nconsole = true', 1))
        self.rejects(text.replace('console = true', 'console = 1', 1))
        self.rejects(text.replace('console = true', 'console = "true"', 1))
        self.rejects(self.text.replace('boot_config = 0', 'boot_config = 26', 1))
        disabled = self.compile(text.replace('console = true', 'console = false', 1))
        self.assertEqual(manifest.struct.unpack_from("<I", disabled, 40 + 2 * 64 + 12)[0], 1)
        # A solo boot of another root drops the inactive entitlement.
        artifact = self.compile(text, solo=0)
        self.assertEqual(manifest.struct.unpack_from("<I", artifact, 40 + 2 * 64 + 12)[0], 0)

    def test_rejects_bad_versions_ids_names_images_entries_and_widths(self):
        for old, new in (("version = 2", "version = 1"),
                         ("identity = 100", "identity = 0"),
                         ("identity = 200", "identity = 100"),
                         ('name = "block"', 'name = "invalid name"'),
                         ("image = 4", "image = 99"),
                         ("entry = 0x40000000", "entry = 18446744073709551616"),
                         ("abi = 4", "abi = 4294967296"), ("abi = 4", "abi = 3")):
            with self.subTest(old=old, new=new):
                self.rejects(self.text.replace(old, new, 1))

    def test_rejects_budget_lifecycle_and_grant_errors(self):
        invalid = (
            ("stack_budget = 16384", "stack_budget = 0"),
            ("writable_budget = 81920", "writable_budget = 81921"),
            ("restart_limit = 3", "restart_limit = 4"),
            ("restart_delay = 4", "restart_delay = 0"),
            ('rights = ["read_reply", "block_reply"]', 'rights = []'),
            ('rights = ["read_reply", "block_reply"]', 'rights = ["read_reply", "read_reply"]'),
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
        self.images[0].write_bytes(bytes([1]) * 64)
        for kwargs in ({"scenario": 25}, {"solo": 4}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.compile(**kwargs)

    def test_storage_rights_are_explicit_and_delegation_remains_read_only(self):
        artifact = self.compile()
        rights = [manifest.struct.unpack_from("<I", artifact, 40 + 4 * 64 + n * 16 + 8)[0]
                  for n in range(6)]
        self.assertEqual(rights, [2 | 256, 1 | 64 | 128, 4 | 0x80000000,
                                  8 | 16 | 8192, 4 | 32 | 512 | 1024 | 2048 | 4096, 16])
        self.rejects(self.text.replace('"block_write"', '"unknown_write"'))
        self.rejects(self.text.replace('"file_write"', '"file_open"'))
        names = manifest.operation_rights(0x8000ffff)
        self.assertEqual(names["file_result"], 8192)
        self.assertEqual(names["delegate"], 0x80000000)

    def prepare_hosting(self):
        self.text = (ROOT / "cells" / "hosting.toml").read_text()
        for number in range(4, 8):
            path = self.directory / f"image-{number}.bin"
            path.write_bytes(bytes([number + 1]) * 64)
            self.images.append(path)

    def test_hosting_catalog_is_distinct_from_running_roots(self):
        self.prepare_hosting()
        for scenario in (21, 22, 23):
            artifact = self.compile(scenario=scenario)
            header = manifest.struct.unpack_from("<IIIIIIIIII", artifact)
            self.assertEqual(header, (0x4C41455A, 2, len(artifact), 4, 6, 2, 1, 0, 0, 0))
            self.assertEqual(len(artifact), 40 + 4 * 64 + 6 * 16 + 2 * 64 + 32)
            configs = [manifest.struct.unpack_from("<I", artifact, 40 + n * 64 + 36)[0]
                       for n in range(4)]
            self.assertEqual(configs, [0, 0, scenario, scenario])
            templates = 40 + 4 * 64 + 6 * 16
            supervisor = manifest.struct.unpack_from("<IIIIQIIIIIIIIII", artifact, templates)
            worker = manifest.struct.unpack_from("<IIIIQIIIIIIIIII", artifact, templates + 64)
            self.assertEqual(supervisor[:5], (1, 5, 4, 0, 0x40000000))
            self.assertEqual(supervisor[6:9], (8192, 16384, scenario))
            self.assertEqual(supervisor[11:], (1, 2, 1, 0))
            self.assertEqual(worker[:5], (2, 6, 4, 0, 0x40000000))
            self.assertEqual(worker[6:9], (4096, 8192, scenario))
            self.assertEqual(worker[11:], (0, 0, 1, 0))
            self.assertEqual(manifest.struct.unpack_from("<IIIIIIII", artifact, templates + 128),
                             (400, 3, 4, 48, 2, 1, 0, 0))
        self.assertEqual(manifest.private_pages(8192, 16384, manifest.schema_layout()[0]), 4)
        self.assertEqual(manifest.private_pages(4096, 8192, manifest.schema_layout()[0]), 2)

    def test_contract_catalog_is_explicit_and_does_not_change_old_hosting(self):
        self.prepare_hosting()
        self.text = (ROOT / "cells" / "contracts.toml").read_text()
        artifact = self.compile(scenario=24)
        header = manifest.struct.unpack_from("<IIIIIIIIII", artifact)
        self.assertEqual(header, (0x4C41455A, 2, 552, 4, 6, 2, 1, 0, 0, 0))
        at = 40 + 4 * 64 + 6 * 16
        broker = manifest.struct.unpack_from("<IIIIQIIIIIIIIII", artifact, at)
        worker = manifest.struct.unpack_from("<IIIIQIIIIIIIIII", artifact, at + 64)
        self.assertEqual(broker[:5], (3, 5, 4, 0, 0x40000000))
        self.assertEqual(broker[6:9], (8192, 16384, 24))
        self.assertEqual(broker[11:], (1, 8, 1, 0))
        self.assertEqual(worker[:5], (4, 6, 4, 0, 0x40000000))
        self.assertEqual(worker[6:9], (4096, 8192, 24))
        self.assertEqual(worker[11:], (0, 0, 1, 0))
        self.assertEqual(manifest.struct.unpack_from("<IIIIIIII", artifact, at + 128),
                         (400, 12, 4, 48, 2, 1, 0, 0))
        configs = [manifest.struct.unpack_from("<I", artifact, 40 + n * 64 + 36)[0]
                   for n in range(4)]
        self.assertEqual(configs, [0, 0, 24, 24])
        self.rejects(self.text.replace("template_mask = 12", "template_mask = 3"), scenario=24)
        self.rejects(self.text.replace("child_template_mask = 8", "child_template_mask = 2"), scenario=24)
        self.rejects(self.text.replace("bootstrap_recipe = 1", "bootstrap_recipe = 2", 1), scenario=24)
        self.rejects(self.text, scenario=25)

    def test_template_and_creation_domain_rejections(self):
        self.prepare_hosting()
        replacements = (
            ("identity = 1\nimage = 5", "identity = 0\nimage = 5"),
            ("identity = 2\nimage = 6", "identity = 1\nimage = 6"),
            ("identity = 1\nimage = 5", "identity = 9\nimage = 5"),
            ("image = 5", "image = 4"), ("image = 5", "image = 9"),
            ("boot_config = 21", "boot_config = 4294967296"),
            ("boot_config = 21", "boot_config = true"),
            ("max_descendant_depth = 1", "max_descendant_depth = 2"),
            ("child_template_mask = 2", "child_template_mask = 4"),
            ("child_template_mask = 2", "child_template_mask = 0"),
            ("bootstrap_recipe = 1", "bootstrap_recipe = 2"),
            ("bootstrap_recipe = 1", "bootstrap_recipe = 0"),
            ("owner_identity = 400", "owner_identity = 300"),
            ("template_mask = 3", "template_mask = 4"),
            ("template_mask = 3", "template_mask = 0"),
            ("slot_limit = 4", "slot_limit = 5"), ("slot_limit = 4", "slot_limit = 0"),
            ("page_limit = 48", "page_limit = 49"), ("page_limit = 48", "page_limit = 0"),
            ("page_limit = 48", "page_limit = 4294967296"),
            ("max_depth = 2", "max_depth = 3"), ("max_depth = 2", "max_depth = 0"),
        )
        for old, new in replacements:
            with self.subTest(old=old, new=new):
                self.rejects(self.text.replace(old, new, 1), scenario=21)
        self.rejects(self.text, solo=3)
        self.rejects(self.text, scenario=20)
        self.rejects(self.text + self.text[self.text.index("[[domain]]"):], scenario=21)

    def test_snapshot_catalog_recipe_is_explicit_and_old_catalogs_stay_unselected(self):
        self.prepare_hosting()
        self.text = (ROOT / "cells" / "analysis.toml").read_text()
        artifact = self.compile(scenario=25)
        header = manifest.struct.unpack_from("<IIIIIIIIII", artifact)
        self.assertEqual(header[3:7], (4, 9, 2, 1))
        at = 40 + 4 * 64 + 9 * 16
        broker = manifest.struct.unpack_from("<IIIIQIIIIIIIIII", artifact, at)
        worker = manifest.struct.unpack_from("<IIIIQIIIIIIIIII", artifact, at + 64)
        self.assertEqual((broker[0], broker[1], broker[-2], worker[0], worker[1], worker[-2]), (5, 5, 2, 6, 6, 2))
        self.assertEqual(manifest.struct.unpack_from("<IIIIIIII", artifact, at + 128), (400, 48, 4, 48, 2, 2, 0, 0))
        for scenario in (21, 24):
            self.rejects(self.text, scenario=scenario)
        replacements = (("identity = 5\nimage = 5", "identity = 3\nimage = 5"),
                        ("image = 6", "image = 5"), ("child_template_mask = 32", "child_template_mask = 8"),
                        ("template_mask = 48", "template_mask = 12"), ("bootstrap_recipe = 2", "bootstrap_recipe = 1"))
        for old, new in replacements:
            self.rejects(self.text.replace(old, new, 1), scenario=25)

    def test_rounding_boundaries_and_fixed_template_configurations(self):
        constants, _ = manifest.schema_layout()
        for stack, writable, pages in ((4096, 4096, 1), (4097, 8194, 4),
                                        (4096, 69632, 17), (16384, 81920, 20)):
            self.assertEqual(manifest.private_pages(stack, writable, constants), pages)
        for stack, writable in ((4095, 4095), (16385, 81920), (4096, 69633),
                                 (4097, 4096), (0xffffffff, 0xffffffff)):
            with self.subTest(stack=stack, writable=writable), self.assertRaises(ValueError):
                manifest.private_pages(stack, writable, constants)
        self.prepare_hosting()
        # Approved configurations are fixed in the manifest, but all bounded fixtures parse.
        for stack, writable in ((4096, 4096), (16384, 81920), (4097, 8194)):
            changed = self.text.replace("stack_budget = 8192", f"stack_budget = {stack}", 1)
            changed = changed.replace("writable_budget = 16384", f"writable_budget = {writable}", 1)
            self.compile(changed, scenario=21)

    def test_unknown_fields_boolean_widths_and_catalog_capacity_rejected(self):
        self.rejects(self.text.replace("version = 2", "version = true", 1))
        self.rejects(self.text.replace("version = 2", "version = 2.0", 1))
        self.rejects(self.text.replace("identity = 100", "identity = true", 1))
        self.rejects(self.text.replace("restart_delay = 4", "restart_delay = 4\nreserved = 1", 1))
        self.rejects(self.text + "\nunsupported = 0\n")
        self.rejects(self.text, scenario=21) # An implicit creator is forbidden.
        self.images.pop()
        with self.assertRaises(ValueError):
            self.compile()
        self.prepare_hosting()
        self.images.append(self.images[-1])
        self.images.append(self.images[-1])
        with self.assertRaises(ValueError):
            self.compile(scenario=21)

    def test_compiler_emission_is_accepted_by_the_production_privileged_validator(self):
        library_path = self.directory / "manifest-validator.so"
        cc = shlex.split(os.environ.get("CC", "cc"))
        subprocess.run(cc + ["-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
                             "-Iinclude", "kernel/manifest.c", "-o", str(library_path)],
                       cwd=ROOT, timeout=20, check=True)
        library = ctypes.CDLL(str(library_path))
        class Catalog(ctypes.Structure):
            _fields_ = [("identity", ctypes.c_uint32), ("role", ctypes.c_uint32), ("data", ctypes.c_void_p),
                        ("length", ctypes.c_size_t), ("entry", ctypes.c_uint64)]
        library.z_manifest_validate.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
            ctypes.POINTER(Catalog), ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
        library.z_manifest_validate.restype = ctypes.c_bool
        def validate(artifact):
            data = ctypes.create_string_buffer(artifact)
            backing = [ctypes.create_string_buffer(path.read_bytes()) for path in self.images]
            catalog = (Catalog * len(backing))(*[Catalog(number + 1, number if number < 6 else 5, ctypes.addressof(image),
                len(self.images[number].read_bytes()), 0x40000000) for number, image in enumerate(backing)])
            output = ctypes.create_string_buffer(2048)
            ctypes.memset(output, 0xa5, len(output))
            error = ctypes.c_int(0)
            accepted = library.z_manifest_validate(data, len(artifact), catalog, len(catalog), output,
                                                    ctypes.byref(error))
            if not accepted:
                self.assertEqual(output.raw, bytes([0xa5]) * len(output))
                self.assertNotEqual(error.value, 0)
            return accepted
        for options in ({}, {"solo": 2}, {"scenario": 18}, {"scenario": 19}, {"scenario": 20}):
            self.assertTrue(validate(self.compile(**options)), options)
        self.prepare_hosting()
        for scenario in (21, 22, 23):
            self.assertTrue(validate(self.compile(scenario=scenario)))
        self.text = (ROOT / "cells" / "contracts.toml").read_text()
        self.assertTrue(validate(self.compile(scenario=24)))
        self.text = (ROOT / "cells" / "analysis.toml").read_text()
        self.assertTrue(validate(self.compile(scenario=25)))
        self.text = (ROOT / "cells" / "hosting.toml").read_text()
        artifact = self.compile(scenario=21)
        templates_at = 40 + 4 * 64 + 6 * 16
        domains_at = templates_at + 2 * 64
        # Every reserved-field bit is checked by privileged code, and rejection
        # never partially replaces the previously unpublished parsed state.
        reserved_offsets = (28, 32, 36, templates_at + 12, templates_at + 60,
                            templates_at + 64 + 12, templates_at + 64 + 60,
                            domains_at + 24, domains_at + 28)
        for offset in reserved_offsets:
            for bit in range(32):
                corrupted = bytearray(artifact)
                manifest.struct.pack_into("<I", corrupted, offset, 1 << bit)
                with self.subTest(offset=offset, bit=bit):
                    self.assertFalse(validate(bytes(corrupted)))
        for length in range(40):
            self.assertFalse(validate(artifact[:length]))
        constants, formats = manifest.schema_layout()
        self.assertEqual({name: manifest.struct.calcsize(fmt) for name, fmt in formats.items()},
                         {"header": 40, "cell": 64, "grant": 16, "template": 64, "domain": 32})
        self.assertTrue(all(fmt.startswith("<") for fmt in formats.values()))
        self.assertEqual(constants["ARTIFACT_MAX"], 1320)


if __name__ == "__main__":
    unittest.main()
