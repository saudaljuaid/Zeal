"""Independent controlled omissions/counterfeits for console acceptance."""
import copy
import hashlib
import pathlib
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

import console_acceptance as oracle


class Fixture:
    def __init__(self, directory):
        self.directory = pathlib.Path(directory)
        self.lines = []
        self.tick = 0
        self.serial = bytearray()
        self.sent = bytearray()
        self.exchanges = []
        self.next_app = 1
        self.next_block = 1
        self.next_handle = 1
        self.manifest = self.directory / "manifest.bin"
        roots = b"".join(struct.pack("<4IQ6I16s", (cell + 1) * 100, cell + 1, 4,
                                     5 if cell == 2 else 1, 0x40000000, 65536,
                                     16384, 81920, 27, 3, 4,
                                     (f"cell{cell}".encode()).ljust(16, b"\0"))
                          for cell in range(4))
        grants = [(300, 200, (10, 11, 13)), (200, 300, (14,)),
                  (200, 100, (7,)), (100, 200, (9,))]
        rows = b"".join(struct.pack("<4I", holder, target, sum(1 << (op - 1) for op in operations), 0)
                        for holder, target, operations in grants)
        self.manifest.write_bytes(struct.pack("<10I", 0x4c41455a, 2, 40 + len(roots) + len(rows),
                                              4, len(grants), 0, 0, 0, 0, 0) + roots + rows)
        for cell in range(4):
            self.event("boot", cell, image=cell + 1, abi=4, entry=0x40000000,
                       image_budget=65536, writable_budget=81920, config=27)
        for name in ("console-input", "console-output"):
            self.rejection(name, 3, -2, 0x40022000, 1, 0)
            self.rejection(name, 2, -5, 0, 1, 0)
            self.rejection(name, 2, -6, 0x40022000, 65, 0)
            self.rejection(name, 2, -1, 0x40022000, 1, 1)
        self.output(oracle.PROMPT)
        self.event("console-denied-verified", 3, value=2)
        self.event("console-progress", 3, value=1)
        start = len(self.trusted.encode())
        self.event("console-progress", 3, value=2)
        self.event("console-progress", 3, value=3)
        self.idle = dict(trusted_start=start, trusted_end=len(self.trusted.encode()),
                         input_start=0, input_end=0, duration=.2)
        self.command("help", b"help\r\n", b"help version info cat <path>\n")
        self.command("version", b"version\n", b"Zeal build=unit-seam abi=4\n", self.system_info)
        self.command("info", b"info\r", b"identity=300 role=2 generation=1 endpoint=0x103\n"
                     b"live ticks={observed_tick} filesystem=0x102 block=0x101\n"
                     b"configured image=65536 stack=16384 writable=81920 console_io=64 line=96\n"
                     b"boot parent=0x0 depth=0 console=1 scenario=27\nglobal statistics: unavailable\n", self.system_info)
        self.command("cat-hello-first", b"cat /hello\n", oracle.HELLO + b"\n", self.cat)
        self.command("cat-missing", b"cat /missing\n", b"error: not found\n", self.missing)
        self.command("malformed-extra", b"cat /hello extra\n", b"error: syntax\n")
        self.command("overflow", b"help" + b" " * 97 + b"\n", b"error: line too long\n")
        self.command("empty", b"\n", b"\n")
        self.command("cat-hello-second", b"cat /hello\n", oracle.HELLO + b"\n", self.cat)
        self.finish = dict(qmp_quit_acknowledged=True, exit=0, forced_termination=False)

    @property
    def trusted(self):
        return "".join(self.lines)

    def event(self, name, cell, **fields):
        self.tick += 1
        values = dict(cell=cell, identity=(cell + 1) * 100, generation=1, tick=self.tick, **fields)
        self.lines.append("EVENT " + name + " " + " ".join(f"{k}=0x{v:x}" for k, v in values.items()) + "\n")

    def io(self, name, data):
        for offset in range(0, len(data), 64):
            chunk = data[offset:offset + 64]
            padded = chunk.ljust(64, b"\0")
            fields = {f"data{i}": int.from_bytes(padded[i * 8:(i + 1) * 8], "little") for i in range(8)}
            self.event(name, 2, privilege=3, result=len(chunk), count=len(chunk), requested=len(chunk), **fields)

    def rejection(self, name, cell, result, address, requested, reserved):
        self.event(name, cell, privilege=3, result=result & 0xffffffffffffffff, count=0,
                   address=address, requested=requested, reserved=reserved,
                   **{f"data{i}": 0 for i in range(8)})

    def system_info(self):
        padded = b"unit-seam".ljust(48, b"\0")
        self.event("console-system-info", 2, privilege=3, address=0x40022000, size=80, reserved=0, result=0,
                   abi=4, console_limit=64, image_budget=65536, stack_budget=16384,
                   writable_budget=81920, console_entitled=1, observed_tick=self.tick + 1,
                   **{f"build{i}": int.from_bytes(padded[i * 8:(i + 1) * 8], "little") for i in range(6)})

    def output(self, data):
        self.io("console-output", data)
        self.serial.extend(data)

    def command(self, case, raw, response, operation=None):
        start = len(self.serial)
        self.io("console-input", raw)
        self.sent.extend(raw)
        if operation is not None:
            operation()
        response = response.replace(b"{observed_tick}", str(self.tick).encode())
        self.output(response + oracle.PROMPT)
        self.exchanges.append(dict(case=case, input_hex=raw.hex(), serial_start=start, serial_end=len(self.serial)))

    def transfer(self, source, recipient, operation, data, length=32):
        fields = dict(target=0x100 + recipient + 1, cap=source + 1, outcome=0, operation=operation, length=length,
                      request=int.from_bytes(data[:8], "little"), handle=int.from_bytes(data[8:16], "little"),
                      offset=int.from_bytes(data[16:20], "little"), result=int.from_bytes(data[20:24], "little"),
                      data=int.from_bytes(data[24:32], "little"), sender=0)
        fields.update({f"raw{i}": int.from_bytes(data[i * 8:(i + 1) * 8], "little") for i in range(4)})
        self.event("storage-ipc", source, **fields)
        fields.update(sender=0x100 + source + 1, cap=0)
        self.event("storage-ipc-deliver", recipient, **fields)

    def request(self, operation, handle=0, offset=0, count=0, name=None):
        ident = self.next_app
        self.next_app += 1
        if name is not None:
            data = ident.to_bytes(8, "little") + name.ljust(16, b"\0") + bytes((len(name), 1)) + bytes(6)
        else:
            data = struct.pack("<QQIIQ", ident, handle, offset, count, 0)
        self.transfer(2, 1, operation, data)
        return ident

    def reply(self, ident, operation, handle, offset, count, data=b""):
        self.event("storage-fs", 1, request=ident, operation=operation, result=count & 0xffffffff)
        self.transfer(1, 2, 14, struct.pack("<QQII", ident, handle, offset, count & 0xffffffff) + data.ljust(8, b"\0"))

    def cat(self):
        ident = self.request(10, name=b"/hello")
        handle = (1 << 32) | (self.next_handle << 8) | 1
        self.next_handle += 1
        self.reply(ident, 10, handle, 0, 0)
        for offset, amount in ((0, 8), (8, len(oracle.HELLO) - 8), (len(oracle.HELLO), 0)):
            ident = self.request(11, handle, offset, 8)
            block = self.next_block
            self.next_block += 1
            self.event("storage-link", 1, request=ident, block_request=block)
            self.transfer(1, 0, 7, struct.pack("<QQIIQ", block, 0, offset, amount, 0))
            self.event("storage-block", 0, request=block, operation=7, result=amount)
            data = oracle.HELLO[offset:offset + amount]
            self.transfer(0, 1, 9, struct.pack("<QQII", block, 0, offset, amount) + data.ljust(8, b"\0"))
            self.reply(ident, 11, handle, offset, amount, data)
            if amount:
                self.event("storage-verified", 2, request=ident, data=int.from_bytes(data.ljust(8, b"\0"), "little"))
        ident = self.request(13, handle)
        self.reply(ident, 13, handle, 0, 0)

    def missing(self):
        ident = self.request(10, name=b"/missing")
        self.reply(ident, 10, 0, 0, -9)

    def verify(self, **changed):
        values = dict(trusted=self.trusted, serial=bytes(self.serial), sent=bytes(self.sent),
                      exchanges=copy.deepcopy(self.exchanges), idle=self.idle,
                      manifest=self.manifest, finish=self.finish)
        values.update(changed)
        return oracle.verify(**values)


class ConsoleOracleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Fixture(self.temporary.name)

    def test_complete_controlled_trace(self):
        result = self.fixture.verify()
        self.assertEqual(result["cat_reads"], 2)
        self.assertEqual(result["filesystem_requests"], 11)
        self.assertEqual(result["block_reads"], 6)
        self.assertEqual(result["idle_progress_events"], 2)
        self.assertTrue(result["finite_finish"])

    def test_all_permanent_negative_controls(self):
        f = self.fixture
        result = oracle.negative_controls(f.trusted, bytes(f.serial), bytes(f.sent), f.exchanges,
                                          f.idle, f.manifest, f.finish)
        self.assertGreaterEqual(len(result), 30)
        self.assertTrue(all(item["rejected"] for item in result))

    def test_missing_close_cannot_pass_with_correct_hello(self):
        f = self.fixture
        trusted = "\n".join(line for line in f.trusted.splitlines()
                              if not (line.startswith("EVENT storage-ipc ") and
                                      " cell=0x2 " in line and " operation=0xd " in line)) + "\n"
        with self.assertRaises(AssertionError):
            f.verify(trusted=trusted)

    def test_static_prompt_and_expected_hello_are_insufficient(self):
        with self.assertRaises(AssertionError):
            self.fixture.verify(trusted="", serial=oracle.PROMPT + oracle.HELLO + oracle.PROMPT)

    def test_unsupported_or_duplicate_trusted_fields(self):
        for line in ("EVENT console-input cell=0x2 cell=0x2", "EVENT console-input count=64",
                     "EVENT console-input cell=0x2 trailing"):
            with self.subTest(line=line), self.assertRaises(AssertionError):
                oracle.events(line)

    def test_uart_count_padding_and_byte_preservation(self):
        fields = dict(count=1, **{f"data{i}": 0 for i in range(8)})
        fields["data0"] = 255
        self.assertEqual(oracle.event_bytes(fields), b"\xff")
        fields["data0"] |= 1 << 8
        with self.assertRaises(AssertionError):
            oracle.event_bytes(fields)
        fields["count"] = 65
        with self.assertRaises(AssertionError):
            oracle.event_bytes(fields)

    def test_console_identity_does_not_substitute_for_entitlement(self):
        data = bytearray(self.fixture.manifest.read_bytes())
        struct.pack_into("<I", data, 40 + 2 * 64 + 12, 1)
        self.fixture.manifest.write_bytes(data)
        with self.assertRaises(AssertionError):
            self.fixture.verify()

    def test_build_identifier_must_match_actual_compiled_identification(self):
        self.fixture.verify(build_id="unit-seam")
        with self.assertRaises(AssertionError):
            self.fixture.verify(build_id="different-source")


class ConsoleSourceHashTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.sources = {
            "Makefile": b"all: source\n", "README.md": b"exported-source console\n",
            "LICENSE": b"license bytes\n", "NOTICE": b"notice bytes\n",
            ".gitignore": b"/build/\n", "rust-toolchain.toml": b"channel = 'stable'\n",
            "kernel/console.c": b"checked copy boundary\n", "cells/console.zig": b"actual parser\n",
            "tests/console_test.py": b"causal oracle\n", "docs/console.md": b"actual command syntax\n",
            ".github/workflows/research.yml": b"full supported make test\n",
            "assets/zeal.png": b"\x89PNG\r\n\x1a\noriginal logo bytes",
        }
        for name, data in self.sources.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        for name in ("build/zeal.img", "work/transcript.log", ".zig-cache/object.bin",
                     "zig-cache/object.bin", "zig-out/cell.bin", "tests/__pycache__/test.pyc",
                     "policy/target/libpolicy.a", "cells/cached.pyc", "tests/cached.pyo"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"generated output must be ignored")

    @property
    def expected(self):
        return {name: hashlib.sha256(data).hexdigest() for name, data in self.sources.items()}

    def test_real_export_tree_without_git_metadata(self):
        self.assertFalse((self.root / ".git").exists())
        self.assertEqual(oracle.source_hashes(self.root), self.expected)
        (self.root / "kernel/console.c").write_bytes(b"changed actual checked boundary\n")
        changed = oracle.source_hashes(self.root)
        self.assertNotEqual(changed["kernel/console.c"], self.expected["kernel/console.c"])
        self.assertEqual(set(changed), set(self.expected))
        (self.root / "build/zeal.img").write_bytes(b"overwritten generated boot image")
        (self.root / "tests/__pycache__/test.pyc").write_bytes(b"changed generated cache")
        self.assertEqual(oracle.source_hashes(self.root), changed)

    def test_git_unavailable_or_timed_out_uses_export_sources(self):
        for error in (FileNotFoundError("git executable unavailable"),
                      subprocess.TimeoutExpired("git ls-files", 5),
                      subprocess.CalledProcessError(128, "git ls-files")):
            with self.subTest(error=type(error).__name__), \
                    mock.patch.object(oracle.subprocess, "run", side_effect=error) as run:
                self.assertEqual(oracle.source_hashes(self.root), self.expected)
                self.assertEqual(run.call_args.kwargs["timeout"], 5)

    def test_successful_git_listing_keeps_git_selection_and_deduplicates(self):
        listed = "kernel/console.c\nassets/zeal.png\nbuild/zeal.img\nkernel/console.c\n"
        result = subprocess.CompletedProcess(["git", "ls-files"], 0, stdout=listed, stderr="")
        with mock.patch.object(oracle.subprocess, "run", return_value=result):
            self.assertEqual(oracle.source_hashes(self.root),
                             {name: self.expected[name] for name in ("assets/zeal.png", "kernel/console.c")})

    def test_unreadable_source_error_is_not_masked(self):
        with mock.patch.object(oracle.subprocess, "run", side_effect=FileNotFoundError("no git")), \
                mock.patch.object(pathlib.Path, "read_bytes", side_effect=PermissionError("unreadable source")), \
                self.assertRaises(PermissionError):
            oracle.source_hashes(self.root)


if __name__ == "__main__":
    unittest.main()
