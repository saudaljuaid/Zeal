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
        self.profile = "legacy"
        self.files = {b"/hello": dict(slot=0, length=len(oracle.HELLO), readonly=True)}
        self.block = bytearray(512)
        self.block[:len(oracle.HELLO)] = oracle.HELLO
        self.manifest = self.directory / "manifest.bin"
        roots = b"".join(struct.pack("<4IQ6I16s", (cell + 1) * 100, cell + 1, 4,
                                     5 if cell == 2 else 1, 0x40000000, 65536,
                                     16384, 81920, 27, 3, 4,
                                     (f"cell{cell}".encode()).ljust(16, b"\0"))
                          for cell in range(4))
        grants = [(300, 200, (10, 11, 12, 13, 21, 22)), (200, 300, (14,)),
                  (200, 100, (7, 8)), (100, 200, (9,))]
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
        self.command("help", b"help\r\n", b"help version info cat <path> ls write <path> [text] append <path> <text>\n")
        self.command("version", b"version\n", b"Zeal build=unit-seam abi=4\n", self.system_info)
        self.command("info", b"info\r", b"identity=300 role=2 generation=1 endpoint=0x103\n"
                     b"live ticks={observed_tick} filesystem=0x102 block=0x101\n"
                     b"configured image=65536 stack=16384 writable=81920 console_io=64 line=96\n"
                     b"boot parent=0x0 depth=0 console=1 scenario=27\nglobal statistics: unavailable\n", self.system_info)
        self.command("cat-hello-first", b"cat /hello\n", oracle.HELLO + b"\n", self.cat)
        self.command("cat-missing", b"cat /missing\n", b"cat: /missing: file not found\n", self.missing)
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
        _, echo = oracle.edited_input(raw)
        self.output(echo + response.replace(b"\n", b"\r\n") + oracle.PROMPT)
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

    def request(self, operation, handle=0, offset=0, count=0, name=None, existing=True, data=b""):
        ident = self.next_app
        self.next_app += 1
        if name is not None:
            data = (ident.to_bytes(8, "little") + name.ljust(16, b"\0") + bytes((len(name), 1)) + bytes(6)) if existing else \
                (ident.to_bytes(8, "little") + name).ljust(32, b"\0")
        else:
            data = struct.pack("<QQII", ident, handle, offset, count) + data.ljust(8, b"\0")
        self.transfer(2, 1, operation, data, 32 if name is None or existing else 8 + len(name))
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
                      manifest=self.manifest, finish=self.finish, profile=self.profile)
        values.update(changed)
        return oracle.verify(**values)


class WritableFixture(Fixture):
    """Independent synthetic packet trace; production state is tested by Zig/QEMU."""
    def __init__(self, directory, profile="basic"):
        super().__init__(directory)
        self.profile = profile
        cases = oracle.command_cases(profile)
        if profile == "basic":
            cases = cases[15:]
        for case, raw in cases:
            self.storage_case(case, raw)

    def block_transfer(self, app, operation, offset, count, data=b""):
        ident = self.next_block
        self.next_block += 1
        self.event("storage-link", 1, request=app, block_request=ident)
        self.transfer(1, 0, operation, struct.pack("<QQII", ident, 0, offset, count) + data.ljust(8, b"\0"))
        if operation == 8:
            self.block[offset:offset + count] = data
            returned = b""
        else:
            returned = bytes(self.block[offset:offset + count])
        self.event("storage-block", 0, request=ident, operation=operation, result=count)
        self.transfer(0, 1, 9, struct.pack("<QQII", ident, 0, offset, count) + returned.ljust(8, b"\0"))
        return returned

    def file_io(self, verb, name, payload):
        if verb == "ls":
            for index in range(4):
                ident = self.request(21, offset=index)
                entry = next(((name, file) for name, file in self.files.items() if file["slot"] == index), None)
                metadata = -9 if entry is None else len(entry[0]) | int(entry[1]["readonly"]) << 8 | entry[1]["length"] << 16
                self.event("storage-fs", 1, request=ident, operation=21, result=metadata & 0xffffffff)
                self.transfer(1, 2, 14, struct.pack("<QII", ident, index, metadata & 0xffffffff) +
                              (bytes(16) if entry is None else entry[0].ljust(16, b"\0")))
            return
        ident = self.request(10, name=name, existing=verb != "write")
        if name not in self.files:
            if verb != "write":
                self.reply(ident, 10, 0, 0, -9)
                return
            index = next(slot for slot in range(4) if slot not in {file["slot"] for file in self.files.values()})
            for offset in range(0, 128, 8):
                self.block_transfer(ident, 8, index * 128 + offset, 8, bytes(8))
            self.files[name] = dict(slot=index, length=0, readonly=False)
        file = self.files[name]
        handle = 1 << 32 | self.next_handle << 8 | 1
        self.next_handle += 1
        self.reply(ident, 10, handle, 0, 0)
        position = 0
        if verb in ("cat", "append"):
            while True:
                count = min(8, 128 - position)
                amount = min(count, file["length"] - position)
                ident = self.request(11, handle, position, count)
                returned = self.block_transfer(ident, 7, file["slot"] * 128 + position, amount)
                self.reply(ident, 11, handle, position, amount, returned)
                if not amount:
                    break
                self.event("storage-verified", 2, request=ident, data=int.from_bytes(returned.ljust(8, b"\0"), "little"))
                position += amount
        if verb == "write":
            ident = self.request(22, handle)
            self.reply(ident, 22, handle, 0, -2 if file["readonly"] else 0)
            if not file["readonly"]:
                file["length"] = 0
        if verb in ("write", "append") and (verb != "write" or not file["readonly"]) and position + len(payload) <= 128:
            chunks = [payload[offset:offset + 8] for offset in range(0, len(payload), 8)]
            if verb == "append" and not chunks:
                chunks = [b""]
            for chunk in chunks:
                ident = self.request(12, handle, position, len(chunk), data=chunk)
                if not file["readonly"]:
                    self.block_transfer(ident, 8, file["slot"] * 128 + position, len(chunk), chunk)
                    file["length"] = max(file["length"], position + len(chunk))
                self.reply(ident, 12, handle, position, -2 if file["readonly"] else len(chunk))
                if file["readonly"]:
                    break
                position += len(chunk)
        ident = self.request(13, handle)
        self.reply(ident, 13, handle, 0, 0)

    def storage_case(self, case, raw):
        line, _ = oracle.edited_input(raw)
        verb, name, payload = oracle.parsed_command(line)
        if verb == "ls":
            response = b"".join(name + f" {file['length']} bytes ".encode() +
                                (b"read-only" if file["readonly"] else b"writable") + b"\n"
                                for name, file in sorted(self.files.items(), key=lambda item: item[1]["slot"]))
        elif verb in ("cat", "append") and name not in self.files:
            response = verb.encode() + b": " + name + b": file not found\n"
        elif verb == "cat":
            file = self.files[name]
            response = oracle.rendered_file(bytes(self.block[file["slot"] * 128:file["slot"] * 128 + file["length"]])).replace(b"\r\n", b"\n")
        elif verb in ("write", "append"):
            file = self.files.get(name)
            error = b"access denied" if file and file["readonly"] else \
                b"file or transfer exceeds its limit" if verb == "append" and file["length"] + len(payload) > 128 else None
            response = verb.encode() + b": " + name + (b": " + error + b" (0 bytes acknowledged; incomplete)\n" if error else
                                                        f": {len(payload)} bytes acknowledged\n".encode())
        elif case.startswith("help"):
            response = b"help version info cat <path> ls write <path> [text] append <path> <text>\n"
        elif case == "overflow":
            response = b"error: line too long\n"
        else:
            response = b"error: syntax\n"
        self.command(case, raw, response, (lambda: self.file_io(verb, name, payload)) if verb in ("ls", "cat", "write", "append") else None)


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

    def test_complete_writable_profiles_have_independent_actual_bytes_and_closes(self):
        for profile in ("basic", "capacity", "overflow", "repeat"):
            with self.subTest(profile=profile):
                fixture = WritableFixture(self.temporary.name, profile)
                proof = fixture.verify()
                self.assertGreater(proof["block_writes"], 0)
                self.assertGreater(proof["successful_truncations"], 0)
                self.assertGreater(len(proof["closed_handles"]), 2)
                if profile == "basic":
                    self.assertEqual(proof["actual_files"]["/note"]["length"], 0)
                    self.assertEqual(proof["acknowledged_append_bytes"], 1)
                    self.assertEqual(proof["list_slot_queries"], 8)
                elif profile == "capacity":
                    self.assertEqual(proof["actual_files"]["/full"]["data_hex"], (b"A" * 64 + b"B" * 64).hex())
                elif profile == "overflow":
                    self.assertEqual(proof["actual_files"]["/cap"]["data_hex"], (b"C" * 80).hex())
                    self.assertEqual(proof["actual_files"]["/hello"]["data_hex"], oracle.HELLO.hex())
                else:
                    self.assertEqual(proof["actual_files"]["/repeat"]["data_hex"], b"r9".hex())

    def test_writable_counterfeits_reject_missing_write_ack_and_stale_suffix(self):
        fixture = WritableFixture(self.temporary.name)
        controls = oracle.negative_controls(fixture.trusted, bytes(fixture.serial), bytes(fixture.sent),
                                            fixture.exchanges, fixture.idle, fixture.manifest,
                                            fixture.finish, fixture.profile)
        self.assertGreaterEqual(len(controls), 40)
        labels = {item["control"] for item in controls}
        self.assertIn("coherently missing actual block write with successful acknowledgment", labels)
        self.assertIn("coherent counterfeit write acknowledgment length", labels)
        self.assertIn("coherent stale suffix bytes after shorter replacement", labels)
        self.assertIn("coherent write acknowledgment delivered after claimed completion prompt", labels)
        self.assertTrue(all(item["rejected"] for item in controls))
        reasons = {item["control"]: item["reason"] for item in controls}
        expected = {
            "expected write string without actual file_write": "unrelated filesystem outcome/publication or missing application result",
            "coherently missing actual block write with successful acknowledgment": "filesystem mutation/read lacks its complete actual block transactions",
            "coherent counterfeit write acknowledgment length": "file write falsely acknowledged an invalid/partial extent",
            "stale suffix replacement without explicit truncate": "replacement lacks acknowledged explicit generation-safe truncate",
            "coherent invented ls length despite expected UART strings": "list metadata/name differs from actual independently reconstructed filesystem entries",
            "coherent stale suffix bytes after shorter replacement": "file read exposed stale suffix, another extent or counterfeit bytes/EOF",
            "coherent write acknowledgment delivered after claimed completion prompt": "command printed completion/data or next prompt before its actual authenticated acknowledgment",
        }
        for label, reason in expected.items():
            with self.subTest(label=label):
                self.assertEqual(reasons[label], reason)

    def test_counterfeit_builder_preserves_kernel_trace_format_and_measured_idle(self):
        fixture = WritableFixture(self.temporary.name)
        kernel_trace = "".join("EVENT " + kind + " " + " ".join(f"{key}=0x{value:016x}" for key, value in fields.items()) + "\r\n"
                               for kind, fields in oracle.events(fixture.trusted))
        idle = oracle.remap_idle_window(fixture.trusted, kernel_trace, fixture.idle)
        identity = oracle.rewrite_events(kernel_trace)
        self.assertEqual(identity, kernel_trace)
        proof = oracle.verify(identity, bytes(fixture.serial), bytes(fixture.sent), copy.deepcopy(fixture.exchanges),
                              idle, fixture.manifest, fixture.finish, profile=fixture.profile)
        self.assertEqual(proof["actual_files"]["/note"]["length"], 0)
        records = oracle.events(kernel_trace)
        listed = next(index for index, (kind, fields) in enumerate(records)
                      if kind == "storage-fs" and fields["operation"] == 21)
        changed = oracle.rewrite_events(kernel_trace, {listed: {"result": records[listed][1]["result"] ^ (1 << 16)}})
        self.assertEqual(changed[:idle["trusted_end"]], kernel_trace[:idle["trusted_end"]])
        self.assertEqual(len(changed), len(kernel_trace))
        self.assertEqual(changed.count("\r\n"), kernel_trace.count("\r\n"))
        removed = oracle.rewrite_events(kernel_trace, removed=[0])
        remapped = oracle.remap_idle_window(kernel_trace, removed, idle)
        self.assertEqual(oracle.events(removed[remapped["trusted_start"]:remapped["trusted_end"]]),
                         oracle.events(kernel_trace[idle["trusted_start"]:idle["trusted_end"]]))
        normalized = kernel_trace.replace("\r\n", "\n")
        normalized_idle = oracle.remap_idle_window(kernel_trace, normalized, idle)
        oracle.verify(normalized, bytes(fixture.serial), bytes(fixture.sent), copy.deepcopy(fixture.exchanges),
                      normalized_idle, fixture.manifest, fixture.finish, profile=fixture.profile)

    def test_actual_uart_payload_spaces_are_preserved_and_empty_payloads_differ_from_missing(self):
        self.assertEqual(oracle.parsed_command(b"   write   /note  a  b  "), ("write", b"/note", b" a  b  "))
        self.assertEqual(oracle.parsed_command(b"write /note"), ("write", b"/note", b""))
        self.assertEqual(oracle.parsed_command(b"write /note "), ("write", b"/note", b""))
        self.assertEqual(oracle.parsed_command(b"append /note "), ("append", b"/note", b""))
        self.assertEqual(oracle.parsed_command(b"append /note"), (None, None, None))
        fixture = WritableFixture(self.temporary.name, "repeat")
        proof = fixture.verify()
        spaces = next(item for item in proof["causal_file_commands"] if item["case"] == "cat-spaces")
        self.assertEqual(bytes.fromhex(spaces["read_hex"]), b" a  b  ")

    def test_overlapping_client_and_block_local_ids_are_scoped_to_authenticated_endpoints(self):
        fixture = WritableFixture(self.temporary.name)
        records = oracle.events(fixture.trusted)
        console = {f["request"] for kind, f in records if kind == "storage-ipc" and f["cell"] == 2}
        block = {f["request"] for kind, f in records if kind == "storage-ipc" and f["cell"] == 1 and f["operation"] in (7, 8)}
        self.assertTrue(console & block)
        fixture.verify()

    def test_overflow_and_unsupported_editor_bytes_never_execute_valid_prefix(self):
        for raw in (b"write /note valid" + b" " * 96 + b"\x08\n", b"write /note valid\x00\x08\n"):
            with self.subTest(raw=raw):
                line, echo = oracle.edited_input(raw)
                self.assertIsNone(line)
                self.assertTrue(echo.endswith(b"\r\n"))
                self.assertEqual(oracle.parsed_command(line), (None, None, None))


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
