"""Independent immutable-input model compared after every production action.

Python represents files by names, block bytes by address dictionaries, handles
by owner identities, inputs by (issuer, serial, placement), and bindings by a
reader placement map. The driver calls production Fs/Block/Table methods; it is
not a clone of the storage dispatcher. Actions and first failing witnesses are
retained under build/analysis-model, including compilation/runtime failures.
"""
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import random
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
MASK = (1 << 64) - 1
LIMIT = (1 << 56) - 1
SEEDS = (0, 1, 7, 19, 73, 257, 1021, 65537, 104729, 0x5EA17)
NAMES = ("/hello", "/alpha", "/beta", "/gamma", "/overflow")
HELLO = b"Zeal survives."


@dataclass
class Input:
    identity: tuple
    owner: int
    transaction: int
    handle: int
    block: int
    filename: str
    file_number: int
    revision: int
    length: int
    capture: tuple = ()
    readers: dict = field(default_factory=dict)
    state: int = 1
    status: int = 0
    checker: int = 0
    settled_reader: int = 0

    @property
    def token(self):
        return self.identity[1] << 8 | 0xA1 + self.identity[2]


class Model:
    def __init__(self):
        self.issuer, self.generation, self.block = 0x102, 1, 0x101
        self.serial, self.handle_serial = 1, 1
        self.inputs, self.handles = {}, {}
        self.files = {"/hello": dict(number=0, readonly=1, length=len(HELLO), revision=1)}
        self.actual = dict(enumerate(HELLO))
        self.old_tokens = []
        self.owner_watermarks = {}

    def reset_metadata(self):
        self.files = {"/hello": dict(number=0, readonly=1, length=len(HELLO), revision=1)}
        self.handles.clear()

    def handle(self, owner, token):
        item = self.handles.get(token)
        return item if owner and item and item["owner"] == owner and token >> 32 == self.generation else None

    def record(self, token, issuer=0):
        if issuer and issuer != self.issuer:
            return None
        return next((r for r in self.inputs.values() if r.token == token), None)

    def prepare_read(self, owner, token, offset, count):
        handle = self.handle(owner, token)
        if not handle or not self.block:
            return -3, None, 0
        if count > 8:
            return -6, None, 0
        if offset + count >= 1 << 32:
            return -1, None, 0
        if offset > 128:
            return -6, None, 0
        file = self.files[handle["name"]]
        amount = 0 if offset >= file["length"] else min(count, file["length"] - offset)
        return 0, handle["name"], amount

    def coherent(self, record):
        handle = self.handle(record.owner, record.handle)
        file = self.files.get(record.filename)
        return self.block and self.block == record.block and handle and handle["name"] == record.filename and file and (
            file["revision"], file["length"]) == (record.revision, record.length)

    def fail(self, record, reason):
        record.capture, record.readers = (), {}
        record.state, record.status = 4, reason
        return reason

    def apply(self, action):
        op, owner, token, offset, count, data, issuer = action
        result, value, output = 0, 0, bytes(8)
        record = self.record(token, issuer)
        if op == "O":
            name = NAMES[token % len(NAMES)]
            if not owner:
                return -1, value, output
            if not self.block:
                return -3, value, output
            if not self.generation or self.generation > 0xFFFFFFFF or self.handle_serial > 0xFFFFFF:
                return -7, value, output
            free_file = min({0, 1, 2, 3} - {f["number"] for f in self.files.values()}, default=None)
            if name not in self.files and free_file is None:
                return -7, value, output
            free_handle = min(set(range(1, 9)) - {h["placement"] for h in self.handles.values()}, default=None)
            if free_handle is None:
                return -7, value, output
            if name not in self.files:
                self.files[name] = dict(number=free_file, readonly=0, length=0, revision=1)
                for pos in range(free_file * 128, free_file * 128 + 128):
                    self.actual[pos] = 0
            value = self.generation << 32 | self.handle_serial << 8 | free_handle
            self.handle_serial += 1
            self.handles[value] = dict(owner=owner, name=name, placement=free_handle)
        elif op == "H":
            if not self.handle(owner, token):
                result = -3
            else:
                del self.handles[token]
        elif op == "W":
            handle = self.handle(owner, token)
            if not handle or not self.block:
                return -3, value, output
            file = self.files[handle["name"]]
            if file["readonly"]:
                return -2, value, output
            if count > 8:
                return -6, value, output
            if offset + count >= 1 << 32:
                return -1, value, output
            if offset > 128 or offset + count > 128:
                return -6, value, output
            if offset > file["length"]:
                return -1, value, output
            if count and file["revision"] == MASK:
                return -7, value, output
            word = data.to_bytes(8, "little")
            for i, byte in enumerate(word[:count]):
                self.actual[file["number"] * 128 + offset + i] = byte
            if issuer == 1:
                return -8, value, output
            file["length"] = max(file["length"], offset + count)
            file["revision"] += int(count > 0)
            result = count
        elif op == "A":
            transaction, source_handle = token, offset
            if not (1 <= owner & 255 <= 8 and 0 < owner <= (1 << 63) - 1 and owner >> 8) or not transaction or not source_handle or not (self.issuer & 255 == 2 and 0 < self.issuer <= (1 << 63) - 1 and self.issuer >> 8):
                return -1, value, output
            old = next((r for r in self.inputs.values() if (r.owner, r.transaction) == (owner, transaction)), None)
            if old:
                return (-1 if old.handle != source_handle else -4 if old.state == 1 else old.status), (0 if old.handle != source_handle else old.token), output
            previous_owner, previous_transaction = self.owner_watermarks.get((owner & 255) - 1, (0, 0))
            if owner >> 8 < previous_owner >> 8 or owner == previous_owner and transaction <= previous_transaction:
                return -3, value, output
            status, filename, _ = self.prepare_read(owner, source_handle, 0, 0)
            if status:
                return status, value, output
            file = self.files[filename]
            if file["length"] > 128:
                return -6, value, output
            if not self.block:
                return -3, value, output
            if not self.serial or self.serial > LIMIT or len(self.inputs) == 2:
                return -7, value, output
            placement = min({0, 1} - {r.identity[2] for r in self.inputs.values()})
            identity = self.issuer, self.serial, placement
            self.serial = 0 if self.serial == LIMIT else self.serial + 1
            record = Input(identity, owner, transaction, source_handle, self.block, filename, file["number"], file["revision"], file["length"])
            self.inputs[identity] = record
            self.owner_watermarks[(owner & 255) - 1] = owner, transaction
            value = record.token
        elif op == "C":
            if not record:
                return -3, value, output
            status, filename, amount = self.prepare_read(record.owner, record.handle, offset, count)
            if status:
                return status, value, output
            file = self.files[filename]
            read = bytes(self.actual.get(file["number"] * 128 + offset + i, 0) for i in range(amount))
            output = read.ljust(8, b"\0")
            if data:
                output = bytes([output[0] ^ (data & 255)]) + output[1:]
            if record.owner != owner or record.state != 1:
                result = -3
            elif not self.coherent(record):
                result = self.fail(record, -3)
            elif offset != len(record.capture) or amount != min(8, record.length - len(record.capture)) or not amount:
                result = -1
            else:
                record.capture += tuple(output[:amount])
        elif op == "P":
            if not record or record.owner != owner or record.state != 1:
                result = -3
            elif not self.coherent(record):
                result = self.fail(record, -3)
            elif len(record.capture) != record.length:
                result = -4
            else:
                record.state = 2
        elif op == "F":
            reason = (-8, -3, -1, 0)[offset % 4]
            if not record or record.owner != owner or record.state != 1 or not reason:
                result = -3
            else:
                result = self.fail(record, reason)
        elif op in ("B", "V", "L"):
            reader = offset
            if not record or record.owner != owner or record.state != 2:
                result = -3
            elif not reader or reader == owner:
                result = -1
            elif op in ("B", "L"):
                if op == "L" and record.checker not in (0, reader):
                    return -2, value, output
                if reader not in record.readers:
                    if len(record.readers) == 2:
                        result = -7
                    else:
                        record.readers[reader] = min({0, 1} - set(record.readers.values()))
                if op == "L" and result == 0:
                    record.checker = reader
            else:
                record.readers.pop(reader, None)
                if record.checker == reader:
                    record.checker = 0
        elif op == "Z":
            if not record:
                result = -3
            elif not owner or record.checker != owner:
                result = -2
            elif record.state == 5:
                result = 0 if not offset or record.settled_reader == offset else -1
            elif record.state != 2 or record.block != self.block or not self.block or owner not in record.readers:
                result = -3
            elif offset and (offset == owner or offset == record.owner or offset not in record.readers):
                result = -2
            else:
                record.state, record.status, record.capture, record.readers = 5, 0, (), {}
                record.settled_reader = offset
        elif op == "R":
            if not record:
                result = -3
            elif not owner or record.state != 2 or record.block != self.block or not self.block or (owner != record.owner and owner not in record.readers):
                result = -2
            elif count > 8:
                result = -6
            elif offset + count >= 1 << 32:
                result = -1
            elif offset > 128:
                result = -6
            else:
                result = 0 if offset >= record.length else min(count, record.length - offset)
                output = bytes(record.capture[offset:offset + result]).ljust(8, b"\0")
        elif op == "T":
            if not record or record.owner != owner:
                result = -3
            else:
                record.state, record.status, record.capture, record.readers = (5 if record.state == 5 else 3), 0, (), {}
        elif op == "E":
            if not record or record.owner != owner:
                result = -3
            elif record.state not in (3, 4, 5):
                result = -4
            else:
                self.old_tokens.append(record.token)
                del self.inputs[record.identity]
        elif op == "Q":
            record = next((r for r in self.inputs.values() if owner and token and (r.owner, r.transaction) == (owner, token)), None)
            result, value = (record.status, record.token) if record else (-3, 0)
        elif op == "K":
            if 1 <= owner & 255 <= 8 and 0 < owner <= (1 << 63) - 1 and owner >> 8:
                slot = (owner & 255) - 1
                previous_owner, _ = self.owner_watermarks.get(slot, (0, 0))
                if owner >> 8 >= previous_owner >> 8:
                    self.owner_watermarks[slot] = owner, MASK
            retiring = [r for r in self.inputs.values() if owner and r.owner == owner]
            value = len(retiring)
            for r in retiring:
                self.old_tokens.append(r.token)
                del self.inputs[r.identity]
        elif op == "I":
            if self.block != owner:
                if self.block:
                    self.reset_metadata()
                self.block = owner
                for r in self.inputs.values():
                    if r.state not in (3, 5):
                        self.fail(r, -3)
        elif op == "G":
            self.old_tokens.extend(r.token for r in self.inputs.values())
            self.issuer, self.generation, self.block = owner, owner >> 8, token
            self.serial, self.handle_serial = 1, 1
            self.inputs.clear()
            self.owner_watermarks.clear()
            self.reset_metadata()
            if offset:
                self.actual = dict(enumerate(HELLO))
        elif op == "X":
            self.serial, self.handle_serial = owner, token
            for f in self.files.values():
                if f["number"] == offset:
                    f["revision"] = count
        elif op == "D":
            for f in self.files.values():
                if f["number"] == owner:
                    f["length"] = token
        else:
            raise ValueError(op)
        return result, value, output

    def report(self, reply):
        result, value, output = reply
        scalar = [result, value, self.serial, self.block, self.generation, self.block, self.handle_serial,
                  len(self.inputs), 128 * sum(r.state in (1, 2) for r in self.inputs.values()), output.hex(),
                  bytes(self.actual.get(i, 0) for i in range(512)).hex()]
        records = []
        for name, file in sorted(self.files.items(), key=lambda item: item[1]["number"]):
            records.append(["F", file["number"], file["readonly"], file["length"], file["revision"], name.encode().hex()])
        for token, h in sorted(self.handles.items(), key=lambda item: item[1]["placement"]):
            records.append(["H", token, h["owner"], self.files[h["name"]]["number"]])
        for r in sorted(self.inputs.values(), key=lambda r: r.identity[2]):
            readers = {placement: endpoint for endpoint, placement in r.readers.items()}
            records.append(["S", r.identity[2], r.state, r.token, r.owner, r.transaction, r.handle, r.block,
                            r.file_number,
                            r.revision, r.length, len(r.capture), r.status, readers.get(0, 0), readers.get(1, 0), r.checker, r.settled_reader,
                            bytes(r.capture).ljust(128, b"\0").hex()])
        for slot, (owner, transaction) in sorted(self.owner_watermarks.items()):
            records.append(["M", slot, owner, transaction])
        return scalar, records

    def invariants(self):
        assert len(self.inputs) <= 2 and len(self.handles) <= 8 and len(self.files) <= 4
        assert len({r.token for r in self.inputs.values()}) == len(self.inputs)
        for r in self.inputs.values():
            assert len(r.capture) <= r.length <= 128 and len(r.readers) <= 2
            assert r.owner not in r.readers and 0 not in r.readers
            assert r.state in (1, 2) or (not r.capture and not r.readers)
            assert r.state != 2 or len(r.capture) == r.length


def parse_report(line):
    scalar, *rows = line.split("|")
    fields = scalar.split(";")
    scalars = [*(int(v) for v in fields[:9]), *fields[9:]]
    records = []
    for row in rows:
        values = row.split(",")
        hex_last = values[0] in ("F", "S")
        records.append([values[0], *(int(v) for v in values[1:-1] if hex_last)] + [values[-1]] if hex_last
                       else [values[0], *(int(v) for v in values[1:])])
    return scalars, records


def action(op, *args):
    return (op, *args, *(0 for _ in range(6 - len(args))))


def generate(seed, count=500):
    rng = random.Random(seed)
    model = Model()
    actions, expected = [], []
    transaction = 1
    for step in range(count):
        handles, inputs = list(model.handles), list(model.inputs.values())
        choice = rng.randrange(100)
        if choice < 15 or not handles:
            item = action("O", rng.choice((0x104, 0x104, 0x103, 0)), rng.randrange(5))
        elif choice < 30:
            token = rng.choice(handles)
            h = model.handles[token]
            f = model.files[h["name"]]
            offset = rng.choice((0, f["length"], rng.randrange(min(129, f["length"] + 2)), 127, 128, 0xFFFFFFFF))
            item = action("W", h["owner"] + (0x100 if rng.randrange(9) == 0 else 0), token, offset,
                          rng.choice((0, 1, 7, 8, 9)), rng.getrandbits(64), int(rng.randrange(15) == 0))
        elif choice < 45:
            if inputs and rng.randrange(3) == 0:
                r = rng.choice(inputs)
                item = action("A", r.owner, r.transaction, r.handle ^ int(rng.randrange(6) == 0))
            else:
                token = rng.choice(handles)
                item = action("A", model.handles[token]["owner"] + (0x100 if rng.randrange(9) == 0 else 0), transaction, token)
                transaction += 1
        elif choice < 50:
            item = action("H", model.handles[rng.choice(handles)]["owner"], rng.choice(handles))
        elif choice < 53:
            item = action("I", rng.choice((0x101, 0x201, 0x301, 0)))
        elif choice < 55:
            item = action("K", rng.choice((0, 0x104, 0x103, 0x204)))
        else:
            r = rng.choice(inputs) if inputs else None
            token = r.token if r and rng.randrange(9) else rng.choice(model.old_tokens) if model.old_tokens else 0x1A1
            op = rng.choice(("C", "C", "P", "B", "V", "L", "Z", "R", "R", "T", "E", "Q", "F"))
            owner = r.owner if r else 0x104
            if rng.randrange(9) == 0:
                owner ^= 0x100
            if op == "Q":
                item = action(op, owner, r.transaction if r else transaction)
            elif op in ("B", "V", "L"):
                item = action(op, owner, token, rng.choice((0x105, 0x205, 0x106, owner, 0)))
            elif op in ("C", "R"):
                at = rng.choice((len(r.capture) if r else 0, 0, 7, 8, 127, 128, 0xFFFFFFFF))
                item = action(op, rng.choice((owner, 0x105, 0x205)) if op == "R" else owner, token, at,
                              rng.choice((0, 1, 7, 8, 9)), 0, rng.choice((0, 0, 0, 0x202)))
            else:
                item = action(op, owner, token, rng.randrange(4) if op == "F" else 0)
        reply = model.apply(item)
        model.invariants()
        actions.append(item)
        expected.append(model.report(reply))
    return actions, expected


class AnalysisModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = ROOT / "build/analysis-model"
        cls.evidence.mkdir(parents=True, exist_ok=True)
        cls.driver = cls.evidence / "production-snapshot-driver"
        cls.summary = {"seeds": SEEDS, "production": ["cells/storage.zig", "cells/snapshot.zig"],
                       "representation": "named files, address dictionary, owner handles, input identity dictionary and reader placements",
                       "status": "running", "cases": [], "failures": []}
        cls.save()
        result = subprocess.run([os.environ.get("ZIG", "zig"), "build-exe", "cells/snapshot_model_driver.zig", "-lc", "-O", "Debug", f"-femit-bin={cls.driver}"],
                                cwd=ROOT, text=True, capture_output=True, timeout=60)
        (cls.evidence / "compile.log").write_text(result.stdout + result.stderr)
        if result.returncode:
            cls.summary["failures"].append({"stage": "compile", "error": result.stdout + result.stderr})
            cls.summary["status"] = "failed"
            cls.save()
            raise AssertionError(result.stdout + result.stderr)

    @classmethod
    def save(cls):
        cls.summary["total_steps"] = sum(case["steps"] for case in cls.summary["cases"])
        (cls.evidence / "results.json").write_text(json.dumps(cls.summary, indent=2) + "\n")

    @classmethod
    def tearDownClass(cls):
        cls.summary["status"] = "failed" if cls.summary["failures"] else "passed"
        cls.save()

    def compare(self, label, actions, expected=None):
        if expected is None:
            model = Model()
            expected = []
            for item in actions:
                reply = model.apply(item)
                model.invariants()
                expected.append(model.report(reply))
        path = self.evidence / f"{label}.actions"
        path.write_text("".join(" ".join(map(str, item)) + "\n" for item in actions))
        try:
            completed = subprocess.run([str(self.driver), str(path)], cwd=ROOT, text=True, capture_output=True, timeout=20)
            (self.evidence / f"{label}.actual").write_text(completed.stdout)
            (self.evidence / f"{label}.stderr").write_text(completed.stderr)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            observed = completed.stdout.splitlines()
            self.assertEqual(len(observed), len(expected))
            for step, (line, wanted) in enumerate(zip(observed, expected)):
                actual = parse_report(line)
                if actual != wanted:
                    witness = {"label": label, "step": step, "actions": actions[:step + 1], "expected": wanted, "actual": actual}
                    (self.evidence / f"{label}-failure-{step}.json").write_text(json.dumps(witness, indent=2) + "\n")
                self.assertEqual(actual, wanted, f"{label} step{step}: {actions[step]}")
        except Exception as error:
            self.summary["failures"].append({"label": label, "error": str(error)})
            self.save()
            raise
        self.summary["cases"].append({"label": label, "steps": len(actions), "passed": True})
        self.save()

    def test_generated_capture_source_reader_cleanup_sequences(self):
        for seed in SEEDS:
            with self.subTest(seed=seed):
                self.compare(f"seed-{seed}", *generate(seed))

    def test_binary_lengths_exact_eof_immutable_source_and_reference_reuse(self):
        for length in (0, 1, 7, 8, 9, 127, 128):
            actions = [action("O", 0x104, 1)]
            handle = (1 << 32) | 0x101
            payload = bytes((0 if i % 5 == 0 else 10 if i % 3 == 0 else 0xFF if i % 7 == 0 else i) for i in range(length))
            for at in range(0, length, 8):
                chunk = payload[at:at + 8]
                actions.append(action("W", 0x104, handle, at, len(chunk), int.from_bytes(chunk.ljust(8, b"\0"), "little")))
            actions.append(action("A", 0x104, 1, handle))
            for at in range(0, length, 8):
                actions.append(action("C", 0x104, 0x1A1, at, 8))
            actions += [action("P", 0x104, 0x1A1), action("A", 0x104, 1, handle), action("B", 0x104, 0x1A1, 0x105)]
            if length:
                actions.append(action("W", 0x104, handle, 0, 1, 0x31))
            for at in range(0, length, 8):
                actions.append(action("R", 0x105, 0x1A1, at, 8))
            actions += [action("R", 0x105, 0x1A1, length, 8), action("V", 0x104, 0x1A1, 0x105),
                        action("R", 0x105, 0x1A1, 0, 8), action("T", 0x104, 0x1A1), action("T", 0x104, 0x1A1),
                        action("E", 0x104, 0x1A1), action("A", 0x104, 2, handle), action("R", 0x104, 0x1A1, 0, 8)]
            self.compare(f"binary-length-{length}", actions)

    def test_creation_watermarks_survive_reap_and_retirement_without_aliasing_successor(self):
        h = 0x100000101
        newer_handle = 0x100000202
        actions = [action("O", 0x103, 1), action("A", 0x103, 1, h), action("P", 0x103, 0x1A1),
                   action("T", 0x103, 0x1A1), action("E", 0x103, 0x1A1), action("A", 0x103, 1, h),
                   action("A", 0x103, 0, h), action("A", 0x103, 2, h), action("K", 0x103),
                   action("A", 0x103, 3, h), action("O", 0x203, 1), action("A", 0x203, 1, newer_handle),
                   action("P", 0x203, 0x3A1), action("A", 0x103, 4, h), action("T", 0x203, 0x3A1),
                   action("E", 0x203, 0x3A1), action("A", 0x203, MASK, newer_handle), action("P", 0x203, 0x4A1),
                   action("T", 0x203, 0x4A1), action("E", 0x203, 0x4A1), action("A", 0x203, MASK, newer_handle),
                   action("A", 0x203, 2, newer_handle)]
        self.compare("creation-watermarks", actions)

    def test_checker_release_scope_duplicate_and_endpoint_boundaries(self):
        h = 0x100000101
        actions = [action("O", 0x104, 1), action("W", 0x104, h, 0, 8, 0x0A0A0A0A0A0A0A0A),
                   action("A", 0x104, 1, h), action("C", 0x104, 0x1A1, 0, 8), action("P", 0x104, 0x1A1),
                   action("L", 0x104, 0x1A1, 0x105), action("B", 0x104, 0x1A1, 0x106),
                   action("Z", 0x106, 0x1A1, 0x105), action("Z", 0x105, 0x1A1, 0x205),
                   action("Z", 0x105, 0x1A1, 0x106), action("Z", 0x105, 0x1A1, 0x106),
                   action("Z", 0x105, 0x1A1), action("Z", 0x105, 0x1A1, 0x206),
                   action("T", 0x104, 0x1A1), action("Q", 0x104, 1), action("E", 0x104, 0x1A1),
                   action("G", 2, 0x101), action("A", 0x104, 1, h),
                   action("G", 0x8000000000000102, 0x101), action("A", 0x104, 1, h)]
        self.compare("checker-release-boundaries", actions)

    def test_coherence_counter_pressure_and_cold_generation_boundaries(self):
        handle = (1 << 32) | 0x101
        actions = [action("O", 0x104, 1), action("W", 0x104, handle, 0, 8, 0x0A000AFF00000A),
                   action("A", 0x104, 1, handle), action("C", 0x104, 0x1A1, 0, 8),
                   action("W", 0x104, handle, 0, 1, 0x11), action("P", 0x104, 0x1A1), action("Q", 0x104, 1),
                   action("E", 0x104, 0x1A1), action("D", 1, 129), action("A", 0x104, 2, handle), action("D", 1, 8),
                   action("X", LIMIT, 0xFFFFFF, 1, MASK), action("W", 0x104, handle, 0, 1, 1),
                   action("A", 0x104, 3, handle), action("A", 0x104, 4, handle), action("T", 0x104, LIMIT << 8 | 0xA1),
                   action("E", 0x104, LIMIT << 8 | 0xA1), action("A", 0x104, 4, handle),
                   action("O", 0x104, 1), action("O", 0x104, 1), action("G", 0x202, 0x201, 1),
                   action("R", 0x104, 0x1A1, 0, 8, 0, 0x102), action("O", 0x104, 1), action("A", 0x104, 1, (2 << 32) | 0x101),
                   action("P", 0x104, 0x1A1), action("B", 0x104, 0x1A1, 0x105), action("B", 0x104, 0x1A1, 0x205),
                   action("B", 0x104, 0x1A1, 0x106), action("V", 0x104, 0x1A1, 0x105),
                   action("B", 0x104, 0x1A1, 0x106), action("I", 0x301), action("Q", 0x104, 1), action("K", 0x104)]
        self.compare("boundaries", actions)


if __name__ == "__main__":
    unittest.main()
