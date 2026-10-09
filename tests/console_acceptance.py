#!/usr/bin/env python3
"""Drive the production console over QEMU UART; inspect separate trusted evidence.

No commands are compiled into the guest. The oracle joins copied UART bytes,
authenticated IPC delivery, filesystem handles, block transactions, returned
bytes, and actual host-visible output. QMP shutdown is acknowledged and finite.
"""
import argparse
import copy
import hashlib
import json
import os
import pathlib
import re
import selectors
import shlex
import socket
import struct
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOGS = ROOT / "build" / "console-acceptance"
PROMPT = b"zeal> "
HELLO = b"Zeal survives."
SERIAL_LIMIT = 256 * 1024
TRUSTED_LIMIT = 8 * 1024 * 1024
IO_LIMIT = 64
LINE_LIMIT = 96


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def events(text):
    result = []
    for line in text.splitlines():
        if not line.startswith("EVENT "):
            continue
        tokens = line.split()
        require(len(tokens) >= 2, "truncated trusted event")
        fields = {}
        for token in tokens[2:]:
            match = re.fullmatch(r"([a-zA-Z_][a-zA-Z_0-9]*)=(0x[0-9a-f]+)", token)
            require(match is not None and match[1] not in fields,
                    "malformed or duplicate trusted field")
            fields[match[1]] = int(match[2], 16)
        result.append((tokens[1], fields))
    return result


def manifest_info(path):
    """Decode the emitted v2 records independently of the compiler."""
    data = pathlib.Path(path).read_bytes()
    require(len(data) >= 40, "manifest header missing")
    magic, version, total, cells, grants, templates, domains, *reserved = struct.unpack_from("<10I", data)
    require(magic == 0x4c41455a and version == 2 and total == len(data) and
            cells == 4 and templates == domains == 0 and not any(reserved),
            "console manifest has an unsupported header")
    require(len(data) == 40 + cells * 64 + grants * 16, "manifest record extent differs")
    roots = []
    for index in range(cells):
        identity, image, abi, flags, entry, image_limit, stack, writable, config, restart, delay, name = \
            struct.unpack_from("<4IQ6I16s", data, 40 + index * 64)
        roots.append(dict(identity=identity, image=image, abi=abi, flags=flags,
                          entry=entry, image_budget=image_limit, stack_budget=stack,
                          writable_budget=writable, config=config, restart=restart,
                          delay=delay, name=name.split(b"\0", 1)[0].decode("ascii")))
    rights = {}
    for index in range(grants):
        holder, target, mask, reserved = struct.unpack_from("<4I", data, 40 + cells * 64 + index * 16)
        require(reserved == 0 and (holder, target) not in rights, "invalid duplicate manifest grant")
        rights[holder, target] = mask
    require([r["identity"] for r in roots] == [100, 200, 300, 400] and
            all(r["abi"] == 4 for r in roots), "console root identity or ABI differs")
    require(roots[2]["flags"] == 5 and all(r["flags"] == 1 for i, r in enumerate(roots) if i != 2),
            "explicit console entitlement is missing or assigned to another cell")
    for holder, target, operations in ((300, 200, (10, 11, 13)), (200, 300, (14,)),
                                       (200, 100, (7,)), (100, 200, (9,))):
        require(all(rights.get((holder, target), 0) & (1 << (op - 1)) for op in operations),
                "console storage authority is missing")
    return roots, rights


def event_bytes(fields):
    count = fields.get("count", -1)
    require(0 < count <= IO_LIMIT and all(f"data{i}" in fields for i in range(8)),
            "copied UART bytes or bounded extent missing")
    data = b"".join(fields[f"data{i}"].to_bytes(8, "little") for i in range(8))
    require(not any(data[count:]), "UART trace has nonzero padding")
    return data[:count]


def packet(fields):
    require(all(f"raw{i}" in fields for i in range(4)), "trusted raw storage packet missing")
    data = b"".join(fields[f"raw{i}"].to_bytes(8, "little") for i in range(4))
    require(fields["request"] == int.from_bytes(data[:8], "little") and
            fields["handle"] == int.from_bytes(data[8:16], "little") and
            fields["offset"] == int.from_bytes(data[16:20], "little") and
            fields["result"] == int.from_bytes(data[20:24], "little") and
            fields["data"] == int.from_bytes(data[24:32], "little"),
            "decoded storage fields contradict the copied packet")
    return data


def signed32(value):
    return value if value < 1 << 31 else value - (1 << 32)


def signed64(value):
    return value if value < 1 << 63 else value - (1 << 64)


def verify(trusted, serial, sent, exchanges, idle, manifest, finish, build_id=None):
    require(isinstance(serial, bytes) and isinstance(sent, bytes), "UART transcript must preserve bytes")
    require(len(serial) <= SERIAL_LIMIT and len(trusted.encode()) <= TRUSTED_LIMIT,
            "console evidence exceeded its host bound")
    require(not any(word in trusted for word in ("PANIC", "RESEARCH_FAIL", "KERNEL_FAULT",
                                                 "EXHAUSTED", "bad-report")),
            "trusted fault or exhausted evidence budget")
    require(b"EVENT " not in serial and b"ZEAL boot" not in serial,
            "trusted test evidence leaked into the plain console")
    require(finish.get("qmp_quit_acknowledged") is True and finish.get("exit") == 0 and
            finish.get("forced_termination") is False,
            "finite completion lacks QMP acknowledgment or clean actual process exit")
    roots, rights = manifest_info(manifest)
    records = events(trusted)
    indexed = [(i, kind, fields) for i, (kind, fields) in enumerate(records)]

    def matching(kind, cell=None, **values):
        return [(i, f) for i, name, f in indexed if name == kind and
                (cell is None or f.get("cell") == cell) and
                all(f.get(k) == v for k, v in values.items())]

    def unique(kind, cell=None, **values):
        found = matching(kind, cell, **values)
        require(len(found) == 1, f"missing or repeated {kind}: {values}")
        return found[0]

    generations = {}
    for i, kind, fields in indexed:
        if kind == "boot":
            cell = fields.get("cell")
            require(cell in range(4) and cell not in generations and fields.get("generation") == 1,
                    "console boot restarted or has wrong root generation")
            root = roots[cell]
            require(all(fields.get(k) == root[k] for k in
                        ("identity", "image", "abi", "entry", "image_budget", "writable_budget", "config")),
                    "live console boot contradicts emitted manifest")
            generations[cell] = 1
        if kind.startswith(("storage-", "console-")):
            cell = fields.get("cell")
            require(cell in generations and fields.get("generation") == generations[cell] and
                    fields.get("identity") == roots[cell]["identity"] and "tick" in fields,
                    "event source identity or generation differs from its live root")
        require(kind not in ("fault", "exit", "quarantine"), "console cell/service failed during acceptance")
    require(generations == {0: 1, 1: 1, 2: 1, 3: 1}, "console composition did not boot all four roots")
    reads = [(i, f) for i, f in matching("console-input", 2) if signed64(f.get("result", 0)) > 0]
    writes = [(i, f) for i, f in matching("console-output", 2) if signed64(f.get("result", 0)) > 0]
    require(reads and writes, "prompt/banner-only implementation lacks copied UART traffic")
    for _, fields in reads + writes:
        require(fields.get("privilege") == 3 and fields.get("result") == fields.get("count") and
                fields["count"] <= fields.get("requested", IO_LIMIT) <= IO_LIMIT,
                "console IO lacks actual ring-three checked-copy success")
    _, denied = unique("console-denied-verified", 3)
    require(denied.get("value") == 2, "unentitled probe lacks verified read and write denials")
    for name in ("console-input", "console-output"):
        unentitled = [(i, f) for i, f in matching(name, 3) if signed64(f.get("result", 0)) < 0]
        require(len(unentitled) == 1 and signed64(unentitled[0][1]["result"]) == -2 and
                unentitled[0][1]["count"] == 0 and unentitled[0][1]["requested"] == 1 and
                unentitled[0][1]["privilege"] == 3 and
                not any(unentitled[0][1].get(f"data{i}", -1) for i in range(8)),
                "actual unentitled UART attempt lacks denial without byte consumption")
        rejected = [(i, f) for i, f in matching(name, 2) if signed64(f.get("result", 0)) < 0]
        require(len(rejected) == 3 and sorted(signed64(f["result"]) for _, f in rejected) == [-6, -5, -1],
                "entitled ring-three UART invalid address/count/reserved controls missing")
        for _, fields in rejected:
            result = signed64(fields["result"])
            require(fields["privilege"] == 3 and fields["count"] == 0 and
                    not any(fields.get(f"data{i}", -1) for i in range(8)) and
                    ((result == -5 and fields["address"] == 0 and fields["requested"] == 1 and fields["reserved"] == 0) or
                     (result == -6 and fields["address"] != 0 and fields["requested"] == 65 and fields["reserved"] == 0) or
                     (result == -1 and fields["address"] != 0 and fields["requested"] == 1 and fields["reserved"] == 1)),
                    "rejected UART control copied bytes or does not match its actual invalid parameter")
    require(b"".join(event_bytes(f) for _, f in reads) == sent,
            "guest copied input differs from actual host serial input")
    require(b"".join(event_bytes(f) for _, f in writes) == serial,
            "cell copied output differs from actual UART transcript")
    require(serial.startswith(PROMPT), "plain console did not begin at zeal> prompt")
    input_positions, position = [], 0
    for at, fields in reads:
        position += fields["count"]
        input_positions.append((position, at))
    output_positions, position = [], 0
    for at, fields in writes:
        position += fields["count"]
        output_positions.append((position, at))

    def input_event(end):
        return next(at for count, at in input_positions if count >= end)

    def output_event(end):
        return next(at for count, at in output_positions if count >= end)

    require(exchanges and exchanges[0]["serial_start"] == len(PROMPT), "initial prompt boundary missing")
    sent_at = 0
    continuous_progress = 0
    for exchange in exchanges:
        raw = bytes.fromhex(exchange["input_hex"])
        start, end = exchange["serial_start"], exchange["serial_end"]
        require(raw and sent[sent_at:sent_at + len(raw)] == raw and 0 <= start < end <= len(serial),
                "host command/input transcript boundary differs")
        response = serial[start:end]
        require(response.endswith(PROMPT) and response.count(PROMPT) == 1,
                "command did not recover to exactly one next prompt")
        # CR completes a command immediately; a following LF may be consumed
        # on the next bounded poll and must not be mistaken for its cause.
        command_extent = len(raw) - 1 if raw.endswith(b"\r\n") else len(raw)
        exchange["input_event"] = input_event(sent_at + command_extent)
        exchange["first_input_event"] = input_event(sent_at + 1)
        exchange["prompt_event"] = output_event(end)
        require(exchange["input_event"] <= exchange["prompt_event"],
                "response prompt predates its real typed command")
        sent_at += len(raw)
        command = exchange["case"]
        body = response[:-len(PROMPT)]
        if command.startswith("help"):
            require(all(syntax in body for syntax in (b"help", b"version", b"info", b"cat <path>")),
                    "help does not describe the supported command syntax")
        elif command == "version":
            require(re.search(rb"Zeal build=([^\r\n ]+) abi=4", body), "version is missing live ABI/build identity")
        elif command == "info":
            endpoint = (generations[2] << 8) | 3
            require(f"identity=300 role=2 generation=1 endpoint=0x{endpoint:x}".encode() in body and
                    re.search(rb"live ticks=[0-9]+ filesystem=0x102 block=0x101", body) and
                    f"configured image={roots[2]['image_budget']} stack={roots[2]['stack_budget']} writable={roots[2]['writable_budget']} console_io=64 line=96".encode() in body and
                    b"boot parent=0x0 depth=0 console=1" in body and
                    b"global statistics: unavailable" in body,
                    "info does not match actual current root/resources or label unavailable global data")
        elif command.startswith("cat-hello"):
            require(HELLO in body, "cat /hello did not display actual complete bytes")
        elif command == "cat-missing":
            require(b"not found" in body, "missing file lacks useful not-found error")
        elif command.startswith("malformed"):
            require(b"error:" in body, "malformed command lacks bounded useful error")
        elif command == "overflow":
            require(b"line too long" in body and b"cat <path>" not in body,
                    "line overflow executed a truncated valid prefix or lacks error")
            if len(raw) > IO_LIMIT * 20:
                ongoing = [(i, f) for i, f in matching("console-progress", 3)
                           if exchange["first_input_event"] < i < exchange["input_event"]]
                require(len(ongoing) >= 2 and ongoing[0][1]["value"] < ongoing[-1][1]["value"],
                        "continuous serial input monopolized scheduling instead of permitting other-cell progress")
                continuous_progress = len(ongoing)
        elif command == "empty":
            require(b"error:" not in body, "empty line produced a command error")
        if command in ("info", "version"):
            observed = [(i, f) for i, f in matching("console-system-info", 2)
                        if exchange["input_event"] < i < exchange["prompt_event"]]
            require(len(observed) == 1, "command lacks a causal actual checked system-information copy")
            _, information = observed[0]
            require(information.get("privilege") == 3 and information.get("result") == 0 and
                    information.get("size") == 80 and information.get("reserved") == 0 and
                    information.get("abi") == 4 and information.get("console_limit") == 64 and
                    information.get("console_entitled") == 1 and
                    information.get("observed_tick") == information["tick"] and
                    all(information.get(key) == roots[2][key] for key in
                        ("image_budget", "stack_budget", "writable_budget")),
                    "copied live system-information snapshot contradicts actual resource/ABI/tick fields")
            require(all(f"build{i}" in information for i in range(6)), "copied build identity bytes missing")
            copied_build = b"".join(information[f"build{i}"].to_bytes(8, "little") for i in range(6))
            identity, separator, padding = copied_build.partition(b"\0")
            require(separator and identity and not any(padding), "system build identity lacks bounded termination")
            if build_id is not None:
                require(identity == build_id.encode(), "system build identity differs from tested image header")
            if command == "version":
                require(b"Zeal build=" + identity + b" abi=4" in body,
                        "reported version differs from the actual checked system-information copy")
            else:
                require(f"live ticks={information['observed_tick']} filesystem=0x102 block=0x101".encode() in body and
                        f"console=1 scenario={roots[2]['config']}".encode() in body,
                        "printed live ticks or boot scenario differ from actual system information")
    require(sent_at == len(sent) and exchanges[-1]["serial_end"] == len(serial),
            "unaccounted host input or extra console output")
    require({"version", "info", "cat-missing", "overflow", "empty"} <= {e["case"] for e in exchanges} and
            sum(e["case"].startswith("cat-hello") for e in exchanges) == 2 and
            any(e["case"].startswith("malformed") for e in exchanges),
            "required multi-command acceptance cases missing")

    # An independently running probe must progress while the host sends no input.
    require(idle["input_start"] == idle["input_end"] and idle["duration"] >= .10,
            "idle window was not a measured no-input interval")
    before = events(trusted.encode()[:idle["trusted_start"]].decode())
    during = events(trusted.encode()[idle["trusted_start"]:idle["trusted_end"]].decode())
    progress_before = [f for name, f in before if name == "console-progress"]
    progress = [f for name, f in during if name == "console-progress"]
    require(progress_before and len(progress) >= 2 and
            all(f.get("cell") == 3 and f.get("generation") == 1 for f in progress) and
            progress[0]["value"] > progress_before[-1]["value"] and
            all(a["value"] < b["value"] and a["tick"] < b["tick"] for a, b in zip(progress, progress[1:])),
            "idle console did not permit independently observed other-cell progress")
    require(not any(name == "console-input" for name, _ in during), "serial input appeared in idle interval")

    # Every storage enqueue must have a unique actual authenticated delivery.
    enqueues = matching("storage-ipc")
    deliveries = matching("storage-ipc-deliver")
    require(enqueues and len(enqueues) == len(deliveries), "storage operation lacks independent checked delivery")
    for at, request in enqueues:
        source = request["cell"]
        operation = request["operation"]
        recipient = {0: 1, 1: 0 if operation == 7 else 2, 2: 1}.get(source)
        require(recipient is not None and request["target"] == 0x100 + recipient + 1 and
                request.get("outcome") == 0 and request.get("cap", 0) > 0 and
                rights.get((roots[source]["identity"], roots[recipient]["identity"]), 0) & (1 << (operation - 1)),
                "storage enqueue lacks current authenticated operation authority")
        raw = packet(request)
        delivered_at, delivered = unique("storage-ipc-deliver", recipient,
                                         operation=operation, request=request["request"])
        require(at < delivered_at and delivered.get("sender") == 0x100 + source + 1 and
                delivered.get("target") == request["target"] and delivered.get("length") == request["length"] and
                packet(delivered) == raw, "storage delivery changed bytes, sender, recipient or order")
    app = matching("storage-ipc", 2)
    require(len({f["request"] for _, f in app}) == len(app), "console reused an application storage identity")
    for at, request in app:
        delivered_at, _ = unique("storage-ipc-deliver", 1, operation=request["operation"], request=request["request"])
        outcome_at, outcome = unique("storage-fs", 1, request=request["request"], operation=request["operation"])
        reply_at, reply = unique("storage-ipc", 1, operation=14, request=request["request"])
        received_at, _ = unique("storage-ipc-deliver", 2, operation=14, request=request["request"])
        require(at < delivered_at < outcome_at < reply_at < received_at and
                outcome["result"] == reply["result"], "filesystem result lacks ordered matched actual delivery")
    transfers = matching("storage-ipc", 1, operation=7)
    require(len(transfers) == len(matching("storage-link", 1)) ==
            len(matching("storage-block", 0)) == len(matching("storage-ipc", 0)),
            "missing or unrelated block participation")
    for at, transfer in transfers:
        link_at, link = unique("storage-link", 1, block_request=transfer["request"])
        request_at, request = unique("storage-ipc", 2, request=link["request"], operation=11)
        delivered_at, _ = unique("storage-ipc-deliver", 0, request=transfer["request"], operation=7)
        applied_at, applied = unique("storage-block", 0, request=transfer["request"], operation=7)
        replied_at, reply = unique("storage-ipc", 0, request=transfer["request"], operation=9)
        received_at, _ = unique("storage-ipc-deliver", 1, request=transfer["request"], operation=9)
        fs_at, fs_reply = unique("storage-ipc", 1, request=request["request"], operation=14)
        require(request_at < link_at < at < delivered_at < applied_at < replied_at < received_at < fs_at and
                transfer["offset"] == reply["offset"] == request["offset"] and
                transfer["result"] == applied["result"] == reply["result"] == fs_reply["result"] and
                reply["data"] == fs_reply["data"], "filesystem/block link has changed offsets/counts/bytes or wrong order")

    opens = [(i, f) for i, f in app if f["operation"] == 10]
    require(len(opens) == 3, "unexpected file opens occurred for malformed or overflow input")
    handles = []
    for exchange in [e for e in exchanges if e["case"].startswith("cat-")]:
        cat_app = [(i, f) for i, f in app if exchange["input_event"] < i < exchange["prompt_event"]]
        require(cat_app and cat_app[0][1]["operation"] == 10,
                "cat did not cause a new filesystem open after its typed command")
        open_at, opened = cat_app[0]
        name = b"/missing" if exchange["case"] == "cat-missing" else b"/hello"
        raw = packet(opened)
        require(opened["length"] == 32 and raw[8:24] == name.ljust(16, b"\0") and
                raw[24] == len(name) and raw[25] == 1 and not any(raw[26:]),
                "cat open did not request the typed exact name in read-only mode")
        open_reply_at, open_reply = unique("storage-ipc", 1, request=opened["request"], operation=14)
        if exchange["case"] == "cat-missing":
            require(len(cat_app) == 1 and signed32(open_reply["result"]) == -9 and
                    open_reply["handle"] == 0 and not matching("storage-link", 1, request=opened["request"]),
                    "missing-file open created storage, leaked a handle or lacks not-found result")
            continue
        handle = open_reply["handle"]
        require(open_reply["result"] == 0 and handle >> 32 == 1 and handle not in handles,
                "open lacks a fresh current-generation filesystem handle")
        handles.append(handle)
        require([f["operation"] for _, f in cat_app] == [10, 11, 11, 11, 13],
                "cat lacks its complete bounded read/read/EOF/close sequence")
        for (request_at, request), offset, count in zip(cat_app[1:4], (0, 8, len(HELLO)), (8, len(HELLO) - 8, 0)):
            reply_at, reply = unique("storage-ipc", 1, request=request["request"], operation=14)
            received_at, _ = unique("storage-ipc-deliver", 2, request=request["request"], operation=14)
            expected = HELLO[offset:offset + count]
            require(request["handle"] == reply["handle"] == handle and
                    request["offset"] == reply["offset"] == offset and request["result"] == 8 and
                    reply["result"] == count and reply["data"] == int.from_bytes(expected.ljust(8, b"\0"), "little"),
                    "cat handle/offset/chunk bytes differ from actual boot /hello")
            if count:
                verified_at, verified = unique("storage-verified", 2, request=request["request"])
                require(received_at < verified_at < exchange["prompt_event"] and verified["data"] == reply["data"],
                        "console did not consume and verify its returned filesystem bytes")
        close_at, close = cat_app[-1]
        close_reply_at, close_reply = unique("storage-ipc", 1, request=close["request"], operation=14)
        require(close["handle"] == close_reply["handle"] == handle and close["offset"] == close["result"] == 0 and
                close_reply["result"] == 0 and close_reply_at < exchange["prompt_event"],
                "cat did not successfully close the same filesystem handle before its prompt")
    require(len(app) == 11 and len(transfers) == 6 and len(matching("storage-verified", 2)) == 4,
            "unexpected application/file/block operations or missing byte reports")
    return {"typed_bytes": len(sent), "displayed_bytes": len(serial), "commands": len(exchanges),
            "cat_reads": 2, "filesystem_requests": len(app), "block_reads": len(transfers),
            "closed_handles": handles, "idle_progress_events": len(progress),
            "continuous_input_progress_events": continuous_progress,
            "ring3_uart_calls": len(reads) + len(writes), "ring3_rejected_uart_calls": 6,
            "unentitled_rejected_uart_calls": 2, "actual_system_information_copies": 2, "finite_finish": True}


class Guest:
    def __init__(self, image, directory, cpu="max", memory="64M"):
        self.directory = directory
        self.serial = bytearray()
        self.sent = bytearray()
        self.exchanges = []
        self.finish = {"qmp_quit_acknowledged": False, "exit": None, "forced_termination": False}
        self.trusted_path = directory / "trusted.log"
        self.trusted_path.write_bytes(b"")
        self.temporary = tempfile.TemporaryDirectory(prefix="zeal-console-")
        self.qmp_path = pathlib.Path(self.temporary.name) / "qmp.sock"
        self.qmp_messages = []
        self.stderr = (directory / "qemu-stderr.log").open("wb")
        command = shlex.split(os.environ.get("QEMU", "qemu-system-x86_64"))
        command += shlex.split(os.environ.get("QEMU_FLAGS", ""))
        command += ["-machine", "pc", "-accel", "tcg", "-cpu", cpu, "-m", memory, "-smp", "1",
                    "-drive", f"file={image},format=raw,if=ide", "-display", "none", "-serial", "stdio",
                    "-monitor", "none", "-nic", "none", "-no-reboot", "-qmp", f"unix:{self.qmp_path},server=on,wait=off",
                    "-debugcon", f"file:{self.trusted_path}", "-global", "isa-debugcon.iobase=0xe9",
                    "-device", "isa-debug-exit,iobase=0xf4,iosize=4"]
        (directory / "qemu-command.json").write_text(json.dumps(command, indent=2) + "\n")
        self.process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr)
        self.selector = selectors.DefaultSelector()
        os.set_blocking(self.process.stdout.fileno(), False)
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.deadline = time.monotonic() + 45
        self.qmp = None

    def trusted_length(self):
        count = self.trusted_path.stat().st_size
        require(count <= TRUSTED_LIMIT, "trusted transcript exceeds bounded host budget")
        # A trace is emitted through several port writes. Snapshot only complete
        # lines so an idle boundary never bisects an independently running event.
        data = self.trusted_path.read_bytes()
        return data.rfind(b"\n") + 1

    def pump(self, seconds):
        end = min(time.monotonic() + seconds, self.deadline)
        while time.monotonic() < end:
            for key, _ in self.selector.select(min(.05, max(0, end - time.monotonic()))):
                data = os.read(key.fileobj.fileno(), 4096)
                if not data:
                    self.selector.unregister(key.fileobj)
                    continue
                self.serial.extend(data)
                require(len(self.serial) <= SERIAL_LIMIT, "UART output exceeds bounded host budget")
            self.trusted_length()
            require(self.process.poll() is None, "QEMU exited before acknowledged finite finish")
        require(time.monotonic() < self.deadline, "console overall host timeout")

    def wait_prompt(self, expected, timeout=3):
        end = min(time.monotonic() + timeout, self.deadline)
        while self.serial.count(PROMPT) < expected and time.monotonic() < end:
            self.pump(.025)
        require(self.serial.count(PROMPT) == expected, "console next prompt timed out or repeated unexpectedly")
        self.pump(.025)

    def command(self, case, raw):
        before = len(self.serial)
        prompts = self.serial.count(PROMPT)
        self.sent.extend(raw)
        self.process.stdin.write(raw)
        self.process.stdin.flush()
        self.wait_prompt(prompts + 1)
        self.exchanges.append({"case": case, "input_hex": raw.hex(), "serial_start": before,
                               "serial_end": len(self.serial)})

    def idle_window(self):
        self.pump(.10)
        before = self.trusted_length()
        start = time.monotonic()
        self.pump(.20)
        return {"trusted_start": before, "trusted_end": self.trusted_length(),
                "input_start": len(self.sent), "input_end": len(self.sent),
                "duration": time.monotonic() - start}

    def qmp_receive(self):
        line = self.qmp_file.readline(65537)
        require(line and len(line) <= 65536, "QMP reply missing or excessive")
        message = json.loads(line)
        self.qmp_messages.append({"received": message})
        return message

    def qmp_execute(self, name, ident):
        message = {"execute": name, "id": ident}
        self.qmp_messages.append({"sent": message})
        self.qmp.sendall(json.dumps(message).encode() + b"\n")
        for _ in range(16):
            reply = self.qmp_receive()
            if reply.get("id") == ident:
                require("return" in reply and "error" not in reply, f"QMP {name} failed")
                return
        raise AssertionError(f"QMP {name} acknowledgment bound exhausted")

    def stop(self):
        self.qmp = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.qmp.settimeout(2)
        self.qmp.connect(str(self.qmp_path))
        self.qmp_file = self.qmp.makefile("rb")
        require("QMP" in self.qmp_receive(), "QMP handshake missing")
        self.qmp_execute("qmp_capabilities", "console-capabilities")
        self.qmp_execute("quit", "console-quit")
        self.finish["qmp_quit_acknowledged"] = True
        self.finish["exit"] = self.process.wait(timeout=3)
        remaining = self.process.stdout.read()
        if remaining:
            self.serial.extend(remaining)

    def close(self):
        if self.process.poll() is None:
            self.finish["forced_termination"] = True
            self.process.kill()
            self.process.wait(timeout=3)
        self.finish["exit"] = self.process.returncode
        self.selector.close()
        self.process.stdin.close()
        self.process.stdout.close()
        self.stderr.close()
        if self.qmp is not None:
            self.qmp_file.close()
            self.qmp.close()
        self.temporary.cleanup()
        (self.directory / "serial-output.bin").write_bytes(self.serial)
        (self.directory / "serial-output.log").write_text(bytes(self.serial).decode("ascii", "backslashreplace"))
        (self.directory / "serial-input.bin").write_bytes(self.sent)
        (self.directory / "serial-input.log").write_text("".join(
            f"{exchange['case']}: {bytes.fromhex(exchange['input_hex'])!r}\n" for exchange in self.exchanges))
        (self.directory / "exchanges.json").write_text(json.dumps(self.exchanges, indent=2) + "\n")
        (self.directory / "qmp-transcript.json").write_text(json.dumps(self.qmp_messages, indent=2) + "\n")


def source_hashes(root=ROOT):
    root = pathlib.Path(root)
    try:
        paths = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                               cwd=root, check=True, capture_output=True, text=True, timeout=5).stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        # Release archives retain sources/assets/license but have no Git
        # metadata. Keep evidence usable there and when Git is unavailable.
        # Prune generated trees before walking so caches cannot enter hashes.
        excluded = {".git", "build", "work", ".zig-cache", "zig-cache", "zig-out", "__pycache__"}
        paths = []

        def fail_walk(error):
            raise error

        for directory, children, files in os.walk(root, onerror=fail_walk):
            relative = pathlib.Path(directory).relative_to(root)
            children[:] = sorted(name for name in children if name not in excluded and
                                 not (relative == pathlib.Path("policy") and name == "target"))
            paths.extend((relative / name).as_posix() for name in files
                         if not name.endswith((".pyc", ".pyo")))
    # Read errors still fail validation. A Git/tool failure may select the
    # export walker; it must never hide an unreadable source or evidence error.
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in sorted(set(paths)) if (root / name).is_file() and not name.startswith("build/")}


def build(directory, scenario=27, test=1):
    directory.mkdir(parents=True, exist_ok=True)
    command = ["make", "--no-print-directory", f"BUILD={directory}", f"SCENARIO={scenario}",
               f"TEST={test}", "SOLO=-1", "all"]
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=120)
    except subprocess.TimeoutExpired as exc:
        (directory / "build.log").write_bytes((exc.stdout or b"") + (exc.stderr or b""))
        raise
    (directory / "build.log").write_bytes(result.stdout + result.stderr)
    require(result.returncode == 0, f"console build failed; inspect {directory / 'build.log'}")
    return directory / "zeal.img"


def run(image, directory, cpu="max", memory="64M"):
    directory.mkdir(parents=True, exist_ok=True)
    result = {"passed": False, "cpu": cpu, "memory": memory}
    guest = Guest(image, directory, cpu, memory)
    started = time.monotonic()
    try:
        guest.wait_prompt(1)
        idle = guest.idle_window()
        guest.command("help", b"help\r\n")
        guest.command("version", b"version\n")
        guest.command("info", b"info\r")
        guest.command("cat-hello-first", b"cat /hello\r\n")
        guest.command("cat-missing", b"cat /missing\n")
        guest.command("malformed-extra", b"cat /hello extra\r")
        guest.command("malformed-path", b"cat /a/b\n")
        guest.command("malformed-unknown", b"unsupported\n")
        guest.command("help-backspace", b"helx\x08p\n")
        guest.command("help-delete", b"helx\x7fp\r\n")
        guest.command("malformed-control", b"he\x01\x00\xfflp\n")
        guest.command("empty", b"\n")
        guest.command("overflow", b"help" + b" " * (IO_LIMIT * 24) + b"\r\n")
        guest.command("help-recovery", b"help\n")
        guest.command("cat-hello-second", b"cat /hello\n")
        guest.stop()
        result["qemu_version"] = guest.qmp_messages[0]["received"]["QMP"]["version"]
        # Preserve CR/LF byte extents: idle boundaries are offsets in the actual
        # debugcon file, so universal newline translation would change them.
        raw_trusted = guest.trusted_path.read_bytes()
        complete = raw_trusted.rfind(b"\n") + 1
        # Host shutdown can interrupt a future trace's individual port writes.
        # Preserve that suffix separately; every required record and copied UART
        # byte must still be present in the complete prefix checked below.
        interrupted_tail = raw_trusted[complete:]
        (directory / "trusted-interrupted-tail.bin").write_bytes(interrupted_tail)
        result["trusted_interrupted_tail_hex"] = interrupted_tail.hex()
        trusted = raw_trusted[:complete].decode("ascii")
        build_header = (image.parent / "build_id.h").read_text()
        build_match = re.fullmatch(r'#define Z_BUILD_ID "([a-z0-9-]+)"\n', build_header)
        require(build_match is not None, "tested image build identification missing")
        result["build_id"] = build_match[1]
        result["evidence"] = verify(trusted, bytes(guest.serial), bytes(guest.sent), copy.deepcopy(guest.exchanges),
                                    idle, image.parent / "manifest.bin", guest.finish, result["build_id"])
        result["idle"] = idle
        result["negative_controls"] = negative_controls(trusted, bytes(guest.serial), bytes(guest.sent),
                                                         guest.exchanges, idle, image.parent / "manifest.bin", guest.finish)
        result["passed"] = True
    except (AssertionError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        result["error"] = str(exc)
        raise
    finally:
        guest.close()
        result["finish"] = guest.finish
        result["seconds"] = round(time.monotonic() - started, 3)
        result["boot_image_sha256"] = hashlib.sha256(image.read_bytes()).hexdigest()
        (directory / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def run_interactive(image, directory):
    """Observe the normal configuration surviving idle time and later commands."""
    directory.mkdir(parents=True, exist_ok=True)
    result = {"passed": False, "scenario": 26, "test": 0}
    guest = Guest(image, directory)
    started = time.monotonic()
    try:
        guest.wait_prompt(1)
        guest.command("help", b"help\n")
        guest.command("version", b"version\n")
        guest.command("info", b"info\n")
        guest.command("cat-hello-before-idle", b"cat /hello\n")
        guest.pump(1)
        guest.command("cat-missing-after-idle", b"cat /missing\n")
        guest.command("cat-hello-after-idle", b"cat /hello\n")
        guest.stop()
        result["qemu_version"] = guest.qmp_messages[0]["received"]["QMP"]["version"]
        require(guest.finish["qmp_quit_acknowledged"] and guest.finish["exit"] == 0 and
                not guest.finish["forced_termination"], "normal interactive configuration did not finish at host request")
        require(bytes(guest.serial).startswith(PROMPT) and bytes(guest.serial).count(PROMPT) == 7 and
                bytes(guest.serial).count(HELLO) == 2 and b"file not found" in guest.serial and
                b"scenario=26" in guest.serial and b"EVENT " not in guest.serial and
                guest.trusted_path.stat().st_size == 0,
                "normal interactive configuration lacks repeated commands, plain UI or separate silent diagnostics")
        result["passed"] = True
        result["evidence"] = {"real_host_commands": len(guest.exchanges), "observed_idle_seconds": 1,
                              "commands_after_idle": 2, "plain_prompt": True, "trusted_debug_bytes": 0,
                              "finite_host_finish": True}
    except (AssertionError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        result["error"] = str(exc)
        raise
    finally:
        guest.close()
        result["finish"] = guest.finish
        result["seconds"] = round(time.monotonic() - started, 3)
        result["boot_image_sha256"] = hashlib.sha256(image.read_bytes()).hexdigest()
        (directory / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def negative_controls(trusted, serial, sent, exchanges, idle, manifest, finish):
    """Apply independent omissions/counterfeits to the actual successful trace."""
    controls = []

    def reject(label, changed_trusted=trusted, changed_serial=serial, changed_sent=sent,
               changed_exchanges=exchanges, changed_idle=idle, changed_finish=finish):
        try:
            verify(changed_trusted, changed_serial, changed_sent, copy.deepcopy(changed_exchanges),
                   changed_idle, manifest, changed_finish)
        except (AssertionError, ValueError, StopIteration, KeyError) as exc:
            controls.append({"control": label, "rejected": True, "reason": str(exc)})
            return
        raise AssertionError(f"console oracle accepted counterfeit: {label}")

    def omit(kind):
        return "\n".join(line for line in trusted.splitlines() if not line.startswith(f"EVENT {kind} ")) + "\n"

    def alter(kind, field, replacement):
        lines = trusted.splitlines()
        for index, line in enumerate(lines):
            if line.startswith(f"EVENT {kind} ") and f" {field}=" in line:
                existing = re.search(rf"\b{field}=(0x[0-9a-f]+)", line)
                if int(existing[1], 16) == replacement:
                    continue
                lines[index] = re.sub(rf"\b{field}=0x[0-9a-f]+", f"{field}=0x{replacement:x}", line)
                return "\n".join(lines) + "\n"
        raise AssertionError(f"negative-control source missing: {kind}.{field}")

    reject("static prompt only", changed_serial=PROMPT, changed_trusted="")
    reject("serial banner without copied input", changed_trusted=omit("console-input"))
    reject("expected string without filesystem", changed_trusted="\n".join(
        line for line in trusted.splitlines() if not line.startswith("EVENT storage-")) + "\n")
    for kind in ("boot", "console-output", "console-system-info", "console-progress", "console-denied-verified", "storage-link", "storage-block",
                 "storage-fs", "storage-ipc-deliver", "storage-verified"):
        reject(f"missing {kind}", changed_trusted=omit(kind))
    for kind, field, value in (("console-input", "privilege", 0), ("console-input", "data0", 0),
                               ("console-input", "count", 65), ("console-output", "data0", 0),
                               ("console-output", "generation", 2), ("storage-link", "block_request", 999),
                               ("console-system-info", "observed_tick", 0),
                               ("console-system-info", "build0", 0),
                               ("storage-block", "result", 0), ("storage-fs", "result", 99),
                               ("storage-verified", "data", 0), ("storage-ipc-deliver", "sender", 0x203),
                               ("storage-ipc", "raw0", 0), ("storage-ipc", "target", 0x202)):
        reject(f"counterfeit {kind}.{field}", changed_trusted=alter(kind, field, value))
    reject("host input not sent", changed_sent=b"")
    reject("wrong displayed hello", changed_serial=serial.replace(HELLO, b"counterfeit!!!"))
    reject("unacknowledged QMP finish", changed_finish={**finish, "qmp_quit_acknowledged": False})
    reject("forced process termination", changed_finish={**finish, "forced_termination": True})
    reject("wrong QEMU exit", changed_finish={**finish, "exit": 1})
    reject("input during idle", changed_idle={**idle, "input_end": idle["input_start"] + 1})
    reject("trace credit exhausted", changed_trusted=trusted + "CONSOLE_TRACE_EXHAUSTED\n")
    annotated = copy.deepcopy(exchanges)
    verify(trusted, serial, sent, annotated, idle, manifest, finish)
    overflow = next(e for e in annotated if e["case"] == "overflow")
    if len(bytes.fromhex(overflow["input_hex"])) > IO_LIMIT * 20:
        lines = trusted.splitlines(keepends=True)
        at = 0
        kept = []
        for line in lines:
            is_event = line.startswith("EVENT ")
            remove = is_event and overflow["first_input_event"] < at < overflow["input_event"] and \
                line.startswith("EVENT console-progress ")
            if not remove:
                kept.append(line)
            at += int(is_event)
        reject("continuous input starves other cells", changed_trusted="".join(kept))
    return controls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path, default=LOGS)
    parser.add_argument("--image", type=pathlib.Path)
    parser.add_argument("--repeat", type=int, default=2)
    args = parser.parse_args()
    require(1 <= args.repeat <= 20, "console repeat must be 1..20")
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    result = {"passed": False, "cases": [], "source_hashes": source_hashes()}
    try:
        image = args.image.resolve() if args.image else build(args.output)
        for index in range(args.repeat):
            case = run(image, args.output / f"run-{index + 1}")
            result["cases"].append(case)
            print(f"PASS console acceptance run-{index + 1}: real typed input, causal FS/block reads, idle progress and acknowledged finite finish", flush=True)
        normal_image = build(args.output / "interactive", scenario=26, test=0)
        result["cases"].append(run_interactive(normal_image, args.output / "interactive" / "run"))
        print("PASS normal interactive configuration: commands before/after idle and finite acknowledged host shutdown", flush=True)
        result["passed"] = True
    except (AssertionError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        result["error"] = str(exc)
        print(f"FAIL console acceptance: {exc}; inspect {args.output}", file=sys.stderr)
        return 1
    finally:
        result["source_hashes_after"] = source_hashes()
        result["source_unchanged"] = result["source_hashes"] == result["source_hashes_after"]
        (args.output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
