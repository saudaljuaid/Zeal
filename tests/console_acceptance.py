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
    for holder, target, operations in ((300, 200, (10, 11, 12, 13, 21, 22)), (200, 300, (14,)),
                                       (200, 100, (7, 8)), (100, 200, (9,))):
        require(all(rights.get((holder, target), 0) & (1 << (op - 1)) for op in operations),
                "console storage authority is missing")
    require(rights[(300, 200)] == sum(1 << (op - 1) for op in (10, 11, 12, 13, 21, 22)) and
            not any(holder == 300 and target != 200 for holder, target in rights),
            "console received unrelated authority")
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


def edited_input(raw):
    """Independently interpret host input and the exact editor echo."""
    line, echo, fault = bytearray(), bytearray(), None
    for byte in raw:
        if byte in (10, 13):
            echo.extend(b"\r\n")
            return (bytes(line) if fault is None else None), bytes(echo)
        if fault is not None:
            continue
        if byte in (8, 127):
            if line:
                line.pop()
                echo.extend(b"\x08 \x08")
        elif byte < 32 or byte > 126:
            fault = "unsupported"
        elif len(line) == LINE_LIMIT:
            fault = "overflow"
        else:
            line.append(byte)
            echo.append(byte)
    raise AssertionError("host input lacks a completed bounded line")


def parsed_command(line):
    if line is None:
        return None, None, None
    stripped = line.lstrip(b" ")
    verb, separator, rest = stripped.partition(b" ")
    if verb in (b"cat", b"write", b"append"):
        rest = rest.lstrip(b" ")
        path, separating_space, payload = rest.partition(b" ")
        if not re.fullmatch(rb"/[a-zA-Z0-9_.-]{1,15}", path):
            return None, None, None
        if verb == b"cat" and payload.strip(b" "):
            return None, None, None
        if verb == b"append" and not separating_space:
            return None, None, None
        return verb.decode(), path, payload
    if verb in (b"ls", b"help", b"version", b"info") and not rest.strip(b" "):
        return verb.decode(), None, None
    return None, None, None


def rendered_file(data):
    result = bytearray()
    for byte in data:
        if byte == 10:
            result.extend(b"\r\n")
        elif byte == 92:
            result.extend(b"\\\\")
        elif 32 <= byte <= 126:
            result.append(byte)
        else:
            result.extend(f"\\x{byte:02X}".encode())
    if not data or data[-1] != 10:
        result.extend(b"\r\n")
    return bytes(result)


def verify_storage(indexed, roots, rights, exchanges, serial):
    """Reconstruct bounded production storage, separately from UART strings."""
    def matching(kind, cell=None, **values):
        return [(i, f) for i, name, f in indexed if name == kind and
                (cell is None or f.get("cell") == cell) and
                all(f.get(k) == v for k, v in values.items())]

    def unique(kind, cell=None, **values):
        found = matching(kind, cell, **values)
        require(len(found) == 1, f"missing or repeated {kind}: {values}")
        return found[0]

    enqueues, deliveries = matching("storage-ipc"), matching("storage-ipc-deliver")
    require(enqueues and len(enqueues) == len(deliveries),
            "storage operation lacks independent checked delivery")
    transaction_scopes = set()
    for at, request in enqueues:
        source, operation = request["cell"], request["operation"]
        recipient = {0: 1, 1: 0 if operation in (7, 8) else 2, 2: 1}.get(source)
        sender = request["generation"] << 8 | source + 1
        target = 0x100 + recipient + 1 if recipient is not None else 0
        require(recipient is not None and request["target"] == target and
                request.get("outcome") == 0 and request.get("cap", 0) > 0 and
                rights.get((roots[source]["identity"], roots[recipient]["identity"]), 0) & (1 << (operation - 1)),
                "storage enqueue lacks current authenticated operation authority")
        scope = sender, target, operation, request["request"]
        require(scope not in transaction_scopes, "storage reused an exact authenticated transaction scope")
        transaction_scopes.add(scope)
        delivered_at, delivered = unique("storage-ipc-deliver", recipient, sender=sender,
                                         target=target, operation=operation, request=request["request"])
        require(at < delivered_at and delivered.get("length") == request["length"] and
                packet(delivered) == packet(request),
                "storage delivery changed bytes, sender, recipient or order")

    app = matching("storage-ipc", 2)
    require(len({(f["generation"], f["request"]) for _, f in app}) == len(app),
            "console reused an application identity within its exact generation")
    results, all_links = {}, matching("storage-link", 1)
    for at, request in app:
        delivered_at, _ = unique("storage-ipc-deliver", 1, sender=0x103, target=0x102,
                                 operation=request["operation"], request=request["request"])
        outcome_at, outcome = unique("storage-fs", 1, request=request["request"], operation=request["operation"])
        reply_at, reply = unique("storage-ipc", 1, target=0x103, operation=14, request=request["request"])
        received_at, _ = unique("storage-ipc-deliver", 2, sender=0x102, target=0x103,
                                operation=14, request=request["request"])
        raw = packet(reply)
        result = int.from_bytes(raw[12:16], "little") if request["operation"] == 21 else reply["result"]
        require(at < delivered_at < outcome_at < reply_at < received_at and outcome["result"] == result,
                "filesystem result lacks ordered exact authenticated publication")
        require(not any(outcome_at < i < reply_at for i, _ in matching("storage-fs", 1)),
                "filesystem outcome crossed another serialized dispatch before publication")
        results[request["request"]] = dict(request=request, at=at, outcome_at=outcome_at,
                                           reply=reply, reply_at=reply_at, received_at=received_at,
                                           value=signed32(result), links=[])
    require(len(matching("storage-fs", 1)) == len(app) == len(matching("storage-ipc", 1, operation=14)),
            "unrelated filesystem outcome/publication or missing application result")

    block_requests = [(i, f) for i, f in matching("storage-ipc", 1) if f["operation"] in (7, 8)]
    require(len(block_requests) == len(all_links) == len(matching("storage-block", 0)) ==
            len(matching("storage-ipc", 0)), "missing or unrelated block participation")
    for at, transfer in block_requests:
        link_at, link = unique("storage-link", 1, block_request=transfer["request"])
        require(link["request"] in results, "block link lacks its exact console transaction")
        transaction = results[link["request"]]
        delivered_at, _ = unique("storage-ipc-deliver", 0, sender=0x102, target=0x101,
                                 request=transfer["request"], operation=transfer["operation"])
        applied_at, applied = unique("storage-block", 0, request=transfer["request"], operation=transfer["operation"])
        replied_at, reply = unique("storage-ipc", 0, target=0x102, request=transfer["request"], operation=9)
        received_at, _ = unique("storage-ipc-deliver", 1, sender=0x101, target=0x102,
                                request=transfer["request"], operation=9)
        require(transaction["at"] < link_at < at < delivered_at < applied_at < replied_at < received_at < transaction["outcome_at"] and
                transfer["handle"] == reply["handle"] == 0 and transfer["offset"] == reply["offset"] and
                transfer["result"] == applied["result"] == reply["result"] and 0 <= transfer["result"] <= 8 and
                transfer["offset"] + transfer["result"] <= 512,
                "filesystem/block link changed extent/count or exact application/publication order")
        transaction["links"].append((at, transfer, reply))

    backing = bytearray(512)
    backing[:len(HELLO)] = HELLO
    files = {b"/hello": dict(slot=0, length=len(HELLO), readonly=True)}
    handles, closed, serials, verified_used = {}, [], set(), set()
    cat_count = truncate_count = list_count = written_count = appended_count = 0
    causal_commands = []

    def apply_blocks(transaction, expected):
        links = transaction["links"]
        require(len(links) == len(expected), "filesystem mutation/read lacks its complete actual block transactions")
        for (_, request, reply), (operation, offset, data_or_count) in zip(links, expected):
            count = len(data_or_count) if isinstance(data_or_count, bytes) else data_or_count
            data = data_or_count if isinstance(data_or_count, bytes) else bytes(backing[offset:offset + count])
            require(request["operation"] == operation and request["offset"] == offset and request["result"] == count,
                    "actual block operation differs from the independent file extent/bytes")
            require(request["data"] == (int.from_bytes(data.ljust(8, b"\0"), "little") if operation == 8 else 0) and
                    reply["data"] == (int.from_bytes(data.ljust(8, b"\0"), "little") if operation == 7 else 0),
                    "actual block write/read bytes differ from independently reconstructed RAM")
            if operation == 8:
                backing[offset:offset + count] = data

    def consume(request, expected_name=None):
        nonlocal truncate_count, list_count, written_count
        transaction = results[request["request"]]
        operation, raw, reply, value = request["operation"], packet(request), transaction["reply"], transaction["value"]
        if operation == 10:
            existing = request["length"] == 32
            name_length = raw[24] if existing else request["length"] - 8
            name = raw[8:8 + name_length]
            require(re.fullmatch(rb"/[a-zA-Z0-9_.-]{1,15}", name) and name == expected_name and
                    (not existing or raw[25] == 1 and not any(raw[8 + name_length:24] + raw[26:])),
                    "open changed the exact typed valid path or reserved mode bytes")
            if name not in files and existing:
                require(value == -9 and reply["handle"] == 0, "missing existing open fabricated a file or handle")
                apply_blocks(transaction, [])
            else:
                if name not in files:
                    available = next((slot for slot in range(4) if slot not in {f["slot"] for f in files.values()}), None)
                    require(available is not None, "unexpected file exhaustion during positive acceptance")
                    apply_blocks(transaction, [(8, available * 128 + offset, bytes(8)) for offset in range(0, 128, 8)])
                    files[name] = dict(slot=available, length=0, readonly=False)
                else:
                    apply_blocks(transaction, [])
                handle = reply["handle"]
                sequence = handle >> 8 & 0xffffff
                slot = handle & 255
                require(value == 0 and handle >> 32 == 1 and sequence and sequence not in serials and
                        1 <= slot <= 8 and slot not in {token & 255 for token in handles},
                        "open lacks a fresh generation-safe live handle or leaked a known handle")
                serials.add(sequence)
                handles[handle] = name
        elif operation == 21:
            index = request["offset"]
            require(request["handle"] == request["result"] == request["data"] == 0 and 0 <= index < 4,
                    "list changed its bounded slot-only request")
            answer = packet(reply)
            require(int.from_bytes(answer[8:12], "little") == index, "list reply changed the exact requested index")
            entry = next(((name, file) for name, file in files.items() if file["slot"] == index), None)
            expected = -9 if entry is None else len(entry[0]) | int(entry[1]["readonly"]) << 8 | entry[1]["length"] << 16
            require(value == expected and answer[16:] == (bytes(16) if entry is None else entry[0].ljust(16, b"\0")),
                    "list metadata/name differs from actual independently reconstructed filesystem entries")
            apply_blocks(transaction, [])
            list_count += 1
        else:
            handle = request["handle"]
            require(handle in handles and reply["handle"] == handle and request["offset"] == reply["offset"],
                    "operation changed owner/live handle or correlated offset")
            file = files[handles[handle]]
            base, offset, count = file["slot"] * 128, request["offset"], request["result"]
            if operation == 11:
                require(count <= 8 and offset <= 128 and request["data"] == 0,
                        "read exceeds the existing file/chunk limit")
                amount = min(count, max(0, file["length"] - offset))
                data = bytes(backing[base + offset:base + offset + amount])
                require(value == amount and reply["data"] == int.from_bytes(data.ljust(8, b"\0"), "little"),
                        "file read exposed stale suffix, another extent or counterfeit bytes/EOF")
                apply_blocks(transaction, [(7, base + offset, amount)])
                if amount:
                    at, report = unique("storage-verified", 2, request=request["request"])
                    require(transaction["received_at"] < at < transaction["prompt_event"] and
                            report["data"] == reply["data"],
                            "console did not consume its actual acknowledged read bytes")
                    verified_used.add(at)
            elif operation == 12:
                data = raw[24:24 + count]
                require(count <= 8 and not any(raw[24 + count:]), "file write changed bounded zero-padded payload")
                if file["readonly"]:
                    require(value == -2, "read-only file write fabricated success")
                    apply_blocks(transaction, [])
                else:
                    require(offset <= file["length"] and offset + count <= 128 and value == count and reply["data"] == 0,
                            "file write falsely acknowledged an invalid/partial extent")
                    apply_blocks(transaction, [(8, base + offset, data)])
                    file["length"] = max(file["length"], offset + count)
                    written_count += count
            elif operation == 22:
                require(count == request["data"] == 0 and reply["data"] == 0,
                        "truncate request/reply changed reserved fields")
                require(value == (-2 if file["readonly"] else 0) and offset <= file["length"],
                        "truncate violated readonly/shrink-only generation-safe outcome")
                apply_blocks(transaction, [])
                if value == 0:
                    file["length"] = offset
                    truncate_count += 1
            elif operation == 13:
                require(offset == count == request["data"] == value == reply["data"] == 0,
                        "close did not acknowledge the exact known handle")
                apply_blocks(transaction, [])
                closed.append(handle)
                del handles[handle]
            else:
                raise AssertionError("unrelated filesystem operation occurred in console acceptance")
        return transaction

    for exchange in exchanges:
        raw = bytes.fromhex(exchange["input_hex"])
        line, echo = edited_input(raw)
        body = serial[exchange["serial_start"]:exchange["serial_end"] - len(PROMPT)]
        require(body.startswith(echo), "actual editor echo differs from real bounded host input")
        displayed = body[len(echo):]
        verb, name, payload = parsed_command(line)
        command_requests = [(i, f) for i, f in app if exchange["input_event"] < i < exchange["prompt_event"]]
        require(all(sum(e["input_event"] < i < e["prompt_event"] for e in exchanges) == 1 for i, _ in command_requests),
                "application transaction ambiguously crossed typed command boundaries")
        for _, request in command_requests:
            transaction = results[request["request"]]
            transaction["prompt_event"] = exchange["prompt_event"]
            require(transaction["received_at"] < exchange["prompt_event"] and
                    transaction["received_at"] < exchange["result_output_event"],
                    "command printed completion/data or next prompt before its actual authenticated acknowledgment")
        if verb not in ("ls", "cat", "write", "append"):
            require(not command_requests, "rejected/non-file command performed storage operations")
            continue
        require(command_requests, "file command only printed expected strings without actual filesystem requests")
        requests = [f for _, f in command_requests]
        operations = [f["operation"] for f in requests]
        proof = dict(case=exchange["case"], verb=verb, path=name.decode() if name else None,
                     operations=operations, requests=[f["request"] for f in requests])
        if verb == "ls":
            require(operations == [21] * 4 and [f["offset"] for f in requests] == list(range(4)),
                    "ls did not enumerate exactly the bounded actual four filesystem slots")
            expected = b"".join(name + f" {file['length']} bytes ".encode() +
                                (b"read-only" if file["readonly"] else b"writable") + b"\r\n"
                                for name, file in sorted(files.items(), key=lambda item: item[1]["slot"]))
            for request in requests:
                consume(request)
            require(displayed == expected, "ls output differs from actual IPC entry metadata")
        else:
            require(operations[0] == 10, "file command lacks causal open after typed command")
            opened = consume(requests[0], name)
            existing = requests[0]["length"] == 32
            require(existing == (verb != "write"), "file command changed create/open-existing semantics")
            if opened["value"] == -9:
                require(len(requests) == 1 and b"file not found" in displayed,
                        "missing file lacks bounded error or performed partial mutation/allocation")
                causal_commands.append(proof)
                continue
            handle = opened["reply"]["handle"]
            proof["handle"] = handle
            require(operations[-1] == 13 and all(f["handle"] == handle for f in requests[1:]),
                    "command did not close the same known generation-safe handle")
            file = files[name]
            initial_length = file["length"]
            position, at = 0, 1
            read_bytes = bytearray()
            if verb in ("cat", "append"):
                eof = False
                while at < len(requests) - 1 and requests[at]["operation"] == 11:
                    request = requests[at]
                    require(request["offset"] == position and request["result"] == min(8, 128 - position),
                            "read/append guessed or skipped the actual bounded file EOF")
                    outcome = consume(request)
                    amount = outcome["value"]
                    if amount == 0:
                        eof = True
                        at += 1
                        break
                    read_bytes.extend(packet(outcome["reply"])[24:24 + amount])
                    position += amount
                    at += 1
                require(eof and position == initial_length, "cat/append omitted exact actual EOF")
            if verb == "cat":
                require(at == len(requests) - 1 and displayed == rendered_file(bytes(read_bytes)),
                        "cat displayed stale suffix, incomplete bytes or fabricated output after actual EOF")
                cat_count += 1
                proof.update(length=len(read_bytes), read_hex=read_bytes.hex())
            elif verb == "write":
                require(at < len(requests) - 1 and requests[at]["operation"] == 22 and requests[at]["offset"] == 0,
                        "replacement lacks acknowledged explicit generation-safe truncate")
                outcome = consume(requests[at])
                at += 1
                position = 0
                if outcome["value"] == -2:
                    require(at == len(requests) - 1 and b"access denied" in displayed and b"incomplete" in displayed,
                            "read-only replacement printed success or continued after truncate denial")
                    consume(requests[-1])
                    causal_commands.append(proof)
                    continue
            if verb in ("write", "append"):
                if position + len(payload) > 128:
                    require(at == len(requests) - 1 and b"exceeds its limit" in displayed and
                            b"0 bytes acknowledged; incomplete" in displayed,
                            "overlarge append committed a falsely successful prefix")
                    proof["rejected_overflow"] = True
                else:
                    chunks = [payload[offset:offset + 8] for offset in range(0, len(payload), 8)]
                    if verb == "append" and not chunks:
                        chunks = [b""]
                    denied, acknowledged = False, 0
                    for chunk in chunks:
                        require(at < len(requests) - 1 and requests[at]["operation"] == 12 and
                                requests[at]["offset"] == position and requests[at]["result"] == len(chunk) and
                                packet(requests[at])[24:] == chunk.ljust(8, b"\0"),
                                "write/append changed typed payload spaces, offsets or complete chunk sequence")
                        outcome = consume(requests[at])
                        at += 1
                        if outcome["value"] == -2:
                            denied = True
                            break
                        position += len(chunk)
                        acknowledged += len(chunk)
                    require(at == len(requests) - 1, "mutation continued after failure or has unrelated requests")
                    if denied:
                        require(b"access denied" in displayed and b"0 bytes acknowledged; incomplete" in displayed,
                                "read-only append fabricated acknowledged success")
                    else:
                        require(displayed == verb.encode() + b": " + name + f": {len(payload)} bytes acknowledged\r\n".encode(),
                                "mutation printed completion without exact acknowledged typed byte length")
                        require(files[name]["length"] == position, "replacement/append left an old suffix exposed")
                        proof.update(acknowledged_bytes=acknowledged, length=position, payload_hex=payload.hex())
                        if verb == "append":
                            appended_count += acknowledged
            consume(requests[-1])
        causal_commands.append(proof)
    require(sum(len(item["requests"]) for item in causal_commands) == len(app),
            "unaccounted filesystem request outside actual typed file commands")
    require(not handles and len(closed) == len(serials), "known opened handles leaked across repeated commands")
    require(len(matching("storage-verified", 2)) == len(verified_used), "unrelated/missing client byte-consumption reports")
    require(backing[:len(HELLO)] == HELLO and files[b"/hello"]["length"] == len(HELLO),
            "read-only /hello changed during unrelated file mutations")
    return dict(cat_reads=cat_count, filesystem_requests=len(app), block_reads=sum(f["operation"] == 7 for _, f in block_requests),
                block_writes=sum(f["operation"] == 8 for _, f in block_requests), closed_handles=closed,
                acknowledged_write_bytes=written_count, acknowledged_append_bytes=appended_count,
                successful_truncations=truncate_count, list_slot_queries=list_count,
                causal_file_commands=causal_commands,
                actual_files={name.decode(): dict(length=file["length"], readonly=file["readonly"],
                                                    data_hex=bytes(backing[file["slot"] * 128:file["slot"] * 128 + file["length"]]).hex())
                              for name, file in files.items()})


def verify(trusted, serial, sent, exchanges, idle, manifest, finish, build_id=None, profile="legacy"):
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
        _, echo = edited_input(raw)
        exchange["result_output_event"] = output_event(start + len(echo) + 1) if start + len(echo) < end - len(PROMPT) else exchange["prompt_event"]
        require(exchange["input_event"] <= exchange["prompt_event"],
                "response prompt predates its real typed command")
        sent_at += len(raw)
        command = exchange["case"]
        body = response[:-len(PROMPT)]
        if command.startswith("help"):
            require(all(syntax in body for syntax in (b"help", b"version", b"info", b"cat <path>",
                                                     b"ls", b"write <path> [text]", b"append <path> <text>")),
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
    require(profile in ("legacy", "basic", "capacity", "overflow", "repeat"), "unknown acceptance profile")
    cases = {e["case"] for e in exchanges}
    if profile in ("legacy", "basic"):
        require({"version", "info", "cat-missing", "overflow", "empty"} <= cases and
                sum(e["case"].startswith("cat-hello") for e in exchanges) == 2 and
                any(e["case"].startswith("malformed") for e in exchanges),
                "required original multi-command acceptance cases missing")
    required = {
        "basic": {"ls-initial", "write-note", "cat-note", "append-note", "cat-appended", "write-short",
                  "cat-short", "write-empty", "cat-empty", "ls-final"},
        "capacity": {"write-capacity", "append-capacity", "cat-capacity", "ls-capacity"},
        "overflow": {"write-before-overflow", "append-overflow", "cat-after-overflow", "append-missing",
                     "write-denied", "append-denied", "append-empty-denied", "cat-hello-denials"},
        "repeat": {"write-spaces", "cat-spaces", "append-empty", "write-empty-space", "cat-empty-space",
                   "cat-repeat", "ls-repeat"},
    }
    require(required.get(profile, set()) <= cases, "required writable acceptance profile cases missing")
    if profile == "repeat":
        require(sum(e["case"].startswith("write-repeat-") for e in exchanges) >= 10,
                "repeated successful replacement/close coverage is incomplete")

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

    proof = verify_storage(indexed, roots, rights, exchanges, serial)
    if profile in ("legacy", "basic"):
        original = [item for item in proof["causal_file_commands"]
                    if item["case"].startswith("cat-hello") or item["case"] == "cat-missing"]
        hello = [item for item in original if item["case"].startswith("cat-hello")]
        missing = [item for item in original if item["case"] == "cat-missing"]
        ids = {ident for item in original for ident in item["requests"]}
        links = [f for _, f in matching("storage-link", 1) if f["request"] in ids]
        require(len(original) == 3 and len(hello) == 2 and len(missing) == 1 and
                sum(len(item["requests"]) for item in original) == 11 and len(links) == 6 and
                len({item["handle"] for item in hello}) == 2 and
                all(item["operations"] == [10, 11, 11, 11, 13] and item["length"] == len(HELLO) and
                    item["read_hex"] == HELLO.hex() for item in hello) and missing[0]["operations"] == [10] and
                len([f for _, f in matching("storage-verified", 2) if f["request"] in ids]) == 4,
                "original scoped subset lost exact 11 FS requests, six block reads, two hello EOF/closes or four byte reports")
        require(all(unique("storage-ipc", 1, request=link["block_request"], operation=7) for link in links),
                "original hello subset changed actual block-read participation")
    if profile == "capacity":
        require(proof["actual_files"]["/full"]["data_hex"] == (b"A" * 64 + b"B" * 64).hex(),
                "bounded commands did not reach the actual full 128-byte file")
    return {"typed_bytes": len(sent), "displayed_bytes": len(serial), "commands": len(exchanges),
            **proof, "idle_progress_events": len(progress),
            "continuous_input_progress_events": continuous_progress,
            "ring3_uart_calls": len(reads) + len(writes), "ring3_rejected_uart_calls": 6,
            "unentitled_rejected_uart_calls": 2,
            "actual_system_information_copies": sum(e["case"] in ("info", "version") for e in exchanges),
            "finite_finish": True}


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


def command_cases(profile):
    original = [
        ("help", b"help\r\n"), ("version", b"version\n"), ("info", b"info\r"),
        ("cat-hello-first", b"cat /hello\r\n"), ("cat-missing", b"cat /missing\n"),
        ("malformed-extra", b"cat /hello extra\r"), ("malformed-path", b"cat /a/b\n"),
        ("malformed-unknown", b"unsupported\n"), ("help-backspace", b"helx\x08p\n"),
        ("help-delete", b"helx\x7fp\r\n"), ("malformed-control", b"he\x01\x00\xfflp\n"),
        ("empty", b"\n"), ("overflow", b"help" + b" " * (IO_LIMIT * 24) + b"\r\n"),
        ("help-recovery", b"help\n"), ("cat-hello-second", b"cat /hello\n")]
    note = [("ls-initial", b"ls\n"), ("write-note", b"write /note Hello Zeal\n"),
            ("cat-note", b"cat /note\n"), ("append-note", b"append /note !\n"),
            ("cat-appended", b"cat /note\n"), ("write-short", b"write /note Hi\n"),
            ("cat-short", b"cat /note\n"), ("write-empty", b"write /note\n"),
            ("cat-empty", b"cat /note\n"), ("ls-final", b"ls\n")]
    profiles = {
        "legacy": original,
        "basic": original + note,
        "capacity": [("write-capacity", b"write /full " + b"A" * 64 + b"\n"),
                     ("append-capacity", b"append /full " + b"B" * 64 + b"\n"),
                     ("cat-capacity", b"cat /full\n"), ("ls-capacity", b"ls\n")],
        "overflow": [("write-before-overflow", b"write /cap " + b"C" * 80 + b"\n"),
                     ("append-overflow", b"append /cap " + b"D" * 60 + b"\n"),
                     ("cat-after-overflow", b"cat /cap\n"), ("append-missing", b"append /missing x\n"),
                     ("write-denied", b"write /hello altered\n"), ("append-denied", b"append /hello !\n"),
                     ("append-empty-denied", b"append /hello \n"), ("cat-hello-denials", b"cat /hello\n"),
                     ("malformed-write-path", b"write /a/b x\n"),
                     ("malformed-append-path", b"append /a/b x\n"),
                     ("malformed-append-no-text", b"append /cap\n"),
                     ("malformed-ls-extra", b"ls extra\n"),
                     ("overflow", b"write /cap " + b"E" * 97 + b"\n"),
                     ("help-recovery", b"help\n")],
        "repeat": [("write-spaces", b"   write   /repeat  a  b  \n"), ("cat-spaces", b"cat /repeat\n"),
                   ("append-empty", b"append /repeat \n"),
                   ("write-empty-space", b"write /repeat \n"), ("cat-empty-space", b"cat /repeat\n")] +
                  [(f"write-repeat-{i}", f"write /repeat r{i}\n".encode()) for i in range(10)] +
                  [("cat-repeat", b"cat /repeat\n"), ("ls-repeat", b"ls\n")],
    }
    require(profile in profiles, "unknown host command profile")
    return profiles[profile]


def run(image, directory, cpu="max", memory="64M", profile="basic"):
    directory.mkdir(parents=True, exist_ok=True)
    result = {"passed": False, "cpu": cpu, "memory": memory, "profile": profile}
    guest = Guest(image, directory, cpu, memory)
    started = time.monotonic()
    try:
        guest.wait_prompt(1)
        idle = guest.idle_window()
        for case, raw in command_cases(profile):
            guest.command(case, raw)
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
                                    idle, image.parent / "manifest.bin", guest.finish, result["build_id"], profile)
        result["idle"] = idle
        result["negative_controls"] = negative_controls(trusted, bytes(guest.serial), bytes(guest.sent),
                                                         guest.exchanges, idle, image.parent / "manifest.bin", guest.finish, profile)
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
        for case, raw in command_cases("basic")[15:]:
            guest.command(case, raw)
        guest.pump(1)
        guest.command("cat-missing-after-idle", b"cat /missing\n")
        guest.command("cat-hello-after-idle", b"cat /hello\n")
        guest.stop()
        result["qemu_version"] = guest.qmp_messages[0]["received"]["QMP"]["version"]
        require(guest.finish["qmp_quit_acknowledged"] and guest.finish["exit"] == 0 and
                not guest.finish["forced_termination"], "normal interactive configuration did not finish at host request")
        require(bytes(guest.serial).startswith(PROMPT) and bytes(guest.serial).count(PROMPT) == 17 and
                bytes(guest.serial).count(HELLO) == 2 and b"file not found" in guest.serial and
                b"write: /note: 10 bytes acknowledged\r\n" in guest.serial and
                b"append: /note: 1 bytes acknowledged\r\n" in guest.serial and
                b"Hello Zeal!\r\n" in guest.serial and b"write: /note: 2 bytes acknowledged\r\n" in guest.serial and
                b"write: /note: 0 bytes acknowledged\r\n" in guest.serial and
                b"/note 0 bytes writable\r\n" in guest.serial and
                b"scenario=26" in guest.serial and b"EVENT " not in guest.serial and
                guest.trusted_path.stat().st_size == 0,
                "normal interactive configuration lacks repeated commands, plain UI or separate silent diagnostics")
        result["passed"] = True
        result["evidence"] = {"real_host_commands": len(guest.exchanges), "observed_idle_seconds": 1,
                              "commands_after_idle": 2, "plain_prompt": True, "trusted_debug_bytes": 0,
                              "writable_file_operations": True,
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


def rewrite_events(trusted, changes=None, removed=()):
    """Change selected fields/events without rewriting unrelated trace bytes."""
    changes, removed = changes or {}, set(removed)
    lines, index = [], 0
    for line in trusted.splitlines(keepends=True):
        if line.startswith("EVENT "):
            if index in removed:
                index += 1
                continue
            for field, value in changes.get(index, {}).items():
                pattern = rf"\b{re.escape(field)}=(0x[0-9a-f]+)"
                existing = re.search(pattern, line)
                require(existing is not None and value >= 0, "counterfeit changed an absent or invalid field")
                width = len(existing[1]) - 2
                line = re.sub(pattern, f"{field}=0x{value:0{width}x}", line)
            index += 1
        lines.append(line)
    return "".join(lines)


def remap_idle_window(original, changed, idle):
    """Keep the same measured interval after artificial trace edits/omissions."""
    def spans(text):
        result, offset = [], 0
        for line in text.splitlines(keepends=True):
            end = offset + len(line.encode())
            if line.startswith("EVENT "):
                kind, fields = events(line)[0]
                result.append((offset, end, (kind, tuple(sorted(fields.items())))))
            offset = end
        return result

    prior, current = spans(original), spans(changed)
    positions = {}
    for start, end, key in current:
        positions.setdefault(key, []).append((start, end))
    start, end = 0, len(changed.encode())
    for _, old_end, key in reversed(prior):
        if old_end <= idle["trusted_start"] and len(positions.get(key, [])) == 1:
            start = positions[key][0][1]
            break
    for old_start, _, key in prior:
        if old_start >= idle["trusted_end"] and len(positions.get(key, [])) == 1:
            end = positions[key][0][0]
            break
    require(start <= end, "counterfeit reordered measured idle boundary events")
    return {**idle, "trusted_start": start, "trusted_end": end}


def negative_controls(trusted, serial, sent, exchanges, idle, manifest, finish, profile="legacy"):
    """Apply independent omissions/counterfeits to the actual successful trace."""
    controls = []

    def reject(label, changed_trusted=trusted, changed_serial=serial, changed_sent=sent,
               changed_exchanges=exchanges, changed_idle=idle, changed_finish=finish):
        try:
            if changed_trusted != trusted and changed_idle is idle:
                changed_idle = remap_idle_window(trusted, changed_trusted, idle)
            verify(changed_trusted, changed_serial, changed_sent, copy.deepcopy(changed_exchanges),
                   changed_idle, manifest, changed_finish, profile=profile)
        except (AssertionError, ValueError, StopIteration, KeyError) as exc:
            controls.append({"control": label, "rejected": True, "reason": str(exc)})
            return
        raise AssertionError(f"console oracle accepted counterfeit: {label}")

    def omit(kind):
        return "".join(line for line in trusted.splitlines(keepends=True) if not line.startswith(f"EVENT {kind} "))

    def alter(kind, field, replacement):
        lines = trusted.splitlines(keepends=True)
        for index, line in enumerate(lines):
            if line.startswith(f"EVENT {kind} ") and f" {field}=" in line:
                existing = re.search(rf"\b{field}=(0x[0-9a-f]+)", line)
                if int(existing[1], 16) == replacement:
                    continue
                width = len(existing[1]) - 2
                lines[index] = re.sub(rf"\b{field}=0x[0-9a-f]+", f"{field}=0x{replacement:0{width}x}", line)
                return "".join(lines)
        raise AssertionError(f"negative-control source missing: {kind}.{field}")

    reject("static prompt only", changed_serial=PROMPT, changed_trusted="")
    reject("serial banner without copied input", changed_trusted=omit("console-input"))
    reject("expected string without filesystem", changed_trusted="".join(
        line for line in trusted.splitlines(keepends=True) if not line.startswith("EVENT storage-")))
    for kind in ("boot", "console-output", "console-progress", "console-denied-verified", "storage-link", "storage-block",
                 "storage-fs", "storage-ipc-deliver", "storage-verified"):
        reject(f"missing {kind}", changed_trusted=omit(kind))
    for kind, field, value in (("console-input", "privilege", 0), ("console-input", "data0", 0),
                               ("console-input", "count", 65), ("console-output", "data0", 0),
                               ("console-output", "generation", 2), ("storage-link", "block_request", 999),
                                                              ("storage-block", "result", 0), ("storage-fs", "result", 99),
                               ("storage-verified", "data", 0), ("storage-ipc-deliver", "sender", 0x203),
                               ("storage-ipc", "raw0", 0), ("storage-ipc", "target", 0x202)):
        reject(f"counterfeit {kind}.{field}", changed_trusted=alter(kind, field, value))
    if any(e["case"] in ("version", "info") for e in exchanges):
        reject("missing console-system-info", changed_trusted=omit("console-system-info"))
        for field in ("observed_tick", "build0"):
            reject(f"counterfeit console-system-info.{field}", changed_trusted=alter("console-system-info", field, 0))
    reject("host input not sent", changed_sent=b"")
    if HELLO in serial:
        reject("wrong displayed hello", changed_serial=serial.replace(HELLO, b"counterfeit!!!"))
    reject("unacknowledged QMP finish", changed_finish={**finish, "qmp_quit_acknowledged": False})
    reject("forced process termination", changed_finish={**finish, "forced_termination": True})
    reject("wrong QEMU exit", changed_finish={**finish, "exit": 1})
    reject("input during idle", changed_idle={**idle, "input_end": idle["input_start"] + 1})
    reject("trace credit exhausted", changed_trusted=trusted + "CONSOLE_TRACE_EXHAUSTED\n")
    records = [(index, kind, fields) for index, (kind, fields) in enumerate(events(trusted))]

    def coordinated(label, changes=None, removed=()):
        reject(label, changed_trusted=rewrite_events(trusted, changes, removed))

    def raw_changes(fields, raw):
        values = {f"raw{i}": int.from_bytes(raw[i * 8:(i + 1) * 8], "little") for i in range(4)}
        values.update(request=int.from_bytes(raw[:8], "little"), handle=int.from_bytes(raw[8:16], "little"),
                      offset=int.from_bytes(raw[16:20], "little"), result=int.from_bytes(raw[20:24], "little"),
                      data=int.from_bytes(raw[24:32], "little"))
        return values

    positive_write = next((f for _, kind, f in records if kind == "storage-ipc" and
                           f.get("cell") == 2 and f.get("operation") == 12 and f.get("result", 0) > 0), None)
    if positive_write:
        ident = positive_write["request"]
        rejected = [i for i, kind, f in records if kind in ("storage-ipc", "storage-ipc-deliver") and
                    f.get("operation") == 12 and f.get("request") == ident]
        coordinated("expected write string without actual file_write", removed=rejected)
        link = next(f for _, kind, f in records if kind == "storage-link" and f["request"] == ident)
        block = link["block_request"]
        rejected = [i for i, kind, f in records if
                    kind == "storage-link" and f.get("block_request") == block or
                    kind == "storage-block" and f.get("request") == block or
                    kind in ("storage-ipc", "storage-ipc-deliver") and f.get("request") == block and
                    (f.get("operation") == 8 and f.get("cell") in (0, 1) or
                     f.get("operation") == 9 and f.get("cell") in (0, 1))]
        coordinated("coherently missing actual block write with successful acknowledgment", removed=rejected)
        wrong_count = positive_write["result"] - 1
        changes = {}
        for i, kind, f in records:
            if f.get("request") != ident:
                continue
            if kind == "storage-fs" and f.get("operation") == 12:
                changes[i] = dict(result=wrong_count)
            elif kind in ("storage-ipc", "storage-ipc-deliver") and f.get("operation") == 14:
                raw = bytearray(packet(f))
                raw[20:24] = wrong_count.to_bytes(4, "little")
                changes[i] = raw_changes(f, raw)
        coordinated("coherent counterfeit write acknowledgment length", changes)
    truncation = next((f for _, kind, f in records if kind == "storage-ipc" and
                       f.get("cell") == 2 and f.get("operation") == 22), None)
    if truncation:
        ident = truncation["request"]
        rejected = [i for i, kind, f in records if f.get("request") == ident and
                    (kind == "storage-fs" and f.get("operation") == 22 or
                     kind in ("storage-ipc", "storage-ipc-deliver") and f.get("operation") in (22, 14))]
        coordinated("stale suffix replacement without explicit truncate", removed=rejected)
    listed = next((f for _, kind, f in records if kind == "storage-ipc" and
                   f.get("cell") == 2 and f.get("operation") == 21 and f.get("offset") == 0), None)
    if listed:
        changes, ident = {}, listed["request"]
        for i, kind, f in records:
            if f.get("request") != ident:
                continue
            if kind == "storage-fs" and f.get("operation") == 21:
                changes[i] = dict(result=f["result"] ^ (1 << 16))
            elif kind in ("storage-ipc", "storage-ipc-deliver") and f.get("operation") == 14:
                raw = bytearray(packet(f))
                raw[12:16] = (int.from_bytes(raw[12:16], "little") ^ (1 << 16)).to_bytes(4, "little")
                changes[i] = raw_changes(f, raw)
        coordinated("coherent invented ls length despite expected UART strings", changes)
    annotated = copy.deepcopy(exchanges)
    verify(trusted, serial, sent, annotated, idle, manifest, finish, profile=profile)
    if positive_write:
        request_at = next(i for i, kind, f in records if kind == "storage-ipc" and f.get("cell") == 2 and
                          f.get("operation") == 12 and f.get("request") == positive_write["request"])
        owner = next(e for e in annotated if e["input_event"] < request_at < e["prompt_event"])
        delivered_at = next(i for i, kind, f in records if kind == "storage-ipc-deliver" and
                            f.get("cell") == 2 and f.get("operation") == 14 and
                            f.get("request") == positive_write["request"])
        lines, event_lines, event_at = trusted.splitlines(keepends=True), {}, 0
        for line_at, line in enumerate(lines):
            if line.startswith("EVENT "):
                event_lines[event_at] = line_at
                event_at += 1
        receipt = lines[event_lines[delivered_at]]
        lines[event_lines[delivered_at]] = ""
        lines.insert(event_lines[owner["prompt_event"]] + 1, receipt)
        reject("coherent write acknowledgment delivered after claimed completion prompt", changed_trusted="".join(lines))
    shorter = next((e for e in annotated if e["case"] == "cat-short"), None)
    if shorter:
        read = next(f for i, kind, f in records if kind == "storage-ipc" and f.get("cell") == 2 and
                    f.get("operation") == 11 and shorter["input_event"] < i < shorter["prompt_event"])
        ident = read["request"]
        link = next(f for _, kind, f in records if kind == "storage-link" and f["request"] == ident)
        block, suffix, changes = link["block_request"], b"Hillo Ze", {}
        for i, kind, f in records:
            if kind == "storage-block" and f.get("request") == block or \
                    kind == "storage-fs" and f.get("request") == ident and f.get("operation") == 11:
                changes[i] = dict(result=8)
            elif kind == "storage-verified" and f.get("request") == ident:
                changes[i] = dict(data=int.from_bytes(suffix, "little"))
            elif kind in ("storage-ipc", "storage-ipc-deliver") and (
                    f.get("request") == block and f.get("operation") in (7, 9) and f.get("cell") in (0, 1) or
                    f.get("request") == ident and f.get("operation") == 14):
                raw = bytearray(packet(f))
                raw[20:24] = (8).to_bytes(4, "little")
                if f["operation"] != 7:
                    raw[24:32] = suffix
                changes[i] = raw_changes(f, raw)
        coordinated("coherent stale suffix bytes after shorter replacement", changes)
    overflow = next((e for e in annotated if e["case"] == "overflow"), None)
    if overflow is not None and len(bytes.fromhex(overflow["input_hex"])) > IO_LIMIT * 20:
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
            print(f"PASS console acceptance run-{index + 1}: real typed read/write/append/list/replace, causal FS/block bytes, idle progress and acknowledged finite finish", flush=True)
        for profile in ("capacity", "overflow", "repeat"):
            result["cases"].append(run(image, args.output / profile, profile=profile))
            print(f"PASS console {profile}: independent actual RAM/write/EOF/close proof and finite host shutdown", flush=True)
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
        if not result["source_unchanged"]:
            result["passed"] = False
            result["error"] = "source changed during console acceptance"
            print(f"FAIL console acceptance: source changed during verification; inspect {args.output}", file=sys.stderr)
        (args.output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
