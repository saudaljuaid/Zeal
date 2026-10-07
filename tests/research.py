#!/usr/bin/env python3
import json
import hashlib
import os
import pathlib
import re
import shlex
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOGS = ROOT / "build" / "research"
EXPECTED = {
    0: (6, 0), 1: (14, 7), 2: (14, 7), 3: (14, 21),
    4: (13, 0), 5: (13, 0), 6: (65, 0),
    9: (14, 5), 10: (14, 6), 11: (14, 4), 13: (7, 0), 14: (6, 0), 16: (69, 0),
    17: (6, 0),
}
NAMES = ["invalid instruction", "supervisor memory", "immutable code", "NX stack",
         "interrupt masking", "port I/O", "infinite loop", "syscall addresses",
         "capability forgery", "null dereference", "stack guard", "unmapped memory",
         "trusted kernel fault", "x87 state isolation", "SSE state isolation", "direction flag",
         "noncanonical return stack", "disabled SYSCALL entry", "disabled SYSENTER entry",
         "blocking receive and timed sleep", "writable storage and generation-safe handles",
         "runtime creation, hierarchy and storage preservation",
         "subtree failure, cancellation and explicit recovery",
         "hosting authority, pressure, rollback and slot reuse",
         "native work contracts, checked receipts and resource settlement"]


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def records(output):
    result = []
    for line in output.splitlines():
        if line.startswith("EVENT "):
            fields = {name: int(value, 16) for name, value in
                      re.findall(r"(\w+)=(0x[0-9a-f]+)", line)}
            result.append((line.split()[1], fields))
    return result


def select(events, name, cell):
    return [fields for kind, fields in events if kind == name and fields["cell"] == cell]


def verify_storage(events):
    """Join application requests to independently observed service transfers and replies."""
    payload = b"Zeal writable RAM storage."
    generations = {}
    unavailable = set()
    indexed = []
    roles = {"storage-block": 0, "storage-fs": 1, "storage-link": 1,
             "storage-verified": 2, "storage-stale": 2, "storage-denied": 2,
             "storage-checkpoint": 2, "storage-complete": 2, "storage-rebind": 2}
    required = {"storage-block": ("request", "operation", "result"),
                "storage-fs": ("request", "operation", "result"),
                "storage-link": ("request", "block_request"),
                "storage-verified": ("request", "data"),
                "storage-stale": ("request", "handle"),
                "storage-denied": ("request", "result"),
                "storage-checkpoint": ("phase",), "storage-complete": (),
                "storage-rebind": ("old", "endpoint"),
                "storage-ipc": ("target", "cap", "operation", "length", "request",
                                "handle", "offset", "result", "data"),
                "storage-reject": ("target", "cap", "operation", "length", "request",
                                   "handle", "offset", "result", "data", "outcome")}
    for index, (name, fields) in enumerate(events):
        if name == "boot":
            generations[fields["cell"]] = fields["generation"]
            unavailable.discard(fields["cell"])
        elif name in ("fault", "exit", "quarantine"):
            unavailable.add(fields["cell"])
        if not name.startswith("storage-"):
            continue
        require(name in required and all(key in fields for key in
                ("cell", "identity", "generation", "tick") + required[name]),
                "storage trace has missing fields or an unknown event")
        cell = fields.get("cell")
        require(cell in (0, 1, 2, 3) and fields["identity"] == (cell + 1) * 100,
                "storage trace contains an invalid cell identity")
        require(cell not in unavailable and fields.get("generation") == generations.get(cell),
                "storage event belongs to a stale service generation")
        if name in roles:
            require(cell == roles[name], "storage report came from the wrong cell")
        elif name in ("storage-ipc", "storage-reject"):
            op = fields.get("operation")
            require((cell == 0 and op == 9) or (cell == 1 and op in (7, 8, 14)) or
                    (cell == 2 and op in (10, 11, 12, 13)),
                    "storage IPC came from the wrong cell or operation")
            target = {0: 1, 1: 0 if op in (7, 8) else 2, 2: 1}[cell]
            require(fields.get("target") == generations[target] * 256 + target + 1,
                    "storage IPC targets a stale or unrelated endpoint")
            require(name != "storage-ipc" or target not in unavailable,
                    "storage IPC was accepted for an unavailable dependency")
            require(fields.get("request", 0) > 0 and
                    (10 <= fields.get("length", 0) <= 24 if op == 10 else fields.get("length") == 32),
                    "storage IPC has a malformed request identity or extent")
        indexed.append((index, name, fields))

    def matches(name, cell=None, **values):
        return [(i, f) for i, n, f in indexed if n == name and
                (cell is None or f["cell"] == cell) and
                all(f.get(k) == v for k, v in values.items())]

    def unique(name, cell=None, **values):
        found = matches(name, cell, **values)
        require(len(found) == 1, f"missing or repeated {name} storage evidence")
        return found[0]

    app = matches("storage-ipc", 2)
    require(len({f["request"] for _, f in app}) == len(app),
            "application reused a storage request identity")
    for request_at, request in app:
        outcome_at, outcome = unique("storage-fs", 1, request=request["request"],
                                      operation=request["operation"])
        reply_at, reply = unique("storage-ipc", 1, request=request["request"], operation=14)
        require(request_at < outcome_at < reply_at and outcome["result"] == reply["result"],
                "filesystem result lacks its ordered application request and matching reply")
    transfers = [(i, f) for i, f in matches("storage-ipc", 1) if f["operation"] in (7, 8)]
    for fs_generation in (1, 2):
        sequence = [f["request"] for _, f in transfers if f["generation"] == fs_generation]
        require(sequence == list(range(1, len(sequence) + 1)),
                "filesystem reused, skipped, or reordered a block request identity")
    require(len(matches("storage-link", 1)) == len(transfers),
            "block participation contains missing or unrelated request links")
    for transfer_at, transfer in transfers:
        link_at, link = unique("storage-link", 1, generation=transfer["generation"],
                                block_request=transfer["request"])
        request_at, request = unique("storage-ipc", 2, request=link["request"])
        reply_at, reply = unique("storage-ipc", 1, operation=14, request=link["request"],
                                  generation=transfer["generation"])
        block_generation = transfer["target"] >> 8
        applied_at, applied = unique("storage-block", 0, request=transfer["request"],
                                      generation=block_generation, operation=transfer["operation"])
        block_reply_at, block_reply = unique("storage-ipc", 0, operation=9, request=transfer["request"],
                                              generation=block_generation)
        require(request_at < link_at < transfer_at < applied_at < block_reply_at < reply_at and
                transfer["offset"] == block_reply["offset"] and
                transfer["result"] == applied["result"] == block_reply["result"] and
                request["operation"] in (10, 11, 12),
                "block transfer lacks a matched owning application operation and ordered outcome")
    require(len(matches("storage-block", 0)) == len(matches("storage-ipc", 0)) == len(transfers),
            "unrelated or counterfeit block operation appeared in storage evidence")
    writes = [(i, f) for i, f in app if f["operation"] == 12 and
              0 < unique("storage-ipc", 1, operation=14, request=f["request"])[1]["result"] <= 8]
    successful_reads = [(i, f) for i, f in app if f["operation"] == 11 and
                        matches("storage-verified", 2, request=f["request"])]
    require(len(writes) == len(successful_reads) == 12,
            "three complete multi-chunk writable file cycles were not observed")
    expected_offsets = (0, 8, 16, 24)
    cycle_bounds = []
    cycle_handles = []
    for cycle in range(3):
        write_chunks = writes[cycle * 4:(cycle + 1) * 4]
        read_chunks = successful_reads[cycle * 4:(cycle + 1) * 4]
        require([f["offset"] for _, f in write_chunks] == list(expected_offsets) and
                [f["offset"] for _, f in read_chunks] == list(expected_offsets),
                "file chunks have missing, repeated, or reordered offsets")
        fs_generation = 1 if cycle < 2 else 2
        block_generation = 1 if cycle == 0 else 2
        for is_read, chunks in ((False, write_chunks), (True, read_chunks)):
            require(len({f["handle"] for _, f in chunks}) == 1,
                    "one file operation changed handle between chunks")
            for request_at, request in chunks:
                identity = request["request"]
                offset = request["offset"]
                expected = payload[offset:offset + 8]
                count = len(expected)
                data = int.from_bytes(expected.ljust(8, b"\0"), "little")
                require(request["result"] == count and (is_read or request["data"] == data),
                        "application write bytes or chunk count differ from the known payload")
                links = matches("storage-link", 1, request=identity, generation=fs_generation)
                require(len(links) == 1, "file transfer lacks its unique block-service request link")
                link_at, link = links[0]
                block_id = link["block_request"]
                block_at, block = unique("storage-ipc", 1, request=block_id,
                                         generation=fs_generation, operation=7 if is_read else 8)
                applied_at, applied = unique("storage-block", 0, request=block_id,
                                               generation=block_generation,
                                               operation=7 if is_read else 8)
                block_reply_at, block_reply = unique("storage-ipc", 0, request=block_id,
                                                       generation=block_generation, operation=9)
                fs_at, fs = unique("storage-fs", 1, request=identity,
                                    generation=fs_generation, operation=request["operation"])
                reply_at, reply = unique("storage-ipc", 1, request=identity,
                                          generation=fs_generation, operation=14)
                require(request_at < link_at < block_at < applied_at < block_reply_at < fs_at < reply_at,
                        "storage operation did not cross both services in the required order")
                require(block["result"] == applied["result"] == block_reply["result"] ==
                        fs["result"] == reply["result"] == count,
                        "storage transfer has a counterfeit or failed operation result")
                require(block["offset"] == block_reply["offset"] and
                        reply["handle"] == request["handle"] and reply["offset"] == offset,
                        "storage reply does not match the requested extent or handle")
                if is_read:
                    verified_at, verified = unique("storage-verified", 2, request=identity)
                    require(reply_at < verified_at and
                            block_reply["data"] == reply["data"] == verified["data"] == data,
                            "application byte verification lacks matching block and filesystem data")
                else:
                    require(block["data"] == data,
                            "filesystem did not send application write bytes to the block service")
        write_handle = write_chunks[0][1]["handle"]
        read_handle = read_chunks[0][1]["handle"]
        require(write_handle != 0 and read_handle != 0 and write_handle != read_handle,
                "close and reopen reused an old file handle")
        opened = [(i, f) for i, f in matches("storage-ipc", 1, operation=14,
                                              generation=fs_generation, handle=write_handle)
                  if f["result"] == 0 and i < write_chunks[0][0] and
                  matches("storage-ipc", 2, operation=10, request=f["request"])]
        require(len(opened) == 1, "write handle lacks its successful file open")
        open_request = unique("storage-ipc", 2, operation=10, request=opened[0][1]["request"])
        zero_links = matches("storage-link", 1, generation=fs_generation,
                              request=open_request[1]["request"])
        # Fresh file slots are cleared through the isolated block service before publication.
        require(len(zero_links) == 16, "file creation lacks complete private-slot initialization")
        zero_offsets = []
        for link_at, link in zero_links:
            block_at, block = unique("storage-ipc", 1, operation=8,
                                     generation=fs_generation, request=link["block_request"])
            applied_at, applied = unique("storage-block", 0, operation=8,
                                         generation=block_generation, request=link["block_request"])
            block_reply_at, block_reply = unique("storage-ipc", 0, operation=9,
                                                 generation=block_generation,
                                                 request=link["block_request"])
            require(open_request[0] < link_at < block_at < applied_at < block_reply_at < opened[0][0] and
                    block["result"] == applied["result"] == block_reply["result"] == 8 and
                    block["data"] == 0 and block["offset"] == block_reply["offset"],
                    "file initialization did not apply zero bytes before opening")
            zero_offsets.append(block["offset"])
        require(zero_offsets == list(range(zero_offsets[0], zero_offsets[0] + 128, 8)),
                "file slot initialization has missing or unrelated extents")
        require(zero_offsets[0] in (128, 256, 384),
                "file initialization changed the reserved hello extent")
        for _, request in write_chunks + read_chunks:
            _, link = unique("storage-link", 1, generation=fs_generation, request=request["request"])
            _, block = unique("storage-ipc", 1, generation=fs_generation,
                               request=link["block_request"],
                               operation=7 if request["operation"] == 11 else 8)
            require(block["offset"] == zero_offsets[0] + request["offset"],
                    "file transfer reached an unrelated storage extent")
        empty_at, empty = unique("storage-ipc", 2, operation=11, handle=write_handle,
                                   offset=0, result=8)
        empty_reply_at, empty_reply = unique("storage-ipc", 1, operation=14, request=empty["request"])
        gap_at, gap = unique("storage-ipc", 2, operation=12, handle=write_handle, offset=1, result=1)
        gap_reply_at, gap_reply = unique("storage-ipc", 1, operation=14, request=gap["request"])
        require(opened[0][0] < empty_at < empty_reply_at < gap_at < gap_reply_at < write_chunks[0][0] and
                empty_reply["result"] == empty_reply["data"] == 0 and
                gap_reply["result"] == 0xffffffff and
                not matches("storage-link", 1, request=gap["request"]),
                "empty read or unsupported file gap had the wrong outcome")
        closed_at, closed = unique("storage-ipc", 2, operation=13, handle=write_handle)
        close_reply_at, close_reply = unique("storage-ipc", 1, operation=14,
                                             generation=fs_generation, request=closed["request"])
        reopened = [(i, f) for i, f in matches("storage-ipc", 1, operation=14,
                                                generation=fs_generation, handle=read_handle)
                    if f["result"] == 0 and i < read_chunks[0][0] and
                    matches("storage-ipc", 2, operation=10, request=f["request"])]
        require(len(reopened) == 1 and close_reply["result"] == 0 and
                write_chunks[-1][0] < closed_at < close_reply_at < reopened[0][0] < read_chunks[0][0],
                "application did not close and reopen before verified reads")
        unique("storage-ipc", 2, operation=10, request=reopened[0][1]["request"])
        final_at, _ = unique("storage-verified", 2, request=read_chunks[-1][1]["request"])
        eof_at, eof = unique("storage-ipc", 2, operation=11, handle=read_handle,
                              offset=len(payload), result=8)
        eof_reply_at, eof_reply = unique("storage-ipc", 1, operation=14, request=eof["request"])
        require(final_at < eof_at < eof_reply_at and eof_reply["result"] == eof_reply["data"] == 0,
                "EOF did not return an empty chunk without reading unrelated storage")
        for no_bytes_at, no_bytes, no_bytes_reply_at in ((empty_at, empty, empty_reply_at),
                                                        (eof_at, eof, eof_reply_at)):
            links = matches("storage-link", 1, request=no_bytes["request"])
            require(len(links) <= 1, "empty file result issued repeated block operations")
            for link_at, link in links:
                block_at, block = unique("storage-ipc", 1, generation=fs_generation, operation=7,
                                         request=link["block_request"])
                applied_at, applied = unique("storage-block", 0, generation=block_generation, operation=7,
                                             request=link["block_request"])
                block_reply_at, block_reply = unique("storage-ipc", 0, generation=block_generation,
                                                     operation=9, request=link["block_request"])
                require(no_bytes_at < link_at < block_at < applied_at < block_reply_at < no_bytes_reply_at and
                        block["result"] == applied["result"] == block_reply["result"] ==
                        block_reply["data"] == 0 and
                        block["offset"] == zero_offsets[0] + no_bytes["offset"],
                        "empty file result read previously used storage bytes")
        cycle_bounds.append((open_request[0], eof_reply_at))
        cycle_handles.append(read_handle)

    require(len(matches("storage-verified", 2)) == 12, "unexpected byte verification count")
    checkpoints = matches("storage-checkpoint", 2)
    require([f["phase"] for _, f in checkpoints] == [1, 2],
            "storage recovery checkpoints are missing or repeated")
    stale = matches("storage-stale", 2)
    require(len(stale) == 2, "block and filesystem restart must each reject an old file handle")
    for phase, service in enumerate((0, 1)):
        checkpoint_at, checkpoint = checkpoints[phase]
        fault = [(i, f) for i, (n, f) in enumerate(events) if n == "fault" and f["cell"] == service]
        boot = [(i, f) for i, (n, f) in enumerate(events) if n == "boot" and f["cell"] == service and
                f["generation"] == 2]
        require(len(fault) == len(boot) == 1 and cycle_bounds[phase][1] < checkpoint_at <
                fault[0][0] < boot[0][0] < stale[phase][0] < cycle_bounds[phase + 1][0] and
                fault[0][1]["tick"] == checkpoint["tick"] + 2,
                "dependency restart did not follow verified progress and precede resumed work")
        stale_at, rejected = stale[phase]
        request_at, request = unique("storage-ipc", 2, operation=11, request=rejected["request"])
        reply_at, reply = unique("storage-ipc", 1, operation=14, request=rejected["request"])
        outcome_at, outcome = unique("storage-fs", 1, operation=11, request=rejected["request"])
        require(request_at < outcome_at < reply_at < stale_at and
                request["handle"] == rejected["handle"] == cycle_handles[phase] and
                outcome["result"] == reply["result"] == 0xfffffffd and
                not matches("storage-link", 1, request=rejected["request"]),
                "stale handle was accepted or reached private block storage")
    denied_at, denied = unique("storage-denied", 2)
    rejected_at, rejected = unique("storage-reject", 2, operation=12, request=denied["request"])
    delegated = select(events, "cap-delegate", 1)
    require(rejected["outcome"] == denied["result"] == 0xfffffffffffffffe and
            len(delegated) == 1 and delegated[0]["cap"] == rejected["cap"] and
            delegated[0]["rights"] == 4 and rejected_at < denied_at < cycle_bounds[0][0],
            "read-only delegated authority did not reject a writable operation")
    rebind_at, rebind = unique("storage-rebind", 2)
    require(rebind["old"] == 0x102 and rebind["endpoint"] == 0x202 and
            checkpoints[1][0] < rebind_at < stale[1][0],
            "storage application did not rebind the filesystem generation")
    complete_at, _ = unique("storage-complete", 2)
    require(cycle_bounds[2][1] < complete_at,
            "storage completion precedes verified resumed application progress")


def verify_waits(events, standalone=False, demonstration=True):
    """Independently pair supervisor records with the current boot generation."""
    pending, generations, unavailable = {}, {}, set()
    completed, cancelled, idle = [], [], []
    entered = None
    identities = {0: 100, 1: 200, 2: 300, 3: 400}
    for index, (name, fields) in enumerate(events):
        if name in ("boot", "wait-arm", "wake", "wait-cancel", "idle-enter", "idle-wake"):
            require(all(key in fields for key in ("cell", "identity", "generation", "tick")),
                    "structured wait event lacks ownership fields")
        if "cell" in fields:
            cell = fields["cell"]
            require(cell in identities and fields.get("identity") == identities[cell],
                    "wait trace contains an invalid cell identity")
        if name == "boot":
            require(cell not in pending, "restart inherited an uncancelled wait")
            generations[cell] = fields["generation"]
            unavailable.discard(cell)
        elif name in ("fault", "exit", "quarantine"):
            require(cell not in pending, "failed or stopped cell retained a pending wait")
            unavailable.add(cell)
        elif name == "wait-arm":
            require(cell not in pending, "cell armed overlapping waits")
            require(cell not in unavailable and fields["generation"] == generations.get(cell),
                    "wait armed for an unavailable generation")
            require(fields.get("kind") in (1, 2), "unknown wait kind")
            require(fields["tick"] < fields.get("deadline", 0) <= fields["tick"] + 1000,
                    "unbounded, zero, or overflowing wait deadline")
            pending[cell] = (index, fields)
        elif name in ("wake", "wait-cancel"):
            require(cell in pending, "completion has no pending wait")
            arm_index, arm = pending.pop(cell)
            require(all(fields.get(key) == arm[key] for key in ("generation", "kind", "deadline")),
                    "completion changed pending wait ownership or deadline")
            require(fields["generation"] == generations.get(cell) and fields["tick"] >= arm["tick"],
                    "completion belongs to a stale generation or precedes arming")
            if name == "wait-cancel":
                require(fields.get("reason", 0) != 0, "cancellation lacks its cause")
                cancelled.append((arm_index, index, arm, fields))
                continue
            require(cell not in unavailable, "completion revived a failed or stopped cell")
            reason, result = fields.get("reason"), fields.get("result")
            if arm["kind"] == 1:
                require(reason == 1 and result == 0 and fields["tick"] >= arm["deadline"],
                        "sleep completed before its deadline or with the wrong result")
            elif reason == 3:
                require(result == 0xfffffffffffffff8 and fields["tick"] >= arm["deadline"],
                        "receive timeout completed early or with the wrong result")
            elif reason in (2, 4):
                require(fields["tick"] < arm["deadline"] and
                        result == (0 if reason == 2 else 0xfffffffffffffffb),
                        "message completion lost deadline ordering or checked-copy result")
            else:
                require(False, "receive has an unknown wake reason")
            completed.append((arm_index, index, arm, fields))
        elif name == "idle-enter":
            require(entered is None, "supervisor entered idle twice without a timer wake")
            require(all(cell in pending or cell in unavailable for cell in generations),
                    "supervisor idled with a runnable cell")
            entered = (index, fields)
        elif name == "idle-wake":
            require(entered is not None, "timer idle wake has no idle entry")
            enter_index, entry = entered
            require(fields.get("reason") == 6 and fields.get("entered") == entry["tick"] and
                    fields["tick"] > entry["tick"] and
                    all(fields[key] == entry[key] for key in ("cell", "identity", "generation")),
                    "idle did not wake on a later timer interrupt with the original identity")
            idle.append((enter_index, index, entry, fields))
            entered = None

    if not demonstration:
        return
    probe = [item for item in completed if item[2]["cell"] == 3]
    timed = [item for item in probe if item[2]["kind"] == 2 and item[3]["reason"] == 3 and
             item[2]["deadline"] - item[2]["tick"] == 2]
    slept = [item for item in probe if item[2]["kind"] == 1 and
             item[2]["deadline"] - item[2]["tick"] == 3]
    require(len(timed) == len(slept) == 1, "probe timeout or timed sleep demonstration missing")
    contracts = [(index, fields) for index, (name, fields) in enumerate(events)
                 if name == "wait-contract" and fields["cell"] == 3]
    require(len(contracts) == 1 and contracts[0][1].get("checks") == 7 and
            contracts[0][1].get("duration") == 3 and contracts[0][1]["generation"] == 1,
            "probe did not verify zero timeout, finite timeout, and sleep results")
    require(timed[0][1] < slept[0][0] < slept[0][1] < contracts[0][0],
            "probe wait verification is out of order")
    if standalone:
        require(idle and any(item[0] < timed[0][1] for item in idle) and
                any(slept[0][0] < item[0] < item[1] <= slept[0][1] for item in idle),
                "idle supervisor did not wake while the only cell was waiting")
        require(not select(events, "wait-delivered", 3), "standalone probe fabricated a sender")
        require(len(select(events, "exit", 3)) == 1 and not select(events, "fault", 3),
                "standalone wait probe did not exit cleanly")
        return

    messages = [item for item in probe if item[2]["kind"] == 2 and item[3]["reason"] == 2 and
                item[2]["deadline"] - item[2]["tick"] == 100]
    require(len(messages) == 1, "empty-queue receiver never woke for the later message")
    received = [(index, fields) for index, (name, fields) in enumerate(events)
                if name == "wait-delivered" and fields["cell"] == 3]
    require(len(received) == 1 and received[0][1].get("sender") == 0x103 and
            received[0][1].get("value") == 0x7a65616c77616b65 and
            received[0][1]["generation"] == 1, "probe did not verify the later application message")
    progress = [(index, fields) for index, (name, fields) in enumerate(events)
                if name == "wait-progress" and fields["cell"] == 2]
    require(len(progress) == 1 and progress[0][1].get("reads", 0) >= 1 and
            progress[0][1]["generation"] == 1 and
            messages[0][0] < progress[0][0] < messages[0][1] < received[0][0] < timed[0][0],
            "another cell did not make verified progress while the receiver was suspended")
    observed_reads = [fields for index, (name, fields) in enumerate(events)
                      if name == "read-verified" and fields["cell"] == 2 and
                      fields["generation"] == 1 and messages[0][0] < index < progress[0][0]]
    require(len(observed_reads) == 1 and observed_reads[0].get("reads") == progress[0][1]["reads"],
            "wait progress lacks its unique verified application read")
    restarted_waits = [item for item in cancelled if item[2]["cell"] in (0, 1) and
                       item[2]["kind"] == 2 and item[2]["generation"] == 1 and
                       any(name == "fault" and fields["cell"] == item[2]["cell"] and
                           fields["generation"] == item[2]["generation"] and
                           fields["tick"] == item[3]["tick"] and
                           fields["reason"] == item[3]["reason"] and index > item[1]
                           for index, (name, fields) in enumerate(events)) and
                       any(name == "boot" and fields["cell"] == item[2]["cell"] and
                           fields["generation"] == 2 and index > item[1]
                           for index, (name, fields) in enumerate(events))]
    require(restarted_waits, "dependency restart did not cancel a pending receive")


def verify(output, code, scenario):
    if scenario == 24:
        import contract_oracle
        return contract_oracle.verify(output, code, scenario)
    if scenario in (21, 22, 23):
        import hosting_oracle
        return hosting_oracle.verify(output, code, scenario)
    if scenario == 12:
        require(code == 5 and "KERNEL_FAULT vector=0x0000000000000006" in output and
                "PANIC trusted kernel fault" in output and "RESEARCH_PASS" not in output,
                "kernel-fault negative control failed")
        return
    require(code == 1, f"unexpected emulator exit {code}")
    require(output.count("ZEAL boot abi=4 x86_64") == 1, "kernel rebooted or never booted")
    require(output.count("MANIFEST_ACCEPT version=2") == 1, "privileged manifest validation missing")
    require(output.count("RESEARCH_PASS") == 1, "missing unique research completion")
    require(f"RESEARCH_PASS scenario=0x{scenario:016x}" in output, "wrong boot configuration")
    require(not any(word in output for word in ("PANIC", "RESEARCH_FAIL", "bad-report")),
            "failure appeared in serial output")
    events = records(output)
    expected_identities = {0: 100, 1: 200, 2: 300, 3: 400}
    for cell, identity in expected_identities.items():
        for boot in select(events, "boot", cell):
            require(boot.get("identity") == identity, "boot identity differs from manifest")
            require(boot.get("abi") == 4 and boot.get("entry") == 0x40000000,
                    "boot image contract differs from manifest")
    for cell in (0, 1):
        boots = select(events, "boot", cell)
        faults = select(events, "fault", cell)
        recovered = select(events, "recovered", cell)
        require([b["generation"] for b in boots] == [1, 2], "service cold boot mismatch")
        require(len(faults) == 1 and faults[0]["reason"] == 64, "service injection missing")
        require(boots[1]["tick"] == faults[0]["tick"] + 4, "service backoff mismatch")
        require(len(recovered) == 1 and recovered[0]["generation"] == 2 and
                recovered[0]["tick"] >= boots[1]["tick"], "file read did not recover")
    require(len(select(events, "boot", 2)) == 1 and not select(events, "fault", 2),
            "healthy application was restarted")
    require(len(select(events, "read", 2)) == 1, "initial verified file read missing")
    delegated = select(events, "cap-delegate", 1)
    allowed = select(events, "demo-allowed", 2)
    forbidden = select(events, "demo-forbidden", 2)
    revoked = select(events, "cap-revoke", 1)
    stale = select(events, "demo-revoked", 2)
    rebind = select(events, "demo-rebind", 2)
    require(len(delegated) == 1 and delegated[0]["rights"] == 4 and
            delegated[0]["holder"] == 0x103 and delegated[0]["target"] == 0x102,
            "runtime delegation identity or rights mismatch")
    require(len(allowed) == 1 and allowed[0]["cap"] == delegated[0]["cap"] and
            allowed[0]["parent"] == delegated[0]["parent"],
            "restricted capability did not complete the allowed file operation")
    require(len(forbidden) == 1 and forbidden[0]["rights"] == 1 and
            forbidden[0]["result"] == 0xfffffffffffffffe,
            "supervisor did not reject the forbidden operation")
    require(len(revoked) == 1 and revoked[0]["cap"] == delegated[0]["cap"] and
            len(stale) == 1 and stale[0]["cap"] == delegated[0]["cap"],
            "revocation or stale-handle rejection missing")
    require(len(rebind) == 1 and rebind[0]["old"] == 0x102 and rebind[0]["endpoint"] == 0x202,
            "filesystem endpoint generation was not rebound")
    def event_index(name, cell):
        return next((i for i, (kind, fields) in enumerate(events)
                     if kind == name and fields["cell"] == cell), -1)
    delegate_at = event_index("cap-delegate", 1)
    forbidden_at = event_index("demo-forbidden", 2)
    allowed_at = event_index("demo-allowed", 2)
    revoke_at = event_index("cap-revoke", 1)
    stale_at = event_index("demo-revoked", 2)
    rebind_at = event_index("demo-rebind", 2)
    fs_restart_at = next(i for i, (kind, fields) in enumerate(events)
                         if kind == "boot" and fields["cell"] == 1 and fields["generation"] == 2)
    require(0 <= delegate_at < forbidden_at < allowed_at < revoke_at < stale_at < fs_restart_at < rebind_at,
            "capability and dependency recovery events are out of order")
    resumed = select(events, "demo-resumed", 2)
    require(len(resumed) >= 2, "application did not resume after explicit and generation revocation")
    healthy_memory = select(events, "healthy-memory", 2)
    require(len(healthy_memory) >= 2 and all(e["stack"] == 0x710bf391ad42c865 and
            e["writable"] == 0x38d126ef8a905b47 for e in healthy_memory),
            "unrelated application memory changed during recovery")
    reads_after_restart = [fields for i, (kind, fields) in enumerate(events)
                           if i > rebind_at and kind == "read-verified" and fields["cell"] == 2
                           and fields["generation"] == 1]
    require(reads_after_restart and reads_after_restart[-1]["reads"] >= 3,
            "verified application reads did not resume after filesystem restart")
    faults = select(events, "fault", 3)
    boots = select(events, "boot", 3)
    reset_reports = select(events, "reset-memory", 3)
    require([r["generation"] for r in reset_reports] == [b["generation"] for b in boots],
            "cold boot did not clear prior stack memory")
    if scenario in (7, 8, 15, 19, 20):
        contract = "wait-contract" if scenario == 19 else "contract"
        require(not faults and len(boots) == 1 and len(select(events, contract, 3)) == 1 and
                len(select(events, "exit", 3)) == 1, "syscall probe did not exit cleanly")
    else:
        require(len(faults) == 4 and len(boots) == 4 and
                len(select(events, "quarantine", 3)) == 1, "fault storm was not bounded")
        require([b["generation"] for b in boots] == [1, 2, 3, 4], "epoch reuse")
        for index, fault in enumerate(faults):
            observed = (fault["reason"], fault["error"])
            valid = observed in ((6, 0), (13, 0)) if scenario == 18 else observed == EXPECTED[scenario]
            require(valid,
                    f"wrong CPU fault in scenario {scenario}: {fault}")
            if index < 3:
                require(boots[index + 1]["tick"] == fault["tick"] + (4 << index),
                        "probe backoff mismatch")
        if scenario in (1, 2, 9, 10, 11):
            address = {1: 0x10000, 2: 0x40000000, 9: 0,
                       10: 0x40020000 - 8, 11: 0x40010000}[scenario]
            require(all(f["address"] == address for f in faults), "wrong fault address")
        if scenario == 3:
            require(all(0x40020000 <= f["address"] < 0x40024000 for f in faults),
                    "NX probe faulted outside its stack")
    if scenario == 20:
        verify_storage(events)
    if scenario == 19:
        verify_waits(events)
    else:
        verify_waits(events, demonstration=False)


def build(scenario, solo=-1):
    output = LOGS / (f"scenario-{scenario:02}" if solo < 0 else f"solo-{solo}-scenario-{scenario:02}")
    command = ["make", "--no-print-directory", f"BUILD={output.relative_to(ROOT)}",
               f"SCENARIO={scenario}", "TEST=1", f"SOLO={solo}", "all"]
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=120)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return output / "zeal.img"


def emulate(image, label, cpu="max", memory="64M", timeout=12):
    command = shlex.split(os.environ.get("QEMU", "qemu-system-x86_64"))
    command += shlex.split(os.environ.get("QEMU_FLAGS", ""))
    command += ["-machine", "pc", "-accel", "tcg", "-cpu", cpu, "-m", memory, "-smp", "1",
                "-drive", f"file={image},format=raw,if=ide", "-display", "none", "-serial", "stdio",
                "-monitor", "none", "-nic", "none", "-no-reboot",
                "-device", "isa-debug-exit,iobase=0xf4,iosize=4"]
    start = time.monotonic()
    try:
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=timeout)
        output, code = result.stdout + result.stderr, result.returncode
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or b"").decode() + (exc.stderr or b"").decode()
        code = None
    (LOGS / f"{label}.log").write_text(output)
    return output, code, round(time.monotonic() - start, 3)


def main():
    LOGS.mkdir(parents=True, exist_ok=True)
    results = []
    negatives = []
    contract_negatives = []
    repetitions = int(os.environ.get("RESEARCH_REPEAT", "2"))
    require(1 <= repetitions <= 20, "RESEARCH_REPEAT must be 1..20")
    try:
        for scenario in range(len(NAMES)):
            image = build(scenario)
            runs = max(2, repetitions) if scenario == 24 else repetitions
            for repeat in range(runs):
                label = f"scenario-{scenario:02}-run-{repeat + 1}"
                output, code, duration = emulate(image, label)
                evidence = verify(output, code, scenario)
                result = {"case": label, "scenario": NAMES[scenario], "seconds": duration,
                          "exit": code, "passed": True, "new_hosting_case": scenario in (21, 22, 23),
                          "new_contract_case": scenario == 24,
                          "boot_image_sha256": hashlib.sha256(image.read_bytes()).hexdigest()}
                if evidence is not None: result["evidence"] = evidence
                results.append(result)
                if scenario == 24 and repeat == 0:
                    import contract_oracle
                    controls = contract_oracle.negative_controls(output, code, scenario)
                    contract_negatives.append({"scenario": scenario, "controls": controls, "passed": True})
                    print(f"PASS contract oracle {scenario}: {len(controls)} negative controls", flush=True)
                if scenario in (21, 22, 23) and repeat == 0:
                    import hosting_oracle
                    controls = hosting_oracle.negative_controls(output, code, scenario)
                    negatives.append({"scenario": scenario, "controls": controls, "passed": True})
                    print(f"PASS hosting oracle {scenario}: {len(controls)} negative controls", flush=True)
            print(f"PASS {scenario:02} {NAMES[scenario]} ({runs} runs)", flush=True)
        image = LOGS / "scenario-00" / "zeal.img"
        for cpu, memory in (("qemu64", "32M"), ("max", "128M")):
            label = f"platform-{cpu}-{memory}"
            output, code, duration = emulate(image, label, cpu, memory)
            verify(output, code, 0)
            results.append({"case": label, "seconds": duration, "passed": True})
            print(f"PASS {label}", flush=True)
        for scenario, cpu, memory in ((21, "qemu64", "32M"), (22, "max", "128M"),
                                      (24, "qemu64", "32M"), (24, "max", "128M")):
            label = f"{'contract' if scenario == 24 else 'hosting'}-platform-{scenario}-{cpu}-{memory}"
            hosted_image = LOGS / f"scenario-{scenario}" / "zeal.img"
            output, code, duration = emulate(hosted_image, label, cpu, memory)
            evidence = verify(output, code, scenario)
            results.append({"case": label, "seconds": duration, "exit": code,
                            "passed": True, "new_hosting_case": scenario in (21, 22, 23),
                            "new_contract_case": scenario == 24, "evidence": evidence,
                            "boot_image_sha256": hashlib.sha256(hosted_image.read_bytes()).hexdigest()})
            print(f"PASS {label}", flush=True)
        output, code, duration = emulate(LOGS / "scenario-18" / "zeal.img",
                                         "sysenter-intel", "max,vendor=GenuineIntel")
        verify(output, code, 18)
        require(all(f["reason"] == 13 for f in select(records(output), "fault", 3)),
                "Intel SYSENTER did not fault at its disabled selector")
        results.append({"case": "sysenter-intel", "seconds": duration, "passed": True})
        print("PASS sysenter-intel", flush=True)
        for cpu in ("qemu64,-nx", "qemu32"):
            label = f"unsupported-{cpu.replace(',', '-')}"
            output, code, duration = emulate(image, label, cpu)
            require(code == 253 and "ZEAL boot" not in output,
                    "unsupported CPU did not fail before launching cells")
            results.append({"case": label, "seconds": duration, "passed": True})
            print(f"PASS {label}", flush=True)
        for solo in range(4):
            scenario = 7 if solo == 3 else 0
            image = build(scenario, solo)
            output, code, duration = emulate(image, f"solo-{solo}", timeout=1)
            events = records(output)
            require(code is None and len(select(events, "boot", solo)) == 1 and
                    len(select(events, "entry", solo)) == 1 and
                    sum(kind == "boot" for kind, _ in events) == 1 and
                    "PANIC" not in output, "standalone service boot failed")
            results.append({"case": f"solo-{solo}", "seconds": duration, "passed": True})
            print(f"PASS solo-{solo}", flush=True)
        for scenario in (0, 7):
            image = build(scenario, 3)
            label = f"idle-supervisor-{scenario:02}"
            output, code, duration = emulate(image, label, timeout=1)
            events = records(output)
            require(code is None and "PANIC" not in output and "bad-report" not in output,
                    "supervisor failed while no cells were runnable")
            if scenario == 0:
                require(len(select(events, "boot", 3)) == 4 and
                        len(select(events, "fault", 3)) == 4 and
                        len(select(events, "quarantine", 3)) == 1,
                        "idle supervisor did not complete bounded recovery")
            else:
                require(len(select(events, "boot", 3)) == 1 and
                        len(select(events, "contract", 3)) == 1 and
                        len(select(events, "exit", 3)) == 1,
                        "idle supervisor did not preserve stopped state")
            results.append({"case": label, "seconds": duration, "passed": True})
            print(f"PASS {label}", flush=True)
        image = build(19, 3)
        label = "idle-supervisor-waits"
        output, code, duration = emulate(image, label)
        events = records(output)
        require(code == 1 and output.count("ZEAL boot abi=4 x86_64") == 1 and
                output.count("MANIFEST_ACCEPT version=2") == 1 and
                output.count("RESEARCH_PASS scenario=0x0000000000000013") == 1 and
                not any(word in output for word in ("PANIC", "RESEARCH_FAIL", "bad-report")),
                "standalone waiting supervisor did not complete with the expected emulator exit")
        require(sum(name == "boot" for name, _ in events) == 1 and
                len(select(events, "entry", 3)) == len(select(events, "reset-memory", 3)) == 1,
                "standalone wait probe boot mismatch")
        verify_waits(events, standalone=True)
        results.append({"case": label, "seconds": duration, "exit": code, "passed": True})
        print(f"PASS {label}", flush=True)
    except (AssertionError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        results.append({"passed": False, "error": str(exc)})
        print(f"FAIL {exc}\nInspect {LOGS}", file=sys.stderr)
        return 1
    finally:
        (LOGS / "hosting-negative-controls.json").write_text(json.dumps(
            {"passed": len(negatives) == 3 and all(item["passed"] for item in negatives),
             "cases": negatives}, indent=2) + "\n")
        (LOGS / "contract-negative-controls.json").write_text(json.dumps(
            {"passed": len(contract_negatives) == 1 and all(item["passed"] for item in contract_negatives),
             "cases": contract_negatives}, indent=2) + "\n")
        (LOGS / "results.json").write_text(json.dumps({"passed": all(r["passed"] for r in results),
                                                     "cases": results}, indent=2) + "\n")
    print(f"Research suite: {len(results)} emulator runs passed. Logs: {LOGS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
