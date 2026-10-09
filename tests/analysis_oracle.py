#!/usr/bin/env python3
"""Independent binary-byte evidence checker for purpose-scoped analysis.

Only standard-library Python and the existing independent privileged hosting
ledger are reused. No production Zig packet, checksum, snapshot, or broker code
is imported. Wire words below are raw privileged observations; progress markers
never replace missing transfers or permit a contradictory authoritative word.
"""
import dataclasses
import hashlib
import json
import pathlib
import re
import struct
import functools
import subprocess
from collections import defaultdict

import hosting_oracle as host
import contract_oracle as scalar

require = host.require
MASK64 = host.MASK64
ROOT = pathlib.Path(__file__).resolve().parents[1]
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
SNAPSHOT_SERIAL_LIMIT = (1 << 56) - 1


def calculate(data):
    """Return the declared tuple; byte iteration has no text normalization."""
    require(isinstance(data, bytes) and len(data) <= 128, "analysis input is not bounded binary bytes")
    checksum = FNV_OFFSET
    for byte in data:
        checksum = ((checksum ^ byte) * FNV_PRIME) & MASK64
    return len(data), data.count(b"\x0a"), checksum


@functools.lru_cache(maxsize=8)
def instruction_boundaries(payload):
    """Decode only the actual immutable image linked into the tested kernel."""
    digest = hashlib.sha256(payload).hexdigest()
    directory = ROOT / "build/research/analysis-code-disassembly"
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / (digest + ".bin")
    source.write_bytes(payload)
    completed = subprocess.run(["objdump", "-D", "-b", "binary", "-m", "i386:x86-64", "--adjust-vma=0x40000000", str(source)],
                               capture_output=True, text=True, timeout=10)
    require(completed.returncode == 0, "independent immutable-code instruction inspection failed")
    (directory / (digest + ".txt")).write_text(completed.stdout)
    boundaries = {int(match.group(1), 16) for line in completed.stdout.splitlines()
                  if (match := re.match(r"^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+\s*[A-Za-z(]", line))}
    require(0x40000000 in boundaries, "tested immutable cell entry is not an actual instruction boundary")
    return frozenset(boundaries)


@functools.lru_cache(maxsize=8)
def entry_prefix(payload):
    """Reconstruct the straight startup stack path through its first INT."""
    instruction_boundaries(payload)
    path = ROOT / "build/research/analysis-code-disassembly" / (hashlib.sha256(payload).hexdigest() + ".txt")
    offsets, delta, expected_address = {}, 0, 0x40000000
    for line in path.read_text().splitlines():
        match = re.match(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*([a-z]+)\s*(.*)$", line)
        if not match:
            continue
        address, raw, mnemonic, operands = match.groups()
        address = int(address, 16)
        if address != expected_address:
            break
        offsets[address] = delta
        width = len(raw.split())
        expected_address = address + width
        if mnemonic == "push":
            delta -= 8
        elif mnemonic == "pop":
            delta += 8
        elif mnemonic in ("sub", "add") and operands.endswith(",%rsp"):
            amount = int(operands.split(",")[0].lstrip("$"), 0)
            delta += amount if mnemonic == "add" else -amount
        elif mnemonic == "int":
            require(operands == "$0x80", "approved startup used unsupported first trap")
            offsets[expected_address] = delta
            return offsets, expected_address
        elif mnemonic.startswith("j") or mnemonic in ("call", "ret") or operands.endswith(",%rsp"):
            break
    raise AssertionError("tested approved startup lacks bounded straight stack path to first INT 0x80")


def snapshot_parts(issuer, token):
    require(issuer & 255 == 2 and 0 < issuer >> 8 <= ((1 << 63) - 1) >> 8,
            "snapshot issuer is not a complete filesystem endpoint")
    require(token & 255 in (0xA1, 0xA2) and 0 < token >> 8 <= SNAPSHOT_SERIAL_LIMIT,
            "snapshot reference has wrong service type/slot or zero serial")
    return issuer, token >> 8, (token & 255) - 0xA1


def endpoint(event):
    slot, generation = event.need("cell", "generation")
    require(0 <= slot < 8 and 0 < generation <= ((1 << 63) - 1) >> 8,
            "trace endpoint has invalid slot or overflowing generation")
    return generation * 256 + slot + 1


def signed32(word):
    require(0 <= word < 1 << 32, "storage result does not fit its raw u32 word")
    return word if word < 1 << 31 else word - (1 << 32)


@dataclasses.dataclass(frozen=True)
class StoragePacket:
    sender: int
    target: int
    operation: int
    transaction: int
    handle: int
    offset: int
    value: int
    data: bytes
    length: int

    @classmethod
    def from_event(cls, event):
        f = event.fields
        event.need("cell", "identity", "generation", "tick", "target", "cap", "operation", "length", "request",
                   "handle", "offset", "result", "data")
        delivered = event.name == "storage-ipc-deliver"
        require(f["request"] > 0 and (f["cap"] == 0 if delivered else f["cap"] > 0) and 0 <= f["offset"] < 1 << 32 and f["data"] <= MASK64,
                "storage wire raw extent or transaction is malformed")
        require(7 <= f["operation"] <= 14, "ordinary storage wire has unsupported operation")
        require(10 <= f["length"] <= 24 if f["operation"] == 10 else f["length"] == 32,
                "storage wire has wrong bounded payload length")
        if "raw0" in f:
            event.need("raw0", "raw1", "raw2", "raw3", "sender", "outcome")
            require((f["raw0"], f["raw1"], f["raw2"], f["raw3"]) == (f["request"], f["handle"], f["offset"] | f["result"] << 32, f["data"]) and (delivered or f["sender"] == endpoint(event)) and (host.signed(f["outcome"]) < 0 if event.name == "storage-reject" else host.signed(f["outcome"]) == 0), "ordinary storage decoded fields contradict raw bytes/authenticated sender/outcome")
        result = cls(f["sender"] if delivered else endpoint(event), f["target"], f["operation"], f["request"], f["handle"], f["offset"],
                     signed32(f["result"]), f["data"].to_bytes(8, "little"), f["length"])
        if result.operation in (7, 11):
            require(0 <= result.value <= 8 and not any(result.data), "read request supplied bytes or an invalid count")
        elif result.operation in (8, 12):
            require(0 <= result.value <= 8 and not any(result.data[result.value:]), "write has invalid count or nonzero padding")
        elif result.operation in (9, 14):
            require(-8 <= result.value <= 8 and not any(result.data[max(result.value, 0):]),
                    "storage reply has invalid signed result or nonzero padding")
        return result

    def open_name(self):
        require(self.operation == 10, "filename selected from a non-open packet")
        raw = struct.pack("<QIi", self.handle, self.offset, self.value)
        name = raw[:self.length - 8]
        require(re.fullmatch(rb"/[A-Za-z0-9_.-]{1,15}", name) is not None, "raw file-open filename is malformed")
        return name.decode("ascii")


class BlockLedger:
    """Reconstruct actual block bytes from applied, matched FS/block transfers."""
    def __init__(self, events):
        self.events = events
        self.bytes = bytearray(512)
        self.bytes[:len(host.PAYLOADS["/hello"])] = host.PAYLOADS["/hello"]
        self.history = {}
        self.transfers = {}
        self.last_transaction = defaultdict(int)
        self.links_by_request = defaultdict(list)
        self.applied = defaultdict(list)
        self.answers = defaultdict(list)
        self.delivered_answers = defaultdict(list)
        for e in events:
            if e.name == "storage-link":
                self.links_by_request[e.fields["request"]].append(e)
            elif e.name == "storage-block":
                self.applied[(endpoint(e), e.fields["request"], e.fields["operation"])].append(e)
            elif e.name == "storage-ipc-deliver" and e.fields.get("operation") == 9:
                self.delivered_answers[(e.fields["sender"], e.fields["request"], e.fields["target"])].append(e)
            elif e.name == "storage-ipc" and e.fields.get("operation") == 9:
                self.answers[(endpoint(e), e.fields["request"])].append(e)

    def run(self):
        events = self.events
        for event in events:
            if event.name != "storage-ipc" or event.fields.get("cell") != 1 or event.fields.get("operation") not in (7, 8):
                continue
            packet = StoragePacket.from_event(event)
            require(packet.sender == 0x102 and packet.target == 0x101 and packet.handle == 0,
                    "actual block transfer changed current filesystem/block generations")
            require(packet.transaction == self.last_transaction[packet.sender] + 1,
                    "filesystem block sequence skipped, reused, or wrapped")
            self.last_transaction[packet.sender] = packet.transaction
            applied = self.applied[(packet.target, packet.transaction, packet.operation)]
            replies = self.answers[(packet.target, packet.transaction)]
            require(len(applied) == len(replies) == 1, "block operation lacks unique actual applied outcome and reply")
            answer = StoragePacket.from_event(replies[0])
            deliveries = self.delivered_answers[(answer.sender, answer.transaction, answer.target)]
            require(len(deliveries) == 1 and StoragePacket.from_event(deliveries[0]) == answer and replies[0].index < deliveries[0].index,
                    "actual filesystem/block byte provenance omitted or counterfeited authenticated copied delivery")
            require(event.index < applied[0].index < replies[0].index and answer.target == packet.sender and
                    answer.handle == 0 and answer.offset == packet.offset and answer.value == packet.value ==
                    signed32(applied[0].fields["result"]), "block applied result contradicts raw request/reply ordering or extent")
            require(packet.offset <= 512 and packet.offset + packet.value <= 512,
                    "block transfer escaped finite backing")
            before = bytes(self.bytes)
            if packet.operation == 8:
                self.bytes[packet.offset:packet.offset + packet.value] = packet.data[:packet.value]
                require(not any(answer.data), "write acknowledgement returned undeclared bytes")
            else:
                require(answer.data[:packet.value] == before[packet.offset:packet.offset + packet.value],
                        "block read bytes contradict independently reconstructed actual earlier writes")
            self.history[event.index] = before
            self.transfers[(packet.sender, packet.transaction)] = (event, applied[0], replies[0], packet, answer)
        return self

    def transfers_for(self, request):
        packet = StoragePacket.from_event(request)
        links = [e for e in self.links_by_request[packet.transaction] if request.index < e.index]
        result = []
        for link in links:
            key = endpoint(link), link.fields.get("block_request")
            if key not in self.transfers:
                continue
            transfer = self.transfers[key]
            if request.index < link.index < transfer[0].index:
                result.append((link, *transfer))
        return result


def manifest_records(path):
    data = pathlib.Path(path).read_bytes()
    require(40 <= len(data) <= 1320, "analysis sealed manifest size is invalid")
    magic, version, length, roots, grants, templates, domains, *reserved = struct.unpack_from("<10I", data)
    require((magic, version, length, roots, templates, domains) == (0x4C41455A, 2, len(data), 4, 2, 1)
            and grants == 9 and not any(reserved), "analysis manifest changed its explicit bounded composition")
    require(len(data) == 40 + roots * 64 + grants * 16 + templates * 64 + domains * 32,
            "analysis manifest record extents are not exact")
    root_records = host.SealedRoots(grants)
    for slot in range(roots):
        values = struct.unpack_from("<4IQ6I16s", data, 40 + slot * 64)
        identity, image, abi, flags, entry, budget, stack, writable, config, limit, delay, name = values
        require((identity, image, abi, flags, entry, budget, stack, writable, config, limit, delay) ==
                (host.ROOT_IDS[slot], slot + 1, 4, 1, 0x40000000, 65536, 16384, 81920, 25 if slot in (2, 3) else 0, 3, 4),
                "analysis manifest changed an original root identity/image/ABI/private reservation")
        root_records[slot] = dict(identity=identity, image=image, abi=abi, entry=entry, budget=budget,
                                 pages=host.pages(stack, writable), stack=stack, writable=writable, config=config)
    require(sum(r["pages"] for r in root_records.values()) == 80, "analysis root pages exceed original reservation")
    at = 40 + roots * 64
    expected = ((100, 200, 258, 0), (200, 100, 193, 0), (200, 200, 0x800E0004, 0),
                (200, 300, 8216, 0), (300, 200, 7716, 0), (400, 200, 0x31E00, 0),
                (200, 400, 0x42000, 0), (400, 300, 1 << 14, 0), (300, 400, 16 | (1 << 15), 0))
    actual = tuple(struct.unpack_from("<4I", data, at + i * 16) for i in range(grants))
    require(actual == expected, "analysis sealed grants changed exact holders/targets/narrow rights or entitlement")
    root_records.initial_capabilities = {
        (i + 1) << 8 | (i + 1): (holder // 100 + 0x100, target // 100 + 0x100, rights)
        for i, (holder, target, rights, unused) in enumerate(actual)}
    at += grants * 16
    approved = {}
    for i in range(templates):
        values = struct.unpack_from("<4IQ10I", data, at + i * 64)
        identity, image, abi, flags, entry, budget, stack, writable, config, limit, delay, depth, mask, recipe, unused = values
        require(identity in (5, 6) and identity not in approved, "analysis template identity is unapproved or repeated")
        expected = (5, 8192, 16384, 1, 32, 4) if identity == 5 else (6, 4096, 8192, 0, 0, 5)
        require((image, stack, writable, depth, mask) == expected[:5] and
                (abi, flags, entry, budget, config, limit, delay, recipe, unused) == (4, 0, 0x40000000, 65536, 25, 3, 4, 2, 0),
                "analysis approved profile/backing/configuration/recipe is not explicit sealed recipe2")
        approved[identity] = dict(image=image, pages=host.pages(stack, writable), depth=depth, mask=mask,
                                 stack=stack, writable=writable, recipe=recipe, role=expected[5], budget=budget)
    require(struct.unpack_from("<8I", data, at + templates * 64) == (400, 48, 4, 48, 2, 2, 0, 0),
            "analysis owner creator domain differs from exact recipe2 entitlement")
    return root_records, approved, hashlib.sha256(data).hexdigest()


@dataclasses.dataclass(frozen=True)
class ContractPacket:
    sender: int
    target: int
    operation: int
    request: int
    command: int
    kind: int
    detail: int
    token: int
    data: int

    @classmethod
    def from_event(cls, event):
        f = event.fields
        event.need("sender", "target", "cap", "operation", "length", "request", "command", "reserved", "argument", "value",
                   "version", "service_command", "kind", "detail", "token", "data", "result", "raw0", "raw1", "raw2", "raw3")
        require(f["length"] == 32 and f["operation"] in (15, 16) and f["request"] > 0,
                "analysis contract wire has invalid transaction/extent/operation")
        require(f["version"] == 1 and 1 <= f["service_command"] <= 15 and f["kind"] <= 3 and f["detail"] <= 255 and f["reserved"] == 0,
                "analysis contract wire version/command/kind/detail/reserved bytes are invalid")
        packed = f["version"] | f["service_command"] << 8 | f["kind"] << 16 | f["detail"] << 24
        require((f["command"], f["argument"], f["value"]) == (packed, f["token"], f["data"]) and
                (f["raw0"], f["raw1"], f["raw2"], f["raw3"]) == (f["request"], packed, f["token"], f["data"]),
                "analysis decoded contract fields contradict authoritative raw bytes")
        return cls(f["sender"], f["target"], f["operation"], f["request"], f["service_command"], f["kind"], f["detail"], f["token"], f["data"])


@dataclasses.dataclass(frozen=True)
class SnapshotPacket:
    sender: int
    target: int
    operation: int
    transaction: int
    token: int
    word: int
    tail: bytes

    @classmethod
    def from_event(cls, event):
        f = event.fields
        event.need("sender", "target", "cap", "operation", "length", "raw0", "raw1", "raw2", "raw3", "result", "outcome", "request", "handle", "offset", "data")
        require((f["request"], f["handle"], f["offset"], f["result"], f["data"]) == (f["raw0"], f["raw1"], f["raw2"] & 0xFFFFFFFF, f["raw2"] >> 32, f["raw3"]), "snapshot decoded fields contradict authoritative raw bytes")
        require(f["length"] == 32 and f["operation"] in (17, 18, 19, 20) and f["raw0"] > 0,
                "snapshot wire has invalid exact extent/operation/transaction")
        require(all(0 <= f[f"raw{i}"] <= MASK64 for i in range(4)), "snapshot raw word overflows u64")
        return cls(f["sender"], f["target"], f["operation"], f["raw0"], f["raw1"], f["raw2"], f["raw3"].to_bytes(8, "little"))

    def control(self):
        require(self.operation == 17 and self.token and 1 <= self.tail[0] <= 8 and not any(self.tail[1:]),
                "snapshot control action/subject/reserved bytes are malformed")
        action = self.tail[0]
        require(self.word > 0 if action in (3, 4, 7) else self.word == 0, "snapshot control peer has wrong exact scope")
        return action, self.word

    def read(self):
        if self.operation == 20:
            require(self.token and self.word, "snapshot release omitted full object identity")
            return self.word, 0, 0
        require(self.operation in (18, 20) and self.token and self.word and not any(self.tail[3:]) and self.tail[2] <= 8,
                "snapshot read has malformed reference/count/padding")
        offset, count = int.from_bytes(self.tail[:2], "little"), self.tail[2]
        require(self.operation != 20 or (offset, count) == (0, 0), "release request changes a read extent")
        return self.word, offset, count

    def control_reply(self):
        require(self.operation == 19 and self.tail[7] == 1 and not any(self.tail[4:7]) and self.tail[0] <= 128 and
                1 <= self.tail[2] <= 8 and self.tail[3] <= 5, "snapshot control reply metadata/padding/version is malformed")
        status = self.tail[1] if self.tail[1] < 128 else self.tail[1] - 256
        require(status in (0, -1, -2, -3, -4, -6, -7, -8), "snapshot control reply has undefined status")
        return self.tail[0], status, self.tail[2], self.tail[3]

    def read_reply(self):
        raw = self.word.to_bytes(8, "little") + self.tail
        require(self.operation == 19 and raw[15] == 2 and not any(raw[12:15]), "snapshot read reply has wrong kind or padding")
        offset, count = int.from_bytes(raw[:2], "little"), raw[2]
        status = raw[3] if raw[3] < 128 else raw[3] - 256
        require(count <= 8 and status in (0, -1, -2, -3, -4, -6, -7, -8) and
                (status == 0 or count == 0) and not any(raw[4 + count:12]), "snapshot read reply count/status/padding is invalid")
        return offset, count, status, raw[4:4 + count]


class KernelLedger(scalar.Observer):
    copied_fields = scalar.Observer.copied_fields
    """Replay the actual shared hosting/page/capability engine for recipe2."""
    def __init__(self, events, roots, approved):
        host.Observer.__init__(self, events, roots, approved, 25, bootstrap_recipe=2)
        self.supervisor_template, self.worker_template, self.root_template_mask, self.fault_commands = 5, 6, 48, (7,)
        self.root_capabilities = dict(roots.initial_capabilities)
        self.catalog, self.catalog_domain = {}, None
        self.route_history, self.storage_channels, self.capability_states = {}, {}, {}
        self.aborted_routes = set()
        self.rpc_channel_history = {}
        self.capability_info = {cap: (holder, target, holder, rights, 0, cap >> 8) for cap, (holder, target, rights) in self.root_capabilities.items()}
        self.queries, self.conservation, self.ordinary_rejections, self.storage_denials = [], [], [], []
        self.packet_events = {}
        self.reap_reports = []
        self.worker_sleep_returns = []
        self.snapshot_enqueued, self.snapshot_delivered, self.snapshot_rejected = [], [], []

    def channel(self, node, parent_cap, child_cap, event):
        f = event.fields
        event.need("recipe", *[f"{d}_{k}" for d in ("parent", "child") for k in ("holder", "target", "issuer", "rights", "derivation", "epoch")])
        for direction, cap in (("parent", parent_cap), ("child", child_cap)):
            self.capability_info[cap] = tuple(f[f"{direction}_{name}"] for name in ("holder", "target", "issuer", "rights", "derivation", "epoch"))
        if f["parent_rights"] == 1 << 14:
            require(parent_cap >> 8 == self.maximum_capability_epoch + 1, "RPC channel omitted consumed capability epochs from complete observed namespace")
            super().channel(node, parent_cap, child_cap, event)
            self.rpc_channel_history[(node.instance, node.endpoint)] = event, parent_cap, child_cap
            return
        rights = (1 << 17) | ((1 << 19) if node.template == 5 else 0)
        require(f["recipe"] == 2 and (f["parent_holder"], f["parent_target"], f["parent_issuer"], f["parent_rights"], f["parent_derivation"], f["parent_epoch"]) ==
                (node.endpoint, 0x102, 0x102, rights, 0x303, parent_cap >> 8),
                "snapshot request route lacks exact current holder/FS issuer/sealed derivation/profile rights")
        require((f["child_holder"], f["child_target"], f["child_issuer"], f["child_rights"], f["child_derivation"], f["child_epoch"]) ==
                (0x102, node.endpoint, 0x102, 1 << 18, 0, child_cap >> 8), "snapshot reply route lacks checked exact-current filesystem holder/worker target")
        require(self.root_capabilities.get(0x303) == (0x102, 0x102, 0x800E0004), "snapshot derivation lacks configured exact live entitlement")
        require(parent_cap >> 8 == self.maximum_capability_epoch + 1 and child_cap >> 8 == (parent_cap >> 8) + 1,
                "snapshot pair reused/wrapped/changed global capability epochs")
        for cap in (parent_cap, child_cap):
            require(1 <= cap & 255 <= 32 and 0 < cap >> 8 <= ((1 << 63) - 1) >> 8 and cap not in self.capabilities_seen and cap >> 8 not in self.capability_epochs,
                    "snapshot route collided with existing capability identity")
            self.capabilities_seen.add(cap)
            self.capability_epochs.add(cap >> 8)
        self.maximum_capability_epoch = child_cap >> 8
        self.storage_channels[parent_cap] = (node.endpoint, 0x102, rights)
        self.storage_channels[child_cap] = (0x102, node.endpoint, 1 << 18)
        self.route_history[(node.instance, node.endpoint)] = (event, parent_cap, child_cap)

    def creation(self, event):
        f = event.fields
        if event.name == "host-channel" and f.get("parent_rights") != 1 << 14:
            key = f["caller_endpoint"], f["request"]
            require(key in self.transactions and self.transactions[key]["stage"] == "channel", "snapshot route preceded actual creation/RPC channel")
            node = self.transactions[key]["node"]
            require(f["instance"] == node.instance and f["endpoint"] == node.endpoint and f["phase"] == 0,
                    "snapshot connection was not part of unpublished checked creation")
            self.channel(node, f["parent_cap"], f["child_cap"], event)
            return
        if event.name == "host-request":
            caller = f["caller_endpoint"]
            require((f["template"], f["requested_slots"], f["requested_pages"]) == ((5, 2, 4) if caller == 0x104 else (6, 0, 0)),
                    "analysis creation did not use the approved exact broker/worker backing")
        if event.name == "host-publish":
            node = self.transactions[(f["caller_endpoint"], f["request"])]["node"]
            require((node.instance, node.endpoint) in self.route_history, "runnable child published without both checked snapshot routes")
        if event.name == "host-abort":
            node = self.transactions[(f["caller_endpoint"], f["request"])]["node"]
            self.storage_channels = {cap: grant for cap, grant in self.storage_channels.items() if node.endpoint not in grant[:2]}
            self.aborted_routes.add((node.instance, node.endpoint))
        if event.name == "host-space":
            require(f.get("ss") == 0x23 and f.get("rflags") == 0x202, "created private frame has contradictory unsafe SS/RFLAGS")
        if event.name == "host-abort" or event.name == "host-result" and host.signed(f["result"]) < 0:
            return host.Observer.creation(self, event)
        return scalar.Observer.creation(self, event)

    def lifecycle(self, event):
        f = event.fields
        if event.name == "host-rebind" and f.get("parent_rights") != 1 << 14:
            node = self.tree.node(f["instance"])
            require(self.rebound and self.rebound[-1].fields["instance"] == node.instance and self.rebound[-1].fields["request"] == f["request"],
                    "snapshot rebind lacks exact immediately paired current-generation parent/RPC rebind")
            self.channel(node, f["parent_cap"], f["child_cap"], event)
            return
        if event.name == "host-fault":
            requests = [e for e in self.delivered if e.fields["target"] == f["endpoint"] and e.fields["service_command"] == 7 and e.index < event.index]
            require(requests, "analysis fault lacks actual complete accepted work delivery")
            work = ContractPacket.from_event(requests[-1])
            lengths = [e for e in self.delivered if e.fields["target"] == work.target and e.fields["request"] == work.request and e.fields["token"] == work.token and e.fields["service_command"] == 12 and e.index < requests[-1].index]
            require(lengths and lengths[-1].fields["data"] >> 24 & 1, "analysis fault was not explicitly selected by exact accepted work descriptor")
        if event.name == "host-invalidate":
            retired = self.tree.node(f["instance"]).endpoint
            self.storage_channels = {cap: grant for cap, grant in self.storage_channels.items() if retired not in grant[:2]}
        return scalar.Observer.lifecycle(self, event)

    def checked_call(self, event):
        f = event.fields
        scalar.Observer.checked_call(self, event)
        if f["result"] == 0 and f["call"] in (14, 19):
            prior_calls = [e for e in self.calls if e.fields["caller_endpoint"] == f["caller_endpoint"] and e.fields["call"] == f["call"]]
            lower = prior_calls[-1].index if prior_calls else -1
            name = "host-status" if f["call"] == 14 else "host-domain"
            observed = [e for e in self.events if lower < e.index < event.index and e.name == name and
                        e.fields.get("caller_endpoint") == f["caller_endpoint"] and
                        e.fields.get("control" if f["call"] == 14 else "domain") == f["arg0"]]
            require(len(observed) == 1, "actual successful management query omitted or duplicated its authoritative service seam")

    def fault_command(self, event):
        return event.fields["service_command"]

    def ipc(self, event):
        packet = ContractPacket.from_event(event)
        endpoint_, node = self.principal(event)
        require(host.signed(event.fields["result"]) == 0, "accepted contract IPC reports failed checked copy")
        if event.name == "host-ipc-enqueue":
            grants = {**self.root_capabilities, **{c: (h, t, 1 << (op - 1)) for c, (h, t, op) in self.channels.items()}}
            require(event.fields["cap"] in grants and grants[event.fields["cap"]][:2] == (packet.sender, packet.target) and
                    grants[event.fields["cap"]][2] & 1 << (packet.operation - 1), "contract IPC lacks actual exact holder/target/operation authority")
            require(endpoint_ == packet.sender and endpoint_ not in self.waits and len(self.queues[packet.target]) < 8,
                    "contract IPC changed authenticated sender, ran asleep, or overflowed kernel queue")
            self.queues[packet.target].append(event)
            self.enqueued.append(event)
        else:
            require(endpoint_ == packet.target and event.fields["cap"] == 0 and self.queues[packet.target],
                    "contract delivery has wrong endpoint/capability or no actual enqueue")
            enqueue = self.queues[packet.target].pop(0)
            require(ContractPacket.from_event(enqueue) == packet and enqueue.index < event.index,
                    "contract delivery contradicted authenticated raw bytes or FIFO")
            if node:
                require(endpoint_ in node.entered == node.cold == set(node.memories), "child IPC lacks actual ring3/cold/private-memory evidence")
            self.delivered.append(event)
        self.packet_events[event.index] = packet

    def snapshot_ipc(self, event):
        packet = SnapshotPacket.from_event(event)
        endpoint_, node = self.principal(event)
        f = event.fields
        if event.name.endswith("reject"):
            require(host.signed(f["outcome"]) < 0, "snapshot rejection reports successful authority")
            self.snapshot_rejected.append(event)
            return
        require(host.signed(f["outcome"]) == 0, "accepted snapshot IPC reports a rejected kernel operation")
        if event.name.endswith("enqueue"):
            grants = {**self.root_capabilities, **self.storage_channels}
            require(f["cap"] in grants and grants[f["cap"]][:2] == (packet.sender, packet.target) and
                    grants[f["cap"]][2] & 1 << (packet.operation - 1), "snapshot request/reply has no exact current checked route")
            require(endpoint_ == packet.sender and len(self.queues[packet.target]) < 8 and endpoint_ not in self.waits,
                    "snapshot IPC changed sender, overflowed FIFO, or ran before wake")
            if packet.operation == 19:
                require(any(query.fields["cap"] == f["cap"] and query.fields["holder"] == packet.sender and query.fields["target"] == packet.target and
                            query.fields["result"] == 0 and query.index < event.index for query in self.queries),
                        "filesystem reply omitted actual current cached holder/target/issuer/derivation/rights/generation query")
            self.queues[packet.target].append(event)
            self.snapshot_enqueued.append(event)
        else:
            require(endpoint_ == packet.target and f["cap"] == 0 and self.queues[packet.target], "snapshot delivery lacks exact authenticated receiver/enqueue")
            enqueue = self.queues[packet.target].pop(0)
            require(SnapshotPacket.from_event(enqueue) == packet and enqueue.index < event.index,
                    "snapshot delivered raw bytes contradicted enqueue or FIFO")
            self.snapshot_delivered.append(event)

    def ordinary_ipc(self, event):
        packet = StoragePacket.from_event(event)
        endpoint_, node = self.principal(event)
        f = event.fields
        require(node is None, "ordinary storage transfer came from an admitted hosted snapshot reader")
        if event.name == "storage-ipc":
            require(f["cap"] in self.root_capabilities and self.root_capabilities[f["cap"]][:2] == (packet.sender, packet.target) and
                    self.root_capabilities[f["cap"]][2] & 1 << (packet.operation - 1),
                    "ordinary file/block transfer lacks exact original sealed holder/target/operation authority")
            require(endpoint_ == packet.sender and endpoint_ not in self.waits and len(self.queues[packet.target]) < 8,
                    "ordinary transfer changed authenticated sender, ran asleep, or overflowed shared bounded kernel FIFO")
            self.queues[packet.target].append(event)
        else:
            require(endpoint_ == packet.target and f["cap"] == 0 and self.queues[packet.target],
                    "ordinary delivery changed receiver/capability or omitted actual authorized enqueue")
            enqueue = self.queues[packet.target].pop(0)
            require(enqueue.name == "storage-ipc" and StoragePacket.from_event(enqueue) == packet and enqueue.index < event.index,
                    "ordinary delivery counterfeited authenticated raw bytes/sender or changed cross-protocol FIFO")

    def kernel_entry(self, event):
        endpoint_, node = self.principal(event)
        f = event.fields
        event.need("endpoint", "instance", "control", "template", "depth", "parent_endpoint", "cs", "ss", "rip", "rsp", "rflags", "vector")
        require(node is not None and endpoint_ not in self.kernel_entries and
                (f["endpoint"], f["instance"], f["control"], f["template"], f["depth"], f["parent_endpoint"]) ==
                (endpoint_, node.instance, node.control, node.template, node.depth, node.parent_endpoint), "actual ring3 entry changed authenticated runtime ancestry")
        t = self.approved[node.template]
        require(f["cs"] == 0x1B and f["ss"] == 0x23 and f["vector"] in (32, 128) and
                0x40000000 <= f["rip"] < 0x40000000 + t["image_bytes"] and f["rip"] in instruction_boundaries(t["payload"]) and 0x40020000 <= f["rsp"] < 0x40020000 + t["stack"] and f["rsp"] & 7 == 0 and
                f["rflags"] & 0x202 == 0x202 and f["rflags"] & 0x27400 == 0 and f["rflags"] & ~scalar.RFLAGS_DOCUMENTED == 0,
                "actual hardware frame lacks safe ring3 code/stack/general-register execution")
        prefix, first_syscall = entry_prefix(t["payload"])
        require(f["rip"] in prefix and f["rsp"] == 0x40020000 + t["stack"] - 8 + prefix[f["rip"]] and
                (f["rip"] == first_syscall if f["vector"] == 128 else f["rip"] < first_syscall),
                "first actual ring3 trap contradicted the linked immutable startup instruction/stack path")
        if f["rip"] == 0x40000000:
            require(f["vector"] == 32 and f["rsp"] == 0x40020000 + t["stack"] - 8 and f["rflags"] == 0x202,
                    "first entry interrupt contradicted its actual prepared initial private stack/flags")
        if f["vector"] == 128:
            offset = f["rip"] - 0x40000000
            require(offset >= 2 and t["payload"][offset - 2:offset] == b"\xcd\x80", "syscall hardware entry RIP does not follow actual immutable INT 0x80 bytes")
        self.kernel_entries.add(endpoint_)

    def run(self):
        for event in self.events:
            f = event.fields
            if event.name == "analysis-conservation":
                event.need("active_capabilities", "root_grants", "legacy_read_grants", "snapshot_empty", "physical_pages", "tick")
                require(self.completed and f["tick"] >= self.last_tick and (f["active_capabilities"], f["root_grants"], f["legacy_read_grants"], f["snapshot_empty"], f["physical_pages"]) ==
                        (len(self.root_capabilities) + len(self.channels) + len(self.storage_channels), self.roots.grant_count, len(self.root_capabilities) - self.roots.grant_count, 1, len(self.tree.page_owners)) == (10, 9, 1, 1, 80),
                        "authoritative final capability/input/private-page conservation contradicted independent ledgers")
                self.conservation.append(event)
                continue
            if event.name not in ("host-template", "host-root-domain"):
                event.need("cell", "identity", "generation", "tick")
                endpoint(event)  # Every complete runtime generation has the policy's signed nonwrapping ceiling.
                require(f["tick"] >= self.last_tick, "analysis trace tick moved backwards")
                self.last_tick = f["tick"]
            if event.name == "host-template":
                template = f.get("template")
                require(template in self.approved and template not in self.catalog and not self.published, "sealed analysis catalog changed after creation or duplicated")
                t = self.approved[template]
                keys = ("image", "abi", "entry", "image_bytes", "image_budget", "stack_budget", "writable_budget", "pages", "config", "restart_limit", "restart_delay", "max_depth", "template_mask", "recipe", "reserved")
                event.need(*keys)
                require(tuple(f[k] for k in keys) == (t["image"], 4, 0x40000000, t["image_bytes"], 65536, t["stack"], t["writable"], t["pages"], 25, 3, 4, t["depth"], t["mask"], 2, 0), "trusted template catalog contradicts sealed/tested image")
                self.catalog[template] = event
            elif event.name == "host-root-domain":
                require(self.catalog_domain is None and not self.published and
                        (f.get("endpoint"), f.get("template_mask"), f.get("slot_limit"), f.get("page_limit"), f.get("max_depth"), f.get("recipe"), f.get("reserved0"), f.get("reserved1")) ==
                        (0x104, 48, 4, 48, 2, 2, 0, 0), "trusted analysis domain catalog contradicts explicit sealed authority")
                self.catalog_domain = event
            elif event.name == "boot":
                slot = f["cell"]
                if slot >= 4:
                    endpoint_, node = self.principal(event)
                    require(any(e.fields["instance"] == node.instance and e.fields["generation"] == f["generation"] for e in self.restarts), "analysis child prebooted or silently restarted")
                    require(f.get("physical_pages") == node.own_pages and tuple(f.get(f"p{i}") for i in range(node.own_pages)) == node.pages_owned, "restart changed retained actual private backing")
                    continue
                require(slot not in self.root_boots and (f["identity"], f["generation"], f.get("abi"), f.get("entry"), f.get("image"), f.get("config"), f.get("writable_budget")) ==
                        (host.ROOT_IDS[slot], 1, 4, 0x40000000, slot + 1, self.roots[slot]["config"], 81920), "analysis boot changed original root identity/configuration/private budget")
                count = self.roots[slot]["pages"]
                require(f.get("physical_pages") == count, "analysis root lacks exact original physical page charge")
                for page in event.need(*(f"p{i}" for i in range(count))):
                    require(0 <= page < 128 and page not in self.tree.page_owners, "root private backing overlaps existing allocation")
                    self.tree.page_owners[page] = -(slot + 1)
                self.root_boots[slot] = event
            elif event.name.startswith("host-") and event.name.removeprefix("host-") in host.MANAGEMENT:
                require(len(self.root_boots) == 4 and set(self.catalog) == {5, 6} and self.catalog_domain is not None, "dynamic management preceded actual roots/sealed catalog")
                if event.name in ("host-request", "host-reserve", "host-space", "host-channel", "host-publish", "host-abort", "host-result"):
                    self.creation(event)
                else:
                    self.lifecycle(event)
            elif event.name == "host-domain":
                self.domain_status(event)
            elif event.name in ("host-ipc-enqueue", "host-ipc-deliver"):
                self.ipc(event)
            elif event.name == "host-ipc-reject":
                self.principal(event)
                ContractPacket.from_event(event)
                require(host.signed(f["result"]) < 0, "contract authority denial returned success")
                self.ipc_rejected.append(event)
            elif event.name in ("snapshot-ipc-enqueue", "snapshot-ipc-deliver", "snapshot-ipc-reject"):
                self.snapshot_ipc(event)
            elif event.name == "host-call":
                self.checked_call(event)
                self.calls.append(event)
            elif event.name == "host-kernel-entry":
                self.kernel_entry(event)
            elif event.name in ("host-entry", "host-cold", "host-memory", "host-ledger", "host-storage-denied", "host-complete"):
                if event.name == "host-storage-denied":
                    self.storage_denials.append(event)
                if event.name == "host-entry":
                    require(endpoint(event) in self.kernel_entries, "child marker substituted for actual ring3 hardware entry")
                if event.name == "host-memory" and self.tree.at(f["cell"]).template == 6:
                    endpoint_, node = self.principal(event)
                    require(endpoint_ in node.cold and f.get("value") == (0x029A814EF734BC71 ^ endpoint_) and f.get("extra") == f["value"] ^ MASK64, "analysis worker lost its execution-specific private-memory sentinel")
                    node.memories[endpoint_] = (f["value"], f["extra"])
                else:
                    super().app(event)
            elif event.name == "entry":
                endpoint_, node = self.principal(event)
                require(node is None, "generic entry substituted for actual hosted ring3 hardware trap")
                self.kernel_entries.add(endpoint_)
            elif event.name in ("wait-arm", "wake", "wait-cancel"):
                self.wait(event)
            elif event.name in ("fault", "exit", "quarantine"):
                require(f["cell"] >= 4, "analysis scenario retired original storage/application root")
                if event.name == "fault":
                    self.principal(event)
                    self.hardware_faults.append(event)
            elif event.name == "cap-delegate":
                endpoint_, _ = self.principal(event)
                require(endpoint_ == 0x102 and (f.get("holder"), f.get("target"), f.get("rights"), f.get("parent")) == (0x103, 0x102, 4, 0x303), "analysis changed independent original delegation")
                require(0 < f["cap"] >> 8 <= ((1 << 63) - 1) >> 8 and f["cap"] >> 8 == self.maximum_capability_epoch + 1 and f["cap"] >> 8 not in self.capability_epochs, "root delegation recycled capability epoch")
                self.maximum_capability_epoch = f["cap"] >> 8
                self.capability_epochs.add(f["cap"] >> 8)
                self.root_capabilities[f["cap"]] = (0x103, 0x102, 4)
                self.capability_info[f["cap"]] = (0x103, 0x102, 0x102, 4, 0x303, f["cap"] >> 8)
            elif event.name == "cap-query":
                endpoint_, node = self.principal(event)
                event.need("cap", "holder", "target", "issuer", "rights", "parent", "epoch", "reserved", "valid", "result")
                if f["result"] == 0:
                    grants = {**self.root_capabilities, **self.storage_channels, **{c: (h, t, 1 << (op - 1)) for c, (h, t, op) in self.channels.items()}}
                    require(f["cap"] in grants and grants[f["cap"]][0] == endpoint_ and f["cap"] in self.capability_info and
                            tuple(f[key] for key in ("holder", "target", "issuer", "rights", "parent", "epoch")) == self.capability_info[f["cap"]] and f["reserved"] == 0 and f["valid"] == 1, "actual capability query contradicted installed holder/target/issuer/derivation/rights/epoch")
                else:
                    require(host.signed(f["result"]) < 0 and not any(f[key] for key in ("holder", "target", "issuer", "rights", "parent", "epoch", "reserved", "valid")), "failed capability query fabricated authority metadata")
                self.queries.append(event)
            elif event.name == "contract-complete":
                require(endpoint(event) == 0x104 and f.get("value") == 25 and f.get("extra") == 0 and self.tree.ledger() == (0, 0, 0, 0, 4, 48) and not self.tree.slots, "analysis completion lacks actual complete tree/page settlement")
                self.completed.append(event)
            elif event.name in ("storage-ipc", "storage-ipc-deliver"):
                self.ordinary_ipc(event)
            elif event.name == "storage-reject":
                packet = StoragePacket.from_event(event)
                endpoint_, node = self.principal(event)
                require(host.signed(f["outcome"]) < 0 and packet.sender == endpoint_ and node is not None,
                        "ordinary storage rejection fabricated success or unrelated sender")
                grants = {**self.root_capabilities, **self.storage_channels, **{c: (h, t, 1 << (op - 1)) for c, (h, t, op) in self.channels.items()}}
                grant = grants.get(f["cap"])
                if host.signed(f["outcome"]) == -2:
                    require(grant is not None and (grant[:2] != (packet.sender, packet.target) or not grant[2] & 1 << (packet.operation - 1)),
                            "ordinary storage denial counterfeited rights that actually authorize the attempted operation")
                self.ordinary_rejections.append(event)
            elif event.name.startswith(("storage-", "hosting-storage-", "analysis-", "contract-", "snapshot-")) or event.name in ("healthy-memory", "reset-memory", "idle", "idle-enter", "idle-exit", "idle-wake", "cap-query", "host-reaped", "host-timeout", "host-sleep-start", "host-sleep-return", "host-computed", "host-copied", "host-stale", "host-denied"):
                # All application/service evidence is checked causally by the
                # profile observer below; principal validation is never skipped.
                endpoint_, node = self.principal(event)
                if event.name.startswith(("contract-", "analysis-", "snapshot-", "hosting-storage-")):
                    event.need("endpoint", "instance", "template", "depth", "parent_endpoint", "value", "extra")
                    require(tuple(f[key] for key in ("endpoint", "instance", "template", "depth", "parent_endpoint")) ==
                            (endpoint_, node.instance if node else 0, node.template if node else 0, node.depth if node else 0, node.parent_endpoint if node else 0),
                            "service/application progress contradicted authenticated current execution ancestry")
                    require(endpoint_ not in self.waits, "waiting execution emitted application progress before actual wake")
            else:
                raise AssertionError("unknown analysis event " + event.name)
            self.capability_states[event.index] = {**self.root_capabilities, **self.storage_channels,
                                                  **{c: (h, t, 1 << (op - 1)) for c, (h, t, op) in self.channels.items()}}
        require(len(self.root_boots) == 4 and not self.transactions and len(self.completed) == 1 and not self.tree.slots and
                self.tree.ledger() == (0, 0, 0, 0, 4, 48), "analysis ended without actual complete resource conservation")
        require(all(n.entered == n.cold == set(n.memories) and n.endpoint in n.entered and n.entered <= self.kernel_entries for n in self.tree.nodes.values()),
                "analysis published child lacks actual private memory/cold/ring3 evidence")
        require(not self.storage_channels and not self.channels, "analysis completed with retained temporary checked IPC routes")
        for node in self.tree.nodes.values():
            for execution in node.entered:
                markers = [e for e in self.storage_denials if endpoint(e) == execution and e.fields["identity"] == node.identity]
                require(len(markers) == 1, "runtime incarnation omitted its actual checked ordinary-storage denial report")
                for operation, target in (((10, 0x102), (7, 0x101), (11, 0x102), (12, 0x102)) if node.template == 6 else ((10, 0x102), (7, 0x101))):
                    denied = [e for e in self.ordinary_rejections if endpoint(e) == execution and e.fields["identity"] == node.identity and
                              e.fields["operation"] == operation and e.fields["target"] == target and e.index < markers[0].index and host.signed(e.fields["outcome"]) == -2]
                    require(len(denied) == 1, "runtime acquired ordinary file-open/chunk/write/raw-block access or omitted actual narrow-route denial")
        require(len(self.conservation) == 1, "analysis omitted unique actual final capability/input/page conservation")
        for (instance, execution), (admission, parent_cap, child_cap) in self.rpc_channel_history.items():
            if (instance, execution) in self.aborted_routes:
                continue
            require(any(e.fields["cap"] == child_cap and e.fields["holder"] == execution and admission.index < e.index for e in self.queries),
                    "actual hosted execution omitted checked parent-channel holder/target/issuer/derivation/rights/generation query")
        for (instance, execution), (admission, request_cap, reply_cap) in self.route_history.items():
            if (instance, execution) in self.aborted_routes:
                continue
            require(all(any(e.fields["cap"] == cap and e.fields["holder"] == holder and admission.index < e.index for e in self.queries)
                        for cap, holder in ((request_cap, execution), (reply_cap, 0x102))),
                    "admitted runtime route lacks actual current holder/target/issuer/derivation/rights/generation query in both directions")
        return self


class SourceLedger:
    """Named file lengths and owners, joined to actual independently replayed RAM."""
    def __init__(self, events, block):
        self.events, self.block = events, block
        self.handles, self.files = {}, {"/hello": {"base": 0, "length": len(host.PAYLOADS["/hello"]), "readonly": True}}
        self.history, self.reads, self.writes, self.opens = {}, [], [], []
        self.last_serial = 0

    def run(self):
        requests = [e for e in self.events if e.name == "storage-ipc" and e.fields.get("cell") in (2, 3) and e.fields.get("operation") in (10, 11, 12, 13)]
        require(len({(endpoint(e), e.fields["request"]) for e in requests}) == len(requests), "ordinary owner reused filesystem request identity")
        by_request = defaultdict(list)
        outcomes_by_key = defaultdict(list)
        for e in requests:
            by_request[(endpoint(e), e.fields["request"])].append(e)
        for e in self.events:
            if e.name == "storage-fs":
                outcomes_by_key[(e.fields["request"], e.fields["operation"])].append(e)
        for reply in [e for e in self.events if e.name == "storage-ipc" and e.fields.get("operation") == 14 and e.fields.get("cell") == 1]:
            answer = StoragePacket.from_event(reply)
            candidates = [e for e in by_request[(answer.target, answer.transaction)] if e.index < reply.index]
            require(len(candidates) == 1, "filesystem reply lacks exact independently authenticated owning request")
            request = candidates[0]
            packet = StoragePacket.from_event(request)
            require(packet.target == answer.sender == 0x102, "ordinary file owner changed filesystem generation")
            outcomes = [e for e in outcomes_by_key[(packet.transaction, packet.operation)] if request.index < e.index < reply.index]
            require(len(outcomes) == 1 and signed32(outcomes[0].fields["result"]) == answer.value,
                    "filesystem reply contradicts actual service applied outcome")
            transfers = [t for t in self.block.transfers_for(request) if t[3].index < outcomes[0].index]
            if packet.operation == 10:
                name = packet.open_name()
                if answer.value == 0:
                    require(name in ("/hello", "/alpha", "/beta") and answer.offset == 0 and not any(answer.data) and answer.handle not in self.handles and answer.handle >> 32 == 1,
                            "analysis owner opened unrelated filename or reused/stale handle")
                    serial = (answer.handle >> 8) & 0xFFFFFF
                    require(serial == self.last_serial + 1 and 1 <= answer.handle & 255 <= 8,
                            "file handle serial skipped/wrapped or changed typed placement")
                    self.last_serial = serial
                    if name not in self.files:
                        base = {"/alpha": 128, "/beta": 256}[name]
                        require(len(transfers) == 16 and [t[4].offset for t in transfers] == list(range(base, base + 128, 8)) and
                                all(t[4].operation == 8 and t[4].value == 8 and not any(t[4].data) for t in transfers),
                                "file publication lacks complete actual private-slot zero-before-open")
                        self.files[name] = dict(base=base, length=0, readonly=False)
                    else:
                        require(not transfers, "opening existing file rewrote its actual backing")
                    self.handles[answer.handle] = dict(owner=packet.sender, name=name, closed=False)
                    self.opens.append((request, reply, name))
            else:
                h = self.handles.get(packet.handle)
                if answer.value >= 0:
                    require(h and h["owner"] == packet.sender and not h["closed"] and answer.handle == packet.handle and answer.offset == packet.offset,
                            "ordinary operation used copied/closed/wrong-owner handle or changed extent")
                    file = self.files[h["name"]]
                    if packet.operation == 13:
                        require(answer.value == packet.offset == packet.value == 0 and not transfers, "close changed bytes or unbounded extent")
                        h["closed"] = True
                    else:
                        amount = packet.value if packet.operation == 12 else min(packet.value, max(0, file["length"] - packet.offset))
                        require(answer.value == amount and len(transfers) == 1, "file chunk omitted actual block crossing or changed captured count")
                        link, transfer, applied, block_reply, sent, got = transfers[0]
                        delivered = self.block.delivered_answers[(got.sender, got.transaction, got.target)][0]
                        require(request.index < link.index < transfer.index < applied.index < block_reply.index < delivered.index < outcomes[0].index < reply.index and
                                sent.offset == file["base"] + packet.offset and sent.value == amount and sent.operation == (8 if packet.operation == 12 else 7),
                                "file extent lacks exact coherent actual FS/block provenance")
                        if packet.operation == 12:
                            require(not file["readonly"] and packet.offset <= file["length"] and packet.offset + amount <= 128 and sent.data == packet.data,
                                    "file write changed owner bytes or escaped immutable/finite file scope")
                            file["length"] = max(file["length"], packet.offset + amount)
                            self.writes.append((request, reply, h["name"], packet.data[:amount]))
                        else:
                            require(answer.data == got.data, "ordinary file read bytes contradicted authoritative block reply")
                            self.reads.append((request, reply, h["name"], answer.data[:amount]))
            self.history[reply.index] = (dict((k, dict(v)) for k, v in self.handles.items()), dict((k, dict(v)) for k, v in self.files.items()))
        verified_by_key = defaultdict(list)
        for event in self.events:
            if event.name == "storage-verified":
                verified_by_key[(endpoint(event), event.fields["request"])].append(event)
        for key, markers in verified_by_key.items():
            matches = [(request, reply, data) for request, reply, name, data in self.reads if (endpoint(request), request.fields["request"]) == key]
            require(len(matches) == len(markers) == 1, "verified file marker invented/duplicated an owning actual read")
        for request, reply, name, data in self.reads:
            markers = verified_by_key[(endpoint(request), request.fields["request"])]
            for marker in markers:
                require(reply.index < marker.index and marker.fields["data"] == int.from_bytes(data.ljust(8, b"\0"), "little"),
                        "application verified marker contradicted authoritative owning FS/block read bytes")
        require({name for _, _, name in self.opens} == {"/hello", "/alpha", "/beta"}, "analysis omitted independent original three-file workload")
        return self

    def at(self, index):
        earlier = [at for at in self.history if at < index]
        require(earlier, "capture preceded actual source file handle publication")
        return self.history[max(earlier)]


@dataclasses.dataclass
class ImmutableInput:
    reference: tuple
    owner: int
    transaction: int
    handle: int
    filename: str
    block: int
    data: bytes
    publication: host.Event
    state: int = 2
    readers: set = dataclasses.field(default_factory=set)
    checker: int = 0
    retained: bool = True
    mutations: list = dataclasses.field(default_factory=list)
    reads: list = dataclasses.field(default_factory=list)
    release: host.Event | None = None


class Inputs:
    def __init__(self, events, kernel, source):
        self.events, self.kernel, self.source = events, kernel, source
        self.records, self.transactions, self.requests = {}, {}, {}
        self.reads, self.controls, self.releases, self.reaped = [], [], [], []
        self.inventories, self.retired_replays, self.creation_recoveries = [], [], []
        self.maximum, self.last_serial = 0, 0
        self.obligations = {}
        self.maximum_transaction = defaultdict(int)
        self.state_history = {}
        self.outcomes_by_key = defaultdict(list)
        self.owners = defaultdict(list)
        self.publications = defaultdict(list)
        for e in events:
            if e.name == "storage-fs":
                self.outcomes_by_key[(e.fields["request"], e.fields["operation"])].append(e)
            elif e.name == "snapshot-capture-owner":
                self.owners[(e.fields["value"], e.fields["extra"])].append(e)
            elif e.name == "snapshot-published":
                self.publications[(e.fields["value"], e.fields["extra"])].append(e)

    def at(self, index, reference):
        earlier = [at for at in self.state_history if at < index]
        return self.state_history[max(earlier)].get(reference) if earlier else None

    def run(self):
        enqueues = {e.index: SnapshotPacket.from_event(e) for e in self.kernel.snapshot_enqueued}
        deliveries = {e.index: SnapshotPacket.from_event(e) for e in self.kernel.snapshot_delivered}
        for event in self.events:
            packet = deliveries.get(event.index)
            if packet and packet.operation in (17, 18, 20):
                key = packet.sender, packet.transaction
                exact_create_replay = packet.operation == 17 and packet.tail[0] == 1 and key in self.requests and self.requests[key][1] == packet and key in self.transactions
                require(exact_create_replay or key not in self.requests and packet.transaction > self.maximum_transaction[packet.sender],
                        "snapshot client reused/reordered/wrapped an identity outside exact retained creation recovery")
                self.maximum_transaction[packet.sender] = max(self.maximum_transaction[packet.sender], packet.transaction)
                self.requests[key] = (event, packet)
            packet = enqueues.get(event.index)
            if not packet or packet.operation != 19:
                continue
            key = packet.target, packet.transaction
            require(key in self.requests, "snapshot reply lacks actual already-dequeued exact owner/reader request")
            request, incoming = self.requests[key]
            require(request.index < event.index and incoming.target == packet.sender == 0x102,
                    "snapshot reply changed authenticated filesystem/request owner generation")
            if packet.tail[7] == 1:
                action, peer = incoming.control()
                length, status, answered_action, state = packet.control_reply()
                require(action == answered_action, "snapshot authoritative control reply changed requested action")
                if action == 1 and status == 0:
                    reference = (packet.sender, packet.token)
                    _, serial, placement = snapshot_parts(*reference)
                    existing = self.transactions.get((incoming.sender, incoming.transaction))
                    if existing:
                        require(existing.retained and reference == existing.reference and incoming.token == existing.handle and length == len(existing.data) and state == existing.state and packet.word == existing.block,
                                "creation replay allocated another input or changed exact owning handle/captured extent")
                    else:
                        require(serial == self.last_serial + 1 and sum(r.retained for r in self.records.values()) < 2 and
                                not any(r.retained and (r.reference[1] & 255) == (packet.token & 255) for r in self.records.values()),
                                "snapshot identity/table allocation collided, skipped, or exceeded finite records")
                        handles, files = self.source.at(request.index)
                        source_handle = handles.get(incoming.token)
                        require(source_handle and source_handle["owner"] == incoming.sender and not source_handle["closed"],
                                "immutable capture lacks exact authenticated owner's actual existing live file handle")
                        filename = source_handle["name"]
                        file = files[filename]
                        require(length == file["length"] and packet.word == 0x101 and state == 2,
                                "snapshot publication changed actual coherent file length/dependency generation or state")
                        transfers = []
                        for link in self.source.block.links_by_request[incoming.transaction]:
                            if request.index < link.index < event.index:
                                found = self.source.block.transfers.get((endpoint(link), link.fields["block_request"]))
                                if found and found[3].operation == 7 and request.index < found[0].index < found[2].index < self.source.block.delivered_answers[(found[4].sender, found[4].transaction, found[4].target)][0].index < event.index:
                                    transfers.append(found)
                        require(len(transfers) == (length + 7) // 8 and
                                [t[3].offset for t in transfers] == [file["base"] + i for i in range(0, length, 8)] and
                                [t[3].value for t in transfers] == [min(8, length - i) for i in range(0, length, 8)],
                                "immutable capture omitted/reordered/duplicated actual bounded FS/block chunks")
                        captured = b"".join(t[4].data[:t[4].value] for t in transfers)
                        require(len(captured) == length, "immutable capture retained a partial prefix")
                        require(not any(t[0].index > request.index and t[2].index < event.index and t[3].operation == 8 and
                                        file["base"] <= t[3].offset < file["base"] + 128 for t in self.source.block.transfers.values()),
                                "immutable publication interleaved source writes across its finite capture barrier")
                        record = ImmutableInput(reference, incoming.sender, incoming.transaction, incoming.token, filename, packet.word, captured, event)
                        owners = [e for e in self.owners[(incoming.sender, incoming.transaction)] if request.index < e.index < event.index]
                        published = [e for e in self.publications[(packet.token, length)] if request.index < e.index < event.index]
                        require(len(owners) == len(published) == 1 and endpoint(owners[0]) == endpoint(published[0]) == 0x102, "snapshot provenance/publication reports contradicted actual authenticated capture")
                        self.records[reference] = record
                        self.transactions[(incoming.sender, incoming.transaction)] = record
                        self.last_serial = serial
                        self.maximum = max(self.maximum, sum(r.retained for r in self.records.values()))
                elif action == 8:
                    require(incoming.sender == 0x104 and incoming.token == 1 and peer == 0 and status == 0 and state == 0 and packet.word == 0x101 and packet.token >> 32 == 0,
                            "input inventory query changed configured owner/action/current dependency or reserved fields")
                    retained = sum(r.retained for r in self.records.values())
                    backing = 128 * sum(r.retained and r.state == 2 for r in self.records.values())
                    readers = sum(len(r.readers) for r in self.records.values() if r.retained)
                    live = sum(r.retained and r.state == 2 for r in self.records.values())
                    require(packet.token == retained | backing << 8 | readers << 24 and length == live,
                            "authoritative input inventory contradicted independently reconstructed actual retained records/byte backing/readers")
                    self.inventories.append((request, event, packet))
                elif status == 0:
                    reference = (packet.sender, incoming.token if action == 6 else packet.token)
                    require(reference in self.records, "snapshot control revived unknown object identity")
                    record = self.records[reference]
                    require(record.retained and incoming.sender == record.owner and (incoming.token == record.reference[1] if action != 2 else incoming.token == record.transaction),
                            "snapshot control changed exact owner/serial scope")
                    require((length, packet.word, packet.token) == ((0, 0, 0) if action == 6 else (len(record.data), record.block, record.reference[1])), "authoritative snapshot metadata contradicted retained input")
                    if action in (3, 7):
                        earlier = [at for at in self.kernel.capability_states if at < request.index]
                        grants = self.kernel.capability_states[max(earlier)] if earlier else {}
                        require(any(grant == (0x102, peer, 1 << 18) for grant in grants.values()),
                                "filesystem binding admitted a guessed future/stale reader without actual current checked reply route")
                        require(record.state == 2 and peer not in (0, record.owner) and len(record.readers | {peer}) <= 2, "snapshot bind exceeded exact live object/two-reader owner scope")
                        record.readers.add(peer)
                        if action == 7:
                            require(record.checker in (0, peer), "checker grant retargeted live existing release authority")
                            record.checker = peer
                    elif action == 4:
                        record.readers.discard(peer)
                        if record.checker == peer:
                            record.checker = 0
                    elif action == 5:
                        record.readers.clear()
                        if record.state != 5:
                            record.state = 3
                        if record.release is None:
                            record.release = event
                    elif action == 6:
                        require(record.state in (3, 4, 5) and not record.readers, "snapshot metadata reaped before actual input authority/backing retirement")
                        record.retained = False
                        self.reaped.append((event, record))
                    require(state == (0 if action == 6 else record.state), "authoritative control state contradicted independently reconstructed lifetime")
                else:
                    require(status < 0, "snapshot failed control returned invalid success-like status")
                    if state == 0:
                        require(packet.token == packet.word == length == 0, "failed control invented or leaked unrelated input metadata")
                if action == 8:
                    inventories = [e for e in self.events if e.name == "snapshot-inventory" and request.index < e.index < event.index]
                    require(len(inventories) == 1 and inventories[0].fields.get("value") == packet.token and inventories[0].fields.get("extra") == length,
                            "snapshot inventory reply contradicts actual service-owned inventory report")
                else:
                    outcomes = [e for e in self.outcomes_by_key[(incoming.transaction, 17)] if request.index < e.index < event.index]
                    require(len(outcomes) == 1 and signed32(outcomes[0].fields["result"]) == status, "snapshot control raw reply contradicts actual dispatcher result")
                self.controls.append((request, event, incoming, packet, status))
            else:
                issuer, offset, count = incoming.read()
                actual_offset, amount, status, data = packet.read_reply()
                reference = issuer, incoming.token
                require(packet.token == incoming.token and actual_offset == offset and amount <= count,
                        "snapshot read reply changed exact requested object/offset/count")
                record = self.records.get(reference)
                outcomes = [e for e in self.outcomes_by_key[(incoming.transaction, incoming.operation)] if request.index < e.index < event.index]
                require(len(outcomes) == 1 and signed32(outcomes[0].fields["result"]) == (amount if status == 0 else status), "snapshot read/release reply contradicts actual dispatcher result")
                if status == 0:
                    require(record and record.retained and issuer == packet.sender and ((incoming.operation == 20 and record.state == 5) or
                            (record.state == 2 and (incoming.sender == record.owner or incoming.sender in record.readers))),
                            "successful snapshot read lacks exact live owner/reader/current issuer binding")
                    if incoming.operation == 20:
                        peer = int.from_bytes(incoming.tail, "little")
                        require(incoming.sender == record.checker and amount == 0 and not data and
                                (not peer or (peer in record.readers and peer not in (record.owner, record.checker))),
                                "input release did not use exact separately granted checker scope")
                        record.state, record.readers, record.release = 5, set(), event
                        self.releases.append((request, event, record))
                    else:
                        require(offset <= 128 and amount == min(count, max(0, len(record.data) - offset)) and
                                data == record.data[offset:offset + amount], "snapshot chunk changed captured bytes/extent/EOF after source mutation")
                        item = request, event, incoming, data, record
                        record.reads.append(item)
                        self.reads.append(item)
                else:
                    require(status in (-1, -2, -3, -4, -6, -7, -8) and not data and amount == 0,
                            "failed snapshot read leaked captured bytes")
            self.state_history[event.index] = {key: (r.state, set(r.readers), r.checker, r.retained) for key, r in self.records.items()}
        require(self.records and self.maximum <= 2 and all(not r.retained and not r.readers and r.release is not None for r in self.records.values()),
                "analysis ended with hidden immutable backing/reader/input metadata or omitted capture")
        require(self.inventories and self.inventories[-1][2].token == 0 and self.inventories[-1][2].tail[0] == 0,
                "analysis completion omitted actual final filesystem-owned input inventory query")
        for request, reply, incoming, answered, status in self.controls:
            if status == 0 and incoming.tail[0] in (3, 7):
                markers = [e for e in self.events if e.name == "analysis-reader-bound" and endpoint(e) == incoming.sender and
                           e.fields["value"] == incoming.token and e.fields["extra"] == incoming.word and reply.index < e.index]
                require(len(markers) == 1, "successful current input binding omitted or duplicated owner-visible exact binding report")
            if status == 0 and incoming.tail[0] == 6:
                markers = [e for e in self.events if e.name == "analysis-input-reaped" and endpoint(e) == incoming.sender and
                           e.fields["value"] == incoming.token and reply.index < e.index]
                require(len(markers) == 1, "successful input metadata reap omitted or duplicated owner-visible retirement report")
        for e in self.events:
            if e.name == "snapshot-retired-transaction":
                owner, transaction, predecessor = endpoint(e), e.fields["value"], e.fields["extra"]
                original = self.transactions.get((owner, transaction))
                replies = [item for item in self.controls if item[2].sender == owner and item[2].transaction == transaction and
                           item[2].tail[0] == 1 and item[1].index < e.index and item[4] == -3]
                require(original and not original.retained and predecessor == original.reference[1] and replies and replies[-1][1].index >
                        next(reaped[0].index for reaped in self.reaped if reaped[1] is original),
                        "retired creation replay allocated/aliased new input or lacks actual owner-scoped stale transaction reply")
                self.retired_replays.append(e)
            if e.name == "snapshot-reply-lost":
                owner, transaction, recovered = endpoint(e), e.fields["value"], e.fields["extra"]
                record = self.transactions.get((owner, transaction))
                queries = [item for item in self.controls if item[2].sender == owner and item[2].tail[0] == 2 and item[2].token == transaction and
                           item[3].token == recovered and item[4] == 0 and item[1].index < e.index]
                require(record and record.reference[1] == recovered and len(queries) == 1,
                        "lost capture reply recovery substituted input or allocated another snapshot")
                self.creation_recoveries.append(e)
        require(len(self.creation_recoveries) == 1, "analysis omitted actual lost creation reply recovery by original owner transaction")
        require(len(self.retired_replays) == 1, "analysis omitted actual owner-scoped retired creation replay rejection")
        return self


@dataclasses.dataclass
class ByteObligation(scalar.Obligation):
    input_issuer: int = 0
    input_length: int = 0
    newlines: int = 0
    tuples: dict = dataclasses.field(default_factory=dict)
    descriptors: dict = dataclasses.field(default_factory=dict)
    notices: list = dataclasses.field(default_factory=list)
    authorizations: list = dataclasses.field(default_factory=list)
    validated_tuple: tuple | None = None
    count_validation: host.Event | None = None
    requester_counts: list = dataclasses.field(default_factory=list)

    def snapshot(self):
        return (*super().snapshot(), self.input_issuer, self.input_length | self.newlines << 16)


class Contracts:
    def __init__(self, events, kernel, inputs):
        self.events, self.kernel, self.inputs = events, kernel, inputs
        self.records, self.live, self.offer_keys = {}, {}, {}
        self.highwater, self.last_serial = defaultdict(int), 0
        self.maximum, self.snapshots, self.groups = 0, [], {}
        self.computations, self.worker_count_reports, self.tuple_stages, self.receipt_checks = {}, {}, {}, []
        self.errors, self.lost, self.deferred, self.late = [], [], {}, []
        self.bootstrap = {}
        self.staged_ready, self.stage_releases = {}, {}
        self.state_history = {}
        self.packets = kernel.packet_events

    def broker(self):
        matches = [n for n in self.kernel.tree.nodes.values() if n.template == 5]
        require(len(matches) == 1, "analysis composition lacks exactly one actual runtime broker")
        return matches[0]

    def record(self, token, retained=True):
        require(token in self.records and (not retained or self.records[token].retained), "analysis revived unknown/reaped contract token")
        return self.records[token]

    def prior(self, predicate, before, after=-1):
        return [e for e in self.events if after < e.index < before and predicate(e)]

    def request_error(self, p):
        if p.sender != 0x104 or p.target != self.broker().endpoint:
            return 1
        if p.command == 1:
            if p.kind != 0 or p.detail != 2 or not p.token or not p.data:
                return 2
            r = self.offer_keys.get((p.sender, p.request))
            if r:
                return 0 if r.retained and (r.input_issuer, r.input) == (p.token, p.data) else 2 if r.retained else 3
            if p.request <= self.highwater[p.sender]:
                return 3
            if len(self.live) == 2:
                return 4
            input_ = self.inputs.records.get((p.token, p.data))
            return 0 if input_ and input_.owner == p.sender else 3
        if p.command == 3 and p.token == 0:
            r = self.offer_keys.get((p.sender, p.data))
            return 0 if p.detail == 0 and r and r.retained else 3
        try:
            scalar.token_parts(p.token)
        except AssertionError:
            return 2
        r = self.records.get(p.token)
        if not r or not r.retained or p.token >> 32 != p.target:
            return 3
        if p.command == 15 and p.detail == 0:
            return 0 if p.kind == 0 and p.data == r.rpc and r.state == 2 and p.token in self.staged_ready else 10
        if p.command in (2, 15):
            if p.detail != 2 or p.data != r.input:
                return 2
            return 0 if r.state in (1, 2, 3, 4) else 10
        if p.command in (3, 4, 5, 6):
            if p.kind != 0 or p.detail or p.data:
                return 2
            if p.command in (5, 6) and r.state not in scalar.TERMINAL:
                return 9
            return 0
        return 2

    def collection(self, reader, record, before, after):
        """Each computation names one complete ordered collection and exact EOF."""
        reads = [item for item in self.inputs.reads if item[2].sender == reader and item[4].reference == (record.input_issuer, record.input) and
                 after < item[0].index < item[1].index < before]
        require(reads, "analysis result lacks independently authenticated captured-byte collection")
        streams, current, offset = [], [], 0
        for item in reads:
            request, reply, packet, data, input_ = item
            issuer, actual_offset, count = packet.read()
            require(actual_offset == offset and count == (8 if reader == record.issuer or offset == len(input_.data) else min(8, len(input_.data) - offset)),
                    "analysis input collection has a gap/overlap/changed count or missing exact EOF")
            current.append(item)
            if offset == len(input_.data):
                require(not data, "analysis EOF supplied undeclared bytes")
                streams.append(current)
                current, offset = [], 0
            else:
                offset += len(data)
        require(not current and streams, "analysis computed from partial prefix or omitted exact EOF")
        stream = streams[-1]
        for request, reply, packet, chunk, input_ in stream:
            answer = SnapshotPacket.from_event(reply)
            require(any(SnapshotPacket.from_event(delivery) == answer and reply.index < delivery.index < before
                        for delivery in self.kernel.snapshot_delivered), "analysis consumed snapshot bytes that were enqueued but never actually delivered")
        captured = b"".join(item[3] for item in stream)
        require(captured == self.inputs.records[(record.input_issuer, record.input)].data and len(captured) == record.input_length,
                "analysis consumed a different snapshot identity or captured length")
        return captured, stream

    def progress(self, event):
        f = event.fields
        token, value = event.need("value", "extra")
        endpoint_ = endpoint(event)
        if event.name == "contract-reply-lost":
            require(endpoint_ == 0x104 and value in (1, 5), "analysis loss marker names wrong owner/command")
            responses = [item for item in self.snapshots if item[2].request == token and item[2].command == value and item[1].index < event.index]
            require(len(responses) == 1, "lost reply marker lacks actual complete authoritative original response")
            packets = [p for e in self.kernel.delivered if e.index < event.index and
                       (p := self.packets[e.index]).request == token and p.command == value and p.kind == 2]
            require([p.detail for p in packets] == list(range(10)), "lost reply lacked ten actual authenticated delivered parts")
            self.lost.append((event, responses[0]))
            return
        if event.name in ("contract-requester-verified", "analysis-requester-counts"):
            r = self.record(token)
            expected = calculate(self.inputs.records[(r.input_issuer, r.input)].data)
            require(endpoint_ == r.owner and r.state == 4 and r.verified and
                    value == (expected[2] if event.name == "contract-requester-verified" else expected[0] | expected[1] << 16),
                    "requester accepted wrong length/newline/digest or unverified terminal result")
            if event.name == "contract-requester-verified":
                responses = [item for item in self.snapshots if item[2].token == token and item[2].command in (3, 5) and
                             r.terminal.index < item[0].index < item[1].index < event.index]
                require(responses and all(any(self.packets.get(delivery.index) == self.packets.get(enqueue.index) and
                                            enqueue.index < delivery.index < event.index for delivery in self.kernel.delivered)
                                          for enqueue in self.kernel.enqueued if responses[-1][0].index <= enqueue.index <= responses[-1][1].index),
                        "requester accepted receipt without full actual authoritative delivery")
                self.collection(r.owner, r, r.terminal.index, self.inputs.records[(r.input_issuer, r.input)].publication.index)
                r.requester_checks.append(event)
                self.receipt_checks.append(event)
            else:
                require(r.requester_checks and r.requester_checks[-1].index < event.index and not r.requester_counts,
                        "requester counters omitted or duplicated the same fully delivered verified receipt")
                r.requester_counts.append(event)
            return
        if event.name == "contract-offer":
            slot, serial, issuer = scalar.token_parts(token)
            require(issuer == endpoint_ == self.broker().endpoint and serial == self.last_serial + 1 and slot not in self.live and len(self.live) < 2,
                    "analysis offer reused/wrapped identity or exceeded finite broker records")
            incoming = self.prior(lambda e: e.name == "host-ipc-deliver" and (p := self.packets[e.index]).operation == 15 and
                                  p.command == 1 and p.kind == 0 and p.sender == 0x104 and p.target == issuer and p.request == value and p.detail == 2,
                                  event.index)
            require(incoming, "analysis offer lacks exact authenticated requester/profile/input request")
            sent = incoming[-1]
            p = self.packets[sent.index]
            require((p.sender, p.request) not in self.offer_keys, "duplicate analysis offer allocated another worker")
            input_ = self.inputs.records.get((p.token, p.data))
            live_input = self.inputs.at(sent.index, (p.token, p.data))
            require(input_ and input_.publication.index < sent.index and input_.owner == p.sender and live_input and
                    live_input[0] == 2 and live_input[3] and live_input[2] == issuer and issuer in live_input[1],
                    "analysis offered stale/reaped/revoked/substituted input or wrong owner/current checker binding")
            children = [n for n in self.kernel.tree.nodes.values() if n.template == 6 and n.parent_instance == self.broker().instance and
                        sent.index < n.born < event.index and all(r.worker.instance != n.instance for r in self.records.values())]
            require(len(children) == 1, "analysis offer lacks one actual newly allocated broker-backed worker")
            worker = children[0]
            published = self.prior(lambda e: e.name == "host-publish" and e.fields["instance"] == worker.instance, event.index)[-1]
            execution = published.fields["endpoint"]
            require(execution in worker.entered and execution in self.bootstrap and self.bootstrap[execution].index < event.index and
                    (worker.instance, execution) in self.kernel.route_history,
                    "analysis offer published before actual ring3/bootstrap and complete checked storage admission")
            status = self.prior(lambda e: e.name == "host-status" and e.fields["instance"] == worker.instance and e.fields["caller_endpoint"] == issuer and
                                e.fields["endpoint"] == execution and e.fields["phase"] == 1 and e.fields["pages"] == 2,
                                event.index, published.index)
            require(status, "analysis backed offer lacks actual current-generation two-page worker status query")
            r = ByteObligation(issuer, token, p.sender, p.request, 2, p.data, worker, event.index,
                               execution=execution, input_issuer=p.token, input_length=len(input_.data))
            self.collection(issuer, r, worker.born, sent.index)
            r.initial_reports.add(event.name)
            self.records[token], self.live[slot], self.offer_keys[(p.sender, p.request)] = r, r, r
            self.highwater[p.sender], self.last_serial = p.request, serial
            self.maximum = max(self.maximum, len(self.live))
            return
        r = self.record(token, retained=event.name != "contract-late-rejected")
        require(endpoint_ == r.issuer, "analysis service progress used unrelated broker endpoint")
        if event.name in ("contract-input", "contract-worker", "contract-control", "contract-endpoint", "analysis-input-issuer", "analysis-input-length"):
            expected = {"contract-input": r.input, "contract-worker": r.worker.instance, "contract-control": r.worker.control,
                        "contract-endpoint": r.execution, "analysis-input-issuer": r.input_issuer, "analysis-input-length": r.input_length}[event.name]
            require(r.state == 1 and value == expected and event.name not in r.initial_reports, "analysis offered binding omitted/changed exact input/worker/capture identity")
            r.initial_reports.add(event.name)
        elif event.name == "contract-accepted":
            accepts = self.prior(lambda e: e.name == "host-ipc-deliver" and (p := self.packets[e.index]).sender == r.owner and p.target == r.issuer and
                                 p.operation == 15 and p.command in (2, 15) and p.kind == 0 and p.detail == 2 and p.token == r.token and p.data == r.input,
                                 event.index, r.born)
            require(r.state == 1 and value == r.input and len(r.initial_reports) == 7 and accepts,
                    "analysis started without explicit exact owner acceptance and full backed immutable offer")
            live_input = self.inputs.at(accepts[-1].index, (r.input_issuer, r.input))
            require(live_input and live_input[0] == 2 and live_input[3] and live_input[2] == r.issuer and r.issuer in live_input[1],
                    "analysis accepted input after owner/service/checker retirement")
            descriptors = self.prior(lambda e: e.name == "host-ipc-enqueue" and (p := self.packets[e.index]).sender == r.issuer and p.target == r.execution and
                                     p.command == 10 and p.token == r.token, event.index, accepts[-1].index)
            require(descriptors, "analysis acceptance omitted full-issuer descriptor after liveness checking")
            self.collection(r.issuer, r, descriptors[0].index, accepts[-1].index)
            require(not any(item[2].sender == r.execution and item[4].reference == (r.input_issuer, r.input) and item[0].index < event.index for item in self.inputs.reads),
                    "worker read captured input before explicit acceptance")
            r.state, r.attempt, r.accepted = 2, 1, event
        elif event.name == "contract-dispatch":
            require(r.state == 2 and value > 0 and value not in r.dispatch_reports, "analysis dispatched duplicate/terminal/preaccept work")
            r.rpc = value
            r.dispatch_reports[value] = event
        elif event.name == "contract-attempt":
            require(r.state == 2 and value == r.attempt and value not in r.attempted and value in (1, 2), "analysis attempt changed or exceeded one retry")
            r.attempted.add(value)
        elif event.name in ("contract-validated", "analysis-broker-counts"):
            expected = calculate(self.inputs.records[(r.input_issuer, r.input)].data)
            require(r.state == 2 and value == (expected[2] if event.name == "contract-validated" else expected[0] | expected[1] << 16),
                    "independent broker accepted wrong full result tuple")
            if event.name == "contract-validated":
                require(r.validation is None and (r.execution, r.rpc) in r.tuples and token in self.deferred and self.deferred[token].index < event.index and self.deferred[token].fields["extra"] == r.rpc, "broker repeated validation or lacks complete authenticated current worker tuple")
                reply = r.tuples[(r.execution, r.rpc)][1]
                delivered = self.prior(lambda e: e.name == "host-ipc-deliver" and self.packets[e.index] == reply, event.index)
                require(delivered, "broker verified enqueued but undelivered result")
                self.collection(r.issuer, r, event.index, delivered[-1].index)
                samples = self.prior(lambda e: e.name == "host-call" and e.fields["call"] == 14 and e.fields["result"] == 0 and
                                     e.fields.get("output_control") == r.worker.control and e.fields.get("output_phase") == 1,
                                     event.index, delivered[-1].index)
                require(samples, "analysis candidate admission lacks exact actual current-worker lifecycle status")
                r.admission_status = samples[-1]
                r.admission_stamp = tuple(samples[-1].fields["output_" + key] for key in ("generation", "faults", "restarts"))
                require(r.admission_stamp[0] == r.execution >> 8 and r.admission_stamp[1] < 0xFFFFFFFF, "analysis admitted stale/exhausted lifecycle generation")
                r.validation, r.validated_tuple = event, expected
            else:
                require(r.validation and r.validation.index < event.index and r.count_validation is None,
                        "broker counters omitted or duplicated the same admitted full tuple")
                r.count_validation = event
        elif event.name == "contract-recovering":
            faults = self.prior(lambda e: e.name == "host-fault" and e.fields["instance"] == r.worker.instance and e.fields["endpoint"] == r.execution, event.index)
            require(r.state == 2 and r.attempt == 1 and r.retries == 0 and value == r.execution and faults,
                    "analysis recovery lacked accepted real fault or exceeded one retry")
            r.state = 3
            r.faults.append(faults[-1])
        elif event.name == "contract-rebound":
            rebound = self.prior(lambda e: e.name == "host-rebind" and e.fields["instance"] == r.worker.instance and e.fields["endpoint"] == value and
                                 e.fields.get("parent_rights") == 1 << 14, event.index)
            require(r.state == 3 and r.retries == 0 and value != r.execution and rebound and
                    (r.worker.instance, value) in self.kernel.route_history and r.authorizations and
                    r.authorizations[-1][1].data == value, "analysis retry silently inherited predecessor storage/input authority")
            r.state, r.retries, r.attempt, r.execution = 2, 1, 2, value
            r.rebinds.append(event)
        elif event.name == "contract-terminal":
            flags = tuple((value >> (i * 8)) & 255 for i in range(7)) + ((value >> 56) & 1,)
            require(value >> 57 == 0 and flags[0] in scalar.TERMINAL and r.state not in scalar.TERMINAL and
                    flags[1:4] == (2, r.retries, r.attempt) and flags[5:7] == (0, 0), "analysis terminal raw flags contradict retained profile/attempt/resources")
            stop = self.prior(lambda e: e.name == "host-stop" and e.fields["instance"] == r.worker.instance, event.index)
            reap = self.prior(lambda e: e.name == "host-reap" and e.fields["instance"] == r.worker.instance, event.index)
            returned = self.prior(lambda e: e.name == "host-return" and e.fields["instance"] == r.worker.instance and e.fields["retired_pages"] == 2, event.index)
            require(len(stop) == len(reap) == len(returned) == 1 and stop[0].index < returned[0].index < reap[0].index,
                    "analysis terminal preceded actual checked worker stop/two-page refund/reap")
            input_ = self.inputs.records[(r.input_issuer, r.input)]
            releases = [item for item in self.inputs.releases if item[2] is input_ and item[0].index > r.born and item[1].index < stop[0].index and
                        SnapshotPacket.from_event(item[0]).sender == r.issuer]
            release_markers = self.prior(lambda e: e.name == "analysis-input-released" and e.fields.get("value") == r.token and e.fields.get("extra") == r.input,
                                         stop[0].index, input_.release.index if input_.release else r.born)
            require(input_.release and len(releases) == len(release_markers) == 1 and r.born < input_.release.index < stop[0].index,
                    "analysis terminal reused historical cleanup or preceded actual temporary input-reader/backing retirement")
            if flags[0] == 4:
                require(r.validated_tuple is not None, "success omitted admitted full tuple")
                r.result, r.newlines, r.verified = r.validated_tuple[2], r.validated_tuple[1], True
                require(r.validation and r.count_validation and r.validation.index < r.count_validation.index < input_.release.index and flags[4] == 0 and flags[7] == 1,
                        "analysis success lacked independent full tuple validation before input/worker settlement")
                release_request = next(item[0] for item in self.inputs.releases if item[2] is input_)
                release_packet = SnapshotPacket.from_event(release_request)
                require(int.from_bytes(release_packet.tail, "little") == r.execution, "successful input settlement omitted current-attempt worker binding")
                stopped = self.prior(lambda e: e.name == "host-call" and e.fields["call"] == 14 and e.fields["result"] == 0 and
                                     e.fields.get("output_control") == r.worker.control and e.fields.get("output_phase") == 4,
                                     reap[0].index, stop[0].index)
                require(stopped and all(tuple(e.fields["output_" + key] for key in ("generation", "faults", "restarts")) == r.admission_stamp for e in stopped),
                        "analysis success crossed generation/fault/restart retirement fence")
            elif flags[0] == 5:
                r.result, r.newlines, r.verified = 0, 0, False
                cancels = self.prior(lambda e: e.name == "host-ipc-deliver" and (p := self.packets[e.index]).sender == r.owner and p.target == r.issuer and
                                    p.operation == 15 and p.command == 4 and p.token == r.token, event.index)
                require(cancels and flags[4] == 1 and flags[7] == 0 and not r.verified, "analysis cancellation lacked actual owner consent or resurrected a candidate")
            else:
                r.result, r.newlines, r.verified = 0, 0, False
                require(2 <= flags[4] <= 8 and flags[7] == 0, "analysis failure retained successful receipt")
            r.state, r.reason, r.terminal = flags[0], flags[4], event
            require(r.flags() == flags, "authoritative terminal flags contradict full independently reconstructed obligation")
        elif event.name == "contract-reaped":
            slot, serial, _ = scalar.token_parts(token)
            requests = self.prior(lambda e: e.name == "host-ipc-deliver" and (p := self.packets[e.index]).sender == r.owner and p.target == r.issuer and
                                  p.operation == 15 and p.command == 6 and p.token == token, event.index, r.terminal.index if r.terminal else -1)
            require(r.state in scalar.TERMINAL and value == serial and requests and self.live.get(slot) is r,
                    "analysis contract record freed without terminal retention/authenticated explicit reap")
            r.retained = False
            del self.live[slot]
        elif event.name == "contract-deferred":
            require(r.state == 2 and value == r.rpc and token not in self.deferred and (r.execution, r.rpc) in r.tuples,
                    "private analysis staging overwrote/misattributed a tuple")
            tuple_ = r.tuples[(r.execution, r.rpc)]
            require(all(any(self.packets[delivery.index] == packet and delivery.index < event.index for delivery in self.kernel.delivered)
                        for packet in tuple_[:2]), "private staging marker omitted actual already-dequeued full worker tuple")
            self.deferred[token] = event
        elif event.name == "contract-late-rejected":
            require(token in self.deferred and self.deferred[token].index < event.index and value == self.deferred[token].fields["extra"] and r.state in (3, 5, 6),
                    "late privately held result completed a cancelled/recovering obligation")
            if r.state in (5, 6):
                require(r.terminal and self.deferred[token].index < r.terminal.index < event.index, "late cancellation rejection preceded actual committed terminal cleanup")
            self.late.append(event)
        elif event.name == "analysis-input-released":
            input_ = self.inputs.records[(r.input_issuer, r.input)]
            require(value == r.input and input_.release and input_.release.index < event.index,
                    "input cleanup marker hid missing actual object-authority retirement")

    def sent(self, event, p):
        if p.operation == 15 and p.command in (7, 10, 12) and p.sender == self.broker().endpoint:
            r = self.record(p.token)
            if p.command in (10, 12):
                accepts = self.prior(lambda e: e.name == "host-ipc-deliver" and (q := self.packets[e.index]).sender == r.owner and q.target == r.issuer and
                                     q.command in (2, 15) and q.operation == 15 and q.kind == 0 and q.detail == 2 and q.token == r.token and q.data == r.input,
                                     event.index, r.born)
                require(accepts and p.request > 0 and p.detail == (1 if r.state == 1 else r.attempt) and r.state in (1, 2),
                        "input descriptor preceded actual explicit exact acceptance/current attempt")
                if p.detail == 2:
                    require(r.authorizations and r.authorizations[-1][1].data == p.target, "retry descriptor omitted explicit current-endpoint owner authorization")
            else:
                require(r.state == 2 and r.accepted and r.accepted.index < event.index and p.detail == r.attempt and p.request == r.rpc and p.request in r.dispatch_reports and r.attempt in r.attempted,
                        "analysis work dispatch changed accepted current attempt/rpc or ran before consent")
            require(p.target == r.execution and p.sender == r.issuer and p.kind == 0,
                    "analysis descriptor changed exact current worker/broker scope")
            descriptor = r.descriptors.setdefault(p.request, [])
            require(p.command == (10, 12, 7)[len(descriptor)] if len(descriptor) < 3 else False,
                    "analysis worker descriptor has duplicate/reordered/missing full issuer/length/input")
            if p.command == 10:
                require(p.data == r.input_issuer, "analysis worker descriptor replaced full filesystem generation")
            elif p.command == 12:
                require(p.data >> 25 == 0 and p.data & 0xFFFF == r.input_length and (p.data >> 16 & 255) <= 32,
                        "analysis worker descriptor changed captured length or unbounded delay")
            else:
                require(p.data == r.input, "analysis worker descriptor changed immutable input token")
                r.dispatches[p.request] = event, p
            descriptor.append((event, p))
        elif p.operation == 16 and p.command in (7, 11):
            r = self.record(p.token)
            require(p.sender == r.execution and p.target == r.issuer and p.request == r.rpc and p.detail == r.attempt and p.kind == 1 and r.state == 2,
                    "worker result changed current accepted attempt/rpc/execution/contract")
            key = p.sender, p.request, p.token, p.detail
            if p.command == 7:
                require(key not in self.tuple_stages and (p.sender, p.request) in self.computations and (p.sender, p.request) in self.worker_count_reports, "worker digest omitted actual ring3 computation or duplicated candidate")
                require(p.data == self.computations[(p.sender, p.request)][1][2], "worker raw digest contradicted reconstructed captured bytes")
                self.tuple_stages[key] = event, p
            else:
                require(key in self.tuple_stages and p.data >> 32 == 0, "worker counters arrived before digest or contain reserved bits")
                digest_event, digest = self.tuple_stages.pop(key)
                expected = calculate(self.inputs.records[(r.input_issuer, r.input)].data)
                require(p.data == expected[0] | expected[1] << 16, "worker raw length/newline result contradicted actual captured bytes")
                r.tuples[(p.sender, p.request)] = digest, p, digest_event, event
        elif p.operation == 15 and p.command == 15:
            r = self.record(p.token)
            require(p.sender == r.owner and p.target == r.issuer and p.kind == 0 and p.detail in (0, 2),
                    "staging control changed exact authenticated owner/issuer/shape")
            if p.detail == 2:
                require(r.state == 1 and p.data == r.input, "staged acceptance changed offered immutable input or reused live attempt")
            else:
                require(r.state == 2 and p.token in self.staged_ready and p.data == r.rpc and p.token not in self.stage_releases,
                        "staging release preceded full readiness or changed current RPC/scope")
                self.stage_releases[p.token] = event
        elif p.operation == 16 and (p.command in range(1, 7) or p.command == 15):
            requests = self.prior(lambda e: e.name == "host-ipc-deliver" and (q := self.packets[e.index]).sender == p.target and q.target == p.sender and
                                  q.request == p.request and q.command == p.command and q.operation == 15, event.index)
            require(requests and p.sender == self.broker().endpoint and p.target == 0x104, "broker authoritative reply changed requester/transaction scope")
            request = self.packets[requests[-1].index]
            if p.kind == 3:
                require(p.detail == 0 and p.token == request.token and p.data == self.request_error(request),
                        "authoritative broker denial contradicted exact owner/input/state")
                self.errors.append(event)
            elif p.kind == 2:
                r = self.record(p.token)
                require(self.request_error(request) == 0 and (request.token == r.token if request.command != 1 and request.token else
                                                            r.offer_request == (request.request if request.command == 1 else request.data)),
                        "authoritative analysis snapshot answered wrong obligation/input generation")
                key = p.sender, p.target, p.request, p.command, p.token
                if p.detail == 0:
                    if p.command == 15:
                        require(r.state == 2 and p.token in self.deferred and self.deferred[p.token].index < event.index and
                                (r.execution, r.rpc) in r.tuples, "staging acknowledgment preceded full authenticated held tuple/current running scope")
                        if request.detail == 0:
                            require(p.token in self.staged_ready and p.token in self.stage_releases and request.data == r.rpc,
                                    "staging release acknowledgment changed exact ready gate")
                        else:
                            require(request.detail == 2 and request.data == r.input, "staging readiness answered a different input/request shape")
                    require(key not in self.groups, "authoritative snapshot restarted/duplicated part0")
                    self.groups[key] = [0, r.snapshot(), event]
                require(key in self.groups and p.detail == self.groups[key][0] and p.detail < 10 and p.data == self.groups[key][1][p.detail],
                        "authoritative snapshot raw fields contradict length/newline/input/worker/attempt/result/charges")
                self.groups[key][0] += 1
                if self.groups[key][0] == 10:
                    self.snapshots.append((self.groups[key][2], event, p, self.groups[key][1]))
                    if p.command == 15 and request.detail == 2:
                        self.staged_ready[p.token] = (requests[-1], self.groups[key][2], event, self.groups[key][1])
                    del self.groups[key]
            else:
                require(p.kind == 1 and p.command == 6 and p.detail == 0 and p.data == 0 and
                        p.token == request.token and not self.record(p.token, False).retained,
                        "broker acknowledged record reap before actual release")
        elif p.command == 13:
            r = self.record(p.token)
            require(p.operation == 16 and p.sender == r.issuer and p.target == r.owner and r.state == 3 and p.data != r.execution,
                    "retry notice changed exact owner/current recovering obligation")
            r.notices.append((event, p))
        elif p.command == 14:
            r = self.record(p.token)
            require(p.operation == 15 and p.sender == r.owner and p.target == r.issuer and r.state == 3 and r.notices and
                    (p.request, p.data, p.token) == (r.notices[-1][1].request, r.notices[-1][1].data, r.token),
                    "retry authorization lacked explicit exact current-endpoint owner response")
            bind = [item for item in self.inputs.controls if item[2].tail[0] == 3 and item[2].token == r.input and item[2].word == p.data and
                    item[4] == 0 and r.notices[-1][0].index < item[1].index < event.index]
            revoke = [item for item in self.inputs.controls if item[2].tail[0] == 4 and item[2].token == r.input and item[2].word == r.execution and
                      item[4] == 0 and r.notices[-1][0].index < item[1].index < event.index]
            require(bind and revoke, "retry restored input access without retiring predecessor and explicitly binding same immutable object")
            r.authorizations.append((event, p))

    def run(self):
        for event in self.events:
            p = self.packets.get(event.index)
            if p and event.name == "host-ipc-deliver" and p.operation == 16 and p.command == 9:
                worker = next((n for n in self.kernel.tree.nodes.values() if n.instance == p.data), None)
                require(worker and worker.template == 6 and p.kind == 1 and p.detail == p.token == 0 and p.request == 1 and
                        p.sender in worker.entered and p.target == worker.parent_endpoint and p.sender not in self.bootstrap,
                        "analysis worker bootstrap changed actual logical/current execution scope")
                self.bootstrap[p.sender] = event
            if p and event.name == "host-ipc-enqueue":
                self.sent(event, p)
            if event.name == "host-computed":
                execution, rpc, digest = endpoint(event), event.fields["value"], event.fields["extra"]
                candidates = [r for r in self.records.values() if r.state == 2 and r.execution == execution and r.rpc == rpc]
                require(len(candidates) == 1 and (execution, rpc) not in self.computations, "worker computed before acceptance/twice/under stale attempt")
                r = candidates[0]
                require(rpc in r.dispatches and r.descriptors[rpc][-1][0].index < event.index,
                        "actual ring3 worker computed without complete authenticated accepted descriptor")
                delivered = [e for e in self.kernel.delivered if e.index < event.index and self.packets[e.index] == r.descriptors[rpc][-1][1]]
                require(delivered, "ring3 work was only enqueued and never actually delivered")
                data, stream = self.collection(execution, r, event.index, delivered[-1].index)
                require(digest == calculate(data)[2], "ring3 computation reported wrong digest of captured bytes")
                self.computations[(execution, rpc)] = event, calculate(data), stream
            if event.name == "analysis-reader-bound":
                token, reader = event.fields["value"], event.fields["extra"]
                bindings = [item for item in self.inputs.controls if item[2].sender == endpoint(event) and item[2].tail[0] in (3, 7) and
                            item[2].token == token and item[2].word == reader and item[4] == 0 and item[1].index < event.index]
                require(bindings and (0x102, token) in self.inputs.records, "reader binding marker invented exact owner/object/current endpoint authority")
            if event.name == "analysis-input-reaped":
                token, contract = event.fields["value"], event.fields["extra"]
                r = self.record(contract)
                reaped = [(e, input_) for e, input_ in self.inputs.reaped if input_.reference == (r.input_issuer, token) and e.index < event.index]
                require(r.input == token and r.owner == endpoint(event) and len(reaped) == 1 and r.terminal and r.terminal.index < reaped[0][0].index, "input reap marker hid service-owned record/binding/backing")
            if event.name == "analysis-denied":
                token, status = event.fields["value"], host.signed(event.fields["extra"])
                rejected = []
                for request in self.kernel.snapshot_delivered:
                    p_ = SnapshotPacket.from_event(request)
                    if p_.operation != 18 or p_.sender != endpoint(event) or p_.token != token or request.index > event.index:
                        continue
                    answers = [answer for answer in self.kernel.snapshot_delivered if answer.index < event.index and answer.index > request.index and
                               (q_ := SnapshotPacket.from_event(answer)).operation == 19 and q_.target == p_.sender and q_.transaction == p_.transaction and q_.token == token]
                    if answers and SnapshotPacket.from_event(answers[-1]).read_reply()[2] == status:
                        rejected.append(request)
                require(rejected and status < 0, "snapshot denial marker lacks actual authenticated no-byte error reply")
            if event.name == "host-denied":
                transaction, code = event.fields["value"], event.fields["extra"]
                errors = [e for e in self.errors if e.index < event.index and self.packets[e.index].request == transaction and self.packets[e.index].data == code]
                require(endpoint(event) == 0x104 and errors and any(e.index < event.index and self.packets[e.index] == self.packets[errors[-1].index] for e in self.kernel.delivered),
                        "service denial marker lacks actual exact authoritative delivered error")
            if event.name == "analysis-worker-counts":
                r = self.record(event.fields["value"])
                require(endpoint(event) == r.execution and (r.execution, r.rpc) in self.computations and (r.execution, r.rpc) not in self.worker_count_reports and
                        self.computations[(r.execution, r.rpc)][0].index < event.index and
                        event.fields["extra"] == r.input_length | calculate(self.inputs.records[(r.input_issuer, r.input)].data)[1] << 16,
                        "worker counters contradict/duplicate actual captured-byte computation")
                self.worker_count_reports[(r.execution, r.rpc)] = event
            if event.name.startswith("contract-") and event.name != "contract-complete" or event.name in (
                    "analysis-input-issuer", "analysis-input-length", "analysis-broker-counts", "analysis-requester-counts", "analysis-input-released"):
                self.progress(event)
            self.state_history[event.index] = {token: (r.state, r.execution, r.attempt, r.rpc) for token, r in self.records.items()}
        require(all(len(r.initial_reports) == 7 for r in self.records.values()), "analysis omitted complete offered input/worker/issuer/length binding reports")
        require(not self.live and not self.groups and not self.tuple_stages and self.records and all(not r.retained for r in self.records.values()),
                "analysis completed with hidden contract/staging/receipt metadata")
        require(sum(r.state == 4 for r in self.records.values()) >= 3 and sum(r.state == 5 for r in self.records.values()) >= 2 and
                sum(r.retries == 1 and r.state == 4 for r in self.records.values()) == 1,
                "analysis omitted real success/cancellation/current-attempt retry sequence")
        require(len(self.lost) == 2 and {item[1][2].command for item in self.lost} == {1, 5} and self.late and
                all(r.requester_checks and r.requester_counts for r in self.records.values() if r.state == 4),
                "analysis omitted authoritative loss recovery, late-result cancellation precedence, or requester receipt check")
        # Readiness must reach the owner through actual authenticated copies
        # before its real FS revoke/cancel. A progress report cannot substitute.
        cancelled_stages = []
        released_stages = []
        for token, (request, first, last, fields) in self.staged_ready.items():
            r = self.records[token]
            delivered = [e for e in self.kernel.delivered if (p := self.packets[e.index]).sender == r.issuer and p.target == r.owner and
                         p.command == 15 and p.request == self.packets[request.index].request and p.token == token and p.kind == 2 and
                         first.index < e.index and p.detail < 10]
            require(len(delivered) == 10 and {self.packets[e.index].detail for e in delivered} == set(range(10)) and
                    fields[5:7] == (r.execution, r.rpc), "owner staging readiness lacked all ten copied parts or changed execution/RPC")
            copied_ready = max(e.index for e in delivered)
            if r.state == 5:
                revokes = [item for item in self.inputs.controls if item[2].sender == r.owner and item[2].token == r.input and
                           item[2].tail[0] == 4 and item[2].word == r.execution and item[4] == 0 and copied_ready < item[0].index < item[1].index < r.terminal.index]
                cancels = self.prior(lambda e: e.name == "host-ipc-deliver" and (p := self.packets[e.index]).sender == r.owner and
                                    p.target == r.issuer and p.command == 4 and p.token == token, r.terminal.index, copied_ready)
                late = [e for e in self.late if e.fields["value"] == token and r.terminal.index < e.index]
                require(revokes and cancels and revokes[-1][1].index < cancels[-1].index and late,
                        "staged cancellation omitted ready-copy -> actual revoke -> owner cancel -> normal late rejection")
                cancelled_stages.append(r)
            elif r.state == 4:
                release = self.stage_releases.get(token)
                require(release and copied_ready < release.index < r.validation.index and r.requester_checks and r.requester_counts,
                        "staged sibling lacked explicit current-RPC release before independent settlement")
                released_stages.append((r, release))
        require(len(cancelled_stages) == len(released_stages) == 1, "analysis omitted exact staged active/sibling controls")
        active = cancelled_stages[0]
        sibling, release = released_stages[0]
        running = [item for item in self.snapshots if item[2].token == sibling.token and item[2].command == 3 and item[3][0] & 255 == 2 and
                   active.terminal.index < item[0].index < item[1].index < release.index]
        require(running and active.token != sibling.token, "staged cancellation changed unrelated running sibling before explicit release")
        return self

ORIGINAL_ALPHA = b"Zeal\x00A\n\xfffile bytes\nold."
CHANGED_ALPHA = b"\n\x00new\xfe!\n" + ORIGINAL_ALPHA[8:]


def verify_workload(events, source, inputs, contracts):
    beta = host.PAYLOADS["/beta"]
    mutation = [(request, reply, data) for request, reply, name, data in source.writes if endpoint(request) == 0x104 and name == "/alpha"]
    require(len(mutation) == 1 and StoragePacket.from_event(mutation[0][0]).offset == 0 and mutation[0][2] == CHANGED_ALPHA[:8],
            "immutable-source demonstration omitted exact controlled real owning file mutation")
    write, acknowledged, changed = mutation[0]
    before = [e for e in events if e.name == "host-ipc-deliver" and e.fields.get("sender") == 0x103 and e.fields.get("target") == 0x104 and
              (p := ContractPacket.from_event(e)).command == 10 and p.detail == 1 and p.data == 1 and e.index < write.index]
    after = [e for e in events if e.name == "host-ipc-deliver" and e.fields.get("sender") == 0x103 and e.fields.get("target") == 0x104 and
             (p := ContractPacket.from_event(e)).command == 10 and p.detail == 2 and p.data == 2 and acknowledged.index < e.index]
    require(before and after and ContractPacket.from_event(before[-1]).request == ContractPacket.from_event(after[0]).request,
            "source mutation did not use actual bounded pause/acknowledged independent-workload model transition")
    markers = [e for e in events if e.name == "analysis-source-mutated"]
    require(len(markers) == 1 and endpoint(markers[0]) == 0x104 and markers[0].fields["value"] == StoragePacket.from_event(write).handle and
            markers[0].fields["extra"] == ContractPacket.from_event(before[-1]).request and acknowledged.index < markers[0].index < after[0].index,
            "source-mutation marker contradicted actual paused owner handle/write/acknowledgement")
    for request, reply, name, data in source.reads:
        if endpoint(request) != 0x103:
            continue
        packet = StoragePacket.from_event(request)
        expected = host.PAYLOADS["/hello"] if name == "/hello" else beta if name == "/beta" else CHANGED_ALPHA if request.index > after[0].index else ORIGINAL_ALPHA
        require(data == expected[packet.offset:packet.offset + packet.value],
                "independent original root workload changed expected actual named-file bytes")
        if data:
            verified = [e for e in events if e.name == "storage-verified" and e.fields.get("request") == packet.transaction and endpoint(e) == packet.sender]
            require(len(verified) == 1 and reply.index < verified[0].index and verified[0].fields.get("data") == int.from_bytes(data.ljust(8, b"\0"), "little"),
                    "preserved workload read lacks actual byte-verified application result")
    require(any(name == "/alpha" and request.index > after[0].index and data == CHANGED_ALPHA[:8] for request, reply, name, data in source.reads),
            "ordinary source reads did not observe acknowledged mutation")
    first = min(inputs.records.values(), key=lambda r: r.publication.index)
    require(first.filename == "/alpha" and first.data == ORIGINAL_ALPHA and first.publication.index < write.index and
            any(r.state == 4 and r.input == first.reference[1] and r.terminal.index > acknowledged.index for r in contracts.records.values()),
            "accepted immutable analysis silently followed changed source file")
    ready = [e for e in events if e.name == "hosting-storage-ready"]
    names = {name: reply.fields["handle"] for request, reply, name in source.opens if endpoint(request) == 0x103}
    require(len(ready) == 1 and endpoint(ready[0]) == 0x103 and ready[0].fields["value"] == names["/alpha"] and ready[0].fields["extra"] == names["/beta"] and
            ready[0].index < min(e.index for e in events if e.name == "host-request"),
            "original three-file workload was not genuinely established before runtime hosting")
    cycles = [e for e in events if e.name == "hosting-storage-cycle"]
    require(len(cycles) >= 2 and [e.fields["value"] for e in cycles] == list(range(len(cycles))) and all(e.fields["extra"] == 7 for e in cycles),
            "independent root workload omitted complete finite three-file cycle reports")
    return dict(source_mutations=len(mutation), independent_storage_cycles=len(cycles), independent_verified_chunks=sum(bool(data) for _, _, _, data in source.reads))


def verify(output, code, scenario=25, manifest_path=None):
    require(scenario == 25 and code == 1, "analysis emulator lacks exact scenario25 success debug-exit1")
    require(output.count("ZEAL boot abi=4 x86_64") == output.count("MANIFEST_ACCEPT version=2") == 1,
            "analysis lacks unique actual boot/privileged manifest acceptance")
    require(output.count("RESEARCH_PASS") == 1 and "RESEARCH_PASS scenario=0x0000000000000019" in output,
            "analysis completion marker is absent/repeated/wrong scenario")
    require(not any(word in output for word in ("PANIC", "RESEARCH_FAIL", "bad-report", "TRACE_EXHAUSTED")),
            "analysis trace reports actual failure or finite quota exhaustion")
    path = pathlib.Path(manifest_path) if manifest_path else ROOT / "build/research/scenario-25/manifest.bin"
    roots, approved, manifest_hash = manifest_records(path)
    images = scalar.linked_images(path.parent / "kernel.elf", include_payload=True)
    approved[5].update(images[3])
    approved[6].update(images[4])
    accepted = next(line for line in output.splitlines() if line.startswith("MANIFEST_ACCEPT"))
    require("cells=0x0000000000000004" in accepted and "grants=0x0000000000000009" in accepted,
            "privileged manifest acceptance counts contradict actual sealed artifact")
    events = host.records(output)
    require(events and sum(e.name.startswith(("host-", "contract-", "analysis-")) or e.name in ("cap-query", "snapshot-capture-owner", "snapshot-published", "snapshot-inventory", "snapshot-reply-lost") for e in events) < 4096,
            "analysis hosting/progress trace credit exhausted")
    require(sum(e.name in ("storage-ipc", "storage-ipc-deliver", "storage-reject", "snapshot-ipc-enqueue", "snapshot-ipc-deliver", "snapshot-ipc-reject") for e in events) < 8192,
            "analysis ordinary/snapshot transfer trace credit exhausted")
    kernel = KernelLedger(events, roots, approved).run()
    host.management_returns(kernel)
    block = BlockLedger(events).run()
    source = SourceLedger(events, block).run()
    inputs = Inputs(events, kernel, source).run()
    contracts = Contracts(events, kernel, inputs).run()
    workload = verify_workload(events, source, inputs, contracts)
    recovered = next(r for r in contracts.records.values() if r.retries == 1 and r.state == 4)
    fault, receipt = recovered.faults[0], recovered.requester_checks[0]
    restart = next(e for e in kernel.restarts if e.fields["instance"] == recovered.worker.instance)
    recovery_reads = [(request, reply) for request, reply, name, data in source.reads if endpoint(request) == 0x103 and data and
                      fault.index < request.index < reply.index < receipt.index]
    require(recovery_reads, "worker recovery interval omitted actual independent root FS/block byte progress")
    workload.update(recovery_fault_tick=fault.fields["tick"], recovery_restart_tick=restart.fields["tick"],
                    recovery_broker_terminal_tick=recovered.terminal.fields["tick"], recovery_requester_verified_tick=receipt.fields["tick"],
                    recovery_observed_restart_ticks=restart.fields["tick"] - fault.fields["tick"],
                    recovery_observed_terminal_ticks=recovered.terminal.fields["tick"] - fault.fields["tick"],
                    recovery_observed_requester_ticks=receipt.fields["tick"] - fault.fields["tick"],
                    independent_storage_chunks_during_recovery=len(recovery_reads))
    return dict(analysis_verified=True, scenario=25, manifest_sha256=manifest_hash,
                serial_sha256=hashlib.sha256(output.encode()).hexdigest(), broker_image_sha256=images[3]["image_sha256"],
                worker_image_sha256=images[4]["image_sha256"], runtime_creations=len(kernel.published),
                immutable_inputs=len(inputs.records), maximum_input_records=inputs.maximum, maximum_snapshot_backing=inputs.maximum * 128,
                captured_bytes=sum(len(r.data) for r in inputs.records.values()), snapshot_reads=len(inputs.reads),
                contracts=len(contracts.records), maximum_contract_records=contracts.maximum,
                successful_receipts=sum(r.state == 4 for r in contracts.records.values()), cancelled_contracts=sum(r.state == 5 for r in contracts.records.values()),
                worker_computations=len(contracts.computations), requester_checks=len(contracts.receipt_checks),
                authoritative_lost_replies=len(contracts.lost), privately_staged_late_results=len(contracts.late),
                authenticated_staging_ready=len(contracts.staged_ready), explicit_staging_releases=len(contracts.stage_releases),
                worker_restarts=len(kernel.restarts), explicit_rebind_authorizations=sum(len(r.authorizations) for r in contracts.records.values()),
                root_private_pages=80, broker_private_pages=4, worker_private_pages=2, final_owned_slots=0, final_owned_pages=0,
                final_reserved_slots=0, final_reserved_pages=0, final_available_slots=4, final_available_pages=48,
                final_temporary_routes=len(kernel.storage_channels), final_input_records=sum(r.retained for r in inputs.records.values()), **workload)


def negative_controls(output, code, scenario=25, manifest_path=None):
    """Durable removals, raw contradictions, and coordinated causal counterfeits."""
    events = host.records(output)
    lines = output.splitlines()
    destination = ROOT / "build/research/analysis-counterfeit-witnesses"
    destination.mkdir(parents=True, exist_ok=True)
    controls = []
    checker_source = pathlib.Path(__file__).read_bytes()
    checker_hash = hashlib.sha256(checker_source).hexdigest()

    def rejected(label, candidate, status=code, artifact=manifest_path):
        try:
            verify(candidate, status, scenario, artifact)
        except (AssertionError, ValueError, IndexError, KeyError, struct.error):
            controls.append(label)
        else:
            witness_key = label + "-" + hashlib.sha256(checker_source + candidate.encode()).hexdigest()[:12]
            (destination / f"{witness_key}.log").write_text(candidate)
            (destination / f"{witness_key}.checker.py").write_bytes(checker_source)
            (destination / f"{witness_key}.json").write_text(json.dumps(dict(label=label, exit=status, escaped=True, checker_sha256=checker_hash,
                                                               prior_rejected_controls=controls, prior_rejected_count=len(controls)), indent=2) + "\n")
            raise AssertionError("analysis oracle accepted counterfeit; retained witness " + label)

    def changed(event, fields):
        result = list(lines)
        for name, value in fields.items():
            require(name in event.fields, "counterfeit tried to alter an absent authoritative field")
            result[event.line] = re.sub(rf"\b{name}=0x[0-9a-f]+\b", f"{name}=0x{value:016x}", result[event.line])
        return "\n".join(result) + "\n"

    essential = ("boot", "host-template", "host-root-domain", "host-reserve", "host-space", "host-channel", "host-publish", "host-kernel-entry",
                 "host-entry", "host-cold", "host-memory", "host-domain", "host-stop", "host-return", "host-reap", "host-fault", "host-restart", "host-rebind",
                 "contract-offer", "contract-input", "contract-worker", "contract-control", "contract-endpoint", "analysis-input-issuer", "analysis-input-length",
                 "contract-accepted", "contract-dispatch", "contract-attempt", "host-computed", "analysis-worker-counts", "contract-validated", "analysis-broker-counts",
                 "contract-terminal", "contract-requester-verified", "analysis-requester-counts", "contract-reaped", "contract-reply-lost", "contract-deferred", "contract-late-rejected",
                 "cap-query", "snapshot-ipc-enqueue", "snapshot-ipc-deliver", "snapshot-capture-owner", "snapshot-published", "storage-link", "storage-block", "storage-fs", "storage-verified", "storage-ipc-deliver", "storage-reject", "host-storage-denied",
                 "snapshot-inventory", "snapshot-retired-transaction", "snapshot-reply-lost", "analysis-reader-bound", "analysis-input-reaped", "analysis-source-mutated", "analysis-input-released", "hosting-storage-ready", "analysis-conservation")
    for name in essential:
        selected = [e for e in events if e.name == name]
        require(selected, "analysis trace omitted mandatory causal evidence " + name)
        for event in selected[:3]:
            candidate = list(lines)
            del candidate[event.line]
            rejected(f"remove-{name}-{event.index}", "\n".join(candidate) + "\n")
    fields_by_name = {
        "cap-query": ("cap", "holder", "target", "issuer", "rights", "parent", "epoch", "reserved", "valid", "result"),
        "host-channel": ("parent_holder", "parent_target", "parent_issuer", "parent_rights", "parent_derivation", "parent_epoch", "child_holder", "child_target", "child_issuer", "child_rights", "child_derivation", "child_epoch"),
        "host-space": ("physical_pages", "zero", "p0", "cs", "ss", "rip", "rsp", "rflags"),
        "host-return": ("retired_pages", "pages", "reserved_slots", "reserved_pages", "retained"),
        "host-kernel-entry": ("cs", "ss", "rip", "rsp", "rflags", "endpoint", "instance", "control"),
        "host-ipc-enqueue": ("sender", "target", "cap", "raw0", "raw1", "raw2", "raw3", "version", "service_command", "kind", "detail", "token", "data", "reserved", "argument", "value"),
        "host-ipc-deliver": ("sender", "target", "cap", "raw0", "raw1", "raw2", "raw3", "version", "service_command", "kind", "detail", "token", "data", "reserved", "argument", "value"),
        "snapshot-ipc-enqueue": ("sender", "target", "cap", "raw0", "raw1", "raw2", "raw3", "request", "handle", "offset", "result", "data"),
        "snapshot-ipc-deliver": ("sender", "target", "cap", "raw0", "raw1", "raw2", "raw3", "request", "handle", "offset", "result", "data"),
        "storage-ipc": ("sender", "target", "cap", "request", "handle", "offset", "result", "data", "raw0", "raw1", "raw2", "raw3"),
        "storage-ipc-deliver": ("sender", "target", "cap", "request", "handle", "offset", "result", "data", "raw0", "raw1", "raw2", "raw3"),
        "storage-reject": ("sender", "target", "cap", "operation", "request", "handle", "offset", "result", "data", "raw0", "raw1", "raw2", "raw3", "outcome"),
        "analysis-conservation": ("active_capabilities", "root_grants", "legacy_read_grants", "snapshot_empty", "physical_pages"),
        "storage-block": ("request", "operation", "result"), "storage-link": ("request", "block_request"),
        "storage-fs": ("request", "operation", "result"), "storage-verified": ("request", "data"),
    }
    for name, fields in fields_by_name.items():
        for event in [e for e in events if e.name == name][:3]:
            for field in fields:
                replacement = event.fields[field] ^ (1 << 63 if name == "host-kernel-entry" and field == "rflags" else 1)
                rejected(f"alter-{name}-{event.index}-{field}", changed(event, {field: replacement}))
    for event in [e for e in events if e.name.startswith(("contract-", "analysis-")) and e.name != "contract-complete"][:80]:
        for field in ("value", "extra"):
            rejected(f"contradict-{event.name}-{event.index}-{field}", changed(event, {field: event.fields[field] ^ 1}))
    stage_events = [e for e in events if e.name in ("host-ipc-enqueue", "host-ipc-deliver") and ContractPacket.from_event(e).command == 15]
    for phase in ((15, 0, 2), (16, 2, 0), (16, 2, 9), (15, 0, 0)):
        selected = [e for e in stage_events if (p := ContractPacket.from_event(e)) and (p.operation, p.kind, p.detail) == phase]
        require(selected, "analysis staging controls omitted protocol phase " + str(phase))
        for event in selected:
            candidate = list(lines)
            del candidate[event.line]
            rejected(f"remove-staging-{event.index}", "\n".join(candidate) + "\n")
        event = selected[0]
        packet = ContractPacket.from_event(event)
        for field in ("sender", "target", "request", "token", "data"):
            rejected(f"staging-scope-{event.index}-{field}", changed(event, {field: event.fields[field] ^ 1}))
    def coordinate(selected, fields):
        result = list(lines)
        for e in selected:
            for name, value in fields.items():
                result[e.line] = re.sub(rf"\b{name}=0x[0-9a-f]+\b", f"{name}=0x{value:016x}", result[e.line])
        return "\n".join(result) + "\n"

    ready_packet = next(ContractPacket.from_event(e) for e in stage_events if ContractPacket.from_event(e).operation == 16 and
                        ContractPacket.from_event(e).kind == 2 and ContractPacket.from_event(e).detail == 0)
    # Coordinated wire edits retain raw/decoded agreement and authenticated
    # copies, so these controls reach the staging joins themselves.
    for part, delta in ((3, 256), (6, 1)):
        selected = [e for e in stage_events if (p := ContractPacket.from_event(e)).operation == 16 and p.kind == 2 and
                    p.request == ready_packet.request and p.token == ready_packet.token and p.detail == part]
        require(len(selected) == 2, "staging coordinated control lacks matching enqueue/copy")
        value = ContractPacket.from_event(selected[0]).data + delta
        rejected("coordinated-staging-ready-part-" + str(part), coordinate(selected, {"data": value, "value": value, "raw3": value}))
    candidate = list(lines)
    for e in stage_events:
        p = ContractPacket.from_event(e)
        if p.token == ready_packet.token and p.request == ready_packet.request:
            packed = (e.fields["raw1"] & ~0xFF00) | (2 << 8)
            for name, value in dict(service_command=2, command=packed, raw1=packed).items():
                candidate[e.line] = re.sub(rf"\b{name}=0x[0-9a-f]+\b", f"{name}=0x{value:016x}", candidate[e.line])
    rejected("coordinated-staging-disguised-as-ordinary-accept", "\n".join(candidate) + "\n")
    candidate = list(lines)
    release_packet = next(ContractPacket.from_event(e) for e in stage_events if ContractPacket.from_event(e).operation == 15 and
                          ContractPacket.from_event(e).detail == 0)
    for e in stage_events:
        p = ContractPacket.from_event(e)
        if p.token == release_packet.token and p.request == release_packet.request:
            packed = (e.fields["raw1"] & ~0xFF00) | (3 << 8)
            values = dict(service_command=3, command=packed, raw1=packed)
            if p.operation == 15: values.update(data=0, value=0, raw3=0)
            for name, value in values.items():
                candidate[e.line] = re.sub(rf"\b{name}=0x[0-9a-f]+\b", f"{name}=0x{value:016x}", candidate[e.line])
    rejected("coordinated-staging-release-disguised-as-status", "\n".join(candidate) + "\n")

    first_capture = next(e for e in events if e.name == "snapshot-capture-owner")
    first_publication = next(e for e in events if e.name == "snapshot-published")
    captured_delivery = next(e for e in events if e.name == "storage-ipc-deliver" and e.fields["operation"] == 9 and
                             first_capture.index < e.index < first_publication.index)
    rejected("capture-delivery-raw-contradiction", changed(captured_delivery, {"raw3": captured_delivery.fields["raw3"] ^ 1}))
    rejected("capture-delivery-coordinated-bytes", changed(captured_delivery, {"raw3": captured_delivery.fields["raw3"] ^ 1, "data": captured_delivery.fields["data"] ^ 1}))
    opened = next(e for e in events if e.name == "storage-ipc" and e.fields["operation"] == 14 and e.fields["result"] == 0 and e.fields["handle"] != 0)
    open_copy = [e for e in events if e.name in ("storage-ipc", "storage-ipc-deliver") and e.fields["operation"] == 14 and
                 (e.fields["sender"], e.fields["target"], e.fields["request"]) == (opened.fields["sender"], opened.fields["target"], opened.fields["request"])]
    rejected("coordinated-open-reply-offset", coordinate(open_copy, {"offset": 1, "raw2": opened.fields["raw2"] | 1}))
    for operation in (7, 10, 11, 12):
        denial = next(e for e in events if e.name == "storage-reject" and e.fields["operation"] == operation)
        rejected("denial-converted-to-success-" + str(operation), changed(denial, {"outcome": 0}))
        rejected("remove-all-denied-operation-" + str(operation), "\n".join(line for line in lines if not
                 (line.startswith("EVENT storage-reject ") and f"operation=0x{operation:016x}" in line)) + "\n")
    offers = [e for e in events if e.name == "contract-offer"]
    predecessor, cancelled_offer = offers[:2]
    old_input = next(e.fields["extra"] for e in events if e.name == "contract-input" and e.fields["value"] == predecessor.fields["value"])
    old_length = next(e.fields["extra"] for e in events if e.name == "analysis-input-length" and e.fields["value"] == predecessor.fields["value"])
    candidate = list(lines)
    def edit_row(e, values):
        for field, value in values.items():
            candidate[e.line] = re.sub(rf"\b{field}=0x[0-9a-f]+\b", f"{field}=0x{value:016x}", candidate[e.line])
    for e in events:
        if e.name in ("host-ipc-enqueue", "host-ipc-deliver"):
            packet = ContractPacket.from_event(e)
            if packet.command == 1 and packet.kind == 0 and packet.request == cancelled_offer.fields["extra"]:
                edit_row(e, dict(raw3=old_input, value=old_input, data=old_input))
            if packet.token == cancelled_offer.fields["value"] and packet.kind == 2 and packet.detail in (1, 9):
                wrong = old_input if packet.detail == 1 else old_length
                edit_row(e, dict(raw3=wrong, value=wrong, data=wrong))
            if packet.token == cancelled_offer.fields["value"] and packet.command == 2 and packet.kind == 0:
                edit_row(e, dict(raw3=old_input, value=old_input, data=old_input))
        if e.fields.get("value") == cancelled_offer.fields["value"]:
            if e.name in ("contract-input", "analysis-input-released"):
                edit_row(e, dict(extra=old_input))
            if e.name == "analysis-input-length":
                edit_row(e, dict(extra=old_length))
        if e.name == "analysis-input-reaped" and e.fields["extra"] == cancelled_offer.fields["value"]:
            edit_row(e, dict(value=old_input))
    rejected("coordinated-offer-reaped-predecessor", "\n".join(candidate) + "\n")
    rebound = [e for e in events if e.name == "host-rebind"][-2:]
    handles = {value for e in rebound for value in (e.fields["parent_cap"], e.fields["child_cap"])}
    for label, shift in (("unobserved-gap", 1), ("over-signed-limit", 1 << 55)):
        mapping = {cap: ((cap >> 8) + shift) << 8 | (cap & 255) for cap in handles}
        epochs = {cap >> 8: (cap >> 8) + shift for cap in handles}
        candidate = list(lines)
        for e in events:
            for field, value in e.fields.items():
                if field.endswith("epoch") and value in epochs:
                    edit_row(e, {field: epochs[value]})
                elif value in mapping:
                    edit_row(e, {field: mapping[value]})
        rejected("coordinated-capability-epoch-" + label, "\n".join(candidate) + "\n")

    request_packet = next(e for e in events if e.name == "snapshot-ipc-enqueue" and e.fields["operation"] == 18)
    corresponding = [e for e in events if e.name in ("snapshot-ipc-enqueue", "snapshot-ipc-deliver") and e.fields["operation"] == 18 and
                     (e.fields["sender"], e.fields["target"], e.fields["raw0"]) == (request_packet.fields["sender"], request_packet.fields["target"], request_packet.fields["raw0"])]
    rejected("coordinated-snapshot-request-wrong-issuer", coordinate(corresponding, {"raw2": 0x202, "offset": 0x202, "result": 0}))
    actual_result = next(e for e in events if e.name == "host-ipc-enqueue" and e.fields["service_command"] == 11)
    tuple_copies = [e for e in events if e.name in ("host-ipc-enqueue", "host-ipc-deliver") and
                    (e.fields["sender"], e.fields["target"], e.fields["request"], e.fields["service_command"]) ==
                    (actual_result.fields["sender"], actual_result.fields["target"], actual_result.fields["request"], 11)]
    for label, bit in (("length", 0), ("newlines", 16)):
        wrong = actual_result.fields["data"] ^ 1 << bit
        rejected("coordinated-worker-" + label, coordinate(tuple_copies, {"data": wrong, "value": wrong, "raw3": wrong}))

    for part in range(10):
        selected = next(e for e in events if e.name == "host-ipc-enqueue" and e.fields["service_command"] == 5 and e.fields["kind"] == 2 and e.fields["detail"] == part)
        p = ContractPacket.from_event(selected)
        candidate = list(lines)
        for e in events:
            if e.name in ("host-ipc-enqueue", "host-ipc-deliver") and ContractPacket.from_event(e) == p:
                for field in ("raw3", "value", "data"):
                    candidate[e.line] = re.sub(rf"\b{field}=0x[0-9a-f]+\b", f"{field}=0x{p.data ^ 1:016x}", candidate[e.line])
        rejected(f"coordinated-authoritative-receipt-part-{part}", "\n".join(candidate) + "\n")
    accepted = next(e for e in events if e.name == "contract-accepted")
    dispatched = next(e for e in events if e.name == "contract-dispatch")
    candidate = list(lines)
    candidate[accepted.line], candidate[dispatched.line] = candidate[dispatched.line], candidate[accepted.line]
    rejected("dispatch-before-consent", "\n".join(candidate) + "\n")
    for status in (0, 3, None):
        rejected("wrong-exit-" + str(status), output, status)
    rejected("marker-only", "ZEAL boot abi=4 x86_64\nMANIFEST_ACCEPT version=2 cells=0x0000000000000004 grants=0x0000000000000009\nRESEARCH_PASS scenario=0x0000000000000019\n")
    for quota in ("HOSTING_TRACE_EXHAUSTED", "STORAGE_TRACE_EXHAUSTED"):
        rejected("exhaustion-" + quota, output + quota + "\n")
    (ROOT / "build/research/analysis-negative-control-list.json").write_text(json.dumps(dict(passed=True, controls=controls), indent=2) + "\n")
    return controls
