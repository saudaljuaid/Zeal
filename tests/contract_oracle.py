#!/usr/bin/env python3
"""Independent causal proof of Zeal's native work-contract scenario.

The kernel hosting observer reconstructs the tree, capabilities, physical pages,
waits and resource returns. This observer independently decodes the service wire
and reconstructs obligations by issuer/token, rather than the broker's arrays.
No production Zig state or protocol code is imported.
"""
import dataclasses
import hashlib
import pathlib
import re
import struct
from collections import defaultdict

import hosting_oracle as host

require = host.require
MASK64 = host.MASK64
ROOT_IDS = host.ROOT_IDS
OFFERED, RUNNING, RECOVERING, COMPLETED, CANCELLED, FAILED = range(1, 7)
TERMINAL = (COMPLETED, CANCELLED, FAILED)
RFLAGS_DOCUMENTED = sum(1 << bit for bit in (0, 1, 2, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21))
REPORTS = {
    "contract-offer", "contract-input", "contract-worker", "contract-control",
    "contract-endpoint", "contract-accepted", "contract-dispatch", "contract-attempt",
    "contract-validated", "contract-terminal", "contract-reaped", "contract-deferred",
    "contract-late-rejected", "contract-recovering", "contract-rebound",
    "contract-requester-verified", "contract-complete", "contract-reply-lost",
}


def manifest_records(path):
    data = pathlib.Path(path).read_bytes()
    require(40 <= len(data) <= 1320, "contract manifest artifact has invalid size")
    magic, version, length, roots, grants, templates, domains, *reserved = struct.unpack_from("<10I", data)
    require((magic, version, length, roots, templates, domains) ==
            (0x4c41455a, 2, len(data), 4, 2, 1) and grants <= 16 and not any(reserved),
            "contract manifest is not the exact bounded sealed v2 composition")
    require(len(data) == 40 + roots * 64 + grants * 16 + templates * 64 + domains * 32,
            "contract manifest record extents differ")
    root_records = host.SealedRoots(grants)
    for slot in range(roots):
        values = struct.unpack_from("<4IQ6I16s", data, 40 + slot * 64)
        identity, image, abi, flags, entry, budget, stack, writable, config, limit, delay, name = values
        require((identity, image, abi, flags, entry, budget, limit, delay) ==
                (ROOT_IDS[slot], slot + 1, 4, 1, 0x40000000, 65536, 3, 4),
                "contract composition changed an original root identity/image/ABI/policy")
        require(config == (24 if slot in (2, 3) else 0), "contract branch escaped its dedicated manifest")
        root_records[slot] = {"identity": identity, "image": image, "abi": abi,
            "entry": entry, "pages": host.pages(stack, writable), "config": config,
            "stack": stack, "writable": writable, "budget": budget}
    require(sum(root["pages"] for root in root_records.values()) == 80,
            "contract composition changed the original root private reservation")
    expected_grants = ((100, 200, 258, 0), (200, 100, 193, 0), (200, 200, 0x80000004, 0),
                       (200, 300, 8216, 0), (300, 200, 7716, 0), (300, 400, 16, 0))
    actual_grants = tuple(struct.unpack_from("<4I", data, 40 + roots * 64 + index * 16) for index in range(grants))
    require(actual_grants == expected_grants, "sealed native composition changed original narrow storage authority grants")
    root_records.initial_capabilities = {
        (index + 1) << 8 | (index + 1): ((holder // 100) + 0x100, (target // 100) + 0x100, rights)
        for index, (holder, target, rights, reserved) in enumerate(actual_grants)}
    at = 40 + roots * 64 + grants * 16
    approved = {}
    for index in range(templates):
        values = struct.unpack_from("<4IQ10I", data, at + index * 64)
        identity, image, abi, flags, entry, budget, stack, writable, config, limit, delay, depth, mask, recipe, reserved = values
        require(identity not in approved and identity in (3, 4), "contract template identity duplicates or is unapproved")
        wanted = (5, 8192, 16384, 1, 8, 4) if identity == 3 else (6, 4096, 8192, 0, 0, 5)
        require((image, stack, writable, depth, mask) == wanted[:5] and
                (abi, flags, entry, budget, config, limit, delay, recipe, reserved) ==
                (4, 0, 0x40000000, 65536, 24, 3, 4, 1, 0),
                "sealed approved contract template/profile/resource/recipe differs")
        approved[identity] = {"image": image, "pages": host.pages(stack, writable),
            "depth": depth, "mask": mask, "stack": stack, "writable": writable,
            "recipe": recipe, "role": wanted[5], "abi": abi, "entry": entry,
            "budget": budget, "config": config, "limit": limit, "delay": delay}
    require(set(approved) == {3, 4} and approved[3]["pages"] == 4 and approved[4]["pages"] == 2,
            "fixed contract supervisor/worker backing differs")
    domain = struct.unpack_from("<8I", data, at + templates * 64)
    require(domain == (400, 12, 4, 48, 2, 1, 0, 0), "contract root creator reservation differs")
    return root_records, approved, hashlib.sha256(data).hexdigest()


def linked_images(path):
    """Read the cell extents from the tested linked ELF, not current build/common."""
    data = pathlib.Path(path).read_bytes()
    require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01", "tested kernel is not little-endian ELF64")
    section_at = struct.unpack_from("<Q", data, 40)[0]
    section_size, section_count = struct.unpack_from("<HH", data, 58)
    require(section_size == 64 and section_at + section_count * section_size <= len(data),
            "tested kernel section table is truncated")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, section_at + index * section_size)
                for index in range(section_count)]
    symbols = {}
    for section in sections:
        if section[1] != 2:
            continue
        offset, size, linked, entry_size = section[4], section[5], section[6], section[9]
        require(entry_size == 24 and linked < len(sections) and offset + size <= len(data),
                "tested kernel symbol table is malformed")
        strings = sections[linked]
        names = data[strings[4]:strings[4] + strings[5]]
        for at in range(offset, offset + size, entry_size):
            name_at, info, other, shndx, value, extent = struct.unpack_from("<IBBHQQ", data, at)
            end = names.find(b"\0", name_at)
            require(end >= name_at, "tested kernel symbol string is truncated")
            name = names[name_at:end].decode("ascii")
            if name.startswith("_binary_"):
                require(name not in symbols, "tested kernel duplicates an immutable image symbol")
                symbols[name] = value
    images = {}
    for template, name in ((3, "supervisor"), (4, "worker")):
        keys = [f"_binary_{name}_bin_{suffix}" for suffix in ("start", "end", "size")]
        require(all(key in symbols for key in keys), "tested kernel lacks actual linked approved cell image")
        start, end, size = (symbols[key] for key in keys)
        require(0 < size == end - start <= 65536, "linked approved immutable cell extent exceeds manifest")
        containing = [section for section in sections if section[1] != 8 and section[2] & 2 and
                      section[3] <= start <= end <= section[3] + section[5]]
        require(len(containing) == 1, "linked approved image overlaps/misses file-backed section")
        section = containing[0]
        offset = section[4] + start - section[3]
        require(offset + size <= len(data), "linked approved image bytes are truncated")
        payload = data[offset:offset + size]
        images[template] = {"image_bytes": size, "image_sha256": hashlib.sha256(payload).hexdigest()}
    return images


@dataclasses.dataclass(frozen=True)
class Packet:
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
        event.need("sender", "target", "cap", "operation", "length", "request", "command", "reserved",
                   "argument", "value", "version", "service_command", "kind", "detail", "token", "data", "result")
        require(f["length"] == 32 and f["operation"] in (15, 16) and f["request"] > 0,
                "contract IPC is not an exact fixed-width nonzero transaction")
        require(f["version"] == 1 and f["reserved"] == 0 and 1 <= f["service_command"] <= 9 and
                0 <= f["kind"] <= 3 and 0 <= f["detail"] <= 255,
                "contract wire has unsupported version/command/kind/detail/reserved bytes")
        packed = f["version"] | f["service_command"] << 8 | f["kind"] << 16 | f["detail"] << 24
        require(f["command"] == packed and f["argument"] == f["token"] and f["value"] == f["data"],
                "authoritative raw and decoded contract IPC fields disagree")
        require((f["operation"] == 15 and f["kind"] == 0 and f["service_command"] <= 8) or
                (f["operation"] == 16 and f["kind"] in (1, 2, 3)),
                "contract command/result direction differs")
        return cls(*(f[key] for key in ("sender", "target", "operation", "request", "service_command",
                                        "kind", "detail", "token", "data")))


def token_parts(token):
    require(token & 255 == 0x80 and 0 < (token >> 9) & 0x7fffff <= 0x7fffff and
            0 < token >> 32 <= 0xffffffff and 0 < (token >> 32) >> 8 <= 0xffffff and
            1 <= (token >> 32) & 255 <= 8,
            "contract reference has wrong service type or exhausted/zero serial")
    return (token >> 8) & 1, (token >> 9) & 0x7fffff, token >> 32


def flag_fields(word):
    require(word >> 57 == 0, "contract snapshot has unknown flag bits")
    fields = tuple((word >> (8 * index)) & 255 for index in range(7)) + ((word >> 56) & 1,)
    state, profile, retries, attempt, reason, slots, pages, verified = fields
    require(state in range(1, 7) and profile == 1 and retries <= 1 and attempt <= 2 and
            reason <= 8 and slots <= 1 and pages in (0, 2) and slots * 2 == pages,
            "contract snapshot flags violate fixed state/profile/retry/backing capacities")
    return fields


@dataclasses.dataclass
class Obligation:
    issuer: int
    token: int
    owner: int
    offer_request: int
    profile: int
    input: int
    worker: host.Node
    born: int
    state: int = OFFERED
    retries: int = 0
    attempt: int = 0
    reason: int = 0
    rpc: int = 0
    execution: int = 0
    result: int = 0
    verified: bool = False
    retained: bool = True
    accepted: host.Event | None = None
    validation: host.Event | None = None
    terminal: host.Event | None = None
    initial_reports: set = dataclasses.field(default_factory=set)
    dispatches: dict = dataclasses.field(default_factory=dict)
    dispatch_reports: dict = dataclasses.field(default_factory=dict)
    attempted: set = dataclasses.field(default_factory=set)
    faults: list = dataclasses.field(default_factory=list)
    rebinds: list = dataclasses.field(default_factory=list)
    requester_checks: list = dataclasses.field(default_factory=list)

    def flags(self):
        backing = self.state not in TERMINAL
        return (self.state, self.profile, self.retries, self.attempt, self.reason,
                int(backing), 2 * int(backing), int(self.verified))

    def snapshot(self):
        flag_word = sum(field << (8 * index) for index, field in enumerate(self.flags()[:7])) | int(self.verified) << 56
        return (flag_word, self.input, self.owner, self.issuer, self.worker.instance,
                self.execution, self.rpc, self.result)


class Observer(host.Observer):
    def __init__(self, events, roots, approved):
        super().__init__(events, roots, approved, 24)
        self.supervisor_template, self.root_template_mask, self.fault_commands = 3, 12, (7,)
        self.obligations = {}
        self.live_records = {}
        self.offer_keys = {}
        self.offer_highwater = defaultdict(int)
        self.last_serial = 0
        self.last_rpc = defaultdict(int)
        self.packet_events = {}
        self.bootstrap = {}
        self.snapshot_groups = {}
        self.requests_by_key = defaultdict(list)
        self.responses = []
        self.errors = []
        self.computations = {}
        self.late = []
        self.deferred = {}
        self.catalog = {}
        self.catalog_domain = None
        self.maximum_records = 0
        self.snapshots = []
        self.reaped_records = []
        self.reap_reports = []
        self.recovery_intervals = []
        self.lost_replies = []
        self.fault_preservation = []
        self.root_capabilities = dict(getattr(roots, "initial_capabilities", {}))
        self.worker_sleeps = {}
        self.worker_sleep_returns = []

    def fault_command(self, event):
        return event.fields["service_command"]

    def broker(self):
        brokers = [node for node in self.tree.nodes.values() if node.template == 3]
        require(len(brokers) == 1, "composition does not have one authenticated contract broker")
        return brokers[0]

    def request_error(self, packet):
        """Independent admission/state rules, including narrow exact offer replay."""
        if packet.sender != 0x104 or packet.target != self.broker().endpoint:
            return 1
        if packet.command == 1:
            if packet.kind != 0 or packet.detail != 1 or packet.token != 0:
                return 2
            existing = self.offer_keys.get((packet.sender, packet.request))
            if existing is not None:
                if not existing.retained:
                    return 3
                return 0 if (existing.profile, existing.input) == (packet.detail, packet.data) else 2
            if packet.request <= self.offer_highwater[packet.sender]:
                return 3
            if len(self.live_records) == 2:
                return 4
            return 0
        if packet.command not in (2, 3, 4, 5, 6):
            return 2
        if packet.command == 3 and packet.token == 0:
            if packet.detail != 0 or packet.data == 0:
                return 2
            existing = self.offer_keys.get((packet.sender, packet.data))
            return 0 if existing is not None and existing.retained else 3
        try:
            token_parts(packet.token)
        except AssertionError:
            return 2
        if packet.command == 2:
            if packet.detail != 1:
                return 2
        elif packet.detail != 0 or packet.data != 0:
            return 2
        record = self.obligations.get((packet.target, packet.token))
        if record is None or not record.retained or token_parts(packet.token)[2] != packet.target:
            return 3
        if packet.command == 2:
            if packet.data != record.input:
                return 2
            return 0 if record.state in (OFFERED, RUNNING, RECOVERING, COMPLETED) else 10
        if packet.command in (5, 6) and record.state not in TERMINAL:
            return 9
        return 0

    def obligation(self, issuer, token, retained=True):
        require(token_parts(token)[2] == issuer, "contract reference encoded issuer generation differs")
        require((issuer, token) in self.obligations, "unknown/stale broker-scoped contract reference")
        record = self.obligations[(issuer, token)]
        require(not retained or record.retained, "reaped contract reference was revived")
        return record

    def catalog_event(self, event):
        f = event.fields
        if event.name == "host-template":
            event.need("template", "image", "abi", "entry", "image_bytes", "image_budget", "stack_budget",
                       "writable_budget", "pages", "config", "restart_limit", "restart_delay", "max_depth",
                       "template_mask", "recipe", "reserved")
            template = f["template"]
            require(template in self.approved and template not in self.catalog, "trusted template catalog duplicates/unapproved entry")
            t = self.approved[template]
            require(tuple(f[key] for key in ("image", "abi", "entry", "image_budget", "stack_budget", "writable_budget",
                    "pages", "config", "restart_limit", "restart_delay", "max_depth", "template_mask", "recipe", "reserved")) ==
                (t["image"], 4, 0x40000000, t["budget"], t["stack"], t["writable"], t["pages"], 24,
                 3, 4, t["depth"], t["mask"], 1, 0), "trusted catalog contradicts independently read sealed template")
            require(0 < f["image_bytes"] <= t["budget"] and f["image_bytes"] == t["image_bytes"],
                    "trusted catalog image extent contradicts tested linked immutable image")
            self.catalog[template] = event
        else:
            event.need("endpoint", "template_mask", "slot_limit", "page_limit", "max_depth", "recipe", "reserved0", "reserved1")
            require(self.catalog_domain is None and tuple(f[key] for key in ("cell", "identity", "endpoint", "template_mask",
                    "slot_limit", "page_limit", "max_depth", "recipe", "reserved0", "reserved1")) ==
                    (3, 400, 0x104, 12, 4, 48, 2, 1, 0, 0),
                    "trusted creator catalog contradicts independently read root authority")
            self.catalog_domain = event

    def ipc(self, event):
        f = event.fields
        packet = Packet.from_event(event)
        endpoint, node = self.principal(event)
        require(host.signed(f["result"]) == 0, "accepted IPC seam reports a failed checked copy/enqueue")
        if event.name == "host-ipc-enqueue":
            require(endpoint not in self.waits, "waiting execution issued user IPC before actual scheduler wake")
            require(endpoint == packet.sender and f["cap"] in self.channels and
                    self.channels[f["cap"]] == (packet.sender, packet.target, packet.operation),
                    "contract enqueue lacks exact holder/target/generation narrow authority")
            target_slot = (packet.target & 255) - 1
            require(target_slot == 3 or 4 <= target_slot <= 7, "contract IPC escaped declared composition")
            if target_slot >= 4:
                target = self.tree.at(target_slot)
                require(target.ready and target.endpoint == packet.target, "contract enqueue targeted retired worker/broker generation")
            require(len(self.queues[packet.target]) < 8, "contract enqueue exceeds bounded kernel FIFO")
            self.queues[packet.target].append(event)
            self.enqueued.append(event)
            self.packet_events[event.index] = packet
            self.sent(event, packet)
        else:
            require(endpoint == packet.target and f["cap"] == 0,
                    "contract copied delivery changed receiver generation or invented an enqueue capability")
            queue = self.queues[packet.target]
            require(queue, "contract delivery lacks actual authenticated enqueue")
            enqueue = queue.pop(0)
            original = Packet.from_event(enqueue)
            require(original == packet and enqueue.index < event.index, "contract delivery changed bytes/sender or FIFO order")
            if node:
                require(endpoint in node.entered and endpoint in node.cold and endpoint in node.memories,
                        "contract processed IPC before ring3 entry/cold private-memory evidence")
            self.delivered.append(event)
            self.packet_events[event.index] = packet
            if packet.operation == 15:
                self.requests_by_key[(packet.sender, packet.request)].append(event)
            if packet.operation == 16 and packet.command == 9:
                require(node is not None and node.template == 3 and packet.sender in self.tree.at((packet.sender & 255) - 1).entered and
                        packet.request == 1 and packet.kind == 1 and packet.detail == 0 and packet.token == 0,
                        "worker bootstrap acknowledgement has counterfeit direction/identity/header")
                worker = self.tree.at((packet.sender & 255) - 1)
                require(worker.template == 4 and worker.parent_instance == node.instance and
                        worker.endpoint == packet.sender and packet.data == worker.instance,
                        "bootstrap acknowledgement names an unrelated worker instance/execution")
                require(packet.sender not in self.bootstrap, "worker bootstrap acknowledgement was duplicated")
                self.bootstrap[packet.sender] = event

    def sent(self, event, packet):
        if packet.operation == 15 and packet.command in (7, 8):
            record = self.obligation(packet.sender, packet.token)
            require(record.state == RUNNING and record.accepted is not None and record.accepted.index < event.index,
                    "worker challenge/fault was sent before explicit exact acceptance")
            require(packet.target == record.execution == record.worker.endpoint and
                    packet.detail == record.attempt and packet.data == record.input and packet.kind == 0,
                    "worker request changed accepted input/profile/current attempt/execution")
            require(packet.request in record.dispatch_reports and record.dispatch_reports[packet.request].index < event.index and
                    record.attempt in record.attempted, "worker request lacks current attempt/dispatch decision")
            require(packet.request > self.last_rpc[packet.sender] and
                    packet.request not in record.dispatches, "worker RPC identity collided or wrapped")
            self.last_rpc[packet.sender] = packet.request
            record.rpc = packet.request
            record.dispatches[packet.request] = (event, packet)
        elif packet.operation == 16:
            if packet.command == 9:
                require(packet.kind == 1 and packet.request == 1 and packet.detail == 0 and packet.token == 0,
                        "worker bootstrap response has malformed fixed fields")
                return
            if packet.command == 7:
                record = self.obligation(packet.target, packet.token)
                require(packet.kind == 1 and record.state == RUNNING and packet.sender == record.execution and
                        packet.detail == record.attempt and packet.request == record.rpc and
                        packet.data == host.calculate(record.input), "worker returned stale/unsolicited/incorrect result")
                require((packet.sender, packet.request) in self.computations and
                        self.computations[(packet.sender, packet.request)].index < event.index,
                        "worker result enqueue has no real ring3 input-sensitive computation")
                return
            broker = self.broker()
            require(packet.sender == broker.endpoint and packet.target == 0x104 and packet.command in range(1, 7),
                    "broker service response came from unrelated requester/issuer scope")
            requests = [request for request in self.delivered if
                        (p := self.packet_events.get(request.index)) is not None and p.operation == 15 and
                        p.sender == packet.target and p.target == packet.sender and
                        p.request == packet.request and p.command == packet.command and request.index < event.index]
            require(requests, "broker response lacks exact authenticated requester transaction/command")
            request = requests[-1]
            if packet.kind == 3:
                require(packet.detail == 0 and 1 <= packet.data <= 10 and packet.token == self.packet_events[request.index].token,
                        "broker error reply claimed undefined status or changed exact requester token")
                require(packet.data == self.request_error(self.packet_events[request.index]),
                        "authoritative service error contradicts independently reconstructed request/state")
                self.errors.append((event, packet, request))
                return
            if packet.kind == 2:
                record = self.obligation(packet.sender, packet.token)
                requested = self.packet_events[request.index]
                require(self.request_error(requested) == 0 and
                        (requested.token == record.token if requested.command != 1 and requested.token != 0 else
                         record.offer_request == (requested.request if requested.command == 1 else requested.data)),
                        "broker snapshot answered a different/stale/mismatched command or contract")
                require(0 <= packet.detail < 8, "snapshot part is outside bounded exact eight-part status")
                key = packet.sender, packet.target, packet.request, packet.command, packet.token
                if packet.detail == 0:
                    require(key not in self.snapshot_groups, "authoritative snapshot restarted/repeated part0")
                    self.snapshot_groups[key] = {"next": 0, "expected": record.snapshot(), "first": event, "record": record}
                require(key in self.snapshot_groups, "authoritative snapshot lacks first part/order")
                group = self.snapshot_groups[key]
                require(packet.detail == group["next"] and packet.data == group["expected"][packet.detail],
                        "authoritative snapshot contradicts independent state/input/issuer/worker/attempt/result/backing")
                if packet.detail == 0:
                    flag_fields(packet.data)
                group["next"] += 1
                if group["next"] == 8:
                    self.snapshots.append((group["first"], event, packet, group["expected"]))
                    del self.snapshot_groups[key]
                return
            require(packet.kind == 1 and packet.command == 6 and packet.detail == 0 and packet.data == 0 and
                    packet.token == self.packet_events[request.index].token and
                    not self.obligation(packet.sender, packet.token, retained=False).retained,
                    "broker response claimed record reap before actual authenticated terminal release")
            self.responses.append((event, packet, request))

    def progress(self, event):
        endpoint, node = self.principal(event)
        f = event.fields
        token, value = event.need("value", "extra")
        event.need("endpoint", "instance", "template", "depth", "parent_endpoint")
        require((f["endpoint"], f["instance"], f["template"], f["depth"], f["parent_endpoint"]) ==
                (endpoint, node.instance if node else 0, node.template if node else 0,
                 node.depth if node else 0, node.parent_endpoint if node else 0),
                "contract progress contradicts authenticated registry instance/template/ancestry")
        if event.name == "contract-complete":
            require(endpoint == 0x104 and token == 24 and value == 0 and not self.live_records and
                    not self.tree.slots and self.tree.ledger() == (0, 0, 0, 0, 4, 48),
                    "contract completion lacks explicit record/worker/broker release and full root reservation return")
            self.completed.append(event)
            return
        if event.name == "contract-reply-lost":
            require(endpoint == 0x104 and value in (1, 5), "lost reply marker has unrelated requester/command")
            snapshots = [snapshot for snapshot in self.snapshots if snapshot[2].request == token and
                         snapshot[2].command == value and snapshot[1].index < event.index]
            require(len(snapshots) == 1, "reply loss lacks exact complete original authoritative response")
            snapshot = snapshots[0]
            replies = [delivery for delivery in self.delivered if
                       (packet := self.packet_events.get(delivery.index)) is not None and packet.kind == 2 and
                       packet.sender == self.broker().endpoint and packet.target == endpoint and
                       packet.request == token and packet.command == value and delivery.index < event.index]
            require([self.packet_events[reply.index].detail for reply in replies] == list(range(8)),
                    "reply loss lacks eight actual authenticated exact-order deliveries to discard")
            self.lost_replies.append((event, snapshot))
            return
        if event.name == "contract-requester-verified":
            require(endpoint == 0x104, "receipt validation came from a different requester generation")
            record = self.obligation(self.broker().endpoint, token)
            require(record.state == COMPLETED and record.verified and value == record.result == host.calculate(record.input),
                    "requester accepted an unverified/nonterminal/wrong-input receipt")
            snapshots = [snapshot for snapshot in self.snapshots if snapshot[0].index > record.terminal.index and
                         snapshot[1].index < event.index and snapshot[2].token == token and
                         snapshot[2].command in (3, 5) and snapshot[3] == record.snapshot()]
            require(snapshots, "requester verification lacks complete authoritative settled status/receipt delivery")
            require(all(any(delivered.index > snapshot[0].index and delivered.index < event.index and
                        self.packet_events.get(delivered.index) == self.packet_events.get(enqueued.index)
                        for delivered in self.delivered)
                        for snapshot in snapshots[-1:] for enqueued in self.enqueued
                        if snapshot[0].index <= enqueued.index <= snapshot[1].index and
                        self.packet_events[enqueued.index].kind == 2),
                    "requester verified snapshots that were only enqueued and never delivered")
            record.requester_checks.append(event)
            return
        require(node is not None and node.template == 3 and endpoint == self.broker().endpoint,
                "contract service progress came from an unrelated execution/template")
        if event.name == "contract-offer":
            slot, serial, encoded_issuer = token_parts(token)
            require(encoded_issuer == endpoint and serial == self.last_serial + 1 and
                    (endpoint, token) not in self.obligations and slot not in self.live_records and
                    len(self.live_records) < 2,
                    "contract issuance reused/exhausted an issuer serial or occupied record")
            offers = [incoming for incoming in self.delivered if
                      (p := self.packet_events.get(incoming.index)) is not None and p.operation == 15 and
                      p.command == 1 and p.kind == 0 and p.sender == node.parent_endpoint and
                      p.target == endpoint and p.request == value and p.detail == 1 and p.token == 0 and
                      incoming.index < event.index]
            require(offers, "backed offer lacks exact authenticated requester/profile/transaction/input")
            incoming, packet = offers[-1], self.packet_events[offers[-1].index]
            require((packet.sender, packet.request) not in self.offer_keys, "duplicate offer allocated a second backing worker")
            children = [worker for worker in self.tree.nodes.values() if worker.retained and worker.template == 4 and
                        worker.parent_instance == node.instance and worker.born > incoming.index and
                        all(other.worker.instance != worker.instance for other in self.obligations.values())]
            require(len(children) == 1, "backed offer lacks exactly one genuinely created unique private worker")
            worker = children[0]
            publication = next(item for item in self.published if item.fields["instance"] == worker.instance)
            require(worker.ready and worker.own_pages == 2 and worker.allowance_slots == worker.allowance_pages == 0 and
                    worker.endpoint in worker.entered and worker.endpoint in worker.cold and worker.endpoint in worker.memories and
                    worker.endpoint in self.bootstrap and self.bootstrap[worker.endpoint].index < event.index,
                    "offer was published without checked live two-page worker and real cold ring3 bootstrap")
            ready_status = [item for item in self.events if item.name == "host-status" and
                            item.fields.get("instance") == worker.instance and item.fields.get("control") == worker.control and
                            item.fields.get("caller_endpoint") == endpoint and item.fields.get("phase") == 1 and
                            item.fields.get("pages") == 2 and publication.index < item.index < event.index]
            require(ready_status, "backed offer lacks actual checked authoritative worker status copy")
            preflight = [item for item in self.events if item.name == "host-domain" and
                         item.fields.get("holder") == endpoint and incoming.index < item.index < worker.born]
            require(preflight and preflight[-1].fields["available_slots"] >= 1 and
                    preflight[-1].fields["available_pages"] >= 2 and publication.index < event.index,
                    "offer lacked actual delegated domain preflight before worker mutation/publication")
            record = Obligation(endpoint, token, packet.sender, packet.request, packet.detail, packet.data,
                                worker, event.index, execution=worker.endpoint)
            record.initial_reports.add(event.name)
            self.obligations[(endpoint, token)] = record
            self.live_records[slot] = record
            self.offer_keys[(packet.sender, packet.request)] = record
            self.offer_highwater[packet.sender] = packet.request
            self.last_serial = serial
            self.maximum_records = max(self.maximum_records, len(self.live_records))
            return
        record = self.obligation(endpoint, token, retained=event.name != "contract-late-rejected")
        if event.name in ("contract-input", "contract-worker", "contract-control", "contract-endpoint"):
            expected = {"contract-input": record.input, "contract-worker": record.worker.instance,
                        "contract-control": record.worker.control, "contract-endpoint": record.execution}[event.name]
            require(record.state == OFFERED and event.name not in record.initial_reports and value == expected,
                    "offered input/worker/control/execution binding duplicates or contradicts actual backing")
            record.initial_reports.add(event.name)
        elif event.name == "contract-accepted":
            require(record.state == OFFERED and value == record.input and len(record.initial_reports) == 5,
                    "acceptance changed input, reused terminal state, or preceded complete backed offer")
            accepts = [incoming for incoming in self.delivered if
                       (p := self.packet_events.get(incoming.index)) is not None and
                       p.sender == record.owner and p.target == endpoint and p.operation == 15 and
                       p.command == 2 and p.kind == 0 and p.detail == record.profile and
                       p.token == token and p.data == record.input and record.born < incoming.index < event.index]
            require(accepts, "work acceptance lacks exact authenticated owner/profile/input/contract delivery")
            worker = record.worker
            require(worker.ready and worker.own_pages == 2 and worker.endpoint == record.execution and
                    any(item.name == "wait-arm" and item.fields["cell"] == worker.slot and
                        item.fields["generation"] == worker.endpoint >> 8 and
                        worker.born < item.index < event.index for item in self.events),
                    "unaccepted worker did not wait with actual retained private backing")
            record.state, record.attempt, record.accepted = RUNNING, 1, event
        elif event.name == "contract-dispatch":
            require(record.state == RUNNING and value > 0 and value not in record.dispatch_reports,
                    "duplicate/terminal/preaccept work dispatch")
            record.rpc = value
            record.dispatch_reports[value] = event
        elif event.name == "contract-attempt":
            require(record.state == RUNNING and value == record.attempt and value not in record.attempted,
                    "contract attempt identity collided or exceeded one retry")
            record.attempted.add(value)
        elif event.name == "contract-validated":
            require(record.state == RUNNING and record.validation is None and value == host.calculate(record.input),
                    "independent broker validation repeated or accepted wrong/terminal input result")
            replies = [incoming for incoming in self.delivered if
                       (p := self.packet_events.get(incoming.index)) is not None and p.operation == 16 and
                       p.command == 7 and p.kind == 1 and p.sender == record.execution and p.target == endpoint and
                       p.token == token and p.detail == record.attempt and p.request == record.rpc and
                       p.data == value and incoming.index < event.index]
            require(len(replies) == 1, "broker validation lacks unique actual authenticated current-attempt worker result delivery")
            require(record.rpc in record.dispatches and record.worker.ready and record.worker.own_pages == 2,
                    "broker verified an unexecuted or prematurely destroyed backing worker")
            record.validation, record.verified, record.result = event, True, value
        elif event.name == "contract-recovering":
            require(record.state == RUNNING and record.retries == 0 and record.attempt == 1 and value == record.execution,
                    "recovery changed stable contract or exceeded retry policy")
            worker = record.worker
            require(worker.last_fault is not None and worker.last_fault.index < event.index and
                    worker.last_fault.fields["endpoint"] == value and worker.own_pages == 2 and worker.retained and
                    worker.rebind_required and ((worker.phase == 2 and not worker.ready and worker.endpoint == value) or
                    (worker.phase == 1 and worker.ready and worker.endpoint >> 8 > value >> 8)),
                    "recovery was announced without real fault/nonrunnable retained backing/backoff")
            record.state = RECOVERING
            record.faults.append(worker.last_fault)
        elif event.name == "contract-rebound":
            require(record.state == RECOVERING and record.retries == 0,
                    "rebind revived terminal contract or exceeded recovery policy")
            worker = record.worker
            require(value == worker.endpoint and value != record.execution and worker.ready and not worker.rebind_required and
                    worker.restarts == 1 and worker.own_pages == 2 and
                    any(item.fields["instance"] == worker.instance and item.fields["control"] == worker.control and
                        item.fields["endpoint"] == value and item.index < event.index for item in self.rebound),
                    "retry lacks stable logical/control continuity, cold bootstrap and explicit fresh authority rebind")
            record.state, record.retries, record.attempt, record.execution = RUNNING, 1, 2, value
            record.rebinds.append(event)
        elif event.name == "contract-terminal":
            flags = flag_fields(value)
            state, profile, retries, attempt, reason, slots, pages, verified = flags
            require(state in TERMINAL and record.state not in TERMINAL and
                    (profile, retries, attempt, slots, pages) == (record.profile, record.retries, record.attempt, 0, 0),
                    "terminal publication contradicted state/profile/retry/attempt/resource settlement")
            worker = record.worker
            require(not worker.retained and not worker.ready and worker.own_pages == 0 and
                    worker.instance in self.returned and worker.endpoint not in self.waits and
                    not any(worker.endpoint in grant[:2] for grant in self.channels.values()) and
                    any(item.name == "host-reap" and item.fields["instance"] == worker.instance and
                        item.index < event.index for item in self.events),
                    "contract terminal publication preceded actual nonrunnable stop/private-page return/control reap")
            stops = [item for item in self.events if item.name == "host-stop" and
                     item.fields.get("instance") == worker.instance and item.index < event.index]
            reaps = [item for item in self.events if item.name == "host-reap" and
                     item.fields.get("instance") == worker.instance and item.index < event.index]
            require(len(stops) == len(reaps) == 1 and any(item.name == "host-status" and
                    item.fields.get("instance") == worker.instance and item.fields.get("control") == worker.control and
                    item.fields.get("phase") == 4 and item.fields.get("pages") == 0 and
                    stops[0].index < item.index < reaps[0].index for item in self.events),
                    "terminal resource return lacks actual authoritative stopped/zero-page status before control reap")
            require(any(call.fields["call"] == 14 and call.fields["arg0"] == worker.control and
                        host.signed(call.fields["result"]) == -3 and call.index < event.index for call in self.calls),
                    "worker control remained queryable after purported lifecycle reap")
            if state == COMPLETED:
                require(record.validation is not None and record.validation.index < event.index and verified == 1 and reason == 0,
                        "completed receipt lacks independent validation before exact resource settlement")
                if record.retries:
                    self.recovery_intervals.append((record.faults[0], event, record))
            elif state == CANCELLED:
                cancels = [incoming for incoming in self.delivered if
                           (p := self.packet_events.get(incoming.index)) is not None and p.operation == 15 and
                           p.command == 4 and p.sender == record.owner and p.target == endpoint and p.token == token and
                           incoming.index < event.index]
                require(cancels and reason == 1 and verified == 0 and not record.verified,
                        "cancelled state lacks authenticated owner cancellation or revived a checked result")
                if record.accepted is None:
                    require(not record.dispatches and not record.dispatch_reports and record.attempt == 0,
                            "cancelled offered worker executed without acceptance")
            else:
                require(reason in range(2, 9) and verified == 0, "failed outcome has undefined reason or receipt")
            record.state, record.reason, record.terminal = state, reason, event
            require(record.flags() == flags, "authoritative terminal flag word contradicts reconstructed obligation")
        elif event.name == "contract-reaped":
            slot, serial, encoded_issuer = token_parts(token)
            require(record.state in TERMINAL and value == serial and record.terminal.index < event.index and
                    self.live_records.get(slot) is record,
                    "service record silently freed/reused without exact terminal metadata retention")
            requests = [incoming for incoming in self.delivered if
                        (p := self.packet_events.get(incoming.index)) is not None and p.operation == 15 and
                        p.command == 6 and p.sender == record.owner and p.target == endpoint and p.token == token and
                        record.terminal.index < incoming.index < event.index]
            require(requests, "contract record reap lacks authenticated owner command")
            record.retained = False
            del self.live_records[slot]
            self.reaped_records.append(event)
        elif event.name == "contract-deferred":
            require(token not in self.deferred, "private late-result slot was overwritten")
            self.deferred[token] = event
            require(record.state == RUNNING and value == record.rpc,
                    "privately deferred result has wrong active contract/RPC")
            require(any((p := self.packet_events.get(incoming.index)) is not None and p.operation == 16 and
                        p.command == 7 and p.sender == record.execution and p.target == endpoint and p.token == token and
                        p.detail == record.attempt and p.request == value and incoming.index < event.index
                        for incoming in self.delivered),
                    "private inbox marker lacks actual already-dequeued authenticated worker result")
        elif event.name == "contract-late-rejected":
            require(record.state in (CANCELLED, FAILED, RECOVERING) and value in record.dispatches,
                    "late-result rejection names live-successful or never-dispatched contract")
            require(token in self.deferred and self.deferred[token].index < event.index,
                    "late-result rejection lacks actual already-dequeued private result")
            if record.state in (CANCELLED, FAILED):
                require(record.terminal is not None and self.deferred[token].index < record.terminal.index < event.index,
                        "cancel/failure precedence lacks private result before terminal cleanup")
            else:
                require(record.faults and record.faults[-1].index < event.index and
                        record.execution in self.tree.dead, "recovering contract accepted an unretired attempt result")
            self.late.append(event)
        else:
            raise AssertionError("unknown contract progress event " + event.name)

    def app(self, event):
        if event.name != "host-kernel-entry":
            endpoint, node = self.principal(event)
            require(endpoint not in self.waits, "waiting execution emitted application progress before actual scheduler wake")
            f = event.fields
            event.need("endpoint", "instance", "template", "depth", "parent_endpoint")
            require((f["endpoint"], f["instance"], f["template"], f["depth"], f["parent_endpoint"]) ==
                    (endpoint, node.instance if node else 0, node.template if node else 0,
                     node.depth if node else 0, node.parent_endpoint if node else 0),
                    "application progress contradicts authenticated execution/instance/template/ancestry")
        if event.name == "host-kernel-entry":
            endpoint, node = self.principal(event)
            f = event.fields
            event.need("endpoint", "instance", "control", "template", "depth", "parent_endpoint",
                       "cs", "ss", "rip", "rsp", "rflags", "vector")
            require(node is not None and endpoint not in self.kernel_entries and
                    (f["endpoint"], f["instance"], f["control"], f["template"], f["depth"], f["parent_endpoint"]) ==
                    (endpoint, node.instance, node.control, node.template, node.depth, node.parent_endpoint),
                    "hardware entry counterfeited current published execution/control/ancestry")
            template = self.approved[node.template]
            require(f["cs"] == 0x1b and f["ss"] == 0x23 and f["vector"] in (32, 128) and
                    0x40000000 <= f["rip"] < 0x40000000 + self.catalog[node.template].fields["image_bytes"] and
                    0x40020000 <= f["rsp"] < 0x40020000 + template["stack"] and
                    f["rflags"] & 0x202 == 0x202 and f["rflags"] & 0x27400 == 0 and
                    f["rflags"] & ~RFLAGS_DOCUMENTED == 0,
                    "first actual hardware trap lacks checked ring3 immutable-code/private-stack/general-register frame")
            self.kernel_entries.add(endpoint)
            return
        if event.name == "host-entry":
            endpoint, node = self.principal(event)
            require(endpoint in self.kernel_entries, "application entry marker lacks prior actual ring3 hardware entry")
        if event.name in REPORTS:
            return self.progress(event)
        if event.name == "host-computed":
            endpoint, node = self.principal(event)
            require(node is not None and node.template == 4, "contract computation came from a different role/template")
            rpc, result = event.need("value", "extra")
            received = [incoming for incoming in self.delivered if
                        (p := self.packet_events.get(incoming.index)) is not None and p.operation == 15 and
                        p.command == 7 and p.target == endpoint and p.request == rpc and incoming.index < event.index]
            require(len(received) == 1, "worker computed without unique actual challenge delivery")
            packet = self.packet_events[received[0].index]
            record = self.obligation(packet.sender, packet.token)
            require(record.state == RUNNING and record.accepted is not None and record.accepted.index < received[0].index and
                    result == host.calculate(record.input) and packet.data == record.input and packet.detail == record.attempt and
                    record.execution == endpoint and endpoint in self.bootstrap and (endpoint, rpc) not in self.computations,
                    "worker computed before acceptance, twice, or under stale/wrong attempt/input")
            self.computations[(endpoint, rpc)] = event
            return
        if event.name == "host-sleep-start":
            endpoint, node = self.principal(event)
            duration, reported_endpoint = event.need("value", "extra")
            require(node is not None and node.template == 4 and reported_endpoint == endpoint and
                    1 <= duration <= 1000 and endpoint not in self.worker_sleeps,
                    "worker sleep changed execution or duplicated an active bounded wait")
            requests = [entry for entry in self.delivered if
                        (packet := self.packet_events.get(entry.index)) is not None and packet.operation == 15 and
                        packet.command == 7 and packet.target == endpoint and entry.index < event.index]
            require(requests, "worker sleep preceded accepted current-attempt challenge delivery")
            self.worker_sleeps[endpoint] = (event, duration)
            return
        if event.name == "host-sleep-return":
            endpoint, node = self.principal(event)
            sentinel, duration = event.need("value", "extra")
            require(endpoint in self.worker_sleeps and sentinel == host.MEMORY_SALT ^ endpoint,
                    "worker bounded sleep lost private execution sentinel or lacked original wait")
            start, original_duration = self.worker_sleeps.pop(endpoint)
            require(duration == original_duration and any(receiver == endpoint and state["kind"] == 1 and
                    state["deadline"] - state["tick"] == duration and wake.name == "wake" and
                    start.index < state["index"] < wake.index < event.index for wake, state, receiver in self.wakes),
                    "worker sleep return contradicted actual preserved deadline/timed hardware wake")
            self.worker_sleep_returns.append(event)
            return
        if event.name == "host-copied":
            endpoint, node = self.principal(event)
            capability, outcome = event.need("value", "extra")
            require(node is not None and node.template == 4 and host.signed(outcome) == -2 and
                    self.channels.get(capability) == (endpoint, node.parent_endpoint, 16),
                    "worker converted knowledge of a contract into requester authority")
            rejected = [entry for entry in self.ipc_rejected if entry.fields["cell"] == node.slot and
                        entry.fields["generation"] == endpoint >> 8 and entry.fields["cap"] == capability and
                        entry.fields["target"] == node.parent_endpoint and host.signed(entry.fields["result"]) == -2 and
                        entry.index < event.index]
            require(rejected, "wrong-owner ACCEPT denial lacks actual checked narrow capability rejection")
            packet = Packet.from_event(rejected[-1])
            require(packet.sender == endpoint and packet.command == 2 and packet.operation == 15 and packet.kind == 0 and
                    packet.detail == 1 and any((received := self.packet_events.get(entry.index)) is not None and
                        received.operation == 15 and received.command == 7 and received.target == endpoint and
                        received.token == packet.token and received.data == packet.data and received.request == packet.request and
                        entry.index < rejected[-1].index for entry in self.delivered),
                    "worker owner probe lacks exact actual accepted challenge/reference/input scope")
            self.copy_denials.append(event)
            return
        if event.name == "host-denied":
            endpoint, node = self.principal(event)
            check, outcome = event.need("value", "extra")
            expected = {101: 4, 102: 2, 103: 2, 104: 2, 105: 4, 106: 3, 107: 10, 108: 3}
            require(endpoint == 0x104 and check in expected and outcome == expected[check],
                    "requester negative case claimed wrong defined service rejection")
            require(self.errors and self.errors[-1][1].data == outcome and self.errors[-1][0].index < event.index and
                    any(self.packet_events.get(delivery.index) == self.errors[-1][1] and delivery.index < event.index
                        for delivery in self.delivered), "service denial marker lacks actual authenticated error delivery")
            self.denied.append(event)
            return
        if event.name == "host-timeout":
            endpoint, node = self.principal(event)
            duration, outcome = event.need("value", "extra")
            require(node is not None and 1 <= duration <= 1000 and host.signed(outcome) == -8 and
                    any(receiver == endpoint and state["kind"] == 2 and state["deadline"] - state["tick"] == duration and
                        wake.name == "wake" and host.signed(wake.fields["result"]) == -8 and wake.index < event.index
                        for wake, state, receiver in self.wakes), "contract timeout lacks actual finite receive arm/timed wake")
            self.timeouts.append(event)
            return
        if event.name == "host-stale" and event.fields["cell"] >= 4:
            # Shared observer's historical scenarios use root400 for this proof.
            # Contract broker is the actual holder of the retired worker channel.
            endpoint, node = self.principal(event)
            old, outcome = event.need("value", "extra")
            require(node.template == 3 and host.signed(outcome) == -3 and
                    (old in self.tree.dead or old in self.capabilities_seen or
                     any(worker.control == old and not worker.retained for worker in self.tree.nodes.values())),
                    "broker stale marker names a still-live or invented authority")
            if old in self.tree.dead:
                proof = [item for item in self.ipc_rejected if item.fields["cell"] == node.slot and item.index < event.index and
                         item.fields["target"] == old and host.signed(item.fields["result"]) == -3]
            elif any(worker.control == old and not worker.retained for worker in self.tree.nodes.values()):
                proof = [item for item in self.calls if item.fields["cell"] == node.slot and item.index < event.index and
                         item.fields["call"] in (14, 16) and item.fields["arg0"] == old and host.signed(item.fields["result"]) == -3]
            else:
                require(old not in self.channels, "broker stale claim names still-live kernel capability authority")
                proof = [item for item in self.ipc_rejected if item.fields["cell"] == node.slot and item.index < event.index and
                         item.fields["cap"] == old and item.fields["target"] not in self.tree.dead and
                         host.signed(item.fields["result"]) == -3]
            require(proof, "broker stale authority claim lacks actual checked exact endpoint/control/capability rejection")
            for rejection in (item for item in proof if item.name == "host-ipc-reject"):
                packet = Packet.from_event(rejection)
                require(packet.sender == endpoint and packet.operation == 15 and packet.command == 7 and
                        packet.kind == 0 and packet.detail == 1 and packet.request == MASK64 and packet.data == 1,
                        "stale-channel probe changed its actual checked bounded payload")
            self.stale.append(event)
            return
        if event.name == "host-reaped":
            endpoint, node = self.principal(event)
            control, instance = event.need("value", "extra")
            require((endpoint == 0x104 or (node is not None and node.template == 3)) and
                    any(worker.control == control and worker.instance == instance and not worker.retained and
                        worker.parent_endpoint == endpoint for worker in self.tree.nodes.values()),
                    "owner claimed worker/broker reap without actual direct-owner control release")
            require(not any(previous.fields["value"] == control for previous in self.reap_reports),
                    "owner published duplicate lifecycle reap progress")
            self.reap_reports.append(event)
            return
        super().app(event)

    def creation(self, event):
        f = event.fields
        kind = event.name.removeprefix("host-")
        require(f["deadline"] == f["queued"] == f["retired_pages"] == 0 and f["retained"] == 1 and
                f["reason"] == 0 and host.signed(f["result"]) == 0,
                "authoritative creation stage contradicts unpublished/live retention or invents retirement")
        require(f["phase"] == (1 if kind in ("request", "publish", "result") else 0),
                "authoritative creation caller/publication phase contradicts actual runnable boundary")
        if kind == "request":
            endpoint, caller = self.principal(event)
            require((f["template"] == 3 and endpoint == 0x104 and
                     (f["requested_slots"], f["requested_pages"]) == (2, 4)) or
                    (f["template"] == 4 and caller is not None and caller.template == 3 and
                     (f["requested_slots"], f["requested_pages"]) == (0, 0)),
                    "actual native profile broker/worker requested allowance differs from fixed two-slot/four-page backing")
            require(f["cell"] == f["caller"] and f["endpoint"] == f["caller_endpoint"] == endpoint and
                    f["identity"] == f["caller_identity"] and f["instance"] == (caller.instance if caller else 0) and
                    f["control"] == (caller.control if caller else 0) and f["parent_endpoint"] == endpoint and
                    f["parent_instance"] == (caller.parent_instance if caller else 0) and
                    f["depth"] == (caller.depth if caller else 0) and
                    f["image"] == (self.approved[caller.template]["image"] if caller else self.roots[f["cell"]]["image"]) and
                    f["pages"] == (caller.own_pages if caller else self.roots[f["cell"]]["pages"]) and
                    f["reserved_slots"] == (caller.allowance_slots if caller else 0) and
                    f["reserved_pages"] == (caller.allowance_pages if caller else 0) and
                    f["creation"] == (caller.creation if caller else 0) and f["transaction"] == 0 and f["child_cap"] == 0,
                    "creation input seam contradicts its actual authenticated requester registry")
        item = self.transactions.get((f["caller_endpoint"], f["request"]))
        if kind not in ("request", "reserve"):
            require(item is not None and f["transaction"] == item["transaction"],
                    "creation stage changed its actual prepared transaction object")
        if kind == "reserve":
            require((f["template"], f["pages"], f["reserved_slots"], f["reserved_pages"]) in
                    ((3, 4, 2, 4), (4, 2, 0, 0)),
                    "actual native profile created different private/delegated resource commitments")
        if kind in ("reserve", "space"):
            require(f["parent_cap"] == f["child_cap"] == 0,
                    "unpublished creation stage claimed channels before narrow authority installation")
        if kind == "result":
            require(item is not None and f["parent_cap"] == item["node"].parent_cap and
                    f["child_cap"] == item["node"].child_cap,
                    "actual checked creation output copied different bootstrap capabilities")
        super().creation(event)

    def copied_fields(self, event, endpoint):
        f, number = event.fields, event.fields["call"]
        if number not in (13, 14, 17, 19):
            return
        event.need("output_copied")
        require(f["output_copied"] == int(f["result"] == 0),
                "management return contradicted actual successful/failed private output copy")
        if number in (13, 17):
            keys = ("input_copied", "input_authority", "input_request", "input_reserved")
            event.need(*keys)
            require(f["input_copied"] == 1 and f["input_reserved"] == 0,
                    "creation/rebind lacked exact checked private input or accepted reserved bytes")
            if number == 13:
                event.need("input_template", "input_slots", "input_pages")
                requests = [item for item in self.requests if item.fields["caller_endpoint"] == endpoint and item.index < event.index]
                require(requests, "actual input copy lacks authenticated lifecycle creation request")
                request = requests[-1].fields
                require(tuple(f[key] for key in ("input_authority", "input_request", "input_template", "input_slots", "input_pages")) ==
                        tuple(request[key] for key in ("parent_cap", "request", "template", "requested_slots", "requested_pages")),
                        "actual copied CREATE input contradicts authority/request/template/resource preparation")
                results = [item for item in self.events if item.name == "host-result" and
                           item.fields.get("caller_endpoint") == endpoint and item.index < event.index]
            else:
                event.need("input_control")
                results = [item for item in self.rebound if item.fields["caller_endpoint"] == endpoint and item.index < event.index]
                require(results, "actual copied REBIND input lacks checked current-generation lifecycle provisioning")
                rebound = results[-1].fields
                parent = self.tree.node(rebound["parent_instance"]) if rebound["parent_instance"] else None
                authority = parent.creation if parent else self.root_domain
                require((f["input_authority"], f["input_control"], f["input_request"]) ==
                        (authority, rebound["control"], rebound["request"]),
                        "actual copied REBIND input changed exact live-domain/control/request identity")
            keys = ("instance", "control", "endpoint", "channel", "creation", "slot", "identity")
            event.need(*(f"output_{key}" for key in keys))
            if f["result"] == 0:
                require(results, "successful checked output lacks actual lifecycle publication")
                result = results[-1].fields
                wanted = tuple(result[key] for key in ("instance", "control", "endpoint", "parent_cap", "creation", "cell", "identity"))
                require(tuple(f[f"output_{key}"] for key in keys) == wanted,
                        "actual copied CREATE/REBIND output contradicts published logical/control/execution/channel/private identity")
            else:
                require(not any(f[f"output_{key}"] for key in keys), "failed output copy manufactured lifecycle handles")
        elif number == 14:
            keys = ("instance", "control", "endpoint", "domain", "parent_instance", "parent_endpoint", "generation", "slot",
                    "template", "depth", "phase", "faults", "restarts", "reason", "own_pages", "reserved_slots",
                    "reserved_pages", "available_slots", "available_pages")
            event.need(*(f"output_{key}" for key in keys))
            if f["result"] != 0:
                require(not any(f[f"output_{key}"] for key in keys), "failed STATUS output copy manufactured live/settled state")
                return
            nodes = [node for node in self.tree.nodes.values() if node.control == f["arg0"] and node.retained]
            require(len(nodes) == 1, "copied STATUS used unknown/reaped control")
            node = nodes[0]
            ledger = self.tree.ledger(node.instance)
            wanted = (node.instance, node.control, node.endpoint if node.ready else 0, node.creation,
                      node.parent_instance, node.parent_endpoint, node.endpoint >> 8, node.slot, node.template, node.depth,
                      node.phase, node.faults, node.restarts, getattr(node, "observed_reason", 0), node.own_pages,
                      node.allowance_slots, node.allowance_pages, ledger[4], ledger[5])
            require(tuple(f[f"output_{key}"] for key in keys) == wanted,
                    "actual copied STATUS contradicts authoritative phase/generation/control/private allocation/resource ledger")
        else:
            keys = ("domain", "holder", "instance", "slot_limit", "page_limit", "owned_slots", "owned_pages",
                    "reserved_slots", "reserved_pages", "available_slots", "available_pages", "max_depth", "template_mask", "recipe", "revoked")
            event.need(*(f"output_{key}" for key in keys))
            if f["result"] != 0:
                require(not any(f[f"output_{key}"] for key in keys), "failed DOMAIN output copy manufactured capacity")
                return
            require(f["arg0"] in self.domains, "copied DOMAIN output used unknown authority")
            domain = self.domains[f["arg0"]]
            ledger = self.tree.ledger(domain["instance"])
            wanted = (f["arg0"], endpoint, domain["instance"], domain["slots"], domain["pages"],
                      ledger[0], ledger[1], ledger[2], ledger[3], ledger[4], ledger[5], domain["max_depth"],
                      domain["mask"], domain["recipe"], int(domain["revoked"]))
            require(tuple(f[f"output_{key}"] for key in keys) == wanted,
                    "actual copied DOMAIN output contradicts sealed entitlement/conserved actual resource ownership")

    def checked_call(self, event):
        endpoint, node = self.principal(event)
        f = event.fields
        event.need("call", "arg0", "arg1", "arg2", "result", "caller_endpoint")
        require(f["caller_endpoint"] == endpoint, "management copy return changed authenticated caller endpoint")
        self.copied_fields(event, endpoint)
        require((endpoint == 0x104 or node is not None) and f["call"] in range(13, 20) and
                -8 <= host.signed(f["result"]) <= 0, "hosting call has unknown owner/syscall/result")
        if host.signed(f["result"]) != 0:
            return
        layout = self.approved[node.template] if node else self.roots[f["cell"]]
        ranges = ((0x40020000, layout["stack"]), (0x40030000, layout["writable"] - layout["stack"]))
        def owned(address, length):
            return address <= MASK64 - length and any(base <= address and address + length <= base + extent
                                                       for base, extent in ranges)
        if f["call"] in (13, 17):
            require(f["arg1"] == 32 and owned(f["arg0"], 32) and owned(f["arg2"], 48),
                    "successful creation/rebind lacks actual checked private input/output copy extent")
        elif f["call"] == 14:
            require(f["arg2"] == 104 and owned(f["arg1"], 104),
                    "successful lifecycle STATUS copied to unowned/null/overflow private output")
        elif f["call"] == 19:
            require(f["arg2"] == 72 and owned(f["arg1"], 72),
                    "successful DOMAIN STATUS copied to unowned/null/overflow private output")
        else:
            require(f["arg1"] == f["arg2"] == 0, "scalar lifecycle syscall accepted unknown extra arguments")

    def lifecycle(self, event):
        f = event.fields
        node = self.tree.node(f["instance"])
        kind = event.name.removeprefix("host-")
        require(f["transaction"] == 0 and (f["request"] > 0 if kind == "rebind" else f["request"] == 0),
                "authoritative lifecycle event invented a creation transaction/request")
        require(f["retained"] == (0 if kind == "reap" else 1),
                "authoritative lifecycle retention contradicts actual logical control/backing lifetime")
        require(host.signed(f["result"]) == 0 or kind == "fault",
                "authoritative checked lifecycle state claims a failed operation")
        if kind in ("fault", "backoff", "restart", "cancel", "invalidate", "cleanup", "return"):
            expected_caller = f["generation"] * 256 + node.slot + 1 if kind == "restart" else node.endpoint
            require(f["caller"] == node.slot and f["caller_endpoint"] == expected_caller and
                    f["caller_identity"] == node.identity and f["parent_cap"] == f["child_cap"] == 0,
                    "subtree cleanup/restart seam changed its actual affected execution or invented authority")
        if kind == "invalidate":
            require(f["retired_pages"] == 0, "generation/grant invalidation manufactured a physical page refund")
        if kind == "rebind":
            require(f["phase"] == 1, "fresh rebind published authority for an authoritative nonrunnable execution")
        if kind in ("stop", "reap", "restart", "rebind"):
            require(f["deadline"] == 0, "ready/stopped/reaped execution retained an authoritative restart deadline")
        if kind not in ("invalidate", "cleanup", "return"):
            require(f["queued"] == f["retired_pages"] == 0,
                    "lifecycle status/control stage manufactured a queued message or page refund")
        if kind in ("cleanup", "return"):
            require(f["queued"] == 0, "post-invalidation cleanup retained target kernel traffic")
        reason = getattr(node, "observed_reason", 0)
        if kind == "restart":
            require(f["endpoint"] == f["generation"] * 256 + node.slot + 1,
                    "authoritative restart endpoint contradicts actual generation/slot")
        if kind == "backoff":
            require(node.last_fault is not None, "backoff status lacks actual fault reason")
            reason = 0x10000 | node.last_fault.fields["result"]
        require(f.get("reason") == reason, "authoritative lifecycle reason contradicts actual fault/stop history")
        if kind == "return":
            require(f["pages"] == self.approved[node.template]["pages"], "resource return changed actual private allocation extent")
        else:
            require(f["pages"] == node.own_pages and f["reserved_slots"] == node.allowance_slots and
                    f["reserved_pages"] == node.allowance_pages and f["creation"] == node.creation,
                    "authoritative lifecycle allocation/reservation contradicts actual owned backing")
        if kind == "status":
            require(f["parent_cap"] == node.control and f["child_cap"] == (node.endpoint if node.ready else 0) and
                    f["retired_pages"] == f["transaction"] == f["request"] == f["queued"] == 0 and f["retained"] == 1,
                    "authoritative copied worker status changed control/endpoint or invented a resource transaction")
        elif kind == "stop":
            require(f["parent_cap"] == node.control and f["child_cap"] == f["retired_pages"] == 0,
                    "checked stop used a different worker control or claimed premature refund")
        elif kind == "reap":
            require(f["parent_cap"] == node.control and f["child_cap"] == 0 and f["phase"] == f["deadline"] == 0 and
                    f["retired_pages"] == 0 and f["retained"] == 0,
                    "checked lifecycle reap retained runnable/backoff/resources or changed control")
        super().lifecycle(event)
        if kind == "backoff":
            node.observed_reason = reason
        elif kind == "return":
            node.observed_reason = 2

    def run(self):
        for event in self.events:
            f = event.fields
            if event.name in ("host-template", "host-root-domain"):
                require(not self.published, "sealed catalog authority appeared after runtime mutation")
                self.catalog_event(event)
                continue
            event.need("cell", "identity", "generation", "tick")
            require(f["tick"] >= self.last_tick, "contract structured trace tick went backwards")
            self.last_tick = f["tick"]
            if event.name == "boot":
                slot = f["cell"]
                if slot >= 4:
                    endpoint, node = self.principal(event)
                    require(node is not None and any(item.fields["instance"] == node.instance and
                            item.fields["generation"] == f["generation"] for item in self.restarts),
                            "contract worker prestarted or restarted without privileged lifecycle")
                    event.need("physical_pages", *[f"p{i}" for i in range(node.own_pages)])
                    require(f["physical_pages"] == node.own_pages and
                            tuple(f[f"p{i}"] for i in range(node.own_pages)) == node.pages_owned and
                            f.get("image") == self.approved[node.template]["image"] and f.get("abi") == 4 and
                            f.get("entry") == 0x40000000, "contract restart changed retained private/image identity")
                    continue
                require(slot in self.roots and slot not in self.root_boots and
                        (f["identity"], f["generation"], f.get("abi"), f.get("entry"), f.get("image")) ==
                        (ROOT_IDS[slot], 1, 4, 0x40000000, slot + 1),
                        "contract boot changed original root diagnostic/execution/image identity")
                event.need("image_budget", "writable_budget", "config")
                require((f["image_budget"], f["writable_budget"], f["config"]) ==
                        (65536, self.roots[slot]["writable"], self.roots[slot]["config"]),
                        "trusted original boot allocation/configuration contradicts sealed manifest")
                count = self.roots[slot]["pages"]
                event.need("physical_pages", *[f"p{i}" for i in range(count)])
                require(f["physical_pages"] == count, "original root private reservation changed")
                for page in (f[f"p{i}"] for i in range(count)):
                    require(0 <= page < 128 and page not in self.tree.page_owners,
                            "contract root physical page overlaps another private allocation")
                    self.tree.page_owners[page] = -(slot + 1)
                self.root_boots[slot] = event
            elif event.name.startswith("host-") and event.name.removeprefix("host-") in host.MANAGEMENT:
                require(len(self.root_boots) == 4 and set(self.catalog) == {3, 4} and self.catalog_domain is not None,
                        "contract management ran without original roots and sealed catalog authority")
                if event.name in ("host-request", "host-reserve", "host-space", "host-channel", "host-publish",
                                  "host-abort", "host-result"):
                    self.creation(event)
                    if event.name == "host-space":
                        event.need("ss", "rflags")
                        require(f["ss"] == 0x23 and f["rflags"] == 0x202,
                                "worker creation prepared an unsafe ring3 frame")
                elif event.name == "host-revoke":
                    raise AssertionError("dedicated contract scenario unexpectedly revoked composition creation policy")
                else:
                    if event.name == "host-fault":
                        affected = self.tree.node(f["instance"])
                        siblings = [record for record in self.obligations.values() if record.state == RUNNING and
                                    record.worker.instance != affected.instance]
                        require(len(siblings) == 1, "worker recovery did not preserve one independent active contract")
                        sibling = siblings[0]
                        self.fault_preservation.append((event, affected, sibling,
                            sibling.worker.endpoint, sibling.worker.control, sibling.worker.pages_owned,
                            {cap: grant for cap, grant in self.channels.items() if sibling.worker.endpoint in grant[:2]},
                            dict(self.waits.get(sibling.worker.endpoint, {}))))
                    self.lifecycle(event)
                    if event.name == "host-restart":
                        event.need("ss", "rflags")
                        require(f["ss"] == 0x23 and f["rflags"] == 0x202,
                                "cold restart prepared an unsafe ring3 frame")
            elif event.name == "host-domain":
                self.domain_status(event)
            elif event.name in ("host-ipc-enqueue", "host-ipc-deliver"):
                self.ipc(event)
            elif event.name == "host-ipc-reject":
                self.principal(event)
                require(host.signed(f.get("result", 0)) < 0, "contract IPC rejection claimed successful outcome")
                self.ipc_rejected.append(event)
            elif event.name == "host-call":
                self.checked_call(event)
                self.calls.append(event)
            elif event.name.startswith("host-") or event.name in REPORTS:
                self.app(event)
            elif event.name == "entry":
                endpoint, node = self.principal(event)
                require(node is None and endpoint in (0x101, 0x102, 0x103, 0x104),
                        "generic entry marker cannot substitute for dynamic ring3 hardware frame evidence")
                self.kernel_entries.add(endpoint)
            elif event.name in ("wait-arm", "wake", "wait-cancel"):
                self.wait(event)
            elif event.name in ("fault", "exit", "quarantine"):
                require(f["cell"] >= 4, "native contract scenario faulted/restarted an independent original root")
                if event.name == "fault":
                    self.principal(event)
                    event.need("reason", "error", "address")
                    self.hardware_faults.append(event)
            elif event.name == "cap-delegate":
                endpoint, _ = self.principal(event)
                require(endpoint == 0x102 and f.get("holder") == 0x103 and f.get("target") == 0x102 and
                        f.get("rights") == 4 and f.get("cap", 0) > 0,
                        "preserved storage root delegation escaped exact original narrow scope")
                epoch = f["cap"] >> 8
                require(1 <= f["cap"] & 255 <= 32 and epoch > self.maximum_capability_epoch and epoch not in self.capability_epochs,
                        "storage delegation reused/collided with kernel IPC mint epoch")
                self.capability_epochs.add(epoch)
                self.capabilities_seen.add(f["cap"])
                self.maximum_capability_epoch = epoch
                event.need("parent")
                require(f["parent"] in self.root_capabilities and self.root_capabilities[f["parent"]] ==
                        (0x102, 0x102, 0x80000004), "storage delegation lacks its sealed current holder/target/delegation parent")
                self.root_capabilities[f["cap"]] = (f["holder"], f["target"], f["rights"])
            elif event.name == "cap-revoke":
                endpoint, _ = self.principal(event)
                require(endpoint == 0x102, "contract cell revoked an independent root storage grant")
            elif event.name.startswith("storage-") or event.name.startswith("hosting-storage-") or event.name in (
                    "healthy-memory", "reset-memory", "idle", "idle-enter", "idle-exit", "idle-wake"):
                if event.name == "storage-ipc":
                    endpoint, node = self.principal(event)
                    event.need("cap", "target", "operation")
                    require(node is None and f["cap"] in self.root_capabilities and
                            self.root_capabilities[f["cap"]][0:2] == (endpoint, f["target"]) and
                            self.root_capabilities[f["cap"]][2] & (1 << (f["operation"] - 1)),
                            "actual storage transfer escaped independently read exact sealed holder/target/operation authority")
                if f["cell"] < 4:
                    require(f["identity"] == ROOT_IDS[f["cell"]] and f["generation"] == 1,
                            "independent storage progress used changed root execution generation")
            else:
                raise AssertionError("unknown contract trace event " + event.name)
            for fault, affected, sibling, old_endpoint, old_control, old_pages, old_channels, old_wait in self.fault_preservation:
                recovery = next((record for record in self.obligations.values() if record.worker.instance == affected.instance), None)
                if recovery is not None and recovery.state != COMPLETED:
                    require(sibling.state == RUNNING and sibling.worker.ready and sibling.worker.retained and
                            sibling.worker.endpoint == old_endpoint and sibling.worker.control == old_control and
                            sibling.worker.pages_owned == old_pages and sibling.worker.own_pages == 2 and
                            all(self.channels.get(cap) == grant for cap, grant in old_channels.items()),
                            "fault/cancel recovery changed unrelated contract execution/private pages/current authority")
                    if old_wait and f["tick"] < old_wait["deadline"]:
                        require(self.waits.get(old_endpoint) == old_wait,
                                "worker recovery changed unrelated sleeping sibling deadline/wait eligibility")
        require({0x101, 0x102, 0x103, 0x104} <= self.kernel_entries, "original roots lack real ring3 entry")
        require(all(len(record.initial_reports) == 5 for record in self.obligations.values()),
                "contract offered binding omitted authoritative input/worker/control/endpoint")
        require(sum(event.name == "host-backoff" for event in self.events) == 1,
                "worker recovery lacks unique actual bounded backoff publication")
        require(len(self.root_boots) == 4 and not self.transactions and not self.snapshot_groups,
                "contract evidence ended with incomplete boot/creation/eight-part status")
        require(len(self.completed) == 1 and not self.live_records and not self.tree.slots and
                self.tree.ledger() == (0, 0, 0, 0, 4, 48), "native contract final resource/record conservation failed")
        require(not self.worker_sleeps and len(self.worker_sleep_returns) == 3,
                "interleaved/preserved workers lack complete real bounded sleep/wake evidence")
        require(len(self.reap_reports) == 8, "native cleanup lacks each checked owner lifecycle reap confirmation")
        require(len(self.published) == 8 and len(self.obligations) == 7 and self.maximum_records == 2 and
                len(self.reaped_records) == 7, "native scenario lacks exact genuine backing/capacity/record reap sequence")
        brokers = [node for node in self.tree.nodes.values() if node.template == 3]
        require(len(brokers) == 1 and brokers[0].depth == 1 and brokers[0].allowance_slots == brokers[0].allowance_pages == 0,
                "broker private pages/descendant reservation were not separately retired")
        require(all(node.parent_instance == brokers[0].instance and node.depth == 2 and
                    self.approved[node.template]["pages"] == 2 for node in self.tree.nodes.values() if node.template == 4),
                "work backing is not actual fixed two-page broker-owned descendants")
        require(all(node.entered == node.cold == set(node.memories) and node.endpoint in node.entered and
                    node.entered <= self.kernel_entries for node in self.tree.nodes.values()),
                "contract execution lacks actual ring3 entry/cold/private memory/kernel entry")
        for node in self.tree.nodes.values():
            denials = [item for item in self.events if item.name == "host-storage-denied" and
                       item.fields["cell"] == node.slot and item.fields["identity"] == node.identity]
            require(all(any(item.fields["generation"] == endpoint >> 8 for item in denials) for endpoint in node.entered),
                    "contract execution lacks actual checked raw block/filesystem authority denial")
        require(len(self.restarts) == len(self.rebound) == 1 and self.stale and len(self.late) == 1 and len(self.deferred) == 6 and
                len(self.denied) == len(self.errors) == 8 and len(self.copy_denials) == 7,
                "contract scenario lacks real fault/restart/rebind/stale authority/private late result fencing")
        require(len(self.lost_replies) == 2 and {snapshot[2].command for _, snapshot in self.lost_replies} == {1, 5},
                "native scenario lacks genuine bounded offer/receipt loss")
        for loss, original in self.lost_replies:
            record = self.obligation(original[2].sender, original[2].token, retained=False)
            recovered = [snapshot for snapshot in self.snapshots if snapshot[0].index > loss.index and
                         snapshot[2].token == record.token and snapshot[2].command == 3 and snapshot[3] == original[3]]
            require(recovered, "lost reply was not resynchronized through exact authoritative STATUS with unchanged backing/attempt")
            command = original[2].command
            retried = [snapshot for snapshot in self.snapshots if snapshot[0].index > recovered[0][1].index and
                       snapshot[2].token == record.token and snapshot[2].command == command and snapshot[3] == original[3]]
            require(retried, "lost offer/receipt did not recover exact original metadata without allocation/execution")
        require(len(self.recovery_intervals) == 1 and len(self.computations) == 6,
                "scenario executed missing/extra successful attempts or failed bounded recovery")
        first, second = sorted(self.obligations.values(), key=lambda record: record.born)[:2]
        require(first.accepted.index < second.accepted.index < second.validation.index < second.terminal.index <
                first.validation.index < first.terminal.index,
                "the two accepted contracts did not genuinely interleave and settle in reverse offer order")
        completed = [record for record in self.obligations.values() if record.state == COMPLETED]
        cancelled = [record for record in self.obligations.values() if record.state == CANCELLED]
        require(len(completed) == 5 and all(record.requester_checks for record in completed) and len(cancelled) == 2 and
                any(record.accepted is None for record in cancelled) and any(record.accepted is not None for record in cancelled),
                "scenario lacks checked terminal receipts and offered/active cancellation")
        require(all(not record.retained and record.worker.own_pages == 0 and not record.worker.retained
                    for record in self.obligations.values()), "unreaped terminal metadata/backing survived final completion")
        require(any(item.fields["cell"] == 3 and item.index < self.published[0].index for item in self.ledger_events) and
                any(item.fields["cell"] == 3 and item.index > max(event.index for event in self.events if event.name == "host-reap")
                    for item in self.ledger_events), "initial/final requester allowance ledger missing")
        require(any(item.fields["cell"] == brokers[0].slot for item in self.ledger_events),
                "broker did not inspect actual attenuated descendant domain")
        return self


def verify(output, code, scenario=24, manifest_path=None):
    require(scenario == 24, "unsupported native contract scenario")
    require(code == 1, "native contract emulator lacks actual success debug-exit status1")
    require(output.count("ZEAL boot abi=4 x86_64") == output.count("MANIFEST_ACCEPT version=2") == 1,
            "native contract boot/privileged manifest validation is missing/repeated")
    require(output.count("RESEARCH_PASS") == 1 and "RESEARCH_PASS scenario=0x0000000000000018" in output,
            "native contract completion has wrong/repeated scenario")
    require(not any(word in output for word in ("PANIC", "RESEARCH_FAIL", "bad-report", "TRACE_EXHAUSTED")),
            "native contract evidence reports failure or trace exhaustion")
    if manifest_path is None:
        manifest_path = pathlib.Path(__file__).resolve().parents[1] / "build/research/scenario-24/manifest.bin"
    roots, approved, manifest_hash = manifest_records(manifest_path)
    images = linked_images(pathlib.Path(manifest_path).parent / "kernel.elf")
    for template, image in images.items():
        approved[template].update(image)
    accepted = next(line for line in output.splitlines() if line.startswith("MANIFEST_ACCEPT"))
    require(f"cells=0x{len(roots):016x}" in accepted and f"grants=0x{roots.grant_count:016x}" in accepted,
            "privileged contract manifest acceptance counts contradict sealed artifact")
    events = host.records(output)
    require(events and sum(event.name.startswith(("host-", "contract-")) for event in events) < 2048,
            "native contract hosting trace credit exhausted")
    require(sum(event.name in ("storage-ipc", "storage-reject") for event in events) < 2048,
            "native contract storage trace credit exhausted")
    observer = Observer(events, roots, approved).run()
    host.management_returns(observer)
    storage = host.verify_storage(events, observer)
    fault, terminal, record = observer.recovery_intervals[0]
    requester_receipt = record.requester_checks[0]
    require(requester_receipt.index > terminal.index, "recovery lacks first fully delivered independently verified current receipt")
    recovery_chunks = [(name, request, reply, verified) for name, request, reply, verified in storage["reads"]
                       if fault.index < request.index < verified.index < requester_receipt.index]
    require(recovery_chunks, "contract recovery interval lacks actual independently matched storage chunk")
    return {"contracts_verified": True, "scenario": 24, "manifest_sha256": manifest_hash,
        "serial_sha256": hashlib.sha256(output.encode()).hexdigest(),
        "broker_image_sha256": images[3]["image_sha256"], "worker_image_sha256": images[4]["image_sha256"],
        "runtime_creations": len(observer.published),
        "contract_records": len(observer.obligations), "maximum_live_records": observer.maximum_records,
        "checked_receipts": sum(record.state == COMPLETED for record in observer.obligations.values()),
        "cancelled_contracts": sum(record.state == CANCELLED for record in observer.obligations.values()),
        "worker_computations": len(observer.computations), "lost_replies_resynchronized": len(observer.lost_replies), "worker_restarts": len(observer.restarts),
        "independent_snapshots": len(observer.snapshots), "recovery_observed_ticks": requester_receipt.fields["tick"] - fault.fields["tick"],
        "recovery_broker_terminal_ticks": terminal.fields["tick"] - fault.fields["tick"],
        "storage_chunks_during_recovery": len(recovery_chunks), "storage_full_cycles": len(storage["cycles"]),
        "storage_verified_chunks": len(storage["reads"]), "root_generations": {str(identity): 1 for identity in ROOT_IDS},
        "physical_root_pages": 80, "broker_private_pages": 4, "broker_descendant_slots": 2, "broker_descendant_pages": 4,
        "maximum_retry": 1, "final_owned_slots": 0, "final_owned_pages": 0,
        "final_reserved_slots": 0, "final_reserved_pages": 0, "final_available_slots": 4, "final_available_pages": 48}


def negative_controls(output, code, scenario=24, manifest_path=None):
    """Essential removals and coordinated counterfeits of genuine serial evidence.

    Unexpected passing witnesses are durable evidence. Fixes never erase them.
    """
    verify(output, code, scenario, manifest_path)
    events, lines, tested = host.records(output), output.splitlines(), []
    unexpected = []
    evidence = pathlib.Path(__file__).resolve().parents[1] / "build/research/contract-witnesses"

    def rejected(name, altered, exit_code=code, alternate_manifest=None):
        try:
            verify(altered, exit_code, scenario, alternate_manifest or manifest_path)
        except (AssertionError, ValueError, UnicodeError, IndexError, KeyError) as error:
            tested.append({"name": name, "rejection": str(error),
                           "counterfeit_sha256": hashlib.sha256(altered.encode()).hexdigest()})
            return
        evidence.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(altered.encode()).hexdigest()
        witness = evidence / f"unexpected-{name}-{digest[:12]}.log"
        witness.write_text(altered)
        unexpected.append({"name": name, "witness": str(witness), "counterfeit_sha256": digest})

    def alter(event, key, value=None):
        require(key in event.fields, f"counterfeit baseline lacks {event.name}.{key}")
        changed = list(lines)
        replacement = event.fields[key] ^ 1 if value is None else value
        changed[event.line] = re.sub(rf"\b{re.escape(key)}=0x[0-9a-f]+\b",
                                    f"{key}=0x{replacement:016x}", changed[event.line], count=1)
        return "\n".join(changed) + "\n"

    artifact = pathlib.Path(manifest_path) if manifest_path is not None else pathlib.Path(__file__).resolve().parents[1] / "build/research/scenario-24/manifest.bin"
    original_manifest = artifact.read_bytes()
    _, _, _, root_count, grant_count, template_count, _, *_ = struct.unpack_from("<10I", original_manifest)
    template_at = 40 + root_count * 64 + grant_count * 16
    manifest_counterfeits = (("magic", 0, 0), ("version", 4, 1), ("reserved", 28, 1),
        ("root-identity", 40, 999), ("root-branch", 40 + 3 * 64 + 36, 0),
        ("storage-authority-holder", 40 + 4 * 64, 400),
        ("storage-authority-rights", 40 + 4 * 64 + 8, 0xffff),
        ("broker-template-mask", template_at + 52, 12),
        ("worker-private-budget", template_at + 64 + 32, 12288),
        ("creator-slot-limit", template_at + template_count * 64 + 8, 5),
        ("creator-page-limit", template_at + template_count * 64 + 12, 49))
    evidence.mkdir(parents=True, exist_ok=True)
    for name, offset, value in manifest_counterfeits:
        counterfeit = bytearray(original_manifest)
        struct.pack_into("<I", counterfeit, offset, value)
        path = evidence / f"counterfeit-manifest-{name}.bin"
        path.write_bytes(counterfeit)
        rejected("counterfeit-sealed-manifest-" + name, output, alternate_manifest=path)

    essential = ["boot", "entry", "host-template", "host-root-domain", "host-domain", "host-request",
        "host-reserve", "host-space", "host-channel", "host-publish", "host-result", "host-kernel-entry",
        "host-entry", "host-cold", "host-memory", "host-storage-denied", "host-ledger", "host-computed", "host-sleep-start", "host-sleep-return",
        "host-ipc-enqueue", "host-ipc-deliver", "host-call", "host-status", "host-stop", "host-cancel",
        "host-invalidate", "host-cleanup", "host-return", "host-reap", "fault", "host-fault", "host-backoff",
        "host-restart", "host-rebind", "host-stale", "host-denied", "host-reaped", "host-copied", "wait-arm", "wake",
        "storage-ipc", "storage-link", "storage-block", "storage-fs", "storage-verified",
        "hosting-storage-ready", "hosting-storage-cycle", *sorted(REPORTS)]
    for name in essential:
        selected = [event for event in events if event.name == name]
        require(selected, f"contract negative control lacks essential baseline evidence {name}")
        removed = {event.line for event in selected}
        rejected("remove-" + name, "\n".join(line for number, line in enumerate(lines) if number not in removed) + "\n")

    mutations = {
        "boot": ("cell", "identity", "generation", "image", "abi", "entry", "image_budget", "writable_budget", "config", "physical_pages", "p0"),
        "host-template": ("template", "image", "abi", "entry", "image_bytes", "image_budget", "stack_budget", "writable_budget", "pages", "config", "restart_limit", "restart_delay", "max_depth", "template_mask", "recipe", "reserved"),
        "host-root-domain": ("cell", "identity", "endpoint", "template_mask", "slot_limit", "page_limit", "max_depth", "recipe", "reserved0", "reserved1"),
        "host-domain": ("domain", "holder", "domain_instance", "slot_limit", "page_limit", "owned_slots", "owned_pages", "domain_reserved_slots", "domain_reserved_pages", "available_slots", "available_pages", "max_depth", "template_mask", "recipe", "revoked"),
        "host-request": ("caller_endpoint", "caller_identity", "request", "template", "parent_cap", "requested_slots", "requested_pages"),
        "host-reserve": ("cell", "identity", "generation", "instance", "control", "endpoint", "parent_instance", "parent_endpoint", "template", "image", "role", "depth", "pages", "reserved_slots", "reserved_pages", "creation", "transaction"),
        "host-space": ("identity", "generation", "instance", "control", "endpoint", "parent_instance", "parent_endpoint", "template", "image", "role", "depth", "pages", "reserved_slots", "reserved_pages", "creation", "cs", "ss", "rip", "rsp", "rflags", "zero", "physical_pages", "p0"),
        "host-channel": ("parent_cap", "child_cap", "instance", "endpoint", "recipe", "parent_holder", "parent_target", "parent_issuer", "parent_rights", "parent_derivation", "parent_epoch", "child_holder", "child_target", "child_issuer", "child_rights", "child_derivation", "child_epoch"),
        "host-publish": ("identity", "generation", "instance", "control", "endpoint", "parent_instance", "parent_endpoint", "template", "image", "role", "depth", "pages", "reserved_slots", "reserved_pages", "creation", "parent_cap", "child_cap", "phase", "result"),
        "host-result": ("instance", "endpoint", "control", "pages", "reserved_slots", "reserved_pages", "caller_endpoint", "request", "result"),
        "host-kernel-entry": ("cell", "identity", "generation", "endpoint", "instance", "control", "template", "depth", "parent_endpoint", "cs", "ss", "rip", "rsp", "rflags", "vector"),
        "host-entry": ("value", "extra", "endpoint", "instance", "template", "depth", "parent_endpoint"),
        "host-cold": ("value", "extra", "endpoint", "instance"),
        "host-memory": ("value", "extra", "endpoint", "instance"),
        "host-computed": ("value", "extra", "endpoint", "instance", "template", "depth", "parent_endpoint"),
        "host-sleep-start": ("value", "extra"), "host-sleep-return": ("value", "extra"),
        "host-storage-denied": ("value", "extra"),
        "host-ledger": ("value", "extra"),
        "host-ipc-enqueue": ("sender", "target", "cap", "operation", "length", "request", "command", "reserved", "argument", "value", "version", "service_command", "kind", "detail", "token", "data", "result"),
        "host-ipc-deliver": ("sender", "target", "cap", "operation", "length", "request", "command", "reserved", "argument", "value", "version", "service_command", "kind", "detail", "token", "data", "result"),
        "host-status": ("control", "endpoint", "generation", "pages", "reserved_slots", "reserved_pages", "creation", "phase", "deadline", "reason", "parent_cap", "child_cap", "retired_pages", "retained"),
        "host-stop": ("control", "instance", "caller_endpoint", "pages", "reserved_slots", "reserved_pages", "phase", "reason", "parent_cap", "retired_pages"),
        "host-reap": ("control", "instance", "caller_endpoint", "pages", "reserved_slots", "reserved_pages", "phase", "deadline", "reason", "parent_cap", "retired_pages", "retained"),
        "host-cancel": ("wait_generation", "wait_kind", "wait_deadline", "phase", "pages"),
        "host-invalidate": ("instance", "endpoint", "phase", "queued", "pages"),
        "host-cleanup": ("instance", "endpoint", "phase", "retired_pages", "retained", "pages", "reserved_slots", "reserved_pages"),
        "host-return": ("instance", "phase", "retired_pages", "pages", "reserved_slots", "reserved_pages"),
        "host-fault": ("instance", "endpoint", "control", "pages", "reserved_slots", "reserved_pages", "phase", "deadline", "result"),
        "host-backoff": ("phase", "deadline", "reason", "pages"),
        "host-restart": ("generation", "instance", "control", "endpoint", "zero", "physical_pages", "cs", "ss", "rip", "rsp", "rflags", "p0", "phase", "reason"),
        "host-rebind": ("request", "caller_endpoint", "endpoint", "instance", "control", "creation", "parent_cap", "child_cap", "recipe", "parent_holder", "parent_target", "parent_issuer", "parent_rights", "parent_derivation", "parent_epoch", "child_holder", "child_target", "child_issuer", "child_rights", "child_derivation", "child_epoch"),
        "host-copied": ("value", "extra"), "host-stale": ("value", "extra"), "host-denied": ("value", "extra"), "host-reaped": ("value", "extra"),
        "host-call": ("call", "result"), "fault": ("reason", "error", "address"),
        "storage-ipc": ("identity", "generation", "target", "operation", "request", "length"),
        "storage-link": ("request", "block_request"), "storage-block": ("operation", "result"),
        "storage-fs": ("request", "result"), "storage-verified": ("request", "data"),
        "hosting-storage-ready": ("value", "extra"), "hosting-storage-cycle": ("value", "extra"),
    }
    canonical = ("phase", "deadline", "queued", "retired_pages", "retained", "reason", "transaction", "parent_cap", "child_cap", "result")
    for name in ("host-request", "host-reserve", "host-space", "host-channel", "host-publish", "host-result",
                 "host-status", "host-stop", "host-reap", "host-fault", "host-backoff", "host-restart",
                 "host-cancel", "host-invalidate", "host-cleanup", "host-return", "host-rebind"):
        keys = mutations[name] + canonical
        if name not in ("host-request", "host-reserve", "host-space", "host-channel", "host-publish", "host-result", "host-rebind"):
            keys += ("request",)
        mutations[name] = tuple(dict.fromkeys(keys))
    for name in sorted(REPORTS):
        mutations[name] = ("value", "extra", "endpoint", "instance", "template", "depth", "parent_endpoint")
    special = {("host-kernel-entry", "rip"): 0, ("host-kernel-entry", "rsp"): 0,
               ("host-kernel-entry", "rflags"): 2, ("host-kernel-entry", "vector"): 0}
    for name, keys in mutations.items():
        selected = next(event for event in events if event.name == name)
        for key in keys:
            rejected(f"counterfeit-{name}.{key}", alter(selected, key, special.get((name, key))))

    for number in (13, 14, 17, 19):
        copied = next(event for event in events if event.name == "host-call" and
                      event.fields["call"] == number and event.fields["result"] == 0)
        for key in copied.fields:
            if key.startswith(("input_", "output_")):
                rejected(f"counterfeit-checked-copy-{number}.{key}", alter(copied, key))
    failed_status = next(event for event in events if event.name == "host-call" and
                         event.fields["call"] == 14 and host.signed(event.fields["result"]) == -3)
    for key in failed_status.fields:
        if key.startswith("output_"):
            rejected(f"counterfeit-stale-status-copy.{key}", alter(failed_status, key))

    def change_fields(changed, event, fields):
        for key, value in fields.items():
            changed[event.line] = re.sub(rf"\b{key}=0x[0-9a-f]+\b", f"{key}=0x{value:016x}", changed[event.line])

    # A coordinated counterfeit changes redundant raw bytes and decoded fields
    # together, so a raw/decoded equality check alone cannot reject it.
    for field, value in (("version", 2), ("reserved", 1), ("service_command", 0), ("kind", 3)):
        changed = list(lines)
        for event in events:
            if event.name not in ("host-ipc-enqueue", "host-ipc-deliver"):
                continue
            f = dict(event.fields)
            f[field] = value
            packed = f["version"] | f["service_command"] << 8 | f["kind"] << 16 | f["detail"] << 24
            change_fields(changed, event, {field: value, "command": packed})
        rejected("coordinated-wire-" + field, "\n".join(changed) + "\n")

    first = next(event for event in events if event.name == "contract-offer")
    original_token = first.fields["value"]
    for label, forged_token in (("type", original_token ^ 1), ("serial", original_token + (4 << 9)),
                                ("issuer", original_token ^ (1 << 32)), ("generation", original_token ^ (1 << 40))):
        changed = list(lines)
        for event in events:
            changes = {key: forged_token for key in ("token", "argument") if event.fields.get(key) == original_token}
            if event.name.startswith("contract-") and event.fields.get("value") == original_token:
                changes["value"] = forged_token
            change_fields(changed, event, changes)
        rejected("coordinated-contract-" + label, "\n".join(changed) + "\n")

    channels = [event for event in events if event.name == "host-channel"]
    channel = channels[0]
    old_child = channel.fields["child_cap"]
    forged_child = (channel.fields["parent_cap"] & ~255) | (old_child & 255)
    changed = list(lines)
    for event in events:
        fields = {key: forged_child for key in ("cap", "child_cap", "arg0") if event.fields.get(key) == old_child}
        if event is channel:
            fields["child_epoch"] = channel.fields["parent_epoch"]
        change_fields(changed, event, fields)
    rejected("coordinated-kernel-capability-epoch-collision", "\n".join(changed) + "\n")

    broker_instance = next(event.fields["instance"] for event in events
                           if event.name == "host-publish" and event.fields["template"] == 3)
    changed = list(lines)
    for event in events:
        f, changes = event.fields, {}
        if event.name == "host-request" and f.get("template") == 3:
            changes.update(requested_slots=3, requested_pages=6)
        if event.name.startswith("host-") and f.get("instance") == broker_instance:
            if f.get("reserved_slots") == 2:
                changes.update(reserved_slots=3, reserved_pages=6)
        if event.name == "host-domain":
            if f["holder"] == 0x104 and f["domain_reserved_slots"] == 2:
                changes.update(domain_reserved_slots=3, domain_reserved_pages=6,
                               available_slots=f["available_slots"] - 1, available_pages=f["available_pages"] - 2)
            elif f["domain_instance"] == broker_instance:
                changes.update(slot_limit=3, page_limit=6, available_slots=f["available_slots"] + 1,
                               available_pages=f["available_pages"] + 2)
        if event.name == "host-ledger":
            value, extra = f["value"], f["extra"]
            if f["cell"] == 3 and (value >> 16) & 0xffff == 2:
                changes.update(value=value + (1 << 16) - (1 << 32), extra=extra + (2 << 16) - (2 << 32))
            elif f.get("instance") == broker_instance:
                changes.update(value=value + (1 << 32), extra=extra + (2 << 32))
        if event.name == "host-call" and f.get("call") == 13 and f.get("input_template") == 3:
            changes.update(input_slots=3, input_pages=6)
        change_fields(changed, event, changes)
    rejected("coordinated-broker-reservation-manufactured-three-slots-six-pages", "\n".join(changed) + "\n")

    worker_spaces = [event for event in events if event.name == "host-space" and event.fields["template"] == 4]
    first_space, second_space = worker_spaces[:2]
    changed = list(lines)
    change_fields(changed, second_space, {"p0": first_space.fields["p0"], "p1": first_space.fields["p1"]})
    rejected("coordinated-two-contracts-share-private-pages", "\n".join(changed) + "\n")
    changed = list(lines)
    for event in events:
        if event.name in ("host-cleanup", "host-return") and event.fields["retired_pages"]:
            change_fields(changed, event, {"retired_pages": 0})
    rejected("coordinated-manufactured-refund-without-private-page-return", "\n".join(changed) + "\n")

    accepted = next(event for event in events if event.name == "contract-accepted")
    dispatched = next(event for event in events if event.name == "contract-dispatch")
    changed = list(lines)
    changed[accepted.line], changed[dispatched.line] = changed[dispatched.line], changed[accepted.line]
    rejected("work-dispatched-before-explicit-acceptance", "\n".join(changed) + "\n")
    cancelled = next(event for event in events if event.name == "contract-terminal" and (event.fields["extra"] & 255) == CANCELLED)
    changed = list(lines)
    change_fields(changed, cancelled, {"extra": (cancelled.fields["extra"] & ~255) | COMPLETED})
    rejected("cancelled-result-resurrected-as-completed", "\n".join(changed) + "\n")
    # Contradict each individual authoritative snapshot field even when the
    # untouched receipt and kernel events already prove the intended truth.
    for part in range(8):
        snapshots = [event for event in events if event.name == "host-ipc-enqueue" and
                     event.fields["kind"] == 2 and event.fields["detail"] == part]
        selected = next(event for event in snapshots if event.fields["service_command"] == 5)
        packet = Packet.from_event(selected)
        changed = list(lines)
        for event in events:
            if event.name in ("host-ipc-enqueue", "host-ipc-deliver") and Packet.from_event(event) == packet:
                change_fields(changed, event, {"data": packet.data ^ 1, "value": packet.data ^ 1})
        rejected(f"coordinated-authoritative-receipt-part-{part}", "\n".join(changed) + "\n")

    completed = next(event for event in events if event.name == "contract-terminal" and (event.fields["extra"] & 255) == COMPLETED)
    verified = next(event for event in events if event.name == "contract-validated" and event.fields["value"] == completed.fields["value"])
    changed = list(lines)
    changed[completed.line], changed[verified.line] = changed[verified.line], changed[completed.line]
    rejected("terminal-receipt-published-before-validation-and-settlement", "\n".join(changed) + "\n")
    changed = list(lines)
    for event in events:
        if event.name == "host-kernel-entry":
            changed[event.line] = "EVENT entry " + " ".join(f"{key}=0x{event.fields[key]:016x}"
                for key in ("cell", "identity", "generation", "tick"))
    rejected("coordinated-dynamic-hardware-entry-replaced-by-generic-markers", "\n".join(changed) + "\n")
    copied = next(event for event in events if event.name == "host-ipc-deliver")
    rejected("contradictory-copied-delivery-capability", alter(copied, "cap", 0xabc))
    changed = list(lines)
    changed[copied.line] = re.sub(r" cap=0x[0-9a-f]+\b", "", changed[copied.line])
    rejected("missing-copied-delivery-capability-field", "\n".join(changed) + "\n")
    for number, key in ((13, "arg0"), (13, "arg2"), (14, "arg1"), (17, "arg0"), (17, "arg2"), (19, "arg1")):
        copied_call = next(event for event in events if event.name == "host-call" and
                           event.fields["call"] == number and event.fields["result"] == 0)
        rejected(f"successful-checked-copy-{number}-{key}-null", alter(copied_call, key, 0))
        rejected(f"successful-checked-copy-{number}-{key}-overflow", alter(copied_call, key, MASK64))
    hardware = next(event for event in events if event.name == "host-kernel-entry")
    rejected("hardware-entry-reserved-rflags", alter(hardware, "rflags", hardware.fields["rflags"] | (1 << 63)))
    rejected("hardware-entry-reserved-low-rflags", alter(hardware, "rflags", hardware.fields["rflags"] | (1 << 3)))
    rejected("wrong-emulator-exit", output, 3)
    rejected("missing-completion", output.replace("RESEARCH_PASS", "UNVERIFIED_COMPLETION"))
    rejected("counterfeit-completion", output.replace("RESEARCH_PASS scenario=0x0000000000000018",
                                                       "RESEARCH_PASS scenario=0x0000000000000017"))
    rejected("marker-only", "ZEAL boot abi=4 x86_64\nMANIFEST_ACCEPT version=2 cells=0x4 grants=0x8\nRESEARCH_PASS scenario=0x0000000000000018\n")
    rejected("hosting-trace-exhaustion", output + "HOSTING_TRACE_EXHAUSTED\n")
    rejected("storage-trace-exhaustion", output + "STORAGE_TRACE_EXHAUSTED\n")
    if unexpected:
        import json
        import time
        audit = evidence / f"review-failures-{time.time_ns()}.json"
        audit.write_text(json.dumps({"passed": False, "unexpected": unexpected, "rejected": tested}, indent=2) + "\n")
        raise AssertionError(f"contract negative controls unexpectedly passed: {[item['name'] for item in unexpected]}; retained {audit}")
    return tested
