#!/usr/bin/env python3
"""Independent external proof for Zeal's bounded runtime-hosting scenarios.

This observer derives a logical tree from sealed manifest bytes and ordered
privileged events. It does not import the production policy, trust completion
reports, or derive dynamic identity from image or slot.
"""
import dataclasses
import hashlib
import pathlib
import re
import struct
from collections import defaultdict

MASK64 = (1 << 64) - 1
ROOT_IDS = (100, 200, 300, 400)
NESTED_SALT = 0x8AC91367EF04D2B5
MEMORY_SALT = 0x9E60328AB74FC1D5
GUARD_SALT = 0x736A21C45E98BD02
PAYLOADS = {"/hello": b"Zeal survives.", "/alpha": b"Zeal alpha private file 01.",
            "/beta": b"Distinct beta bytes survive."}
MANAGEMENT = {"request", "reserve", "space", "channel", "publish", "abort", "result",
              "status", "stop", "reap", "fault", "backoff", "restart", "rebind", "revoke",
              "cancel", "invalidate", "cleanup", "return"}
MANAGEMENT_FIELDS = ("cell", "identity", "generation", "tick", "caller", "caller_identity",
    "caller_endpoint", "request", "instance", "control", "endpoint", "parent_instance",
    "parent_endpoint", "template", "image", "role", "depth", "pages", "reserved_slots",
    "reserved_pages", "creation", "transaction", "parent_cap", "child_cap", "result",
    "phase", "deadline", "queued", "retired_pages", "retained")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def signed(value):
    return value if value < 1 << 63 else value - (1 << 64)


def calculate(challenge):
    value = 0xCBF29CE484222325
    for byte in b"Zeal bounded ring-3 worker" + challenge.to_bytes(8, "little"):
        value = ((value ^ byte) * 0x100000001B3) & MASK64
    return value


def expected(command, argument):
    if command == 1:
        return calculate(argument)
    if command == 2:
        return calculate(argument) ^ calculate(argument ^ NESTED_SALT)
    if command in (3, 4):
        return argument
    if command in (7, 9, 10):
        return (-2) & MASK64
    if command == 8:
        return (-8) & MASK64
    if command in (5, 6):
        return 0
    raise AssertionError("unsupported hosting command")


@dataclasses.dataclass(frozen=True)
class Event:
    index: int
    name: str
    fields: dict
    line: int

    def need(self, *keys):
        missing = [key for key in keys if key not in self.fields]
        require(not missing, f"{self.name} line {self.line} missing fields {missing}")
        return [self.fields[key] for key in keys]


def records(output):
    events = []
    for line_number, line in enumerate(output.splitlines()):
        if not line.startswith("EVENT "):
            continue
        words = line.split()
        require(len(words) >= 2, "truncated structured event")
        fields = {}
        for token in words[2:]:
            match = re.fullmatch(r"([A-Za-z_][A-Za-z_0-9]*)=(0x[0-9a-f]{1,16})", token)
            require(match is not None, f"malformed structured token at line {line_number}: {token}")
            key, value = match.groups()
            require(key not in fields, f"duplicate structured field {key}")
            fields[key] = int(value, 16)
        events.append(Event(len(events), words[1], fields, line_number))
    return events


def pages(stack, writable):
    require(4096 <= stack <= 16384 and stack <= writable <= 81920 and writable - stack <= 65536,
            "sealed manifest contains invalid private memory")
    count = (stack + 4095) // 4096 + (writable - stack + 4095) // 4096
    require(count <= 20, "sealed manifest exceeds per-cell pages")
    return count


class SealedRoots(dict):
    def __init__(self, grant_count):
        super().__init__()
        self.grant_count = grant_count


def manifest_records(path, scenario):
    data = pathlib.Path(path).read_bytes()
    require(40 <= len(data) <= 1320, "hosting manifest artifact has invalid size")
    header = struct.unpack_from("<10I", data)
    magic, version, length, roots, grants, templates, domains, *reserved = header
    require(magic == 0x4C41455A and version == 2 and length == len(data) and not any(reserved),
            "hosting manifest header is not sealed v2")
    require(roots == 4 and grants <= 16 and templates <= 8 and domains == 1,
            "hosting manifest record capacities or creator count differ")
    require(len(data) == 40 + roots * 64 + grants * 16 + templates * 64 + domains * 32,
            "hosting manifest exact record extents differ")
    root_records = SealedRoots(grants)
    for slot in range(roots):
        values = struct.unpack_from("<4IQ6I16s", data, 40 + slot * 64)
        identity, image, abi, flags, entry, image_budget, stack, writable, config, limit, delay, name = values
        require(identity == ROOT_IDS[slot] and image == slot + 1 and abi == 4 and flags == 1 and
                entry == 0x40000000 and image_budget == 65536 and limit == 3 and delay == 4,
                "sealed original root contract differs")
        require(config == (scenario if slot in (2, 3) else 0), "hosting root branch differs from manifest")
        root_records[slot] = {"identity": identity, "image": image, "abi": abi, "entry": entry,
                              "pages": pages(stack, writable), "config": config}
    require(sum(root["pages"] for root in root_records.values()) == 80, "root page reservation differs")
    at = 40 + roots * 64 + grants * 16
    approved = {}
    for index in range(templates):
        values = struct.unpack_from("<4IQ10I", data, at + index * 64)
        identity, image, abi, flags, entry, budget, stack, writable, config, limit, delay, depth, mask, recipe, reserved = values
        require(identity not in approved and 1 <= identity <= 8 and image in (5, 6) and abi == 4 and
                not flags and not reserved and entry == 0x40000000 and budget == 65536 and
                config == scenario and limit == 3 and delay == 4 and recipe == 1,
                "invalid approved hosting template")
        approved[identity] = {"image": image, "pages": pages(stack, writable), "depth": depth,
                              "mask": mask, "stack": stack, "writable": writable, "recipe": recipe,
                              "role": {1: 4, 2: 5}.get(identity)}
    require(set(approved) == {1, 2} and approved[1]["pages"] == 4 and approved[2]["pages"] == 2 and
            approved[1]["depth"] == 1 and approved[1]["mask"] == 2 and
            approved[2]["depth"] == 0 and approved[2]["mask"] == 0,
            "purpose-built fixed supervisor/worker templates differ")
    domain = struct.unpack_from("<8I", data, at + templates * 64)
    require(domain == (400, 3, 4, 48, 2, 1, 0, 0), "root creator reservation differs")
    return root_records, approved, hashlib.sha256(data).hexdigest()


@dataclasses.dataclass
class Node:
    instance: int
    control: int
    slot: int
    identity: int
    template: int
    parent_instance: int
    parent_endpoint: int
    endpoint: int
    depth: int
    own_pages: int
    allowance_slots: int
    allowance_pages: int
    creation: int
    parent_cap: int
    child_cap: int
    born: int
    phase: int = 1
    deadline: int = 0
    faults: int = 0
    restarts: int = 0
    ready: bool = True
    retained: bool = True
    pages_owned: tuple = ()
    last_fault: Event | None = None
    rebind_required: bool = False
    entered: set = dataclasses.field(default_factory=set)
    cold: set = dataclasses.field(default_factory=set)
    memories: dict = dataclasses.field(default_factory=dict)
    physical_history: dict = dataclasses.field(default_factory=dict)


class Tree:
    """Logical objects and nested commitments, rather than production slot tables."""
    def __init__(self, approved):
        self.approved = approved
        self.nodes = {}
        self.slots = {}
        self.history = {}
        self.dead = set()
        self.page_owners = {}
        self.object_epochs = set()
        self.identity_history = set(ROOT_IDS)
        self.maximum_epoch = 0

    def node(self, instance):
        require(instance in self.nodes and self.nodes[instance].retained, "event names a retired logical instance")
        return self.nodes[instance]

    def at(self, slot):
        require(slot in self.slots, "event names an unassigned runtime slot")
        return self.node(self.slots[slot])

    def parent(self, node):
        return self.nodes.get(node.parent_instance)

    def children(self, instance):
        return [node for node in self.nodes.values() if node.retained and node.parent_instance == instance]

    def descendants(self, instance):
        result, todo = [], [instance]
        while todo:
            parent = todo.pop()
            for node in self.children(parent):
                require(node.instance not in result, "cyclic external logical tree")
                result.append(node.instance)
                todo.append(node.instance)
            require(len(result) <= 4, "external tree exceeds descendant slots")
        return result

    def ledger(self, owner=0):
        nodes = self.children(owner)
        limit_slots, limit_pages = (4, 48) if owner == 0 else (
            self.node(owner).allowance_slots, self.node(owner).allowance_pages)
        owned_slots = len(nodes)
        owned_pages = sum(node.own_pages for node in nodes)
        reserved_slots = sum(node.allowance_slots for node in nodes)
        reserved_pages = sum(node.allowance_pages for node in nodes)
        available_slots = limit_slots - owned_slots - reserved_slots
        available_pages = limit_pages - owned_pages - reserved_pages
        require(available_slots >= 0 and available_pages >= 0, "external reservation ledger overspent")
        return owned_slots, owned_pages, reserved_slots, reserved_pages, available_slots, available_pages

    def check(self):
        require(len(self.slots) <= 4, "runtime slot ownership exceeds four free root-excluding slots")
        require(sum(node.own_pages for node in self.nodes.values() if node.retained) <= 48,
                "unique physical allocations exceed descendant pool")
        self.ledger()
        for node in self.nodes.values():
            if not node.retained:
                continue
            require(node.slot >= 4 and node.slot <= 7 and self.slots.get(node.slot) == node.instance,
                    "logical instance escaped the permanently reserved root slots")
            parent = self.parent(node)
            require(node.depth == (parent.depth + 1 if parent else 1) and 1 <= node.depth <= 2,
                    "external parent ancestry or depth differs")
            require(parent is None or parent.retained, "orphaned child instance")
            if parent:
                require(node.parent_endpoint == parent.endpoint, "child belongs to a retired parent execution")
                require(self.approved[parent.template]["mask"] & (1 << (node.template - 1)),
                        "child escaped its parent's attenuated template mask")
            else:
                require(node.parent_endpoint == 0x104, "dynamic root child escaped identity400 creator")
            require(node.ready == (node.phase == 1), "external execution phase and runnable state disagree")
            self.ledger(node.instance)

    def physical(self, node, page_ids):
        require(len(page_ids) == node.own_pages and len(set(page_ids)) == len(page_ids),
                "private physical page count or uniqueness differs")
        for page in page_ids:
            require(0 <= page < 128 and page not in self.page_owners, "overlapping physical writable page ownership")
            self.page_owners[page] = node.instance
        node.pages_owned = tuple(page_ids)
        node.physical_history[node.endpoint] = tuple(page_ids)

    def release_pages(self, node):
        for page in node.pages_owned:
            require(self.page_owners.get(page) == node.instance, "private page ownership was refunded twice")
            del self.page_owners[page]
        node.pages_owned = ()
        node.own_pages = 0

    def reap(self, node):
        require(not self.children(node.instance), "external cleanup reaped an owner before descendants")
        require(node.own_pages == node.allowance_slots == node.allowance_pages == 0,
                "reaped instance retains a page or delegated credit charge")
        require(self.slots.get(node.slot) == node.instance, "runtime slot was released twice")
        del self.slots[node.slot]
        self.dead.add(node.endpoint)
        node.ready = node.retained = False


class Observer:
    def __init__(self, events, roots, approved, scenario):
        self.events, self.roots, self.approved, self.scenario = events, roots, approved, scenario
        self.tree = Tree(approved)
        self.root_boots = {}
        self.transactions = {}
        self.finished_transactions = set()
        self.requests = []
        self.published = []
        self.channels = {}
        self.capabilities_seen = set()
        self.capability_epochs = set(range(1, roots.grant_count + 1))
        self.maximum_capability_epoch = roots.grant_count
        self.waits = {}
        self.queues = defaultdict(list)
        self.enqueued = []
        self.delivered = []
        self.replies = defaultdict(list)
        self.verified = []
        self.cleaned = []
        self.returned = set()
        self.restarts = []
        self.rebound = []
        self.stale = []
        self.denied = []
        self.ledger_events = []
        self.completed = []
        self.calls = []
        self.ipc_rejected = []
        self.fifo = []
        self.cancelled = []
        self.last_tick = 0
        self.copy_denials = []
        self.timeouts = []
        self.sleep_returns = []
        self.hardware_faults = []
        self.probes = []
        self.current_frames = {}
        self.kernel_entries = set()
        self.domains = {}
        self.root_domain = None
        self.accepted_requests = {}
        self.retirements = {}
        self.wakes = []

    def principal(self, event, ready=True):
        slot, identity, generation = event.need("cell", "identity", "generation")
        require(0 <= slot < 8 and generation > 0, f"{event.name} has invalid runtime endpoint")
        endpoint = generation * 256 + slot + 1
        if slot < 4:
            require(identity == self.roots[slot]["identity"] and generation == 1 and slot in self.root_boots,
                    "root identity/generation changed in hosting preservation")
            return endpoint, None
        node = self.tree.at(slot)
        require(identity == node.identity and endpoint == node.endpoint,
                f"{event.name} has counterfeit dynamic identity or execution generation")
        if ready:
            require(node.ready, "retired dynamic execution emitted user work")
        return endpoint, node

    def management_identity(self, event):
        event.need(*MANAGEMENT_FIELDS)
        f = event.fields
        require(0 <= f["caller"] < 8 and 0 <= f["cell"] < 8,
                "management event contains an invalid runtime slot")
        require(0 <= f["role"] <= 5, "unrecognized trusted catalog role")
        if f["cell"] < 4:
            require(f["role"] == {100: 0, 200: 1, 300: 2, 400: 3}[ROOT_IDS[f["cell"]]],
                    "original root role changed through image/runtime-slot arithmetic")
        elif event.name == "host-request" or (event.name == "host-result" and signed(f["result"]) < 0):
            caller_node = self.tree.at(f["cell"])
            require(f["role"] == self.approved[caller_node.template]["role"],
                    "management caller role differs from its explicit sealed program role")
        caller_endpoint = f["caller_endpoint"]
        require(caller_endpoint & 255 == f["caller"] + 1 and caller_endpoint >> 8 > 0,
                "management caller endpoint is not its exact trusted generation")
        if f["caller"] < 4:
            require(f["caller_identity"] == ROOT_IDS[f["caller"]] and caller_endpoint >> 8 == 1,
                    "management root caller identity changed")
        else:
            candidates = [n for n in self.tree.nodes.values() if n.slot == f["caller"] and
                          n.identity == f["caller_identity"] and
                          n.endpoint == caller_endpoint]
            if event.name == "host-restart":
                candidates = [n for n in self.tree.nodes.values() if n.retained and n.slot == f["caller"] and
                              n.identity == f["caller_identity"] and caller_endpoint >> 8 > n.endpoint >> 8]
            require(candidates, "management caller names an unknown dynamic execution")
        require(f["phase"] in range(5), "unknown lifecycle phase in structured management evidence")
        require(-8 <= signed(f["result"]) <= 0 or event.name == "host-fault",
                "management result is not a defined signed success/error")

    def tokens(self, node, transaction):
        tokens = [(node.instance, 0x40), (node.control, 0x50), (transaction, 0x70)]
        if node.creation:
            tokens.append((node.creation, 0x60))
        epochs = []
        for token, tag in tokens:
            require(tag < token & 255 <= tag + 8 and 0 < token >> 8 <= ((1 << 63) - 1) >> 8,
                    "typed lifecycle/domain/transaction handle is malformed")
            epoch = token >> 8
            require(epoch not in self.tree.object_epochs, "typed object epoch was recycled")
            epochs.append(epoch)
        require(len(set(epochs)) == len(epochs) and min(epochs) > self.tree.maximum_epoch,
                "logical object epochs decreased or collided")
        self.tree.object_epochs.update(epochs)
        self.tree.maximum_epoch = max(epochs)

    def channel(self, node, parent_cap, child_cap, event):
        f = event.fields
        event.need("recipe", *[f"{direction}_{name}" for direction in ("parent", "child")
                   for name in ("holder", "target", "issuer", "rights", "derivation", "epoch")])
        require(f["recipe"] == 1, "channel lacks explicit current creation-policy bootstrap recipe")
        for direction, cap, holder, target, rights in (("parent", parent_cap, node.parent_endpoint, node.endpoint, 1 << 14),
                ("child", child_cap, node.endpoint, node.parent_endpoint, 1 << 15)):
            require((f[direction + "_holder"], f[direction + "_target"], f[direction + "_issuer"],
                     f[direction + "_rights"], f[direction + "_derivation"], f[direction + "_epoch"]) ==
                    (holder, target, node.parent_endpoint, rights, 0, cap >> 8),
                    "actual installed channel holder/target/issuer/rights/derivation/epoch is not the narrow trusted recipe")
        parent_epoch, child_epoch = parent_cap >> 8, child_cap >> 8
        require(parent_epoch > self.maximum_capability_epoch and child_epoch == parent_epoch + 1,
                "atomic channel pair reused or reordered the global nonrepeating capability epoch counter")
        for cap in (parent_cap, child_cap):
            require(1 <= cap & 255 <= 32 and cap >> 8 > 0 and cap not in self.capabilities_seen,
                    "fresh narrow channel reused a capability epoch")
            require(cap >> 8 not in self.capability_epochs, "two capability entries share a supposedly unique epoch")
            self.capability_epochs.add(cap >> 8)
            self.capabilities_seen.add(cap)
        self.maximum_capability_epoch = child_epoch
        require(parent_cap != child_cap, "parent and child share a copied holder capability")
        node.parent_cap, node.child_cap = parent_cap, child_cap
        self.channels[parent_cap] = (node.parent_endpoint, node.endpoint, 15)
        self.channels[child_cap] = (node.endpoint, node.parent_endpoint, 16)

    def creation(self, event):
        f = event.fields
        self.management_identity(event)
        kind = event.name.removeprefix("host-")
        key = f["caller_endpoint"], f["request"]
        if kind == "request":
            event.need("requested_slots", "requested_pages")
            require(key[1] > 0 and key not in self.transactions and key not in self.finished_transactions,
                    "ambiguous or repeated caller-generation management request identity")
            if f["caller"] >= 4 and self.tree.at(f["caller"]).template == 1:
                parent = self.tree.at(f["caller"])
                require(parent.ready and not parent.rebind_required,
                        "restarted supervisor created without explicit fresh authority")
            self.transactions[key] = {"stage": "request", "event": event}
            self.requests.append(event)
            return
        require(key in self.transactions, f"{event.name} lacks its exact caller-generation request")
        item = self.transactions[key]
        if kind in ("space", "channel", "publish", "abort") or (kind == "result" and signed(f["result"]) == 0):
            require("node" in item, "publication stage lacks a reserved logical object")
            n = item["node"]
            require((f["cell"], f["identity"], f["generation"], f["instance"], f["control"], f["endpoint"],
                    f["parent_instance"], f["parent_endpoint"], f["template"], f["image"], f["role"], f["depth"], f["pages"],
                    f["reserved_slots"], f["reserved_pages"], f["creation"]) ==
                    (n.slot, n.identity, n.endpoint >> 8, n.instance, n.control, n.endpoint, n.parent_instance,
                     n.parent_endpoint, n.template, self.approved[n.template]["image"], self.approved[n.template]["role"], n.depth, n.own_pages,
                     n.allowance_slots, n.allowance_pages, n.creation),
                    "transaction stage counterfeited sealed/runtime ancestry, generation, or resource charge")
        if kind in ("reserve", "space", "channel"):
            require(f["phase"] == 0, "unpublished transaction exposed a runnable execution")
        if kind == "reserve":
            require(f["caller"] == 3 or (f["caller"] >= 4 and self.tree.at(f["caller"]).template == 1),
                    "unauthorized root/image became a hosting creator")
            require(item["stage"] == "request", "reservation duplicated or out of order")
            req = item["event"].fields
            require(f["template"] in self.approved and f["template"] == req["template"],
                    "reservation selected an unapproved/different template")
            require(f["parent_endpoint"] == f["caller_endpoint"] and
                    f["reserved_slots"] == req["requested_slots"] and
                    f["reserved_pages"] == req["requested_pages"],
                    "reservation does not match exact parent/requested allowance")
            require(req["parent_cap"] in self.domains, "creation authority is not an authenticated typed domain")
            entitlement = self.domains[req["parent_cap"]]
            require(entitlement["valid"] and not entitlement["revoked"] and
                    entitlement["holder"] == f["caller_endpoint"] and
                    entitlement["mask"] & (1 << (f["template"] - 1)) and entitlement["recipe"] == 1,
                    "creation escaped exact-holder live unrevoked template/recipe entitlement")
            require(f["request"] > self.accepted_requests.get(f["caller_endpoint"], 0),
                    "creation reused a request retired by earlier create/rebind preparation")
            self.accepted_requests[f["caller_endpoint"]] = f["request"]
            template = self.approved[f["template"]]
            require(f["image"] == template["image"] and f["role"] == template["role"] and f["pages"] == template["pages"],
                    "reservation image or rounded private charge differs from sealed template")
            require(f["cell"] not in self.tree.slots and 4 <= f["cell"] < 8,
                    "creation reused an occupied or permanently reserved root slot")
            require(f["identity"] not in self.tree.identity_history and f["identity"] > max(self.tree.identity_history),
                    "runtime diagnostic identity was inferred/reused instead of independently allocated")
            self.tree.identity_history.add(f["identity"])
            parent = self.tree.at(f["caller"]) if f["caller"] >= 4 else None
            require(f["parent_instance"] == (parent.instance if parent else 0) and
                    f["depth"] == (parent.depth + 1 if parent else 1) and f["depth"] <= min(2, entitlement["max_depth"]),
                    "reservation forged a parent logical instance or hierarchy depth")
            if parent:
                require(self.approved[parent.template]["mask"] & (1 << (f["template"] - 1)),
                        "reservation escaped attenuated ancestor template scope")
            if template["depth"] == 0:
                require(f["reserved_slots"] == f["reserved_pages"] == f["creation"] == 0,
                        "leaf template manufactured descendant allowance")
            endpoint = f["endpoint"]
            require(endpoint & 255 == f["cell"] + 1 and endpoint >> 8 == f["generation"] and
                    endpoint >> 8 > self.tree.history.get(f["cell"], 0),
                    "runtime slot execution generation reset/decreased on reuse")
            node = Node(f["instance"], f["control"], f["cell"], f["identity"], f["template"],
                        f["parent_instance"], f["parent_endpoint"], endpoint, f["depth"], f["pages"],
                        f["reserved_slots"], f["reserved_pages"], f["creation"], 0, 0, event.index)
            self.tokens(node, f["transaction"])
            ledger = self.tree.ledger(node.parent_instance)
            require(ledger[4] >= 1 + node.allowance_slots and ledger[5] >= node.own_pages + node.allowance_pages,
                    "reservation exceeds independent ancestor available credit")
            item.update(stage="reserve", node=node, transaction=f["transaction"], entitlement=entitlement,
                        template_config=template, authority=req["parent_cap"])
        elif kind == "space":
            require(item["stage"] == "reserve", "address-space initialization precedes reservation")
            node = item["node"]
            require(f["instance"] == node.instance and f["pages"] == node.own_pages,
                    "address-space initialization belongs to another logical instance")
            event.need("cs", "rip", "rsp", "zero", "physical_pages", *[f"p{i}" for i in range(node.own_pages)])
            require(f["zero"] == 1 and f["physical_pages"] == node.own_pages,
                    "private address-space initialization did not cold-clear its actual owned backing")
            require(f["cs"] == 0x1b and f["rip"] == 0x40000000 and
                    f["rsp"] == 0x40020000 + self.approved[node.template]["stack"] - 8,
                    "created execution frame is not bounded ring3 code/stack")
            self.tree.physical(node, [f[f"p{i}"] for i in range(node.own_pages)])
            item["stage"] = "space"
        elif kind == "channel":
            require(item["stage"] == "space", "bootstrap channel precedes private frame initialization")
            self.channel(item["node"], f["parent_cap"], f["child_cap"], event)
            item["stage"] = "channel"
        elif kind == "publish":
            require(item["stage"] == "channel" and signed(f["result"]) == 0,
                    "runnable publication lacks complete successful transaction")
            node = item["node"]
            require(f["instance"] == node.instance and f["control"] == node.control and
                    f["endpoint"] == node.endpoint and f["pages"] == node.own_pages,
                    "published object differs from reserved execution/control/private configuration")
            require(f["phase"] == 1, "published cell is not READY")
            self.tree.nodes[node.instance] = node
            self.tree.slots[node.slot] = node.instance
            self.tree.history[node.slot] = node.endpoint >> 8
            self.tree.identity_history.add(node.identity)
            require(f["parent_cap"] == node.parent_cap and f["child_cap"] == node.child_cap,
                    "publication changed holder-specific bootstrap capability epochs")
            entitlement, template = item["entitlement"], item["template_config"]
            if node.creation:
                self.domains[node.creation] = {"holder": node.endpoint, "instance": node.instance,
                    "slots": node.allowance_slots, "pages": node.allowance_pages,
                    "max_depth": min(entitlement["max_depth"], node.depth + template["depth"]),
                    "mask": entitlement["mask"] & template["mask"], "recipe": 1, "revoked": False,
                    "valid": True, "parent": item["authority"]}
            self.published.append(event)
            item["stage"] = "publish"
            self.tree.check()
        elif kind == "abort":
            require(item["stage"] in ("reserve", "space", "channel") and signed(f["result"]) < 0,
                    "rollback lacks an unpublished failed reservation")
            node = item["node"]
            if node.pages_owned:
                self.tree.release_pages(node)
            for cap in (node.parent_cap, node.child_cap):
                self.channels.pop(cap, None)
            item["stage"] = "abort"
        elif kind == "result":
            if signed(f["result"]) == 0:
                require(item["stage"] == "publish", "successful management result lacks runnable publication")
            else:
                require(item["stage"] in ("request", "abort"), "rejected creation retained a partial reservation")
                require(not any(e.fields["caller_endpoint"] == key[0] and e.fields["request"] == key[1]
                                for e in self.published), "rejected creation published a child")
            self.finished_transactions.add(key)
            del self.transactions[key]
        self.tree.check()

    def lifecycle(self, event):
        f = event.fields
        self.management_identity(event)
        kind = event.name.removeprefix("host-")
        node = self.tree.node(f["instance"])
        require(f["cell"] == node.slot and f["identity"] == node.identity and
                f["control"] == node.control and f["template"] == node.template and
                f["parent_instance"] == node.parent_instance and f["parent_endpoint"] == node.parent_endpoint,
                "lifecycle event changed its trusted logical owner/template/identity")
        require(f["image"] == self.approved[node.template]["image"] and
                f["role"] == self.approved[node.template]["role"] and f["depth"] == node.depth and
                0 <= f["queued"] <= 8 and 0 <= f["retired_pages"] <= 20 and f["retained"] in (0, 1),
                "lifecycle event counterfeited image, depth, or bounded ownership")
        if kind != "restart":
            require(f["generation"] == node.endpoint >> 8 and f["endpoint"] == node.endpoint,
                    "lifecycle event resurrected an earlier execution incarnation")
        if kind == "fault":
            require(node.ready and f["generation"] == node.endpoint >> 8, "fault belongs to stale execution")
            hardware = [e for e in self.hardware_faults if e.fields["cell"] == node.slot and
                        e.fields["generation"] == node.endpoint >> 8 and e.fields["reason"] == f["result"] and
                        e.index < event.index]
            require(hardware, "lifecycle fault lacks actual privileged hardware trap evidence")
            received = [e for e in self.delivered if e.fields["target"] == node.endpoint and
                        e.fields["operation"] == 15 and e.fields["command"] in (5, 11) and
                        e.index < hardware[-1].index]
            require(received, "faulting dynamic execution lacks authenticated scenario fault/probe request")
            if received[-1].fields["command"] == 5:
                require((hardware[-1].fields["reason"], hardware[-1].fields["error"], hardware[-1].fields["address"]) ==
                        (6, 0, 0), "deliberate ring3 invalid instruction trap has a counterfeit vector/error/address")
            node.faults += 1
            delay = min(4 << node.restarts, 64)
            node.phase = (2 if node.restarts < 3 and (node.endpoint >> 8) < (((1 << 63) - 1) >> 8) and
                          f["tick"] <= MASK64 - delay else 3)
            node.deadline = f["tick"] + delay if node.phase == 2 else 0
            require(f["phase"] == node.phase and f["deadline"] == node.deadline,
                    "fault lifecycle phase/deadline differs from independent bounded restart policy")
            node.last_fault = event
            self.retirements[node.instance] = event
            if node.creation in self.domains:
                self.domains[node.creation]["valid"] = False
            for instance in [node.instance] + self.tree.descendants(node.instance):
                affected = self.tree.node(instance)
                affected.ready = False
                if affected.instance != node.instance:
                    affected.phase, affected.deadline = 0, 0
                self.tree.dead.add(affected.endpoint)
            node.rebind_required = True
        elif kind in ("cancel", "invalidate", "cleanup", "return"):
            require(f["phase"] != 1 and f["phase"] == node.phase and f["deadline"] == node.deadline,
                    "retired subtree remained runnable or changed lifecycle/deadline during mandatory cleanup")
            if f["retained"] == 0:
                require(f["phase"] == 0 and f["deadline"] == 0,
                        "automatically reaped descendant retained runnable/backoff state")
            elif kind in ("cleanup", "return"):
                if f["retired_pages"] == 0:
                    require(kind == "cleanup" and f["phase"] == 2 and f["deadline"] > f["tick"],
                            "recoverable allocation retention lacks bounded nonrunnable backoff")
                else:
                    require(f["phase"] in (3, 4) and f["deadline"] == 0,
                            "released retained child can still restart or run")
        if kind == "cancel":
            event.need("wait_generation", "wait_kind", "wait_deadline")
            endpoint = f["wait_generation"] * 256 + node.slot + 1
            require(endpoint in self.waits and self.waits[endpoint]["kind"] == f["wait_kind"] and
                    self.waits[endpoint]["deadline"] == f["wait_deadline"],
                    "subtree cancellation changed or invented a pending wait")
            del self.waits[endpoint]
            self.cancelled.append(event)
        elif kind == "invalidate":
            target = self.tree.at(f["caller"])
            require(target.instance in self.retirements and self.retirements[target.instance].index < event.index and
                    node.instance in [target.instance] + self.tree.descendants(target.instance),
                    "generation/grant invalidation lacks authorized affected-subtree retirement")
            require(f["queued"] == len(self.queues[node.endpoint]), "generation cleanup changed unrelated FIFO queue accounting")
            require(node.endpoint not in self.waits, "generation invalidation preceded required wait cancellation")
            for cap, grant in list(self.channels.items()):
                if node.endpoint in grant[:2]:
                    del self.channels[cap]
            self.queues[node.endpoint].clear()
            for target, queued in self.queues.items():
                self.queues[target] = [entry for entry in queued if entry.fields["sender"] != node.endpoint]
            node.ready = False
            self.tree.dead.add(node.endpoint)
        elif kind == "cleanup":
            target = self.tree.at(f["caller"])
            require(f["retained"] == int(node.instance == target.instance),
                    "cleanup retained an orphan descendant or dropped an externally owned terminal instance")
            require(node.endpoint not in self.waits and not self.queues[node.endpoint] and
                    not any(node.endpoint in grant[:2] for grant in self.channels.values()),
                    "private cleanup preceded wait/queue/grant retirement")
            require(all(not self.tree.node(instance).own_pages for instance in self.tree.descendants(node.instance)),
                    "private cleanup is not bottom-up")
            if node.creation in self.domains:
                self.domains[node.creation]["valid"] = False
            if f["retired_pages"]:
                require(f["retired_pages"] == node.own_pages, "cleanup returned the wrong physical page allocation")
                self.tree.release_pages(node)
                node.allowance_slots = node.allowance_pages = node.creation = 0
            else:
                require(node.last_fault is not None and f["phase"] == 2 and f["retained"] == 1,
                        "cleanup retained private pages outside recoverable backoff")
            require(f["queued"] >= 0, "invalid bounded queue count")
            self.cleaned.append(event)
        elif kind == "return":
            target = self.tree.at(f["caller"])
            require(f["retained"] == int(node.instance == target.instance),
                    "resource return counterfeited retained versus automatically reaped ownership")
            require(node.instance not in self.returned and node.own_pages == 0,
                    "resource accounting returned a still-owned or already-refunded allocation")
            cleanup = [e for e in self.cleaned if e.fields["instance"] == node.instance and
                       e.fields["retired_pages"] > 0 and e.index < event.index]
            require(len(cleanup) == 1, "resource refund lacks its unique exact preceding physical cleanup")
            prior = cleanup[0].fields
            require(all(f[key] == prior[key] for key in ("pages", "retired_pages", "reserved_slots",
                        "reserved_pages", "creation", "retained", "phase", "deadline")) and
                    f["retired_pages"] == self.approved[node.template]["pages"],
                    "resource return counterfeited exact allocation/reservation refund amount or terminal state")
            self.returned.add(node.instance)
            if f["retained"] == 0:
                self.tree.reap(node)
        elif kind == "backoff":
            require(node.last_fault is not None and f["phase"] == 2 and
                    f["deadline"] == node.deadline,
                    "backoff deadline lacks its exact fault and lifecycle delay")
        elif kind == "restart":
            require(node.last_fault is not None and not node.ready and node.phase == 2 and node.retained and
                    f["generation"] > node.endpoint >> 8 and f["phase"] == 1 and
                    f["tick"] >= node.last_fault.fields["tick"] + 4,
                    "cold restart revived a destroyed/stale execution or violated delay")
            require(not self.tree.children(node.instance), "restart inherited descendants from retired owner generation")
            node.endpoint = f["generation"] * 256 + node.slot + 1
            require(node.endpoint not in self.tree.dead and f["generation"] > self.tree.history[node.slot],
                    "automatic restart recycled execution generation history")
            self.tree.history[node.slot] = f["generation"]
            event.need("zero", "physical_pages", "cs", "rip", "rsp", *[f"p{i}" for i in range(node.own_pages)])
            require(f["zero"] == 1 and f["physical_pages"] == node.own_pages and
                    tuple(f[f"p{i}"] for i in range(node.own_pages)) == node.pages_owned and
                    f["cs"] == 0x1b and f["rip"] == 0x40000000 and
                    f["rsp"] == 0x40020000 + self.approved[node.template]["stack"] - 8,
                    "restart did not cold-clear its own retained physical backing and ring3 frame")
            node.physical_history[node.endpoint] = node.pages_owned
            node.phase, node.deadline = 1, 0
            node.restarts += 1
            node.ready = True
            node.creation = 0
            self.restarts.append(event)
        elif kind == "rebind":
            require(node.ready and node.rebind_required and f["caller_endpoint"] == node.parent_endpoint and
                    f["endpoint"] == node.endpoint and f["request"] > 0,
                    "fresh-channel rebind lacks live direct-owner current-generation entitlement")
            require(f["request"] > self.accepted_requests.get(f["caller_endpoint"], 0),
                    "rebind reused the owner accepted create/rebind request namespace")
            self.accepted_requests[f["caller_endpoint"]] = f["request"]
            parent_domain = self.root_domain if node.parent_instance == 0 else self.tree.node(node.parent_instance).creation
            require(parent_domain in self.domains and self.domains[parent_domain]["valid"] and
                    not self.domains[parent_domain]["revoked"],
                    "rebind restored authority from a revoked/retired ancestor recipe")
            if not self.approved[node.template]["depth"]:
                require(f["creation"] == 0, "leaf rebind manufactured creation-domain authority")
            if self.approved[node.template]["depth"]:
                require(0x60 < f["creation"] & 255 <= 0x68 and
                        f["creation"] >> 8 > self.tree.maximum_epoch,
                        "rebind recycled creation authority or restored a stale handle")
                self.tree.maximum_epoch = f["creation"] >> 8
                self.tree.object_epochs.add(f["creation"] >> 8)
            node.creation = f["creation"]
            if node.creation:
                ancestor = self.domains[parent_domain]
                self.domains[node.creation] = {"holder": node.endpoint, "instance": node.instance,
                    "slots": node.allowance_slots, "pages": node.allowance_pages,
                    "max_depth": min(ancestor["max_depth"], node.depth + self.approved[node.template]["depth"]),
                    "mask": ancestor["mask"] & self.approved[node.template]["mask"], "recipe": 1,
                    "revoked": False, "valid": True, "parent": parent_domain}
            self.channel(node, f["parent_cap"], f["child_cap"], event)
            node.rebind_required = False
            self.rebound.append(event)
        elif kind == "stop":
            require(f["caller_endpoint"] == node.parent_endpoint and f["phase"] == 4,
                    "stop lacks direct-owner authority and terminal policy retirement")
            self.retirements[node.instance] = event
            for instance in [node.instance] + self.tree.descendants(node.instance):
                affected = self.tree.node(instance)
                affected.phase, affected.deadline = (4, 0) if affected.instance == node.instance else (0, 0)
                affected.ready = False
                self.tree.dead.add(affected.endpoint)
        elif kind == "reap":
            require(f["caller_endpoint"] == node.parent_endpoint and not node.ready,
                    "reap accepted a live child or unrelated owner")
            self.tree.reap(node)
        elif kind == "status":
            require(f["caller_endpoint"] == node.parent_endpoint, "authoritative status used an unrelated owner")
            require(f["generation"] == node.endpoint >> 8 and f["phase"] == node.phase and
                    f["deadline"] == node.deadline and f["pages"] == node.own_pages and
                    f["reserved_slots"] == node.allowance_slots and f["reserved_pages"] == node.allowance_pages,
                    "authoritative status contradicts independently observed phase/generation/allocation/reservation")
        self.tree.check()

    def ipc(self, event):
        f = event.fields
        event.need("sender", "target", "cap", "operation", "length", "request", "command", "reserved", "argument", "value")
        endpoint, node = self.principal(event)
        require(f["operation"] in (15, 16) and f["length"] == 32 and f["request"] > 0 and
                1 <= f["command"] <= 11 and f["reserved"] == 0, "hosting IPC payload is malformed")
        if f["operation"] == 15:
            command, argument, value = f["command"], f["argument"], f["value"]
            require((command in (1, 2) and value == 0) or
                    (command in (3, 4, 8) and 1 <= argument <= 1000 and value == 0) or
                    (command in (5, 6) and argument == value == 0) or
                    (command == 7 and argument > 0 and value > 0) or
                    (command in (9, 10) and argument > 0 and value == 0) or
                    (command == 11 and 1 <= argument <= 5 and value == 0),
                    "accepted hosting request violates its exact bounded command contract")
        else:
            require(f["command"] <= 10 and f["value"] == expected(f["command"], f["argument"]),
                    "accepted hosting reply has unsupported command or counterfeit independently known result")
        packet = (f["sender"], f["target"], f["operation"], f["request"],
                  f["command"], f["reserved"], f["argument"], f["value"])
        if event.name == "host-ipc-enqueue":
            require(endpoint == f["sender"] and f["cap"] in self.channels and
                    self.channels[f["cap"]] == (f["sender"], f["target"], f["operation"]),
                    "IPC enqueue lacks exact holder/target/generation narrow authority")
            target_slot = (f["target"] & 255) - 1
            require(target_slot >= 4 or target_slot == 3, "dynamic IPC reached an unauthorized root service")
            if target_slot >= 4:
                target = self.tree.at(target_slot)
                require(target.ready and target.endpoint == f["target"], "IPC enqueue targets a retired execution")
            require(len(self.queues[f["target"]]) < 8, "external bounded IPC queue overflow")
            # Store sender explicitly to compact only retired-related work.
            self.queues[f["target"]].append(event)
            self.enqueued.append(event)
        else:
            require(endpoint == f["target"], "authenticated delivery target differs from receiver generation")
            queue = self.queues[f["target"]]
            require(queue, "IPC delivery lacks an authorized enqueue")
            enqueue = queue.pop(0)
            ef = enqueue.fields
            original = (ef["sender"], ef["target"], ef["operation"], ef["request"],
                        ef["command"], ef["reserved"], ef["argument"], ef["value"])
            require(original == packet and enqueue.index < event.index,
                    "IPC delivery counterfeited payload/authenticated sender or changed FIFO")
            if node:
                require(endpoint in node.entered and endpoint in node.cold and endpoint in node.memories,
                        "child processed IPC before real ring3 entry and cold/private-memory proof")
            self.delivered.append(event)
            if f["operation"] == 16:
                self.replies[(endpoint, f["request"])].append(event)

    def app(self, event):
        endpoint, node = self.principal(event)
        value, extra = event.need("value", "extra")
        f = event.fields
        event.need("endpoint", "instance", "template", "depth", "parent_endpoint")
        require(f["endpoint"] == endpoint and f["instance"] == (node.instance if node else 0) and
                f["template"] == (node.template if node else 0) and f["depth"] == (node.depth if node else 0) and
                f["parent_endpoint"] == (node.parent_endpoint if node else 0),
                "application evidence counterfeited authenticated registry ancestry or generation")
        if event.name == "host-entry":
            require(node is not None and value == endpoint and extra == node.instance and
                    endpoint not in node.entered, "real child entry lacks published exact instance/endpoint")
            require(not self.transactions, "child ran before owner received committed creation result")
            node.entered.add(endpoint)
        elif event.name == "host-cold":
            require(node is not None and endpoint in node.entered and endpoint not in node.cold and
                    value == extra == 0, "child cold restart/reuse contains residual private memory")
            node.cold.add(endpoint)
        elif event.name == "host-memory":
            require(node is not None and endpoint in node.cold and
                    value == (MEMORY_SALT ^ endpoint) and extra == (value ^ MASK64),
                    "private-memory sentinel is not execution/instance-specific or was changed")
            node.memories[endpoint] = (value, extra)
        elif event.name in ("host-computed", "host-verified", "host-nested-verified"):
            request = value
            if event.name == "host-computed":
                received = [e for e in self.delivered if e.fields["target"] == endpoint and
                            e.fields["operation"] == 15 and e.fields["request"] == request]
                require(len(received) == 1 and received[0].fields["command"] == 1 and
                        extra == calculate(received[0].fields["argument"]),
                        "ring3 worker computation lacks authenticated challenge or correct known bytes")
            else:
                replies = self.replies[(endpoint, request)]
                require(replies, "parent verified a late/unsolicited or undelivered reply")
                candidates = [e for e in replies if e.fields["value"] == extra]
                require(len(candidates) == 1, "parent reply matcher selected an ambiguous/wrong result")
                reply = candidates[0]
                rf = reply.fields
                require(extra == expected(rf["command"], rf["argument"]),
                        "external scalar recomputation disagrees with parent progress")
                originals = [e for e in self.enqueued if e.fields["sender"] == endpoint and
                             e.fields["target"] == rf["sender"] and e.fields["operation"] == 15 and
                             e.fields["request"] == request and e.fields["command"] == rf["command"] and
                             e.fields["argument"] == rf["argument"]]
                require(len(originals) == 1 and originals[0].index < reply.index < event.index,
                        "parent progress has no exact current-generation outstanding request")
                if rf["command"] == 1:
                    computations = [e for e in self.events if e.name == "host-computed" and
                        e.fields.get("cell") == (rf["sender"] & 255) - 1 and
                        e.fields.get("generation") == rf["sender"] >> 8 and
                        e.fields.get("value") == request and e.fields.get("extra") == extra and
                        originals[0].index < e.index < reply.index]
                    require(len(computations) == 1, "verified direct challenge lacks real ring3 processing")
                elif rf["command"] == 2:
                    child = self.tree.at((rf["sender"] & 255) - 1)
                    proofs = [e for e in self.events if e.name == "host-nested-verified" and
                              e.fields.get("cell") == child.slot and
                              e.fields.get("generation") == rf["sender"] >> 8 and
                              originals[0].index < e.index < reply.index]
                    wanted = 1 if self.scenario == 23 else 2
                    require(len(proofs) == wanted, "nested RPC lacks every independently matched grandchild reply")
                    grandchildren = set()
                    for proof in proofs:
                        found = [e for e in self.delivered if e.fields["target"] == child.endpoint and
                                 e.fields["operation"] == 16 and e.fields["request"] == proof.fields["value"]]
                        require(len(found) == 1 and found[0].fields["argument"] == (rf["argument"] ^ NESTED_SALT) and
                                found[0].fields["value"] == calculate(rf["argument"] ^ NESTED_SALT),
                                "nested RPC did not process the independently salted known challenge")
                        grandchild = self.tree.at((found[0].fields["sender"] & 255) - 1)
                        require(grandchild.parent_instance == child.instance and grandchild.depth == 2,
                                "nested response came from an unrelated/sibling worker")
                        grandchildren.add(found[0].fields["sender"])
                    require(len(grandchildren) == wanted, "supervisor consumed one worker reply twice")
                if event.name == "host-nested-verified":
                    require(node is not None and node.template == 1 and rf["command"] == 1,
                            "grandchild matcher ran outside the approved supervisor")
                else:
                    require(endpoint == 0x104, "independent root owner verification came from another application")
                self.verified.append((event, reply, originals[0]))
        elif event.name == "host-storage-denied":
            require(node is not None and signed(value) == signed(extra) == -2,
                    "dynamic template acquired unauthorized filesystem or block authority")
            for operation, target in ((10, 0x102), (7, 0x101)):
                rejected = [e for e in self.events if e.name == "storage-reject" and
                    e.fields.get("cell") == node.slot and e.fields.get("identity") == node.identity and
                    e.fields.get("generation") == endpoint >> 8 and e.fields.get("operation") == operation and
                    e.fields.get("target") == target and signed(e.fields.get("outcome", 0)) == -2 and
                    e.index < event.index]
                require(len(rejected) == 1, "storage denial marker lacks actual checked FS/block send rejection")
        elif event.name == "host-ledger":
            require(endpoint == 0x104 or (node is not None and node.template == 1),
                    "resource ledger report belongs to a different domain owner")
            slots = tuple((value >> (16 * i)) & 0xffff for i in range(3))
            counts = tuple((extra >> (16 * i)) & 0xffff for i in range(3))
            require(value >> 48 == extra >> 48 == 0, "ledger report contains unknown packed fields")
            ledger = self.tree.ledger(node.instance if node else 0)
            require(slots == (ledger[0], ledger[2], ledger[4]) and
                    counts == (ledger[1], ledger[3], ledger[5]),
                    "reported budget differs from independently reconstructed reservations/refunds")
            self.ledger_events.append(event)
        elif event.name == "host-stale":
            require(endpoint == 0x104 and signed(extra) == -3, "stale authority report did not reject the old object")
            require(value in self.tree.dead or value in self.capabilities_seen or
                    any(n.control == value and not n.retained for n in self.tree.nodes.values()),
                    "stale rejection used an invented token rather than the retired endpoint/control/channel")
            if value in self.tree.dead:
                proof = [e for e in self.ipc_rejected if e.fields["cell"] == f["cell"] and
                         e.fields["target"] == value and signed(e.fields["result"]) == -3 and e.index < event.index]
            elif any(n.control == value and not n.retained for n in self.tree.nodes.values()):
                proof = [e for e in self.calls if e.fields["cell"] == f["cell"] and
                         e.fields["call"] in (14, 16) and e.fields["arg0"] == value and
                         signed(e.fields["result"]) == -3 and e.index < event.index]
            else:
                proof = [e for e in self.ipc_rejected if e.fields["cell"] == f["cell"] and
                         e.fields["cap"] == value and e.fields["target"] not in self.tree.dead and
                         signed(e.fields["result"]) == -3 and e.index < event.index]
                require(value not in self.channels, "stale capability report named still-valid authority")
            require(proof, "stale marker lacks exact actual checked endpoint/control/capability rejection")
            self.stale.append(event)
        elif event.name == "host-denied":
            require(endpoint == 0x104 and 1 <= value <= 17 and signed(extra) < 0,
                    "management pressure/authority denial is malformed")
            candidates = [e for e in (self.ipc_rejected if value in (14, 15) else self.calls)
                          if e.fields["cell"] == f["cell"] and e.fields["generation"] == f["generation"]]
            require(candidates and candidates[-1].index < event.index and
                    candidates[-1].fields["result"] == extra,
                    "denial report lacks its actual checked kernel-call result")
            self.denied.append(event)
        elif event.name == "host-copied":
            require(node is not None and signed(extra) == -2, "copied parent authority became child-owned")
            incoming = [e for e in self.delivered if e.fields["target"] == endpoint and
                        e.fields["operation"] == 15 and e.fields["command"] in (7, 9, 10) and
                        e.fields["argument"] == value and e.index < event.index]
            require(incoming, "copied authority denial lacks the exact authenticated parent challenge")
            packet = incoming[-1]
            if packet.fields["command"] == 7:
                proof = [e for e in self.ipc_rejected if e.fields["cell"] == node.slot and
                         e.fields["generation"] == endpoint >> 8 and e.fields["cap"] == value and
                         e.fields["target"] == packet.fields["value"] and signed(e.fields["result"]) == -2 and
                         packet.index < e.index < event.index]
            else:
                call = 15 if packet.fields["command"] == 9 else 13
                proof = [e for e in self.calls if e.fields["cell"] == node.slot and
                         e.fields["generation"] == endpoint >> 8 and e.fields["call"] == call and
                         signed(e.fields["result"]) == -2 and packet.index < e.index < event.index]
            require(proof, "copied IPC/control/domain authority marker lacks actual kernel holder rejection")
            self.copy_denials.append(event)
        elif event.name == "host-sleep-start":
            require(node is not None and extra == endpoint and 1 <= value <= 1000,
                    "worker sleep is unbounded or reports another execution")
        elif event.name == "host-sleep-return":
            require(node is not None and value == (MEMORY_SALT ^ endpoint) and
                    endpoint not in self.waits, "sibling sleep lost memory or completed before timed wake")
            self.sleep_returns.append(event)
        elif event.name == "host-timeout":
            require(node is not None and 1 <= value <= 1000 and signed(extra) == -8,
                    "worker finite receive did not observe exact timeout outcome")
            incoming = [e for e in self.delivered if e.fields["target"] == endpoint and
                        e.fields["operation"] == 15 and e.fields["command"] == 8 and e.fields["argument"] == value]
            require(incoming and any(wake.name == "wake" and state["kind"] == 2 and
                    state["deadline"] - state["tick"] == value and signed(wake.fields["result"]) == -8 and
                    incoming[-1].index < state["index"] < wake.index < event.index
                    for wake, state, receiver in self.wakes if receiver == endpoint),
                    "worker timeout lacks actual bounded receive arm and timed completion")
            self.timeouts.append(event)
        elif event.name == "host-rebound":
            require(endpoint == 0x104 and any(e.fields["endpoint"] == extra for e in self.rebound) and value in self.tree.dead,
                    "owner rebind report lacks explicit valid current-generation provisioning")
        elif event.name == "host-fifo":
            require(endpoint == 0x104 and value < extra, "sleeping sibling lost FIFO request order")
            a = [item for item in self.verified if item[0].fields["value"] == value]
            b = [item for item in self.verified if item[0].fields["value"] == extra]
            require(len(a) == len(b) == 1 and a[0][1].fields["sender"] == b[0][1].fields["sender"] and
                    a[0][1].index < b[0][1].index and a[0][2].index < b[0][2].index,
                    "two outstanding sibling requests did not retain distinct FIFO delivery and matching")
            self.fifo.append((event, a[0], b[0]))
        elif event.name == "host-reaped":
            require(endpoint == 0x104 and any(n.control == value and n.instance == extra and not n.retained
                                           for n in self.tree.nodes.values()),
                    "owner claimed reap before actual terminal record release")
        elif event.name == "host-backoff-observed":
            require(node is not None and node.template == 1 and extra == 2,
                    "supervisor did not inspect grandchild delayed backoff")
            worker = self.tree.at((value & 255) - 1)
            require(worker.endpoint == value and worker.parent_instance == node.instance and
                    worker.last_fault is not None and not worker.ready,
                    "observed delayed worker is not in the actual affected subtree/current execution")
            require(any(e.name == "host-status" and e.fields["caller_endpoint"] == endpoint and
                        e.fields["instance"] == worker.instance and e.fields["phase"] == 2 and
                        worker.last_fault.index < e.index < event.index for e in self.events),
                    "backoff observation lacks an exact direct-owner authoritative status query")
        elif event.name == "host-probe-verified":
            require(endpoint == 0x104 and self.scenario == 23 and 1 <= value <= 5 and extra in (13, 14),
                    "dynamic CPU isolation report has an invalid owner/mode/vector")
            self.probes.append(event)
        elif event.name == "host-complete":
            require(endpoint == 0x104 and value == self.scenario and extra == 0 and
                    self.tree.ledger() == (0, 0, 0, 0, 4, 48) and not self.tree.slots,
                    "completion marker lacks full actual teardown and exact resource return")
            self.completed.append(event)
        else:
            raise AssertionError(f"unknown hosting application event {event.name}")

    def wait(self, event):
        endpoint, _ = self.principal(event, ready=event.name == "wait-arm")
        kind, deadline = event.need("kind", "deadline")
        require(kind in (1, 2), "wait kind is not finite sleep/receive")
        if event.name == "wait-arm":
            require(endpoint not in self.waits and event.fields["tick"] < deadline <= event.fields["tick"] + 1000,
                    "finite wait deadline overflowed, duplicated, or became unbounded")
            self.waits[endpoint] = {"kind": kind, "deadline": deadline, "index": event.index,
                                    "tick": event.fields["tick"]}
        else:
            require(endpoint in self.waits and self.waits[endpoint]["kind"] == kind and
                    self.waits[endpoint]["deadline"] == deadline, "wake changed a wait's original deadline")
            if event.name == "wake":
                event.need("reason", "result")
                if kind == 1 or signed(event.fields["result"]) == -8:
                    require(event.fields["tick"] >= deadline, "timed wake fired before original deadline")
                require(endpoint not in self.tree.dead, "retired generation received a stale deferred completion")
            self.wakes.append((event, dict(self.waits[endpoint]), endpoint))
            del self.waits[endpoint]

    def domain_status(self, event):
        endpoint, node = self.principal(event)
        f = event.fields
        event.need("domain", "holder", "domain_instance", "slot_limit", "page_limit", "owned_slots",
                   "owned_pages", "domain_reserved_slots", "domain_reserved_pages", "available_slots",
                   "available_pages", "max_depth", "template_mask", "recipe", "revoked")
        handle = f["domain"]
        require(0x60 < handle & 255 <= 0x68 and 0 < handle >> 8 <= ((1 << 63) - 1) >> 8 and
                f["holder"] == endpoint and f["domain_instance"] == (node.instance if node else 0),
                "domain query lacks exact typed current-generation logical holder")
        if node is None:
            require(endpoint == 0x104 and (f["slot_limit"], f["page_limit"], f["max_depth"],
                    f["template_mask"], f["recipe"]) == (4, 48, 2, 3, 1),
                    "configured root creation allowance differs from sealed root400 domain")
            if self.root_domain is None:
                require(not self.published and not f["revoked"], "root domain was anchored after publication/revocation")
                self.root_domain = handle
                self.tree.object_epochs.add(handle >> 8)
                self.tree.maximum_epoch = max(self.tree.maximum_epoch, handle >> 8)
                self.domains[handle] = {"holder": endpoint, "instance": 0, "slots": 4, "pages": 48,
                    "max_depth": 2, "mask": 3, "recipe": 1, "revoked": False, "valid": True, "parent": None}
            require(handle == self.root_domain, "root creation-domain handle changed without generation retirement")
        else:
            require(node.template == 1 and handle == node.creation, "domain query leaked another instance's authority")
        require(handle in self.domains and self.domains[handle]["valid"], "domain query revived retired creation epoch")
        entitlement = self.domains[handle]
        require((f["slot_limit"], f["page_limit"], f["max_depth"], f["template_mask"], f["recipe"], f["revoked"]) ==
                (entitlement["slots"], entitlement["pages"], entitlement["max_depth"], entitlement["mask"],
                 entitlement["recipe"], int(entitlement["revoked"])), "domain query changed sealed/attenuated entitlement")
        ledger = self.tree.ledger(node.instance if node else 0)
        require((f["owned_slots"], f["owned_pages"], f["domain_reserved_slots"], f["domain_reserved_pages"],
                 f["available_slots"], f["available_pages"]) == ledger,
                "authoritative kernel domain ledger differs from independent logical reservations")

    def run(self):
        for event in self.events:
            f = event.fields
            event.need("cell", "identity", "generation", "tick")
            require(f["tick"] >= self.last_tick, "structured trace tick went backwards")
            self.last_tick = f["tick"]
            if event.name == "boot":
                slot = f["cell"]
                if slot >= 4:
                    endpoint, node = self.principal(event)
                    require(node is not None and any(e.fields["instance"] == node.instance and
                            e.fields["generation"] == f["generation"] for e in self.restarts),
                            "dynamic boot was prestarted or lacks actual automatic restart")
                    event.need("physical_pages", *[f"p{i}" for i in range(node.own_pages)])
                    require(f["physical_pages"] == node.own_pages and
                            tuple(f[f"p{i}"] for i in range(node.own_pages)) == node.pages_owned and
                            f.get("image") == self.approved[node.template]["image"] and f.get("abi") == 4 and
                            f.get("entry") == 0x40000000, "restart changed retained physical/image identity")
                    continue
                require(slot in self.roots and slot not in self.root_boots and
                        f["identity"] == self.roots[slot]["identity"] and f["generation"] == 1 and
                        f.get("abi") == 4 and f.get("entry") == 0x40000000 and
                        f.get("image") == self.roots[slot]["image"], "original root boot contract differs")
                count = self.roots[slot]["pages"]
                event.need("physical_pages", *[f"p{i}" for i in range(count)])
                require(f["physical_pages"] == count, "root physical allocation lost the original private budget")
                for page in (f[f"p{i}"] for i in range(count)):
                    require(0 <= page < 128 and page not in self.tree.page_owners,
                            "root writable backing overlaps another physical allocation")
                    self.tree.page_owners[page] = -(slot + 1)
                self.root_boots[slot] = event
            elif event.name.startswith("host-") and event.name.removeprefix("host-") in MANAGEMENT:
                require(len(self.root_boots) == 4, "dynamic management ran before all original roots booted")
                if event.name in ("host-request", "host-reserve", "host-space", "host-channel", "host-publish",
                                  "host-abort", "host-result"):
                    self.creation(event)
                elif event.name == "host-revoke":
                    self.management_identity(event)
                    require(f["caller_endpoint"] == 0x104 and signed(f["result"]) == 0,
                            "creation revocation came from an unrelated generation")
                    token = f["parent_cap"]
                    require(token in self.domains and self.domains[token]["holder"] == f["caller_endpoint"],
                            "revocation names an unknown or wrong-owner creation object")
                    revoked = {token}
                    for _ in range(2):
                        revoked |= {handle for handle, domain in self.domains.items() if domain["parent"] in revoked}
                    for handle in revoked:
                        self.domains[handle]["revoked"] = True
                else:
                    self.lifecycle(event)
            elif event.name == "host-domain":
                self.domain_status(event)
            elif event.name in ("host-ipc-enqueue", "host-ipc-deliver"):
                self.ipc(event)
            elif event.name == "host-ipc-reject":
                self.principal(event)
                require(signed(f.get("result", f.get("outcome", 0))) < 0,
                        "IPC rejection carried a successful outcome")
                self.ipc_rejected.append(event)
            elif event.name == "host-call":
                endpoint, _ = self.principal(event)
                event.need("call", "arg0", "arg1", "arg2", "result")
                require(endpoint in (0x104,) or f["cell"] >= 4, "management call used an unauthorized root")
                self.calls.append(event)
            elif event.name.startswith("host-"):
                self.app(event)
            elif event.name == "entry":
                endpoint, _ = self.principal(event)
                self.kernel_entries.add(endpoint)
            elif event.name in ("wait-arm", "wake", "wait-cancel"):
                self.wait(event)
            elif event.name in ("fault", "exit", "quarantine"):
                require(f["cell"] >= 4, "hosting preservation faulted/restarted an existing root")
                if event.name == "fault":
                    self.principal(event)
                    event.need("reason", "error", "address")
                    self.hardware_faults.append(event)
            elif event.name == "cap-delegate":
                endpoint, _ = self.principal(event)
                require(endpoint == 0x102 and f.get("holder") == 0x103 and f.get("target") == 0x102 and
                        f.get("rights") == 4 and f.get("cap", 0) > 0,
                        "existing root delegation escaped its original narrow storage scope")
                epoch = f["cap"] >> 8
                require(1 <= f["cap"] & 255 <= 32 and epoch > self.maximum_capability_epoch and
                        epoch not in self.capability_epochs, "root delegation recycled a global capability epoch")
                self.capability_epochs.add(epoch)
                self.capabilities_seen.add(f["cap"])
                self.maximum_capability_epoch = epoch
            elif event.name == "cap-revoke":
                endpoint, _ = self.principal(event)
                require(endpoint == 0x102, "unrelated cell revoked a preserved root grant")
            elif event.name.startswith("storage-") or event.name.startswith("hosting-storage-") or event.name in (
                    "healthy-memory", "reset-memory", "idle", "idle-enter", "idle-exit", "idle-wake"):
                if f["cell"] < 4:
                    require(f["identity"] == ROOT_IDS[f["cell"]] and f["generation"] == 1,
                            "independent storage progress belongs to a changed root generation")
            else:
                raise AssertionError(f"unknown hosting trace event {event.name}")
        require(len(self.root_boots) == 4 and not self.transactions, "incomplete root boot or creation transaction")
        require(len(self.completed) == 1 and self.ledger_events and
                self.tree.ledger() == (0, 0, 0, 0, 4, 48), "missing exact final resource conservation")
        require(len(self.published) >= (4 if self.scenario == 21 else 6 if self.scenario == 22 else 5),
                "insufficient genuine free-slot runtime creation")
        require(self.timeouts, "no worker proved finite receive timeout under actual scheduler")
        require(all(n.endpoint in n.entered and n.entered == n.cold == set(n.memories)
                    for n in self.tree.nodes.values()),
                "published child lacks actual cold ring3 execution and private-memory proof")
        for node in self.tree.nodes.values():
            denials = [e for e in self.events if e.name == "host-storage-denied" and
                       e.fields["cell"] == node.slot and e.fields["identity"] == node.identity]
            require(all(any(e.fields["generation"] == endpoint >> 8 for e in denials) for endpoint in node.entered),
                    "dynamic execution lacks explicit checked storage authority denial")
        root_ledgers = [e for e in self.ledger_events if e.fields["cell"] == 3]
        require(any(e.index < self.published[0].index for e in root_ledgers) and
                any(e.index > max(x.index for x in self.events if x.name == "host-reap") for e in root_ledgers),
                "initial/final owner-visible exact allowance ledger is missing")
        require(any(e.fields["cell"] == supervisorslot for e in self.ledger_events
                    for supervisorslot in [n.slot for n in self.tree.nodes.values() if n.template == 1]),
                "supervisor did not authoritatively inspect its attenuated descendant ledger")
        return self


def verify_storage(events, observer):
    """Rebuild named file bytes from actual owning app/FS/block transactions."""
    chosen = [event for event in events if event.name.startswith("storage-") or
              event.name.startswith("hosting-storage-")]
    by_kind = defaultdict(list)
    for event in chosen:
        event.need("cell", "identity", "generation", "tick")
        f = event.fields
        if event.name == "storage-reject" and f["cell"] >= 4:
            require(signed(f.get("outcome", 0)) == -2, "dynamic storage request escaped narrow authority")
            continue
        require(f["cell"] in (0, 1, 2) and f["identity"] == ROOT_IDS[f["cell"]] and f["generation"] == 1,
                "storage preservation used a changed or unrelated owner/service generation")
        if event.name == "storage-ipc":
            event.need("target", "cap", "operation", "length", "request", "handle", "offset", "result", "data")
            op = f["operation"]
            target = 1 if f["cell"] in (0, 2) else 0 if op in (7, 8) else 2
            require(f["target"] == 256 + target + 1 and f["cap"] > 0 and f["request"] > 0,
                    "storage transfer targeted a stale service or lacks actual authority")
            require((f["cell"] == 0 and op == 9) or (f["cell"] == 1 and op in (7, 8, 14)) or
                    (f["cell"] == 2 and op in (10, 11, 12)), "storage IPC changed its established routing")
        elif event.name == "storage-block":
            require(f["cell"] == 0, "block participation came from another cell")
            event.need("request", "operation", "result")
        elif event.name in ("storage-fs", "storage-link"):
            require(f["cell"] == 1, "filesystem participation came from another cell")
            event.need("request", *(('block_request',) if event.name == "storage-link" else ('operation', 'result')))
        elif event.name in ("storage-verified", "hosting-storage-ready", "hosting-storage-cycle"):
            require(f["cell"] == 2, "storage application verification belongs to another cell")
        else:
            raise AssertionError(f"unexpected hosting storage event {event.name}")
        by_kind[event.name].append(event)

    def matches(name, **fields):
        return [event for event in by_kind[name] if all(event.fields.get(key) == value for key, value in fields.items())]

    def one(name, **fields):
        result = matches(name, **fields)
        require(len(result) == 1, f"missing or duplicated exact {name} service evidence {fields}")
        return result[0]

    requests = matches("storage-ipc", cell=2)
    require(len({event.fields["request"] for event in requests}) == len(requests),
            "independent storage app reused a request identity")
    handles, names, lengths = {}, {}, {name: len(payload) for name, payload in PAYLOADS.items()}
    verified_reads, writes = [], []
    completed_app = []
    transfers = [event for event in matches("storage-ipc", cell=1) if event.fields["operation"] in (7, 8)]
    require([event.fields["request"] for event in transfers] == list(range(1, len(transfers) + 1)),
            "filesystem block sequence lost bounded request identity ordering")
    for transfer in transfers:
        f = transfer.fields
        link = one("storage-link", block_request=f["request"])
        require(link.index < transfer.index, "block transfer preceded its owning app request link")
        app = one("storage-ipc", cell=2, request=link.fields["request"])
        require(app.index < link.index, "filesystem manufactured an unrelated block operation")
        applied = matches("storage-block", request=f["request"], operation=f["operation"])
        answer = matches("storage-ipc", cell=0, request=f["request"], operation=9)
        if not applied or not answer:
            require(transfer.index > observer.completed[0].index, "required storage transfer is incomplete before completion")
            continue
        require(len(applied) == len(answer) == 1 and transfer.index < applied[0].index < answer[0].index and
                f["offset"] == answer[0].fields["offset"] and
                f["result"] == applied[0].fields["result"] == answer[0].fields["result"],
                "actual block transfer lost ordered applied outcome/reply extent")
    for request in requests:
        f = request.fields
        replies = matches("storage-ipc", cell=1, operation=14, request=f["request"])
        outcomes = matches("storage-fs", request=f["request"], operation=f["operation"])
        if not replies or not outcomes:
            require(request.index > observer.completed[0].index, "storage app operation never crossed both services")
            continue
        require(len(replies) == len(outcomes) == 1 and request.index < outcomes[0].index < replies[0].index and
                outcomes[0].fields["result"] == replies[0].fields["result"],
                "filesystem result lacks unique actual owning app operation")
        reply = replies[0]
        rf = reply.fields
        completed_app.append((request, reply))
        if f["operation"] == 10:
            encoded = f["handle"].to_bytes(8, "little") + f["offset"].to_bytes(4, "little") + f["result"].to_bytes(4, "little")
            name = encoded[:f["length"] - 8].decode("ascii")
            require(name in PAYLOADS and name not in names and rf["result"] == 0 and rf["handle"] != 0,
                    "preservation workload did not open each exact independent named file")
            handle = rf["handle"]
            require(handle not in handles and handle >> 32 == 1, "file handle reused or changed filesystem generation")
            handles[handle] = name
            names[name] = handle
            links = matches("storage-link", request=f["request"])
            if name == "/hello":
                require(not links, "opening existing /hello unexpectedly changed backing")
            else:
                base = 128 if name == "/alpha" else 256
                require(len(links) == 16, "new file publication lacks complete zero-before-publication creation")
                cleared = []
                for link in links:
                    block = one("storage-ipc", cell=1, request=link.fields["block_request"], operation=8)
                    answer = one("storage-ipc", cell=0, request=link.fields["block_request"], operation=9)
                    applied = one("storage-block", request=link.fields["block_request"], operation=8)
                    require(request.index < link.index < block.index < applied.index < answer.index < reply.index and
                            block.fields["data"] == 0 and block.fields["result"] == applied.fields["result"] ==
                            answer.fields["result"] == 8, "new file was published before actual zero writes completed")
                    cleared.append(block.fields["offset"])
                require(cleared == list(range(base, base + 128, 8)), "fresh file slots overlap or were incompletely cleared")
            continue
        require(f["handle"] in handles and rf["handle"] == f["handle"] and rf["offset"] == f["offset"],
                "file chunk changed its stable owning handle or extent")
        name = handles[f["handle"]]
        payload = PAYLOADS[name]
        count = f["result"]
        require(f["length"] == 32 and 1 <= count <= 8 and f["offset"] <= len(payload),
                "file chunk is outside bounded known payload")
        expected_bytes = payload[f["offset"]:f["offset"] + count]
        require(count == min(8, len(payload) - f["offset"]) if f["offset"] < len(payload) else count == 8,
                "file chunk request is not the expected independently known extent")
        links = matches("storage-link", request=f["request"])
        if not expected_bytes:
            require(f["operation"] == 11 and rf["result"] == 0 and len(links) <= 1,
                    "known EOF changed bytes or produced extra transfers")
            if links:
                empty = one("storage-ipc", cell=1, request=links[0].fields["block_request"], operation=7)
                applied = one("storage-block", request=links[0].fields["block_request"], operation=7)
                answer = one("storage-ipc", cell=0, request=links[0].fields["block_request"], operation=9)
                require(request.index < links[0].index < empty.index < applied.index < answer.index < reply.index and
                        empty.fields["result"] == applied.fields["result"] == answer.fields["result"] == 0 and
                        answer.fields["data"] == rf["data"] == 0,
                        "EOF zero-byte block RPC changed data or lacks matching service outcome")
            continue
        require(len(links) == 1 and rf["result"] == len(expected_bytes), "file chunk omitted actual block participation")
        link = links[0]
        operation = 7 if f["operation"] == 11 else 8
        block = one("storage-ipc", cell=1, request=link.fields["block_request"], operation=operation)
        applied = one("storage-block", request=link.fields["block_request"], operation=operation)
        answer = one("storage-ipc", cell=0, request=link.fields["block_request"], operation=9)
        base = {"/hello": 0, "/alpha": 128, "/beta": 256}[name]
        word = int.from_bytes(expected_bytes.ljust(8, b"\0"), "little")
        require(request.index < link.index < block.index < applied.index < answer.index < outcomes[0].index < reply.index and
                block.fields["offset"] == base + f["offset"] and answer.fields["offset"] == block.fields["offset"] and
                block.fields["result"] == applied.fields["result"] == answer.fields["result"] == rf["result"],
                "known file bytes did not traverse actual FS/block operation with matching result")
        if f["operation"] == 12:
            require(name != "/hello" and f["data"] == block.fields["data"] == word,
                    "unrelated writable file payload changed or /hello was overwritten")
            writes.append((name, request, reply))
        else:
            verified = one("storage-verified", request=f["request"])
            require(reply.index < verified.index and answer.fields["data"] == rf["data"] == verified.fields["data"] == word,
                    "storage application byte verification lacks independent matching block/filesystem bytes")
            verified_reads.append((name, request, reply, verified))
    require(set(names) == set(PAYLOADS), "the three preservation file handles were not established")
    ready = one("hosting-storage-ready")
    require(ready.fields["value"] == names["/alpha"] and ready.fields["extra"] == names["/beta"],
            "storage-ready report lacks actual distinct committed file handles")
    for name in ("/alpha", "/beta"):
        chunks = [(request, reply) for file_name, request, reply in writes if file_name == name]
        require([request.fields["offset"] for request, _ in chunks] == list(range(0, lengths[name], 8)),
                "missing complete multi-chunk writes for both unrelated files")
    require(any(observer.published[0].index < request.index < observer.cleaned[0].index for _, request, _ in writes),
            "original storage owner did not actually write while dynamic children were active")
    cycles, previous = [], -1
    for serial, cycle in enumerate(by_kind["hosting-storage-cycle"]):
        require(cycle.fields.get("value") == serial and cycle.fields.get("extra") == 7,
                "storage full-cycle identity or mask is counterfeit")
        chunks = [(name, request, reply, verified) for name, request, reply, verified in verified_reads
                  if previous < verified.index < cycle.index]
        for name, payload in PAYLOADS.items():
            selected = [chunk for chunk in chunks if chunk[0] == name]
            require([request.fields["offset"] for _, request, _, _ in selected] == list(range(0, len(payload), 8)),
                    "full storage cycle lacks byte-verified /hello and both complete independent file payloads")
        cycles.append((cycle, min(request.index for _, request, _, _ in chunks), chunks))
        previous = cycle.index
    last_reap = max(event.index for event in observer.events if event.name == "host-reap")
    require(len(cycles) >= 2 and any(start > last_reap for _, start, _ in cycles),
            "complete file contents were not byte-verified after dynamic teardown")
    return {"cycles": cycles, "reads": verified_reads, "writes": writes,
            "handles": names, "completed_operations": len(completed_app)}


def verify_scenario(observer, storage):
    events, scenario = observer.events, observer.scenario
    supervisors = [node for node in observer.tree.nodes.values() if node.template == 1]
    require(len(supervisors) == 1, "scenario did not create exactly one independent logical supervisor")
    supervisor = supervisors[0]
    siblings = [node for node in observer.tree.nodes.values() if node.template == 2 and node.depth == 1]
    grandchildren = [node for node in observer.tree.nodes.values() if node.depth == 2]
    require(siblings and len(grandchildren) >= (1 if scenario == 23 else 2),
            "runtime hierarchy lacks approved root sibling and true second-depth workers")
    require(len({node.identity for node in siblings + grandchildren}) == len(siblings + grandchildren),
            "workers sharing one sealed image also shared runtime identity")
    for node in observer.tree.nodes.values():
        require(node.physical_history and node.memories and
                all(len(page_ids) == (4 if node.template == 1 else 2) for page_ids in node.physical_history.values()),
                "approved fixed private page ownership differs from the actual initialized address spaces")
    dynamic_sentinels = [memory[0] for node in observer.tree.nodes.values() for memory in node.memories.values()]
    require(len(dynamic_sentinels) == len(set(dynamic_sentinels)), "runtime workers do not preserve distinct private sentinels")
    require(any(reply.fields["command"] == 2 for _, reply, _ in observer.verified) and
            any(reply.fields["command"] == 1 for _, reply, _ in observer.verified),
            "root/supervisor and independent sibling did not both perform real verified work")
    require(all(not node.retained for node in observer.tree.nodes.values()),
            "final teardown retained an orphaned bounded terminal/control record")
    faults = [event for event in events if event.name == "host-fault"]
    if scenario == 21:
        require(not faults and not observer.restarts and not observer.stale,
                "creation/progress preservation scenario injected a recovery or stale endpoint")
        require(len(observer.published) == 4 and len(grandchildren) == 2 and len(siblings) == 1,
                "bounded normal hierarchy differs from two owned grandchildren plus independent sibling")
        return {}
    if scenario == 22:
        require(len(faults) == 2 and len(observer.restarts) == len(observer.rebound) == 1,
                "failure/recovery scenario lacks exactly the supervisor restart and delayed worker fault")
        manager_fault = next((event for event in faults if event.fields["instance"] == supervisor.instance), None)
        require(manager_fault is not None and signed(manager_fault.fields["result"]) == 6,
                "supervisor failure is not the actual ring3 invalid-instruction fault")
        restart, rebind = observer.restarts[0], observer.rebound[0]
        require(restart.fields["instance"] == supervisor.instance == rebind.fields["instance"] and
                restart.fields["control"] == supervisor.control == rebind.fields["control"] and
                restart.fields["tick"] == manager_fault.fields["tick"] + 4 and
                manager_fault.index < restart.index < rebind.index,
                "logical/control continuity or exact four-tick automatic restart delay differs")
        recovery = [(proof, reply, request) for proof, reply, request in observer.verified
                    if reply.fields["sender"] == supervisor.endpoint and reply.fields["command"] == 2]
        require(len(recovery) == 1 and rebind.index < recovery[0][2].index < recovery[0][0].index,
                "recovery interval lacks first verified nested RPC after explicit current-generation rebind")
        recovery_end = recovery[0][0]
        old_endpoint = manager_fault.fields["endpoint"]
        old_channel = next(event.fields["parent_cap"] for event in observer.published
                           if event.fields["instance"] == supervisor.instance)
        require(any(event.fields["value"] == old_endpoint and restart.index < event.index < rebind.index
                    for event in observer.stale) and
                any(event.fields["value"] == old_channel and restart.index < event.index < rebind.index
                    for event in observer.stale), "old supervisor endpoint/channel were not rejected before fresh work")
        asleep_cancelled = [event for event in observer.cancelled if event.fields["wait_kind"] == 1 and
                            event.fields["queued"] > 0 and event.fields["parent_instance"] == supervisor.instance and
                            event.index > manager_fault.index and event.index < restart.index]
        receiving_cancelled = [event for event in observer.cancelled if event.fields["wait_kind"] == 2 and
                               event.fields["parent_instance"] == supervisor.instance and
                               manager_fault.index < event.index < restart.index]
        require(len(asleep_cancelled) == 1 and receiving_cancelled,
                "supervisor fault did not cancel queued sleeping grandchild and separate finite receiver")
        sleeper_endpoint = asleep_cancelled[0].fields["endpoint"]
        queued_grandchild = [event for event in observer.enqueued if event.fields["target"] == sleeper_endpoint and
                            event.fields["command"] == 1 and
                            event.index < manager_fault.index and event.fields["request"] > 0]
        require(queued_grandchild and not any(event.fields["target"] == sleeper_endpoint and
                event.fields["request"] == queued_grandchild[-1].fields["request"] and
                event.index > manager_fault.index for event in observer.delivered),
                "retired waiting grandchild received stale queued work after owner failure")
        require(len(observer.fifo) == 1, "sibling preservation lacks two explicitly outstanding matched requests")
        _, first, second = observer.fifo[0]
        sibling_endpoint = first[1].fields["sender"]
        sleeps = [(wake, state) for wake, state, endpoint in observer.wakes if endpoint == sibling_endpoint and
                  state["kind"] == 1 and wake.name == "wake" and
                  state["index"] < first[2].index < second[2].index < manager_fault.index < wake.index]
        require(len(sleeps) == 1 and sleeps[0][0].fields["tick"] >= sleeps[0][1]["deadline"] and
                sleeps[0][0].index < first[1].index < second[1].index,
                "sibling queued FIFO work did not retain its original sleep deadline through subtree failure")
        require(any(event.fields["cell"] == (sibling_endpoint & 255) - 1 and
                    event.fields["generation"] == sibling_endpoint >> 8 and
                    event.fields["extra"] == sleeps[0][1]["deadline"] - sleeps[0][1]["tick"]
                    for event in observer.sleep_returns), "sibling sleep lost private-memory preservation proof")
        delayed = next(event for event in faults if event is not manager_fault)
        require(delayed.fields["parent_instance"] == supervisor.instance and
                delayed.index > recovery_end.index and not any(event.fields["instance"] == delayed.fields["instance"]
                for event in observer.restarts), "delayed descendant restart survived explicit subtree destruction")
        delayed_cleanup = next((event for event in observer.cleaned if event.fields["instance"] == delayed.fields["instance"] and event.fields["retired_pages"] > 0), None)
        require(delayed_cleanup is not None and delayed_cleanup.fields["tick"] < delayed.fields["tick"] + 4 and
                any(event.name == "host-backoff-observed" and delayed.index < event.index < delayed_cleanup.index
                    for event in events), "parent did not destroy a genuinely observed delayed-backoff descendant")
        require(observer.last_tick >= delayed.fields["tick"] + 10 and
                any(reply.fields["sender"] == sibling_endpoint and proof.index > delayed_cleanup.index and
                    reply.fields["command"] == 1 for proof, reply, _ in observer.verified),
                "independent sibling did not resume real work after delayed subtree restart cancellation")
        require(any(cycle.index < manager_fault.index for cycle, _, _ in storage["cycles"]) and
                any(start > recovery_end.index for _, start, _ in storage["cycles"]),
                "complete file payloads were not byte-verified before and after hierarchical recovery")
        inside = [chunk for chunk in storage["reads"] if manager_fault.index < chunk[1].index and
                  chunk[3].index < recovery_end.index]
        require(inside, "recovery interval contains no actual matched FS/block byte-verified storage chunk")
        return {"recovery_fault_tick": manager_fault.fields["tick"],
                "recovery_first_verified_rpc_tick": recovery_end.fields["tick"],
                "recovery_interval_ticks": recovery_end.fields["tick"] - manager_fault.fields["tick"],
                "storage_chunks_inside_recovery": len(inside),
                "sibling_sleep_deadline": sleeps[0][1]["deadline"]}
    require(len(faults) == 6 and len(observer.restarts) == len(observer.rebound) == 1 and
            len(observer.probes) == 5,
            "pressure/reuse scenario lacks actual leaf restart and all five dynamic privilege faults")
    expected_errors = {1: -1, 2: -1, 3: -1, 4: -7, 5: -1, 6: -5, 7: -1, 8: -5, 9: -5,
                       10: -1, 11: -7, 12: -3, 13: -3, 14: -3, 15: -3, 16: -3, 17: -2}
    require({event.fields["value"]: signed(event.fields["extra"]) for event in observer.denied} == expected_errors and
            len(observer.denied) == 17, "authority, address, pressure, or stale-reuse denial is missing/counterfeit")
    require(len(observer.copy_denials) == 3, "copied parent IPC/control/domain authority checks did not all fail")
    old_candidates = [node for node in siblings if any(event.fields["value"] == node.control
                      for event in observer.stale)]
    require(len(old_candidates) == 1, "stale control does not identify the actually reaped original worker")
    old = old_candidates[0]
    reuse = [(old, new) for new in siblings if old.born < new.born and old.slot == new.slot]
    require(len(reuse) == 1, "pressure scenario did not reap and genuinely reuse one runtime worker slot")
    old, replacement = reuse[0]
    require(old.instance != replacement.instance and old.control != replacement.control and
            old.endpoint >> 8 < replacement.endpoint >> 8 and old.parent_cap != replacement.parent_cap,
            "slot reuse revived earlier instance, control, execution, or channel authority")
    old_pages = set(next(iter(old.physical_history.values())))
    new_pages = set(next(iter(replacement.physical_history.values())))
    require(old_pages & new_pages, "slot reuse did not prove cold clearing of previously owned physical backing")
    replacement_initial_endpoint = min(replacement.physical_history)
    replacement_work = next((proof for proof, reply, _ in observer.verified if
                             reply.fields["sender"] == replacement_initial_endpoint and reply.fields["command"] == 1), None)
    require(replacement_work is not None and all(any(event.fields["value"] == token and
                event.index < replacement_work.index for event in observer.stale)
                for token in (old.endpoint, old.parent_cap)) and
            any(event.fields["value"] == 12 and event.index < replacement_work.index for event in observer.denied),
            "old endpoint/control/capability were not rejected before valid replacement work")
    revocations = [event for event in events if event.name == "host-revoke"]
    require(len(revocations) == 1 and revocations[0].index < observer.denied[-1].index and
            any(event.name == "host-status" and event.fields["instance"] == supervisor.instance and
                event.index > revocations[0].index for event in events),
            "revocation failed to deny creation while retaining direct-owner lifecycle query/control")
    require(any(cycle.index < min(event.index for event in observer.cleaned) for cycle, _, _ in storage["cycles"]),
            "pressure/reuse teardown occurred before complete byte-verified independent file payloads")
    leaf_restart, leaf_rebind = observer.restarts[0], observer.rebound[0]
    leaf_fault = next(event for event in faults if event.fields["instance"] == replacement.instance)
    require(leaf_restart.fields["instance"] == leaf_rebind.fields["instance"] == replacement.instance and
            leaf_restart.fields["control"] == leaf_rebind.fields["control"] == replacement.control and
            leaf_restart.fields["generation"] == (replacement_initial_endpoint >> 8) + 1 and
            leaf_restart.fields["tick"] == leaf_fault.fields["tick"] + 4 and
            leaf_restart.index < leaf_rebind.index and leaf_rebind.fields["creation"] == 0,
            "leaf automatic restart changed logical/control lifetime or acquired ambient descendant authority")
    require(any(proof.index > leaf_rebind.index and reply.fields["sender"] == replacement.endpoint and
                reply.fields["command"] == 1 for proof, reply, _ in observer.verified),
            "rebound leaf did not resume independently recomputed ring3 work")
    require(all(any(event.fields["value"] == token and leaf_restart.index < event.index < leaf_rebind.index
                    for event in observer.stale) for token in
                    (replacement_initial_endpoint, next(event.fields["parent_cap"] for event in observer.published
                     if event.fields["instance"] == replacement.instance))),
            "leaf old endpoint/channel survived automatic restart before fresh rebinding")
    privilege = {1: (14, 7, 0x40000000), 2: (14, 5, 0x10000), 3: (13, 0, 0),
                 4: (14, 6, 0x4001fff8), 5: (14, 21, 0x40030080)}
    require([event.fields["value"] for event in observer.probes] == list(privilege),
            "dynamic privilege probes were skipped, duplicated, or reordered")
    for proof in observer.probes:
        mode = proof.fields["value"]
        vector, error, address = privilege[mode]
        requests = [event for event in observer.delivered if event.fields["operation"] == 15 and
                    event.fields["command"] == 11 and event.fields["argument"] == mode]
        require(len(requests) == 1, "hardware probe lacks exact authorized ring3 instruction request")
        request = requests[0]
        endpoint = request.fields["target"]
        traps = [event for event in observer.hardware_faults if event.fields["cell"] == (endpoint & 255) - 1 and
                 event.fields["generation"] == endpoint >> 8 and request.index < event.index < proof.index]
        require(len(traps) == 1 and (traps[0].fields["reason"], traps[0].fields["error"], traps[0].fields["address"]) ==
                (vector, error, address) and proof.fields["extra"] == vector,
                "dynamic cell escaped immutable image/supervisor/I/O/guard/NX hardware isolation")
        nodes = [node for node in observer.tree.nodes.values() if endpoint in node.entered]
        require(len(nodes) == 1 and nodes[0].template == 2 and nodes[0].depth == 1,
                "privilege probe faulted an unrelated or manifest-prebooted cell")
        victim = nodes[0]
        queried = [event for event in events if event.name == "host-status" and
                   event.fields["instance"] == victim.instance and event.fields["phase"] == 2 and
                   traps[0].index < event.index < proof.index]
        cleanup = next((event for event in observer.cleaned if event.fields["instance"] == victim.instance and event.fields["retired_pages"] > 0), None)
        require(queried and cleanup is not None and proof.index < cleanup.index and
                cleanup.fields["tick"] < traps[0].fields["tick"] + 4 and
                not any(event.fields["instance"] == victim.instance for event in observer.restarts),
                "privilege probe lacks authoritative backoff query and cancellation before delayed restart")
    return {"reused_slot": old.slot, "old_execution_generation": old.endpoint >> 8,
            "replacement_execution_generation": replacement_initial_endpoint >> 8,
            "leaf_restarted_generation": replacement.endpoint >> 8,
            "checked_denials": 17, "dynamic_privilege_probes": 5}


def verify(output, code, scenario, manifest_path=None):
    require(scenario in (21, 22, 23), "unsupported dedicated hosting scenario")
    require(code == 1, f"hosting emulator exited with {code}, expected genuine success status1")
    require(output.count("ZEAL boot abi=4 x86_64") == 1 and
            output.count("MANIFEST_ACCEPT version=2") == 1, "hosting boot/privileged manifest validation is missing/repeated")
    require(output.count("RESEARCH_PASS") == 1 and f"RESEARCH_PASS scenario=0x{scenario:016x}" in output,
            "hosting completion lacks unique exact scenario and emulator status")
    require(not any(word in output for word in ("PANIC", "RESEARCH_FAIL", "bad-report", "TRACE_EXHAUSTED")),
            "failure or independently bounded trace exhaustion appeared in serial evidence")
    if manifest_path is None:
        manifest_path = pathlib.Path(__file__).resolve().parents[1] / f"build/research/scenario-{scenario}/manifest.bin"
    roots, approved, manifest_hash = manifest_records(manifest_path, scenario)
    accepted = next(line for line in output.splitlines() if line.startswith("MANIFEST_ACCEPT"))
    require(f"cells=0x{len(roots):016x}" in accepted and f"grants=0x{roots.grant_count:016x}" in accepted,
            "privileged manifest acceptance counts do not match the independently read sealed artifact")
    events = records(output)
    require(events and sum(event.name.startswith("host-") for event in events) < 2048,
            "hosting trace credit was exhausted")
    require(sum(event.name in ("storage-ipc", "storage-reject") for event in events) < 1024,
            "storage transfer trace credit was exhausted")
    observer = Observer(events, roots, approved, scenario).run()
    management_returns(observer)
    storage = verify_storage(events, observer)
    scenario_evidence = verify_scenario(observer, storage)
    return {"hosting_verified": True, "scenario": scenario, "manifest_sha256": manifest_hash,
            "serial_sha256": hashlib.sha256(output.encode()).hexdigest(),
            "runtime_creations": len(observer.published), "maximum_depth": max(node.depth for node in observer.tree.nodes.values()),
            "root_generations": {str(identity): 1 for identity in ROOT_IDS},
            "physical_root_pages": 80, "descendant_page_limit": 48,
            "final_owned_slots": 0, "final_owned_pages": 0, "final_reserved_slots": 0, "final_reserved_pages": 0,
            "final_available_slots": 4, "final_available_pages": 48,
            "independently_verified_rpcs": len(observer.verified), "storage_full_cycles": len(storage["cycles"]),
            "storage_verified_chunks": len(storage["reads"]), **scenario_evidence}


def management_returns(observer):
    """Join production orchestration to actual authenticated ring3 syscall returns."""
    numbers = {"host-result": 13, "host-status": 14, "host-stop": 15, "host-reap": 16,
               "host-rebind": 17, "host-revoke": 18, "host-domain": 19}
    for event in observer.events:
        if event.name not in numbers or (event.name == "host-result" and signed(event.fields["result"]) != 0):
            continue
        endpoint = event.fields["holder"] if event.name == "host-domain" else event.fields["caller_endpoint"]
        later = [call for call in observer.calls if call.index > event.index and
                 call.fields.get("caller_endpoint") == endpoint]
        require(later and later[0].fields["call"] == numbers[event.name] and signed(later[0].fields["result"]) == 0,
                "management publication/query/control lacks its actual checked ring3 syscall result")
        call = later[0]
        f = call.fields
        if event.name in ("host-status", "host-stop", "host-reap"):
            require(f["arg0"] == event.fields["control"], "management syscall returned for a different control object")
        elif event.name in ("host-revoke", "host-domain"):
            require(f["arg0"] == (event.fields["domain"] if event.name == "host-domain" else event.fields["parent_cap"]),
                    "domain syscall returned for a different typed authority object")
        if f["call"] in (15, 16, 18):
            require(f["arg1"] == f["arg2"] == 0, "lifecycle syscall accepted unknown scalar arguments")
        elif f["call"] in (13, 17):
            require(f["arg1"] == 32, "creation/rebind syscall accepted an incompatible input length")
        elif f["call"] == 14:
            require(f["arg2"] == 104, "status syscall accepted an incompatible checked output length")
        elif f["call"] == 19:
            require(f["arg2"] == 72, "domain syscall accepted an incompatible checked output length")


def negative_controls(output, code, scenario, manifest_path=None):
    """Remove or counterfeit essential evidence; every altered trace must fail."""
    verify(output, code, scenario, manifest_path)
    events = records(output)
    lines = output.splitlines()
    tested = []

    def rejected(name, altered, exit_code=code):
        try:
            verify(altered, exit_code, scenario, manifest_path)
        except (AssertionError, ValueError, UnicodeError) as error:
            tested.append({"name": name, "rejection": str(error)})
            return
        evidence = pathlib.Path(__file__).resolve().parents[1] / "build/research"
        evidence.mkdir(parents=True, exist_ok=True)
        (evidence / f"negative-unexpected-{scenario}-{name}.log").write_text(altered)
        raise AssertionError(f"hosting negative control unexpectedly passed: {name}")

    essential = ["boot", "host-domain", "host-request", "host-reserve", "host-space", "host-channel",
                 "host-publish", "host-result", "host-entry", "host-cold", "host-memory", "host-computed",
                 "host-nested-verified", "host-verified", "host-storage-denied", "host-ledger", "host-timeout",
                 "host-ipc-enqueue", "host-ipc-deliver", "host-stop", "host-cancel", "host-invalidate",
                 "host-cleanup", "host-return", "host-reap", "host-call", "host-complete",
                 "storage-ipc", "storage-link", "storage-block", "storage-fs", "storage-verified",
                 "hosting-storage-ready", "hosting-storage-cycle", "wait-arm", "wake"]
    if scenario in (22, 23):
        essential += ["fault", "host-fault", "host-restart", "host-rebind", "host-stale"]
    if scenario == 22:
        essential += ["host-fifo", "host-sleep-return", "host-backoff-observed"]
    if scenario == 23:
        essential += ["host-denied", "host-copied", "host-revoke", "host-probe-verified"]
    for name in essential:
        selected = [event for event in events if event.name == name]
        require(selected, f"negative control lacks essential baseline evidence {name}")
        rejected("remove-" + name, "\n".join(line for number, line in enumerate(lines)
                 if number not in {event.line for event in selected}) + "\n")

    mutations = {
        "boot": ("identity", "generation", "abi", "entry", "image", "physical_pages", "p0"),
        "host-domain": ("domain", "holder", "domain_instance", "slot_limit", "page_limit", "max_depth",
                        "template_mask", "recipe", "revoked", "owned_slots", "available_pages"),
        "host-request": ("caller_endpoint", "caller_identity", "request", "template", "parent_cap",
                         "requested_slots", "requested_pages"),
        "host-reserve": ("cell", "identity", "generation", "instance", "control", "endpoint", "parent_instance",
                         "parent_endpoint", "template", "image", "role", "depth", "pages", "reserved_slots",
                         "reserved_pages", "creation", "transaction"),
        "host-space": ("identity", "generation", "instance", "parent_endpoint", "template", "image", "pages",
                       "reserved_slots", "zero", "physical_pages", "cs", "rip", "rsp", "p0"),
        "host-channel": ("parent_cap", "child_cap", "parent_endpoint", "endpoint", "instance", "recipe",
                         "parent_holder", "parent_target", "parent_issuer", "parent_rights", "parent_derivation",
                         "parent_epoch", "child_holder", "child_target", "child_issuer", "child_rights",
                         "child_derivation", "child_epoch"),
        "host-publish": ("identity", "generation", "instance", "control", "endpoint", "parent_instance",
                         "depth", "pages", "reserved_slots", "parent_cap", "child_cap", "phase", "result"),
        "host-entry": ("identity", "generation", "value", "extra", "endpoint", "instance", "template", "depth",
                       "parent_endpoint"),
        "host-cold": ("value", "extra", "generation"), "host-memory": ("value", "extra"),
        "host-computed": ("value", "extra", "generation"), "host-verified": ("value", "extra", "generation"),
        "host-ipc-enqueue": ("sender", "target", "cap", "operation", "length", "request", "command", "reserved", "argument", "value"),
        "host-ipc-deliver": ("sender", "target", "operation", "length", "request", "command", "reserved", "argument", "value"),
        "host-cancel": ("instance", "wait_generation", "wait_kind", "wait_deadline", "phase"),
        "host-invalidate": ("instance", "queued", "phase"),
        "host-cleanup": ("identity", "instance", "parent_endpoint", "retired_pages", "retained", "phase"),
        "host-status": ("phase", "deadline", "pages", "reserved_slots", "reserved_pages", "generation", "control"),
        "host-return": ("instance", "retained", "pages", "retired_pages", "reserved_slots", "reserved_pages", "phase"), "host-reap": ("control", "instance", "caller_endpoint"),
        "host-call": ("call", "result"), "host-complete": ("value", "extra"),
        "storage-ipc": ("identity", "generation", "target", "operation", "request", "length"),
        "storage-link": ("request", "block_request"), "storage-block": ("operation", "result"),
        "storage-fs": ("request", "result"), "storage-verified": ("request", "data"),
        "hosting-storage-ready": ("value", "extra"), "hosting-storage-cycle": ("value", "extra"),
    }
    if scenario in (22, 23):
        mutations.update({"host-restart": ("generation", "instance", "control", "zero", "physical_pages", "cs", "rip", "rsp"),
                          "host-rebind": ("request", "caller_endpoint", "endpoint", "instance", "control", "creation", "parent_cap",
                                          "recipe", "parent_holder", "parent_target", "parent_issuer", "parent_rights",
                                          "parent_derivation", "parent_epoch", "child_holder", "child_target",
                                          "child_issuer", "child_rights", "child_derivation", "child_epoch"),
                          "host-stale": ("value", "extra"), "fault": ("reason", "error", "address")})
    if scenario == 22:
        mutations.update({"host-fifo": ("value", "extra"), "host-sleep-return": ("value", "extra"),
                          "host-backoff-observed": ("value", "extra")})
    if scenario == 23:
        mutations.update({"host-denied": ("value", "extra"), "host-copied": ("value", "extra"),
                          "host-probe-verified": ("value", "extra")})
    for name, keys in mutations.items():
        selected = next(event for event in events if event.name == name)
        for key in keys:
            require(key in selected.fields, f"mutation baseline is missing {name}.{key}")
            changed = list(lines)
            replacement = selected.fields[key] ^ 1
            changed[selected.line] = re.sub(rf"\b{re.escape(key)}=0x[0-9a-f]+\b",
                                            f"{key}=0x{replacement:016x}", changed[selected.line], count=1)
            rejected(f"counterfeit-{name}.{key}", "\n".join(changed) + "\n")
    # Coordinated counterfeits matter: changing both a grant handle and its
    # matching epoch/delivery fields must not evade global nonce conservation.
    pair = next(event for event in events if event.name == "host-channel")
    old_child = pair.fields["child_cap"]
    forged_child = (pair.fields["parent_cap"] & ~255) | (old_child & 255)
    changed = []
    for line in lines:
        if line.startswith("EVENT "):
            line = re.sub(r"\b(cap|child_cap|arg0)=0x([0-9a-f]+)\b", lambda match:
                f"{match.group(1)}=0x{forged_child:016x}" if int(match.group(2), 16) == old_child else match.group(0), line)
        changed.append(line)
    changed[pair.line] = re.sub(r"\bchild_epoch=0x[0-9a-f]+\b",
                                 f"child_epoch=0x{pair.fields['parent_epoch']:016x}", changed[pair.line])
    rejected("coordinated-capability-epoch-collision", "\n".join(changed) + "\n")
    changed = [re.sub(r"\breserved=0x[0-9a-f]+\b", "reserved=0x0000000000000001", line)
               if line.startswith(("EVENT host-ipc-enqueue ", "EVENT host-ipc-deliver ")) else line for line in lines]
    rejected("coordinated-nonzero-ipc-reserved", "\n".join(changed) + "\n")
    returned = next(event for event in events if event.name == "host-return")
    changed = list(lines)
    changed[returned.line] = re.sub(r"\bretired_pages=0x[0-9a-f]+\b", "retired_pages=0x0000000000000000", changed[returned.line])
    rejected("zeroed-refund-amount", "\n".join(changed) + "\n")
    retired = next(event for event in events if event.name == "host-cleanup" and event.fields["retained"] == 0)
    changed = list(lines)
    changed[retired.line] = re.sub(r"\bphase=0x[0-9a-f]+\b", "phase=0x0000000000000001", changed[retired.line])
    rejected("ready-automatically-reaped-descendant", "\n".join(changed) + "\n")
    rejected("wrong-emulator-exit", output, 3)
    rejected("missing-completion", output.replace("RESEARCH_PASS", "UNVERIFIED_COMPLETION"))
    rejected("counterfeit-completion", output.replace(f"RESEARCH_PASS scenario=0x{scenario:016x}",
                                                       f"RESEARCH_PASS scenario=0x{scenario + 1:016x}"))
    rejected("hosting-trace-exhaustion", output + "HOSTING_TRACE_EXHAUSTED\n")
    rejected("storage-trace-exhaustion", output + "STORAGE_TRACE_EXHAUSTED\n")
    return tested
