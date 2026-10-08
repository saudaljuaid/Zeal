"""Independent dictionary/event-history model against the production Zig broker.

The model uses obligations keyed by (full issuer endpoint, serial, placement), provider objects,
sets of owned page identities, and an attempt history. It does not import the
production wire/core or reproduce the broker's two-record array representation.
Every generated step is compared with the compiled production implementation.
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
SERIAL_LIMIT = (1 << 23) - 1
ISSUER = 0x104
OWNER = 0x103
SEEDS = (0, 1, 7, 19, 37, 73, 109, 257, 400, 577, 1021, 4093, 65537, 104729, 0x5EA1, 0xC011)


def calculate(value):
    answer = 0xCBF29CE484222325
    for byte in b"Zeal bounded ring-3 worker" + value.to_bytes(8, "little"):
        answer = ((answer ^ byte) * 0x100000001B3) & MASK
    return answer


@dataclass
class Obligation:
    reference: tuple
    transaction: int
    input: int
    provider: int
    accepted: bool = False
    recovering: bool = False
    retry_count: int = 0
    attempts: list = field(default_factory=list)
    outcome: str | None = None
    reason: int = 0
    result: int = 0
    cleanup_calls: int = 0

    @property
    def token(self):
        issuer, serial, placement = self.reference
        return issuer << 32 | serial << 9 | placement << 8 | 0x80

    @property
    def state(self):
        if self.outcome:
            return {"success": 4, "cancel": 5, "failure": 6}[self.outcome]
        return 3 if self.recovering else 2 if self.accepted else 1


class Model:
    def __init__(self):
        self.obligations = {}
        self.issuer, self.owner = ISSUER, OWNER
        self.transactions = {}
        self.providers = {}
        self.allocations = {}
        self.endpoint_history = {4: 0, 5: 0}
        self.object_epoch = 1
        self.ipc_epoch = 1
        self.next_serial = 1
        self.highwater = 0
        self.next_rpc = 1
        self.calls = dict(create=0, send=0, settle=0, rebind=0, validated=0)
        self.retired_tokens = []
        self.cleanup_mode = 0
        self.candidate_mode = 0

    def lookup(self, token):
        if token & 255 != 0x80 or not (token >> 9 & SERIAL_LIMIT) or not token >> 40 or not 1 <= (token >> 32) & 255 <= 8:
            return None, "invalid"
        for obligation in self.obligations.values():
            if obligation.token == token:
                return obligation, "ok"
        return None, "stale"

    def finish(self, obligation, outcome, reason):
        if obligation.cleanup_calls >= 2:
            return "cleanup"
        self.calls["settle"] += 1
        obligation.cleanup_calls += 1
        if self.cleanup_mode:
            if self.cleanup_mode == 1:
                self.allocations[obligation.provider].clear()
            obligation.outcome, obligation.reason, obligation.result = "failure", 6, 0
            return "cleanup"
        self.allocations.pop(obligation.provider, None)
        obligation.outcome = outcome
        obligation.reason = reason
        obligation.result = 0

    def dispatch(self, obligation, failure=False):
        if not self.next_rpc:
            return self.finish(obligation, "failure", 5) or "exhausted"
        rpc = self.next_rpc
        self.next_rpc = 0 if rpc == MASK else rpc + 1
        obligation.accepted = True
        obligation.recovering = False
        obligation.attempts.append((obligation.retry_count + 1, rpc, self.providers[obligation.provider]["endpoint"]))
        self.calls["send"] += 1
        if failure:
            return self.finish(obligation, "failure", 3) or "transport"
        return "ok"

    def apply(self, action):
        op, a, b, c = action
        if op == "Y":
            self.cleanup_mode = a
            return "ok"
        if op == "V":
            self.candidate_mode = a
            return "ok"
        if op == "B":
            self.calls["settle"] += len(self.allocations)
            self.retired_tokens.extend(item.token for item in self.obligations.values())
            self.allocations.clear()
            self.obligations.clear()
            self.transactions.clear()
            self.issuer = a
            if b:
                self.owner = b
            self.next_serial, self.highwater, self.next_rpc = 1, 0, 1
            self.cleanup_mode = 0
            self.candidate_mode = 0
            return "ok"
        if op == "X":
            self.next_serial, self.next_rpc = a, b
            return "ok"
        if op == "O":
            if c & 4:
                return "denied"
            if a == 0 or c & 2:
                return "invalid"
            if a in self.transactions:
                item = self.obligations[self.transactions[a]]
                return "ok" if item.input == b else "invalid"
            if a <= self.highwater:
                return "stale"
            if len(self.obligations) == 2:
                return "no_space"
            if not self.next_serial or self.next_serial > SERIAL_LIMIT:
                return "exhausted"
            if len(self.allocations) == 2:
                return "no_space"
            serial = self.next_serial
            self.next_serial = 0 if serial == SERIAL_LIMIT else serial + 1
            self.highwater = a
            self.calls["create"] += 1
            if c & 1:
                return "resource"
            placement = min({0, 1} - {x.reference[2] for x in self.obligations.values()})
            physical_slot = min({4, 5} - {self.providers[k]["slot"] for k in self.allocations})
            self.endpoint_history[physical_slot] += 1
            epoch = self.object_epoch
            self.object_epoch += 1
            instance = epoch << 8 | 0x40
            self.providers[instance] = {"control": epoch << 8 | 0x50,
                "endpoint": self.endpoint_history[physical_slot] << 8 | physical_slot + 1,
                "channel": self.ipc_epoch << 8 | 0x10, "slot": physical_slot}
            self.ipc_epoch += 1
            self.allocations[instance] = {2 * epoch, 2 * epoch + 1}
            reference = (self.issuer, serial, placement)
            self.obligations[reference] = Obligation(reference, a, b, instance)
            self.transactions[a] = reference
            return "ok"
        if op == "L":
            if b:
                return "denied"
            return "invalid" if not a else "ok" if a in self.transactions else "stale"
        if (op == "A" and c & 1) or (op == "G" and b != self.owner):
            return "denied"
        item, outcome = self.lookup(a)
        if op in ("C", "R", "Q") and b:
            return "denied"
        if item is None:
            return outcome
        if op == "Q":
            return "ok"
        if op in ("A", "G"):
            if (op == "A" and b) or (op == "G" and c != item.input):
                return "invalid"
            if item.state in (2, 3, 4):
                return "ok"
            if item.state != 1:
                return "not_ready"
            return self.dispatch(item, c & 2 if op == "A" else False)
        if op == "C":
            if item.outcome is None:
                return self.finish(item, "cancel", 1) or "ok"
            if item.outcome == "failure" and item.provider in self.allocations:
                return self.finish(item, "failure", item.reason) or "ok"
            return "ok"
        if op == "R":
            if item.outcome is None or item.provider in self.allocations:
                return "not_terminal"
            self.transactions.pop(item.transaction)
            self.obligations.pop(item.reference)
            self.retired_tokens.append(item.token)
            return "ok"
        if op == "D":
            if b == 5:
                return "lost"
            if b == 4 or not item.attempts:
                return "invalid"
            if item.state != 2 or b in (2, 3):
                return "stale"
            if b == 1:
                return self.finish(item, "failure", 2) or "invalid"
            if self.candidate_mode in (3, 4):
                return self.finish(item, "failure", 6) or "stale"
            self.calls["validated"] += 1
            if self.candidate_mode in (1, 2):
                if self.candidate_mode == 2:
                    self.endpoint_history[self.providers[item.provider]["slot"]] += 1
                return self.finish(item, "failure", 6) or "stale"
            failure = self.finish(item, "success", 0)
            if failure:
                return failure
            item.result = calculate(item.input)
            return "ok"
        if op == "F":
            if item.state != 2:
                return "stale"
            if item.retry_count:
                return self.finish(item, "failure", 4) or "ok"
            else:
                item.recovering = True
            return "ok"
        if op == "T":
            if item.state != 3:
                return "not_ready"
            self.calls["rebind"] += 1
            if b:
                return self.finish(item, "failure", 8) or "resource"
            provider = self.providers[item.provider]
            self.endpoint_history[provider["slot"]] += 1
            provider["endpoint"] += 0x100
            provider["channel"] = self.ipc_epoch << 8 | 0x10
            self.ipc_epoch += 1
            item.retry_count = 1
            return self.dispatch(item)
        if op == "E":
            if item.outcome:
                return "ok"
            if not item.accepted:
                return "not_ready"
            return self.finish(item, "failure", 3) or "ok"
        if op == "U":
            if item.outcome:
                return "ok"
            return self.finish(item, "failure", 6) or "ok"
        raise ValueError(op)

    def report(self, outcome):
        scalar = [outcome, self.next_serial, self.highwater, self.next_rpc,
                  *(self.calls[k] for k in ("create", "send", "settle", "rebind", "validated")),
                  len(self.allocations), sum(len(pages) for pages in self.allocations.values()), self.issuer, self.owner]
        records = []
        for item in sorted(self.obligations.values(), key=lambda x: x.reference[2]):
            provider = self.providers[item.provider]
            attempt, rpc, execution = item.attempts[-1] if item.attempts else (0, 0, provider["endpoint"])
            records.append([item.token, item.transaction, item.input, item.state, item.retry_count, attempt, rpc,
                            item.provider, provider["control"], provider["endpoint"], provider["channel"], provider["slot"],
                            int(item.provider in self.allocations), len(self.allocations.get(item.provider, ())),
                            item.reason, int(item.outcome == "success"), item.result, item.cleanup_calls, execution])
        return scalar, records

    def invariants(self):
        assert len(self.obligations) <= 2 and len(self.allocations) <= 2
        assert len({x.provider for x in self.obligations.values()}) == len(self.obligations)
        all_pages = [p for pages in self.allocations.values() for p in pages]
        assert len(all_pages) <= 4 and len(set(all_pages)) == len(all_pages)
        for item in self.obligations.values():
            assert len(item.attempts) <= 2
            assert item.accepted or not item.attempts
            assert item.outcome not in ("success", "cancel") or item.provider not in self.allocations
            assert item.provider not in self.allocations or item.outcome is None or item.reason == 6
            assert item.outcome != "success" or item.result == calculate(item.input)


def parse_report(line):
    scalar, *records = line.split("|")
    fields = scalar.split(";")
    return [fields[0], *(int(x) for x in fields[1:])], [[int(x) for x in r.split(",")] for r in records]


def generate(seed, count=600):
    rng = random.Random(seed)
    model = Model()
    actions, expected = [], []
    next_offer = 1
    for step in range(count):
        live = list(model.obligations.values())
        choice = rng.randrange(100)
        if choice < 28:
            if live and rng.randrange(3) == 0:
                old = rng.choice(live)
                action = ("O", old.transaction, old.input ^ int(rng.randrange(4) == 0), 0)
            else:
                flags = rng.choice((0, 0, 0, 0, 1, 2, 4))
                action = ("O", next_offer, rng.getrandbits(64), flags)
                next_offer += 1
        elif choice < 33:
            transaction = rng.choice(live).transaction if live else rng.randrange(1, max(2, next_offer))
            action = ("L", transaction, int(rng.randrange(10) == 0), 0)
        else:
            token = rng.choice(live).token if live and rng.randrange(8) else rng.choice(model.retired_tokens) if model.retired_tokens else 0x180
            if live and rng.randrange(8) == 0:
                token ^= 1 << rng.randrange(64)
            operation = rng.choice(("A", "A", "D", "D", "Q", "C", "R", "F", "T", "E"))
            if operation == "A":
                action = (operation, token, int(rng.randrange(8) == 0), rng.choice((0, 0, 0, 1, 2)))
            elif operation == "D":
                action = (operation, token, rng.choice((0, 0, 0, 1, 2, 3, 4, 5)), 0)
            elif operation == "T":
                action = (operation, token, int(rng.randrange(4) == 0), 0)
            else:
                action = (operation, token, int(operation in "CQR" and rng.randrange(12) == 0), 0)
        outcome = model.apply(action)
        model.invariants()
        actions.append(action)
        expected.append(model.report(outcome))
    return actions, expected


class ContractModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = ROOT / "build/contract-model"
        cls.evidence.mkdir(parents=True, exist_ok=True)
        cls.driver = cls.evidence / "production-driver"
        cls.summary = {"seeds": SEEDS, "steps_per_seed": 600, "production": "cells/contract_core.zig",
                       "representation": "dictionary obligations, provider objects, page identity sets and attempt histories",
                       "status": "running", "cases": [], "failures": []}
        cls.save_summary()
        result = subprocess.run([os.environ.get("ZIG", "zig"), "build-exe", "cells/contract_model_driver.zig", "-lc", "-O", "Debug", f"-femit-bin={cls.driver}"],
                                cwd=ROOT, capture_output=True, text=True, timeout=60)
        (cls.evidence / "compile.log").write_text(result.stdout + result.stderr)
        if result.returncode:
            cls.summary["status"] = "failed"
            cls.summary["failures"].append({"stage": "compile", "error": result.stdout + result.stderr})
            cls.save_summary()
            raise AssertionError(result.stdout + result.stderr)

    @classmethod
    def save_summary(cls):
        cls.summary["total_steps"] = sum(case["steps"] for case in cls.summary["cases"])
        (cls.evidence / "results.json").write_text(json.dumps(cls.summary, indent=2) + "\n")

    @classmethod
    def tearDownClass(cls):
        cls.summary["status"] = "failed" if cls.summary["failures"] else "passed"
        cls.save_summary()

    def compare(self, seed, actions, expected):
        try:
            self.compare_case(seed, actions, expected)
        except Exception as error:
            self.summary["status"] = "failed"
            self.summary["failures"].append({"seed": seed, "error": str(error)})
            self.save_summary()
            raise
        self.summary["cases"].append({"seed": seed, "steps": len(actions), "status": "passed"})
        self.save_summary()

    def compare_case(self, seed, actions, expected):
        source = self.evidence / f"seed-{seed}.actions"
        source.write_text("".join(f"{op} {a} {b} {c}\n" for op, a, b, c in actions))
        completed = subprocess.run([str(self.driver), str(source)], cwd=ROOT, capture_output=True, text=True, timeout=20)
        (self.evidence / f"seed-{seed}.actual").write_text(completed.stdout)
        (self.evidence / f"seed-{seed}.stderr").write_text(completed.stderr)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        actual = completed.stdout.splitlines()
        self.assertEqual(len(actual), len(expected))
        for index, (line, expected_report) in enumerate(zip(actual, expected)):
            observed = parse_report(line)
            if observed != expected_report:
                witness = {"seed": seed, "step": index, "actions": actions[:index + 1], "expected": expected_report, "actual": observed}
                (self.evidence / f"seed-{seed}-failure-{index}.json").write_text(json.dumps(witness, indent=2) + "\n")
            self.assertEqual(observed, expected_report, f"seed {seed} step {index}: {actions[index]}")

    def test_deterministic_generated_sequences_against_production(self):
        for seed in SEEDS:
            with self.subTest(seed=seed):
                self.compare(seed, *generate(seed))

    def test_counter_exhaustion_against_production(self):
        model = Model()
        first = ("O", 1, 17, 0)
        outcome = model.apply(first)
        token = next(iter(model.obligations.values())).token
        actions = [first, ("X", SERIAL_LIMIT, MASK, 0), ("O", 2, 31, 0), ("A", token, 0, 0),
                   ("F", token, 0, 0), ("T", token, 0, 0), ("O", 3, 99, 0), ("C", token, 0, 0), ("R", token, 0, 0), ("O", 4, 99, 0)]
        model = Model()
        expected = []
        for action in actions:
            outcome = model.apply(action)
            model.invariants()
            expected.append(model.report(outcome))
        self.compare("boundaries", actions, expected)

    def test_broker_and_requester_cold_retirement_against_production(self):
        model = Model()
        actions, expected = [], []
        def step(action):
            actions.append(action)
            result = model.apply(action)
            model.invariants()
            expected.append(model.report(result))
        step(("O", 1, 17, 0))
        first = next(iter(model.obligations.values())).token
        step(("O", 2, 31, 0))
        second = model.obligations[model.transactions[2]].token
        step(("A", first, 0, 0))
        step(("F", first, 0, 0))
        # Existing C/kernel tests prove subtree teardown. This sequence invokes
        # that seam and the same production cold Broker.init used at real boot.
        step(("B", 0x204, 0, 0))
        step(("D", first, 0, 0))
        step(("Q", second, 0, 0))
        step(("O", 1, 17, 0))
        fresh = next(iter(model.obligations.values())).token
        self.assertNotEqual(first, fresh)
        step(("A", fresh, 0, 0))
        step(("B", 0x304, 0x203, 0))
        step(("G", fresh, OWNER, 17))
        step(("O", 1, 31, 0))
        newer = next(iter(model.obligations.values())).token
        step(("G", newer, OWNER, 31))
        step(("G", newer, 0x203, 31))
        step(("D", newer, 0, 0))
        step(("R", newer, 0, 0))
        self.compare("cold-retirement", actions, expected)

    def test_partial_cleanup_and_false_refund_against_production(self):
        model = Model()
        actions, expected = [], []
        def step(action):
            actions.append(action)
            result = model.apply(action)
            model.invariants()
            expected.append(model.report(result))
        step(("O", 1, 17, 0))
        first = next(iter(model.obligations.values())).token
        for action in (("A", first, 0, 0), ("Y", 1, 0, 0), ("D", first, 0, 0), ("Q", first, 0, 0),
                       ("R", first, 0, 0), ("C", first, 0, 0), ("C", first, 0, 0), ("Y", 0, 0, 0),
                       ("C", first, 0, 0), ("B", 0x204, 0, 0), ("O", 1, 17, 0)):
            step(action)
        second = next(iter(model.obligations.values())).token
        for action in (("A", second, 0, 0), ("Y", 2, 0, 0), ("D", second, 0, 0), ("Y", 0, 0, 0),
                       ("C", second, 0, 0), ("R", second, 0, 0), ("O", 2, 31, 0)):
            step(action)
        third = next(iter(model.obligations.values())).token
        for action in (("A", third, 0, 0), ("Y", 1, 0, 0), ("E", third, 0, 0), ("Y", 0, 0, 0),
                       ("C", third, 0, 0), ("R", third, 0, 0)):
            step(action)
        self.compare("settlement-failures", actions, expected)

    def test_unavailable_worker_is_failed_without_owner_cancellation(self):
        model = Model()
        actions, expected = [], []
        def step(action):
            actions.append(action)
            result = model.apply(action)
            model.invariants()
            expected.append(model.report(result))
        step(("O", 1, 17, 0))
        offered = next(iter(model.obligations.values())).token
        step(("U", offered, 0, 0))
        step(("U", offered, 0, 0))
        step(("C", offered, 0, 0))
        step(("R", offered, 0, 0))
        step(("O", 2, 31, 0))
        running = next(iter(model.obligations.values())).token
        step(("O", 3, 99, 0))
        sibling = model.obligations[model.transactions[3]].token
        step(("A", running, 0, 0))
        step(("A", sibling, 0, 0))
        step(("F", running, 0, 0))
        step(("U", running, 0, 0))
        step(("D", running, 0, 0))
        step(("Q", sibling, 0, 0))
        step(("D", sibling, 0, 0))
        step(("U", sibling, 0, 0))
        step(("R", running, 0, 0))
        step(("R", sibling, 0, 0))
        step(("O", 4, 127, 0))
        next_running = next(iter(model.obligations.values())).token
        step(("A", next_running, 0, 0))
        step(("U", next_running, 0, 0))
        step(("D", next_running, 0, 0))
        self.compare("unavailable-worker", actions, expected)

    def test_late_fault_after_candidate_admission_and_before_settlement(self):
        model = Model()
        actions, expected = [], []
        def step(action):
            actions.append(action)
            result = model.apply(action)
            model.invariants()
            expected.append(model.report(result))
        next_offer = 1
        for retirement_mode in (1, 2, 3, 4):
            step(("O", next_offer, 17, 0))
            affected = model.obligations[model.transactions[next_offer]].token
            next_offer += 1
            step(("O", next_offer, 31, 0))
            sibling = model.obligations[model.transactions[next_offer]].token
            next_offer += 1
            step(("A", affected, 0, 0))
            step(("A", sibling, 0, 0))
            step(("V", retirement_mode, 0, 0))
            step(("D", affected, 0, 0))
            step(("Q", sibling, 0, 0))
            step(("V", 0, 0, 0))
            step(("D", affected, 0, 0))
            step(("D", sibling, 0, 0))
            step(("R", affected, 0, 0))
            step(("R", sibling, 0, 0))
        self.compare("late-fault-settlement", actions, expected)


if __name__ == "__main__":
    unittest.main()
