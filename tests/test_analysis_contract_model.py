"""Combined production Broker + real captured-byte Table differential model.

The separate Python obligation/provider/page-history model is composed with the
independent dictionary storage model. Uppercase actions exercise capture/storage;
lowercase actions exercise the shared production byte-profile broker. Every
step compares all storage bytes/bindings and all broker charges/attempts/results.
"""
import json
import os
import random
import subprocess
import unittest
from pathlib import Path

import test_analysis_model as inputs
import test_contract_model as scalar
from analysis_oracle import calculate

ROOT = Path(__file__).resolve().parents[1]
SEEDS = (0, 1, 19, 73, 257, 1021, 65537, 0xA17C)
action = inputs.action


class Contracts(scalar.Model):
    def __init__(self, storage):
        super().__init__()
        self.storage = storage
        self.input_reads = 0
        self.successful_candidate = False
        self.release_mode = False
        self.routes = {}

    def current_reader(self, reader, issuer):
        return issuer == 0x102 and (reader == 0x104 or any(provider["endpoint"] == reader and self.routes.get(identity, False)
                                                     for identity, provider in self.providers.items()))

    def collect(self, reader, issuer, token):
        if not self.current_reader(reader, issuer):
            self.input_reads += 1
            return None
        captured = b""
        for at in range(0, 129, 8):
            self.input_reads += 1
            count, _, data = self.storage.apply(action("R", reader, token, len(captured), 8, 0, issuer))
            if count < 0:
                return None
            if count == 0:
                return captured
            captured += data[:count]
        return None

    def dispatch(self, obligation, failure=False):
        current = self.collect(0x104, obligation.input_issuer, obligation.input)
        if current is None or len(current) != obligation.input_length:
            return self.finish(obligation, "failure", 6) or "stale"
        return super().dispatch(obligation, failure)

    def finish(self, obligation, outcome, reason):
        if obligation.cleanup_calls >= 2:
            return "cleanup"
        worker = self.providers[obligation.provider]["endpoint"]
        released = self.storage.apply(action("Z", 0x104, obligation.input, worker if self.successful_candidate else 0,
                                             0, 0, obligation.input_issuer))[0] == 0 if not self.release_mode else False
        previous = self.cleanup_mode
        if not released:
            self.cleanup_mode = 4 if not previous else previous
        if self.cleanup_mode == 4:
            # Physical stop/reap succeeds while input retirement fails. The
            # service must retain a failed decision and honest zero charges.
            self.calls["settle"] += 1
            obligation.cleanup_calls += 1
            self.allocations.pop(obligation.provider, None)
            obligation.outcome, obligation.reason, obligation.result = "failure", 6, 0
            result = "cleanup"
        else:
            result = super().finish(obligation, outcome, reason)
        self.cleanup_mode = previous
        if obligation.provider not in self.allocations or not self.allocations[obligation.provider]:
            self.routes[obligation.provider] = False
        return result

    def apply_combined(self, item):
        op, owner, token, a, b, c, d = item
        if op == "o":
            if owner != self.owner:
                return "denied"
            if not token or not a or not (b or self.storage.issuer):
                return "invalid"
            previous = self.obligations.get(self.transactions.get(token))
            issuer = b or self.storage.issuer
            if previous:
                return "ok" if (previous.input, previous.input_issuer) == (a, issuer) else "invalid"
            # Allocation eligibility is pure and precedes admitted input I/O.
            if not 1 <= self.issuer & 255 <= 8:
                return "invalid"
            if token <= self.highwater:
                return "stale"
            if len(self.obligations) == 2:
                return "no_space"
            if not self.next_serial or self.next_serial > scalar.SERIAL_LIMIT or not 0 < self.issuer >> 8 <= (1 << 24) - 1:
                return "exhausted"
            if len(self.allocations) == 2 or sum(len(pages) for pages in self.allocations.values()) > 2:
                return "no_space"
            data = self.collect(0x104, issuer, a)
            if data is None:
                return "stale"
            result = super().apply(("O", token, a, int(c == 1)))
            if result == "ok":
                r = self.obligations[self.transactions[token]]
                r.input_issuer, r.input_length, r.newlines, r.input_bytes = issuer, len(data), 0, data
                self.routes[r.provider] = True
            return result
        if op == "a":
            r, error = self.lookup(token)
            if error != "ok":
                return error
            return super().apply(("A", token, a, int(owner != self.owner) | (2 if b else 0)))
        if op in ("c", "r", "q"):
            return super().apply((op.upper(), token, int(owner != self.owner), 0))
        if op == "f":
            if owner != self.owner:
                return "denied"
            r, error = self.lookup(token)
            if r and r.state == 2:
                self.routes[r.provider] = False
            return super().apply(("F", token, 0, 0))
        if op == "t":
            r, error = self.lookup(token)
            result = super().apply(("T", token, a, 0))
            if r and r.provider in self.allocations and result == "ok":
                self.routes[r.provider] = True
            return result
        if op == "x":
            return super().apply(("X", owner, token, 0))
        if op == "y":
            self.release_mode = owner == 3
            self.cleanup_mode = owner if owner in (1, 2) else 0
            return "ok"
        if op == "v":
            self.candidate_mode = owner
            return "ok"
        if op == "d":
            if owner != self.owner:
                return "denied"
            r, error = self.lookup(token)
            if error != "ok":
                return error
            data = self.collect(self.providers[r.provider]["endpoint"], r.input_issuer, r.input)
            if data is None:
                return "unreadable"
            if r.state != 2 or a in (4, 5, 6):
                return "stale"
            checked = self.collect(0x104, r.input_issuer, r.input)
            if checked is None or len(checked) != r.input_length or a in (1, 2, 3):
                return self.finish(r, "failure", 6 if checked is None else 2) or "invalid"
            if self.candidate_mode in (3, 4):
                return self.finish(r, "failure", 6) or "stale"
            self.calls["validated"] += 1
            self.successful_candidate = True
            try:
                if self.candidate_mode in (1, 2):
                    if self.candidate_mode == 2:
                        self.endpoint_history[self.providers[r.provider]["slot"]] += 1
                    return self.finish(r, "failure", 6) or "stale"
                failure = self.finish(r, "success", 0)
                if failure:
                    return failure
                _, r.newlines, r.result = calculate(data)
                return "ok"
            finally:
                self.successful_candidate = False
        return "ok"

    def report(self, outcome):
        scalars, rows = super().report(outcome)
        scalars.append(self.input_reads)
        scalars.append(sum(1 << (self.providers[provider]["slot"] - 4) for provider in self.allocations if self.routes.get(provider, False)))
        for row, record in zip(rows, sorted(self.obligations.values(), key=lambda r: r.reference[2])):
            row += [record.input_issuer, record.input_length, record.newlines]
        return scalars, rows

    def invariants(self):
        assert len(self.obligations) <= 2 and len(self.allocations) <= 2
        for r in self.obligations.values():
            assert len(r.attempts) <= 2 and (r.accepted or not r.attempts)
            assert r.outcome != "success" or (r.provider not in self.allocations and r.result == calculate(r.input_bytes)[2])
            assert r.outcome != "success" or not self.storage.record(r.input).readers


def expected(actions):
    storage = inputs.Model()
    contracts = Contracts(storage)
    result = []
    for item in actions:
        if item[0] in ("B", "L"):
            op, owner, token, reader, count, data, issuer = item
            if owner != 0x103 or not contracts.current_reader(reader, storage.issuer):
                answer = (-2, 0, bytes(8))
            else:
                answer = storage.apply(item)
        else:
            answer = storage.apply(item) if item[0].isupper() else (0, 0, bytes(8))
        outcome = contracts.apply_combined(item)
        storage.invariants()
        contracts.invariants()
        result.append((contracts.report(outcome), storage.report(answer)))
    return result


def generate(seed, rounds=35):
    rng = random.Random(seed)
    actions = []
    handle = 0x100000101
    actions.append(action("O", 0x103, 1))
    serial, contract_serial, offer, worker_generations = 1, 1, 1, {4: 0, 5: 0}
    for round_ in range(rounds):
        length = rng.choice((0, 1, 7, 8, 9, 127, 128))
        # Source does not truncate: explicit length fixture permits successive
        # zero/short/boundary inputs while captured bytes still come from Block.
        actions.append(action("D", 1, 0))
        payload = bytes(rng.randrange(256) if rng.randrange(3) else 10 for _ in range(length))
        for at in range(0, length, 8):
            chunk = payload[at:at + 8]
            actions.append(action("W", 0x103, handle, at, len(chunk), int.from_bytes(chunk.ljust(8, b"\0"), "little")))
        token = serial << 8 | 0xA1
        actions.append(action("A", 0x103, serial, handle))
        for at in range(0, length, 8):
            actions.append(action("C", 0x103, token, at, 8))
        actions += [action("P", 0x103, token), action("L", 0x103, token, 0x104), action("o", 0x103, offer, token),
                    action("o", 0x103, offer, token), action("o", 0x203, offer, token), action("q", 0x103, (0x104 << 32) | contract_serial << 9 | 0x80)]
        contract = 0x104 << 32 | contract_serial << 9 | 0x80
        worker_generations[4] += 1
        worker = worker_generations[4] << 8 | 5
        mode = rng.randrange(7)
        if mode == 0:
            actions.append(action("c", 0x103, contract))
        else:
            actions += [action("B", 0x103, token, worker), action("a", 0x103, contract), action("a", 0x103, contract)]
            if length:
                actions.append(action("W", 0x103, handle, 0, 1, rng.randrange(256)))
            if mode == 1:
                actions += [action("c", 0x103, contract), action("d", 0x103, contract)]
            elif mode == 2:
                actions += [action("f", 0x103, contract), action("V", 0x103, token, worker), action("t", 0x103, contract)]
                worker_generations[4] += 1
                worker = worker_generations[4] << 8 | 5
                actions += [action("R", 0x105, token, 0, 8), action("B", 0x103, token, worker), action("d", 0x103, contract)]
            elif mode == 3:
                actions += [action("d", 0x103, contract, rng.choice((1, 2, 3))), action("d", 0x103, contract)]
            elif mode == 4:
                actions += [action("V", 0x103, token, worker), action("d", 0x103, contract), action("c", 0x103, contract)]
            elif mode == 5:
                actions += [action("d", 0x103, contract, rng.choice((4, 5, 6))), action("d", 0x103, contract)]
            else:
                actions.append(action("d", 0x103, contract))
        actions += [action("q", 0x103, contract), action("a", 0x103, contract), action("r", 0x103, contract),
                    action("E", 0x103, token), action("R", 0x103, token, 0, 8), action("q", 0x103, contract)]
        serial += 1
        contract_serial += 1
        offer += 1
    return actions


class CombinedAnalysisContractModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = ROOT / "build/analysis-contract-model"
        cls.evidence.mkdir(parents=True, exist_ok=True)
        cls.driver = cls.evidence / "production-driver"
        cls.summary = {"seeds": SEEDS, "production": ["cells/storage.zig", "cells/snapshot.zig", "cells/contract_core.zig"],
                       "representation": "dictionary input objects composed with provider/page sets and obligation histories",
                       "status": "running", "cases": [], "failures": []}
        cls.save()
        completed = subprocess.run([os.environ.get("ZIG", "zig"), "build-exe", "cells/analysis_model_driver.zig", "-lc", "-O", "Debug", f"-femit-bin={cls.driver}"], cwd=ROOT, text=True, capture_output=True, timeout=60)
        (cls.evidence / "compile.log").write_text(completed.stdout + completed.stderr)
        if completed.returncode:
            cls.summary["failures"].append({"stage": "compile", "error": completed.stdout + completed.stderr})
            cls.summary["status"] = "failed"
            cls.save()
            raise AssertionError(completed.stdout + completed.stderr)

    @classmethod
    def save(cls):
        cls.summary["total_steps"] = sum(case["steps"] for case in cls.summary["cases"])
        (cls.evidence / "results.json").write_text(json.dumps(cls.summary, indent=2) + "\n")

    @classmethod
    def tearDownClass(cls):
        cls.summary["status"] = "failed" if cls.summary["failures"] else "passed"
        cls.save()

    def compare(self, label, actions):
        wanted = expected(actions)
        path = self.evidence / f"{label}.actions"
        path.write_text("".join(" ".join(map(str, item)) + "\n" for item in actions))
        try:
            completed = subprocess.run([str(self.driver), str(path)], cwd=ROOT, text=True, capture_output=True, timeout=20)
            (self.evidence / f"{label}.actual").write_text(completed.stdout)
            (self.evidence / f"{label}.stderr").write_text(completed.stderr)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            actual = completed.stdout.splitlines()
            self.assertEqual(len(actual), len(wanted) * 2)
            for step, expected_report in enumerate(wanted):
                observed = scalar.parse_report(actual[step * 2]), inputs.parse_report(actual[step * 2 + 1])
                if observed != expected_report:
                    witness = {"label": label, "step": step, "actions": actions[:step + 1], "expected": expected_report, "actual": observed}
                    (self.evidence / f"{label}-failure-{step}.json").write_text(json.dumps(witness, indent=2) + "\n")
                self.assertEqual(observed, expected_report, f"{label} step{step}: {actions[step]}")
        except Exception as error:
            self.summary["failures"].append({"label": label, "error": str(error)})
            self.save()
            raise
        self.summary["cases"].append({"label": label, "steps": len(actions), "passed": True})
        self.save()

    def test_two_obligations_preserve_unrelated_work_and_revoke_before_settlement(self):
        h = 0x100000101
        first = 0x104 << 32 | 1 << 9 | 0x80
        second = 0x104 << 32 | 2 << 9 | 0x100 | 0x80
        actions = [action("O", 0x103, 1), action("W", 0x103, h, 0, 8, 0x0AFF000AFF000AFF)]
        for transaction, token in ((1, 0x1A1), (2, 0x2A2)):
            actions += [action("A", 0x103, transaction, h), action("C", 0x103, token, 0, 8),
                        action("P", 0x103, token), action("L", 0x103, token, 0x104), action("o", 0x103, transaction, token)]
        actions += [action("o", 0x103, 3, 0x1A1), action("B", 0x103, 0x1A1, 0x105), action("B", 0x103, 0x2A2, 0x106),
                    action("a", 0x103, first), action("a", 0x103, second), action("f", 0x103, first),
                    action("V", 0x103, 0x1A1, 0x105), action("t", 0x103, first), action("B", 0x103, 0x1A1, 0x205),
                    action("V", 0x103, 0x1A1, 0x104), action("d", 0x103, first), action("q", 0x103, second),
                    action("d", 0x103, second), action("T", 0x103, 0x1A1), action("E", 0x103, 0x1A1),
                    action("r", 0x103, first), action("r", 0x103, second), action("E", 0x103, 0x2A2)]
        self.compare("siblings-revocation", actions)

    def test_candidate_fences_partial_cleanup_and_counter_exhaustion(self):
        h = 0x100000101
        first = 0x104 << 32 | 1 << 9 | 0x80
        def prefix():
            return [action("O", 0x103, 1), action("W", 0x103, h, 0, 8, 0x0AFFFFFFFFFFFFFF),
                    action("A", 0x103, 1, h), action("C", 0x103, 0x1A1, 0, 8), action("P", 0x103, 0x1A1),
                    action("L", 0x103, 0x1A1, 0x104), action("o", 0x103, 1, 0x1A1),
                    action("B", 0x103, 0x1A1, 0x105), action("a", 0x103, first)]
        for mode in (1, 2, 3, 4):
            actions = prefix() + [action("v", mode), action("d", 0x103, first), action("q", 0x103, first),
                                  action("c", 0x103, first), action("r", 0x103, first), action("E", 0x103, 0x1A1)]
            self.compare(f"candidate-fence-{mode}", actions)
        for mode in (1, 2, 3):
            actions = prefix() + [action("y", mode), action("d", 0x103, first), action("q", 0x103, first),
                                  action("y", 0), action("c", 0x103, first), action("r", 0x103, first),
                                  action("T", 0x103, 0x1A1), action("E", 0x103, 0x1A1)]
            self.compare(f"partial-cleanup-{mode}", actions)
        actions = prefix() + [action("x", scalar.SERIAL_LIMIT, scalar.MASK), action("f", 0x103, first),
                              action("V", 0x103, 0x1A1, 0x105), action("t", 0x103, first),
                              action("B", 0x103, 0x1A1, 0x205), action("f", 0x103, first), action("q", 0x103, first),
                              action("r", 0x103, first), action("E", 0x103, 0x1A1)]
        self.compare("nonwrapping-retry-rpc-boundary", actions)

    def test_closed_or_revoked_offered_input_fails_before_first_dispatch(self):
        h = 0x100000101
        contract = 0x104 << 32 | 1 << 9 | 0x80
        prefix = [action("O", 0x103, 1), action("W", 0x103, h, 0, 8, 0x0A00FF0A00FF0A00),
                  action("A", 0x103, 1, h), action("C", 0x103, 0x1A1, 0, 8), action("P", 0x103, 0x1A1),
                  action("L", 0x103, 0x1A1, 0x104), action("o", 0x103, 1, 0x1A1), action("B", 0x103, 0x1A1, 0x105)]
        for retirement in (action("T", 0x103, 0x1A1), action("V", 0x103, 0x1A1, 0x104), action("I", 0x201)):
            actions = prefix + [retirement, action("a", 0x103, contract), action("q", 0x103, contract),
                                action("r", 0x103, contract), action("T", 0x103, 0x1A1), action("E", 0x103, 0x1A1)]
            self.compare(f"offered-input-retirement-{retirement[0]}", actions)

    def test_reader_routes_refuse_future_and_faulted_generation_before_explicit_rebind(self):
        h = 0x100000101
        contract = 0x104 << 32 | 1 << 9 | 0x80
        actions = [action("O", 0x103, 1), action("W", 0x103, h, 0, 8, 0x0AFF000AFFFF000A),
                   action("A", 0x103, 1, h), action("C", 0x103, 0x1A1, 0, 8), action("P", 0x103, 0x1A1),
                   action("L", 0x103, 0x1A1, 0x104), action("B", 0x103, 0x1A1, 0x105),
                   action("o", 0x103, 1, 0x1A1), action("B", 0x103, 0x1A1, 0x205),
                   action("B", 0x103, 0x1A1, 0x105), action("a", 0x103, contract), action("f", 0x103, contract),
                   action("B", 0x103, 0x1A1, 0x105), action("B", 0x103, 0x1A1, 0x205), action("d", 0x103, contract),
                   action("t", 0x103, contract), action("B", 0x103, 0x1A1, 0x205), action("V", 0x103, 0x1A1, 0x105),
                   action("B", 0x103, 0x1A1, 0x205), action("d", 0x103, contract),
                   action("q", 0x103, contract), action("r", 0x103, contract), action("E", 0x103, 0x1A1)]
        self.compare("current-route-generation", actions)

    def test_unallocatable_offer_prevalidation_consumes_no_input_read_or_identity(self):
        h = 0x100000101
        first = 0x104 << 32 | 1 << 9 | 0x80
        actions = [action("O", 0x103, 1), action("A", 0x103, 1, h), action("P", 0x103, 0x1A1),
                   action("L", 0x103, 0x1A1, 0x104), action("o", 0x103, 1, 0x1A1),
                   action("c", 0x103, first), action("r", 0x103, first), action("E", 0x103, 0x1A1),
                   action("A", 0x103, 2, h), action("P", 0x103, 0x2A1), action("L", 0x103, 0x2A1, 0x104),
                   action("o", 0x103, 1, 0x2A1), action("x", 0, 1), action("o", 0x103, 2, 0x2A1),
                   action("x", scalar.SERIAL_LIMIT + 1, 1), action("o", 0x103, 2, 0x2A1),
                   action("x", 2, 1), action("o", 0x103, 2, 0x2A1)]
        self.compare("pure-offer-prevalidation", actions)

    def test_generated_actual_byte_capture_analysis_attempt_revocation_sequences(self):
        for seed in SEEDS:
            with self.subTest(seed=seed):
                self.compare(f"seed-{seed}", generate(seed))


if __name__ == "__main__":
    unittest.main()
