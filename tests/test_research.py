import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location("research", pathlib.Path(__file__).with_name("research.py"))
research = importlib.util.module_from_spec(spec)
spec.loader.exec_module(research)


def event(name, cell, generation, tick, **fields):
    fields = dict(identity={0: 100, 1: 200, 2: 300, 3: 400}[cell], **fields)
    fields = dict(cell=cell, generation=generation, tick=tick, **fields)
    return "EVENT " + name + "".join(f" {key}=0x{value:016x}" for key, value in fields.items()) + "\n"


def healthy_trace():
    output = "ZEAL boot abi=2 x86_64\nMANIFEST_ACCEPT version=1\n"
    for cell in range(4):
        output += event("boot", cell, 1, 0, abi=2, entry=0x40000000)
    output += event("healthy-memory", 2, 1, 1, stack=0x710bf391ad42c865, writable=0x38d126ef8a905b47)
    output += event("cap-delegate", 1, 1, 1, holder=0x103, target=0x102, rights=4, cap=0x606, parent=0x303)
    output += event("demo-forbidden", 2, 1, 1, rights=1, result=0xfffffffffffffffe)
    output += event("read-verified", 2, 1, 1, reads=1)
    output += event("read", 2, 1, 1)
    output += event("demo-allowed", 2, 1, 1, cap=0x606, parent=0x303)
    output += event("cap-revoke", 1, 1, 2, cap=0x606)
    output += event("demo-revoked", 2, 1, 2, cap=0x606, endpoint=0x102)
    output += event("demo-resumed", 2, 1, 3, endpoint=0x102, cap=0x403)
    for cell, tick in ((0, 20), (1, 40)):
        output += event("fault", cell, 1, tick, reason=64, error=0, address=0)
        output += event("boot", cell, 2, tick + 4, abi=2, entry=0x40000000)
        if cell == 0:
            output += event("read-verified", 2, 1, 25, reads=2)
            output += event("recovered", cell, 2, 25, reads=2)
        else:
            output += event("demo-rebind", 2, 1, 44, old=0x102, endpoint=0x202)
            output += event("healthy-memory", 2, 1, 44, stack=0x710bf391ad42c865, writable=0x38d126ef8a905b47)
            output += event("demo-resumed", 2, 1, 45, endpoint=0x202, cap=0x503)
            output += event("read-verified", 2, 1, 46, reads=3)
            output += event("recovered", cell, 2, 46, reads=3)
    for generation, tick in enumerate((1, 5, 13, 29), 1):
        if generation > 1:
            output += event("boot", 3, generation, tick, abi=2, entry=0x40000000)
        output += event("reset-memory", 3, generation, tick)
        output += event("fault", 3, generation, tick, reason=6, error=0, address=0)
    output += event("quarantine", 3, 4, 29)
    return output + "RESEARCH_PASS scenario=0x0000000000000000 reads=0x100 tick=0x78\n"


def wait_probe_trace(standalone=False):
    output = event("reset-memory", 3, 1, 0)
    if not standalone:
        output += event("wait-arm", 3, 1, 1, kind=2, deadline=101)
        output += event("read-verified", 2, 1, 2, reads=1)
        output += event("wait-progress", 2, 1, 4, reads=1)
        output += event("wake", 3, 1, 4, kind=2, deadline=101, reason=2, result=0)
        output += event("wait-delivered", 3, 1, 4, sender=0x103, value=0x7a65616c77616b65)
    output += event("wait-arm", 3, 1, 4, kind=2, deadline=6)
    if standalone:
        output += event("idle-enter", 3, 1, 4)
        output += event("idle-wake", 3, 1, 5, entered=4, reason=6)
        output += event("idle-enter", 3, 1, 5)
        output += event("idle-wake", 3, 1, 6, entered=5, reason=6)
    output += event("wake", 3, 1, 6, kind=2, deadline=6, reason=3, result=0xfffffffffffffff8)
    output += event("wait-arm", 3, 1, 6, kind=1, deadline=9)
    if standalone:
        output += event("idle-enter", 3, 1, 6)
        output += event("idle-wake", 3, 1, 7, entered=6, reason=6)
    output += event("wake", 3, 1, 9, kind=1, deadline=9, reason=1, result=0)
    output += event("wait-contract", 3, 1, 9, checks=7, duration=3)
    return output + event("exit", 3, 1, 9)


def waiting_trace():
    output = "".join(line + "\n" for line in healthy_trace().splitlines()
                     if not (line.startswith("EVENT ") and "cell=0x0000000000000003" in line and
                             not (line.startswith("EVENT boot ") and
                                  "generation=0x0000000000000001" in line)))
    first_fault = event("fault", 0, 1, 20, reason=64, error=0, address=0)
    output = output.replace(first_fault, wait_probe_trace() +
                            event("wait-arm", 0, 1, 18, kind=2, deadline=118) +
                            event("wait-arm", 1, 1, 19, kind=2, deadline=119) +
                            event("wait-cancel", 0, 1, 20, kind=2, deadline=118, reason=64) + first_fault)
    fs_fault = event("fault", 1, 1, 40, reason=64, error=0, address=0)
    output = output.replace(fs_fault, event("wait-cancel", 1, 1, 40,
                                          kind=2, deadline=119, reason=64) + fs_fault)
    return output.replace("RESEARCH_PASS scenario=0x0000000000000000",
                          "RESEARCH_PASS scenario=0x0000000000000013")


class ResearchOracleTests(unittest.TestCase):
    def test_complete_trace_is_accepted(self):
        research.verify(healthy_trace(), 1, 0)

    def test_success_line_alone_cannot_pass(self):
        with self.assertRaises(AssertionError):
            research.verify("ZEAL boot abi=1 x86_64\nRESEARCH_PASS scenario=0x0000000000000000", 1, 0)

    def test_counterfeit_recovery_is_rejected(self):
        good = healthy_trace()
        modifications = [
            good.replace("ZEAL boot", "ZEAL missing"),
            "ZEAL boot abi=2 x86_64\n" + good,
            good.replace("RESEARCH_PASS", "RESEARCH_FAIL"),
            good + "PANIC simulated\n",
            good.replace(event("read", 2, 1, 1), ""),
            good.replace(event("recovered", 0, 2, 25, reads=2), ""),
            good.replace(event("recovered", 1, 2, 46, reads=3),
                         event("recovered", 1, 1, 46, reads=3)),
            good.replace(event("boot", 0, 2, 24, abi=2, entry=0x40000000),
                         event("boot", 0, 2, 23, abi=2, entry=0x40000000)),
            good + event("boot", 2, 2, 50),
            good + event("fault", 2, 1, 50, reason=6, error=0, address=0),
            good.replace(event("quarantine", 3, 4, 29), ""),
            good.replace(event("reset-memory", 3, 2, 5), ""),
            good.replace("reason=0x0000000000000006", "reason=0x000000000000000e"),
            good.replace(event("boot", 3, 2, 5, abi=2, entry=0x40000000),
                         event("boot", 3, 1, 5, abi=2, entry=0x40000000)),
            good.replace("scenario=0x0000000000000000", "scenario=0x0000000000000001"),
            good.replace(event("cap-delegate", 1, 1, 1, holder=0x103, target=0x102,
                               rights=4, cap=0x606, parent=0x303), ""),
            good.replace("rights=0x0000000000000001 result=0xfffffffffffffffe",
                         "rights=0x0000000000000001 result=0x0000000000000000"),
            good.replace(event("cap-revoke", 1, 1, 2, cap=0x606), ""),
            good.replace(event("demo-revoked", 2, 1, 2, cap=0x606, endpoint=0x102), ""),
            good.replace(event("demo-rebind", 2, 1, 44, old=0x102, endpoint=0x202),
                         event("demo-rebind", 2, 1, 44, old=0x102, endpoint=0x102)),
            good.replace(event("read-verified", 2, 1, 46, reads=3), ""),
        ]
        for index, altered in enumerate(modifications):
            with self.subTest(index=index), self.assertRaises(AssertionError):
                research.verify(altered, 1, 0)

    def test_wrong_emulator_exit_is_rejected(self):
        for code in (0, 3, 5, None):
            with self.subTest(code=code), self.assertRaises(AssertionError):
                research.verify(healthy_trace(), code, 0)

    def test_kernel_fault_must_fail_loudly(self):
        trace = "KERNEL_FAULT vector=0x0000000000000006\nPANIC trusted kernel fault\n"
        research.verify(trace, 5, 12)
        for output, code in ((trace, 1), ("", 5), (trace + "RESEARCH_PASS", 5)):
            with self.assertRaises(AssertionError):
                research.verify(output, code, 12)

    def test_complete_wait_trace_is_accepted(self):
        research.verify(waiting_trace(), 1, 19)

    def test_idle_timer_wait_trace_is_accepted(self):
        trace = event("boot", 3, 1, 0, abi=2, entry=0x40000000) + wait_probe_trace(True)
        research.verify_waits(research.records(trace), standalone=True)

    def test_missing_or_counterfeit_wakeups_are_rejected(self):
        good = waiting_trace()
        message = event("wake", 3, 1, 4, kind=2, deadline=101, reason=2, result=0)
        timeout = event("wake", 3, 1, 6, kind=2, deadline=6, reason=3, result=0xfffffffffffffff8)
        sleep = event("wake", 3, 1, 9, kind=1, deadline=9, reason=1, result=0)
        cancellation = event("wait-cancel", 0, 1, 20, kind=2, deadline=118, reason=64)
        alterations = [
            good.replace(message, ""),
            good.replace(timeout, ""),
            good.replace(sleep, ""),
            good.replace(cancellation, ""),
            good.replace(message, event("wake", 3, 2, 4, kind=2, deadline=101, reason=2, result=0)),
            good.replace(message, event("wake", 3, 1, 101, kind=2, deadline=101, reason=2, result=0)),
            good.replace(message, event("wake", 3, 1, 4, kind=2, deadline=100, reason=2, result=0)),
            good.replace(timeout, event("wake", 3, 1, 5, kind=2, deadline=6, reason=3,
                                        result=0xfffffffffffffff8)),
            good.replace(timeout, event("wake", 3, 1, 6, kind=2, deadline=6, reason=3, result=0)),
            good.replace(sleep, event("wake", 3, 1, 8, kind=1, deadline=9, reason=1, result=0)),
            good.replace(sleep, event("wake", 3, 1, 9, kind=1, deadline=9, reason=2, result=0)),
            good.replace(event("wait-arm", 3, 1, 1, kind=2, deadline=101), ""),
            good.replace(event("wait-progress", 2, 1, 4, reads=1), ""),
            good.replace(event("wait-progress", 2, 1, 4, reads=1),
                         event("wait-progress", 2, 1, 4, reads=0)),
            good.replace("value=0x7a65616c77616b65", "value=0x0000000000000000"),
            good.replace("checks=0x0000000000000007", "checks=0x0000000000000003"),
            good.replace(event("read-verified", 2, 1, 2, reads=1), ""),
            good.replace(event("read-verified", 2, 1, 2, reads=1),
                         event("read-verified", 2, 1, 2, reads=1) * 2),
            good.replace(event("read-verified", 2, 1, 2, reads=1),
                         event("read-verified", 2, 1, 2, reads=2)),
            good.replace(event("wait-arm", 3, 1, 1, kind=2, deadline=101),
                         event("wait-arm", 3, 1, 1, kind=2, deadline=1002)),
            good + event("wake", 0, 1, 25, kind=2, deadline=118, reason=2, result=0),
        ]
        for index, output in enumerate(alterations):
            with self.subTest(index=index), self.assertRaises(AssertionError):
                research.verify(output, 1, 19)

    def test_missing_or_counterfeit_idle_wake_is_rejected(self):
        good = event("boot", 3, 1, 0, abi=2, entry=0x40000000) + wait_probe_trace(True)
        alterations = [
            good.replace(event("idle-wake", 3, 1, 5, entered=4, reason=6), ""),
            good.replace(event("idle-enter", 3, 1, 4), ""),
            good.replace(event("idle-wake", 3, 1, 5, entered=4, reason=6),
                         event("idle-wake", 3, 1, 4, entered=4, reason=6)),
            good.replace(event("idle-wake", 3, 1, 5, entered=4, reason=6),
                         event("idle-wake", 3, 1, 5, entered=4, reason=2)),
            good.replace(event("idle-wake", 3, 1, 5, entered=4, reason=6),
                         event("idle-wake", 3, 1, 5, entered=3, reason=6)),
            good.replace(event("idle-wake", 3, 1, 5, entered=4, reason=6),
                         event("idle-wake", 3, 2, 5, entered=4, reason=6)),
            good.replace(event("wait-arm", 3, 1, 4, kind=2, deadline=6), ""),
        ]
        for index, output in enumerate(alterations):
            with self.subTest(index=index), self.assertRaises(AssertionError):
                research.verify_waits(research.records(output), standalone=True)

    def test_terminal_event_requires_prior_wait_cancellation(self):
        trace = event("boot", 0, 1, 0, abi=2, entry=0x40000000)
        trace += event("wait-arm", 0, 1, 1, kind=2, deadline=20)
        for terminal in ("fault", "exit", "quarantine"):
            with self.subTest(terminal=terminal), self.assertRaises(AssertionError):
                research.verify_waits(research.records(trace + event(terminal, 0, 1, 2)),
                                     demonstration=False)

    def test_idle_with_runnable_cell_is_rejected(self):
        trace = event("boot", 3, 1, 0, abi=2, entry=0x40000000)
        trace += event("idle-enter", 3, 1, 1)
        trace += event("idle-wake", 3, 1, 2, entered=1, reason=6)
        with self.assertRaises(AssertionError):
            research.verify_waits(research.records(trace), demonstration=False)


if __name__ == "__main__":
    unittest.main()
