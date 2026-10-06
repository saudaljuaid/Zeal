#!/usr/bin/env python3
import json
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
         "blocking receive and timed sleep"]


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
    if scenario == 12:
        require(code == 5 and "KERNEL_FAULT vector=0x0000000000000006" in output and
                "PANIC trusted kernel fault" in output and "RESEARCH_PASS" not in output,
                "kernel-fault negative control failed")
        return
    require(code == 1, f"unexpected emulator exit {code}")
    require(output.count("ZEAL boot abi=2 x86_64") == 1, "kernel rebooted or never booted")
    require(output.count("MANIFEST_ACCEPT version=1") == 1, "privileged manifest validation missing")
    require(output.count("RESEARCH_PASS") == 1, "missing unique research completion")
    require(f"RESEARCH_PASS scenario=0x{scenario:016x}" in output, "wrong boot configuration")
    require(not any(word in output for word in ("PANIC", "RESEARCH_FAIL", "bad-report")),
            "failure appeared in serial output")
    events = records(output)
    expected_identities = {0: 100, 1: 200, 2: 300, 3: 400}
    for cell, identity in expected_identities.items():
        for boot in select(events, "boot", cell):
            require(boot.get("identity") == identity, "boot identity differs from manifest")
            require(boot.get("abi") == 2 and boot.get("entry") == 0x40000000,
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
    if scenario in (7, 8, 15, 19):
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
    repetitions = int(os.environ.get("RESEARCH_REPEAT", "2"))
    require(1 <= repetitions <= 20, "RESEARCH_REPEAT must be 1..20")
    try:
        for scenario in range(len(NAMES)):
            image = build(scenario)
            for repeat in range(repetitions):
                label = f"scenario-{scenario:02}-run-{repeat + 1}"
                output, code, duration = emulate(image, label)
                verify(output, code, scenario)
                results.append({"case": label, "scenario": NAMES[scenario], "seconds": duration,
                                "exit": code, "passed": True})
            print(f"PASS {scenario:02} {NAMES[scenario]} ({repetitions} runs)", flush=True)
        image = LOGS / "scenario-00" / "zeal.img"
        for cpu, memory in (("qemu64", "32M"), ("max", "128M")):
            label = f"platform-{cpu}-{memory}"
            output, code, duration = emulate(image, label, cpu, memory)
            verify(output, code, 0)
            results.append({"case": label, "seconds": duration, "passed": True})
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
        require(code == 1 and output.count("ZEAL boot abi=2 x86_64") == 1 and
                output.count("MANIFEST_ACCEPT version=1") == 1 and
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
        (LOGS / "results.json").write_text(json.dumps({"passed": all(r["passed"] for r in results),
                                                     "cases": results}, indent=2) + "\n")
    print(f"Research suite: {len(results)} emulator runs passed. Logs: {LOGS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
