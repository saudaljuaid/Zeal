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
         "noncanonical return stack", "disabled SYSCALL entry", "disabled SYSENTER entry"]


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


def verify(output, code, scenario):
    if scenario == 12:
        require(code == 5 and "KERNEL_FAULT vector=0x0000000000000006" in output and
                "PANIC trusted kernel fault" in output and "RESEARCH_PASS" not in output,
                "kernel-fault negative control failed")
        return
    require(code == 1, f"unexpected emulator exit {code}")
    require(output.count("ZEAL boot abi=1 x86_64") == 1, "kernel rebooted or never booted")
    require(output.count("RESEARCH_PASS") == 1, "missing unique research completion")
    require(f"RESEARCH_PASS scenario=0x{scenario:016x}" in output, "wrong boot configuration")
    require(not any(word in output for word in ("PANIC", "RESEARCH_FAIL", "bad-report")),
            "failure appeared in serial output")
    events = records(output)
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
    faults = select(events, "fault", 3)
    boots = select(events, "boot", 3)
    reset_reports = select(events, "reset-memory", 3)
    require([r["generation"] for r in reset_reports] == [b["generation"] for b in boots],
            "cold boot did not clear prior stack memory")
    if scenario in (7, 8, 15):
        require(not faults and len(boots) == 1 and len(select(events, "contract", 3)) == 1 and
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
        for solo in range(3):
            image = build(0, solo)
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
