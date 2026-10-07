#!/usr/bin/env python3
"""Report and check the bounded privileged supervisor's linked footprint."""
import argparse
import json
import pathlib
import subprocess

LOAD_START = 0x10000
LOAD_END_MAX = 0x90000
LOADED_BYTES_MAX = 0x70000
STATIC_END_MAX = 0x400000
SYMBOLS = {"__kernel_start", "__kernel_load_end", "__bss_start", "__bss_end", "__kernel_end"}


def footprint(kernel, symbols):
    if set(symbols) != SYMBOLS or any(type(value) is not int or not 0 <= value < 1 << 64
                                     for value in symbols.values()):
        raise ValueError("missing or malformed linker footprint symbols")
    start, load_end = symbols["__kernel_start"], symbols["__kernel_load_end"]
    bss_start, bss_end, end = symbols["__bss_start"], symbols["__bss_end"], symbols["__kernel_end"]
    if start != LOAD_START or not start < load_end <= LOAD_END_MAX:
        raise ValueError("linked BIOS payload exceeds the conventional-memory window")
    if not kernel or len(kernel) > LOADED_BYTES_MAX or len(kernel) > load_end - start:
        raise ValueError("loaded kernel bytes exceed the BIOS image builder bound")
    if not load_end <= bss_start <= bss_end == end < STATIC_END_MAX:
        raise ValueError("bounded supervisor must end below 4 MiB")
    return {"loaded_kernel_bytes": len(kernel), "loaded_address_start": start,
            "loaded_address_end": load_end, "bss_bytes": bss_end - bss_start,
            "static_supervisor_bytes": len(kernel) + bss_end - bss_start,
            "static_address_end": end, "loaded_bytes_limit": LOADED_BYTES_MAX,
            "static_address_end_limit": STATIC_END_MAX}


def linker_symbols(elf):
    result = subprocess.run(["nm", "-n", str(elf)], check=True, capture_output=True,
                            text=True, timeout=20)
    symbols = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2] in SYMBOLS:
            if fields[2] in symbols:
                raise ValueError("duplicate linker footprint symbol")
            symbols[fields[2]] = int(fields[0], 16)
    return symbols


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=pathlib.Path)
    parser.add_argument("kernel", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    try:
        report = footprint(args.kernel.read_bytes(), linker_symbols(args.elf))
        result = json.dumps(report, indent=2) + "\n"
        if args.output:
            args.output.write_text(result)
        print(result, end="")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
