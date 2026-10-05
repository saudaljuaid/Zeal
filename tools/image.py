#!/usr/bin/env python3
import pathlib
import sys

MAX_KERNEL = 0x70000
DISK_SIZE = 16 * 1024 * 1024


def make_image(boot: bytes, kernel: bytes) -> bytes:
    if len(boot) != 512 or boot[-2:] != b"\x55\xaa":
        raise ValueError("invalid BIOS boot sector")
    if not kernel or len(kernel) > MAX_KERNEL:
        raise ValueError("kernel exceeds conventional memory loading limit")
    return (boot + kernel).ljust(DISK_SIZE, b"\0")


if __name__ == "__main__":
    boot, kernel, output = map(pathlib.Path, sys.argv[1:])
    output.write_bytes(make_image(boot.read_bytes(), kernel.read_bytes()))
