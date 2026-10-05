#!/usr/bin/env python3
import pathlib
import struct
import sys

BASE = 0x40000000
LIMIT = 0x10000


def check_cell(data: bytes) -> None:
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("expected ELF64 little-endian cell")
    kind, machine = struct.unpack_from("<HH", data, 16)
    entry, phoff = struct.unpack_from("<QQ", data, 24)
    phsize, phcount = struct.unpack_from("<HH", data, 54)
    if kind != 2 or machine != 62 or entry != BASE or phsize != 56 or not phcount:
        raise ValueError("invalid cell identity or entry")
    loaded = executable = False
    for i in range(phcount):
        offset = phoff + i * phsize
        if offset + phsize > len(data):
            raise ValueError("truncated program headers")
        ptype, flags, fileoff, vaddr, _, filesz, memsz, align = struct.unpack_from(
            "<IIQQQQQQ", data, offset)
        if ptype != 1:
            continue
        loaded = True
        if flags & 2 or flags & ~7 or not flags & 4:
            raise ValueError("cell image must be immutable")
        if filesz != memsz or not memsz or not BASE <= vaddr < BASE + LIMIT:
            raise ValueError("mutable or empty cell segment")
        if memsz > BASE + LIMIT - vaddr or fileoff + filesz > len(data):
            raise ValueError("cell segment out of bounds")
        if align not in (0, 1) and (align & (align - 1) or vaddr % align != fileoff % align):
            raise ValueError("invalid segment alignment")
        if vaddr <= entry < vaddr + memsz and flags & 1:
            executable = True
    if not loaded or not executable:
        raise ValueError("missing executable entry")


if __name__ == "__main__":
    check_cell(pathlib.Path(sys.argv[1]).read_bytes())
