#!/usr/bin/env python3
import pathlib
import struct
import sys

BASE = 0x40000000
LIMIT = 0x10000
PROGRAM_HEADER_MAX = 8


def check_cell(data: bytes) -> None:
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("expected ELF64 little-endian cell")
    if data[7:16] != bytes(9):
        raise ValueError("unsupported ELF ABI or reserved identity bytes")
    kind, machine, version = struct.unpack_from("<HHI", data, 16)
    entry, phoff = struct.unpack_from("<QQ", data, 24)
    flags, ehsize, phsize, phcount = struct.unpack_from("<IHHH", data, 48)
    if kind != 2 or machine != 62 or version != 1 or flags or ehsize != 64 or entry != BASE or phsize != 56 or not 1 <= phcount <= PROGRAM_HEADER_MAX:
        raise ValueError("invalid cell identity or entry")
    headers_end = phoff + phcount * phsize
    if phoff < 64 or headers_end > len(data):
        raise ValueError("truncated or overlapping program header table")
    loaded = executable = False
    virtual_ranges, file_ranges = [], []
    for i in range(phcount):
        offset = phoff + i * phsize
        if offset + phsize > len(data):
            raise ValueError("truncated program headers")
        ptype, flags, fileoff, vaddr, paddr, filesz, memsz, align = struct.unpack_from(
            "<IIQQQQQQ", data, offset)
        if ptype != 1:
            if ptype == 0x6474E551 and flags & 1:
                raise ValueError("executable stack is outside the cell CPU contract")
            continue
        loaded = True
        if flags & 2 or flags & ~7 or not flags & 4:
            raise ValueError("cell image must be immutable")
        if filesz != memsz or not memsz or not BASE <= vaddr < BASE + LIMIT:
            raise ValueError("mutable or empty cell segment")
        if paddr != vaddr or memsz > BASE + LIMIT - vaddr or fileoff < headers_end or fileoff + filesz > len(data):
            raise ValueError("cell segment out of bounds")
        if align not in (0, 1) and (align & (align - 1) or vaddr % align != fileoff % align):
            raise ValueError("invalid segment alignment")
        if any(vaddr < end and start < vaddr + memsz for start, end in virtual_ranges) or any(fileoff < end and start < fileoff + filesz for start, end in file_ranges):
            raise ValueError("overlapping immutable cell segments")
        virtual_ranges.append((vaddr, vaddr + memsz))
        file_ranges.append((fileoff, fileoff + filesz))
        if vaddr <= entry < vaddr + memsz and flags & 1:
            executable = True
    if not loaded or not executable:
        raise ValueError("missing executable entry")


if __name__ == "__main__":
    check_cell(pathlib.Path(sys.argv[1]).read_bytes())
