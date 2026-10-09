#!/usr/bin/env python3
"""Fingerprint the actual build inputs, including exported-source checkouts."""
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def source_id():
    digest = hashlib.sha256()
    files = [ROOT / "Makefile", ROOT / "rust-toolchain.toml"]
    for directory in ("arch", "boot", "cells", "include", "kernel", "policy", "tools"):
        files.extend(path for path in (ROOT / directory).rglob("*")
                     if path.is_file() and "__pycache__" not in path.parts
                     and path.suffix in (".c", ".h", ".def", ".S", ".ld", ".zig", ".rs", ".toml", ".py", ".sh"))
    for path in sorted(files):
        data = path.read_bytes()
        digest.update(str(path.relative_to(ROOT)).encode() + b"\0")
        digest.update(len(data).to_bytes(8, "little") + data)
    return "source-" + digest.hexdigest()[:32]


if __name__ == "__main__":
    identity = source_id()
    if len(sys.argv) == 2:
        output = Path(sys.argv[1])
        text = f'#define Z_BUILD_ID "{identity}"\n'
        if not output.exists() or output.read_text() != text:
            output.write_text(text)
    else:
        print(identity)
